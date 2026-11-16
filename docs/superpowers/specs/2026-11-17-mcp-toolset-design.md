# YL Agent Runtime — MCP Toolset & Approval Gate Design

**Date:** 2026-11-17
**Status:** Proposed (pending operator approval)
**Scope:** Phase 1–4 tool layer on top of the existing crate architecture; daemon/CLI wiring required to make it live.

---

## Intent & Why

YL Agent Runtime's main goal: an MCP server an agent connects to and immediately does real work on the host — grep, read, write, edit, replace, copy, move, rename, delete, run commands (PowerShell / CMD / Git Bash) — **fastest to use, safest by design, better than any existing open-source option** (localforge-mcp, official filesystem server, j0hanz/filesystem-mcp).

This design distills line-by-line source study of those three projects into a Rust implementation that (a) copies their proven patterns, (b) fixes their admitted weaknesses, and (c) adds what none of them have: a real in-server approval gate backed by YL's policy engine.

## Goals

- G1: Agent connects via stdio MCP and performs all filesystem work inside allowed workspace roots with hard containment (symlink/UNC/ADS/traversal-safe).
- G2: Edits are precise and self-explaining: occurrence counting, all-or-nothing, dryRun diffs, closest-match errors that teach the model how to retry.
- G3: Long-running processes with incremental cursor-paged logs; children can never outlive the server (Windows Job Objects).
- G4: Approval gate with read/write/exec tiers, project + global policy files, optional YOLO mode, safety overrides that always prompt.
- G5: Every mutating call is audited; secrets are blocked at the path layer; outputs are bounded (inline head+tail + spill files readable back).
- G6: Each phase compiles green on Windows and lands independently usable.

## Non-Goals (this design)

- OS-sandbox enforcement (AppContainer/Landlock/Seatbelt) — separate backends per HANDOFF plan; the tool layer only reports what the active backend provides.
- Tauri desktop UI, remote/Iroh transport, device pairing.
- Replacing rmcp 3.10 or restructuring crates.

## Anti-Goals (failure even if it "works")

- Fake sandbox claims (labeling unsandboxed execution as sandboxed).
- Silent overwrite of files; first-match-wins edits; unbounded reads; approval bypass via `env` vars.

## Approaches Considered

| | A. Big bang (~30 tools at once) | **B. Layered phases (chosen)** | C. Port j0hanz wholesale |
|---|---|---|---|
| First usable | Weeks | Days | Medium |
| Risk | One huge diff, hard to verify | Each phase green + testable | Abandons YL's policy/crate architecture |
| Fit to goal | Poor | **Best** | Poor — loses the differentiators |

## Constraints

- Windows-first (PowerShell quirks: `&&` unavailable in 5.1, `InvalidEndOfLine` detection, `taskkill /T`), POSIX portable.
- Existing stack: rmcp 3.10 (`#[tool]` + `Parameters<T>`), tokio, thiserror; schemars 0.8 in-core vs rmcp's 1.x (explicit `input_schema` where they'd collide).
- PATH_RULE for every path arg: "Absolute, or relative to an allowed workspace root; must resolve inside."

---

## Phase 1 — Filesystem core (+ daemon wiring)

**Prereq wiring:** `RuntimeDaemon::new()` registers `NativeBackend`; `select_backend` by execution profile (Development→native); `runtime-cli` commands become real (`start`, `status`, `discover-tools`, `mcp` runs `McpServer` over stdio). Note: `runtime-mcp` already compiles against rmcp 3.10 (HANDOFF.md is stale on this point).

### Tools (namespace `workspace.*`, registered as `#[tool]` handlers)

| Tool | Params (exact) | Returns / notes |
|---|---|---|
| `workspace.read` | `path`, `offset`? (bytes), `max_bytes`? (≤1 MiB default 64 KiB), `line_start`?/`line_end`? (1-based), `head`?/`tail`? (lines), `line_numbers`?, `media`? | Numbered `N\tline` for line mode; binary probe (NUL in first 8 KiB) → `BINARY_FILE` unless `media:true` (images/audio → base64 content block); >10 MiB → 2000-line head + continuation trailer carrying exact next-call args; `sha256` of returned slice on request |
| `workspace.write` | `path`, `content`, `overwrite`? (default false; refusal names the fix), `append`? | Atomic temp+rename; creates missing parents; EOL: existing file keeps dominant EOL; returns `{path, bytes, eol, diff?}` |
| `workspace.edit` | `path`, `edits[]` (1..100 × `old_text`/`new_text`/`expected_occurrences`? default 1), `dry_run`? | All-or-nothing; two-stage matcher (exact substring → trim-equal lines + reindent); no-match → bigram-Dice closest-match error with numbered lines; multi-match without `expected_occurrences` → error listing up to 5 line numbers; EOL-preserving algorithm (LF-view count, byte-exact CRLF run preferred); returns diff (3 context lines) |
| `workspace.patch` | `path` (base), `diff` (≤256 KiB, ≤10 files), `dry_run`? | diffy `PatchSet` (git-style); relative-only paths, reject `..`/drive letters; hunks in strict order; **two-phase: build all temps, then rename all** (fixes localforge's partial-application hole); all-or-nothing |
| `workspace.replace_text` | `path`? (file or tree; omitted = whole single root), `pattern`? (file glob), `search`, `replacement`, `is_regex`?, `case_sensitive`? (default false), `whole_word`?, `max_matches`? (default 100), `dry_run`? | Per-file occurrence counts; self-matching guard on early stop; returns per-file diffs |
| `workspace.search` | `path`?, `query`, `is_regex`? (default false), `case_sensitive`? (default false), `include`?/`exclude`? globs, `context`? (0..5), `max_results`? (default 200), `files_only`?, `include_hidden`?, `include_ignored`?, `max_file_size`? | Engine: `ignore` walker + `regex` (linear-time) + literal prefilter; gitignore respected by default; binary skipped (NUL rule); default excludes (.git, node_modules, target, dist, build, __pycache__, .venv, coverage); returns matches `{file, line, column, text, before?, after?}` + skip triads (`skipped_binary/too_large/inaccessible`) + `truncated` + `stopped_reason` |
| `workspace.find_files` | `path`?, `pattern` (globset; bare word = exact name anywhere), `max_results`? (default 100), `type`? (file/dir/any), `exclude`? | Names only, never content; `bare_word_hint` advice |
| `workspace.list` | `path`?, `depth`? (default 1), `max_entries`? (default 1000), `include_hidden`?, `include_ignored`?, `include_sizes`?, `sort_by`? (name/size) | Dirs-first; `ignored_dirs` + `hidden` accounting with `//` notes; cursor paging (5-min TTL) |
| `workspace.tree` | `path`, `depth`?, `exclude_patterns`? | JSON tree; 100 000-entry budget → loud stop with narrowing advice |
| `workspace.stat` | `path` \| `paths[]` (≤1000) | size, created/modified/accessed, `token_estimate` (bytes/4), `line_count` (≤256 KiB files), `read_only` on Windows (never fake POSIX bits), `symlink_target`; per-path errors settle independently |
| `workspace.mkdir` | `path` | parents created |
| `workspace.move` | `source`, `destination` (full path incl. name), `copy`? | destination must not exist (no overwrite bypass on move); copy has `overwrite`? flag; 2-phase plan/execute |
| `workspace.delete` | `paths[]` (≤1000), `recursive`? | non-empty dir without `recursive` → refusal naming the fix; nested-in-batch pairs refused; approval prompt when non-empty (Phase 3) |
| `workspace.allowed_roots` | — | roots + read-only dirs list |

### Cross-cutting rules (all filesystem tools)

- **Containment:** per-call resolve → expanduser → normalize (drive capitalization, `/c/`→`C:\`, bare `C:`→`C:\`) → deny-list check → root-prefix check with separator-boundary → **realpath every call** → re-containment of the resolved path. Rejections: ADS colon, reserved device names (CON/PRN/AUX/NUL/COM1-9/LPT1-9 + ext), trailing dot/space components, NUL bytes.
- **Typed access modes** `read`/`write`/`move` threaded through validation; read-only roots refuse `write`/`move` on the *resolved* path.
- **Secret-file blocking** (j0hanz's ~50 patterns compiled to a GlobSet): `.env*`, `*.pem/key/p12/pfx`, `.ssh/**`, `.aws/**`, `.npmrc`, `.git-credentials`, `*.tfstate*`, `id_rsa*` etc. Blocked entries vanish from listings/search (not counted), reads/writes refused with the relief switches named; tiered: builtins (relievable via allow list) / operator denies (never); ADS suffix stripped before matching (`.env:stream` → `.env`).
- **Aliasing + suggestions:** `file/target→path`, `old/find→old_text`, `new/replacement→new_text`, `text→content`, `dest→destination`, `start/end→line_start/line_end`, `cmd→command`, `id→process_id`. Unknown args → `Did you mean 'pattern'?` via closest-match over the tool's arg table.
- **Output discipline:** `//`-prefixed advice lines (never data); dual text + structured output, structured never duplicates heavy bytes; spill overflow (>200 KiB result) → head+tail preview + spill file path added to read roots.
- **Audit:** every mutating call → `AuditEvent` (tool, path(s), decision, duration).

## Phase 2 — Process & shells

| Tool | Params | Notes |
|---|---|---|
| `execute` | `command` (string \| array; string ⇒ shell), `cwd`?, `shell`? (powershell\|pwsh\|cmd\|bash\|sh; default powershell on Windows), `timeout_s`? (default 600), `env`?, `input`? (≤64 KiB stdin) | Inline 30 KB head+tail per stream (`...\n[N bytes cut]...\n`) + spill files (`stdout_path`/`stderr_path`) in read roots; `duration_ms`, `exit_code`, `error_type` (process_exit/timeout/process_start); PS 5.1 `&&` failure → hint; timeout > default → warning suggesting `process.start` |
| `process.start` | `command`, `cwd`?, `shell`?, `env`? | `process_id` (`proc-`+10 hex); `CREATE_NEW_PROCESS_GROUP`; **Job Object kill-on-close** via windows-rs (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` + `AssignProcessToJobObject`) — children/grandchildren die with the server; registry GC: TTL 1 h exited / max 50 |
| `process.read` | `process_id`, `after`? (seq), `limit_bytes`? (default 30 000), `wait_ms`? (≤60 000), `format`? (text\|chunks) | tokio pump tasks → seq chunks (split streams), 4 MiB ring trimmed by raw bytes; `oldest_sequence`, `cursor_lost`, `next_after`, `truncated` |
| `process.write` | `process_id`, `text`, `append_newline`? (default true) | 30 s stdin drain guard → `stdin_blocked` warning |
| `process.status` / `process.list` | `process_id`? | `{state: running\|exited, exit_code, started_at, ...}` |
| `process.stop` | `process_id`, `force`? | graceful `taskkill /PID x /T` → 10 s → `/F`; POSIX killpg |
| `process.restart` | `process_id` | same command/cwd/shell/env, same id |
| `process.discover_tools` | `name`? | existing `ToolchainDiscovery` |

**Env security:** whitelist inherit (PATH, PATHEXT, SYSTEMROOT, TEMP, USERPROFILE, APPDATA, ProgramFiles*, ProgramData, COMSPEC), deny fnmatch upper (`*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*KEY*`, `AWS_*`, `AZURE_*`, `GITHUB_*`, `NPM_TOKEN`); caller env keys hitting deny → hard error (tokens can never ride `env`). Output redaction regex `(token|secret|password|api[_-]?key)\s*[:=]\s*\S+` → `[REDACTED]`.

## Phase 3 — Approval gate + git

- **Tiers:** every tool declares `read` / `write` / `exec` (safe default for unknown: `exec`).
- **Three-input resolution** (oh-my-pi model): tool declaration → tool policy (allow/deny/prompt, argument-dependent patterns) → user policy (`[tools.approval.<tool>]`), then active mode (always-ask: auto read; write: auto read+write; **yolo**: auto all).
- **Safety overrides always prompt even in YOLO:** `rm -rf /`-class deletes, writes to `~/.ssh`, fork-bomb shapes, remote-fetch-then-execute, `git add -A`/`.` staging, private-key staging.
- **Scope:** project `.yl/policy.toml` overrides global `config/runtime.toml` `[tools.approval]`; CLI `--yolo` requires one-time risk ack (state file flag).
- **MCP surface:** `approval.request` tool + approval prompt surfacing via elicitation when the client supports it, else queued decision with audit.
- **Git tools:** `git.status/diff/log/show/branch/root` presets (`status --porcelain=v2 --branch`, `log --oneline -n 20`), `git.run` for explicit args; deny-list + network markers honored; runs through `execute` caps.
- **Audit:** every approval decision (granted/denied/prompted, policy source) is an `AuditEvent`; approval state joins capability grants.

## Phase 4 — Undo + batch + agent guidance

- **Undo journal (simplified, disk-backed):** snapshot-before records (`write{path, bytes, mode, expect-hash}`, `remove`, `rename{identity}`, `mkdir`, `rmdir-if-empty`); spill-dir persistence (survives restart, fixes j0hanz's in-memory gap); 30-min TTL, 64 entries / 32 MiB budget; restore newest-first, reverse capture order, **skip-not-fail** with precise reasons; `undo(id?, steps?, dry_run?)`; per-path abandonment (`undoUnavailable: reason`) never sinks the batch.
- **`batch`** (1..16 mixed calls, no nesting) and **`multi_search`** (1..16), per-entry error isolation, `index`/`label` matching; striped per-path locks so same-file edits serialize.
- **`QUICK.md`** agent guidance + server `instructions`: batch-first, filesystem-first, read-before-edit, use process tool for long waits.

## Dependencies (workspace)

`diffy 0.5.2` (Myers patch + git PatchSet), `ignore 0.4.34` + `globset 0.4.20` + `regex`, `tempfile`, `sha2`, `windows` (Job Objects; already present), existing tokio/serde/tracing.

## Testing

- Unit: EOL-preserving edit algorithm, occurrence counting, bigram-Dice closest-match, containment rejections (ADS/device/trailing-dot), secret GlobSet, env deny, cursor paging, ring trim.
- Integration (`tests/` per PRD §21): temp-dir end-to-end per tool via testkit; path-escape attempts (symlink out, `..`, UNC, ADS); approval resolution matrix (tier × policy × mode × override); process spawn/kill/tree-cleanup on Windows.
- Conformance: rmcp tool listing includes every PRD §13.1-defined tool name (`docs/spec/YL-Agent-Runtime-Specification-v0.2.md`).

## Conformance & tool naming

The PRD v0.2.0 now lives **in-repo at `docs/spec/YL-Agent-Runtime-Specification-v0.2.md`**. PRD §13.1 tool names are canonical where the PRD defines them (`workspace.read_file`, `workspace.write_file`, `workspace.search`, `workspace.list`, `process.exec`, `process.start`, `process.wait`, `process.terminate`, `process.discover_tools`, `git.status`, `git.diff`, `git.commit`, `approval.request`, `runtime.status`, `runtime.capabilities`). This design's tool tables are a superset: richer names (`workspace.edit`, `workspace.patch`, `workspace.stat`, …) extend the set, and PRD `process.wait` semantics are covered by `process.read` (`wait_ms`) + `process.status`. The conformance test asserts every PRD-defined name is registered; `terminal.*` tools are **deferred** to a later phase (runtime-terminal is currently Unix-only and a portable PTY is its own project, ADR-005).

## Resolved design decisions (builder check)

1. **Root provisioning (Q1):** roots come from repeatable `yl mcp --root <dir>` flags (primary, matching the official server's drop-in UX) plus `[workspace] roots = [...]` in `config/runtime.toml` for persistent defaults; read-only dirs via `--read-only-root` + `[workspace] read_only_roots`. **Zero roots = fail closed**: every path-taking tool refuses with an actionable error naming how to add roots; the server never implicitly trusts cwd. The spill dir is added internally as a read root (not operator-visible config).
2. **Approval interaction (Q2):** non-blocking **queued** model — a gated call returns a pending `approval_id`; the agent re-polls via `approval.request`. When the client supports elicitation, one interactive round is offered instead. Human answers via client UI or `yl approval approve <id>` CLI. **Auto-deny at expiry** (30 min, matching the existing `ApprovalBrokerImpl`). Blocking a `tools/call` for a human is never done.
3. **Project policy trust (Q3):** `.yl/policy.toml` is **not trusted by default** — a hostile repo cannot ship permissive policy. Operator trust-marks a project policy once (`yl policy trust <path>` records its hash in global config; re-prompt on hash change). Secret-blocking relief switches (allow lists) and any policy relaxation live **only in operator global config**, never in project files.
4. **Identity (Q4):** synthetic per-process principal — `AgentId("mcp-local")`, one `SessionId` per server run — recorded in audit and approval events. The identity/pairing stack stays out of scope until remote transport. Tool calls route through the existing `WorkspaceService` / `ProcessServiceOps` trait boundaries; `path_safety.rs` is upgraded in place (typed access modes, drive canonicalization, realpath re-containment) so validation is never duplicated.
5. **Process architecture (Q5):** `runtime-process` is rewritten **in place** (seq-chunk registry, tokio pump tasks, Job Objects, stdin guard); `backend-native` delegates to it so Job Objects live in one place. MCP-driven `execute` maps to `ExecutionProfile::Development` → native backend; the design's earlier "trusted→native" wording is corrected.
6. **Daemon scope (Q7):** `yl mcp` is a **self-contained single-process server** hosting all services in-process — `yl start`/`status` remain minimal in Phase 1; daemon lifecycle + IPC is deferred to the remote/desktop phase. Process/cursor state intentionally does not survive disconnects (kill-on-close is the point).
7. **Approval mode (Q8):** mode is **startup-only** (CLI flag + config), never runtime-mutable by a tool call (that would be a bypass path). `--yolo` requires a one-time ack: first use without ack fails with instructions to run `yl mcp --i-understand-yolo-risks` once, which writes the state flag. Mode + policy-file hash are audited at startup.
8. **Batch gating (Q9):** each sub-call is resolved individually through tier/policy/mode; all `prompt` decisions within one batch are aggregated into a **single** elicitation question (or one queued group with per-sub-call pending ids) so batch-first usage never causes prompt storms. Read-tier sub-calls never prompt in any mode.



- Exact JSON schema casing (snake_case params chosen; rmcp derives camelCase aliases where trivial).
- Spill directory location (`%TEMP%\yl-runtime\spill\<config-hash>`).
- Cursor format (base64url of canonicalized args hash).
