# Phase 2 — Process & Shell Execution Implementation Plan

> **Goal:** Add real command execution to YL Agent Runtime so an MCP-connected agent can run builds, installs, git, and tests inside registered workspace roots — with executable allowlisting, timeouts, Windows Job Object process-tree cleanup, and stdout/stderr streaming.
>
> **Source of good patterns:** `E:\ylstack-space\Developments\ai\agents_tools\projects\yl-agent-runtime` (their `process.rs`, `registry.rs`, `workspace.rs`, `main.rs`, `CURRENT_FEATURES.md`, `WINDOWS_SECURITY_NOTES.md`) — a working Rust runtime with proven process execution on Windows.
>
> **Our adaptation:** Route through MCP stdio tools (not CLI-only), gate through `RuntimeDaemon` + existing `path_safety.rs` containment, route approval through the existing `runtime-approval` crate stub, and keep `runtime-core` trait signatures unchanged.

---

## Constraints (binding)

- Windows is acceptance platform; POSIX compile-green only.
- No crate restructuring; no new workspace members.
- schemars 0.8 vs rmcp 1.x — never derive JsonSchema for core types; explicit `input_schema = Arc::new(...)`.
- Direct argv execution only — **no implicit shell** (avoids PowerShell `&&` parser errors).
- Every path tool resolves through `validator.validate_access(project_id, path, AccessMode::Read/Write)`.
- Every mutating call records one `AuditEvent`; audit failures log warning, never fail the call.
- Direct `Command::spawn` → assign to Windows Job Object **before** resuming (suspended creation preferred to close spawn-to-assignment race).
- Env: whitelist inherit (PATH, SYSTEMROOT, TEMP, USERPROFILE, APPDATA, ProgramFiles*, COMSPEC); deny `*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*KEY*`, `AWS_*`, `AZURE_*`, `GITHUB_*`, `NPM_TOKEN`; caller-supplied `env` keys hitting deny → hard error.
- Output redaction regex `(token|secret|password|api[_-]?key)\s*[:=]\s*\S+` → `[REDACTED]`.
- Spill-overflow: inline head+tail (30 KB per stream) + spill file in read roots for full output.

---

## File map (create/modify)

| File | Action | Responsibility |
|------|--------|----------------|
| `crates/runtime-process/Cargo.toml` | Modify | Add `windows-sys` (Job Objects) + `cap-std` optional, keep workspace deps |
| `crates/runtime-process/src/lib.rs` | Modify | Re-export process modules; keep `ProcessService` trait |
| `crates/runtime-process/src/process.rs` | Create | Executable allowlist, direct `Command::spawn`, Job Object (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`), timeouts, env whitelist/deny, output redaction, spill overflow |
| `crates/runtime-process/src/cursor.rs` | Create | Seq-chunk ring buffer (4 MB), `after`/`next_after`/`cursor_lost`, split stdout/stderr, condvar-free tokio pump tasks |
| `crates/runtime-daemon/src/daemon.rs` | Modify | Register process service in backends; expose `process_service` to MCP server |
| `crates/runtime-mcp/src/server.rs` | Modify | Add `process.execute`, `process.start`, `process.read`, `process.stop`, `process.list`, `process.discover_tools` tools |
| `crates/runtime-cli/src/main.rs` | Modify | Add `yl exec` subcommand (project, program, args, approve, timeout) |
| `crates/runtime-cli/src/commands.rs` | Modify | Implement `exec` command |
| `crates/runtime-cli/Cargo.toml` | Modify | Add `runtime-process` dep |
| `tests/process/` | Create | End-to-end process tests |

---

## Interfaces (exact, consumed by MCP tools)

```rust
// runtime-process
pub struct ProcessConfig {
    pub allowlist: Vec<String>,          // cargo, rustc, rustup, git, node, bun, python, python3, py, go, dotnet, cmake, ninja, java, javac
    pub env_whitelist: Vec<String>,      // PATH, SYSTEMROOT, TEMP, USERPROFILE, APPDATA, ProgramFiles*, COMSPEC
    pub env_deny: Vec<String>,           // *TOKEN*, *SECRET*, *PASSWORD*, *KEY*, AWS_*, AZURE_*, GITHUB_*, NPM_TOKEN
    pub default_timeout_secs: u64,       // 300
    pub max_timeout_secs: u64,           // 3600
    pub max_output_bytes: u64,           // 30_000 inline + spill
    pub ring_buffer_bytes: u64,          // 4_000_000
}

pub struct ProcessSpec {
    pub project_id: ProjectId,
    pub program: String,                 // executable name only (no path separators)
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,            // relative to project root
    pub timeout_secs: Option<u64>,
    pub approve: bool,                   // required unless YOLO
}

pub struct ProcessHandle {
    pub process_id: String,              // "proc-" + 10 hex
    pub pid: u32,
    pub state: ProcessState,             // running / exited
    pub exit_code: Option<i32>,
    pub started_at: DateTime<Utc>,
}

pub struct ProcessOutput {
    pub process_id: String,
    pub oldest_sequence: u64,
    pub cursor_lost: bool,
    pub next_after: Option<u64>,
    pub truncated: bool,
    pub stdout: String,                  // inline head+tail
    pub stderr: String,
    pub stdout_path: Option<String>,     // spill file (added to read roots)
    pub stderr_path: Option<String>,
    pub duration_ms: u64,
}

pub trait ProcessService: Send + Sync {
    fn discover_tools(&self) -> Vec<String>;
    async fn start(&self, spec: ProcessSpec) -> Result<ProcessHandle>;
    async fn read(&self, process_id: &str, after: Option<u64>, limit_bytes: Option<u64>, wait_ms: Option<u64>) -> Result<ProcessOutput>;
    async fn stop(&self, process_id: &str, force: bool) -> Result<()>;
    async fn list(&self) -> Result<Vec<ProcessHandle>>;
}
```

---

## Tasks

### Task 2.1: Process service core (allowlist, spawn, Job Objects, env)

**Files:** Create `crates/runtime-process/src/process.rs`; modify `crates/runtime-process/Cargo.toml`, `crates/runtime-process/src/lib.rs`

Implement:
- `ProcessConfig` with allowlist (cargo, rustc, rustup, git, node, bun, python, python3, py, go, dotnet, cmake, ninja, java, javac)
- `resolve_executable(name)` — name only, no path separators, search PATH with `.exe`/`.com` on Windows
- `Command::spawn` with `stdout/Stderr::piped()`, `kill_on_drop(true)`, `env_clear()` + whitelist restore
- Windows Job Object: `CreateJobObjectW` + `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` + `AssignProcessToJobObject` — spawn **suspended**, assign, then resume (closes spawn-to-assignment race)
- Env deny: `*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*KEY*`, `AWS_*`, `AZURE_*`, `GITHUB_*`, `NPM_TOKEN` → hard error
- Output redaction regex → `[REDACTED]`
- Spill overflow: inline 30 KB head+tail per stream, full output to spill file added to read roots
- Timeout: graceful terminate → 10 s → force kill; Job Object cleanup

**Tests:** executable allowlist acceptance/rejection, PATH resolution, env deny, Job Object assignment (Windows), timeout termination, spill file creation.

### Task 2.2: Cursor-paged process log (seq chunks)

**Files:** Create `crates/runtime-process/src/cursor.rs`

Implement:
- Per-process seq-chunk ring buffer (4 MB raw bytes)
- Split stdout/stderr streams
- `after`/`next_after`/`oldest_sequence`/`cursor_lost`/`truncated`
- tokio pump tasks (no condvar polling)
- Process registry GC: TTL 1 h exited, max 50 processes

**Tests:** cursor paging, ring buffer truncation, cursor lost detection, process GC.

### Task 2.3: Wire ProcessService into RuntimeDaemon + MCP tools

**Files:** Modify `crates/runtime-daemon/src/daemon.rs`, `crates/runtime-mcp/src/server.rs`

Implement:
- `RuntimeDaemon` holds `Arc<dyn ProcessService>`; register in `new()`
- MCP tools: `process.execute` (sync, wait for completion), `process.start`, `process.read`, `process.stop`, `process.list`, `process.discover_tools`
- Each tool: `Parameters<JsonObject>`, `normalize_args` aliases, explicit `input_schema`
- Mutating tools record `AuditEvent`; failures → `tracing::warn!`
- Zero roots → `invalid("No workspace roots configured")`

**Tests:** MCP tool listing includes all process tools; execute returns exit_code/stdout/stderr; start/read/stop lifecycle; discover_tools returns installed toolchains.

### Task 2.4: CLI `yl exec` subcommand

**Files:** Modify `crates/runtime-cli/src/main.rs`, `crates/runtime-cli/src/commands.rs`, `crates/runtime-cli/Cargo.toml`

Implement:
- `Commands::Exec { project, program, args, approve, timeout }`
- Requires `--approve` unless YOLO mode
- Prints exit code, stdout, stderr, duration

**Tests:** `yl exec <project> cargo --approve -- --version` works; without `--approve` errors; unknown executable errors.

### Task 2.5: E2E integration tests (real stdio client)

**Files:** Create `tests/process/` or extend `crates/runtime-cli/tests/mcp_stdio.rs`

Implement:
- Spawn `yl mcp --root <tmp>`, call `process.execute` with `cargo --version`
- Call `process.start` + `process.read` cursor paging
- Call `process.stop`
- Test env deny blocks `AWS_SECRET_ACCESS_KEY`
- Test path escape rejection

**Tests:** All 7+ E2E tests pass against real binary.

---

## Self-review checklist

- [ ] Direct argv only — no `shell=true`, no `cmd /c`, no `powershell -Command`
- [ ] Executable allowlist enforced (name only, no path separators)
- [ ] Windows Job Object assigned before process resume (suspended creation)
- [ ] Env deny list blocks tokens; caller env keys hitting deny → hard error
- [ ] Output redaction regex applied
- [ ] Spill overflow: inline head+tail + spill file path in read roots
- [ ] Timeout: graceful → 10 s → force kill
- [ ] Every mutating call → AuditEvent (best-effort, never fails call)
- [ ] Zero roots → fail closed
- [ ] All tests green: `cargo test --workspace --exclude backend-linux --exclude backend-macos --exclude runtime-terminal --exclude backend-windows`

---

## What this does NOT cover (Phase 3+)

- Full approval gate with project/global policy files, `.yl/policy.toml` trust-marks, YOLO CLI flag, `approval.request` MCP tool — Phase 3
- Git tools (`git.status`, `git.diff`, etc.) — Phase 3
- Undo journal + batch/multi_search — Phase 4
- Terminal/PTY tools — deferred (runtime-terminal is Unix-only)
- OS sandbox backends (AppContainer/Landlock/Seatbelt) — separate backend work

---
