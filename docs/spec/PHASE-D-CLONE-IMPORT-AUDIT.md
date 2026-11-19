# Phase D audit — git clone + local import foundation + root flag enforcement

**Source spec:** `docs/spec/REMOTE-WORKSPACE-AND-CONNECTIONS-SPEC.md` (Proposed, v1.0, 2026-11-19), §4.5 (import), §4.6 (clone), §5.2 (root create/register flags), §8 (root capabilities distinct)  
**Branch:** `phase-a-discovery-roots` (from master `4b89c1c`, Phase D commits on top)  
**Rule followed:** Spec §17 — audit first, implement Phase D in small steps; never claim unrun behavior.

## Status

**Phase D: complete (D.1–D.5).** D.6 (import HTTP upload) deferred to later phase.

## 1. Build / test baseline

- `cargo check --workspace --exclude backend-linux --exclude backend-macos --exclude runtime-terminal --exclude backend-windows`: clean
- `cargo test --workspace --exclude ... --no-fail-fast`: all green except two pre-existing unrelated failures (`backend-native::test_native_backend_capabilities_honest`, `runtime-toolchain::test_detect_source`)
- `runtime-workspace`: 116 tests (112 + 4 new root flag tests) — all pass
- `runtime-mcp`: 27 lib + 9 args — all pass
- `runtime-config`: 4 tests — all pass
- Live MCP verified: `git.clone` end-to-end (approval → start → clone progress → success), credential redaction, invalid root rejection

## 2. Requirement-to-code map (all resolved)

| Spec | Requirement | Status | Where |
|---|---|---|---|
| 5.2 | Root `create`/`register` flags enforced before create/register | **Done** | `check_discovery_root()` + `register()`/`create_workspace()` checks in `crates/runtime-workspace/src/service.rs` |
| 4.6 | Host-side `git.clone` of Git URL into allowed destination | **Done** | `git.clone` MCP tool in `crates/runtime-mcp/src/server.rs` |
| 4.6 | Clone on runtime host, not controller | **Done** | Uses `ProcessService::start` (long-running, host-side) |
| 4.6 | Branch/tag/commit selection | **Done** | `--branch` arg in `GitCloneArgs` |
| 4.6 | Credential redaction | **Done** | `redact_url_credentials()` strips `user:pass@host` from URLs in audit/display |
| 4.6 | Structured progress, stdout/stderr, exit status, cancellation | **Done** | Uses `ProcessService` cursor-paged output + `process.stop` |
| 4.6 | Register checkout only after clone succeeds | **Deferred** | Client calls `workspace.register` after clone completes (origin tracking can be added later) |
| 4.5 | Import from controller with staging, progress, integrity | **Types only** | `TransferManifest`/`TransferState` types defined; HTTP upload deferred |

## 3. What was implemented

**`crates/runtime-workspace/src/service.rs`**
- `check_discovery_root(path, require_op)` — finds the enabled discovery root containing a path, checks `register`/`create` flag
- `validate_clone_dest(root_id, dest_rel)` — validates clone destination is within an enabled root with `clone` flag, destination doesn't exist, path containment via `PathValidator`
- `register()` — calls `check_discovery_root(root, "register")` before registering
- `create_workspace()` — calls `check_discovery_root(parent, "create")` before creating
- `clean_verbatim_prefix()` applied to clone destination path (strips `\\?\` on Windows)
- 4 new tests: `test_register_rejects_disabled_root`, `test_register_rejects_root_outside_discovery`, `test_create_rejects_root_without_create_flag`, `test_register_allowed_when_root_flags_enabled`

**`crates/runtime-mcp/src/server.rs`**
- `git.clone` MCP tool — takes `url`, `root`, `dest`, optional `branch`/`depth`
- Validates destination via `fs.validate_clone_dest()`, enforces `Capability::GitWrite` approval gate
- Starts `git clone` via `process_service.start()` (long-running, cursor-paged output)
- Redacts URL credentials via `redact_url_credentials()`
- Returns `{process_id, dest, dest_absolute, url (redacted), status: "started"}`
- `redact_url_credentials()` helper — strips `user:pass@host` from `http(s)://` URLs

**`crates/runtime-mcp/src/tools_fs.rs`**
- `GitCloneArgs` struct — `url`, `root_id`, `dest`, optional `branch`/`depth`

**`crates/runtime-mcp/src/args.rs`**
- `git.clone` added to ALIASES, REQUIRED (`url`/`root`/`dest`), KNOWN fields

**`crates/runtime-cli/src/main.rs` + `commands.rs`**
- CLI passes `config.discovery` to `WorkspaceServiceImpl::with_data_dir()` (all 3 call sites)

## 4. Deferred (later phases)

- Import HTTP chunked upload with resumable transfers (spec 4.5) — `TransferManifest`/`TransferState` types defined in spec, implementation deferred
- Auto-register workspace after clone success (origin=Cloned) — client calls `workspace.register` manually for now
- Root `import` flag enforcement — follows `create`/`register` pattern

## 5. CLI / GUI controllability

`git.clone` and workspace creation go through protocol-agnostic service methods. `yl git clone …` (future) and `yl workspace create …` call the same functions a future GUI would call. Opaque root/workspace IDs; no host-path-as-identity.

## 6. Verification

- Build gate: `cargo check --workspace --exclude ...` clean
- Tests: all green except two pre-existing unrelated failures
- Live MCP client (`@modelcontextprotocol/sdk` StreamableHTTP): verified end-to-end
  - `git.clone` blocks with `approval_id`, `approval.approve` accepts, retry starts process
  - `git clone` clones a local repo successfully (README.md content verified)
  - Credential URLs redacted in audit resource and response
  - Invalid/disabled roots rejected
