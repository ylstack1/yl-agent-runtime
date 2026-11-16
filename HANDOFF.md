# Handoff — YL Agent Runtime (standalone repo)

**Path:** `E:\ylstack-space\Developments\ai\agents_app\yl-agent-runtime`  
**Remote:** `https://github.com/ylstack1/yl-agent-runtime` (origin, intact)  
**Status:** Phase 0 skeleton (PRD v0.2.0). Core compiles on Windows; MCP CLI and Unix backends are stubs/broken.  
**Last session:** Moved repo out of `YL-COS/` to standalone path; fixed ~30 manifest/source bugs so the core set compiles.

---

## Goal (next session)

Get the whole workspace compiling on Windows, then implement the missing pieces:

1. **Fix `runtime-mcp`** — current stub does not match `rmcp 3.10` (31 errors). Either rewrite against `rmcp 3.10` (`ServerConfig`, `InitializeResult`, `tool_handler` signature changes) or downgrade `rmcp` to a version the stub matches. `runtime-cli`, `runtime-daemon`, and `runtime-testkit` depend on it.
2. **Implement `runtime-cli` daemon commands** — `start`, `status`, `discover-tools`, `pair`, `mcp` are currently no-op prints.
3. **Implement Unix backends** (`backend-linux` via Landlock/seccomp/cgroups, `backend-macos` via Seatbelt) — currently stubs; `cgroups`, `landlock`, `seccomp` dep versions were pinned to existent ones (0.1/0.4/0.1).
4. **Wire daemon backend selection** — `RuntimeDaemon::select_backend` exists but nothing registers backends or wires policy→backend→process.
5. **Finish `runtime-workspace`** — ops (`search`, `find_files`, `get_tree`, `copy_entry`, `delete`, `replace_text`) compile but have unused vars / dead code warnings; tests exist.
6. **Add integration/conformance tests** — `tests/` dirs exist in README but are empty.

---

## What compiles now (Windows, exit 0)

These crates check cleanly (warnings only):

```
runtime-core runtime-policy runtime-workspace runtime-process runtime-audit
runtime-identity runtime-approval runtime-config runtime-backend-api
runtime-protocol runtime-transport backend-native backend-arapuca backend-virtx
runtime-toolchain
```

**Does NOT compile:** `runtime-mcp` (31 errors), `runtime-cli`, `runtime-daemon`, `runtime-testkit` (depend on `runtime-mcp`), `backend-linux`/`backend-macos`/`runtime-terminal` (Unix-only, can't build on Windows).

## Key build fixes already applied

- `Cargo.toml` `[workspace.lints]` → `[workspace.lints.clippy]` (quoted clippy keys).
- Removed invalid `[target.'cfg(...)'.workspace.dependencies]` sections (virtual manifest); moved `windows`/`libc`/`nix`/`landlock`/`seccomp`/`cgroups`/`core-foundation`/`security-framework` into `[workspace.dependencies]`.
- Pinned existent versions: `figment 0.10`, `x25519-dalek 3.0`, `cgroups 0.1`, `landlock 0.4`, `seccomp 0.1`, `rmcp 3.10` (features `["server"]`), `iroh 1.4` (plain), `tokio-util 0.7` (`codec, io`), `portable-pty 0.9` (plain), `nix 0.28` (plain).
- Fixed invalid `windows-rs 0.59` features: dropped `Win32_System_ProcessSnapshot` (not a feature), `Win32_System_Token`; added `Win32_Security_Authorization` for `OpenProcessToken`/`GetTokenInformation`.
- `runtime-core`: `types.rs` re-exports `DateTime`/`Utc`; `traits.rs` imports `serde` + `AuditEvent`/`AuditFilter`; `session.rs` imports `CapabilityGrant` from `traits`; `platform.rs` Windows token calls use correct paths (`System::Threading::OpenProcessToken`, `Security::GetTokenInformation` with `Some(...)`) and `HANDLE::default()`.
- Broke cycles: `runtime-identity` no longer depends on `runtime-audit`; `runtime-backend-api`/`runtime-process`/`backend-native` pruned unused path deps.
- `runtime-process`: `TrackedProcess` gained `handle: Arc<Mutex<Option<Child>>>` + manual `Clone` (derive `Clone` removed); `start()` stores child; `wait()`/`terminate()` use lock + `child.kill()`; `exec()` builds `ProcessStatus` from `ExitStatus`.
- `runtime-backend-api`: `ProcessHandle` gained `status: ProcessStatus` field.
- `runtime-policy`: `engine.rs` imports `CapabilityGrant`/`ExecutionProfileConfig` from `runtime_core` (not `types`/`capability`); `.await` on store calls; `lib.rs` re-exports `PolicyEngine` from `runtime_core::traits`; `store.rs` uses `runtime_core::CapabilityGrant`.
- `runtime-workspace`: `get_workspace`/`get_validator` sync (`std::sync::RwLock`); `PathValidator` derives `Clone`; `PathBuf::contains` → `to_string_lossy().contains(...)`; clone before move in `list`/`stat`/`get_tree_recursive`; `lib.rs` re-exports `WorkspaceService` from `runtime_core::traits`.
- `runtime-identity`: `ApprovalState` imported from `runtime_core`; fingerprint uses hex formatting.
- `runtime-toolchain`: `cache` wrapped in `Mutex` (interior mutability for `&self` methods); fixed temp-value borrow in `find_executable`; `discover_all` returns cached toolchains.
- `backend-virtx`/`backend-arapuca`: added `async-trait = "0.1"` dep.

## Known warnings (low priority, can clean up)

- `runtime-core`: unused `HashMap` (types.rs), `Duration` (capability.rs), `HashMap` (session.rs)
- `runtime-config`: unused `HashMap`
- `runtime-identity`: `pairings` field never read
- `runtime-policy`: unused `crate::evaluator::*` / `crate::store::*` glob imports; unused `config` var
- `runtime-process`: unused `ResourceLimits`, `PathBuf`, `Mutex`, `HANDLE`
- `backend-native`: unused `PathBuf`, unnecessary `mut`
- `runtime-workspace`: unused `workspace`/`validator` vars; `PathValidator.max_file_size`; `WorkspaceWatcher.project_id`
- `runtime-transport`/`runtime-toolchain`: unused imports
- `backend-arapuca`/`backend-virtx`: unused `platform::*`, `PathBuf`

## Files changed (uncommitted, 33 files)

See `git diff --stat` in repo. Most edits are in `Cargo.toml`, `crates/runtime-core/**`, `crates/runtime-process/**`, `crates/runtime-workspace/**`, `crates/runtime-policy/**`.

## Git / workflow notes

- Repo has **one commit** (`ec61107 chore: initial project structure per YL Agent Runtime PRD v0.2.0`). All build-fix work is **uncommitted**.
- Windows line endings: Git warns `LF will be replaced by CRLF` on some files — normal on Windows.
- `cargo check` on full `--workspace` fails only because `runtime-mcp` (and its dependents) don't compile. Use `--exclude runtime-mcp` to check everything else.
- `backend-linux`/`backend-macos` can't be `cargo check`ed on Windows; they're Unix-only stubs anyway.
- `apps/desktop-tauri` is excluded from the workspace (Tauri optional).

## Repo layout (reference)

```
crates/
  runtime-core/        types, traits, errors, capability, session, audit, platform
  runtime-daemon/      RuntimeDaemon, backend selection
  runtime-cli/         yl CLI (stub commands)
  runtime-mcp/         MCP server adapter — BROKEN stub (rmcp 3.10 mismatch)
  runtime-policy/      engine, evaluator, profiles, store
  runtime-identity/    agents, devices, pairing, revocation
  runtime-approval/    ApprovalBroker impl
  runtime-workspace/   WorkspaceService + path_safety (path containment)
  runtime-process/     ProcessService + ProcessTreeSupervisor
  runtime-audit/       AuditService + AuditEvent
  runtime-config/      Config + ConfigMigrator (TOML)
  runtime-protocol/    McpToolDefinition schemas
  runtime-backend-api/ ExecutionBackend trait + types
  runtime-terminal/    PTY/ConPTY stub
  runtime-toolchain/   ToolchainDiscovery (which/where + version parse)
  runtime-transport/   local + remote (iroh) stubs
  runtime-testkit/     test fixtures
  backend-native/      host execution (no sandbox claims)
  backend-windows/     AppContainer / restricted token / Job Objects stub
  backend-linux/       Landlock/seccomp/cgroups stub (Unix-only)
  backend-macos/       Seatbelt stub (Unix-only)
  backend-arapuca/     Arapuca wrapper stub (not linked)
  backend-virtx/       Virtx VM stub
apps/
  desktop-tauri/       optional Tauri UI (excluded from workspace)
docs/
  architecture/, decisions/ (ADR-001..009), integrations/, threat-model/
```

## Suggested commit message

```
chore: fix build so platform-agnostic crates compile

- Fix workspace manifests (lints, target sections, dep versions/features)
- Break circular crate deps
- Fix core source errors (imports, types, platform calls)
- Implement process child-handle tracking
- Add JsonSchema support to core ID newtypes

Assisted-By: LLM
```

## Where to start next

Open the repo and run:

```powershell
cd E:\ylstack-space\Developments\ai\agents_app\yl-agent-runtime
cargo check --exclude runtime-mcp
```

Then tackle `runtime-mcp` server.rs — it's the blocker for `runtime-cli`/`runtime-daemon`/`runtime-testkit`. If you want to skip MCP for now, you can stub `runtime-mcp` out enough for the dependents to compile, then implement the real MCP server later.
