# Phase C audit — workspace registry with persistence + create empty project

**Source spec:** `docs/spec/REMOTE-WORKSPACE-AND-CONNECTIONS-SPEC.md` (Proposed, v1.0, 2026-11-19), §4.4 (create), §4.7 (workspace management), §5.2 (per-root register/create flags), §8 (root capabilities distinct)  
**Branch:** `phase-a-discovery-roots` (HEAD `9f20fde` → Phase C commits)  
**Rule followed:** Spec §17 — audit first, implement Phase C in small steps; never claim unrun behavior.

## Status

**Phase C: complete.** All milestones implemented, tested, committed.

## 1. Build / test baseline

- `cargo check --workspace --exclude backend-linux --exclude backend-macos --exclude runtime-terminal --exclude backend-windows`: clean
- `cargo test --workspace --exclude ... --no-fail-fast`: all green except two pre-existing unrelated failures (`backend-native::test_native_backend_capabilities_honest`, `runtime-toolchain::test_detect_source`)
- `runtime-workspace`: 112 tests (105 existing + 7 Phase C) — all pass
- `runtime-mcp`: 27 lib + 9 args — all pass
- `runtime-config`: 4 tests — all pass
- Live MCP verification via `@modelcontextprotocol/sdk`: `workspace.register` approval flow (block → approve → retry succeeds) confirmed through real StreamableHTTP client

## 2. Requirement-to-code map (all resolved)

| Spec | Requirement | Status | Where |
|---|---|---|---|
| 4.7 | List registered workspaces (opaque ID + safe display metadata) | **Done** | `WorkspaceServiceImpl::list_workspaces()` → `Vec<WorkspaceRecord>` |
| 4.7 | Get workspace by ID | **Done** | `WorkspaceServiceImpl::get_workspace()` (public) |
| 4.7 | Unregister workspace (remove registry association, never delete files) | **Done** | `WorkspaceServiceImpl::unregister()` + persistence |
| 4.7 | Registry persistence across daemon restarts | **Done** | `<data_dir>/workspaces.jsonl`, `with_data_dir()` constructor, auto-save on register/create/unregister |
| 4.7 | Workspace record: display name, origin, timestamps, tags | **Done** | `RegisteredWorkspace` gains `display_name`, `origin`, `last_opened`, `tags`; `WorkspaceOrigin` enum |
| 4.4 | Create empty project dir under parent; validate name/collisions; register after create | **Done** | `WorkspaceServiceImpl::create_workspace(parent, name, profile, subdirs)` |
| 5.2 | Root `create`/`register` flags | **Exists in config** (Phase B) — enforcement deferred | `DiscoveryRoot.create`/`register` in `runtime-config` |
| 8 | `WorkspaceRegister` capability wired to approval gate | **Done** | `workspace.register` MCP tool calls `enforce_tool(Capability::WorkspaceRegister, ...)` |

## 3. What was implemented

**`crates/runtime-workspace/src/service.rs`**
- `WorkspaceOrigin` enum (Registered/Created/Imported/Cloned)
- `WorkspaceRecord` struct (safe display metadata for clients)
- `RegisteredWorkspace` gains `display_name`, `origin`, `last_opened`, `tags`
- `WorkspaceServiceImpl::with_data_dir(data_dir)` — loads registry from `<data_dir>/workspaces.jsonl` on construction
- `persist_registry()` — full JSONL rewrite after any mutation
- `register()` — sets new fields, persists
- `unregister()` — persists
- `get_workspace()` — made public
- `list_workspaces()` — returns `Vec<WorkspaceRecord>` (no absolute host path leakage)
- `create_workspace(parent, name, profile, subdirs)` — validates name (no traversal/reserved/separators), validates parent, rejects existing destination, creates dir + subdirs, registers as `WorkspaceOrigin::Created`, persists
- 7 new tests (list/get/create/reject existing/reject bad names/persistence reload/unregister persists) — all pass

**`crates/runtime-mcp/src/server.rs`**
- `workspace.register` MCP tool — takes `path` + optional `profile`, validates path exists/is dir, enforces `Capability::WorkspaceRegister` approval gate, calls `fs.register()`, records audit event, returns `id`/`path`/`profile`
- Live-verified: blocked pending approval → `approval.approve` → retry succeeds

**`crates/runtime-mcp/src/args.rs`**
- `workspace.register` added to ALIASES (`directory`/`dir` → `path`), REQUIRED (`path`), KNOWN fields

**`crates/runtime-cli/src/main.rs` + `commands.rs`**
- `yl workspace list` — lists registered workspaces with id/display_name/origin/profile/root
- `yl workspace register <path>` — registers an existing directory
- `yl workspace unregister <id>` — unregisters by UUID (does not delete files)
- `yl workspace create <parent> <name>` — creates new empty project dir + registers
- CLI `WorkspaceServiceImpl` uses `with_data_dir(config.data_dir)` for persistence
- `run_mcp_server` and `run_http_server` use `with_data_dir(config.data_dir)` for persisted registry

## 4. Deferred (later phases)

- Root `create`/`register` flag enforcement in workspace service (currently config-only) — Phase D/E
- Workspace rename, favorite, last-opened tracking — Phase D
- Active-session safety preventing unsafe unregister — Phase D/E
- Import/clone producing workspaces — Phase D
- HTTP management API for workspaces — Phase E

## 5. CLI / GUI controllability

Every workspace operation goes through `WorkspaceServiceImpl` (protocol-agnostic). The same inherent methods back `yl workspace …` CLI commands and can back a future desktop controller GUI. Opaque `ProjectId` used throughout; clients never construct host paths as workspace identity. MCP `workspace.register` and CLI `workspace register` both call `fs.register()` with the same approval gate.

## 6. Verification

- Build gate: `cargo check --workspace --exclude backend-linux --exclude backend-macos --exclude runtime-terminal --exclude backend-windows` clean
- Tests: all green except two pre-existing unrelated failures
- Live MCP client (`@modelcontextprotocol/sdk` StreamableHTTP): 39 tools advertised (incl. `workspace.register`); `workspace.register` correctly blocks with `approval_id`, `approval.approve` accepts, retry succeeds
