# YL Agent Runtime — next session plan

## DONE this session (runtime-mcp rmcp 3.10 blocker)
- Read & understood HANDOFF.md + repo layout.
- Rewrote `crates/runtime-mcp/src/server.rs` against rmcp 3.10 API:
  - `get_info(&self) -> ServerConfig` (sync; `ServerInfo`→`ServerConfig`)
  - `#[tool_handler]` on `impl ServerHandler for McpServer` (auto-gen `call_tool`/`list_tools`/`get_tool`/`get_info`)
  - `#[tool_router] impl McpServer` with `#[tool]` methods taking `Parameters<T>`
  - Tools return `std::result::Result<CallToolResult, rmcp::ErrorData>`
- Added `macros` feature to workspace `rmcp` dep (needed for `#[tool]`/`#[tool_handler]`/`#[tool_router]` proc macros)
- Fixed schemars version conflict (workspace 0.8 vs rmcp 1.2.3): use explicit `input_schema` as `Arc<JsonObject>` instead of `JsonSchema` on `Args`
- Fixed pre-existing errors now visible since runtime-mcp compiles:
  - `runtime-core/src/types.rs`: `Capability` derives `JsonSchema` (0.8)
  - `runtime-core/src/audit.rs`: `AuditEventType` derives `JsonSchema` (0.8)
  - `runtime-mcp/src/tools.rs`: import `AuditEventType`
  - `runtime-daemon/src/daemon.rs`: `toolchain_discovery` is concrete `ToolchainDiscovery` struct (not dyn)
  - `runtime-policy/workspace/terminal/process/lib.rs`: re-export `PolicyEngineImpl`/`WorkspaceServiceImpl`/`TerminalServiceImpl`/`ProcessServiceOps`
  - `runtime-testkit/src/fixtures.rs`: `CapabilityGrant`/`ExecutionProfileConfig` at `runtime_core::*`
  - `runtime-cli/src/main.rs`: `use crate::commands;` (removed redundant import causing redefinition)

## VERIFICATION
- `cargo check -p runtime-mcp` — 0 errors
- `cargo check -p runtime-cli -p runtime-daemon -p runtime-testkit` — 0 errors
- `cargo check --workspace --exclude backend-linux --exclude backend-macos --exclude runtime-terminal --exclude backend-windows` — 0 errors
- Remaining failures are EXPECTED on Windows: `backend-linux`/`backend-macos`/`runtime-terminal` (Unix-only), `backend-windows` (pre-existing stub, not in handoff's compiling list), `landlock`/`core-foundation` (Unix deps)

## NEXT (per HANDOFF.md goal)
1. Implement `runtime-cli` daemon commands (`start`, `status`, `discover-tools`, `pair`, `mcp` are no-op prints in `crates/runtime-cli/src/commands.rs`)
2. Wire daemon backend selection (`RuntimeDaemon::select_backend` → register backends → policy→backend→process)
3. Finish `runtime-workspace` dead code / unused var warnings
4. Add integration/conformance tests under `tests/`

## NOTES
- `cargo check --exclude runtime-mcp` no longer needed (runtime-mcp now compiles)
- 33 uncommitted build-fix files + HANDOFF.md remain uncommitted (one commit `ec61107`)
- Suggested commit message in HANDOFF.md still applies
