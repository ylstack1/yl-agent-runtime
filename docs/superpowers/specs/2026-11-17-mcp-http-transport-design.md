# YL Agent Runtime — MCP Streamable HTTP Transport Design

**Date:** 2026-11-17
**Status:** Approved (operator said "do best")
**Branch:** phase2-process-shell (will merge to master after build)

## Intent

Serve the YL Agent Runtime MCP server over Streamable HTTP (rmcp 3.10) so remote MCP clients can connect over the network, in addition to the existing stdio transport.

## Constraints (binding)

- MCP spec 2026-07-28 Streamable HTTP: single POST endpoint (`/mcp`), stateless by default, JSON or SSE response, Origin header validation (DNS rebinding protection), bind to localhost by default
- rmcp 3.10 `transport-streamable-http-server` feature → `StreamableHttpService` (Tower service)
- No crate restructuring; no new workspace members
- Existing `Config.transport` fields (`http_bind_address`, `http_port`, `enable_streamable_http`) already exist — wire them up
- `McpServer` already implements `ServerHandler` — works with rmcp's server factory directly
- Stateless mode: fresh server per request, no session state (matches our single-process stdio design)

## Files

| File | Action | Responsibility |
|------|--------|----------------|
| `Cargo.toml` (root) | Modify | Add `axum`, `tower-http`; enable `rmcp` feature `transport-streamable-http-server` |
| `crates/runtime-cli/src/main.rs` | Modify | Add `Serve` subcommand (`--host`, `--port`) |
| `crates/runtime-cli/src/commands.rs` | Modify | Implement `run_http_server()` — build axum router, mount `StreamableHttpService`, bind TCP |
| `crates/runtime-cli/Cargo.toml` | Modify | Add `axum`, `tower-http` deps |
| `crates/runtime-mcp/src/server.rs` | No change | `McpServer` already implements `ServerHandler` |

## Security

- Origin header validation → 403 on invalid origin (DNS rebinding protection)
- Bind to 127.0.0.1 by default; `--allow-remote` opts into 0.0.0.0
- Config `transport.http_bind_address` / `http_port` drive defaults

## Not in scope

- Approval gate (Phase 3)
- Git tools (Phase 3)
- Undo/batch (Phase 4)
- OS sandbox backends (separate)
