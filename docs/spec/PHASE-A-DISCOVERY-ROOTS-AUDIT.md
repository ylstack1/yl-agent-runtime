# Phase A audit — remote workspace discovery roots

**Source spec:** `docs/spec/REMOTE-WORKSPACE-AND-CONNECTIONS-SPEC.md` (Proposed, v1.0, 2026-11-19)  
**Branch:** `phase-a-discovery-roots` (from master `4b89c1c`)  
**Rule followed:** Spec §17 — audit first, implement Phase A then Phase B in small steps; never claim unrun behavior.

## Status

**Phase A (audit): complete.** This document is the audit.  
**Phase B (discovery roots + browse + detect + CLI): complete.** Implemented, tested, committed.

## 1. Build / test baseline

- HEAD: `4b89c1c feat(phase4): ...` on `master`, then `phase-a-discovery-roots` branch
- `cargo check --workspace --exclude backend-linux --exclude backend-macos --exclude runtime-terminal --exclude backend-windows`: clean
- `cargo test --workspace --exclude backend-linux --exclude backend-macos --exclude runtime-terminal --exclude backend-windows --no-fail-fast`: all green except two pre-existing unrelated failures (`backend-native::test_native_backend_capabilities_honest`, `runtime-toolchain::test_detect_source`)
- `runtime-workspace`: 105 tests (98 existing + 7 discovery) — all pass
- `runtime-config`: 4 tests — all pass
- `runtime-mcp`: 27 lib + 9 args — all pass
- `runtime-process`: 37 tests — all pass

## 2. Requirement-to-code map

| Spec | Requirement | Status | Where |
|---|---|---|---|
| 5.1–5.2 | Typed root config with id/label/path/enabled + per-op flags (browse/create/register/import/clone) | **Done** | `crates/runtime-config/src/config.rs`: `DiscoveryRoot`, `DiscoveryConfig`, `DiscoveryBrowseEntry`, `DiscoveryBrowseResult`, `DiscoveryProjectDetection`, `DiscoveryEntryKind`; `Config.discovery` with `#[serde(default)]`, defaults, TOML round-trip tests |
| 5.3 | Path containment, traversal/symlink/junction/ADS rejection, re-containment | **Exists — reused** | `crates/runtime-workspace/src/path_safety.rs`: `PathValidator`, `validate_access`, `ContainedPath` |
| 5.4 | Paginated root-relative browse, bounded page size | **Done** | `crates/runtime-workspace/src/discovery.rs`: `DiscoveryService::browse_root` (offset cursor, `max_entries_per_page` cap, stable sort, hidden filter) |
| 4.2 / 5.6 | Bounded project-detection marker scan (no code execution) | **Done** | `crates/runtime-workspace/src/discovery.rs`: `DiscoveryService::detect_project` (marker files, git branch, confidence, entry-count bound) |
| 4.3 / 6.2 | Workspace register / list / get / unregister; restart persistence | **Partial** — deferred to Phase C | `WorkspaceServiceImpl::register` exists (in-memory only) |
| 4.4 | Create empty project dir under allowed root | **Missing** — deferred to Phase C | — |
| 4.5 | Import from controller with staging, progress, integrity | **Missing** — deferred to Phase D | — |
| 4.6 | Host-side git clone | **Missing** — deferred to Phase D | `runtime-process` git tools exist; no `git.clone` |
| 6.2 | Versioned HTTP management API endpoints | **Missing** — deferred to Phase E | axum + rmcp on `:8077`; only `/mcp` MCP endpoint |
| 7.4 / 8 | Pairing, auth, sessions, TLS, origin validation, rate limits, audit | **Missing** — deferred to Phase E | `pair_device`/`list_devices` stubs only |
| 7.1 | LAN bind only under explicit `--allow-remote` | **Exists** | `crates/runtime-cli/src/commands.rs`: `run_http_server` |

## 3. What was implemented

**`crates/runtime-config/src/config.rs`**
- `DiscoveryRoot { id, label, path, enabled, browse, create, register, import, clone }` — defaults all true
- `DiscoveryConfig { enabled, default_root_id, show_hidden, follow_symlinks, max_depth, max_entries_per_page, roots }`
- `DiscoveryBrowseEntry`, `DiscoveryBrowseResult`, `DiscoveryProjectDetection`, `DiscoveryEntryKind`
- `Config.discovery` field (`#[serde(default)]`), `Default` impl, TOML parse/default tests

**`crates/runtime-workspace/src/discovery.rs`** (new — 7 tests, all passing)
- `DiscoveryService::from_config(DiscoveryConfig)` — canonicalizes roots, builds `PathValidator`s
- `list_roots()` — root metadata; absolute host paths never leaked to callers
- `set_root_enabled(id, bool)` — enable/disable toggle
- `browse_root(id, rel_path, cursor, limit)` — paginated offset cursor, containment-validated via `PathValidator`, rejects traversal/link escapes, disabled roots
- `detect_project(id, rel_path)` — bounded marker scan (Cargo.toml, package.json, etc.), git HEAD branch, confidence score, no code execution

**`crates/runtime-cli/src/main.rs` + `commands.rs`**
- `yl discovery roots` — list roots with all flags
- `yl discovery browse <root> [path] [--cursor N] [--limit N]` — paginated browse
- `yl discovery detect <root> [path]` — project type + git detection
- `yl discovery enable <root>` / `yl discovery disable <root>` — toggle root

## 4. Security gaps remaining (spec 7.4 Critical)

- `yl` served on `0.0.0.0:8077` with `--allow-remote` + open CORS and **no auth** during phase-4 testing — conflicts with spec §7.4 ("Do not ship remote filesystem browsing ... on an unauthenticated endpoint"). The test server was stopped; do not expose remote access until auth/pairing/TLS are implemented (Phase E).
- No device identity / pairing approval lifecycle (stubs only).
- Root enable/disable is in-memory per CLI invocation; not yet persisted back to `config/runtime.toml`.
- No authentication, sessions, TLS, origin validation, or rate limits for discovery operations.

## 5. Deferred (per spec phases C–G)

- Workspace registry CRUD + restart persistence (Phase C)
- Create empty project (Phase C)
- Import with staging/integrity, git clone (Phase D)
- Authenticated management HTTP API, pairing, TLS (Phase E)
- Tailscale/Cloudflare/Iroh providers (Phase F)
- Desktop controller GUI (Phase G)

## 6. CLI / GUI controllability principle

Every discovery operation goes through `DiscoveryService` in `runtime-workspace` — protocol-agnostic, no MCP/HTTP/CLI knowledge. The same service backs `yl discovery …` CLI commands and can back a future desktop controller GUI. Opaque root IDs are used; clients never construct host paths. This keeps CLI and GUI consistent and lets both call the same shared service with identical policy checks (spec §6.3).
