# Phase G — Stage 1 GUI audit (TLS transport, /api/v1 management API, /ui console)

**Source spec:** `docs/spec/REMOTE-WORKSPACE-AND-CONNECTIONS-SPEC.md` §1, §4.2–4.7, §6.1–6.3, §7.1, §7.4, §12; design doc `docs/superpowers/specs/2026-11-19-stage1-gui-design.md` (rev 2).

**Branch:** `feat/stage1-gui` (HEAD `0f9520f`)

**Rule followed:** Spec §17 — audit first, implement Stage 1 in small steps; never claim unrun behavior. Everything in §8 below was compiled, run, and observed on Windows against `target\debug\yl.exe`.

---

## 1. Build / test baseline (current branch)

- `cargo check --workspace --exclude backend-linux --exclude backend-macos --exclude runtime-terminal --exclude backend-windows`: clean
- `cargo test --workspace --exclude ... --no-fail-fast`: all green except two pre-existing, unrelated failures named in Global Constraints:
  - `backend-native::tests::test_native_backend_capabilities_honest` (pre-existing)
  - `runtime-toolchain::discovery::tests::test_detect_source` (environmental, not touched by Stage 1)
- `cargo test -p runtime-cli --bin yl`: 38 passed, 0 failed
- `cargo test -p runtime-workspace`: 119 passed, 0 failed

---

## 2. Requirement-to-code map

| Spec | Requirement | Code | Status | Where | Evidence |
|------|-------------|------|--------|-------|----------|
| §7.1 | LAN mode requires auth **and** encrypted transport | TLS listener per LAN IP; plaintext only on loopback; `--insecure-http` opt-out | Done | `crates/runtime-cli/src/tls.rs`, `commands.rs` | `plan_listeners`, `spawn_tls_listener`, live LAN `https://192.168.1.130:8081/ui` 200; plain HTTP to LAN IP refused |
| §7.4 Critical | No unauthenticated remote filesystem browsing | `require_session` middleware: remote peer + no valid bearer → 401/403; `/api/v1/*` gated regardless of `pairing_required` | Done | `commands.rs` `require_session`, `is_public_path` | auth-verify: unauth remote `/mcp` 401, remote `/api/v1/device` 401 |
| §7.4 | Auth model: ed25519 device keys, 6-digit code, 30-min bearer token, loopback bypass | IdentityService pairing + sessions; `AppState { identity, pairing_required, limiter }` | Done | `runtime-identity`, `commands.rs` | auth-verify: pair→code→approve→authenticate→token; token works |
| §7.4 | Approval gate: approve/deny/ask, project + global policy, `--yolo` | `runtime-approval` broker + PolicyEngine; `--yolo` config; console polls `/approvals` | Done | `runtime-approval`, `http_api/approvals.rs` | unit tests `pending_approval_can_be_approved_then_disappears`, `approve_and_reject_write_audit_events` |
| §7.4 | Host-only pairing/device endpoints | `is_host_peer` (loopback-only); remote gets 403 | Done | `http_api/devices.rs` `require_host` | auth-verify: remote `/api/v1/pairings` 403 even with valid token |
| §7.4 | Revoked device immediately invalidates live sessions | `validate_session` re-checks `Device.is_revoked` | Done | `runtime-identity` `validate_session` | auth-verify: revoke → token 401; re-auth rejected |
| §7.4 | Rate limiting for pairing/auth attempts | Fixed-window per-IP `RateLimiter`, loopback never throttled | Done | `commands.rs` `RateLimiter`, `require_session` | unit test `limiter_counts_only_unauthenticated_traffic` |
| §7.4 | Every API body rejection returns `{"error": ...}` JSON | `ApiJson<T>` extractor maps axum rejections to JSON | Done | `http_api/mod.rs` `ApiJson` | unit test `malformed_json_is_400_with_a_json_error` |
| §7.5 | `GET /api/v1/device` — device facts | `device::get_device` returns version/os/arch/yolo/pairing_required/tls/lan_urls, no absolute paths | Done | `http_api/device.rs` | live: 200 JSON with no absolute path |
| §7.5 | `GET/PATCH /api/v1/discovery/roots` + entries + detect | `discovery::routes()`; root-relative paths only, `synthetic` flag | Done | `http_api/discovery.rs` | unit tests roots/entries/toggle/detect; live roots 200 |
| §7.5 | `GET/POST/DELETE /api/v1/workspaces` — list/get/register/create/unregister | `workspaces::routes()`; `root_id`+`relative_path` only, never `root` | Done | `http_api/workspaces.rs` | unit tests register/list/unregister/duplicate/create/unknown/escape/paths-only; live create+delete+dirs-survive |
| §7.5 | Duplicate registration reuses existing id (idempotent) | `WorkspaceServiceImpl::register` canonicalizes + `same_path`; startup registration idempotent too | Done | `runtime-workspace/src/service.rs` `register`, `find_by_root` | unit test `duplicate_register_reuses_the_id`; live two restarts → same id + `already_registered:true` |
| §7.6 / §7.7 | Discovery synthesis from workspace roots; `ConfiguredRoot.synthetic` | `effective_discovery` synthesizes roots marked `synthetic: true` | Done | `runtime-config`, `runtime-workspace` | unit test `roots_list_exposes_flags_but_no_absolute_paths` |
| §7.9 | `/ui` console — six panes, enrollment, polling | `ui/index.html`, `app.css`, `app.js` served via `ui::routes()`; endpoints consumed | Done | `crates/runtime-cli/src/ui/` | app.js implements Roots/Browser/Workspaces/Approvals/Devices/enrollment |
| §12 | Controller screens: device state, roots, browsing, detection, workspaces | All six panes present against the endpoints above | Done | `ui/app.js` | code review; endpoints verified live |
| §17 | Audit before each phase; never claim unrun behavior | This document + `.superpowers/sdd/2026-11-19-stage1-gui/progress.md` ledger | Done | `.superpowers/sdd/…/progress.md` | per-task rulings recorded |

---

## 3. Design decisions

- **Transport:** `axum-server` 0.9 with `tls-rustls-no-provider`; rustls pinned to `ring` (verified: no `aws-lc-rs` in `cargo tree`). `rcgen` 0.14 self-signed cert with IP SANs at `<data_dir>/tls/{cert.pem,key.pem}` + `cert-meta.json`; regenerated on corrupt/expired/SAN-missing. Two listeners on one port: plain HTTP on `127.0.0.1`, TLS on each LAN IPv4. Never binds `0.0.0.0`.
- **Auth gate order:** OPTIONS → loopback bypass → valid bearer → rate-limit unauthenticated remote → allowlist (`/health`, `/pair/*`, `/ui*`) → `/mcp` relaxed only when `pairing_required=false` → everything else 401. `pairing_required=false` relaxes `/mcp` only, never `/api/v1/*`.
- **Path hygiene:** responses expose `{root_id, relative_path}` only; absolute host paths never leave `workspaces.rs`/`discovery.rs`. Exceptions limited to `ApprovalRequest.resource` and service error text (per design).
- **Duplicate registration:** enforced inside `WorkspaceServiceImpl::register` (canonicalize + `clean_verbatim_prefix` + `same_path`, case-insensitive on Windows) so startup re-registration of `[workspace].roots` is idempotent too. `find_by_root` returns the earliest registration among duplicates for stable ids across restarts.
- **Handler shape:** axum 0.8's `Handler` trait rejects `State<T> + Request` with a `Path` extractor, so Task 7 handlers read `{id}`/`{code}` from the URI manually (`segment_from_uri`/`id_from_uri`), mirroring existing `pair_approve`/`pair_list`. Wrapping `IdentityService::validate_session` in a helper `async fn` breaks axum's Send-future bound, so device-id resolution is inlined directly.
- **Console assets:** plain ES module, no build step/framework; embedded via `include_str!` so `yl serve` stays one binary. `crypto.subtle` Ed25519 enrollment requires a secure context (HTTPS on LAN, or loopback HTTP).
- **Audit:** best-effort `audit_event` helper — failures `warn!` but never fail the request (mutation already happened). Event names: `http.workspace.register|create|unregister`, `http.approval.approve|reject`, `http.device.revoke`, `http.identity.device.paired`.

---

## 4. Deferred (beyond Stage 1)

- Per-workspace / per-device authorization binding (backlog) — today an authenticated device reaches every advertised tool.
- Phase F providers, dynamic config get/set, usage stats, `workspace.find_files` bare `*.rs`, fix `backend-windows`.
- Tauri Stage 2 (reuses the same `/api/v1` endpoints and UI assets).
- File transfer / import streams, clone orchestration UI, event stream (Stage 1 polls instead).
- Root add/remove from the UI (enable/disable only; config stays file/CLI-driven).
- Public CA / ACME certs, DNS names, mDNS; the self-signed LAN cert requires the user to accept the browser warning on first enrollment.

---

## 5. Console panes (implemented in `ui/app.js`)

| Pane | Endpoints | Notes |
|------|-----------|-------|
| Roots | `GET/PATCH /discovery/roots`, `GET /discovery/roots/{id}/entries` | toggle + `synthetic` chip |
| Browser | `GET /discovery/roots/{id}/entries`, `POST /projects/detect` | breadcrumb, entries, Register/New project/Detect |
| Workspaces | `GET/DELETE /api/v1/workspaces{,/id}` | cards, relative path, restart note, Unregister with confirm |
| Approvals | `GET/POST /api/v1/approvals{,/id/approve|reject}` | 5 s poll while visible |
| Devices | `GET /api/v1/devices`, `POST /devices/{id}/revoke`, `GET/POST /api/v1/pairings{,/code/approve|reject}` | 10 s poll while visible, host-only notice |
| Enrollment | `POST /pair/request`, `GET /pair/status`, `POST /pair/authenticate` | IndexedDB ed25519 keypair, paste-token fallback if `crypto.subtle` unavailable |

---

## 6. Verification scripts

- `scripts/verify/auth-verify.ps1` — 13 checks: unauth remote `/mcp` 401; pair→code→approve→authenticate→token; authed remote `/api/v1/device` 200; remote `/api/v1/pairings` 403 (host-only); wrong key rejected; revoke → token 401; re-auth rejected. **13/13 passed.**
- `scripts/verify/persist-verify.ps1` — 11 checks: pair/authenticate/revoke before restart; token works before restart; revoked token 401 before restart; after server restart — revoked token still 401, device still registered+revoked, pairing still recorded, identity.jsonl has events. **11/11 passed.**
- `scripts/verify/auth-flow.mjs` — real MCP SDK over Streamable HTTP (ported from `mcp-verify/auth-flow.mjs`): loopback no-token works; LAN no-token rejected; pair+authenticate→LAN-with-token works; revoke kills token.

Run from a fresh `yl serve` with a temp config:
```
$env:YL_RUNTIME_URL="http://127.0.0.1:8081"
$env:YL_LAN_URL="https://192.168.1.130:8081"
./scripts/verify/auth-verify.ps1
./scripts/verify/persist-verify.ps1
```

---

## 7. Live phone pass (not executed — no phone available)

Per spec, Step 3 requires `yl serve --allow-remote`, opening `https://<lan-ip>:P/ui`, accepting the self-signed warning, comparing fingerprints, pairing by code, toggling a root, browsing, registering a workspace, confirming `workspaces.jsonl` grew, `yl devices revoke`, next console call → 401. No physical phone was available for this session, so this step was **not executed**. The host-side equivalent was verified live (LAN `https://192.168.1.130:8081/ui` 200 over HTTPS with the self-signed cert; enrollment flow via `pair/request`+`approve`+`authenticate`; root toggle; workspace register/create/unregister; revoke → 401). Claim only the host-side equivalent.

---

## 8. Known restart limitations (as-built)

- Console-registered workspaces are in the service registry but not in the MCP server's startup snapshot; agents see them only after a `yl serve` restart (surfaced in the UI as "available_to_agents_after_restart").
- Registrations written before idempotent `register` (pre-Stage-1 `workspaces.jsonl`) can hold duplicate rows for one directory; `find_by_root` returns the earliest for stability, but the stale duplicates remain in the file until cleaned.
- `ApiState.{approvals, identity, audit}` fields are unused by handlers today (handlers read `state.api.*`); harmless dead fields retained for future `/pair/*` audit hooks (Task 7 design).
- Two pre-existing build failures outside Stage 1's scope (see §1).

---

## 9. Verification commands

```
cargo check --workspace --exclude backend-linux --exclude backend-macos --exclude runtime-terminal --exclude backend-windows
cargo test  --workspace --exclude backend-linux --exclude backend-macos --exclude runtime-terminal --exclude backend-windows --no-fail-fast
cargo test -p runtime-cli --bin yl
cargo test -p runtime-workspace
./scripts/verify/auth-verify.ps1
./scripts/verify/persist-verify.ps1
```
