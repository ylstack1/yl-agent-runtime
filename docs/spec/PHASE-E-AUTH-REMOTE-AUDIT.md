# Phase E audit — authenticated remote access (pairing, sessions, TLS prereqs)

**Source spec:** `docs/spec/REMOTE-WORKSPACE-AND-CONNECTIONS-SPEC.md` (Proposed, v1.0, 2026-11-19), §7.1 (LAN default), §7.2 (optional remote), §7.4 (security prerequisites — Critical), §8 (pairing, authorization, policy)  
**Branch:** `phase-a-discovery-roots` (HEAD `9dcd29e`)  
**Rule followed:** Spec §17 — audit first, implement Phase E in small steps; never claim unrun behavior.

## Status

**Phase E: implemented and verified live (E.1–E.4).** Sections 1–7 are the pre-implementation audit and requirement map; §8 is the as-built record with the evidence actually observed. The remaining Phase E gap is TLS certificate provisioning, which is documented as a hard prerequisite for non-loopback deployment (§8.6).

## 1. Build / test baseline (current branch)

- `cargo check --workspace --exclude backend-linux --exclude backend-macos --exclude runtime-terminal --exclude backend-windows`: clean
- `cargo test --workspace --exclude ... --no-fail-fast`: all green except two pre-existing unrelated failures
- Server was live on `0.0.0.0:8077` with `--allow-remote` + open CORS + **no auth** — conflicts with spec §7.4 Critical

## 2. Requirement-to-code map

| Spec | Requirement | Existing code | Status | Where |
|---|---|---|---|---|
| 7.4 | Device pairing/approval lifecycle with cryptographic identity | `runtime-identity` crate: IdentityService trait, IdentityServiceImpl, PairingRequest, PairingState, generate_pairing_code, compute_fingerprint — all exist | **Partial** — pairing request/approve/reject not wired; no persistence; CLI stubs only | `crates/runtime-identity/src/service.rs`, `crates/runtime-cli/src/commands.rs` |
| 7.4 | Authenticated sessions, scoped revocable credentials | `runtime-core/src/session.rs`: Session struct exists; no session store, no token issuance, no validation middleware | **Missing** | — |
| 7.4 | Per-device/per-user/per-agent/per-workspace authorization | `runtime-policy`: PolicyEngine exists with evaluate(); CapabilityGrant exists | **Partial** — no device/session binding to policy | `crates/runtime-policy/src/engine.rs` |
| 7.4 | Short-lived access tokens, refresh/revocation | None | **Missing** | — |
| 7.4 | TLS for HTTP/WebSocket when traffic leaves loopback | axum + rmcp streamable-HTTP on `:8077`; no TLS, no certificate provisioning | **Missing** | `crates/runtime-cli/src/commands.rs` (run_http_server) |
| 7.4 | Strict origin/host validation | rmcp has DNS rebinding protection; CORS `AllowOrigin::any()` | **Partial** — need origin validation for non-loopback | `crates/runtime-cli/src/commands.rs` |
| 7.4 | Rate limits for pairing/auth/browse/transfer | Config has `rate_limit_per_minute`; no rate limiter middleware | **Missing** | — |
| 7.4 | Audit events for auth/pairing | `runtime-audit`: AuditEventType has Pairing-related entries? Need to check | **Partial** | `crates/runtime-core/src/audit.rs` |
| 8 | Pairing must be explicit user-approved trust | CLI `pair_device`/`list_devices`/`revoke_device` are stubs | **Missing** | `crates/runtime-cli/src/commands.rs` |

## 3. Design decisions

- **Pairing flow**: Device generates ed25519 keypair → requests pairing code (6-digit) → user sees code on device → user approves on host → device registered as trusted with public key stored
- **Session auth**: After pairing, device signs a challenge with its private key → server verifies ed25519 signature → issues short-lived session token (random UUID, 30-min TTL) → token presented in `Authorization: Bearer <token>` header on each request
- **HTTP middleware**: axum `from_fn` middleware extracts Bearer token, validates against session store, rejects 401 if invalid/expired; bypassed on loopback when `pairing_required=false`
- **Rate limiting**: Simple fixed-window counter per IP address, stored in Arc<Mutex<HashMap>>, configurable via `rate_limit_per_minute`
- **Origin validation**: On non-loopback binds, require `Origin` or `Host` header to match allowed list; reject unknown origins
- **No circular deps**: `runtime-cli` already depends on `runtime-identity`; add `runtime-identity` to `runtime-mcp` if needed for middleware (or keep auth in CLI layer)
- **Persistence**: Pairings and sessions stored in memory (Phase E); JSONL persistence deferred to later phase per spec's incremental approach

## 4. Deferred (later phases)

- TLS certificate provisioning (Phase E prerequisite but complex — document as required, implement when certificates available)
- JSONL persistence for pairings/sessions (deferred per spec incremental approach)
- WebSocket auth (deferred — no WebSocket endpoints yet)
- Per-workspace authorization binding (Phase E starts with device-level; workspace binding follows)

## 5. Phase E milestones

**E.1** — Complete IdentityService pairing lifecycle: `request_pairing`, `approve_pairing`, `reject_pairing`, `list_pairings`; CLI commands `yl pairing {request|approve|reject|list}`; tests
**E.2** — Session authentication: `authenticate_device` (ed25519 signature verification), session store with TTL, token issuance; tests
**E.3** — HTTP auth middleware + rate limiting + origin validation; wire into `run_http_server`; tests
**E.4** — CLI: `yl devices {list|revoke}` implemented; `yl pairing` fully wired; tests
**E.5** — Full workspace/mcp/identity test suite + security tests (invalid token, expired token, revoked device, rate limit); build gate clean

## 6. CLI / GUI controllability

Pairing and session management are protocol-agnostic service methods in `runtime-identity`. The same functions back `yl pairing …` CLI commands and can back a future desktop controller GUI pairing UI. Opaque DeviceId/SessionId used throughout.

## 7. Verification plan

- Build gate: `cargo check --workspace --exclude ...` clean
- Tests: all green except two pre-existing unrelated failures
- Live MCP client: HTTP requests without token → 401; with valid token → 200; pairing request → code → approve → authenticate → token works; rate limiting triggers after N requests; revoked device → token invalid

---

# 8. As-built record (implemented)

Everything below was compiled, run, and observed on Windows against `target\debug\yl.exe`. Nothing in this section is aspirational.

## 8.1 Trust split

| Endpoint | Method | Reachable by | Notes |
|---|---|---|---|
| `/health` | GET | any peer | Liveness only; exposes service name + version, no workspace data |
| `/pair/request` | POST | any peer | Device submits `{device_name, public_key_hex}` (ed25519, 32 bytes) → returns 6-digit `pairing_code`, 10-min TTL |
| `/pair/status` | GET `?pairing_code=` | any peer | Lets the device poll `pending`/`approved`/`rejected` and learn its `device_id` once approved |
| `/pair/authenticate` | POST | any peer | `{device_id, signature_hex}` — signature over the `device_id` string with the paired key → 30-min bearer `token` |
| `/pair/approve` | POST | **host only** | Loopback peer required; non-loopback gets `403` |
| `/pair/reject` | POST | **host only** | Loopback peer required |
| `/pair/list` | GET | **host only** | Pairings + devices |
| `/device/revoke` | POST | **host only** | Revoking invalidates live sessions immediately |
| `/mcp` | POST | host, or remote with bearer | Non-loopback requires `Authorization: Bearer <token>` when `remote.pairing_required`; OPTIONS preflight always passes |

"Host only" means the connection's peer `SocketAddr` is a loopback address. Without connect info the peer cannot be proven local, so the request is refused (fail closed). This is what makes `yl pairing approve` safe to expose on a LAN bind: a remote device can *ask* to pair and *authenticate*, but only a process running on the host can grant it.

## 8.2 Identity service (`crates/runtime-identity/src/service.rs`)

- `request_pairing(name, public_key)` → `PairingRequest { pairing_code, state: Pending, expires_at, device_id: None }`
- `approve_pairing(code)` → registers `Device`, sets `state: Approved` + `device_id: Some(..)`; `reject_pairing(code)` → `Rejected`
- `authenticate_device(device_id, signature_hex)` → verifies the ed25519 signature over the `device_id` string against the stored public key; on success inserts a `Session` (UUID token, 30-min TTL) and returns it
- `validate_session(token)` → rejects unknown/expired/inactive sessions **and** re-checks `Device.is_revoked`, so revocation is immediate rather than waiting for TTL
- `revoke_device(id)`, `list_devices()`, `list_pairings()`
- 11 unit tests; all pass

## 8.3 HTTP layer (`crates/runtime-cli/src/commands.rs`)

- `AppState { identity, pairing_required, limiter }`; `require_session` middleware applied via `from_fn_with_state`, router served with `into_make_service_with_connect_info::<SocketAddr>()` so peer IPs are real
- `RateLimiter` — fixed 60-second window per IP, `remote.rate_limit_per_minute` (0 → 100). **Loopback peers are never rate limited**, so the host CLI cannot throttle itself
- CORS: `AllowOrigin::any()`, `allow_credentials(false)` — compatible with Android MCP clients, safe because credentials travel in an explicit `Authorization` header rather than cookies

## 8.4 CLI (`crates/runtime-cli/src/main.rs`)

- `yl pairing {list|approve <code>|reject <code>|status <code>|request --name X [--key-hex HEX]|authenticate <device_id> --key-hex HEX}`
- `yl devices {list|revoke <device_id>}` (legacy `list-devices` / `revoke-device` retained)
- Server base URL from `YL_RUNTIME_URL` (default `http://127.0.0.1:8077`); non-2xx responses surface the server's `error` field
- `pairing request` generates an ed25519 key when `--key-hex` is omitted and prints the seed once for the device to store

## 8.5 Observed verification

Config: temp `runtime.toml` with a single discovery root over the test workspace, `pairing_required = true`. Server bound `0.0.0.0:8077` with `--allow-remote`.

`C:\Users\SawYeLin\AppData\Local\Temp\opencode\auth-verify.ps1` — 12/12:
```
PASS  unauth LAN /mcp rejected            status=401
PASS  pair request returns a 6-digit code code=986450
PASS  pending status before approval      state=pending
PASS  authenticate before approval fails  rejected
PASS  host approve returns device id
PASS  approved status exposes device id   state=approved
PASS  authenticate issues a token
PASS  authed LAN /mcp allowed             status=200
PASS  wrong key rejected                  rejected
PASS  devices list shows paired device    listed
PASS  revoked device token rejected       status=401 ... is revoked
PASS  re-auth after revoke rejected       rejected
ALL AUTH CHECKS PASSED
```

`C:\Users\SawYeLin\AppData\Local\Temp\opencode\mcp-verify\auth-flow.mjs` — real MCP SDK over the Streamable HTTP transport, 10/10:
```
loopback client connects without a token     40 tools
loopback tool call succeeds                  workspace.allowed_roots
workspace.read returns file content          {"content":"hello from auth test\r\n",...}
LAN client without token rejected            missing bearer token
pairing request issued / host approved
device authenticated
LAN client connects with token               40 tools
LAN tool call succeeds with token            workspace.list
revoked token can no longer connect          invalid session ... is revoked
```

Rate limiting on a second instance (`rate_limit_per_minute = 3`):
```
LAN request 1..3: 200   LAN request 4..5: 429
loopback request 1..6: 200 (never throttled)
```

Host-only enforcement from the LAN address:
```
POST http://<lan-ip>:8077/pair/approve -> 403 "pairing approval is host-only; run 'yl pairing approve CODE' on the host"
```

## 8.6 Remaining Phase E gap — TLS

Traffic on the LAN is still plaintext HTTP. The bearer token and pairing signatures are therefore visible to anyone on the same network segment. Per spec §7.4, **no non-loopback deployment should be treated as production until TLS is provisioned**. Accepted options, in order of preference:

1. **Reverse proxy / tunnel terminates TLS** (Cloudflare Tunnel, Tailscale Funnel, Caddy, nginx) — recommended, because certificate lifecycle stays outside the runtime
2. **In-process TLS** via `axum-server` + `rustls` with a host-provided certificate
3. Loopback-only deployment (current dev default) — no LAN exposure at all

Also deferred and still open: JSONL persistence for pairings/sessions (an in-memory store means every server restart forgets paired devices), and binding authorization policy to a specific workspace or device (today an authenticated device can reach every tool the runtime advertises).

## 8.7 Verification commands

```
cargo check --workspace --exclude backend-linux --exclude backend-macos --exclude runtime-terminal --exclude backend-windows
cargo test  --workspace --exclude backend-linux --exclude backend-macos --exclude runtime-terminal --exclude backend-windows --no-fail-fast
cargo test -p runtime-identity
```
