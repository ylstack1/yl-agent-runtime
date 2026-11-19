# Stage 1 GUI: TLS transport + management API (`/api/v1`) + web console (`/ui`)

Status: draft for approval (rev 2, post builder-check)
Date: 2026-11-19
Related: `docs/spec/REMOTE-WORKSPACE-AND-CONNECTIONS-SPEC.md` §1, §4.2–4.7, §6.1–6.3, §7.1, §7.4, §12

## 1. Intent and why

The runtime is drivable today only through MCP (`/mcp`) and the `yl` CLI. The spec says
MCP is not the only control plane (§1), requires a versioned HTTP management API (§6.2),
requires controller screens for device state, roots, browsing, project detection and
workspaces (§12), and requires **encrypted transport even on a LAN** (§7.1). Stage 1
delivers all three in the order that makes the third one possible:

- **M0 — transport:** TLS on the LAN listener, so `https://` origins are secure contexts.
- **M1–M3 — API and console:** `/api/v1/*` + `/ui`, phone-usable.

TLS is not optional polish here. Browsers only expose `crypto.subtle` in secure contexts,
and `http://192.168.x.x` is not one — so without M0 the ed25519 enrollment the identity
system is built around cannot run on a phone at all. It also closes the one open security
gap recorded in `docs/spec/PHASE-E-AUTH-REMOTE-AUDIT.md` §8.6.

The console is Stage 1 of the GUI decision: a Tauri desktop shell (Stage 2) later loads the
same endpoints and reuses the same assets, so no screen is written twice.

## 2. Goals

- G1. **Encrypted LAN transport by default** (§7.1), with loopback left plain for the
  host's own CLI/MCP clients, on one port number.
- G2. A versioned `/api/v1/*` management API whose handlers only authenticate, validate
  JSON shape, and call the same domain services MCP calls (§6.3).
- G3. A `/ui` console usable from a phone on the LAN: device/LAN/certificate state, roots,
  browse, project detection, workspace list/register/create/unregister, approvals,
  device/pairing management.
- G4. Browser enrollment on the *existing* identity model (ed25519 device keys, 6-digit
  code, bearer token) — no server-side key generation, no weakening.
- G5. Zero new build toolchain: no npm, no bundler, no `rust-embed`; assets compiled in
  with `include_str!` so `yl serve` stays one binary.

## 3. Non-goals (Stage 1)

- File transfer / import streams (`/api/v1/imports/*`, §4.5).
- Clone task orchestration UI (`/api/v1/git/clones`, `tasks/*`).
- Event stream (`/api/v1/events`, `/ws/v1/events`); Stage 1 polls.
- Tauri shell, tray, native file pickers, OS credential storage (Stage 2).
- Per-workspace / per-device authorization binding (backlog).
- Root add/remove from the UI (`POST`/`DELETE /discovery/roots`) — configuration stays
  file/CLI-driven; enable/disable is exposed.
- Public CA / ACME certificates, DNS names, mDNS discovery.

## 4. Anti-goals

- Re-implementing filesystem authorization in the HTTP layer. Root containment, sensitive
  file refusal, disabled-root refusal and profile enforcement stay inside
  `WorkspaceServiceImpl` / `DiscoveryService` / `PolicyEngine`.
- A second server process or a separate SPA dev server.
- Exposing absolute host paths in list/detail payloads or URLs.
- Any unauthenticated remote browse, listing or file read (§7.4 Critical).
- Making the console a prerequisite for MCP/CLI use.
- Silently falling back to plaintext on a LAN interface.

## 5. What exists today (verified in this checkout)

- `crates/runtime-cli/src/commands.rs::run_http_server` builds `WorkspaceServiceImpl`
  (registry persisted at `<data_dir>/workspaces.jsonl`; discovery config enforced from a
  **private** `Arc<RwLock<DiscoveryConfig>>`), `AuditServiceImpl`, `ApprovalBrokerImpl`,
  `ProcessService`, `PolicyEngineImpl`, `UndoJournal`, `IdentityServiceImpl` (JSONL
  replayed), `AppState { identity, pairing_required, limiter }`, and an axum `Router` with
  `/health`, `/pair/{request,status,authenticate,approve,reject,list}`,
  `/device/revoke`, `.nest_service("/mcp")`, permissive `CorsLayer`, then `require_session`.
- `require_session` order: OPTIONS passthrough → rate limit every non-loopback peer → if
  `!pairing_required || loopback` pass → only `/health` public → else require a bearer
  token validated by `validate_session`.
- Identity: `request_pairing(name, pubkey)` → 6-digit code, 10-min TTL;
  `approve_pairing(code)` → `DeviceId`; `authenticate_device(device_id, signature_hex)`
  verifies ed25519 over `device_id.to_string().as_bytes()`, issues an opaque UUID token
  with a **hard-coded 30-minute** expiry; sessions are in memory + identity JSONL;
  `revoke_device` and `validate_session` re-check `is_revoked`.
- `WorkspaceServiceImpl`: `list_workspaces()`, `get_workspace(id)`, `register(path,
  profile)`, `unregister(id)`, `create_workspace(parent, name, profile, subdirs)`,
  `workspace_count()` (**a stub returning 0**), `clean_verbatim_prefix` (private helper).
- `DiscoveryService`: `from_config`, `list_roots()`, `set_root_enabled()`,
  `browse_root(root_id, rel_path, cursor, limit)`, `detect_project(root_id, rel_path)`;
  `ConfiguredRoot { id, label, canonical_path, enabled, browse, create, register, import,
  clone }`. It is **not** instantiated in `run_http_server` today.
- `McpServer` is the only place that applies `enforce_tool` (approval/policy gate) and
  `record_audit`; the services themselves do authorization but not approval or audit.
- `McpServer` resolves paths against a `roots: Vec<(ProjectId, PathBuf)>` snapshot taken at
  startup, and profiles are set on `policy_engine` at startup only.
- Only plain HTTP is served (`axum::serve`); no TLS anywhere; `ring` is already a
  workspace dependency.
- The `mcp-verify` scripts referenced by earlier phases live **outside** the repo
  (`%TEMP%\opencode\mcp-verify`), so they are not reproducible gates today.

## 6. Approaches considered

**A. Handlers inside `runtime-cli` (`src/http_api/*` + `ui/` assets). — chosen**
No new crate, routes sit beside `/mcp` on the same listeners as §6.3 suggests, every
handler calls an existing service method, assets are `include_str!`ed. Cost: `runtime-cli`
becomes composition root *and* HTTP adapter.

**B. New crate `runtime-api`. Rejected for Stage 1.**
Cleaner on paper, but auth (`AppState`, `require_session`, `RateLimiter`, host-peer checks)
lives in `runtime-cli` and is the exact code just verified 12/12 + 10/10. Moving it
mid-stream risks the one thing that must not regress for no user-visible gain; §6.3 also
warns against creating crates pre-emptively. Revisit if `runtime-daemon` later hosts routes.

**C. Separate SPA (React/Vite). Rejected.** New toolchain for six screens; fails G5.

**D. Tauri desktop first. Rejected for Stage 1.** Useless from a phone, which is the
remote-workspace case. It is Stage 2 on top of A.

**Transport alternative rejected:** TLS on the single `0.0.0.0` listener and make loopback
use https too. It would force every local MCP client (`opencode.json` → `http://127.0.0.1`)
to trust a self-signed cert. Keeping loopback plain preserves that; `http://localhost` is
already a secure context, so host-side browser enrollment is unaffected.

## 7. Design

### 7.0 Transport (M0)

**Two listeners, one port number.** `axum::Router` is cheap to clone and stateless here.

```
127.0.0.1:P        plain HTTP    host CLI, local MCP clients, host browser console
<each LAN IPv4>:P  HTTPS/rustls  phones and other LAN devices
```

- Loopback plain keeps `opencode.json` and every existing local client working untouched,
  and `http://127.0.0.1` is a trustworthy origin, so `crypto.subtle` works there.
- Each local non-loopback IPv4 address gets its own TLS listener on the same port (binding
  `0.0.0.0` would collide with the loopback bind on Windows). `local_lan_ip()` already
  exists; it grows into a "all local IPv4s" helper. If none is found, log a warning and do
  not claim LAN availability.
- `--allow-remote` / non-loopback `--host` now means exactly this: loopback plain + TLS on
  every LAN address. `0.0.0.0` is no longer bound.

**Server.** `axum-server = { version = "0.9", features = ["tls-rustls"] }` (axum is only a
dev-dependency there; it is built on hyper 1.4 + rustls 0.23, so axum 0.8's
`into_make_service_with_connect_info::<SocketAddr>()` works, as does `Handle::graceful_shutdown`).
Loopback keeps using `axum::serve` with connect info; LAN uses
`axum_server::bind_rustls(addr, RustlsConfig::from_pem_file(...))`.
**Build risk to verify first:** rustls 0.23 defaults to `aws_lc_rs`, which needs cmake/nasm
on Windows. We pin `rustls = { version = "0.23", default-features = false, features =
["ring", "std", "tls12", "logging"] }` in workspace deps (matching the existing `ring`
dependency) and install the provider explicitly at startup. If feature unification still
pulls aws-lc, M0 stops and the crate choice is revisited — it does not ship broken.

**Certificate.** `rcgen = "0.14"`, `generate_simple_self_signed` / `CertificateParams`
with SANs = `localhost`, the machine hostname, `127.0.0.1` and **every** local IPv4 (IP
SANs matter: browsers match the URL host, not the machine name).
- Stored at `<data_dir>/tls/{cert.pem,key.pem}`, file mode restricted where the OS allows.
- Generated on first run only if absent; reused afterwards (so a phone's pinned trust
  survives restarts). Regenerated when it is expired, unparseable, or its SAN set no longer
  covers the current LAN address — logging the reason when that happens.
- `[remote] tls = "auto" | "off"` plus optional `tls_cert`/`tls_key` paths for a real
  certificate. `"off"` while bound to a LAN address is refused unless the explicit
  `--insecure-http` flag (or `remote.allow_plaintext_lan = true`) is set; that path logs a
  loud warning on every start. Default: never plaintext on a LAN interface.
- At startup print the LAN URL and the certificate **SHA-256 fingerprint** (colon-separated
  hex, as browsers show it). Same value in `GET /api/v1/device` and in the console header.

**Phone trust flow (documented in the UI):** open `https://<lan-ip>:P/ui`, accept the
security warning once ("Advanced → Proceed"), then compare the fingerprint shown by
`yl serve` with the one in the console header. Pinning the certificate in the OS trust
store is optional and operator-driven; we never ask for it programmatically.

### 7.1 Layering

```
ui/*.js  --fetch-->  /api/v1/*  --(middleware auth)--> handlers --calls--> domain services
                                                                             ^
/mcp  --rmcp--> McpServer --enforce_tool/record_audit--calls-----------------+
```

A handler does: (1) authenticate the peer (middleware), (2) parse/validate JSON,
(3) call one service method, (4) map the error. No handler reads the filesystem, resolves
paths, or checks a root.

One honest correction to the first draft: **approval gating and audit do not live in the
services** — they live in `McpServer::enforce_tool` / `record_audit`. So:

- **Approval gate: not applied to console mutations.** A human operating the console *is*
  the consent (§6.3 frames the HTTP handler as the authenticated principal, not an agent).
  Register/create/unregister/approve/reject therefore do not round-trip through
  `ApprovalBroker`. Agent-initiated mutations via MCP keep their gate unchanged.
- **Audit: applied.** `ApiState` carries `Arc<dyn AuditService>` and every mutating
  endpoint records an audit event (`http.workspace.register`, `http.workspace.create`,
  `http.workspace.unregister`, `http.approval.approve|reject`, `http.device.revoke`),
  naming the acting device from the session token. This is new behaviour, not inherited,
  and is called out as such in the audit doc.

### 7.2 Module layout

```
crates/runtime-cli/src/http_api/mod.rs        ApiState, routes(), error mapping, path helpers
crates/runtime-cli/src/http_api/device.rs     GET /api/v1/device
crates/runtime-cli/src/http_api/discovery.rs  roots, entries, detect
crates/runtime-cli/src/http_api/workspaces.rs list/get/register/create/delete
crates/runtime-cli/src/http_api/approvals.rs  list/approve/reject
crates/runtime-cli/src/http_api/devices.rs    devices/pairings (host-only)
crates/runtime-cli/src/http_api/ui.rs         static /ui assets
crates/runtime-cli/src/tls.rs                 cert generation/loading, fingerprint, listeners
crates/runtime-cli/ui/{index.html,app.css,app.js}
```

```rust
#[derive(Clone)]
pub struct ApiState {
    pub fs: Arc<WorkspaceServiceImpl>,
    pub discovery: Arc<DiscoveryService>,
    pub approvals: Arc<dyn ApprovalBroker>,
    pub identity: Arc<IdentityServiceImpl>,
    pub audit: Arc<dyn AuditService>,
    pub device: DeviceFacts, // version, os, arch, lan bind addrs, cert fingerprint, yolo
}
```

`run_http_server` clones what it already builds (`service.clone()` before `McpServer` takes
it), builds `DiscoveryService::from_config(fs.discovery_config())`, and merges
`http_api::routes()` into the router before the CORS and auth layers. Router assembly is
factored into a testable `pub(crate) fn build_router(...) -> Router` so the integration
tests do not spawn a server.

### 7.3 Auth changes (security-relevant, regression-tested)

1. **Public bootstrap allowlist** in `require_session`: `/health`, `/ui`, `/ui/*`,
   `/pair/request`, `/pair/status`, `/pair/authenticate`.
   *Bug fixed:* with `pairing_required = true` a non-loopback peer currently needs a token
   to call `/pair/request`, so a phone can never start pairing. Approve / reject / list /
   revoke stay loopback-only via the existing `is_host_peer`.
2. **Rate limiting applies to unauthenticated traffic only.** New order: OPTIONS
   passthrough → loopback? pass → valid bearer token? pass → otherwise count against the
   per-IP window. The console polls, and 100 req/min would throttle a legitimate session;
   the brute-force target (pairing/auth) stays limited exactly as today.
3. **`/api/v1/*` is gated for non-loopback peers regardless of `pairing_required`.**
   Measured against §7.4 (Critical), `pairing_required = false` must not turn a LAN
   interface into an unauthenticated browse API. That flag continues to apply only to
   `/mcp` (its documented local-dev opt-out). This is a deliberate difference in behaviour
   between `/mcp` and `/api/v1`, stated here so it is a decision and not an accident.
4. **Bearer tokens only, no cookies** → no CSRF surface. CORS stays permissive
   (`allow_origin: any`, `allow_credentials: false`) because tokens are not ambient, and
   `PATCH` is added to `allow_methods`.

### 7.4 Browser enrollment (ed25519 via WebCrypto)

Now viable because M0 makes the LAN origin a secure context. No new server endpoints:

1. UI generates a non-extractable ed25519 keypair
   (`crypto.subtle.generateKey({name:"Ed25519"}, false, ["sign","verify"])`) and stores the
   `CryptoKeyPair` in IndexedDB (structured-cloneable, so the private key never becomes
   readable JS). The raw public key is exported for pairing.
2. `POST /pair/request {device_name, public_key_hex}` → 6-digit code + expiry.
3. The user approves on the host (`yl pairing approve CODE`, or the console on loopback).
4. UI polls `GET /pair/status?pairing_code=…` until `state = approved` → `device_id`.
5. UI signs `TextEncoder().encode(device_id)` → `POST /pair/authenticate {device_id,
   signature_hex}` → 30-minute token.
6. Token in `sessionStorage`; a 20-minute timer silently re-signs for a fresh one, so an
   open console never expires. `yl devices revoke` still kills it on the next call.

Fallback (browsers without WebCrypto ed25519, or an operator pinning nothing): paste-token
form — `yl pairing request` → `approve` → `authenticate --key-hex`, paste the token; same
storage, re-paste on 401. The UI states which path it is using.

### 7.5 Endpoints

All JSON; errors keep today's shape `{ "error": "..." }`.

| Method | Path | Service call | Access |
|---|---|---|---|
| GET | `/ui`, `/ui/app.js`, `/ui/app.css` | `include_str!` | public |
| GET | `/api/v1/device` | facts + `list_workspaces().len()` + discovery roots + cert fingerprint | session |
| GET | `/api/v1/discovery/roots` | `DiscoveryService::list_roots` | session |
| PATCH | `/api/v1/discovery/roots/{id}` | `set_root_enabled` (both copies, see 7.7) | session |
| GET | `/api/v1/discovery/roots/{id}/entries?path&cursor&limit` | `browse_root` | session |
| POST | `/api/v1/projects/detect` | `detect_project` | session |
| GET | `/api/v1/workspaces` | `list_workspaces` (sanitized) | session |
| GET | `/api/v1/workspaces/{id}` | `get_workspace` (sanitized) | session |
| POST | `/api/v1/workspaces/register` | root resolve → `register(abs, profile)` | session |
| POST | `/api/v1/workspaces/create` | root resolve → `create_workspace` | session |
| DELETE | `/api/v1/workspaces/{id}` | `unregister` (registry only, never files) | session |
| GET | `/api/v1/approvals` | `ApprovalBroker` pending list | session |
| POST | `/api/v1/approvals/{id}/approve` | `ApprovalBroker::approve` | session |
| POST | `/api/v1/approvals/{id}/reject` | `ApprovalBroker::reject` | session |
| GET | `/api/v1/devices` | `list_devices` | host-only |
| POST | `/api/v1/devices/{id}/revoke` | `revoke_device` | host-only |
| GET | `/api/v1/pairings` | `list_pairings` + `list_devices` | host-only |
| POST | `/api/v1/pairings/{code}/approve` | `approve_pairing` | host-only |
| POST | `/api/v1/pairings/{code}/reject` | `reject_pairing` | host-only |

"host-only" = loopback peer, same rule/message style as `/pair/approve` (a phone can use
these only if it *is* the host, which it is not).

**Path hygiene, stated precisely.** Requests carry `{root_id, relative_path}`; the handler
resolves to an absolute path through the discovery root and passes that to the service, so
no absolute path is ever *accepted* from a client. Responses never include one from
list/detail payloads: `WorkspaceRecord.root` (an absolute `PathBuf`) is replaced by
`{root_id, relative_path}` computed by matching against configured roots, with both fields
`null` when there is no match. Two deliberate exceptions, because the value *is* the thing
under discussion and both are only readable by an authenticated principal:
1. `ApprovalRequest.resource` — a human cannot judge an approval without knowing what it
   touches.
2. Service error text (e.g. "not within any enabled discovery root") — redacting paths
   would make root misconfiguration undiagnosable over the console.

### 7.6 Discovery roots when `[discovery]` is empty

`Config::default()` has `discovery.roots = []`, and `run_http_server` only fails on empty
*workspace* roots. `check_discovery_root` then skips enforcement entirely. Without a fix,
the console would show an empty Roots pane on a perfectly configured runtime.

Rule: when `[discovery].roots` is empty, synthesize roots from the effective workspace
roots — id `ws-<n>`/`ro-<n>`, label = directory name, canonical path as given:
- writable roots → `browse = register = create = true`, `import = clone = false`
- read-only roots → `browse = true`, everything else `false`

This is strictly narrower than today's "no discovery config ⇒ no enforcement", so it
cannot widen access. Synthesized roots are marked `synthetic: true` in the API payload and
the UI says so, pointing at `[discovery]` for durable configuration. When
`[discovery].roots` is non-empty, configuration wins and nothing is synthesized.

### 7.7 Two accessors and the enable-toggle semantics

```rust
pub fn discovery_config(&self) -> DiscoveryConfig;                       // clone of the lock
pub fn set_discovery_root_enabled(&self, id: &str, enabled: bool) -> Result<()>;
```

Needed because the config that *enforces* register/create is private inside
`WorkspaceServiceImpl`, while browse uses a separate `DiscoveryService`. The toggle calls
the accessor **and** `DiscoveryService::set_root_enabled`, so both copies move together:
disabling stops browsing as well as registration (`browse_root` already refuses a disabled
root). It is **in-memory only** — nothing rewrites `runtime.toml`, so the toggle resets on
restart. The UI says "resets on restart"; persisting it would mean rewriting a hand-edited
config file (unknown/comment loss), which is not Stage 1 work.

### 7.8 Registration semantics

- **Duplicates:** before registering, the handler scans `list_workspaces()` for the same
  canonical path (normalised with `clean_verbatim_prefix`, case-insensitive on Windows) and
  returns `{workspace_id, already_registered: true}` with 200 instead of minting a second
  id for one directory (§4.3 requires exactly this).
- **Not yet visible to agents:** `McpServer` resolves paths against a startup snapshot of
  `roots` and profiles are set at startup, so a console-registered workspace cannot be
  addressed by MCP tools until `yl serve` restarts. This is the same limitation MCP's own
  `workspace.register` has today and is **not** being fixed here (it would mean making root
  resolution dynamic across crates). The response carries `"available_to_agents_after_restart":
  true` and the UI shows it.

### 7.9 Console (no build step)

One page, plain ES modules, `fetch`, no framework, no hash routing needed for six panes:

- **Header** — device name/version, transport badge (`Local · http://127.0.0.1:P` /
  `LAN · https://192.168.x.x:P (self-signed)`), certificate fingerprint with copy button,
  token state, sign out.
- **Roots** — label, stable id, enabled toggle, capability chips, `synthetic` marker;
  click → browser.
- **Browser** — breadcrumb from root, entries with kind/size/modified, actions *Register
  here*, *New project here*, *Detect project* (shows detected types).
- **Workspaces** — cards with display name, `root/relative_path`, profile, registered at,
  the restart note; *Unregister* only (files never touched).
- **Approvals** — pending requests with tool, resource, TTL; Approve / Reject.
- **Devices** — paired devices (name, fingerprint, created, revoked) with Revoke, and
  pending pairings with Approve / Reject (disabled with an explanation unless the page is
  open on the host).

Polling: approvals 5 s, devices/pairings 10 s while visible, everything else on demand.

### 7.10 Error mapping

`Validation` / bad JSON → 400 · `PermissionDenied` → 403 · `NotFound` / `WorkspaceNotFound`
/ `DeviceNotFound` → 404 · `Config` and everything else → 500. Message text passes through
(see 7.5 exception 2).

## 8. Testing

Rust integration tests (`tower::ServiceExt::oneshot` against `build_router` with a temp
`data_dir`, a temp discovery root, and a test-only `ConnectInfo` extension so peers can be
simulated without sockets):

1. Loopback: `/api/v1/device` 200 with real counts; browse → register → list → unregister.
2. Non-loopback + `pairing_required = true`, no token: `/api/v1/workspaces` → 401.
3. Same, with a valid token → 200.
4. **Same, with `pairing_required = false` → still 401** (§7.4 gate is independent).
5. Non-loopback: `/pair/request` → 200 (**regression test for the bootstrap bug**).
6. Non-loopback: `/api/v1/devices` → 403 (host-only).
7. Limiter: unauthenticated burst > N → 429; authenticated burst of the same size → no 429.
8. Duplicate register returns the existing id and `already_registered: true`.
9. Path hygiene: `/api/v1/workspaces` and `/api/v1/device` bodies contain no absolute path;
   approvals may (documented exception) — asserted explicitly so the exception is pinned.
10. `/ui`, `/ui/app.js`, `/ui/app.css` → 200 without a token.
11. Empty `[discovery]` synthesises roots; non-empty config wins over synthesis.
12. Root disable: browse → 403/400 afterwards, and `register` refuses.
13. MCP unchanged: `cargo test -p runtime-mcp` plus the re-committed auth suite (below).

TLS (M0):
14. Cert generated once, reused on second start (mtime/fingerprint stable), regenerated when
    the SAN set no longer covers the current address.
15. `https://<lan-ip>:P/health` succeeds against the generated cert with a pinned rustls
    client; plain `http://<lan-ip>:P/health` is refused when TLS is on.
16. Loopback still answers plain HTTP on the same port while a LAN listener is up.
17. `tls = "off"` on a LAN bind is refused unless `--insecure-http` is passed.

Reproducibility: copy the existing verification scripts into the repo at `scripts/verify/`
(`auth-flow.mjs`, `auth-verify.ps1`, `persist-verify.ps1`) so the M1/M3 gates run from a
clean checkout instead of `%TEMP%`. If they are gone from `%TEMP%`, they are rewritten.

Live, end of M3: `yl serve --allow-remote` with a temp config, open `https://<lan-ip>:P/ui`
on a phone, accept the warning, compare fingerprints, pair by code, browse, register,
confirm `workspaces.jsonl` grew, `yl devices revoke`, next console call → 401.

No test claims behaviour that was not executed (§17).

## 9. Milestones

- **M0 — transport.** `tls.rs` (cert gen/load/fingerprint), dual listeners, rustls feature
  pinning, `--insecure-http` guard, startup output, tests 14–17. Gate: `cargo check
  --workspace` (standard excludes), TLS tests, and a real `https://` request from another
  device.
- **M1 — plumbing + auth fix.** Middleware allowlist/limiter/`/api/v1` gate,
  `build_router`, `ApiState`, `DiscoveryService` wiring (incl. §7.6 synthesis), the two
  `WorkspaceServiceImpl` accessors, `/api/v1/device`, `/ui` shell, tests 2/3/4/5/6/7/10/11.
  Gate: `cargo test -p runtime-cli` + `mcp-verify` auth suite green from repo scripts.
- **M2 — discovery + workspaces.** Roots/entries/detect, workspace list/get/register/
  create/unregister, path hygiene, duplicates, UI panes. Tests 1/8/9/12.
- **M3 — approvals + devices.** Approvals, devices/pairings (host-only), audit events, UI
  panes, full suite, phone pass, `docs/spec/PHASE-G-STAGE1-AUDIT.md` per §17.

## 10. Risks and mitigations

- **rustls/aws-lc build failure on Windows** → pin `rustls` to the `ring` provider (already
  a workspace dependency) and verify before writing any TLS code; M0 stops rather than
  shipping a broken build.
- **Self-signed cert friction on phones** → documented one-time warning + fingerprint
  comparison in the UI; no programmatic trust changes.
- **Making `/pair/*` public widens the anonymous surface** → single-use codes, 10-min TTL,
  rate-limited; approve/reject/list/revoke stay loopback-only.
- **Limiter change weakens brute-force protection** → only *valid* sessions bypass; test 7.
- **`runtime-cli` becomes the HTTP adapter too** → handlers stay thin; move `http_api` to
  `runtime-api` if a second host appears.
- **Console-registered workspaces need a restart to be agent-visible** → surfaced in the
  response and UI; documented, not silently ignored.

## 11. Left to the builder

Visual design and CSS, exact polling intervals, test file placement
(`crates/runtime-cli/tests/` vs inline `#[cfg(test)]`), whether the header shows a `yolo`
badge, whether pairing codes are logged locally, and how many prior-run certificates to keep
when regenerating.
