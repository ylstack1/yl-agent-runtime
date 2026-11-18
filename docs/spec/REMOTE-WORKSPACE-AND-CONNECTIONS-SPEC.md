# YL Agent Runtime — Remote Workspace Discovery, Project Lifecycle & Connectivity

**Document type:** Architecture and implementation specification  
**Status:** Proposed — design baseline for repository implementation  
**Version:** 1.0  
**Date:** 2026-11-19  
**Applies to:** Existing YL Agent Runtime repository  
**Primary host:** Windows 10/11 x64  
**Targets:** Windows, Linux and macOS runtime hosts; desktop controller first  
**Relationship:** Focused companion to `YL-Agent-Runtime-Specification-v0.2.md`  
**Implementation rule:** This document describes intended behavior. It does not claim that any feature below is already implemented.

---

## 1. Purpose

Build a first-class way for a user or compatible client to discover, select, create, import, clone and manage a project on a runtime host **before an AI agent starts**.

MCP is an agent integration protocol, not the only control plane. A client must be able to connect to a runtime, browse permitted locations, choose or prepare a workspace, and inspect its metadata without first starting an agent or relying on an MCP client to expose a file picker.

The runtime remains the execution and security boundary. A remote project normally stays on the remote machine; selecting it must not require downloading the entire project to the controller.

This specification covers:

1. Configurable filesystem discovery roots and drive/folder allowlists.
2. Browsing and project detection before workspace registration.
3. Existing workspace registration.
4. Creating an empty project/folder.
5. Importing/copying a project from the controller to the runtime host.
6. Cloning a Git repository (including GitHub URLs).
7. Workspace registry and lifecycle operations.
8. LAN-first connectivity and optional secure overlay/tunnel access.
9. A client flow that selects the workspace before starting an agent.
10. Security, reliability, performance, testing and phased delivery.

## 2. Product decisions

The following are accepted product decisions for this design:

| Area | Decision |
|---|---|
| Discovery start location | Configurable roots, not a hard-coded home directory or full-disk scan |
| Example default on the primary Windows development host | A configured root such as `E:\\ylstack-space\\Developments` |
| Root configuration | User-controlled, editable, enable/disable per root and per drive |
| Discovery scope | Only explicitly enabled/authorized roots and their descendants |
| Existing projects | Support registering an existing directory without copying it |
| New projects | Support creating an empty project directory |
| Import | Support copying/uploading a project from controller to runtime host |
| Git | Support cloning a Git URL into a selected allowed destination |
| Workspace use | Existing project registration, import, clone and new project creation all produce a selectable workspace |
| Default network | Same-LAN connection |
| Optional network | Tailscale, Cloudflare Tunnel and other pluggable user-managed connectivity |
| Protocols | Versioned management API + realtime channel + MCP adapter + native Rust APIs |
| Dependency policy | No mandatory Cloudflare, Tailscale, GitHub, cloud account or hosted service |
| Agent startup | Must happen after device connection and workspace selection/creation |

The example E: path is a suggested user configuration, **not a hard-coded product default**. Fresh installations should present a first-run setup to select one or more roots, with safe platform-aware suggestions.

## 3. Core concepts and terminology

Keep these operations distinct in APIs and UI:

- **Browse:** List directories and files within an authorized discovery root. Does not register or copy anything.
- **Detect:** Inspect a selected directory and return project hints (for example Git repository, Cargo workspace, package.json, solution, pyproject, Android project). Detection is advisory and must not execute project code.
- **Register:** Add an existing directory as a named workspace. Files remain where they are.
- **Create:** Create a new directory under an authorized destination, optionally with a minimal empty folder structure. Do not silently scaffold arbitrary templates.
- **Import:** Transfer files from a controller/client or another approved source into a destination on the runtime host.
- **Clone:** Run Git clone on the runtime host into an authorized destination.
- **Attach:** Optionally create a temporary session-scoped workspace reference without adding it to the persistent favorites/registry.
- **Workspace:** A registered or session-attached project root that agent capabilities can reference by opaque ID.
- **Discovery root:** A user-authorized filesystem boundary from which browsing and destination selection are allowed. It is not automatically a workspace.

A workspace ID must be opaque and stable; do not make clients construct arbitrary host paths and pass them as workspace identity.

## 4. User experience and required flows

### 4.1 First-run runtime setup

When a runtime host is first configured:

1. Show detected drives/mounts as informational choices, not as automatically authorized roots.
2. Let the user add a directory by native folder picker or explicit path.
3. Let the user enable/disable each configured root.
4. Let the user add a root such as `E:\\ylstack-space\\Developments`.
5. Optionally configure narrower or broader roots, e.g. `D:\\Projects`, `C:\\Users\\<user>\\source`, or a Linux/macOS project directory.
6. Show the effective access scope before saving.
7. Warn if a selected root is a drive root or contains sensitive/system directories.
8. Persist configuration and make it editable later without restarting unrelated agent sessions where safe.

Do not automatically authorize every mounted drive. Do not use an empty allowlist to mean unrestricted access.

### 4.2 Connect and select a project

The controller flow should be:

1. Select a known runtime device or add/connect to one.
2. Establish and authenticate the connection.
3. Display host identity, OS, runtime version, connection type and trust status.
4. Load authorized discovery roots.
5. Browse folders under a selected root.
6. Select an existing project or a destination.
7. Show project detection results and Git status hints where available.
8. Choose **Open existing**, **Create**, **Import**, or **Clone**.
9. Register/attach the resulting workspace as appropriate.
10. Select the workspace and its execution profile/permissions.
11. Only then start or connect an agent.

The client must preserve the distinction between local controller files and remote host files. Show the target device and destination clearly before a copy or clone begins.

### 4.3 Existing project registration

- Browse to a directory under an enabled discovery root.
- Preview its name, path relative to the root, detected project markers and Git repository status.
- Register it without moving, copying or modifying its contents.
- Permit an optional display name and tags.
- Detect an already registered directory and offer to open the existing workspace rather than create a duplicate.
- Registration must not imply unrestricted process, network or filesystem permissions. The policy engine still grants capabilities separately.

### 4.4 Create an empty project

- User selects an enabled destination root and a valid new folder name.
- Validate path, reserved names, collisions, permissions and available space where supported.
- Create the directory atomically where practical.
- Optionally create only user-selected empty subdirectories (for example `src`, `docs`, `tests`); no implicit dependency install or arbitrary template execution.
- Register the new directory after successful creation.
- If registration fails, return a recoverable result and explain whether the directory was created.
- Never overwrite an existing destination silently.

### 4.5 Import/copy from controller to runtime host

Support importing a project folder from the controller into an authorized remote destination.

Requirements:

- Preflight the source and destination; show a file-count/size estimate when feasible.
- Provide explicit conflict behavior: fail if destination exists (default), merge only with explicit confirmation, or import into a new uniquely named folder.
- Preserve relative directory structure and supported file metadata.
- Exclude configured patterns such as `.git`, build output, dependency caches or secrets only when the user chooses/accepts the import profile. Make exclusions visible and editable; never silently omit user data.
- Support large files, bounded concurrency, progress, cancellation and resumable transfer.
- Use chunked streaming; do not buffer the whole project in memory.
- Verify per-file or per-chunk integrity and a final manifest/hash before reporting success.
- Use temporary staging and atomic rename/finalization where supported. On failure, keep a recoverable transfer record and clean temporary data only under a defined retention policy.
- Reject path traversal, absolute-path injection, alternate data stream abuse where relevant, symlink/reparse escapes and duplicate/case-colliding names on case-insensitive targets.
- Apply destination-root authorization on the runtime host, not just in the client UI.
- After a successful import, offer to register the imported directory as a workspace.

The transfer protocol must not require SMB shares, a shared drive, or a mounted remote filesystem.

### 4.6 Clone Git repository

- Accept HTTPS and SSH Git URLs supported by the installed Git client; provider-specific GitHub integration is optional.
- Clone on the runtime host, not the controller, so the resulting checkout and toolchains remain on the execution machine.
- Destination must be inside an enabled discovery root with create permission.
- Show normalized repository host/URL and destination before execution.
- Support branch/tag/commit selection when the installed Git supports it.
- Support private repositories through user-managed credentials or a future credential-provider integration. Never ask the user to paste a token into a URL or persist plaintext credentials in runtime config, logs, audit events or process output.
- Do not assume GitHub API access is required for ordinary public Git clone.
- Do not run hooks, build scripts, package installation or project code as part of clone.
- Capture structured progress, stdout/stderr, exit status and cancellation.
- Register the checkout only after clone succeeds and destination validation passes.
- Avoid deleting an existing destination on failure or retry.

### 4.7 Workspace management

The client should be able to list, open, rename display metadata, favorite, detach, unregister and inspect registered workspaces.

- Unregistering a workspace removes its registry association; it must not delete project files.
- Deleting files/project directories is a separate destructive capability requiring explicit authorization and confirmation.
- Active sessions must prevent unsafe unregister/delete operations or require a documented detach/stop flow.
- Workspace registry persistence must survive daemon restarts.
- Store canonical host-side root references and stable IDs; clients receive opaque IDs plus safe display metadata.
- Registry entries should include created/updated timestamps, source operation (registered/created/imported/cloned), host/device association and optional last-opened metadata.
- Registry persistence must be designed to match the existing SQLx/database architecture and migrations. Reuse existing storage abstractions after inspecting the current implementation; do not introduce a second database stack without an ADR.

## 5. Configurable filesystem discovery and allowlist

### 5.1 Configuration model

The runtime must support multiple configured roots. Suggested conceptual TOML (final names and schema must be reconciled with the current `runtime-config` types and migration system):

```toml
[filesystem_discovery]
enabled = true
default_root_id = "developments"
show_hidden = false
follow_symlinks = false
max_depth = 12
max_entries_per_page = 250

[[filesystem_discovery.roots]]
id = "developments"
label = "Developments"
path = "E:\\ylstack-space\\Developments"
enabled = true
browse = true
create = true
register = true
import = true
clone = true

[[filesystem_discovery.roots]]
id = "other-projects"
label = "Other Projects"
path = "D:\\Projects"
enabled = false
browse = true
create = true
register = true
import = true
clone = true

[filesystem_discovery.drives]
# Optional platform-specific drive-level controls.
# A disabled drive must not be browsable merely because another root
# happens to be configured on it.
```

This is an illustrative schema, not a committed config contract. The implementation must define a typed, validated schema, defaults, migration behavior and documentation.

### 5.2 Root and drive controls

- Roots are explicit canonical directories, not arbitrary string prefixes.
- Multiple roots can exist on the same drive.
- User can enable/disable, add, edit, remove and reorder roots.
- Browse/create/register/import/clone permissions may be independently configured per root.
- Optional drive-level deny/disable controls may prevent adding roots from a drive.
- Drive-level configuration must not accidentally broaden a narrower root.
- An explicit root is the maximum discovery scope; the default is no access outside configured roots.
- Never interpret `C:\\*` or a wildcard pattern as permission to traverse all of C: without an explicit high-risk confirmation and a clearly defined policy.
- Prefer literal canonical root paths. If glob-like root patterns are supported later, expand them at configuration time, display the resolved roots, cap expansion and require explicit confirmation. Do not use ambiguous wildcard matching as the security boundary.
- Environment-variable expansion, if supported, must be deterministic, documented and validated; do not allow an untrusted client to inject environment expansion into privileged paths.
- A user may allow one directory on C: while denying the rest of C:. A disabled drive blocks new discovery roots on that drive but does not erase or relocate files.

### 5.3 Path containment and platform safety

All browse and destination paths must be resolved by the runtime host:

1. Resolve the selected root ID to a configured canonical root.
2. Accept a normalized relative path, not an arbitrary client-supplied absolute path.
3. Reject traversal segments and invalid platform path forms.
4. Resolve existing path components and verify containment after canonicalization.
5. Enforce symlink/reparse-point policy, including junctions and mount points.
6. Re-check containment at the point of opening/creating to reduce time-of-check/time-of-use races.
7. For create/import/clone, validate the final destination and its parent before mutation.
8. Apply platform-specific case sensitivity and reserved-name rules.
9. Do not follow links outside the root unless a separate explicit policy and safe implementation is approved.
10. Return stable error codes without leaking unrelated host paths.

Use and extend the repository's existing `runtime-workspace` path-safety primitives where appropriate. Do not create a weaker parallel path validator in the HTTP layer.

### 5.4 Browsing performance

- Paginate large directories; never require returning an entire drive tree.
- Default to shallow directory listing and on-demand expansion.
- Use bounded page sizes and configurable maximum depth.
- Avoid recursively scanning the whole configured root on every UI refresh.
- Cache only metadata that can be invalidated safely; provide explicit refresh.
- Support cancellation and timeouts for slow/network-mounted folders.
- Return file type, name, relative path, size and modified time where available; do not read file contents during ordinary browsing.
- Hidden/system files visibility is configurable and should default conservatively.
- Project detection is a bounded, non-executing marker scan. Do not recursively inspect huge dependency/build directories.
- Add watcher-driven invalidation only after verifying the current watcher implementation and platform behavior.

## 6. Management API and protocol boundaries

### 6.1 Protocol responsibilities

Use a hybrid model:

| Interface | Responsibility |
|---|---|
| Native Rust service APIs | Internal service-to-service operations and embedded clients |
| Versioned HTTP API | Device info, roots, browse, detect, workspace CRUD, create, clone, transfer control and configuration |
| HTTP streaming | Upload/download and large transfer data with bounded streaming |
| WebSocket or equivalent event stream | Transfer progress, filesystem invalidation, task/process events, terminal I/O where supported |
| MCP | Agent-facing capability tools once an agent/session is running |
| Optional Iroh transport | Encrypted peer connectivity if its current implementation is completed and validated |

Do not make WebSocket the only management interface. Ordinary browse/list/register requests should be request/response operations. Realtime events should be additive.

### 6.2 Proposed endpoint shape

The exact router/crate placement is a design decision to make after inspecting current code. Suggested versioned API:

- `GET /api/v1/device` — runtime identity, platform and capabilities.
- `GET /api/v1/discovery/roots` — roots visible to the authenticated principal.
- `POST /api/v1/discovery/roots` — add/configure root (owner/admin permission).
- `PATCH /api/v1/discovery/roots/{root_id}` — update root settings.
- `DELETE /api/v1/discovery/roots/{root_id}` — remove root configuration (not files).
- `GET /api/v1/discovery/roots/{root_id}/entries?path=&cursor=&limit=` — paginated browse.
- `POST /api/v1/projects/detect` — bounded project detection for root-relative path.
- `POST /api/v1/workspaces/register` — register existing directory.
- `POST /api/v1/workspaces/create` — create and register a new directory.
- `GET /api/v1/workspaces` — list registered workspaces.
- `GET /api/v1/workspaces/{workspace_id}` — workspace metadata.
- `PATCH /api/v1/workspaces/{workspace_id}` — metadata only.
- `DELETE /api/v1/workspaces/{workspace_id}` — unregister only; never delete files.
- `POST /api/v1/imports` — create transfer and return upload instructions.
- `PUT /api/v1/imports/{transfer_id}/chunks/{chunk_id}` — authenticated streaming chunk upload.
- `GET /api/v1/imports/{transfer_id}` — transfer status/resume metadata.
- `POST /api/v1/imports/{transfer_id}/finalize` — verify and finalize import.
- `POST /api/v1/git/clones` — create a clone task.
- `GET /api/v1/tasks/{task_id}` — task status and structured result.
- `POST /api/v1/tasks/{task_id}/cancel` — cancel a supported task.
- `GET /api/v1/events` or `/ws/v1/events` — authenticated event stream.

Endpoint names are proposals; maintain consistent REST conventions and the repository's existing API versioning. Do not expose host absolute paths in IDs or require the client to know internal path layout.

### 6.3 Shared service layer

All interfaces must call the same underlying services and policy checks:

- Native client API
- HTTP management adapter
- MCP tool adapter
- Future other protocol adapters

Avoid implementing filesystem authorization separately in REST and MCP. The HTTP handler should validate request shape/authentication, then call a domain service that enforces root authorization, workspace ownership and path safety.

Reuse existing crates and traits when they already provide the right abstraction. Potential responsibilities (not a mandate to create these exact crates):

- `runtime-workspace`: registered workspace operations and safe filesystem access.
- A discovery service, potentially within `runtime-workspace` initially: configured roots, browse and project detection.
- `runtime-config`: typed root/drive settings and migrations.
- `runtime-identity` / `runtime-policy`: device/user identity, authorization and capability checks.
- `runtime-transport`: peer connectivity and transport lifecycle, not business-level browse handlers.
- `runtime-daemon`: shared service graph and lifecycle.
- `runtime-cli`: local administration and diagnostics.
- `runtime-mcp`: MCP adapter over the shared service layer.
- Existing Axum server/router, if still present and suitable: host the management routes alongside MCP rather than starting an unrelated second server.

Do not create `runtime-discovery` or `runtime-http` automatically just because they are listed as possible boundaries. First inspect current crates, dependencies and ownership; document the chosen placement.

## 7. Connectivity: LAN default, optional remote access

### 7.1 Default LAN connection

- Runtime can listen on loopback by default for local-only use.
- LAN access is an explicit user-enabled setting, not an accidental `0.0.0.0` exposure.
- Provide a clear LAN address/port and pairing flow.
- Bind only to selected interfaces where possible.
- Discoverability (mDNS/broadcast) is optional; manual address entry must work.
- LAN mode still requires authentication, authorization and encrypted transport. A trusted Wi-Fi network is not an authentication mechanism.
- Do not expose an unauthenticated management or MCP endpoint on the LAN.
- The UI must show whether the runtime is local-only or LAN-accessible.

### 7.2 Optional connectivity providers

Connectivity must be pluggable and optional. The runtime should not require a cloud account or a specific vendor.

Initial provider targets:

1. **Tailscale:** User installs/configures Tailscale separately. Runtime can connect using the host's Tailscale interface/address. Do not require the runtime to manage the user's tailnet or store Tailscale credentials.
2. **Cloudflare Tunnel / Quick Tunnel:** Optional user-managed outbound tunnel to a configured local runtime endpoint. Treat Quick Tunnels as temporary/development convenience, not a production identity or authorization system. A tunnel URL is not a secret substitute for authentication.
3. **Other tunnel/reverse-proxy providers:** Support by documented generic endpoint configuration or a provider adapter, without hard-coding vendor behavior into core workspace services.
4. **Iroh:** Optional peer-to-peer transport if/when the existing Iroh implementation is complete, secure and interoperable. It is not a prerequisite for LAN use.

The runtime should accept an externally reachable endpoint and transport metadata through configuration. It must not launch or configure third-party tunnel clients without explicit user consent.

### 7.3 Connection abstraction

Conceptual model:

- Device identity is independent of network address.
- A device may advertise multiple connection candidates: local loopback, LAN, Tailscale, configured tunnel, Iroh.
- Client chooses a reachable candidate and authenticates the device identity.
- A changed IP address must not create a new device identity.
- Connection provider is replaceable without changing workspace APIs.
- Expose connection state and type (local/LAN/overlay/tunnel/P2P), latency where measurable, last seen and authentication/trust status.
- Reconnect with bounded backoff and cancellation.
- Do not claim end-to-end encryption for a provider unless the actual connection path and certificate/peer verification guarantee it.

### 7.4 Security prerequisites before remote exposure

Remote management must not be exposed until the following are implemented and tested:

- Device pairing/approval lifecycle with cryptographic identity verification.
- Authenticated sessions and scoped, revocable credentials.
- Per-device, per-user, per-agent and per-workspace authorization.
- Short-lived access tokens or equivalent session credentials; secure refresh/revocation.
- TLS for HTTP/WebSocket when traffic leaves loopback, or a verified encrypted peer transport.
- Strict origin/host validation appropriate to the deployment; do not disable checks merely to make LAN access work.
- Rate limits for pairing, authentication, browse and transfer endpoints.
- Request size, upload size, concurrency and time limits.
- Audit events for root changes, workspace mutations, clone/import operations, permission changes and authentication failures.
- WebSocket authentication and authorization before upgrade, plus session expiry/revocation handling.
- Secrets redaction from logs, errors, process output and audit events.
- Fail-closed behavior when authentication or authorization cannot be established.

**Critical:** Binding to `0.0.0.0`, using CORS, obscuring a URL or relying on a private network does not authenticate a caller. Do not ship remote filesystem browsing or file transfer on top of an unauthenticated endpoint. Audit the current server path and close any existing exposure before enabling LAN/tunnel access.

## 8. Pairing, authorization and policy

- Pairing must be an explicit user-approved trust operation.
- A new controller receives no workspace access before approval.
- Revocation takes effect for future requests and active streams/sessions according to a documented shutdown policy.
- Discovery roots are owner-controlled resources.
- Root capabilities are distinct: browse, create, register, import, clone.
- Workspace capabilities remain distinct: read, write, search, delete, execute, terminal, network and Git operations.
- A root's existence does not imply all workspace capabilities are granted.
- Agent permissions are scoped to the selected workspace and session.
- A client cannot elevate itself by choosing a different path, root ID or workspace ID.
- Destructive operations and permission escalation require approval according to policy.
- Record the authenticated principal, target device, root/workspace ID, action, result and timestamp in audit logs. Avoid recording sensitive file contents or credentials.

## 9. Data model concepts

The final types must fit existing ID conventions and serde/schema patterns. Suggested concepts:

- `DiscoveryRootId`
- `DiscoveryRoot`: ID, label, canonical host path (internal only), enabled state, per-operation flags, platform metadata.
- `BrowseEntry`: name, relative path, entry kind, size, modified time, hidden flag, optional safe metadata.
- `ProjectDetection`: detected markers, likely project types, Git presence/branch hints, confidence and scan limits.
- `WorkspaceId`
- `WorkspaceRecord`: opaque ID, root reference, relative path, display name, origin operation, timestamps, optional tags/favorite.
- `TransferId`
- `TransferManifest`: source metadata, relative entries, size, hashes, exclusions, destination root ID and relative path.
- `TransferState`: queued, receiving, paused, verifying, finalizing, completed, failed, cancelled, expired.
- `TaskId` / `CloneTask`: sanitized repository reference, destination root/path, selected ref, progress and result.
- `ConnectionCandidate`: provider, endpoint, transport security metadata and priority.
- `DeviceTrustState`: pending, approved, revoked, expired.

Never serialize internal canonical host paths to an untrusted remote principal unless the UI/API explicitly needs a redacted display value. Prefer root-relative paths.

## 10. Error handling and operation semantics

Return stable machine-readable error codes, with safe human-readable messages. Suggested categories:

- `ROOT_NOT_FOUND`, `ROOT_DISABLED`, `ROOT_ACCESS_DENIED`
- `PATH_OUTSIDE_ROOT`, `PATH_INVALID`, `PATH_LINK_ESCAPE`
- `ENTRY_NOT_FOUND`, `ENTRY_TYPE_MISMATCH`, `ENTRY_LIMIT_EXCEEDED`
- `WORKSPACE_ALREADY_REGISTERED`, `WORKSPACE_NOT_FOUND`, `WORKSPACE_BUSY`
- `DESTINATION_EXISTS`, `DESTINATION_NOT_WRITABLE`, `INSUFFICIENT_SPACE`
- `TRANSFER_EXPIRED`, `TRANSFER_HASH_MISMATCH`, `TRANSFER_INCOMPLETE`
- `GIT_NOT_FOUND`, `GIT_AUTH_FAILED`, `GIT_CLONE_FAILED`
- `PAIRING_REQUIRED`, `DEVICE_REVOKED`, `SESSION_EXPIRED`, `CAPABILITY_DENIED`
- `OPERATION_CANCELLED`, `OPERATION_TIMEOUT`, `INTERNAL_ERROR`

Mutating operations must be idempotent where practical. Use operation/transfer IDs to make retries safe. Never report success before final verification and durable state update.

## 11. Observability and audit

- Structured logs with correlation/request/task/transfer IDs.
- Progress events include completed/total bytes and files where known, rate and current phase; avoid overly frequent events.
- Do not log file contents, secrets, private clone URLs containing credentials or raw authorization headers.
- Audit records distinguish attempted, approved, denied, completed and failed actions.
- Surface meaningful diagnostics in the client without exposing stack traces or sensitive host details.
- Provide a CLI diagnostic command for effective roots, connectivity mode, identity/pairing state and service health, with secrets redacted.

## 12. Desktop/controller requirements

The desktop app is a controller, not the authority for filesystem access. It should provide:

- Device list and connect/disconnect state.
- Pair/approve/revoke device flow.
- Local/LAN/optional overlay endpoint management.
- Remote file browser rooted at configured roots.
- Root management screen with enabled state and browse/create/register/import/clone toggles.
- Project detection preview.
- Actions: Open existing, Create new, Import from this device, Clone Git repository.
- Import progress, pause/resume/cancel and retry.
- Clone task progress and errors.
- Workspace list, favorites and recent workspaces.
- Workspace detail showing target device and root-relative location.
- Agent start flow only after workspace selection.
- Clear distinction between controller-local and runtime-remote file locations.

The app must not store long-lived credentials in plaintext. Use platform credential storage where available, or the established secure secret-storage abstraction.

## 13. Non-goals and explicit constraints

- This is not a remote desktop product.
- Do not sync every remote project continuously by default.
- Do not mount the remote filesystem as a local drive as a prerequisite.
- Do not scan every drive recursively by default.
- Do not expose the whole filesystem because a user enabled one project root.
- Do not make MCP responsible for device onboarding or pre-agent project selection.
- Do not hard-code `E:\\ylstack-space\\Developments`, drive letters, usernames, tunnel vendors, ports or provider credentials in runtime logic.
- Do not require GitHub API credentials for public clone.
- Do not run project scripts during browse, detection, registration, import or clone.
- Do not delete project files when unregistering a workspace.
- Do not introduce a new database, HTTP framework or transport stack without inspecting and documenting why existing abstractions are insufficient.

## 14. Implementation strategy and phases

Implementation must be incremental, compile-tested and reviewable. Do not attempt to build all remote functionality in one large patch.

### Phase A — Repository audit and design reconciliation

1. Read the current PRD, handoff, ADRs, config schema/migrations, identity/pairing, policy, workspace/path-safety, daemon, CLI/server, MCP, transport and desktop app.
2. Inspect git status and preserve all pre-existing modifications and untracked files.
3. Identify which requirements already exist, partially exist, are stubs or are missing.
4. Map each requirement to existing crate/types/functions.
5. Confirm the current HTTP server/router and whether it can safely host management endpoints.
6. Write/update an ADR for discovery roots and remote management/security boundaries if architecture decisions are needed.
7. Produce a short implementation plan with acceptance criteria before broad edits.

**Exit criteria:** Current-state matrix with file references, dependency direction and verified build/test baseline. No feature is marked complete based only on old docs.

### Phase B — Local discovery and configurable roots

1. Define validated typed root configuration and migration/default behavior.
2. Implement root add/edit/enable/disable/remove.
3. Implement root-relative paginated browse.
4. Enforce canonical containment and link policy using shared path-safety code.
5. Add bounded project detection without executing code.
6. Add CLI diagnostics and unit/security tests.

**Exit criteria:** Local user can configure a root, browse only within it, disable it, and receive safe errors for traversal and link escapes. No remote networking required.

### Phase C — Workspace lifecycle and persistence

1. Inspect current workspace registry and database abstractions.
2. Persist workspace records and migrations.
3. Implement register existing, create empty, list/get and unregister semantics.
4. Add duplicate detection and active-session safety.
5. Keep destructive file deletion separate.
6. Add restart/recovery tests.

**Exit criteria:** Existing project can be registered and reopened after daemon restart; create produces a registered workspace; unregister never deletes files.

### Phase D — Git clone and local import foundation

1. Implement host-side clone task with safe destination and credential redaction.
2. Add clone cancellation, progress and structured errors.
3. Define import manifest, transfer state and integrity verification.
4. Implement local transfer primitives and staging/finalization.
5. Test conflict policies, interrupted transfers and retries.

**Exit criteria:** Clone and import are safe, resumable where specified, integrity-verified and produce a selectable workspace.

### Phase E — Authenticated LAN management API

1. Finish/review device identity, pairing approval, sessions and revocation.
2. Define management API DTOs and stable error codes.
3. Mount endpoints in the existing server architecture if suitable.
4. Enforce root/workspace authorization in shared services.
5. Add TLS/verified encrypted transport, origin/host validation, rate limits and audit.
6. Add authenticated streaming upload and event channel.
7. Run threat-focused integration tests before enabling LAN exposure.

**Exit criteria:** A paired controller can browse and manage an authorized workspace over LAN; an unpaired/revoked controller cannot access roots or streams.

### Phase F — Optional remote connectivity

1. Support manual endpoint configuration.
2. Document and test Tailscale connectivity without taking ownership of the user's tailnet.
3. Document Cloudflare Tunnel/Quick Tunnel reverse-proxy setup and its limitations.
4. Add provider-neutral connection candidates and health state.
5. Evaluate Iroh implementation against current crate/API and threat model.
6. Test reconnect, address change, revocation and provider failure.

**Exit criteria:** Optional provider can carry the same authenticated API without changing workspace behavior. LAN-only installs remain fully functional.

### Phase G — Desktop controller integration

1. Device connection/pairing UI.
2. Root management and remote browser.
3. Register/create/import/clone flows.
4. Workspace list and selection.
5. Agent startup bound to the selected workspace and policy.
6. Error, progress and offline states.
7. Usability and performance tests on Windows 10/11.

**Exit criteria:** User can connect to a remote host, select/create/import/clone a project, register it and start an agent without manually configuring MCP workspace roots.

## 15. Acceptance criteria (end-to-end)

The feature is not complete until these scenarios pass on a real Windows runtime host:

1. User configures `E:\\ylstack-space\\Developments` as an enabled root.
2. Controller connects over the same LAN using an approved device identity.
3. Controller browses subfolders and selects an existing repository.
4. Controller registers it without copying or modifying files.
5. Workspace remains registered after daemon restart.
6. User disables the root; subsequent browse/create/import/clone calls against it are denied.
7. User enables a second root on D: while C: remains disabled; only configured roots are visible.
8. User creates a new project folder under an allowed root and it appears in the workspace list.
9. User imports a local controller folder to the remote host, sees progress, and the remote manifest verifies.
10. Interrupted import can resume or fail safely without corrupting an existing project.
11. User clones a public Git repository to an allowed destination and can register/open it.
12. Clone destination outside configured roots is rejected.
13. Traversal, junction and symlink escape tests fail closed.
14. Unpaired and revoked clients cannot browse, upload, clone or use WebSocket events.
15. LAN access is disabled by default until explicitly enabled and secured.
16. Optional Tailscale/Cloudflare endpoint can be configured without changing the workspace API.
17. Agent starts only after a workspace is selected and receives only granted workspace capabilities.
18. MCP and native/HTTP interfaces enforce the same workspace and policy rules.
19. No whole-drive recursive scan or whole-project in-memory buffering occurs in normal flows.
20. Existing tests and unrelated runtime features continue to pass.

## 16. Required test matrix

- Unit: config validation, root resolution, path normalization, project marker detection, workspace registry, transfer manifest.
- Security: traversal, symlink/junction/reparse escape, case collisions, reserved names, unauthorized root IDs, forged workspace IDs, expired/revoked tokens, origin/host validation, upload path injection.
- Integration: browse/register/create/import/clone over local services; daemon restart; database migration; task cancellation.
- Transfer: large files, many small files, empty files, hidden files, interrupted chunks, duplicate chunks, hash mismatch, destination conflict, disk full.
- Network: loopback, LAN, address change, reconnect, tunnel unavailable, unauthorized remote peer, expired session during WebSocket stream.
- Platform: Windows 10/11 first; Linux/macOS follow their platform support plan.
- Regression: current workspace/path-safety, policy, identity, daemon, MCP and CLI suites.

## 17. Implementation-agent instructions

This section is intended to be handed directly to the coding agent already working on this repository.

1. Treat this file as a **design specification**, not evidence that the features exist.
2. Start by inspecting the live repository and current git status. Do not trust old handoff claims until verified.
3. Preserve all user changes, untracked files, test artifacts and unrelated work. Never reset, clean, checkout-overwrite or delete files to make the tree look tidy.
4. Do not replace the current PRD or rewrite the architecture wholesale.
5. Reuse current crates and dependencies where appropriate; do not create duplicate services or parallel security validators.
6. Before implementation, produce a requirement-to-code map: existing / partial / missing / unsafe, with exact paths and symbols.
7. Propose the smallest coherent next milestone, its API/types, dependency direction, tests and acceptance criteria.
8. Implement one phase/milestone at a time. Run targeted tests, formatting and the relevant workspace checks after each change.
9. Never claim a test passed unless it was run and its result observed. Clearly separate verified behavior from planned work.
10. Update the repository's engineering handoff/memory documentation after every meaningful verified milestone: current state, decisions, roadmap, known issues, commands/tests and session log. If the repository has no `.memory/` directory, inspect the existing handoff convention and add to it consistently rather than inventing conflicting documentation.
11. Update ADRs when changing a durable architecture/security decision.
12. Do not enable LAN/tunnel remote filesystem access before authentication, pairing, authorization, TLS/verified encryption and security tests are complete.
13. Ask for clarification only when a decision materially blocks safe implementation; otherwise use the defaults and constraints in this document.

### Required first response from the implementation agent

Before changing source code, report:

- Current git status and latest commit.
- Relevant existing crates/files and their actual responsibilities.
- What is already implemented versus stubbed/missing.
- Current build/test baseline and exact commands/results.
- Security gaps affecting discovery or remote access.
- Proposed first milestone with a concise task list and tests.

Then proceed with Phase A and Phase B in small, reviewable steps after the audit.

---

## 18. Open decisions to resolve during repository audit

These are implementation details, not reasons to block the architecture:

- Exact config field names and schema version.
- Whether discovery initially lives inside `runtime-workspace` or a separate crate.
- Whether the current Axum router is the correct management API host.
- Exact database tables/migrations for workspace/root/transfer persistence.
- Whether upload streaming uses HTTP body streaming, a dedicated transfer protocol or both.
- Exact LAN TLS certificate provisioning and trust UX.
- Whether Iroh is sufficiently implemented to be offered as a supported provider.
- Which import exclusions should be offered as presets; defaults must be visible and non-destructive.
- Whether temporary attached workspaces are needed in the first desktop milestone.

Resolve these with repository evidence, tests and ADRs—not assumptions.

## 19. Final architecture principle

**Connect to a device → authenticate it → browse its configured roots → select/register/create/import/clone a project → choose permissions → start any compatible agent.**

The project lives on the machine that will execute it. The runtime controls what can be discovered and what the agent can do. MCP is one adapter among several, and optional networking providers change how the client reaches the runtime—not how workspace security or agent capabilities work.
