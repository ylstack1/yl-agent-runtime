# YL Agent Runtime — Approval Gate Design

**Date:** 2026-11-18
**Branch:** `phase3-approval-gate`
**Status:** Proposed (proceeding per partner instruction to not delay on questions)

## Intent / why

MCP tool calls currently bypass the policy engine entirely. `runtime-process` enforces its own executable allowlist, but there is no approval/gate mechanism: any allowlisted binary runs immediately, and dangerous tools (process exec/start, git write/commit) have no user-consent step. Phase 3 adds an approval gate so sensitive operations require explicit approval before executing, with project-level + global policy, a 30-minute auto-deny TTL, and a `--yolo` bypass for automation.

## Goals

1. **Every dangerous tool call is gated by policy.** `Ask` decisions return an `approval_id` and refuse to act until approved.
2. **Approve/deny/ask flow** via CLI (`yl approval approve <id>`) and MCP (`approval.approve` / `approval.reject` / `approval.list` / `approval.request`).
3. **Project-level policy** (`.yl/policy.toml`) overrides global policy (`config/runtime.toml` `[tools.approval]`).
4. **30-minute auto-deny** on pending approvals; persisted to disk so restarts don't lose them.
5. **`--yolo` bypass** (CLI flag + `YL_YOLO=1` env) that treats `Ask` as `Allow`, audited prominently.
6. **CLI and core are equally capable.** A GUI or desktop app can use the same CLI or core; no desktop-mode dependency.
7. **Add-on able.** `ApprovalBroker` is a trait; a different host (GUI) can plug its own broker.

## Non-goals

- Terminal approval (Phase 4).
- Per-file granular approval beyond resource string matching (Phase 4+).
- Approval for read-only tools (they remain `Allow`).

## Constraints

- Windows is the acceptance platform; all code must compile on Windows.
- Every output must compile and run — no stubs that only error.
- Do not break existing 23 MCP tools or the 78 passing tests.
- `data/audit.jsonl` and any new `data/approvals.jsonl` remain gitignored.

## Approaches considered

| Approach | Description | Trade-off | Verdict |
|---|---|---|---|
| **A — Centralized gate in MCP handlers** (chosen) | One `enforce_tool()` helper called at the start of each dangerous handler. Policy engine → Allow/Deny/Ask. Ask creates a pending approval via `ApprovalBroker`. | Slightly more surface (one call per handler) but single enforcement point, no drift. | **Chosen** |
| B — Per-tool manual enforcement | Each handler calls policy engine directly. | Duplicated logic, drifts (caused the runtime.* stub bug). | Rejected |
| C — Client-side only | No server enforcement; client decides. | Violates containment; compromised client bypasses. | Rejected |

## Design

### Data model (existing, reused)

- `Capability` (runtime-core): `ProcessExec`, `ProcessStart`, `ProcessTerminate`, `WorkspaceWrite`, `GitWrite`, `GitCommit`, etc.
- `PolicyDecision`: `Allow` / `Deny` / `Ask`
- `ApprovalId(pub Uuid)`, `AgentId(pub Uuid)`, `ProjectId(pub Uuid)`
- `ApprovalState`: `NotRequired` / `Pending` / `Granted` / `Rejected` / `Expired` / `Revoked`
- `ApprovalBroker` trait (runtime-core traits.rs): `request/check/approve/reject`
- `PolicyEngine` trait (runtime-core traits.rs): `evaluate/get_profile/get_capabilities`

### New component: `PendingApprovalStore` (`runtime-policy/src/broker.rs`)

Implements `ApprovalBroker`. Holds pending approvals in an `Arc<RwLock<HashMap<ApprovalId, PendingApproval>>>` and appends every state change to a JSONL log (`data/approvals.jsonl` under the data dir) for restart survival.

```rust
pub struct PendingApproval {
    pub id: ApprovalId,
    pub agent_id: AgentId,
    pub project_id: ProjectId,
    pub capability: Capability,
    pub resource: Option<String>,
    pub justification: String,
    pub requested_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,   // requested_at + 30 min
    pub state: ApprovalState,        // Pending / Granted / Rejected / Expired
}
```

Methods:
- `request(...)` → creates `Pending` entry, returns `ApprovalId`
- `check(id)` → returns current `PolicyDecision` (Allow if Granted, Deny if Rejected/Expired, Ask if Pending)
- `approve(id)` → `Granted`
- `reject(id, reason)` → `Rejected`
- Background TTL sweep: entries older than 30 minutes transition `Pending` → `Expired`

### Config

`config/runtime.toml`:
```toml
[tools.approval]
ttl_seconds = 1800          # 30 minutes
require_approval_for = ["process.exec", "process.start", "process.stop"]
yolo = false
```

Project override: `.yl/policy.toml` with same `[tools.approval]` table; most specific wins (project > global).

`PolicyConfig` already has `require_approval_for: Vec<Capability>` and `fail_closed`. I'll add `approval_ttl_seconds` and `yolo` fields, plus a loader that merges `.yl/policy.toml` over `config/runtime.toml`.

### MCP server wiring

`McpServer` gains two fields:
```rust
policy_engine: Arc<dyn PolicyEngine>,
approval_broker: Arc<dyn ApprovalBroker>,
```

New helper:
```rust
async fn enforce_tool(&self, capability: Capability, resource: Option<&str>) -> Result<(), McpError> {
    if self.yolo { return Ok(()); }  // bypass, audited
    let decision = self.policy_engine.evaluate(agent_id, project_id, capability, resource).await?;
    match decision {
        Allow => Ok(()),
        Deny => Err(invalid(format!("policy denied: {capability}"))),
        Ask => {
            let approval_id = self.approval_broker.request(agent_id, project_id, capability, resource.map(|s| s.to_string()), "tool call requires approval".into()).await?;
            Err(invalid(format!("approval required: {capability}. Approve with: yl approval approve {approval_id} (or MCP approval.approve). Expires in 30 minutes.")))
        }
    }
}
```

`agent_id` is derived from `principal_agent` (a fixed `AgentId` from a namespace UUID + name hash). `project_id` is `roots[0].0` (the primary root).

Handlers gated (Phase 3):
- `process.exec` → `ProcessExec`, resource = command
- `process.start` → `ProcessStart`, resource = program
- `process.stop` → `ProcessTerminate`, resource = process_id
- `workspace.write`/`edit`/`patch`/`delete` → `WorkspaceWrite`, resource = path (when not already Allow in the active profile)

`runtime-status`/`runtime-capabilities`/`workspace.read`/etc. remain ungated (`Allow` by default).

### New MCP tools

- `approval.request` — explicitly request approval for a capability+resource; returns `approval_id`
- `approval.approve` — approve a pending approval by id
- `approval.reject` — reject by id + reason
- `approval.list` — list pending (non-expired) approvals

### CLI

- `yl approval approve <id>`
- `yl approval reject <id> <reason>`
- `yl approval list`

### `--yolo`

- CLI flag: `yl serve --yolo`
- Env var: `YL_YOLO=1`
- When set, `enforce_tool` short-circuits to `Ok(())` and audits with `metadata.insert("yolo", "true")`.

## What's left to the builder

- Exact `.yl/policy.toml` merge semantics (project overrides global, or additive).
- Whether `approval.request` as a standalone MCP tool is needed (client can infer id from the tool-call error).
- Git tool gating (`git.add -A` block) is Phase 4, not here.
