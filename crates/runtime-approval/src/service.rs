//! Approval broker implementation
//!
//! User consent for sensitive operations per PRD section 7.4.
//! Pending approvals are persisted to a JSONL log so they survive server
//! restarts, and entries older than the TTL (30 minutes) auto-expire.

use runtime_core::ApprovalState;
use runtime_core::error::{Error, Result};
use runtime_core::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Approval broker trait
#[async_trait::async_trait]
pub trait ApprovalBroker: Send + Sync {
    async fn request(
        &self,
        agent_id: AgentId,
        project_id: ProjectId,
        capability: Capability,
        resource: Option<String>,
        justification: String,
    ) -> Result<ApprovalId>;
    async fn check(&self, approval_id: ApprovalId) -> Result<PolicyDecision>;
    async fn approve(&self, approval_id: ApprovalId) -> Result<()>;
    async fn reject(&self, approval_id: ApprovalId, reason: String) -> Result<()>;
    /// List pending (not-yet-decided) approvals.
    async fn list_pending(&self) -> Vec<ApprovalRequest>;
    /// List all approval requests (any state).
    async fn list_all(&self) -> Vec<ApprovalRequest>;
}

/// Approval request state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: ApprovalId,
    pub agent_id: AgentId,
    pub project_id: ProjectId,
    pub capability: Capability,
    pub resource: Option<String>,
    pub justification: String,
    pub state: ApprovalState,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub decided_at: Option<DateTime<Utc>>,
    pub decision_reason: Option<String>,
}

/// A single line written to the approval journal for persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JournalEntry {
    id: ApprovalId,
    agent_id: AgentId,
    project_id: ProjectId,
    capability: Capability,
    resource: Option<String>,
    justification: String,
    state: ApprovalState,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    decided_at: Option<DateTime<Utc>>,
    decision_reason: Option<String>,
}

/// Approval broker implementation
#[derive(Clone, Default)]
pub struct ApprovalBrokerImpl {
    requests: Arc<RwLock<HashMap<ApprovalId, ApprovalRequest>>>,
    log_path: Option<PathBuf>,
}

impl ApprovalBrokerImpl {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a broker that persists state changes to `path` and replays any
    /// existing journal on startup.
    pub fn with_log_path(mut self, path: PathBuf) -> Self {
        // Replay existing journal so pending approvals survive restarts.
        if let Ok(entries) = Self::replay(&path) {
            let mut map = HashMap::new();
            for entry in entries {
                map.insert(entry.id, entry.into());
            }
            self.requests = Arc::new(RwLock::new(map));
        }
        self.log_path = Some(path);
        self
    }

    /// Replay all journal entries from `path`. Later entries for the same id
    /// overwrite earlier ones, so the final map reflects the latest state.
    fn replay(path: &PathBuf) -> Result<Vec<ApprovalRequest>> {
        let mut entries = Vec::new();
        if !path.exists() {
            return Ok(entries);
        }
        let contents = std::fs::read_to_string(path)
            .map_err(|e| Error::Audit(format!("failed to read approval journal: {e}")))?;
        for line in contents.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let entry: JournalEntry = serde_json::from_str(line)
                .map_err(|e| Error::Audit(format!("failed to parse approval journal line: {e}")))?;
            entries.push(entry.into());
        }
        Ok(entries)
    }

    /// Append a state change to the journal.
    fn append_journal(&self, request: &ApprovalRequest) {
        let Some(ref path) = self.log_path else { return };
        let entry = JournalEntry {
            id: request.id,
            agent_id: request.agent_id,
            project_id: request.project_id,
            capability: request.capability,
            resource: request.resource.clone(),
            justification: request.justification.clone(),
            state: request.state,
            created_at: request.created_at,
            expires_at: request.expires_at,
            decided_at: request.decided_at,
            decision_reason: request.decision_reason.clone(),
        };
        let json = match serde_json::to_string(&entry) {
            Ok(j) => j,
            Err(e) => {
                tracing::warn!("failed to serialize approval journal entry: {e}");
                return;
            }
        };
        if let Err(e) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .and_then(|mut f| std::writeln!(f, "{json}"))
        {
            tracing::warn!("failed to append to approval journal: {e}");
        }
    }

    /// Check if an approval has expired
    fn is_expired(&self, request: &ApprovalRequest) -> bool {
        match request.expires_at {
            Some(expires) => chrono::Utc::now() > expires,
            None => false,
        }
    }

    /// Expire any pending entries past their TTL.
    pub async fn expire_old_requests(&self) {
        let now = chrono::Utc::now();
        let expired: Vec<(ApprovalId, ApprovalRequest)> = {
            let mut requests = self.requests.write().await;
            requests
                .iter_mut()
                .filter_map(|(id, request)| {
                    if request.state == ApprovalState::Pending {
                        if let Some(expires) = request.expires_at {
                            if now > expires {
                                request.state = ApprovalState::Expired;
                                request.decided_at = Some(chrono::Utc::now());
                                return Some((*id, request.clone()));
                            }
                        }
                    }
                    None
                })
                .collect()
        };
        for (_, request) in expired {
            self.append_journal(&request);
        }
    }
}

#[async_trait::async_trait]
impl ApprovalBroker for ApprovalBrokerImpl {
    async fn request(
        &self,
        agent_id: AgentId,
        project_id: ProjectId,
        capability: Capability,
        resource: Option<String>,
        justification: String,
    ) -> Result<ApprovalId> {
        let id = ApprovalId::new();
        let expires_at = Some(chrono::Utc::now() + chrono::Duration::minutes(30)); // 30 minute default

        let request = ApprovalRequest {
            id,
            agent_id,
            project_id,
            capability,
            resource,
            justification,
            state: ApprovalState::Pending,
            created_at: chrono::Utc::now(),
            expires_at,
            decided_at: None,
            decision_reason: None,
        };

        self.requests.write().await.insert(id, request.clone());
        self.append_journal(&request);
        Ok(id)
    }

    async fn check(&self, approval_id: ApprovalId) -> Result<PolicyDecision> {
        let requests = self.requests.read().await;
        let request = requests
            .get(&approval_id)
            .ok_or_else(|| Error::ApprovalExpired(format!("Approval not found: {}", approval_id)))?;

        if self.is_expired(request) {
            return Ok(PolicyDecision::Deny);
        }

        match request.state {
            ApprovalState::Granted => Ok(PolicyDecision::Allow),
            ApprovalState::Rejected => Ok(PolicyDecision::Deny),
            ApprovalState::Pending => Ok(PolicyDecision::Ask),
            ApprovalState::Expired => Ok(PolicyDecision::Deny),
            ApprovalState::NotRequired => Ok(PolicyDecision::Allow),
            ApprovalState::Revoked => Ok(PolicyDecision::Deny),
        }
    }

    async fn approve(&self, approval_id: ApprovalId) -> Result<()> {
        let mut requests = self.requests.write().await;
        let request = requests
            .get_mut(&approval_id)
            .ok_or_else(|| Error::ApprovalExpired(format!("Approval not found: {}", approval_id)))?;

        if self.is_expired(request) {
            return Err(Error::ApprovalExpired(format!("Approval expired: {}", approval_id)));
        }

        request.state = ApprovalState::Granted;
        request.decided_at = Some(chrono::Utc::now());
        let req = request.clone();
        drop(requests);
        self.append_journal(&req);
        Ok(())
    }

    async fn reject(&self, approval_id: ApprovalId, reason: String) -> Result<()> {
        let mut requests = self.requests.write().await;
        let request = requests
            .get_mut(&approval_id)
            .ok_or_else(|| Error::ApprovalExpired(format!("Approval not found: {}", approval_id)))?;

        request.state = ApprovalState::Rejected;
        request.decided_at = Some(chrono::Utc::now());
        request.decision_reason = Some(reason);
        let req = request.clone();
        drop(requests);
        self.append_journal(&req);
        Ok(())
    }

    async fn list_pending(&self) -> Vec<ApprovalRequest> {
        self.requests
            .read()
            .await
            .values()
            .filter(|r| r.state == ApprovalState::Pending)
            .cloned()
            .collect()
    }

    async fn list_all(&self) -> Vec<ApprovalRequest> {
        self.requests.read().await.values().cloned().collect()
    }
}

impl From<JournalEntry> for ApprovalRequest {
    fn from(e: JournalEntry) -> Self {
        Self {
            id: e.id,
            agent_id: e.agent_id,
            project_id: e.project_id,
            capability: e.capability,
            resource: e.resource,
            justification: e.justification,
            state: e.state,
            created_at: e.created_at,
            expires_at: e.expires_at,
            decided_at: e.decided_at,
            decision_reason: e.decision_reason,
        }
    }
}
