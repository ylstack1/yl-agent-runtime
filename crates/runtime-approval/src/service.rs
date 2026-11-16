//! Approval broker implementation

use runtime_core::ApprovalState;
use runtime_core::error::{Error, Result};
use runtime_core::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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

/// Approval broker implementation
#[derive(Clone, Default)]
pub struct ApprovalBrokerImpl {
    requests: Arc<RwLock<HashMap<ApprovalId, ApprovalRequest>>>,
}

impl ApprovalBrokerImpl {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if an approval has expired
    fn is_expired(&self, request: &ApprovalRequest) -> bool {
        match request.expires_at {
            Some(expires) => chrono::Utc::now() > expires,
            None => false,
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

        self.requests.write().await.insert(id, request);
        Ok(id)
    }

    async fn check(&self, approval_id: ApprovalId) -> Result<PolicyDecision> {
        let requests = self.requests.read().await;
        let request = requests.get(&approval_id)
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
        let request = requests.get_mut(&approval_id)
            .ok_or_else(|| Error::ApprovalExpired(format!("Approval not found: {}", approval_id)))?;

        if self.is_expired(request) {
            return Err(Error::ApprovalExpired(format!("Approval expired: {}", approval_id)));
        }

        request.state = ApprovalState::Granted;
        request.decided_at = Some(chrono::Utc::now());
        Ok(())
    }

    async fn reject(&self, approval_id: ApprovalId, reason: String) -> Result<()> {
        let mut requests = self.requests.write().await;
        let request = requests.get_mut(&approval_id)
            .ok_or_else(|| Error::ApprovalExpired(format!("Approval not found: {}", approval_id)))?;

        request.state = ApprovalState::Rejected;
        request.decided_at = Some(chrono::Utc::now());
        request.decision_reason = Some(reason);
        Ok(())
    }
}

impl ApprovalBrokerImpl {
    pub async fn get_request(&self, id: ApprovalId) -> Option<ApprovalRequest> {
        self.requests.read().await.get(&id).cloned()
    }

    pub async fn list_pending(&self) -> Vec<ApprovalRequest> {
        self.requests.read().await.values()
            .filter(|r| r.state == ApprovalState::Pending)
            .cloned()
            .collect()
    }

    pub async fn expire_old_requests(&self) {
        let now = chrono::Utc::now();
        let mut requests = self.requests.write().await;
        for request in requests.values_mut() {
            if request.state == ApprovalState::Pending {
                if let Some(expires) = request.expires_at {
                    if now > expires {
                        request.state = ApprovalState::Expired;
                    }
                }
            }
        }
    }
}