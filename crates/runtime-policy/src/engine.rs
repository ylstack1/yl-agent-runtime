//! Policy engine trait implementation

use crate::evaluator::*;
use crate::store::*;
use runtime_core::{CapabilityGrant, ExecutionProfileConfig};
use runtime_core::error::Result;
use runtime_core::traits::PolicyEngine;
use runtime_core::types::*;
use std::sync::Arc;
use tokio::sync::RwLock;

/// In-memory policy engine implementation
#[derive(Clone)]
pub struct PolicyEngineImpl {
    store: Arc<RwLock<PolicyStore>>,
    evaluator: Arc<RwLock<PolicyEvaluator>>,
}

impl PolicyEngineImpl {
    pub fn new() -> Self {
        Self {
            store: Arc::new(RwLock::new(PolicyStore::new())),
            evaluator: Arc::new(RwLock::new(PolicyEvaluator::new())),
        }
    }

    pub fn with_store(store: PolicyStore) -> Self {
        Self {
            store: Arc::new(RwLock::new(store)),
            evaluator: Arc::new(RwLock::new(PolicyEvaluator::new())),
        }
    }
}

impl Default for PolicyEngineImpl {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl PolicyEngine for PolicyEngineImpl {
    async fn evaluate(
        &self,
        agent_id: AgentId,
        project_id: ProjectId,
        capability: Capability,
        resource: Option<&str>,
    ) -> Result<PolicyDecision> {
        let store = self.store.read().await;
        let evaluator = self.evaluator.read().await;

        // Get the profile for this project
        let profile = store.get_profile(project_id).await?;

        // Get capabilities for this agent+project
        let grants = store.get_capabilities(agent_id, project_id).await?;

        // Evaluate
        evaluator.evaluate(agent_id, project_id, capability, resource, &profile, &grants)
    }

    async fn get_profile(&self, project_id: ProjectId) -> Result<ExecutionProfile> {
        let store = self.store.read().await;
        store.get_profile(project_id).await
    }

    async fn get_capabilities(
        &self,
        agent_id: AgentId,
        project_id: ProjectId,
    ) -> Result<Vec<CapabilityGrant>> {
        let store = self.store.read().await;
        store.get_capabilities(agent_id, project_id).await
    }
}

/// Policy store - holds grants and profiles
#[derive(Clone, Default)]
pub struct PolicyStore {
    profiles: std::collections::HashMap<ProjectId, ExecutionProfile>,
    grants: std::collections::HashMap<(AgentId, ProjectId), Vec<CapabilityGrant>>,
}

impl PolicyStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn set_profile(&mut self, project_id: ProjectId, profile: ExecutionProfile) {
        self.profiles.insert(project_id, profile);
    }

    pub async fn get_profile(&self, project_id: ProjectId) -> Result<ExecutionProfile> {
        self.profiles
            .get(&project_id)
            .copied()
            .ok_or_else(|| runtime_core::error::Error::PolicyViolation(format!("No profile for project {}", project_id)))
    }

    pub async fn set_capabilities(
        &mut self,
        agent_id: AgentId,
        project_id: ProjectId,
        capabilities: Vec<CapabilityGrant>,
    ) {
        self.grants.insert((agent_id, project_id), capabilities);
    }

    pub async fn get_capabilities(
        &self,
        agent_id: AgentId,
        project_id: ProjectId,
    ) -> Result<Vec<CapabilityGrant>> {
        Ok(self
            .grants
            .get(&(agent_id, project_id))
            .cloned()
            .unwrap_or_default())
    }

    pub async fn add_grant(
        &mut self,
        agent_id: AgentId,
        project_id: ProjectId,
        grant: CapabilityGrant,
    ) {
        let key = (agent_id, project_id);
        let grants = self.grants.entry(key).or_default();
        // Replace existing grant for same capability+resource or add new
        if let Some(existing) = grants
            .iter_mut()
            .find(|g| g.capability == grant.capability && g.resource == grant.resource)
        {
            *existing = grant;
        } else {
            grants.push(grant);
        }
    }

    pub async fn revoke_grant(
        &mut self,
        agent_id: AgentId,
        project_id: ProjectId,
        capability: Capability,
        resource: Option<String>,
    ) {
        let key = (agent_id, project_id);
        if let Some(grants) = self.grants.get_mut(&key) {
            grants.retain(|g| !(g.capability == capability && g.resource == resource));
        }
    }
}

/// Policy evaluator - makes decisions based on grants and profile
pub struct PolicyEvaluator {
    default_profiles: std::collections::HashMap<ExecutionProfile, ExecutionProfileConfig>,
}

impl PolicyEvaluator {
    pub fn new() -> Self {
        Self {
            default_profiles: ExecutionProfileConfig::default_profiles(),
        }
    }

    pub fn evaluate(
        &self,
        _agent_id: AgentId,
        _project_id: ProjectId,
        capability: Capability,
        resource: Option<&str>,
        profile: &ExecutionProfile,
        grants: &[CapabilityGrant],
    ) -> Result<PolicyDecision> {
        // Check for explicit grants first
        for grant in grants {
            if grant.capability == capability {
                // Check resource match
                if let (Some(ref grant_resource), Some(ref requested_resource)) =
                    (&grant.resource, &resource)
                {
                    if grant_resource != requested_resource {
                        continue;
                    }
                }

                // Check expiry
                if let Some(expires) = grant.expires_at {
                    if chrono::Utc::now() > expires {
                        return Ok(PolicyDecision::Deny);
                    }
                }

                return Ok(grant.decision);
            }
        }

        // Fall back to profile default
        let config = self
            .default_profiles
            .get(profile)
            .cloned()
            .unwrap_or_else(|| ExecutionProfileConfig::get(*profile));

        Ok(runtime_core::capability::default_decision(capability, *profile))
    }
}