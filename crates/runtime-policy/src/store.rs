//! Policy store - persistence layer for grants and profiles

use runtime_core::types::*;
use std::collections::HashMap;

/// Policy store trait (abstraction for different backends)
#[async_trait::async_trait]
pub trait PolicyStore: Send + Sync {
    async fn set_profile(&mut self, project_id: ProjectId, profile: ExecutionProfile);
    async fn get_profile(&self, project_id: ProjectId) -> runtime_core::error::Result<ExecutionProfile>;
    async fn set_capabilities(
        &mut self,
        agent_id: AgentId,
        project_id: ProjectId,
        capabilities: Vec<runtime_core::types::CapabilityGrant>,
    );
    async fn get_capabilities(
        &self,
        agent_id: AgentId,
        project_id: ProjectId,
    ) -> runtime_core::error::Result<Vec<runtime_core::types::CapabilityGrant>>;
    async fn add_grant(
        &mut self,
        agent_id: AgentId,
        project_id: ProjectId,
        grant: runtime_core::types::CapabilityGrant,
    );
    async fn revoke_grant(
        &mut self,
        agent_id: AgentId,
        project_id: ProjectId,
        capability: Capability,
        resource: Option<String>,
    );
}

/// In-memory policy store implementation
#[derive(Clone, Default)]
pub struct MemoryPolicyStore {
    profiles: HashMap<ProjectId, ExecutionProfile>,
    grants: HashMap<(AgentId, ProjectId), Vec<runtime_core::types::CapabilityGrant>>,
}

impl MemoryPolicyStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl PolicyStore for MemoryPolicyStore {
    async fn set_profile(&mut self, project_id: ProjectId, profile: ExecutionProfile) {
        self.profiles.insert(project_id, profile);
    }

    async fn get_profile(&self, project_id: ProjectId) -> runtime_core::error::Result<ExecutionProfile> {
        self.profiles
            .get(&project_id)
            .copied()
            .ok_or_else(|| {
                runtime_core::error::Error::PolicyViolation(format!(
                    "No profile for project {}",
                    project_id
                ))
            })
    }

    async fn set_capabilities(
        &mut self,
        agent_id: AgentId,
        project_id: ProjectId,
        capabilities: Vec<runtime_core::types::CapabilityGrant>,
    ) {
        self.grants.insert((agent_id, project_id), capabilities);
    }

    async fn get_capabilities(
        &self,
        agent_id: AgentId,
        project_id: ProjectId,
    ) -> runtime_core::error::Result<Vec<runtime_core::types::CapabilityGrant>> {
        Ok(self
            .grants
            .get(&(agent_id, project_id))
            .cloned()
            .unwrap_or_default())
    }

    async fn add_grant(
        &mut self,
        agent_id: AgentId,
        project_id: ProjectId,
        grant: runtime_core::types::CapabilityGrant,
    ) {
        let key = (agent_id, project_id);
        let grants = self.grants.entry(key).or_default();
        if let Some(existing) = grants
            .iter_mut()
            .find(|g| g.capability == grant.capability && g.resource == grant.resource)
        {
            *existing = grant;
        } else {
            grants.push(grant);
        }
    }

    async fn revoke_grant(
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