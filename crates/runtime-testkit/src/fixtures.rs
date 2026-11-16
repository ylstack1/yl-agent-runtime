//! Test fixtures for YL Agent Runtime tests

use runtime_core::types::*;
use std::path::PathBuf;
use tempfile::TempDir;

/// Creates a temporary workspace directory for testing
pub fn create_temp_workspace() -> (TempDir, PathBuf) {
    let temp = TempDir::new().unwrap();
    let root = temp.path().to_path_buf();
    (temp, root)
}

/// Creates a test project ID
pub fn test_project_id() -> ProjectId {
    ProjectId::new()
}

/// Creates a test agent ID
pub fn test_agent_id() -> AgentId {
    AgentId::new()
}

/// Creates a test device ID
pub fn test_device_id() -> DeviceId {
    DeviceId::new()
}

/// Creates a test session ID
pub fn test_session_id() -> SessionId {
    SessionId::new()
}

/// Creates a test capability grant
pub fn test_grant(capability: Capability) -> runtime_core::CapabilityGrant {
    runtime_core::CapabilityGrant {
        capability,
        decision: PolicyDecision::Allow,
        resource: None,
        expires_at: None,
        approval_id: None,
    }
}

/// Creates a test execution profile config
pub fn test_profile_config(profile: ExecutionProfile) -> runtime_core::ExecutionProfileConfig {
    runtime_core::ExecutionProfileConfig::get(profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixtures() {
        let pid = test_project_id();
        let aid = test_agent_id();
        let did = test_device_id();
        let sid = test_session_id();

        assert_ne!(pid, ProjectId::nil());
        assert_ne!(aid, AgentId::new()); // Different UUIDs
        assert_ne!(did, DeviceId::new());
        assert_ne!(sid, SessionId::new());

        let grant = test_grant(Capability::WorkspaceRead);
        assert_eq!(grant.capability, Capability::WorkspaceRead);
        assert_eq!(grant.decision, PolicyDecision::Allow);
    }
}