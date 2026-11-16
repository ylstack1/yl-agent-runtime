//! Capability model for YL Agent Runtime

use crate::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// A permission grant with full scoping dimensions per PRD section 7.1
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionGrant {
    pub agent_id: AgentId,
    pub device_id: DeviceId,
    pub project_id: ProjectId,
    pub session_id: Option<SessionId>,
    pub capability: Capability,
    pub resource: Option<String>,
    pub decision: PolicyDecision,
    pub profile: ExecutionProfile,
    pub expires_at: Option<DateTime<Utc>>,
    pub approval_state: ApprovalState,
}

/// Approval state for a grant
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalState {
    NotRequired,
    Pending,
    Granted,
    Rejected,
    Expired,
    Revoked,
}

/// Execution profile with default permissions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionProfileConfig {
    pub profile: ExecutionProfile,
    pub file_access: FileAccess,
    pub process_execution: ProcessExecution,
    pub network: NetworkAccess,
    pub description: String,
}

/// File access scope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAccess {
    pub workspace_root: Option<String>,
    pub read_only: bool,
    pub deny_paths: Vec<String>,
    pub max_file_size: Option<u64>,
}

/// Process execution scope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessExecution {
    pub enabled: bool,
    pub allowed_executables: Vec<String>,
    pub max_runtime_seconds: Option<u64>,
    pub max_processes: Option<u32>,
    pub memory_limit_mb: Option<u64>,
}

/// Network access scope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAccess {
    pub enabled: bool,
    pub proxy_only: bool,
    pub allowed_hosts: Vec<String>,
}

/// Default profile configurations per PRD section 7.2
impl ExecutionProfileConfig {
    pub fn default_profiles() -> HashMap<ExecutionProfile, ExecutionProfileConfig> {
        let mut profiles = HashMap::new();

        profiles.insert(
            ExecutionProfile::Inspect,
            ExecutionProfileConfig {
                profile: ExecutionProfile::Inspect,
                file_access: FileAccess {
                    workspace_root: None,
                    read_only: true,
                    deny_paths: vec![
                        "%USERPROFILE%/.ssh".to_string(),
                        "%USERPROFILE%/.aws".to_string(),
                        "%APPDATA%/Microsoft/Credentials".to_string(),
                    ],
                    max_file_size: Some(10_000_000), // 10 MB
                },
                process_execution: ProcessExecution {
                    enabled: false,
                    allowed_executables: vec![],
                    max_runtime_seconds: None,
                    max_processes: None,
                    memory_limit_mb: None,
                },
                network: NetworkAccess {
                    enabled: false,
                    proxy_only: false,
                    allowed_hosts: vec![],
                },
                description: "Repository review - read-only workspace access".to_string(),
            },
        );

        profiles.insert(
            ExecutionProfile::Edit,
            ExecutionProfileConfig {
                profile: ExecutionProfile::Edit,
                file_access: FileAccess {
                    workspace_root: None,
                    read_only: false,
                    deny_paths: vec![
                        "%USERPROFILE%/.ssh".to_string(),
                        "%USERPROFILE%/.aws".to_string(),
                        "%APPDATA%/Microsoft/Credentials".to_string(),
                    ],
                    max_file_size: Some(10_000_000),
                },
                process_execution: ProcessExecution {
                    enabled: false,
                    allowed_executables: vec![],
                    max_runtime_seconds: None,
                    max_processes: None,
                    memory_limit_mb: None,
                },
                network: NetworkAccess {
                    enabled: false,
                    proxy_only: false,
                    allowed_hosts: vec![],
                },
                description: "File editing - workspace read/write, no process execution".to_string(),
            },
        );

        profiles.insert(
            ExecutionProfile::Development,
            ExecutionProfileConfig {
                profile: ExecutionProfile::Development,
                file_access: FileAccess {
                    workspace_root: None,
                    read_only: false,
                    deny_paths: vec![
                        "%USERPROFILE%/.ssh".to_string(),
                        "%USERPROFILE%/.aws".to_string(),
                        "%APPDATA%/Microsoft/Credentials".to_string(),
                    ],
                    max_file_size: Some(100_000_000), // 100 MB
                },
                process_execution: ProcessExecution {
                    enabled: true,
                    allowed_executables: vec![
                        "node".to_string(),
                        "pnpm".to_string(),
                        "bun".to_string(),
                        "python".to_string(),
                        "git".to_string(),
                        "cargo".to_string(),
                    ],
                    max_runtime_seconds: Some(1800), // 30 minutes
                    max_processes: Some(128),
                    memory_limit_mb: Some(4096), // 4 GB
                },
                network: NetworkAccess {
                    enabled: true,
                    proxy_only: true,
                    allowed_hosts: vec![],
                },
                description: "Normal development - build/test with allowlisted tools".to_string(),
            },
        );

        profiles.insert(
            ExecutionProfile::SandboxedDevelopment,
            ExecutionProfileConfig {
                profile: ExecutionProfile::SandboxedDevelopment,
                file_access: FileAccess {
                    workspace_root: None,
                    read_only: false,
                    deny_paths: vec![
                        "%USERPROFILE%/.ssh".to_string(),
                        "%USERPROFILE%/.aws".to_string(),
                        "%APPDATA%/Microsoft/Credentials".to_string(),
                    ],
                    max_file_size: Some(100_000_000),
                },
                process_execution: ProcessExecution {
                    enabled: true,
                    allowed_executables: vec![
                        "node".to_string(),
                        "pnpm".to_string(),
                        "bun".to_string(),
                        "python".to_string(),
                        "git".to_string(),
                        "cargo".to_string(),
                    ],
                    max_runtime_seconds: Some(1800),
                    max_processes: Some(64),
                    memory_limit_mb: Some(2048),
                },
                network: NetworkAccess {
                    enabled: false,
                    proxy_only: true,
                    allowed_hosts: vec![],
                },
                description: "Untrusted project work - sandboxed child process, network denied".to_string(),
            },
        );

        profiles.insert(
            ExecutionProfile::ElevatedOneShot,
            ExecutionProfileConfig {
                profile: ExecutionProfile::ElevatedOneShot,
                file_access: FileAccess {
                    workspace_root: None,
                    read_only: false,
                    deny_paths: vec![],
                    max_file_size: None,
                },
                process_execution: ProcessExecution {
                    enabled: true,
                    allowed_executables: vec![],
                    max_runtime_seconds: Some(3600),
                    max_processes: Some(16),
                    memory_limit_mb: Some(8192),
                },
                network: NetworkAccess {
                    enabled: false,
                    proxy_only: false,
                    allowed_hosts: vec![],
                },
                description: "Exceptional system task - specific elevated operation, one-shot approval".to_string(),
            },
        );

        profiles
    }

    pub fn get(profile: ExecutionProfile) -> ExecutionProfileConfig {
        Self::default_profiles()
            .get(&profile)
            .cloned()
            .unwrap_or_else(|| ExecutionProfileConfig {
                profile,
                file_access: FileAccess {
                    workspace_root: None,
                    read_only: true,
                    deny_paths: vec![],
                    max_file_size: Some(1_000_000),
                },
                process_execution: ProcessExecution {
                    enabled: false,
                    allowed_executables: vec![],
                    max_runtime_seconds: None,
                    max_processes: None,
                    memory_limit_mb: None,
                },
                network: NetworkAccess {
                    enabled: false,
                    proxy_only: false,
                    allowed_hosts: vec![],
                },
                description: format!("{:?} profile", profile),
            })
    }
}

/// Capability requirement for an operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityRequirement {
    pub capability: Capability,
    pub resource: Option<String>,
    pub decision: PolicyDecision,
    pub requires_approval: bool,
    pub justification: Option<String>,
}

/// Check if a capability requires approval based on the profile
pub fn requires_approval(capability: Capability, profile: ExecutionProfile) -> bool {
    matches!(
        (capability, profile),
        // Approval required for sensitive operations in most profiles
        (Capability::ProcessExec, ExecutionProfile::Development)
        | (Capability::TerminalOpen, ExecutionProfile::Development)
        | (Capability::GitCommit, ExecutionProfile::Development)
        | (Capability::NetworkDirect, _)
        | (Capability::SecretsRead, _)
        | (Capability::SecretsWrite, _)
        | (Capability::SystemElevate, _)
        // Sandboxed development is more restrictive
        | (Capability::ProcessExec, ExecutionProfile::SandboxedDevelopment)
        | (Capability::TerminalOpen, ExecutionProfile::SandboxedDevelopment)
        | (Capability::GitCommit, ExecutionProfile::SandboxedDevelopment)
        // Inspect and Edit never allow process/terminal
        | (Capability::ProcessExec, ExecutionProfile::Inspect)
        | (Capability::ProcessExec, ExecutionProfile::Edit)
        | (Capability::TerminalOpen, ExecutionProfile::Inspect)
        | (Capability::TerminalOpen, ExecutionProfile::Edit)
    )
}

/// Default decision for a capability in a given profile
pub fn default_decision(capability: Capability, profile: ExecutionProfile) -> PolicyDecision {
    if requires_approval(capability, profile) {
        PolicyDecision::Ask
    } else {
        match (capability, profile) {
            // Read operations are generally allowed
            (Capability::WorkspaceRead, _) => PolicyDecision::Allow,
            (Capability::WorkspaceList, _) => PolicyDecision::Allow,
            (Capability::WorkspaceSearch, _) => PolicyDecision::Allow,
            (Capability::GitRead, ExecutionProfile::Inspect | ExecutionProfile::Edit | ExecutionProfile::Development | ExecutionProfile::SandboxedDevelopment) => PolicyDecision::Allow,
            (Capability::GitStatus, ExecutionProfile::Inspect | ExecutionProfile::Edit | ExecutionProfile::Development | ExecutionProfile::SandboxedDevelopment) => PolicyDecision::Allow,
            (Capability::GitDiff, ExecutionProfile::Inspect | ExecutionProfile::Edit | ExecutionProfile::Development | ExecutionProfile::SandboxedDevelopment) => PolicyDecision::Allow,
            // Write operations in development profiles
            (Capability::WorkspaceWrite, ExecutionProfile::Edit | ExecutionProfile::Development | ExecutionProfile::SandboxedDevelopment | ExecutionProfile::ElevatedOneShot) => PolicyDecision::Allow,
            (Capability::WorkspaceWrite, _) => PolicyDecision::Deny,
            // Everything else defaults to ask/deny
            _ => PolicyDecision::Ask,
        }
    }
}