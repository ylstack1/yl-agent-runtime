//! Audit event types for YL Agent Runtime

use crate::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// An audit event record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_type: AuditEventType,
    pub user_id: Option<String>,
    pub agent_id: Option<AgentId>,
    pub device_id: Option<DeviceId>,
    pub project_id: Option<ProjectId>,
    pub session_id: Option<SessionId>,
    pub capability: Option<Capability>,
    pub resource: Option<String>,
    pub policy_decision: Option<PolicyDecision>,
    pub approval_id: Option<ApprovalId>,
    pub backend: Option<String>,
    pub enforcement_report: Option<EnforcementReport>,
    pub process_id: Option<ProcessId>,
    pub exit_status: Option<ExitStatus>,
    pub duration_ms: Option<u64>,
    pub resource_usage: Option<ResourceUsage>,
    pub output_truncated: bool,
    pub error: Option<String>,
    pub termination_reason: Option<String>,
    pub metadata: HashMap<String, String>,
}

impl AuditEvent {
    pub fn new(event_type: AuditEventType) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type,
            user_id: None,
            agent_id: None,
            device_id: None,
            project_id: None,
            session_id: None,
            capability: None,
            resource: None,
            policy_decision: None,
            approval_id: None,
            backend: None,
            enforcement_report: None,
            process_id: None,
            exit_status: None,
            duration_ms: None,
            resource_usage: None,
            output_truncated: false,
            error: None,
            termination_reason: None,
            metadata: HashMap::new(),
        }
    }

    pub fn with_agent(mut self, agent_id: AgentId) -> Self {
        self.agent_id = Some(agent_id);
        self
    }

    pub fn with_device(mut self, device_id: DeviceId) -> Self {
        self.device_id = Some(device_id);
        self
    }

    pub fn with_project(mut self, project_id: ProjectId) -> Self {
        self.project_id = Some(project_id);
        self
    }

    pub fn with_session(mut self, session_id: SessionId) -> Self {
        self.session_id = Some(session_id);
        self
    }

    pub fn with_capability(mut self, capability: Capability) -> Self {
        self.capability = Some(capability);
        self
    }

    pub fn with_resource(mut self, resource: String) -> Self {
        self.resource = Some(resource);
        self
    }

    pub fn with_policy_decision(mut self, decision: PolicyDecision) -> Self {
        self.policy_decision = Some(decision);
        self
    }

    pub fn with_approval(mut self, approval_id: ApprovalId) -> Self {
        self.approval_id = Some(approval_id);
        self
    }

    pub fn with_backend(mut self, backend: String) -> Self {
        self.backend = Some(backend);
        self
    }

    pub fn with_enforcement_report(mut self, report: EnforcementReport) -> Self {
        self.enforcement_report = Some(report);
        self
    }

    pub fn with_process(mut self, process_id: ProcessId) -> Self {
        self.process_id = Some(process_id);
        self
    }

    pub fn with_exit_status(mut self, status: ExitStatus) -> Self {
        self.exit_status = Some(status);
        self
    }

    pub fn with_duration(mut self, ms: u64) -> Self {
        self.duration_ms = Some(ms);
        self
    }

    pub fn with_resource_usage(mut self, usage: ResourceUsage) -> Self {
        self.resource_usage = Some(usage);
        self
    }

    pub fn with_error(mut self, error: String) -> Self {
        self.error = Some(error);
        self
    }

    pub fn redact_secrets(&mut self) {
        // Redact sensitive values from metadata
        let sensitive_keys = [
            "password", "secret", "token", "api_key", "access_token",
            "refresh_token", "credential", "private_key", "connection_string",
        ];
        for key in sensitive_keys.iter() {
            if let Some(val) = self.metadata.get_mut(*key) {
                *val = "***REDACTED***".to_string();
            }
        }
        // Redact resource if it looks like a sensitive path
        if let Some(ref resource) = self.resource {
            let lower = resource.to_lowercase();
            if lower.contains(".ssh") || lower.contains(".aws") || lower.contains("credential") {
                self.resource = Some("***REDACTED PATH***".to_string());
            }
        }
    }
}

/// Types of audit events
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    /// Workspace operations
    WorkspaceRegister,
    WorkspaceUnregister,
    WorkspaceRead,
    WorkspaceWrite,
    WorkspaceDelete,
    WorkspaceMove,
    WorkspaceCopy,
    WorkspaceSearch,
    WorkspaceList,

    /// Process operations
    ProcessExec,
    ProcessStart,
    ProcessWait,
    ProcessTerminate,
    ProcessList,

    /// Terminal operations
    TerminalOpen,
    TerminalWrite,
    TerminalRead,
    TerminalResize,
    TerminalClose,

    /// Git operations
    GitStatus,
    GitDiff,
    GitCommit,

    /// Policy and approval
    PolicyEvaluation,
    ApprovalRequested,
    ApprovalGranted,
    ApprovalRejected,
    ApprovalExpired,

    /// Identity and device
    AgentRegistered,
    DevicePaired,
    DeviceRevoked,
    SessionCreated,
    SessionExpired,

    /// Sandbox and backend
    SandboxViolation,
    BackendCapabilityReport,
    IsolationFailure,

    /// System
    RuntimeStart,
    RuntimeStop,
    ConfigurationLoaded,
    ConfigurationInvalid,

    /// Error
    Error,
}

/// Filter for querying audit events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditFilter {
    pub event_type: Option<AuditEventType>,
    pub agent_id: Option<AgentId>,
    pub device_id: Option<DeviceId>,
    pub project_id: Option<ProjectId>,
    pub session_id: Option<SessionId>,
    pub capability: Option<Capability>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// Audit export format
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditExportFormat {
    Jsonl,
    Json,
    Csv,
}