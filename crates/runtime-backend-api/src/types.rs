//! Backend API types

use runtime_core::CapabilityGrant;
use runtime_core::types::*;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Execution backend request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionRequest {
    pub id: ProcessId,
    pub session_id: SessionId,
    pub project_id: ProjectId,
    pub agent_id: AgentId,
    pub executable: PathBuf,
    pub arguments: Vec<String>,
    pub environment: HashMap<String, String>,
    pub working_directory: PathBuf,
    pub profile: ExecutionProfile,
    pub capabilities: Vec<CapabilityGrant>,
    pub max_runtime_seconds: Option<u64>,
    pub max_processes: Option<u32>,
    pub memory_limit_mb: Option<u64>,
    pub stdin_data: Option<Vec<u8>>,
}

/// Prepared execution after backend validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedExecution {
    pub id: ProcessId,
    pub executable: PathBuf,
    pub arguments: Vec<String>,
    pub environment: HashMap<String, String>,
    pub working_directory: PathBuf,
    pub enforcement_report: EnforcementReport,
}

/// Process handle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessHandle {
    pub id: ProcessId,
    pub os_pid: u32,
    pub status: ProcessStatus,
}

/// Process status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessStatus {
    pub id: ProcessId,
    pub os_pid: u32,
    pub running: bool,
    pub exit_status: Option<ExitStatus>,
    pub resource_usage: ResourceUsage,
    pub started_at: DateTime<Utc>,
}

/// Termination mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminationMode {
    Graceful,
    Force,
    ProcessTree,
}

use std::collections::HashMap;