//! Core traits for YL Agent Runtime

use crate::audit::{AuditEvent, AuditFilter};
use crate::error::Result;
use crate::types::*;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Capability granted to an agent for a specific resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityGrant {
    pub capability: Capability,
    pub decision: PolicyDecision,
    pub resource: Option<String>, // path or resource identifier
    pub expires_at: Option<DateTime<Utc>>,
    pub approval_id: Option<ApprovalId>,
}

/// Execution request for a backend
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

/// Prepared execution (after backend validation/setup)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedExecution {
    pub id: ProcessId,
    pub executable: PathBuf,
    pub arguments: Vec<String>,
    pub environment: HashMap<String, String>,
    pub working_directory: PathBuf,
    pub enforcement_report: EnforcementReport,
}

/// Handle to a spawned process
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
    Graceful, // SIGTERM / Ctrl-C, wait for exit
    Force,    // SIGKILL / TerminateProcess, immediate
    ProcessTree, // Kill entire process tree
}

/// ExecutionBackend trait - stable trait boundary per PRD section 9.1
#[async_trait]
pub trait ExecutionBackend: Send + Sync {
    fn name(&self) -> &'static str;
    fn capabilities(&self) -> BackendCapabilities;
    async fn prepare(&self, request: ExecutionRequest) -> Result<PreparedExecution>;
    async fn spawn(&self, prepared: PreparedExecution) -> Result<ProcessHandle>;
    async fn inspect(&self, id: ProcessId) -> Result<ProcessStatus>;
    async fn terminate(&self, id: ProcessId, mode: TerminationMode) -> Result<()>;
    async fn list_processes(&self) -> Result<Vec<ProcessStatus>>;
}

/// WorkspaceService trait
#[async_trait]
pub trait WorkspaceService: Send + Sync {
    async fn register(&self, root: PathBuf, profile: ExecutionProfile) -> Result<ProjectId>;
    async fn unregister(&self, project_id: ProjectId) -> Result<()>;
    async fn list(&self, project_id: ProjectId, path: Option<PathBuf>) -> Result<Vec<FileEntry>>;
    async fn stat(&self, project_id: ProjectId, path: PathBuf) -> Result<FileEntry>;
    async fn read_file(&self, project_id: ProjectId, path: PathBuf) -> Result<Vec<u8>>;
    async fn read_range(&self, project_id: ProjectId, path: PathBuf, start: u64, end: u64) -> Result<Vec<u8>>;
    async fn write_file(&self, project_id: ProjectId, path: PathBuf, content: Vec<u8>) -> Result<()>;
    async fn replace_text(&self, project_id: ProjectId, path: PathBuf, old_text: String, new_text: String) -> Result<()>;
    async fn create_directory(&self, project_id: ProjectId, path: PathBuf) -> Result<()>;
    async fn move_entry(&self, project_id: ProjectId, source: PathBuf, destination: PathBuf) -> Result<()>;
    async fn copy_entry(&self, project_id: ProjectId, source: PathBuf, destination: PathBuf) -> Result<()>;
    async fn delete(&self, project_id: ProjectId, path: PathBuf, recursive: bool) -> Result<()>;
    async fn search(&self, project_id: ProjectId, query: String) -> Result<Vec<SearchResult>>;
    async fn find_files(&self, project_id: ProjectId, pattern: String) -> Result<Vec<PathBuf>>;
    async fn get_tree(&self, project_id: ProjectId, path: Option<PathBuf>, max_depth: Option<usize>) -> Result<Vec<FileEntry>>;
}

/// ToolchainDiscovery trait
#[async_trait]
pub trait ToolchainDiscovery: Send + Sync {
    async fn discover_all(&self) -> Result<Vec<Toolchain>>;
    async fn find_by_name(&self, name: &str) -> Result<Option<Toolchain>>;
}

/// PolicyEngine trait
#[async_trait]
pub trait PolicyEngine: Send + Sync {
    async fn evaluate(&self, agent_id: AgentId, project_id: ProjectId, capability: Capability, resource: Option<&str>) -> Result<PolicyDecision>;
    async fn get_profile(&self, project_id: ProjectId) -> Result<ExecutionProfile>;
    async fn get_capabilities(&self, agent_id: AgentId, project_id: ProjectId) -> Result<Vec<CapabilityGrant>>;
    /// Set the execution profile for a project (called when a workspace root is registered).
    async fn set_profile(&self, project_id: ProjectId, profile: ExecutionProfile) -> Result<()>;
}

/// ApprovalBroker trait
#[async_trait]
pub trait ApprovalBroker: Send + Sync {
    async fn request(&self, agent_id: AgentId, project_id: ProjectId, capability: Capability, resource: Option<String>, justification: String) -> Result<ApprovalId>;
    async fn check(&self, approval_id: ApprovalId) -> Result<PolicyDecision>;
    async fn approve(&self, approval_id: ApprovalId) -> Result<()>;
    async fn reject(&self, approval_id: ApprovalId, reason: String) -> Result<()>;
}

/// AuditService trait
#[async_trait]
pub trait AuditService: Send + Sync {
    async fn record(&self, event: AuditEvent) -> Result<()>;
    async fn query(&self, filter: AuditFilter) -> Result<Vec<AuditEvent>>;
    async fn export_jsonl(&self, path: PathBuf) -> Result<()>;
}