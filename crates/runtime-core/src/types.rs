//! Core type definitions for YL Agent Runtime

use serde::{Deserialize, Serialize};
use schemars::JsonSchema;
use uuid::Uuid;
pub use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::path::PathBuf;

/// Unique identifier for a project/workspace
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProjectId(pub Uuid);

impl ProjectId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn nil() -> Self {
        Self(Uuid::nil())
    }
}

impl Default for ProjectId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ProjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for ProjectId {
    type Err = uuid::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}

/// Unique identifier for an agent
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(pub Uuid);

impl AgentId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for AgentId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for AgentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for a device
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId(pub Uuid);

impl DeviceId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl std::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for a session
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub Uuid);

impl SessionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for a process
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessId(pub Uuid);

impl ProcessId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl std::fmt::Display for ProcessId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for a terminal session
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TerminalId(pub Uuid);

impl TerminalId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl std::fmt::Display for TerminalId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for an approval request
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ApprovalId(pub Uuid);

impl ApprovalId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl std::fmt::Display for ApprovalId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Platform identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Windows,
    Linux,
    MacOS,
    Unknown,
}

impl Platform {
    pub fn current() -> Self {
        #[cfg(target_os = "windows")]
        return Platform::Windows;
        #[cfg(target_os = "linux")]
        return Platform::Linux;
        #[cfg(target_os = "macos")]
        return Platform::MacOS;
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        return Platform::Unknown;
    }
}

/// Architecture identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Architecture {
    X86_64,
    Aarch64,
    Unknown,
}

impl Architecture {
    pub fn current() -> Self {
        #[cfg(target_arch = "x86_64")]
        return Architecture::X86_64;
        #[cfg(target_arch = "aarch64")]
        return Architecture::Aarch64;
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        return Architecture::Unknown;
    }
}

/// Process exit status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitStatus {
    pub code: Option<i32>,
    pub signal: Option<i32>,
    pub success: bool,
}

impl ExitStatus {
    pub fn success() -> Self {
        Self {
            code: Some(0),
            signal: None,
            success: true,
        }
    }

    pub fn from_code(code: i32) -> Self {
        Self {
            code: Some(code),
            signal: None,
            success: code == 0,
        }
    }

    pub fn from_signal(signal: i32) -> Self {
        Self {
            code: None,
            signal: Some(signal),
            success: false,
        }
    }
}

/// Process resource usage
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub cpu_time_ms: u64,
    pub memory_bytes: u64,
    pub peak_memory_bytes: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub process_count: u32,
}

/// File system entry type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileType {
    File,
    Directory,
    Symlink,
    Junction,
    Other,
}

/// File system entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: PathBuf,
    pub name: String,
    pub file_type: FileType,
    pub size: u64,
    pub modified: DateTime<Utc>,
    pub created: DateTime<Utc>,
    pub permissions: FilePermissions,
    pub is_binary: bool,
}

/// File permissions
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FilePermissions {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

/// Search result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub path: PathBuf,
    pub line_number: usize,
    pub column: usize,
    pub match_text: String,
    pub context_before: Vec<String>,
    pub context_after: Vec<String>,
}

/// Toolchain information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Toolchain {
    pub name: String,
    pub version: String,
    pub path: PathBuf,
    pub architecture: Architecture,
    pub detection_source: ToolchainSource,
}

/// Toolchain detection source
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ToolchainSource {
    Path,
    Registry,
    PackageManager,
    KnownLocation,
    EnvironmentVariable,
}

/// Capability names (standardized)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    WorkspaceRead,
    WorkspaceWrite,
    WorkspaceSearch,
    WorkspaceList,
    WorkspaceRegister,
    ProcessExec,
    ProcessStart,
    ProcessWait,
    ProcessTerminate,
    ProcessList,
    ProcessResourceUsage,
    TerminalOpen,
    TerminalWrite,
    TerminalRead,
    TerminalResize,
    TerminalClose,
    GitRead,
    GitWrite,
    GitStatus,
    GitDiff,
    GitCommit,
    NetworkProxy,
    NetworkDirect,
    SecretsRead,
    SecretsWrite,
    ApprovalRequest,
    SystemElevate,
}

impl Capability {
    pub fn as_str(&self) -> &'static str {
        match self {
            Capability::WorkspaceRead => "workspace.read",
            Capability::WorkspaceWrite => "workspace.write",
            Capability::WorkspaceSearch => "workspace.search",
            Capability::WorkspaceList => "workspace.list",
            Capability::WorkspaceRegister => "workspace.register",
            Capability::ProcessExec => "process.exec",
            Capability::ProcessStart => "process.start",
            Capability::ProcessWait => "process.wait",
            Capability::ProcessTerminate => "process.terminate",
            Capability::ProcessList => "process.list",
            Capability::ProcessResourceUsage => "process.resource_usage",
            Capability::TerminalOpen => "terminal.open",
            Capability::TerminalWrite => "terminal.write",
            Capability::TerminalRead => "terminal.read",
            Capability::TerminalResize => "terminal.resize",
            Capability::TerminalClose => "terminal.close",
            Capability::GitRead => "git.read",
            Capability::GitWrite => "git.write",
            Capability::GitStatus => "git.status",
            Capability::GitDiff => "git.diff",
            Capability::GitCommit => "git.commit",
            Capability::NetworkProxy => "network.proxy",
            Capability::NetworkDirect => "network.direct",
            Capability::SecretsRead => "secrets.read",
            Capability::SecretsWrite => "secrets.write",
            Capability::ApprovalRequest => "approval.request",
            Capability::SystemElevate => "system.elevate",
        }
    }
}

impl Capability {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "workspace.read" => Ok(Capability::WorkspaceRead),
            "workspace.write" => Ok(Capability::WorkspaceWrite),
            "workspace.search" => Ok(Capability::WorkspaceSearch),
            "workspace.list" => Ok(Capability::WorkspaceList),
            "workspace.register" => Ok(Capability::WorkspaceRegister),
            "process.exec" => Ok(Capability::ProcessExec),
            "process.start" => Ok(Capability::ProcessStart),
            "process.wait" => Ok(Capability::ProcessWait),
            "process.terminate" => Ok(Capability::ProcessTerminate),
            "process.list" => Ok(Capability::ProcessList),
            "process.resource_usage" => Ok(Capability::ProcessResourceUsage),
            "terminal.open" => Ok(Capability::TerminalOpen),
            "terminal.write" => Ok(Capability::TerminalWrite),
            "terminal.read" => Ok(Capability::TerminalRead),
            "terminal.resize" => Ok(Capability::TerminalResize),
            "terminal.close" => Ok(Capability::TerminalClose),
            "git.read" => Ok(Capability::GitRead),
            "git.write" => Ok(Capability::GitWrite),
            "git.status" => Ok(Capability::GitStatus),
            "git.diff" => Ok(Capability::GitDiff),
            "git.commit" => Ok(Capability::GitCommit),
            "network.proxy" => Ok(Capability::NetworkProxy),
            "network.direct" => Ok(Capability::NetworkDirect),
            "secrets.read" => Ok(Capability::SecretsRead),
            "secrets.write" => Ok(Capability::SecretsWrite),
            "approval.request" => Ok(Capability::ApprovalRequest),
            "system.elevate" => Ok(Capability::SystemElevate),
            _ => Err(format!("Unknown capability: {}", s)),
        }
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Execution profile
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionProfile {
    Inspect,
    Edit,
    Development,
    SandboxedDevelopment,
    ElevatedOneShot,
}

impl ExecutionProfile {
    pub fn as_str(&self) -> &'static str {
        match self {
            ExecutionProfile::Inspect => "inspect",
            ExecutionProfile::Edit => "edit",
            ExecutionProfile::Development => "development",
            ExecutionProfile::SandboxedDevelopment => "sandboxed_development",
            ExecutionProfile::ElevatedOneShot => "elevated_one_shot",
        }
    }

    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "inspect" => Ok(ExecutionProfile::Inspect),
            "edit" => Ok(ExecutionProfile::Edit),
            "development" => Ok(ExecutionProfile::Development),
            "sandboxed_development" => Ok(ExecutionProfile::SandboxedDevelopment),
            "elevated_one_shot" => Ok(ExecutionProfile::ElevatedOneShot),
            _ => Err(format!("Unknown execution profile: {}", s)),
        }
    }
}

/// Policy decision
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    Allow,
    Deny,
    Ask,
}

impl PolicyDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyDecision::Allow => "allow",
            PolicyDecision::Deny => "deny",
            PolicyDecision::Ask => "ask",
        }
    }
}

/// Isolation level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationLevel {
    None,
    ProcessLimited,
    WriteRestricted,
    FilesystemRestricted,
    NetworkRestricted,
    StrongIsolation,
    VmIsolated,
}

impl IsolationLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            IsolationLevel::None => "none",
            IsolationLevel::ProcessLimited => "process_limited",
            IsolationLevel::WriteRestricted => "write_restricted",
            IsolationLevel::FilesystemRestricted => "filesystem_restricted",
            IsolationLevel::NetworkRestricted => "network_restricted",
            IsolationLevel::StrongIsolation => "strong_isolation",
            IsolationLevel::VmIsolated => "vm_isolated",
        }
    }
}

/// Backend capability report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendCapabilities {
    pub backend_name: String,
    pub platform: Platform,
    pub architecture: Architecture,
    pub filesystem_write_isolation: IsolationSupport,
    pub filesystem_read_isolation: IsolationSupport,
    pub network_isolation: IsolationSupport,
    pub process_tree_limit: IsolationSupport,
    pub memory_limit: IsolationSupport,
    pub cpu_limit: IsolationSupport,
    pub interactive_terminal: bool,
    pub required_privileges: Vec<String>,
    pub unsupported_policy_fields: Vec<String>,
    pub overall: OverallIsolation,
}

/// Isolation support level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationSupport {
    Enforced,
    Partial,
    Unavailable,
    NotRequested,
}

/// Overall isolation assessment
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverallIsolation {
    None,
    Partial,
    Full,
    Vm,
}

/// Enforcement report from backend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementReport {
    pub backend: String,
    pub requested_profile: ExecutionProfile,
    pub applied_isolation: IsolationLevel,
    pub filesystem_write: IsolationSupport,
    pub filesystem_read: IsolationSupport,
    pub network: IsolationSupport,
    pub process_tree: IsolationSupport,
    pub memory: IsolationSupport,
    pub cpu: IsolationSupport,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

impl EnforcementReport {
    pub fn is_fully_enforced(&self) -> bool {
        self.errors.is_empty()
            && self.filesystem_write == IsolationSupport::Enforced
            && self.filesystem_read == IsolationSupport::Enforced
            && self.network == IsolationSupport::Enforced
            && self.process_tree == IsolationSupport::Enforced
            && self.memory == IsolationSupport::Enforced
    }

    pub fn has_failures(&self) -> bool {
        !self.errors.is_empty()
    }
}

// JSON Schema support for the UUID-based identifier newtypes. schemars has no
// built-in UUID schema, so each identifier serializes as a JSON string.
macro_rules! impl_json_schema_for_uuid_newtype {
    ($ty:ident) => {
        impl JsonSchema for $ty {
            fn schema_name() -> String {
                stringify!($ty).to_string()
            }
            fn schema_id() -> std::borrow::Cow<'static, str> {
                stringify!($ty).into()
            }
            fn json_schema(
                _gen: &mut schemars::gen::SchemaGenerator,
            ) -> schemars::schema::Schema {
                String::json_schema(_gen)
            }
        }
    }
}

impl_json_schema_for_uuid_newtype!(ProjectId);
impl_json_schema_for_uuid_newtype!(AgentId);
impl_json_schema_for_uuid_newtype!(DeviceId);
impl_json_schema_for_uuid_newtype!(SessionId);
impl_json_schema_for_uuid_newtype!(ProcessId);
impl_json_schema_for_uuid_newtype!(TerminalId);
impl_json_schema_for_uuid_newtype!(ApprovalId);