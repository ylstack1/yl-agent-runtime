//! Error types for YL Agent Runtime

use thiserror::Error;

/// Main error type for the runtime
#[derive(Error, Debug)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Approval required: {0}")]
    ApprovalRequired(String),

    #[error("Approval expired: {0}")]
    ApprovalExpired(String),

    #[error("Approval rejected: {0}")]
    ApprovalRejected(String),

    #[error("Workspace not found: {0}")]
    WorkspaceNotFound(String),

    #[error("Path not allowed: {0}")]
    PathNotAllowed(String),

    #[error("Path escape attempt: {0}")]
    PathEscape(String),

    #[error("Process error: {0}")]
    Process(String),

    #[error("Process not found: {0}")]
    ProcessNotFound(String),

    #[error("Process timeout: {0}")]
    ProcessTimeout(String),

    #[error("Process tree limit exceeded: {0}")]
    ProcessTreeLimit(String),

    #[error("Memory limit exceeded: {0}")]
    MemoryLimit(String),

    #[error("Resource limit exceeded: {0}")]
    ResourceLimit(String),

    #[error("Sandbox error: {0}")]
    Sandbox(String),

    #[error("Sandbox backend unavailable: {0}")]
    SandboxUnavailable(String),

    #[error("Isolation failure: {0}")]
    IsolationFailure(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Network not allowed: {0}")]
    NetworkNotAllowed(String),

    #[error("Toolchain not found: {0}")]
    ToolchainNotFound(String),

    #[error("Toolchain discovery error: {0}")]
    ToolchainDiscovery(String),

    #[error("Identity error: {0}")]
    Identity(String),

    #[error("Agent not found: {0}")]
    AgentNotFound(String),

    #[error("Device not found: {0}")]
    DeviceNotFound(String),

    #[error("Pairing error: {0}")]
    Pairing(String),

    #[error("Transport error: {0}")]
    Transport(String),

    #[error("MCP error: {0}")]
    Mcp(String),

    #[error("Audit error: {0}")]
    Audit(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Cryptography error: {0}")]
    Crypto(String),

    #[error("Terminal error: {0}")]
    Terminal(String),

    #[error("Terminal session not found: {0}")]
    TerminalNotFound(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Not implemented: {0}")]
    NotImplemented(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("{0}")]
    Other(String),
}

/// Convenience result type
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Check if this error is a policy violation that should be reported to the agent
    pub fn is_policy_violation(&self) -> bool {
        matches!(
            self,
            Error::PolicyViolation(_)
                | Error::PermissionDenied(_)
                | Error::ApprovalRequired(_)
                | Error::PathNotAllowed(_)
                | Error::PathEscape(_)
                | Error::NetworkNotAllowed(_)
        )
    }

    /// Check if this error indicates an isolation failure (security critical)
    pub fn is_isolation_failure(&self) -> bool {
        matches!(
            self,
            Error::IsolationFailure(_) | Error::SandboxUnavailable(_) | Error::PathEscape(_)
        )
    }

    /// Get a user-friendly error code for MCP responses
    pub fn error_code(&self) -> &'static str {
        match self {
            Error::Io(_) => "IO_ERROR",
            Error::Serde(_) => "SERIALIZATION_ERROR",
            Error::Config(_) => "CONFIG_ERROR",
            Error::PolicyViolation(_) => "POLICY_VIOLATION",
            Error::PermissionDenied(_) => "PERMISSION_DENIED",
            Error::ApprovalRequired(_) => "APPROVAL_REQUIRED",
            Error::ApprovalExpired(_) => "APPROVAL_EXPIRED",
            Error::ApprovalRejected(_) => "APPROVAL_REJECTED",
            Error::WorkspaceNotFound(_) => "WORKSPACE_NOT_FOUND",
            Error::PathNotAllowed(_) => "PATH_NOT_ALLOWED",
            Error::PathEscape(_) => "PATH_ESCAPE",
            Error::Process(_) => "PROCESS_ERROR",
            Error::ProcessNotFound(_) => "PROCESS_NOT_FOUND",
            Error::ProcessTimeout(_) => "PROCESS_TIMEOUT",
            Error::ProcessTreeLimit(_) => "PROCESS_TREE_LIMIT",
            Error::MemoryLimit(_) => "MEMORY_LIMIT",
            Error::ResourceLimit(_) => "RESOURCE_LIMIT",
            Error::Sandbox(_) => "SANDBOX_ERROR",
            Error::SandboxUnavailable(_) => "SANDBOX_UNAVAILABLE",
            Error::IsolationFailure(_) => "ISOLATION_FAILURE",
            Error::Network(_) => "NETWORK_ERROR",
            Error::NetworkNotAllowed(_) => "NETWORK_NOT_ALLOWED",
            Error::ToolchainNotFound(_) => "TOOLCHAIN_NOT_FOUND",
            Error::ToolchainDiscovery(_) => "TOOLCHAIN_DISCOVERY_ERROR",
            Error::Identity(_) => "IDENTITY_ERROR",
            Error::AgentNotFound(_) => "AGENT_NOT_FOUND",
            Error::DeviceNotFound(_) => "DEVICE_NOT_FOUND",
            Error::Pairing(_) => "PAIRING_ERROR",
            Error::Transport(_) => "TRANSPORT_ERROR",
            Error::Mcp(_) => "MCP_ERROR",
            Error::Audit(_) => "AUDIT_ERROR",
            Error::Database(_) => "DATABASE_ERROR",
            Error::Crypto(_) => "CRYPTO_ERROR",
            Error::Terminal(_) => "TERMINAL_ERROR",
            Error::TerminalNotFound(_) => "TERMINAL_NOT_FOUND",
            Error::Validation(_) => "VALIDATION_ERROR",
            Error::NotImplemented(_) => "NOT_IMPLEMENTED",
            Error::Internal(_) => "INTERNAL_ERROR",
            Error::Other(_) => "UNKNOWN_ERROR",
        }
    }
}