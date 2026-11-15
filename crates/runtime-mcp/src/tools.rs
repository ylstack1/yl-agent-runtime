//! MCP tool definitions
//!
//! Each tool has a JSON schema, permission requirement, timeout, output limit,
//! audit event, and structured error format per PRD section 13.1.

use runtime_core::types::*;
use serde::{Deserialize, Serialize};
use schemars::JsonSchema;

/// MCP tool definition
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct McpToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
    pub required_capability: Option<Capability>,
    pub timeout_seconds: u64,
    pub max_output_bytes: u64,
    pub audit_event: AuditEventType,
}

/// Tool category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolCategory {
    Runtime,
    Workspace,
    Process,
    Terminal,
    Git,
    Approval,
}

/// All MCP tools exposed by the runtime
pub struct McpTools;

impl McpTools {
    /// Get all tool definitions
    pub fn all() -> Vec<McpToolDefinition> {
        vec![
            // Runtime tools
            McpToolDefinition {
                name: "runtime.status".to_string(),
                description: "Get runtime status and capability report".to_string(),
                input_schema: serde_json::json!({}),
                required_capability: None,
                timeout_seconds: 5,
                max_output_bytes: 10_000,
                audit_event: AuditEventType::RuntimeStart,
            },
            McpToolDefinition {
                name: "runtime.capabilities".to_string(),
                description: "Get available backend capabilities".to_string(),
                input_schema: serde_json::json!({}),
                required_capability: None,
                timeout_seconds: 5,
                max_output_bytes: 10_000,
                audit_event: AuditEventType::BackendCapabilityReport,
            },

            // Workspace tools
            McpToolDefinition {
                name: "workspace.list".to_string(),
                description: "List files in a workspace".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "project_id": { "type": "string" },
                        "path": { "type": "string" }
                    },
                    "required": ["project_id"]
                }),
                required_capability: Some(Capability::WorkspaceList),
                timeout_seconds: 10,
                max_output_bytes: 100_000,
                audit_event: AuditEventType::WorkspaceList,
            },
            McpToolDefinition {
                name: "workspace.read_file".to_string(),
                description: "Read a file from a workspace".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "project_id": { "type": "string" },
                        "path": { "type": "string" }
                    },
                    "required": ["project_id", "path"]
                }),
                required_capability: Some(Capability::WorkspaceRead),
                timeout_seconds: 10,
                max_output_bytes: 10_000_000,
                audit_event: AuditEventType::WorkspaceRead,
            },
            McpToolDefinition {
                name: "workspace.write_file".to_string(),
                description: "Write a file to a workspace".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "project_id": { "type": "string" },
                        "path": { "type": "string" },
                        "content": { "type": "string" }
                    },
                    "required": ["project_id", "path", "content"]
                }),
                required_capability: Some(Capability::WorkspaceWrite),
                timeout_seconds: 10,
                max_output_bytes: 10_000_000,
                audit_event: AuditEventType::WorkspaceWrite,
            },
            McpToolDefinition {
                name: "workspace.search".to_string(),
                description: "Search code in a workspace".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "project_id": { "type": "string" },
                        "query": { "type": "string" }
                    },
                    "required": ["project_id", "query"]
                }),
                required_capability: Some(Capability::WorkspaceSearch),
                timeout_seconds: 30,
                max_output_bytes: 100_000,
                audit_event: AuditEventType::WorkspaceSearch,
            },

            // Process tools
            McpToolDefinition {
                name: "process.discover_tools".to_string(),
                description: "Discover installed development toolchains".to_string(),
                input_schema: serde_json::json!({}),
                required_capability: None,
                timeout_seconds: 10,
                max_output_bytes: 50_000,
                audit_event: AuditEventType::ProcessList,
            },
            McpToolDefinition {
                name: "process.exec".to_string(),
                description: "Execute a command and wait for completion".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "project_id": { "type": "string" },
                        "command": { "type": "string" },
                        "args": { "type": "array", "items": { "type": "string" } },
                        "timeout_seconds": { "type": "integer" }
                    },
                    "required": ["project_id", "command"]
                }),
                required_capability: Some(Capability::ProcessExec),
                timeout_seconds: 300,
                max_output_bytes: 1_000_000,
                audit_event: AuditEventType::ProcessExec,
            },
            McpToolDefinition {
                name: "process.start".to_string(),
                description: "Start a long-running process".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "project_id": { "type": "string" },
                        "command": { "type": "string" },
                        "args": { "type": "array", "items": { "type": "string" } }
                    },
                    "required": ["project_id", "command"]
                }),
                required_capability: Some(Capability::ProcessStart),
                timeout_seconds: 10,
                max_output_bytes: 10_000,
                audit_event: AuditEventType::ProcessStart,
            },
            McpToolDefinition {
                name: "process.wait".to_string(),
                description: "Wait for a process to complete".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "process_id": { "type": "string" },
                        "timeout_seconds": { "type": "integer" }
                    },
                    "required": ["process_id"]
                }),
                required_capability: Some(Capability::ProcessWait),
                timeout_seconds: 300,
                max_output_bytes: 10_000,
                audit_event: AuditEventType::ProcessWait,
            },
            McpToolDefinition {
                name: "process.terminate".to_string(),
                description: "Terminate a running process".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "process_id": { "type": "string" },
                        "mode": { "type": "string", "enum": ["graceful", "force", "process_tree"] }
                    },
                    "required": ["process_id"]
                }),
                required_capability: Some(Capability::ProcessTerminate),
                timeout_seconds: 10,
                max_output_bytes: 10_000,
                audit_event: AuditEventType::ProcessTerminate,
            },

            // Terminal tools
            McpToolDefinition {
                name: "terminal.open".to_string(),
                description: "Open an interactive terminal session".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "project_id": { "type": "string" },
                        "rows": { "type": "integer" },
                        "cols": { "type": "integer" }
                    },
                    "required": ["project_id"]
                }),
                required_capability: Some(Capability::TerminalOpen),
                timeout_seconds: 10,
                max_output_bytes: 10_000,
                audit_event: AuditEventType::TerminalOpen,
            },
            McpToolDefinition {
                name: "terminal.write".to_string(),
                description: "Write to a terminal session".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "terminal_id": { "type": "string" },
                        "data": { "type": "string" }
                    },
                    "required": ["terminal_id", "data"]
                }),
                required_capability: Some(Capability::TerminalWrite),
                timeout_seconds: 5,
                max_output_bytes: 10_000,
                audit_event: AuditEventType::TerminalWrite,
            },
            McpToolDefinition {
                name: "terminal.read".to_string(),
                description: "Read terminal output".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "terminal_id": { "type": "string" }
                    },
                    "required": ["terminal_id"]
                }),
                required_capability: Some(Capability::TerminalRead),
                timeout_seconds: 5,
                max_output_bytes: 100_000,
                audit_event: AuditEventType::TerminalRead,
            },
            McpToolDefinition {
                name: "terminal.close".to_string(),
                description: "Close a terminal session".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "terminal_id": { "type": "string" }
                    },
                    "required": ["terminal_id"]
                }),
                required_capability: Some(Capability::TerminalClose),
                timeout_seconds: 5,
                max_output_bytes: 10_000,
                audit_event: AuditEventType::TerminalClose,
            },

            // Approval tool
            McpToolDefinition {
                name: "approval.request".to_string(),
                description: "Request user approval for a sensitive operation".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "capability": { "type": "string" },
                        "resource": { "type": "string" },
                        "justification": { "type": "string" }
                    },
                    "required": ["capability", "justification"]
                }),
                required_capability: Some(Capability::ApprovalRequest),
                timeout_seconds: 300,
                max_output_bytes: 10_000,
                audit_event: AuditEventType::ApprovalRequested,
            },
        ]
    }

    /// Get tool definition by name
    pub fn get(name: &str) -> Option<McpToolDefinition> {
        Self::all().into_iter().find(|t| t.name == name)
    }

    /// Get tools by category
    pub fn by_category(_category: ToolCategory) -> Vec<McpToolDefinition> {
        Self::all()
    }

    /// Get tools requiring a specific capability
    pub fn requiring_capability(capability: Capability) -> Vec<McpToolDefinition> {
        Self::all()
            .into_iter()
            .filter(|t| t.required_capability == Some(capability))
            .collect()
    }
}

/// Tool execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolExecutionResult {
    pub tool_name: String,
    pub success: bool,
    pub output: Option<serde_json::Value>,
    pub error: Option<ToolError>,
    pub duration_ms: u64,
    pub audit_event: Option<AuditEventType>,
}

/// Tool error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolError {
    pub code: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

impl ToolError {
    pub fn from_runtime_error(error: &runtime_core::error::Error) -> Self {
        Self {
            code: error.error_code().to_string(),
            message: error.to_string(),
            details: None,
        }
    }
}