//! Protocol types for MCP messages

use runtime_core::types::*;
use serde::{Deserialize, Serialize};
use schemars::JsonSchema;

/// MCP tool call request
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct McpToolRequest {
    pub tool: String,
    pub arguments: serde_json::Value,
    pub session_id: Option<SessionId>,
    pub request_id: String,
}

/// MCP tool call response
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct McpToolResponse {
    pub success: bool,
    pub result: Option<serde_json::Value>,
    pub error: Option<McpError>,
    pub request_id: String,
    pub duration_ms: u64,
}

/// MCP error
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct McpError {
    pub code: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

/// MCP resource
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct McpResource {
    pub uri: String,
    pub name: String,
    pub description: Option<String>,
    pub mime_type: Option<String>,
}

/// Runtime capability report (for MCP runtime.capabilities tool)
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CapabilityReport {
    pub platform: Platform,
    pub architecture: Architecture,
    pub backend: String,
    pub isolation_level: String,
    pub filesystem_write: String,
    pub filesystem_read: String,
    pub network: String,
    pub process_tree: String,
    pub memory: String,
    pub cpu: String,
    pub overall: String,
    pub warnings: Vec<String>,
}