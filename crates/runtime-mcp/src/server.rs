//! MCP server implementation
//!
//! Exposes YL Agent Runtime capabilities as MCP tools.
//! Uses the official rmcp SDK (ADR-002), targeting rmcp 3.10.
//
//! rmcp 3.10 API notes:
//!   - `get_info(&self) -> ServerConfig` (sync; `ServerInfo` renamed to `ServerConfig`)
//!   - `#[tool_handler]` is applied to the `impl ServerHandler` block and
//!     auto-generates `call_tool`, `list_tools`, `get_tool`, `get_info`.
//!   - Individual tools are marked with `#[tool]` and receive deserialized
//!     arguments through `Parameters<T>`.
//!   - Tool return values must implement `IntoCallToolResult` (e.g.
//!     `std::result::Result<CallToolResult, McpError>`).

use rmcp::{
    ServerHandler, tool, tool_handler, tool_router,
    model::{CallToolResult, ContentBlock, JsonObject},
    handler::server::wrapper::Parameters,
};
use rmcp::ErrorData as McpError;
use runtime_core::traits::CapabilityGrant;
use runtime_core::types::*;
use std::result::Result;
use std::sync::Arc;

/// MCP server for YL Agent Runtime
pub struct McpServer {
    runtime: Arc<dyn RuntimeService + Send + Sync>,
}

/// Runtime service trait for MCP server to call
#[async_trait::async_trait]
pub trait RuntimeService: Send + Sync {
    async fn get_status(&self) -> runtime_core::error::Result<RuntimeStatus>;
    async fn get_capabilities(&self) -> runtime_core::error::Result<Vec<CapabilityGrant>>;
    async fn list_workspaces(&self) -> runtime_core::error::Result<Vec<String>>;
    async fn execute_command(
        &self,
        command: String,
        args: Vec<String>,
    ) -> runtime_core::error::Result<CommandResult>;
}

/// Runtime status
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RuntimeStatus {
    pub version: String,
    pub platform: String,
    pub backend: String,
    pub isolation_level: String,
    pub active_processes: u32,
    pub active_sessions: u32,
}

/// Command result
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CommandResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
}

impl McpServer {
    pub fn new(runtime: Arc<dyn RuntimeService + Send + Sync>) -> Self {
        Self { runtime }
    }
}

/// Tool routes exposed to MCP clients.
///
/// `#[tool_router]` generates `McpServer::tool_router()`, which is used by the
/// `#[tool_handler]` impl below to route `tools/call` requests.
#[tool_router]
impl McpServer {
    /// Report runtime status and capability summary.
    #[tool(name = "runtime.status")]
    async fn runtime_status(&self) -> Result<CallToolResult, McpError> {
        let status = self
            .runtime
            .get_status()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![ContentBlock::text(
            serde_json::to_string(&status).unwrap(),
        )]))
    }

    /// Report available backend capabilities.
    #[tool(name = "runtime.capabilities")]
    async fn runtime_capabilities(&self) -> Result<CallToolResult, McpError> {
        let caps = self
            .runtime
            .get_capabilities()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![ContentBlock::text(
            serde_json::to_string(&caps).unwrap(),
        )]))
    }

    /// List registered workspaces.
    #[tool(name = "workspace.list")]
    async fn workspace_list(&self) -> Result<CallToolResult, McpError> {
        let workspaces = self
            .runtime
            .list_workspaces()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![ContentBlock::text(
            serde_json::to_string(&workspaces).unwrap(),
        )]))
    }

    /// Execute a command and wait for completion.
    #[tool(
        name = "process.exec",
        input_schema = Arc::new(
            serde_json::from_value::<JsonObject>(
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "project_id": { "type": "string" },
                        "command": { "type": "string" },
                        "args": { "type": "array", "items": { "type": "string" } },
                        "timeout_seconds": { "type": "integer" }
                    },
                    "required": ["project_id", "command"]
                })
            )
            .expect("invalid process.exec input schema")
        )
    )]
    async fn process_exec(
        &self,
        args: Parameters<process_exec::Args>,
    ) -> Result<CallToolResult, McpError> {
        let args = args.0;
        let result = self
            .runtime
            .execute_command(args.command, args.args.unwrap_or_default())
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![ContentBlock::text(
            serde_json::to_string(&result).unwrap(),
        )]))
    }
}

/// `#[tool_handler]` wires the router into `ServerHandler` and generates
/// `call_tool`, `list_tools`, `get_tool`, and `get_info`.
///
/// `get_info` is auto-generated from `name`/`version`/`instructions` and
/// returns a `ServerConfig` advertising the tools capability.
#[tool_handler(
    name = "yl-agent-runtime",
    version = "0.1.0",
    instructions = "YL Agent Runtime - Portable agent execution runtime"
)]
impl ServerHandler for McpServer {
    // Intentionally empty: `#[tool_handler]` generates the required
    // `ServerHandler` methods (call_tool, list_tools, get_tool, get_info).
}

// ---------------------------------------------------------------------------
// MCP tool argument types
// ---------------------------------------------------------------------------

pub mod workspace_list {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    pub struct Args {}
}

pub mod process_exec {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    pub struct Args {
        pub command: String,
        pub args: Option<Vec<String>>,
    }
}
