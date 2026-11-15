//! MCP server implementation
//!
//! Exposes YL Agent Runtime capabilities as MCP tools.

use rmcp::{ServerHandler, ServerInfo, ServerCapabilities, tool_handler};
use rmcp::model::*;
use runtime_core::error::{Error, Result};
use runtime_core::types::*;
use std::sync::Arc;
use tokio::sync::RwLock;

/// MCP server for YL Agent Runtime
pub struct McpServer {
    runtime: Arc<dyn RuntimeService + Send + Sync>,
}

/// Runtime service trait for MCP server to call
#[async_trait::async_trait]
pub trait RuntimeService: Send + Sync {
    async fn get_status(&self) -> Result<RuntimeStatus>;
    async fn get_capabilities(&self) -> Result<Vec<CapabilityGrant>>;
    async fn list_workspaces(&self) -> Result<Vec<String>>;
    async fn execute_command(&self, command: String, args: Vec<String>) -> Result<CommandResult>;
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

#[async_trait::async_trait]
impl ServerHandler for McpServer {
    async fn get_info(&self) -> ServerInfo {
        ServerInfo {
            server: Implementation {
                name: "yl-agent-runtime".to_string(),
                version: Some("0.1.0".to_string()),
            },
            capabilities: ServerCapabilities::builder().build(),
            instructions: Some("YL Agent Runtime - Portable agent execution runtime".to_string()),
        }
    }

    #[tool_handler]
    async fn runtime_status(&self) -> Result<CallToolResult> {
        let status = self.runtime.get_status().await.map_err(|e| {
            rmcp::Error::internal(format!("{}", e))
        })?;
        Ok(CallToolResult::success(vec![
            Content::text(serde_json::to_string(&status).unwrap())
        ]))
    }

    #[tool_handler]
    async fn runtime_capabilities(&self) -> Result<CallToolResult> {
        let caps = self.runtime.get_capabilities().await.map_err(|e| {
            rmcp::Error::internal(format!("{}", e))
        })?;
        Ok(CallToolResult::success(vec![
            Content::text(serde_json::to_string(&caps).unwrap())
        ]))
    }

    #[tool_handler]
    async fn workspace_list(&self, args: workspace_list::Args) -> Result<CallToolResult> {
        let _ = args;
        let workspaces = self.runtime.list_workspaces().await.map_err(|e| {
            rmcp::Error::internal(format!("{}", e))
        })?;
        Ok(CallToolResult::success(vec![
            Content::text(serde_json::to_string(&workspaces).unwrap())
        ]))
    }

    #[tool_handler]
    async fn process_exec(&self, args: process_exec::Args) -> Result<CallToolResult> {
        let result = self.runtime.execute_command(args.command, args.args.unwrap_or_default()).await
            .map_err(|e| rmcp::Error::internal(format!("{}", e)))?;
        Ok(CallToolResult::success(vec![
            Content::text(serde_json::to_string(&result).unwrap())
        ]))
    }
}

// MCP tool argument types
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