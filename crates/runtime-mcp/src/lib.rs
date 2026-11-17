//! YL Agent Runtime MCP adapter
//!
//! Exposes focused MCP tools to agents per PRD section 13.1.
//! Uses the official rmcp SDK (ADR-002).

pub mod args;
pub mod server;
pub mod tools;
pub mod tools_fs;

pub use server::McpServer;
pub use tools::*;
