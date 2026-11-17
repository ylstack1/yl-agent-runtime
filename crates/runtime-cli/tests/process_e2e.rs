//! End-to-end stdio conformance tests for Phase 2 process execution.
//!
//! Every test spawns the real compiled `yl` binary as a child process over
//! stdio and speaks JSON-RPC through the rmcp client. No mocks are used.
//! The binary is exercised through its real MCP tools:
//! `process.exec`, `process.start`, `process.read`, `process.stop` and
//! `process.discover_tools`.

use rmcp::{
    model::{CallToolRequestParams, CallToolResult, ClientConfig, JsonObject},
    service::{RoleClient, RunningService, ServiceError, ServiceExt},
    transport::TokioChildProcess,
};
use serde_json::json;
use std::error::Error;
use tokio::process::Command;

type McpClient = RunningService<RoleClient, ClientConfig>;

/// A live stdio session against the real `yl` binary.
///
/// The `TempDir` guard is kept alive so the workspace root is not deleted
/// while the child server is still running.
struct StdioSession {
    client: McpClient,
    _tmp: tempfile::TempDir,
}

/// Concatenate the text content blocks of a tool result.
fn result_text(result: &CallToolResult) -> String {
    result
        .content
        .iter()
        .filter_map(|block| block.as_text().map(|text| text.text.clone()))
        .collect::<Vec<_>>()
        .join("")
}

/// Call a tool over stdio.
///
/// Returns the concatenated text content on success, or the error message
/// when the call fails — either a JSON-RPC error from the server or an
/// `is_error` tool result.
async fn call_tool(
    session: &StdioSession,
    name: &'static str,
    arguments: JsonObject,
) -> Result<String, String> {
    let params = CallToolRequestParams::new(name).with_arguments(arguments);
    match session.client.call_tool(params).await {
        Ok(result) => {
            if result.is_error.unwrap_or(false) {
                Err(result_text(&result))
            } else {
                Ok(result_text(&result))
            }
        }
        Err(err) => match err {
            ServiceError::McpError(e) => Err(e.message.to_string()),
            other => Err(format!("{other}")),
        },
    }
}

/// Call a tool and parse the response text as JSON.
async fn call_tool_json(
    session: &StdioSession,
    name: &'static str,
    arguments: JsonObject,
) -> Result<serde_json::Value, String> {
    let text = call_tool(session, name, arguments).await?;
    serde_json::from_str(&text).map_err(|e| format!("tool returned non-JSON: {e}: {text}"))
}

fn args(object: serde_json::Value) -> JsonObject {
    object
        .as_object()
        .expect("test arguments must be a JSON object")
        .clone()
}

/// Spawn `yl mcp --root <tmp>` and connect the rmcp client over stdio.
///
/// A minimal environment is passed to the child so that no deny-listed
/// secret variables leak from the test harness into the server process.
async fn spawn_mcp(
    extra_args: &[&str],
    extra_env: &[(&str, &str)],
) -> Result<StdioSession, Box<dyn Error + Send + Sync>> {
    let tmp = tempfile::TempDir::new().unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_yl"));
    cmd.arg("mcp").arg("--root").arg(tmp.path());
    for arg in extra_args {
        cmd.arg(arg);
    }
    cmd.env_clear();
    cmd.env("PATH", std::env::var("PATH").unwrap_or_default());
    #[cfg(windows)]
    {
        if let Ok(v) = std::env::var("SYSTEMROOT") {
            cmd.env("SYSTEMROOT", v);
        }
    }
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let transport = TokioChildProcess::new(cmd)?;
    let client = ClientConfig::default().serve(transport).await?;
    Ok(StdioSession { client, _tmp: tmp })
}

#[tokio::test]
async fn execute_roundtrip_returns_version() {
    let session = spawn_mcp(&[], &[]).await.expect("spawn stdio server");
    let result = call_tool_json(
        &session,
        "process.exec",
        args(json!({
            "project_id": "unused",
            "command": "cargo",
            "args": ["--version"],
            "timeout_seconds": 30,
        })),
    )
    .await
    .expect("process.exec should succeed");
    assert_eq!(
        result["exit_code"].as_i64(),
        Some(0),
        "expected exit_code 0, got {result:?}"
    );
    let stdout = result["stdout"].as_str().expect("stdout is a string");
    assert!(
        stdout.split_whitespace().any(|token| {
            !token.is_empty()
                && token.chars().all(|c| c.is_ascii_digit() || c == '.')
                && token.contains('.')
        }),
        "stdout should contain a version number, got {stdout:?}"
    );
}

#[tokio::test]
async fn start_read_stop_lifecycle() {
    let session = spawn_mcp(&[], &[]).await.expect("spawn stdio server");
    let handle = call_tool_json(
        &session,
        "process.start",
        args(json!({
            "project_id": "unused",
            "program": "node",
            "args": ["-e", "setTimeout(()=>{}, 60000);"],
        })),
    )
    .await
    .expect("process.start should succeed");
    let process_id = handle["process_id"]
        .as_str()
        .expect("process_id is a string")
        .to_string();
    assert!(!process_id.is_empty(), "process_id must be non-empty");

    let read = call_tool_json(
        &session,
        "process.read",
        args(json!({ "process_id": process_id.clone() })),
    )
    .await
    .expect("process.read should succeed");
    assert!(
        read["exit_status"].is_null(),
        "process should still be running, got {read:?}"
    );

    let stopped = call_tool_json(
        &session,
        "process.stop",
        args(json!({ "process_id": process_id, "force": true })),
    )
    .await
    .expect("process.stop should succeed");
    assert_eq!(
        stopped["stopped"],
        true,
        "expected stopped: true, got {stopped:?}"
    );
}

#[tokio::test]
async fn env_deny_blocks_aws_secret_access_key() {
    let session = spawn_mcp(&[], &[("AWS_SECRET_ACCESS_KEY", "secret")])
        .await
        .expect("spawn stdio server");
    let err = call_tool(
        &session,
        "process.start",
        args(json!({
            "project_id": "unused",
            "program": "cargo",
            "args": ["--version"],
        })),
    )
    .await
    .expect_err("process.start with denied env should fail");
    assert!(
        err.contains("denied"),
        "expected env-deny error, got: {err}"
    );
}

#[tokio::test]
async fn path_escape_rejected() {
    let session = spawn_mcp(&[], &[]).await.expect("spawn stdio server");
    let err = call_tool(
        &session,
        "process.start",
        args(json!({
            "project_id": "unused",
            "program": "cargo",
            "cwd": "../../../",
        })),
    )
    .await
    .expect_err("process.start with escaping cwd should fail");
    assert!(
        err.contains("root") || err.contains("allowed"),
        "expected path-escape error, got: {err}"
    );
}

#[tokio::test]
async fn discover_tools_lists_toolchains() {
    let session = spawn_mcp(&[], &[]).await.expect("spawn stdio server");
    let result = call_tool_json(
        &session,
        "process.discover_tools",
        args(json!({})),
    )
    .await
    .expect("process.discover_tools should succeed");
    let tools = result["tools"].as_array().expect("tools is an array");
    let names: Vec<&str> = tools
        .iter()
        .map(|t| t.as_str().expect("tool name is a string"))
        .collect();
    for tool in ["cargo", "git", "node"] {
        assert!(
            names.contains(&tool),
            "discover_tools should include {tool}, got {names:?}"
        );
    }
}

#[tokio::test]
async fn allowlist_rejects_unknown_program() {
    let session = spawn_mcp(&[], &[]).await.expect("spawn stdio server");
    let err = call_tool(
        &session,
        "process.start",
        args(json!({
            "project_id": "unused",
            "program": "evilcmd-xyz",
            "args": [],
        })),
    )
    .await
    .expect_err("process.start with non-allowlisted program should fail");
    assert!(
        err.contains("allowlist"),
        "expected allowlist error, got: {err}"
    );
}

#[tokio::test]
async fn timeout_returns_timeout_error_type() {
    let session = spawn_mcp(&[], &[]).await.expect("spawn stdio server");
    let result = call_tool_json(
        &session,
        "process.exec",
        args(json!({
            "project_id": "unused",
            "command": "node",
            "args": ["-e", "setTimeout(()=>{}, 60000);"],
            "timeout_seconds": 1,
        })),
    )
    .await
    .expect("process.exec should return a result");
    let error_type = result["error_type"].as_str();
    assert_eq!(
        error_type,
        Some("timeout"),
        "expected error_type=timeout, got {result:?}"
    );
    assert_eq!(
        result["success"],
        false,
        "expected success=false on timeout, got {result:?}"
    );
}
