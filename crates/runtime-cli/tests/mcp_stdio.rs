//! End-to-end stdio MCP conformance tests for the Phase 1 filesystem toolset.
//!
//! Every test spawns the real compiled `yl` binary as a child process over
//! stdio and speaks JSON-RPC through the rmcp 3.10 client. No mocks are used.

use rmcp::{
    model::{CallToolRequestParams, CallToolResult, ClientConfig, JsonObject},
    service::{RoleClient, RunningService, ServiceError, ServiceExt},
    transport::{ConfigureCommandExt, TokioChildProcess},
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

/// Phase 1 conformance tool list (PRD § "Conformance & tool naming").
/// `process.start/wait/terminate/discover_tools`, `terminal.*`, `git.*` and
/// `approval.request` are intentionally deferred to Phase 2/3.
const CONFORMANCE_TOOLS: &[&str] = &[
    "runtime.status",
    "runtime.capabilities",
    "workspace.read",
    "workspace.write",
    "workspace.edit",
    "workspace.patch",
    "workspace.replace_text",
    "workspace.search",
    "workspace.find_files",
    "workspace.list",
    "workspace.tree",
    "workspace.stat",
    "workspace.mkdir",
    "workspace.move",
    "workspace.delete",
    "workspace.allowed_roots",
    "workspace.read_file",
    "workspace.write_file",
    "process.exec",
];

/// Spawn `yl mcp --root <tmp>` and connect the rmcp client over stdio.
async fn spawn_mcp(extra_args: &[&str]) -> Result<StdioSession, Box<dyn Error + Send + Sync>> {
    let tmp = tempfile::TempDir::new().unwrap();
    let transport = TokioChildProcess::new(
        Command::new(env!("CARGO_BIN_EXE_yl"))
            .configure(|cmd| {
                cmd.arg("mcp").arg("--root").arg(tmp.path());
                for arg in extra_args {
                    cmd.arg(arg);
                }
            }),
    )?;
    let client = ClientConfig::default().serve(transport).await?;
    Ok(StdioSession { client, _tmp: tmp })
}

/// Return the names of every tool the server advertises via `tools/list`.
async fn tool_names(session: &StdioSession) -> Vec<String> {
    let result = session
        .client
        .list_tools(None)
        .await
        .expect("tools/list should succeed against a running stdio server");
    result
        .tools
        .into_iter()
        .map(|tool| tool.name.to_string())
        .collect()
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
/// when the call fails — either a JSON-RPC error from the server (e.g.
/// path escape or sensitive-file refusal) or an `is_error` tool result.
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

#[tokio::test]
async fn conformance_phase1_tools_present() {
    let session = spawn_mcp(&[]).await.expect("spawn stdio server");
    let names = tool_names(&session).await;
    for name in CONFORMANCE_TOOLS {
        assert!(
            names.iter().any(|n| n == *name),
            "conformance tool missing: {name} (present: {names:?})"
        );
    }
}

#[tokio::test]
async fn write_read_edit_roundtrip_over_stdio() {
    let session = spawn_mcp(&[]).await.expect("spawn stdio server");

    call_tool(
        &session,
        "workspace.write",
        args(json!({ "path": "a.txt", "content": "alpha\n", "overwrite": true })),
    )
    .await
    .expect("workspace.write should succeed");

    call_tool(
        &session,
        "workspace.edit",
        args(json!({
            "path": "a.txt",
            "edits": [{ "old_text": "alpha", "new_text": "ALPHA" }],
            "dry_run": false
        })),
    )
    .await
    .expect("workspace.edit should succeed");

    let result = call_tool_json(
        &session,
        "workspace.read",
        args(json!({ "path": "a.txt" })),
    )
    .await
    .expect("workspace.read should succeed");
    let content = result["content"]
        .as_str()
        .expect("read content is a string");
    assert!(
        content.ends_with("ALPHA\n"),
        "expected edited content ending in ALPHA\\n, got {content:?}"
    );
}

#[tokio::test]
async fn search_over_stdio_finds_content() {
    let session = spawn_mcp(&[]).await.expect("spawn stdio server");

    call_tool(
        &session,
        "workspace.write",
        args(json!({ "path": "note1.txt", "content": "the needle is here\n", "overwrite": true })),
    )
    .await
    .expect("write note1.txt should succeed");
    call_tool(
        &session,
        "workspace.write",
        args(json!({ "path": "note2.txt", "content": "haystack only\n", "overwrite": true })),
    )
    .await
    .expect("write note2.txt should succeed");

    let result = call_tool_json(
        &session,
        "workspace.search",
        args(json!({ "query": "needle" })),
    )
    .await
    .expect("workspace.search should succeed");
    let matches = result["matches"]
        .as_array()
        .expect("search matches is an array");
    assert!(
        matches.iter().any(|m| {
            m["path"]
                .as_str()
                .map_or(false, |p| p.ends_with("note1.txt"))
        }),
        "expected a match for note1.txt, got {matches:?}"
    );
    assert!(
        matches.iter().all(|m| {
            m["path"]
                .as_str()
                .map_or(true, |p| !p.ends_with("note2.txt"))
        }),
        "note2.txt should not match needle, got {matches:?}"
    );
}

#[tokio::test]
async fn escape_attempt_is_error() {
    let session = spawn_mcp(&[]).await.expect("spawn stdio server");

    let err = call_tool(
        &session,
        "workspace.read",
        args(json!({ "path": "../../outside.txt" })),
    )
    .await
    .expect_err("reading a path outside the root should fail");
    assert!(
        err.contains("allowed"),
        "escape error should mention allowed roots, got: {err}"
    );
}

#[tokio::test]
async fn sensitive_file_hidden_and_refused() {
    let session = spawn_mcp(&[]).await.expect("spawn stdio server");

    let write_err = call_tool(
        &session,
        "workspace.write",
        args(json!({ "path": ".env", "content": "K=1", "overwrite": true })),
    )
    .await
    .expect_err("writing a sensitive file should be refused");
    assert!(
        write_err.contains("Sensitive file blocked"),
        "sensitive write error should mention blocked, got: {write_err}"
    );

    let read_err = call_tool(
        &session,
        "workspace.read",
        args(json!({ "path": ".env" })),
    )
    .await
    .expect_err("reading a sensitive file should be refused");
    assert!(
        read_err.contains("Sensitive file blocked"),
        "sensitive read error should mention blocked, got: {read_err}"
    );
}

#[tokio::test]
async fn mcp_without_roots_fails_closed() {
    // No --root and no config file: the binary must exit 1 before serving.
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_yl"));
    cmd.arg("mcp");
    let transport = TokioChildProcess::new(cmd).expect("spawning yl mcp should succeed");
    let result = ClientConfig::default().serve(transport).await;
    assert!(
        result.is_err(),
        "stdio server without roots should fail to initialize (fail-closed)"
    );
}

#[tokio::test]
async fn server_instructions_advertise_workspace_tools() {
    let session = spawn_mcp(&[]).await.expect("spawn stdio server");

    let info = session
        .client
        .peer_info()
        .expect("server should send peer info during initialize");
    let instructions = info.instructions.as_deref().unwrap_or("");
    assert!(
        instructions.contains("workspace.read"),
        "instructions should advertise workspace.read, got: {instructions:?}"
    );
    assert!(
        instructions.contains("--root"),
        "instructions should advertise --root, got: {instructions:?}"
    );
}
