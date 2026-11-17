//! MCP server implementation
//!
//! Exposes YL Agent Runtime capabilities as MCP tools.
//! Uses the official rmcp SDK (ADR-002), targeting rmcp 3.10.
//!
//! rmcp 3.10 API notes:
//!   - `get_info(&self) -> ServerConfig` (sync; `ServerInfo` renamed to `ServerConfig`)
//!   - `#[tool_handler]` is applied to the `impl ServerHandler` block and
//!     auto-generates `call_tool`, `list_tools`, `get_tool`, `get_info`.
//!   - Individual tools are marked with `#[tool]` and receive deserialized
//!     arguments through `Parameters<T>`.
//!   - Tool return values must implement `IntoCallToolResult` (e.g.
//!     `std::result::Result<CallToolResult, McpError>`).
//!
//! Task 11: the full Phase 1 workspace tool registry lives in this single
//! `#[tool_router] impl McpServer` block (rmcp does not merge multiple
//! `#[tool_router]` impls). Argument normalization, aliases and helpers live
//! in `args.rs` and `tools_fs.rs`.

use rmcp::{
    ServerHandler, tool, tool_handler, tool_router,
    model::{CallToolResult, JsonObject},
    handler::server::wrapper::Parameters,
};
use rmcp::ErrorData as McpError;
use runtime_audit::AuditService;
use runtime_approval::ApprovalBroker;
use runtime_core::ApprovalState;
use runtime_core::audit::{AuditEvent, AuditEventType};
use runtime_core::error::Error;
use runtime_core::traits::{ExecutionRequest, PolicyEngine, TerminationMode, WorkspaceService};
use runtime_core::types::*;
use runtime_process::{ProcessExecutor, ProcessServiceOps};
use runtime_workspace::WorkspaceServiceImpl;
use runtime_workspace::files::edit::{EditOptions, EditSpec};
use runtime_workspace::files::read::{ReadOptions, ReadOutcome};
use runtime_workspace::files::write::WriteOptions;
use runtime_workspace::search::{FindOptions, SearchOptions};
use crate::args::normalize_args;
use crate::tools_fs::{
    AllowedRootsArgs, DeleteArgs, EditArgs, FindFilesArgs, invalid, ListArgs,
    MkdirArgs, MoveArgs, output_json, PatchArgs, ProcessExecArgs,
    ProcessListArgs, ProcessReadArgs, ProcessStartArgs, ProcessStopArgs, ReadArgs, ReplaceTextArgs,
    resolve_project, SearchArgs, StatArgs, TreeArgs, TreeBudgetExceeded, walk_shallow, walk_tree,
    WriteArgs,
};
use serde_json::json;
use std::collections::HashMap;
use std::path::PathBuf;
use std::result::Result;
use std::sync::Arc;
use uuid::Uuid;

/// MCP server for YL Agent Runtime
pub struct McpServer {
    fs: Arc<WorkspaceServiceImpl>,
    roots: Vec<(ProjectId, PathBuf)>,       // ordered; roots[0] is primary for relative paths
    read_only_roots: Vec<PathBuf>,
    audit: Arc<dyn runtime_audit::AuditService>,
    process_service: Arc<dyn ProcessServiceOps>,
    policy_engine: Arc<dyn PolicyEngine>,
    approval_broker: Arc<dyn ApprovalBroker>,
    yolo: bool,                              // bypass Ask -> Allow, audited
    agent_id: AgentId,                       // derived from principal_agent
    principal_agent: String,                 // "mcp-local" (design decision 4)
    session_id: SessionId,                   // per-process synthetic session
}

/// Runtime status shape returned by `runtime.status`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RuntimeStatus {
    pub version: String,
    pub platform: String,
    pub backend: String,
    pub isolation_level: String,
    pub active_processes: u32,
    pub active_sessions: u32,
}

/// Command result shape returned by `process.exec`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CommandResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
}

impl McpServer {
    pub async fn new_for_fs(
        fs: Arc<WorkspaceServiceImpl>,
        roots: Vec<(ProjectId, PathBuf)>,
        audit: Arc<dyn AuditService>,
        read_only_roots: Vec<PathBuf>,
        process_service: Arc<dyn ProcessServiceOps>,
        policy_engine: Arc<dyn PolicyEngine>,
        approval_broker: Arc<dyn ApprovalBroker>,
        yolo: bool,
    ) -> Self {
        // Derive a stable agent id from the principal agent name so policy
        // grants persist across restarts for the same logical agent.
        let principal_agent = "mcp-local".to_string();
        let agent_id = agent_id_from_name(&principal_agent);

        // Register each root's profile in the policy store so enforcement
        // knows which profile applies to each project.
        for (id, _) in &roots {
            let _ = policy_engine.set_profile(*id, ExecutionProfile::Development).await;
        }

        Self {
            fs,
            roots,
            read_only_roots,
            audit,
            process_service,
            policy_engine,
            approval_broker,
            yolo,
            agent_id,
            principal_agent,
            session_id: SessionId::new(),
        }
    }

    /// Resolve a user-supplied path against the configured roots, surfacing
    /// MCP-friendly invalid-params errors for zero roots and escapes.
    fn resolve_user_path(&self, user_path: &PathBuf) -> Result<(ProjectId, PathBuf), McpError> {
        if self.roots.is_empty() {
            return Err(invalid(
                "No workspace roots configured. Restart with --root <dir>.",
            ));
        }
        match resolve_project(&self.roots, user_path) {
            Some(resolved) => Ok(resolved),
            None => {
                let list = self
                    .roots
                    .iter()
                    .map(|(_, root)| root.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                Err(invalid(format!(
                    "Path is not within any allowed workspace root: {}. Allowed roots: {list}",
                    user_path.display()
                )))
            }
        }
    }

    /// Map workspace/runtime errors to MCP errors: path/validation errors
    /// become `invalid_params`, I/O errors become `invalid_params` with an
    /// "IO error:" prefix, everything else becomes `internal_error`.
    fn map_runtime_error(e: Error) -> McpError {
        match e {
            Error::PathEscape(msg)
            | Error::PathNotAllowed(msg)
            | Error::Validation(msg)
            | Error::WorkspaceNotFound(msg)
            | Error::PolicyViolation(msg) => invalid(msg),
            Error::Io(e) => invalid(format!("IO error: {e}")),
            other => McpError::internal_error(other.to_string(), None),
        }
    }
}

/// Derive a stable AgentId from a principal-agent name so policy grants
/// and approvals are tied to the same logical agent across restarts.
fn agent_id_from_name(name: &str) -> AgentId {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    name.hash(&mut hasher);
    AgentId(Uuid::from_u128(hasher.finish() as u128))
}

impl McpServer {
    /// Enforce policy before a tool runs. Returns `Ok(())` when the call is
    /// allowed. On `Deny`, returns an `invalid_params` error. On `Ask`,
    /// creates a pending approval via the broker and returns an error that
    /// includes the `approval_id` so the caller can approve and retry.
    ///
    /// When `yolo` is set, `Ask` is treated as `Allow` (bypass) and the call
    /// proceeds, audited with `yolo: true`.
    async fn enforce_tool(
        &self,
        capability: Capability,
        resource: Option<&str>,
    ) -> Result<(), McpError> {
        if self.yolo {
            let mut event = AuditEvent::new(AuditEventType::ApprovalRequested);
            event = event.with_agent(self.agent_id);
            if let Some(pid) = self.roots.first().map(|(id, _)| *id) {
                event = event.with_project(pid);
            }
            event = event.with_session(self.session_id);
            event = event.with_capability(capability);
            if let Some(r) = resource {
                event = event.with_resource(r.to_string());
            }
            event.metadata.insert("yolo".to_string(), "true".to_string());
            if let Err(e) = self.audit.record(event).await {
                tracing::warn!("failed to record yolo audit event: {e}");
            }
            return Ok(());
        }

        let project_id = self
            .roots
            .first()
            .map(|(id, _)| *id)
            .ok_or_else(|| invalid("no workspace root configured for policy evaluation"))?;

        let decision = self
            .policy_engine
            .evaluate(self.agent_id, project_id, capability, resource)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        match decision {
            PolicyDecision::Allow => Ok(()),
            PolicyDecision::Deny => Err(invalid(format!(
                "policy denied: {capability}{}",
                resource.map(|r| format!(" (resource: {r})")).unwrap_or_default()
            ))),
            PolicyDecision::Ask => {
                // Before creating a new pending approval, check if the caller
                // already has a granted (non-expired) approval for this
                // capability+resource. If so, allow the call without
                // requiring re-approval.
                let already_granted = self
                    .approval_broker
                    .list_all()
                    .await
                    .into_iter()
                    .any(|r| {
                        r.capability == capability
                            && r.resource == resource.map(|s| s.to_string())
                            && r.state == ApprovalState::Granted
                            && r.expires_at
                                .map(|e| chrono::Utc::now() <= e)
                                .unwrap_or(true)
                    });
                if already_granted {
                    return Ok(());
                }

                let justification = format!("MCP tool call requires approval for {capability}");
                let approval_id = self
                    .approval_broker
                    .request(
                        self.agent_id,
                        project_id,
                        capability,
                        resource.map(|s| s.to_string()),
                        justification,
                    )
                    .await
                    .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                Err(invalid(format!(
                    "approval required: {capability}{}. Approve with: yl approval approve {approval_id} (or MCP approval.approve). Expires in 30 minutes.",
                    resource.map(|r| format!(" (resource: {r})")).unwrap_or_default()
                )))
            }
        }
    }

    /// Record one audit event for a mutating tool call. Audit failures are
    /// logged and never fail the call.
    async fn record_audit(
        &self,
        event_type: AuditEventType,
        project_id: Option<ProjectId>,
        resource: Option<String>,
    ) {
        let mut event = AuditEvent::new(event_type);
        event
            .metadata
            .insert("agent".to_string(), self.principal_agent.clone());
        if let Some(id) = project_id {
            event = event.with_project(id);
        }
        event = event.with_session(self.session_id);
        if let Some(resource) = resource {
            event = event.with_resource(resource);
        }
        if let Err(e) = self.audit.record(event).await {
            tracing::warn!("failed to record audit event: {e}");
        }
    }
}

/// Tool routes exposed to MCP clients.
///
/// `#[tool_router]` generates `McpServer::tool_router()`, which is used by the
/// `#[tool_handler]` impl below to route `tools/call` requests.
#[tool_router]
impl McpServer {
    /// Report runtime status and capability summary.
    #[tool(
        name = "runtime.status",
        input_schema = Arc::new(
            serde_json::from_value::<JsonObject>(
                serde_json::json!({ "type": "object", "properties": {}, "required": [] })
            )
            .expect("invalid runtime.status input schema")
        )
    )]
    async fn runtime_status(&self) -> Result<CallToolResult, McpError> {
        let active_processes = self
            .process_service
            .list()
            .await
            .map(|list| list.iter().filter(|p| p.running).count())
            .unwrap_or(0);
        output_json(&json!({
            "version": env!("CARGO_PKG_VERSION"),
            "platform": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "mode": "filesystem+process",
            "backend": "native",
            "isolation_level": "process-scoped",
            "workspace_roots": self
                .roots
                .iter()
                .map(|(_, root)| root.display().to_string())
                .collect::<Vec<_>>(),
            "read_only_roots": self
                .read_only_roots
                .iter()
                .map(|root| root.display().to_string())
                .collect::<Vec<_>>(),
            "tools_registered": Self::tool_router().list_all().len(),
            "active_processes": active_processes,
            "active_sessions": 1,
        }))
    }

    /// Report what this server can actually do, including the executable
    /// allowlist, so an agent can avoid calls that are guaranteed to fail.
    #[tool(
        name = "runtime.capabilities",
        input_schema = Arc::new(
            serde_json::from_value::<JsonObject>(
                serde_json::json!({ "type": "object", "properties": {}, "required": [] })
            )
            .expect("invalid runtime.capabilities input schema")
        )
    )]
    async fn runtime_capabilities(&self) -> Result<CallToolResult, McpError> {
        output_json(&json!({
            "filesystem": {
                "read": true,
                "write": true,
                "edit": true,
                "patch": true,
                "search": true,
                "line_numbered_read": true,
                "root_contained": true,
                "sensitive_files_blocked": true,
            },
            "process": {
                "exec": true,
                "long_running": true,
                "cursor_paged_output": true,
                "executable_allowlist": runtime_process::ALLOWED_TOOLS,
                "shell_builtins_available": false,
            },
            "runtime": {
                "git_tools": false,
                "approval_gate": true,
                "undo_journal": false,
            },
            "limits": {
                "workspace_roots": self.roots.len(),
                "read_only_roots": self.read_only_roots.len(),
            },
        }))
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
    async fn process_exec(&self, args: Parameters<JsonObject>) -> Result<CallToolResult, McpError> {
        let args = normalize_args("process.exec", &args.0)?;
        let args: ProcessExecArgs =
            serde_json::from_value(serde_json::Value::Object(args))
                .map_err(|e| invalid(format!("failed to deserialize parameters: {e}")))?;

        // Approval gate: process execution requires consent in most profiles.
        self.enforce_tool(Capability::ProcessExec, Some(&args.command))
            .await?;

        let executor = ProcessExecutor::new();
        let result = executor
            .execute(
                &args.command,
                &args.args.unwrap_or_default(),
                None,
                args.timeout_seconds.unwrap_or(300),
            )
            .map_err(Self::map_runtime_error)?;
        output_json(&json!({
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "error_type": result.error_type,
            "duration_ms": result.duration_ms,
            "success": result.success,
        }))
    }

    /// Spawn a process and return a handle.
    #[tool(
        name = "process.start",
        input_schema = Arc::new(
            serde_json::from_value::<JsonObject>(
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "project_id": { "type": "string" },
                        "program": { "type": "string" },
                        "args": { "type": "array", "items": { "type": "string" } },
                        "cwd": { "type": "string" },
                        "timeout_seconds": { "type": "integer" }
                    },
                    "required": ["project_id", "program"]
                })
            )
            .expect("invalid process.start input schema")
        )
    )]
    async fn process_start(&self, args: Parameters<JsonObject>) -> Result<CallToolResult, McpError> {
        let args = normalize_args("process.start", &args.0)?;
        let args: ProcessStartArgs =
            serde_json::from_value(serde_json::Value::Object(args))
                .map_err(|e| invalid(format!("failed to deserialize parameters: {e}")))?;

        // Approval gate: spawning a process requires consent in most profiles.
        self.enforce_tool(Capability::ProcessStart, Some(&args.program))
            .await?;

        if self.roots.is_empty() {
            return Err(invalid("No workspace roots configured"));
        }

        // Resolve the project: prefer an explicit project_id that matches a
        // registered root, otherwise fall back to the first (primary) root so
        // clients do not need to know the internally-assigned UUID.
        let project_id = Uuid::parse_str(&args.project_id)
            .ok()
            .and_then(|pid| {
                self.roots
                    .iter()
                    .find(|(p, _)| *p == ProjectId(pid))
                    .map(|(p, _)| *p)
            })
            .or_else(|| self.roots.first().map(|(p, _)| *p))
            .ok_or_else(|| invalid("No workspace roots configured"))?;
        let root = self
            .roots
            .iter()
            .find(|(p, _)| *p == project_id)
            .map(|(_, path)| path.clone())
            .ok_or_else(|| invalid("project root not found"))?;

        let cwd = match &args.cwd {
            Some(c) => {
                let joined = root.join(c);
                let canonical_root = std::fs::canonicalize(&root)
                    .map_err(|e| invalid(format!("cannot canonicalize root: {e}")))?;
                let canonical_cwd = std::fs::canonicalize(&joined).map_err(|_| {
                    invalid(format!(
                        "cwd is not within allowed workspace root: {c}. Allowed roots: {root:?}"
                    ))
                })?;
                if !canonical_cwd.starts_with(&canonical_root) {
                    return Err(invalid(format!(
                        "cwd is not within allowed workspace root: {c}. Allowed roots: {root:?}"
                    )));
                }
                canonical_cwd
            }
            None => root.clone(),
        };

        let request = ExecutionRequest {
            id: ProcessId::new(),
            session_id: self.session_id,
            project_id,
            agent_id: AgentId(Uuid::nil()),
            executable: PathBuf::from(&args.program),
            arguments: args.args.unwrap_or_default(),
            environment: HashMap::new(),
            working_directory: cwd,
            profile: ExecutionProfile::Development,
            capabilities: vec![],
            max_runtime_seconds: args.timeout_seconds,
            max_processes: None,
            memory_limit_mb: None,
            stdin_data: None,
        };

        let handle = self
            .process_service
            .start(request)
            .await
            .map_err(Self::map_runtime_error)?;

        self.record_audit(
            AuditEventType::ProcessStart,
            Some(project_id),
            Some(args.program.clone()),
        )
        .await;

        output_json(&json!({
            "process_id": handle.id.to_string(),
            "pid": handle.os_pid,
            "running": handle.status.running,
            "exit_code": handle.status.exit_status.as_ref().and_then(|s| s.code),
            "started_at": handle.status.started_at.to_rfc3339(),
        }))
    }

    /// Read process output (cursor-paged log read).
    #[tool(
        name = "process.read",
        input_schema = Arc::new(
            serde_json::from_value::<JsonObject>(
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "process_id": { "type": "string" },
                        "after": { "type": "integer" },
                        "limit_bytes": { "type": "integer" },
                        "wait_ms": { "type": "integer" }
                    },
                    "required": ["process_id"]
                })
            )
            .expect("invalid process.read input schema")
        )
    )]
    async fn process_read(&self, args: Parameters<JsonObject>) -> Result<CallToolResult, McpError> {
        let args = normalize_args("process.read", &args.0)?;
        let args: ProcessReadArgs =
            serde_json::from_value(serde_json::Value::Object(args))
                .map_err(|e| invalid(format!("failed to deserialize parameters: {e}")))?;

        let process_id = Uuid::parse_str(&args.process_id)
            .map_err(|e| invalid(format!("invalid process_id: {e}")))?;
        let process_id = ProcessId(process_id);

        let output = self
            .process_service
            .output(process_id)
            .await
            .map_err(Self::map_runtime_error)?;

        output_json(&json!({
            "process_id": args.process_id,
            "stdout": String::from_utf8_lossy(&output.stdout),
            "stderr": String::from_utf8_lossy(&output.stderr),
            "exit_status": output.exit_status,
            "truncated": output.truncated,
        }))
    }

    /// Terminate a running process.
    #[tool(
        name = "process.stop",
        input_schema = Arc::new(
            serde_json::from_value::<JsonObject>(
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "process_id": { "type": "string" },
                        "force": { "type": "boolean" }
                    },
                    "required": ["process_id"]
                })
            )
            .expect("invalid process.stop input schema")
        )
    )]
    async fn process_stop(&self, args: Parameters<JsonObject>) -> Result<CallToolResult, McpError> {
        let args = normalize_args("process.stop", &args.0)?;
        let args: ProcessStopArgs =
            serde_json::from_value(serde_json::Value::Object(args))
                .map_err(|e| invalid(format!("failed to deserialize parameters: {e}")))?;

        // Approval gate: terminating a process requires consent.
        self.enforce_tool(Capability::ProcessTerminate, Some(&args.process_id))
            .await?;

        let process_id = Uuid::parse_str(&args.process_id)
            .map_err(|e| invalid(format!("invalid process_id: {e}")))?;
        let process_id = ProcessId(process_id);

        let mode = if args.force.unwrap_or(false) {
            TerminationMode::Force
        } else {
            TerminationMode::Graceful
        };

        self.process_service
            .terminate(process_id, mode)
            .await
            .map_err(Self::map_runtime_error)?;

        self.record_audit(
            AuditEventType::ProcessTerminate,
            None,
            Some(args.process_id.clone()),
        )
        .await;

        output_json(&json!({ "stopped": true, "process_id": args.process_id }))
    }

    /// List running processes.
    #[tool(
        name = "process.list",
        input_schema = Arc::new(
            serde_json::from_value::<JsonObject>(
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "project_id": { "type": "string" }
                    },
                    "required": []
                })
            )
            .expect("invalid process.list input schema")
        )
    )]
    async fn process_list(&self, args: Parameters<JsonObject>) -> Result<CallToolResult, McpError> {
        let args = normalize_args("process.list", &args.0)?;
        let _args: ProcessListArgs =
            serde_json::from_value(serde_json::Value::Object(args))
                .map_err(|e| invalid(format!("failed to deserialize parameters: {e}")))?;

        let processes = self
            .process_service
            .list()
            .await
            .map_err(Self::map_runtime_error)?;

        self.record_audit(AuditEventType::ProcessList, None, None).await;

        let values: Vec<serde_json::Value> = processes
            .into_iter()
            .map(|p| {
                json!({
                    "process_id": p.id.to_string(),
                    "pid": p.os_pid,
                    "running": p.running,
                    "exit_code": p.exit_status.as_ref().and_then(|s| s.code),
                })
            })
            .collect();

        output_json(&json!({ "processes": values }))
    }

    /// Discover installed toolchains.
    #[tool(
        name = "process.discover_tools",
        input_schema = Arc::new(
            serde_json::from_value::<JsonObject>(
                serde_json::json!({ "type": "object", "properties": {}, "required": [] })
            )
            .expect("invalid process.discover_tools input schema")
        )
    )]
    async fn process_discover_tools(
        &self,
        _args: Parameters<JsonObject>,
    ) -> Result<CallToolResult, McpError> {
        let tools = vec![
            "cargo", "rustc", "rustup", "git", "node", "bun", "python", "python3",
            "py", "go", "dotnet", "cmake", "ninja", "java", "javac",
        ];
        output_json(&json!({ "tools": tools }))
    }

    /// Read a file's text content.
    #[tool(
        name = "workspace.read",
        input_schema = Arc::new(
            serde_json::from_value::<JsonObject>(
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string" },
                        "line_start": { "type": "integer" },
                        "line_end": { "type": "integer" },
                        "offset": { "type": "integer" },
                        "max_bytes": { "type": "integer" },
                        "media": { "type": "boolean" },
                        "head": { "type": "integer" },
                        "tail": { "type": "integer" },
                        "want_sha256": { "type": "boolean" }
                    },
                    "required": ["path"]
                })
            )
            .expect("invalid workspace.read input schema")
        )
    )]
    async fn workspace_read(&self, args: Parameters<JsonObject>) -> Result<CallToolResult, McpError> {
        self.read_impl("workspace.read", args.0).await
    }

    /// `workspace.read_file` — deprecated alias of `workspace.read`.
    #[tool(
        name = "workspace.read_file",
        input_schema = Arc::new(
            serde_json::from_value::<JsonObject>(
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string" },
                        "line_start": { "type": "integer" },
                        "line_end": { "type": "integer" }
                    },
                    "required": ["path"]
                })
            )
            .expect("invalid workspace.read_file input schema")
        )
    )]
    async fn workspace_read_file(&self, args: Parameters<JsonObject>) -> Result<CallToolResult, McpError> {
        self.read_impl("workspace.read_file", args.0).await
    }

    async fn read_impl(&self, tool: &str, args: JsonObject) -> Result<CallToolResult, McpError> {
        let args = normalize_args(tool, &args)?;
        let args: ReadArgs =
            serde_json::from_value(serde_json::Value::Object(args))
                .map_err(|e| invalid(format!("failed to deserialize parameters: {e}")))?;
        let (project_id, path) = self.resolve_user_path(&PathBuf::from(&args.path))?;
        let opts = ReadOptions {
            offset: args.offset,
            max_bytes: args.max_bytes,
            line_start: args.line_start,
            line_end: args.line_end,
            head: args.head,
            tail: args.tail,
            line_numbers: true,
            media: args.media.unwrap_or(false),
            want_sha256: args.want_sha256.unwrap_or(false),
        };
        match self
            .fs
            .read_text(project_id, &path, &opts)
            .await
            .map_err(Self::map_runtime_error)?
        {
            ReadOutcome::Text(t) => output_json(&json!({
                "content": t.content,
                "truncated": t.truncated,
                "size": t.size,
                "returned_bytes": t.returned_bytes,
            })),
            ReadOutcome::Media(m) => output_json(&json!({
                "mime": m.mime,
                "base64": m.base64,
                "size": m.size,
            })),
            ReadOutcome::Binary { size } => output_json(&json!({ "binary": true, "size": size })),
        }
    }

    /// Write (or append to) a file.
    #[tool(
        name = "workspace.write",
        input_schema = Arc::new(
            serde_json::from_value::<JsonObject>(
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string" },
                        "content": { "type": "string" },
                        "overwrite": { "type": "boolean" },
                        "append": { "type": "boolean" }
                    },
                    "required": ["path", "content"]
                })
            )
            .expect("invalid workspace.write input schema")
        )
    )]
    async fn workspace_write(&self, args: Parameters<JsonObject>) -> Result<CallToolResult, McpError> {
        self.write_impl("workspace.write", args.0).await
    }

    /// `workspace.write_file` — deprecated alias of `workspace.write`.
    #[tool(
        name = "workspace.write_file",
        input_schema = Arc::new(
            serde_json::from_value::<JsonObject>(
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string" },
                        "content": { "type": "string" },
                        "overwrite": { "type": "boolean" }
                    },
                    "required": ["path", "content"]
                })
            )
            .expect("invalid workspace.write_file input schema")
        )
    )]
    async fn workspace_write_file(&self, args: Parameters<JsonObject>) -> Result<CallToolResult, McpError> {
        self.write_impl("workspace.write_file", args.0).await
    }

    async fn write_impl(&self, tool: &str, args: JsonObject) -> Result<CallToolResult, McpError> {
        let args = normalize_args(tool, &args)?;
        let args: WriteArgs =
            serde_json::from_value(serde_json::Value::Object(args))
                .map_err(|e| invalid(format!("failed to deserialize parameters: {e}")))?;
        let (project_id, path) = self.resolve_user_path(&PathBuf::from(&args.path))?;

        // Approval gate: file writes require consent in restrictive profiles.
        self.enforce_tool(Capability::WorkspaceWrite, Some(&path.display().to_string()))
            .await?;

        let opts = WriteOptions {
            overwrite: args.overwrite.unwrap_or(false),
            append: args.append.unwrap_or(false),
            want_diff: false,
        };
        let outcome = self
            .fs
            .write_text(project_id, &path, &args.content, &opts)
            .await
            .map_err(Self::map_runtime_error)?;
        self.record_audit(
            AuditEventType::WorkspaceWrite,
            Some(project_id),
            Some(path.display().to_string()),
        )
        .await;
        output_json(&json!({ "bytes": outcome.bytes, "eol": outcome.eol, "diff": outcome.diff }))
    }

    /// Apply one or more text edits to a file (all-or-nothing).
    #[tool(
        name = "workspace.edit",
        input_schema = Arc::new(
            serde_json::from_value::<JsonObject>(
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string" },
                        "edits": { "type": "array" },
                        "old_text": { "type": "string" },
                        "new_text": { "type": "string" },
                        "expected_occurrences": { "type": "integer" },
                        "dry_run": { "type": "boolean" }
                    },
                    "required": ["path"]
                })
            )
            .expect("invalid workspace.edit input schema")
        )
    )]
    async fn workspace_edit(&self, args: Parameters<JsonObject>) -> Result<CallToolResult, McpError> {
        let args = normalize_args("workspace.edit", &args.0)?;
        let args: EditArgs =
            serde_json::from_value(serde_json::Value::Object(args))
                .map_err(|e| invalid(format!("failed to deserialize parameters: {e}")))?;
        let (project_id, path) = self.resolve_user_path(&PathBuf::from(&args.path))?;

        // Approval gate: file edits require consent in restrictive profiles.
        self.enforce_tool(Capability::WorkspaceWrite, Some(&path.display().to_string()))
            .await?;

        let dry_run = args.dry_run.unwrap_or(false);
        let edits: Vec<EditSpec> = args
            .into_specs()
            .map_err(|e| invalid(format!("failed to deserialize parameters: {e}")))?
            .into_iter()
            .map(|edit| EditSpec {
                old_text: edit.old_text,
                new_text: edit.new_text,
                expected_occurrences: edit.expected_occurrences,
            })
            .collect();
        let outcome = self
            .fs
            .edit_text(
                project_id,
                &path,
                &edits,
                &EditOptions { dry_run },
            )
            .await
            .map_err(Self::map_runtime_error)?;
        self.record_audit(
            AuditEventType::WorkspaceWrite,
            Some(project_id),
            Some(path.display().to_string()),
        )
        .await;
        output_json(&json!({
            "applied_edits": outcome.applied_edits,
            "diff": outcome.diff,
            "dry_run": outcome.dry_run,
        }))
    }

    /// Apply a unified/git diff to the workspace.
    #[tool(
        name = "workspace.patch",
        input_schema = Arc::new(
            serde_json::from_value::<JsonObject>(
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "diff": { "type": "string" },
                        "dry_run": { "type": "boolean" }
                    },
                    "required": ["diff"]
                })
            )
            .expect("invalid workspace.patch input schema")
        )
    )]
    async fn workspace_patch(&self, args: Parameters<JsonObject>) -> Result<CallToolResult, McpError> {
        let args = normalize_args("workspace.patch", &args.0)?;
        let args: PatchArgs =
            serde_json::from_value(serde_json::Value::Object(args))
                .map_err(|e| invalid(format!("failed to deserialize parameters: {e}")))?;

        // Approval gate: applying patches requires consent in restrictive profiles.
        self.enforce_tool(Capability::WorkspaceWrite, None).await?;

        // The patch engine validates each patched path against the root itself;
        // the project id is only needed to locate the root.
        let (project_id, _) = self.resolve_user_path(&PathBuf::new())?;
        let results = self
            .fs
            .apply_patch(project_id, &args.diff, args.dry_run.unwrap_or(false))
            .await
            .map_err(Self::map_runtime_error)?;
        self.record_audit(AuditEventType::WorkspaceWrite, Some(project_id), None)
            .await;
        let values: Vec<serde_json::Value> = results
            .into_iter()
            .map(|result| {
                json!({ "path": result.path, "created": result.created, "bytes": result.bytes })
            })
            .collect();
        output_json(&values)
    }

    /// Replace occurrences of `search` with `replacement` in a single file
    /// (implemented on top of `workspace.edit`; tree-wide replace is Phase 4).
    #[tool(
        name = "workspace.replace_text",
        input_schema = Arc::new(
            serde_json::from_value::<JsonObject>(
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string" },
                        "search": { "type": "string" },
                        "replacement": { "type": "string" },
                        "case_sensitive": { "type": "boolean" },
                        "max_matches": { "type": "integer" },
                        "dry_run": { "type": "boolean" }
                    },
                    "required": ["search", "replacement"]
                })
            )
            .expect("invalid workspace.replace_text input schema")
        )
    )]
    async fn workspace_replace_text(&self, args: Parameters<JsonObject>) -> Result<CallToolResult, McpError> {
        let args = normalize_args("workspace.replace_text", &args.0)?;
        let args: ReplaceTextArgs =
            serde_json::from_value(serde_json::Value::Object(args))
                .map_err(|e| invalid(format!("failed to deserialize parameters: {e}")))?;
        let path = match args.path {
            Some(path) => path,
            None => {
                return Err(invalid(
                    "workspace.replace_text requires a `path` argument; tree-wide replace is deferred to Phase 4",
                ))
            }
        };
        let (project_id, path) = self.resolve_user_path(&PathBuf::from(&path))?;

        // Approval gate: file writes require consent in restrictive profiles.
        self.enforce_tool(Capability::WorkspaceWrite, Some(&path.display().to_string()))
            .await?;

        let outcome = self
            .fs
            .replace_text(
                project_id,
                &path,
                &args.search,
                &args.replacement,
                args.max_matches,
                args.dry_run.unwrap_or(false),
            )
            .await
            .map_err(Self::map_runtime_error)?;
        self.record_audit(
            AuditEventType::WorkspaceWrite,
            Some(project_id),
            Some(path.display().to_string()),
        )
        .await;
        output_json(&json!({ "applied_edits": outcome.applied_edits, "dry_run": outcome.dry_run }))
    }

    /// Search file contents within a workspace root.
    #[tool(
        name = "workspace.search",
        input_schema = Arc::new(
            serde_json::from_value::<JsonObject>(
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string" },
                        "max_results": { "type": "integer" },
                        "is_regex": { "type": "boolean" },
                        "case_sensitive": { "type": "boolean" },
                        "include": { "type": "array", "items": { "type": "string" } },
                        "exclude": { "type": "array", "items": { "type": "string" } },
                        "context": { "type": "integer", "minimum": 0, "maximum": 5 }
                    },
                    "required": ["query"]
                })
            )
            .expect("invalid workspace.search input schema")
        )
    )]
    async fn workspace_search(&self, args: Parameters<JsonObject>) -> Result<CallToolResult, McpError> {
        let args = normalize_args("workspace.search", &args.0)?;
        let args: SearchArgs =
            serde_json::from_value(serde_json::Value::Object(args))
                .map_err(|e| invalid(format!("failed to deserialize parameters: {e}")))?;
        let (project_id, _) = self.resolve_user_path(&PathBuf::new())?;
        let opts = SearchOptions {
            query: args.query,
            is_regex: args.is_regex,
            case_sensitive: args.case_sensitive,
            include: args.include,
            exclude: args.exclude,
            context: args.context,
            max_results: args.max_results.min(5_000),
            files_only: false,
            include_hidden: false,
            include_ignored: false,
            max_file_size: 1_000_000,
            sensitive: Some(self.fs.sensitive()),
        };
        let report = self
            .fs
            .search(project_id, None, &opts)
            .await
            .map_err(Self::map_runtime_error)?;
        let matches: Vec<serde_json::Value> = report
            .matches
            .into_iter()
            .map(|m| {
                json!({
                    "path": m.file,
                    "line": m.line,
                    "column": m.column,
                    "text": m.text,
                    "before": m.before,
                    "after": m.after,
                })
            })
            .collect();
        output_json(&json!({
            "matches": matches,
            "files_matched": report.files_matched,
            "files_scanned": report.files_scanned,
            "skipped_binary": report.skipped_binary,
            "skipped_too_large": report.skipped_too_large,
            "skipped_inaccessible": report.skipped_inaccessible,
            "truncated": report.truncated,
        }))
    }

    /// Find files by name pattern.
    #[tool(
        name = "workspace.find_files",
        input_schema = Arc::new(
            serde_json::from_value::<JsonObject>(
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string" },
                        "pattern": { "type": "string" },
                        "max_results": { "type": "integer" }
                    },
                    "required": ["pattern"]
                })
            )
            .expect("invalid workspace.find_files input schema")
        )
    )]
    async fn workspace_find_files(&self, args: Parameters<JsonObject>) -> Result<CallToolResult, McpError> {
        let args = normalize_args("workspace.find_files", &args.0)?;
        let args: FindFilesArgs =
            serde_json::from_value(serde_json::Value::Object(args))
                .map_err(|e| invalid(format!("failed to deserialize parameters: {e}")))?;
        let (project_id, path) = match args.path {
            Some(p) => self.resolve_user_path(&PathBuf::from(&p))?,
            None => self.resolve_user_path(&PathBuf::new())?,
        };
        let opts = FindOptions {
            pattern: args.pattern,
            max_results: args.max_results,
            want_dirs: false,
            include_hidden: false,
            include_ignored: false,
        };
        let report = self
            .fs
            .find(project_id, Some(&path), &opts)
            .await
            .map_err(Self::map_runtime_error)?;
        output_json(&report.paths)
    }

    /// List entries of a directory (shallow, depth-bounded).
    #[tool(
        name = "workspace.list",
        input_schema = Arc::new(
            serde_json::from_value::<JsonObject>(
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string" },
                        "depth": { "type": "integer" },
                        "max_entries": { "type": "integer" },
                        "include_hidden": { "type": "boolean" },
                        "sort_by": { "type": "string" }
                    },
                    "required": []
                })
            )
            .expect("invalid workspace.list input schema")
        )
    )]
    async fn workspace_list(&self, args: Parameters<JsonObject>) -> Result<CallToolResult, McpError> {
        let args = normalize_args("workspace.list", &args.0)?;
        let args: ListArgs =
            serde_json::from_value(serde_json::Value::Object(args))
                .map_err(|e| invalid(format!("failed to deserialize parameters: {e}")))?;
        let (project_id, path) = match args.path {
            Some(p) => self.resolve_user_path(&PathBuf::from(&p))?,
            None => self.resolve_user_path(&PathBuf::new())?,
        };
        let _ = project_id;
        let (entries, hidden_count) =
            walk_shallow(&path, args.depth, args.include_hidden, args.sort_by.as_deref().unwrap_or("name"));
        let max_entries = args.max_entries.min(20_000);
        let total = entries.len();
        let entries: Vec<_> = entries.into_iter().take(max_entries).collect();
        let mut value = json!({ "entries": entries, "total": total });
        if hidden_count > 0 && !args.include_hidden {
            value
                .as_object_mut()
                .expect("list output is an object")
                .insert(
                    "advice".to_string(),
                    json!(format!(
                        "// hid {hidden_count} entries (hidden or ignored); pass include_hidden: true to see hidden entries."
                    )),
                );
        }
        output_json(&value)
    }

    /// Walk a directory tree and return nested `{name, type, children?}` nodes.
    #[tool(
        name = "workspace.tree",
        input_schema = Arc::new(
            serde_json::from_value::<JsonObject>(
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string" },
                        "depth": { "type": "integer" },
                        "exclude_patterns": { "type": "array", "items": { "type": "string" } }
                    },
                    "required": ["path"]
                })
            )
            .expect("invalid workspace.tree input schema")
        )
    )]
    async fn workspace_tree(&self, args: Parameters<JsonObject>) -> Result<CallToolResult, McpError> {
        let args = normalize_args("workspace.tree", &args.0)?;
        let args: TreeArgs =
            serde_json::from_value(serde_json::Value::Object(args))
                .map_err(|e| invalid(format!("failed to deserialize parameters: {e}")))?;
        let (project_id, path) = self.resolve_user_path(&PathBuf::from(&args.path))?;
        let _ = project_id;
        let nodes = match walk_tree(&path, args.depth, &args.exclude_patterns) {
            Ok(nodes) => nodes,
            Err(TreeBudgetExceeded) => {
                return Err(invalid(format!(
                    "Tree stopped after 100000 entries under {}. Narrow the path or add exclude_patterns.",
                    path.display()
                )))
            }
        };
        output_json(&nodes)
    }

    /// Return file metadata for a path.
    #[tool(
        name = "workspace.stat",
        input_schema = Arc::new(
            serde_json::from_value::<JsonObject>(
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string" }
                    },
                    "required": ["path"]
                })
            )
            .expect("invalid workspace.stat input schema")
        )
    )]
    async fn workspace_stat(&self, args: Parameters<JsonObject>) -> Result<CallToolResult, McpError> {
        let args = normalize_args("workspace.stat", &args.0)?;
        let args: StatArgs =
            serde_json::from_value(serde_json::Value::Object(args))
                .map_err(|e| invalid(format!("failed to deserialize parameters: {e}")))?;
        let (project_id, path) = self.resolve_user_path(&PathBuf::from(&args.path))?;
        let entry = self
            .fs
            .stat(project_id, path)
            .await
            .map_err(Self::map_runtime_error)?;
        output_json(&json!({
            "name": entry.name,
            "type": entry.file_type,
            "size": entry.size,
            "modified": entry.modified,
        }))
    }

    /// Create a directory.
    #[tool(
        name = "workspace.mkdir",
        input_schema = Arc::new(
            serde_json::from_value::<JsonObject>(
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string" }
                    },
                    "required": ["path"]
                })
            )
            .expect("invalid workspace.mkdir input schema")
        )
    )]
    async fn workspace_mkdir(&self, args: Parameters<JsonObject>) -> Result<CallToolResult, McpError> {
        let args = normalize_args("workspace.mkdir", &args.0)?;
        let args: MkdirArgs =
            serde_json::from_value(serde_json::Value::Object(args))
                .map_err(|e| invalid(format!("failed to deserialize parameters: {e}")))?;
        let (project_id, path) = self.resolve_user_path(&PathBuf::from(&args.path))?;

        // Approval gate: directory creation requires consent in restrictive profiles.
        self.enforce_tool(Capability::WorkspaceWrite, Some(&path.display().to_string()))
            .await?;

        self.fs
            .create_directory(project_id, path)
            .await
            .map_err(Self::map_runtime_error)?;
        self.record_audit(
            AuditEventType::WorkspaceWrite,
            Some(project_id),
            Some(PathBuf::from(&args.path).display().to_string()),
        )
        .await;
        output_json(&json!({ "created": args.path }))
    }

    /// Move a source path to a destination path.
    #[tool(
        name = "workspace.move",
        input_schema = Arc::new(
            serde_json::from_value::<JsonObject>(
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "source": { "type": "string" },
                        "destination": { "type": "string" }
                    },
                    "required": ["source", "destination"]
                })
            )
            .expect("invalid workspace.move input schema")
        )
    )]
    async fn workspace_move(&self, args: Parameters<JsonObject>) -> Result<CallToolResult, McpError> {
        let args = normalize_args("workspace.move", &args.0)?;
        let args: MoveArgs =
            serde_json::from_value(serde_json::Value::Object(args))
                .map_err(|e| invalid(format!("failed to deserialize parameters: {e}")))?;
        let (project_id, source) = self.resolve_user_path(&PathBuf::from(&args.source))?;
        let (_project_id, destination) = self.resolve_user_path(&PathBuf::from(&args.destination))?;
        let _ = _project_id;

        // Approval gate: moving files requires consent in restrictive profiles.
        self.enforce_tool(Capability::WorkspaceWrite, Some(&source.display().to_string()))
            .await?;

        let dest = self
            .fs
            .move_entry_checked(project_id, &source, &destination)
            .await
            .map_err(Self::map_runtime_error)?;
        self.record_audit(
            AuditEventType::WorkspaceMove,
            Some(project_id),
            Some(dest.display().to_string()),
        )
        .await;
        output_json(&json!({ "destination": dest.display().to_string() }))
    }

    /// Delete one or more paths.
    #[tool(
        name = "workspace.delete",
        input_schema = Arc::new(
            serde_json::from_value::<JsonObject>(
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "paths": { "type": "array", "items": { "type": "string" } },
                        "recursive": { "type": "boolean" }
                    },
                    "required": ["paths"]
                })
            )
            .expect("invalid workspace.delete input schema")
        )
    )]
    async fn workspace_delete(&self, args: Parameters<JsonObject>) -> Result<CallToolResult, McpError> {
        let args = normalize_args("workspace.delete", &args.0)?;
        let args: DeleteArgs =
            serde_json::from_value(serde_json::Value::Object(args))
                .map_err(|e| invalid(format!("failed to deserialize parameters: {e}")))?;
        let paths: Vec<PathBuf> = args
            .paths
            .into_paths()
            .into_iter()
            .map(PathBuf::from)
            .collect();
        let first = paths.first().cloned();
        let (project_id, _) = match &first {
            Some(path) => self.resolve_user_path(path)?,
            None => {
                return Err(invalid("workspace.delete requires at least one path"))
            }
        };

        // Approval gate: deleting files requires consent in restrictive profiles.
        if let Some(path) = &first {
            self.enforce_tool(Capability::WorkspaceWrite, Some(&path.display().to_string()))
                .await?;
        }

        let deleted = self
            .fs
            .delete_entries(project_id, &paths, args.recursive.unwrap_or(false))
            .await
            .map_err(Self::map_runtime_error)?;
        self.record_audit(
            AuditEventType::WorkspaceDelete,
            Some(project_id),
            Some(format!("{} paths", paths.len())),
        )
        .await;
        output_json(&json!({
            "deleted": deleted
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
        }))
    }

    /// List the configured workspace roots (and read-only roots).
    #[tool(
        name = "workspace.allowed_roots",
        input_schema = Arc::new(
            serde_json::from_value::<JsonObject>(
                serde_json::json!({ "type": "object", "properties": {}, "required": [] })
            )
            .expect("invalid workspace.allowed_roots input schema")
        )
    )]
    async fn workspace_allowed_roots(&self, _args: Parameters<JsonObject>) -> Result<CallToolResult, McpError> {
        let _args: AllowedRootsArgs =
            serde_json::from_value(serde_json::Value::Object(_args.0))
                .map_err(|e| invalid(format!("failed to deserialize parameters: {e}")))?;
        output_json(&json!({
            "roots": self
                .roots
                .iter()
                .map(|(_, root)| root.display().to_string())
                .collect::<Vec<_>>(),
            "read_only_roots": self
                .read_only_roots
                .iter()
                .map(|root| root.display().to_string())
                .collect::<Vec<_>>(),
        }))
    }

    /// Request approval for a capability+resource. Returns an `approval_id`
    /// that can be used with `approval.approve` or `yl approval approve`.
    #[tool(
        name = "approval.request",
        input_schema = Arc::new(
            serde_json::from_value::<JsonObject>(
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "capability": { "type": "string" },
                        "resource": { "type": "string" },
                        "justification": { "type": "string" }
                    },
                    "required": ["capability"]
                })
            )
            .expect("invalid approval.request input schema")
        )
    )]
    async fn approval_request(&self, args: Parameters<JsonObject>) -> Result<CallToolResult, McpError> {
        let args = normalize_args("approval.request", &args.0)?;
        let capability_str: String = args
            .get("capability")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| invalid("approval.request requires a `capability` argument"))?;
        let capability = Capability::from_str(&capability_str)
            .map_err(|e| invalid(format!("unknown capability: {e}")))?;
        let resource = args.get("resource").and_then(|v| v.as_str()).map(|s| s.to_string());
        let justification = args
            .get("justification")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("Approval requested for {capability}"));

        let project_id = self
            .roots
            .first()
            .map(|(id, _)| *id)
            .ok_or_else(|| invalid("no workspace root configured"))?;

        let approval_id = self
            .approval_broker
            .request(self.agent_id, project_id, capability, resource, justification)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        output_json(&json!({
            "approval_id": approval_id.to_string(),
            "state": "pending",
            "expires_in_seconds": 1800,
        }))
    }

    /// Approve a pending approval by id, allowing the blocked tool call to proceed on retry.
    #[tool(
        name = "approval.approve",
        input_schema = Arc::new(
            serde_json::from_value::<JsonObject>(
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "approval_id": { "type": "string" }
                    },
                    "required": ["approval_id"]
                })
            )
            .expect("invalid approval.approve input schema")
        )
    )]
    async fn approval_approve(&self, args: Parameters<JsonObject>) -> Result<CallToolResult, McpError> {
        let args = normalize_args("approval.approve", &args.0)?;
        let approval_id_str: String = args
            .get("approval_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| invalid("approval.approve requires an `approval_id` argument"))?;
        let approval_id = ApprovalId(Uuid::parse_str(&approval_id_str)
            .map_err(|e| invalid(format!("invalid approval_id: {e}")))?);

        self.approval_broker.approve(approval_id)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        output_json(&json!({ "approved": true, "approval_id": approval_id_str }))
    }

    /// Reject a pending approval by id, with an optional reason.
    #[tool(
        name = "approval.reject",
        input_schema = Arc::new(
            serde_json::from_value::<JsonObject>(
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "approval_id": { "type": "string" },
                        "reason": { "type": "string" }
                    },
                    "required": ["approval_id"]
                })
            )
            .expect("invalid approval.reject input schema")
        )
    )]
    async fn approval_reject(&self, args: Parameters<JsonObject>) -> Result<CallToolResult, McpError> {
        let args = normalize_args("approval.reject", &args.0)?;
        let approval_id_str: String = args
            .get("approval_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| invalid("approval.reject requires an `approval_id` argument"))?;
        let reason = args
            .get("reason")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "rejected".to_string());
        let approval_id = ApprovalId(Uuid::parse_str(&approval_id_str)
            .map_err(|e| invalid(format!("invalid approval_id: {e}")))?);

        self.approval_broker.reject(approval_id, reason.clone())
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        output_json(&json!({ "rejected": true, "approval_id": approval_id_str, "reason": reason }))
    }

    /// List pending (not-yet-decided) approvals.
    #[tool(
        name = "approval.list",
        input_schema = Arc::new(
            serde_json::from_value::<JsonObject>(
                serde_json::json!({ "type": "object", "properties": {}, "required": [] })
            )
            .expect("invalid approval.list input schema")
        )
    )]
    async fn approval_list(&self, _args: Parameters<JsonObject>) -> Result<CallToolResult, McpError> {
        let pending = self.approval_broker.list_pending().await;
        let items: Vec<serde_json::Value> = pending
            .into_iter()
            .map(|r| {
                json!({
                    "approval_id": r.id.to_string(),
                    "capability": r.capability.as_str(),
                    "resource": r.resource,
                    "justification": r.justification,
                    "requested_at": r.created_at.to_rfc3339(),
                    "expires_at": r.expires_at.map(|t| t.to_rfc3339()),
                })
            })
            .collect();
        output_json(&json!({ "pending": items, "count": items.len() }))
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
    instructions = "YL Agent Runtime - Portable agent execution runtime. Use workspace.read (and the other workspace.* tools) against files under the directories passed with --root; the server refuses any path outside the configured roots and blocks sensitive files such as .env."
)]
impl ServerHandler for McpServer {
    // Intentionally empty: `#[tool_handler]` generates the required
    // `ServerHandler` methods (call_tool, list_tools, get_tool, get_info).
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::ContentBlock;
    use runtime_audit::AuditServiceImpl;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn obj(value: serde_json::Value) -> JsonObject {
        value.as_object().expect("test fixture is a JSON object").clone()
    }

    async fn fixture() -> (McpServer, TempDir, Arc<AuditServiceImpl>) {
        let dir = TempDir::new().expect("temp dir");
        std::fs::write(dir.path().join("a.txt"), b"hello world\n").expect("write fixture");
        let fs = Arc::new(WorkspaceServiceImpl::new());
        let id = fs
            .register(dir.path().to_path_buf(), ExecutionProfile::Development)
            .await
            .expect("register workspace");
        let audit = Arc::new(AuditServiceImpl::new());
        let process_service: Arc<dyn ProcessServiceOps> =
            Arc::new(runtime_process::ProcessService::new());
        let policy_engine: Arc<dyn PolicyEngine> =
            Arc::new(runtime_policy::PolicyEngineImpl::new());
        let approval_broker: Arc<dyn ApprovalBroker> =
            Arc::new(runtime_approval::ApprovalBrokerImpl::new());
        let server = McpServer::new_for_fs(
            fs,
            vec![(id, dir.path().to_path_buf())],
            audit.clone(),
            vec![],
            process_service,
            policy_engine,
            approval_broker,
            false,
        ).await;
        (server, dir, audit)
    }

    fn content_text(result: &CallToolResult) -> String {
        match &result.content[0] {
            ContentBlock::Text(block) => block.text.clone(),
            other => panic!("expected text content block, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn read_tool_returns_file_content_json() {
        let (server, _dir, _audit) = fixture().await;
        let result = server
            .workspace_read(Parameters(obj(json!({"path": "a.txt"}))))
            .await
            .unwrap();
        assert!(content_text(&result).contains("hello"));
    }

    #[tokio::test]
    async fn edit_tool_reports_diff_and_writes() {
        let (server, _dir, _audit) = fixture().await;
        let result = server
            .workspace_edit(Parameters(obj(json!({
                "path": "a.txt",
                "edits": [{"old_text": "hello", "new_text": "hola"}]
            }))))
            .await
            .unwrap();
        assert!(content_text(&result).contains("\"applied_edits\":1"));
        let after = server
            .workspace_read(Parameters(obj(json!({"path": "a.txt"}))))
            .await
            .unwrap();
        assert!(content_text(&after).contains("hola"));
    }

    #[tokio::test]
    async fn escape_attempt_is_invalid_params() {
        let (server, _dir, _audit) = fixture().await;
        let err = server
            .workspace_read(Parameters(obj(json!({"path": "../../etc/passwd"}))))
            .await
            .unwrap_err();
        assert!(
            err.message.contains("allowed"),
            "unexpected message: {}",
            err.message
        );
    }

    #[tokio::test]
    async fn sensitive_write_is_refused_with_pattern() {
        let (server, _dir, _audit) = fixture().await;
        let err = server
            .workspace_write(Parameters(obj(json!({
                "path": ".env",
                "content": "secrets",
                "overwrite": true
            }))))
            .await
            .unwrap_err();
        assert!(
            err.message.contains("Sensitive file blocked"),
            "unexpected message: {}",
            err.message
        );
    }

    #[tokio::test]
    async fn alias_file_key_accepted_on_read() {
        let (server, _dir, _audit) = fixture().await;
        let result = server
            .workspace_read(Parameters(obj(json!({"file": "a.txt"}))))
            .await
            .unwrap();
        assert!(content_text(&result).contains("hello"));
    }

    #[tokio::test]
    async fn prd_alias_tools_registered_and_callable() {
        let (server, _dir, _audit) = fixture().await;
        let result = server
            .workspace_read_file(Parameters(obj(json!({"path": "a.txt"}))))
            .await
            .unwrap();
        assert!(content_text(&result).contains("hello"));
    }

    /// Regression: an MCP client sent `edits: [{oldText, newText}]` and got
    /// `missing field old_text` because alias rewriting only touched the
    /// top-level argument map, never the nested edit objects.
    #[tokio::test]
    async fn edit_accepts_camel_case_inside_edits_array() {
        let (server, _dir, _audit) = fixture().await;
        server
            .workspace_edit(Parameters(obj(json!({
                "path": "a.txt",
                "edits": [{ "oldText": "hello", "newText": "hola" }],
            }))))
            .await
            .unwrap();
        let read = server
            .workspace_read(Parameters(obj(json!({"path": "a.txt"}))))
            .await
            .unwrap();
        assert!(content_text(&read).contains("hola"));
    }

    /// Regression: the flat single-edit form `{path, old_text, new_text}`
    /// (what most agents try first) must work, not demand an array.
    #[tokio::test]
    async fn edit_accepts_flat_old_text_new_text() {
        let (server, _dir, _audit) = fixture().await;
        server
            .workspace_edit(Parameters(obj(json!({
                "path": "a.txt",
                "old_text": "hello",
                "new_text": "bonjour",
            }))))
            .await
            .unwrap();
        let read = server
            .workspace_read(Parameters(obj(json!({"path": "a.txt"}))))
            .await
            .unwrap();
        assert!(content_text(&read).contains("bonjour"));
    }

    /// A call with no edit content at all must fail with a message that says
    /// what to send, not a raw serde error.
    #[tokio::test]
    async fn edit_without_edits_explains_the_expected_shape() {
        let (server, _dir, _audit) = fixture().await;
        let err = server
            .workspace_edit(Parameters(obj(json!({"path": "a.txt"}))))
            .await
            .unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("old_text") && message.contains("edits"),
            "unhelpful error: {message}"
        );
    }

    /// `runtime.status` and `runtime.capabilities` used to be advertised by
    /// `tools/list` and then fail with "not available in filesystem-only mode".
    #[tokio::test]
    async fn runtime_tools_answer_with_real_data() {
        let (server, _dir, _audit) = fixture().await;

        let status = server.runtime_status().await.unwrap();
        let status_text = content_text(&status);
        assert!(status_text.contains("\"platform\""));
        assert!(status_text.contains("\"tools_registered\""));

        let caps = server.runtime_capabilities().await.unwrap();
        let caps_text = content_text(&caps);
        assert!(
            caps_text.contains("executable_allowlist"),
            "capabilities must expose the allowlist: {caps_text}"
        );
    }

    #[tokio::test]
    async fn mutating_calls_write_audit_events() {
        let (server, _dir, audit) = fixture().await;
        server
            .workspace_write(Parameters(obj(json!({
                "path": "notes.txt",
                "content": "hi",
                "overwrite": true
            }))))
            .await
            .unwrap();
        let count = audit.event_count().await;
        assert!(count > 0, "expected at least one audit event, got {count}");
    }

    #[tokio::test]
    async fn allowed_roots_returns_configured_roots() {
        let (server, _dir, _audit) = fixture().await;
        let result = server
            .workspace_allowed_roots(Parameters(obj(json!({}))))
            .await
            .unwrap();
        assert!(content_text(&result).contains("\"roots\""));
    }

    #[tokio::test]
    async fn allowed_roots_returns_configured_read_only_roots() {
        let fs = Arc::new(WorkspaceServiceImpl::new());
        let dir = tempfile::TempDir::new().expect("temp dir");
        let id = fs
            .register(dir.path().to_path_buf(), ExecutionProfile::Development)
            .await
            .expect("register workspace");
        let audit = Arc::new(AuditServiceImpl::new());
        let process_service: Arc<dyn ProcessServiceOps> =
            Arc::new(runtime_process::ProcessService::new());
        let policy_engine: Arc<dyn PolicyEngine> =
            Arc::new(runtime_policy::PolicyEngineImpl::new());
        let approval_broker: Arc<dyn ApprovalBroker> =
            Arc::new(runtime_approval::ApprovalBrokerImpl::new());
        let server = McpServer::new_for_fs(
            fs,
            vec![(id, dir.path().to_path_buf())],
            audit,
            vec![dir.path().to_path_buf()],
            process_service,
            policy_engine,
            approval_broker,
            false,
        ).await;
        let result = server
            .workspace_allowed_roots(Parameters(obj(json!({}))))
            .await
            .unwrap();
        let text = content_text(&result);
        assert!(text.contains("\"read_only_roots\""), "unexpected: {text}");
    }

    #[tokio::test]
    async fn read_head_is_plumbed_from_args() {
        let (server, _dir, _audit) = fixture().await;
        server
            .workspace_write(Parameters(obj(json!({
                "path": "lines.txt",
                "content": "one\nneedle two\nthree\n",
                "overwrite": true
            }))))
            .await
            .unwrap();
        let result = server
            .workspace_read(Parameters(obj(json!({
                "path": "lines.txt",
                "head": 1
            }))))
            .await
            .unwrap();
        let text = content_text(&result);
        assert!(text.contains("one"), "expected first line, got: {text}");
        assert!(
            !text.contains("three"),
            "head must limit the read window, got: {text}"
        );
    }

    #[tokio::test]
    async fn replace_text_default_max_matches_replaces_all_occurrences() {
        let (server, _dir, _audit) = fixture().await;
        server
            .workspace_write(Parameters(obj(json!({
                "path": "multi.txt",
                "content": "alpha\nbeta\nalpha\n",
                "overwrite": true
            }))))
            .await
            .unwrap();

        // Default max_matches (100) must behave as "replace up to all N".
        let result = server
            .workspace_replace_text(Parameters(obj(json!({
                "path": "multi.txt",
                "search": "alpha",
                "replacement": "ALPHA"
            }))))
            .await
            .unwrap();
        assert!(content_text(&result).contains("\"applied_edits\":1"));

        let after = server
            .workspace_read(Parameters(obj(json!({"path": "multi.txt"}))))
            .await
            .unwrap();
        let text = content_text(&after);
        assert!(text.contains("ALPHA"), "expected replacement, got: {text}");
        assert!(
            !text.contains("alpha"),
            "both occurrences should have been replaced, got: {text}"
        );
    }

    #[tokio::test]
    async fn replace_text_single_occurrence_still_replaces_one() {
        let (server, _dir, _audit) = fixture().await;
        server
            .workspace_write(Parameters(obj(json!({
                "path": "single.txt",
                "content": "only needle here\n",
                "overwrite": true
            }))))
            .await
            .unwrap();

        let result = server
            .workspace_replace_text(Parameters(obj(json!({
                "path": "single.txt",
                "search": "needle",
                "replacement": "NEEDLE"
            }))))
            .await
            .unwrap();
        assert!(content_text(&result).contains("\"applied_edits\":1"));

        let after = server
            .workspace_read(Parameters(obj(json!({"path": "single.txt"}))))
            .await
            .unwrap();
        let text = content_text(&after);
        assert!(text.contains("NEEDLE"), "expected replacement, got: {text}");
    }

    #[tokio::test]
    async fn search_context_is_accepted_and_honored() {
        let (server, _dir, _audit) = fixture().await;
        server
            .workspace_write(Parameters(obj(json!({
                "path": "ctx.txt",
                "content": "alpha\nneedle here\ngamma\n",
                "overwrite": true
            }))))
            .await
            .unwrap();

        let result = server
            .workspace_search(Parameters(obj(json!({ "query": "needle", "context": 1 }))))
            .await
            .unwrap();
        let text = content_text(&result);
        assert!(
            text.contains("\"before\"") && text.contains("\"after\""),
            "context must be plumbed into match before/after, got: {text}"
        );
        assert!(
            text.contains("alpha") && text.contains("gamma"),
            "context lines should be returned around the match, got: {text}"
        );
    }

    #[tokio::test]
    async fn list_tool_returns_directory_entries() {
        let (server, _dir, _audit) = fixture().await;
        let result = server
            .workspace_list(Parameters(obj(json!({}))))
            .await
            .unwrap();
        assert!(content_text(&result).contains("a.txt"));
    }

    #[tokio::test]
    async fn zero_roots_rejected() {
        let fs = Arc::new(WorkspaceServiceImpl::new());
        let audit = Arc::new(AuditServiceImpl::new());
        let process_service: Arc<dyn ProcessServiceOps> =
            Arc::new(runtime_process::ProcessService::new());
        let policy_engine: Arc<dyn PolicyEngine> =
            Arc::new(runtime_policy::PolicyEngineImpl::new());
        let approval_broker: Arc<dyn ApprovalBroker> =
            Arc::new(runtime_approval::ApprovalBrokerImpl::new());
        let server = McpServer::new_for_fs(
            fs,
            vec![],
            audit,
            vec![],
            process_service,
            policy_engine,
            approval_broker,
            false,
        ).await;
        let err = server
            .workspace_read(Parameters(obj(json!({"path": "a.txt"}))))
            .await
            .unwrap_err();
        assert!(
            err.message.contains("No workspace roots configured"),
            "unexpected message: {}",
            err.message
        );
    }
}
