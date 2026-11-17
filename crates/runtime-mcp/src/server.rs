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
use runtime_core::audit::{AuditEvent, AuditEventType};
use runtime_core::error::Error;
use runtime_core::traits::{CapabilityGrant, WorkspaceService};
use runtime_core::types::*;
use runtime_workspace::WorkspaceServiceImpl;
use runtime_workspace::files::edit::{EditOptions, EditSpec};
use runtime_workspace::files::read::{ReadOptions, ReadOutcome};
use runtime_workspace::files::write::WriteOptions;
use runtime_workspace::search::{FindOptions, SearchOptions};
use crate::args::normalize_args;
use crate::tools_fs::{
    AllowedRootsArgs, DeleteArgs, EditArgs, FindFilesArgs, invalid, ListArgs,
    MkdirArgs, MoveArgs, output_json, PatchArgs, ProcessExecArgs, ReadArgs, ReplaceTextArgs,
    resolve_project, SearchArgs, StatArgs, TreeArgs, TreeBudgetExceeded, walk_shallow, walk_tree,
    WriteArgs,
};
use serde_json::json;
use std::path::PathBuf;
use std::result::Result;
use std::sync::Arc;

/// MCP server for YL Agent Runtime
pub struct McpServer {
    runtime: Arc<dyn RuntimeService + Send + Sync>,
    fs: Arc<WorkspaceServiceImpl>,
    roots: Vec<(ProjectId, PathBuf)>,       // ordered; roots[0] is primary for relative paths
    read_only_roots: Vec<PathBuf>,
    audit: Arc<dyn runtime_audit::AuditService>,
    principal_agent: String,                // "mcp-local" (design decision 4)
    session_id: SessionId,                  // per-process synthetic session
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

/// Stub runtime service used when the server is built with `new_for_fs`
/// (filesystem-only mode): no `RuntimeService` is supplied by the Task 10
/// wiring, so the `runtime.*`/`process.exec` tools are registered but report
/// a clear error instead of failing open.
struct FsOnlyRuntime;

#[async_trait::async_trait]
impl RuntimeService for FsOnlyRuntime {
    async fn get_status(&self) -> runtime_core::error::Result<RuntimeStatus> {
        Err(Error::Internal(
            "runtime status is not available in filesystem-only MCP mode".to_string(),
        ))
    }

    async fn get_capabilities(&self) -> runtime_core::error::Result<Vec<CapabilityGrant>> {
        Err(Error::Internal(
            "runtime capabilities are not available in filesystem-only MCP mode".to_string(),
        ))
    }

    async fn list_workspaces(&self) -> runtime_core::error::Result<Vec<String>> {
        Err(Error::Internal(
            "workspace listing is not available in filesystem-only MCP mode".to_string(),
        ))
    }

    async fn execute_command(
        &self,
        _command: String,
        _args: Vec<String>,
    ) -> runtime_core::error::Result<CommandResult> {
        Err(Error::Internal(
            "process execution is not available in filesystem-only MCP mode".to_string(),
        ))
    }
}

impl McpServer {
    pub fn new_for_fs(
        fs: Arc<WorkspaceServiceImpl>,
        roots: Vec<(ProjectId, PathBuf)>,
        audit: Arc<dyn AuditService>,
        read_only_roots: Vec<PathBuf>,
    ) -> Self {
        Self {
            runtime: Arc::new(FsOnlyRuntime),
            fs,
            roots,
            read_only_roots,
            audit,
            principal_agent: "mcp-local".to_string(),
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
            | Error::WorkspaceNotFound(msg) => invalid(msg),
            Error::Io(e) => invalid(format!("IO error: {e}")),
            other => McpError::internal_error(other.to_string(), None),
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
        let status = self
            .runtime
            .get_status()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        output_json(&status)
    }

    /// Report available backend capabilities.
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
        let caps = self
            .runtime
            .get_capabilities()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        output_json(&caps)
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
        let result = self
            .runtime
            .execute_command(args.command, args.args.unwrap_or_default())
            .await
            .map_err(Self::map_runtime_error)?;
        output_json(&result)
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
                        "dry_run": { "type": "boolean" }
                    },
                    "required": ["path", "edits"]
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
        let edits: Vec<EditSpec> = args
            .edits
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
                &EditOptions { dry_run: args.dry_run.unwrap_or(false) },
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
        let (project_id, _) = match first {
            Some(path) => self.resolve_user_path(&path)?,
            None => {
                return Err(invalid("workspace.delete requires at least one path"))
            }
        };
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
        let server = McpServer::new_for_fs(
            fs,
            vec![(id, dir.path().to_path_buf())],
            audit.clone(),
            vec![],
        );
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
        let server = McpServer::new_for_fs(
            fs,
            vec![(id, dir.path().to_path_buf())],
            audit,
            vec![dir.path().to_path_buf()],
        );
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
        let server = McpServer::new_for_fs(fs, vec![], audit, vec![]);
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
