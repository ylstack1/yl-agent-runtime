//! CLI command implementations

use anyhow::Result;
use runtime_audit::{AuditService, AuditServiceImpl};
use runtime_config::Config;
use runtime_core::traits::ExecutionRequest;
use runtime_core::types::*;
use runtime_process::{ProcessService, ProcessServiceOps};
use runtime_toolchain::ToolchainDiscovery;
use runtime_workspace::{SensitiveMatcher, WorkspaceService, WorkspaceServiceImpl};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::info;
use uuid::Uuid;

pub async fn start_daemon(config_path: &str) {
    info!("Starting daemon with config: {}", config_path);
    println!("YL Agent Runtime daemon starting...");
    println!("Config: {}", config_path);
    // Would load config and start daemon
}

pub async fn show_status() {
    let config = Config::load_from_file(&PathBuf::from("./config/runtime.toml"))
        .unwrap_or_else(|_| Config::default());

    println!("YL Agent Runtime Status");
    println!("========================");
    println!("Version: {}", env!("CARGO_PKG_VERSION"));
    println!("Platform: {}", std::env::consts::OS);
    println!("Architecture: {}", std::env::consts::ARCH);
    println!("Config path: ./config/runtime.toml");
    println!("Data dir: {}", config.data_dir.display());
    println!("Config dir: {}", config.config_dir.display());
    println!("Log dir: {}", config.log_dir.display());
    println!("Workspace roots: {:?}", config.workspace.roots);
    println!("Read-only roots: {:?}", config.workspace.read_only_roots);
}

pub async fn discover_tools() {
    println!("Discovering installed toolchains...");
    let discovery = ToolchainDiscovery::new();
    match discovery.discover_all() {
        Ok(toolchains) if toolchains.is_empty() => {
            println!("  (none)");
        }
        Ok(toolchains) => {
            for toolchain in toolchains {
                println!(
                    "  {}: {} @ {} ({:?}, source: {:?})",
                    toolchain.name,
                    toolchain.version,
                    toolchain.path.display(),
                    toolchain.architecture,
                    toolchain.detection_source,
                );
            }
        }
        Err(err) => {
            println!("  discovery error: {err}");
        }
    }
}

pub async fn pair_device(device_name: Option<&str>) {
    let name = device_name.unwrap_or("Unknown Device");
    println!("Pairing device: {}", name);
    // Would use IdentityService
    let code = "123456"; // Would generate random code
    println!("Pairing code: {}", code);
    println!("Please approve this device on the host.");
}

pub async fn list_devices() {
    println!("Registered devices:");
    println!("  (none)");
}

pub async fn revoke_device(device_id: &str) {
    println!("Revoking device: {}", device_id);
    // Would use IdentityService
}

pub async fn register_workspace(path: &str) {
    println!("Registering workspace: {}", path);
    // Would use WorkspaceService
}

/// Execute a command in a workspace via the process service.
pub async fn exec_command(
    project: &str,
    program: &str,
    args: Vec<String>,
    approve: bool,
    timeout: Option<u64>,
) -> Result<()> {
    if !approve {
        return Err(anyhow::anyhow!(
            "--approve is required to execute commands"
        ));
    }

    let project_id =
        Uuid::parse_str(project).map_err(|e| anyhow::anyhow!("invalid project id: {e}"))?;
    let project_id = ProjectId(project_id);

    let process_service = ProcessService::new();
    let request = ExecutionRequest {
        id: ProcessId::new(),
        session_id: SessionId::new(),
        project_id,
        agent_id: AgentId(Uuid::nil()),
        executable: PathBuf::from(program),
        arguments: args,
        environment: HashMap::new(),
        working_directory: std::env::current_dir()?,
        profile: ExecutionProfile::Development,
        capabilities: vec![],
        max_runtime_seconds: timeout,
        max_processes: None,
        memory_limit_mb: None,
        stdin_data: None,
    };

    let handle = process_service.exec(request).await?;
    println!("Process ID: {}", handle.id);
    println!("OS PID: {}", handle.os_pid);
    println!("Running: {}", handle.status.running);
    if let Some(ref exit_status) = handle.status.exit_status {
        println!("Exit code: {:?}", exit_status.code);
        println!("Success: {}", exit_status.success);
    }

    Ok(())
}

/// Options for `yl mcp`.
pub struct McpOptions {
    pub roots: Vec<String>,
    pub read_only_roots: Vec<String>,
    pub config: Option<String>,
}

/// Run the stdio MCP server with the workspace roots from CLI flags/config.
///
/// Pinned behavior (Task 10):
/// 1. Load config: `--config` path if given (error if unreadable), else
///    `./config/runtime.toml` when it exists, else `Config::default()`.
/// 2. Merge roots: CLI `--root` replaces config roots when non-empty;
///    read-only roots append. Every root is canonicalized and must exist.
/// 3. Fail closed: zero roots → message on stderr + exit(1).
/// 4. Build `WorkspaceServiceImpl`, set the sensitive matcher, register each
///    root (`Development`) / read-only root (`Inspect`).
/// 5. Build `AuditServiceImpl` logging to `config.data_dir.join("audit.jsonl")`.
/// 6. Build `McpServer::new_for_fs(...)` (Task 11 constructor skeleton).
/// 7. Serve over stdio; return `Ok(())` on clean shutdown.
pub async fn run_mcp_server(opts: McpOptions) -> Result<()> {
    // 1. Load config.
    let config = match &opts.config {
        Some(path) => Config::load_from_file(&PathBuf::from(path))?,
        None => {
            let default_path = PathBuf::from("./config/runtime.toml");
            if default_path.exists() {
                Config::load_from_file(&default_path)?
            } else {
                Config::default()
            }
        }
    };

    // 2. Merge roots: CLI `--root` replaces config roots when non-empty;
    //    read-only roots append (CLI read-only roots first, then config ones).
    let cli_roots: Vec<PathBuf> = opts.roots.iter().map(PathBuf::from).collect();
    let roots: Vec<PathBuf> = if cli_roots.is_empty() {
        config.workspace.roots.clone()
    } else {
        cli_roots
    };
    let mut read_only_roots: Vec<PathBuf> =
        opts.read_only_roots.iter().map(PathBuf::from).collect();
    read_only_roots.extend(config.workspace.read_only_roots.clone());

    // Canonicalize + existence-check every root.
    // On Windows `std::fs::canonicalize` returns `\\?\` verbatim-prefixed
    // paths, which the path-safety layer rejects as UNC; strip it so roots
    // are stored as ordinary absolute paths.
    let check_root = |p: &PathBuf| -> Result<PathBuf> {
        let canonical = std::fs::canonicalize(p)
            .map_err(|_| anyhow::anyhow!("Workspace root does not exist: {}", p.display()))?;
        Ok(strip_verbatim_prefix(&canonical))
    };
    let roots: Vec<PathBuf> = roots.iter().map(check_root).collect::<Result<_>>()?;
    let read_only_roots: Vec<PathBuf> =
        read_only_roots.iter().map(check_root).collect::<Result<_>>()?;

    // 3. Fail closed: no workspace roots at all.
    if roots.is_empty() && read_only_roots.is_empty() {
        eprintln!(
            "No workspace roots configured. Pass --root <dir> (repeatable) or set [workspace] roots in your config."
        );
        std::process::exit(1);
    }

    info!("Workspace roots: {:?}", roots);
    info!("Read-only roots: {:?}", read_only_roots);

    // 4. Build the workspace service and register roots.
    let service = Arc::new(WorkspaceServiceImpl::new());
    service.set_sensitive(SensitiveMatcher::new());
    let mut roots_pairs: Vec<(ProjectId, PathBuf)> = Vec::new();
    for root in roots {
        let id = service
            .register(root.clone(), ExecutionProfile::Development)
            .await?;
        roots_pairs.push((id, root));
    }
    let server_read_only_roots = read_only_roots.clone();
    for root in read_only_roots {
        let id = service.register(root.clone(), ExecutionProfile::Inspect).await?;
        roots_pairs.push((id, root));
    }

    // 5. Build the audit service, creating the data directory if missing.
    std::fs::create_dir_all(&config.data_dir)?;
    let audit: Arc<dyn AuditService> =
        Arc::new(AuditServiceImpl::new().with_log_path(config.data_dir.join("audit.jsonl")));

    // 6. Build the MCP server (Task 11 `new_for_fs`).
    let process_service: Arc<dyn runtime_process::ProcessServiceOps> =
        Arc::new(runtime_process::ProcessService::new());
    let mcp_server = runtime_mcp::McpServer::new_for_fs(
        service,
        roots_pairs,
        audit,
        server_read_only_roots,
        process_service,
    );

    // 7. Serve over stdio.
    use rmcp::ServiceExt;
    let server = mcp_server.serve(rmcp::transport::stdio()).await?;
    server.waiting().await?;
    Ok(())
}

/// Strip the Windows verbatim `\\?\` prefix from a canonicalized path so it
/// is stored as an ordinary absolute path (path-safety rejects `\\` heads as
/// UNC). No-op on non-Windows and on paths without the prefix.
fn strip_verbatim_prefix(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if s.starts_with(r"\\?\") {
        PathBuf::from(&s[4..])
    } else {
        path.to_path_buf()
    }
}
