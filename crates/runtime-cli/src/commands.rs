//! CLI command implementations

use anyhow::Result;
use axum::Router;
use axum::http::{HeaderName, Method};
use tower_http::cors::{AllowOrigin, CorsLayer};
use runtime_audit::{AuditService, AuditServiceImpl};
use runtime_config::Config;
use runtime_core::traits::ExecutionRequest;
use runtime_core::types::*;
use runtime_process::{ProcessService, ProcessServiceOps};
use runtime_toolchain::ToolchainDiscovery;
use runtime_workspace::{SensitiveMatcher, WorkspaceService, WorkspaceServiceImpl};
use std::collections::HashMap;
use std::net::SocketAddr;
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

/// Run the MCP server over Streamable HTTP (remote access).
///
/// Pinned behavior:
/// 1. Load config: `--config` path if given (error if unreadable), else
///    `./config/runtime.toml` when it exists, else `Config::default()`.
/// 2. Merge roots: CLI `--root` replaces config roots when non-empty;
///    read-only roots append. Every root is canonicalized and must exist.
/// 3. Fail closed: zero roots → message on stderr + exit(1).
/// 4. Build `WorkspaceServiceImpl`, set the sensitive matcher, register each
///    root (`Development`) / read-only root (`Inspect`).
/// 5. Build `AuditServiceImpl` logging to `config.data_dir.join("audit.jsonl")`.
/// 6. Build `McpServer::new_for_fs(...)` (Task 11 constructor skeleton).
/// 7. Mount `StreamableHttpService` on an axum router at `/mcp` with origin
///    validation (DNS rebinding protection) and bind to TCP.
/// 8. Default bind address is 127.0.0.1 (localhost only); pass
///    `--allow-remote` to bind 0.0.0.0.
/// Discover the LAN address a remote client should dial, by asking the OS which
/// local address it would use to reach the internet. No packets are sent.
fn local_lan_ip() -> Option<std::net::IpAddr> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    sock.local_addr().ok().map(|a| a.ip())
}

pub async fn run_http_server(host: String, port: u16, allow_remote: bool, roots: Vec<String>) -> Result<()> {
    // 1. Load config.
    let config = match std::env::var("YL_RUNTIME_CONFIG").ok() {
        Some(path) if !path.is_empty() => Config::load_from_file(&PathBuf::from(path))?,
        _ => {
            let default_path = PathBuf::from("./config/runtime.toml");
            if default_path.exists() {
                Config::load_from_file(&default_path)?
            } else {
                Config::default()
            }
        }
    };

    // 2. Merge roots: CLI `--root` replaces config roots when non-empty;
    //    read-only roots append. Every root is canonicalized and must exist.
    let cli_roots: Vec<PathBuf> = roots.iter().map(PathBuf::from).collect();
    let roots: Vec<PathBuf> = if cli_roots.is_empty() {
        config.workspace.roots.clone()
    } else {
        cli_roots
    };
    let mut read_only_roots: Vec<PathBuf> = vec![];
    read_only_roots.extend(config.workspace.read_only_roots.clone());

    // Canonicalize + existence-check every root.
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
    let mcp_server = Arc::new(runtime_mcp::McpServer::new_for_fs(
        service,
        roots_pairs,
        audit,
        server_read_only_roots,
        process_service,
    ));

    // 7. Serve over Streamable HTTP.
    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    };

    // DNS-rebinding protection: by default rmcp only accepts loopback `Host`
    // headers and answers anything else with `403 Forbidden`. When we are bound
    // to 0.0.0.0 (i.e. serving a LAN client such as the Android app), the client
    // legitimately sends `Host: <lan-ip>:<port>`, so host validation must be off.
    // A `--host` that is not loopback is treated the same way.
    let host_is_loopback = matches!(host.as_str(), "127.0.0.1" | "localhost" | "::1");
    let accept_any_host = allow_remote || !host_is_loopback;

    let mut config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false) // stateless for 2026-07-28
        .with_json_response(true)        // plain JSON replies (simpler than SSE)
        .disable_allowed_origins();      // clients may send any Origin

    if accept_any_host {
        config = config.disable_allowed_hosts();
    } else {
        config = config.with_allowed_hosts(["localhost", "127.0.0.1", "::1"]);
    }

    let mcp_server_clone = mcp_server.clone();
    let mcp_service = StreamableHttpService::new(
        move || Ok(mcp_server_clone.clone()),
        LocalSessionManager::default().into(),
        config,
    );

    // Build axum router with the MCP service mounted at /mcp.
    let app = Router::new().nest_service("/mcp", mcp_service);

    // Permissive CORS. The Android client is a native HTTP client and does not
    // enforce CORS at all; this exists for browser-based MCP clients and for
    // browser preflight requests. `AllowOrigin::any()` cannot be combined with
    // credentials, which we do not use.
    let app = app.layer(
        CorsLayer::new()
            .allow_methods([Method::POST, Method::GET, Method::DELETE, Method::OPTIONS])
            .allow_headers([
                HeaderName::from_static("content-type"),
                HeaderName::from_static("accept"),
                HeaderName::from_static("authorization"),
                HeaderName::from_static("mcp-session-id"),
                HeaderName::from_static("mcp-protocol-version"),
                HeaderName::from_static("last-event-id"),
                HeaderName::from_static("origin"),
            ])
            .expose_headers([
                HeaderName::from_static("mcp-session-id"),
                HeaderName::from_static("mcp-protocol-version"),
            ])
            .allow_origin(AllowOrigin::any())
            .allow_credentials(false),
    );

    let addr: SocketAddr = if allow_remote {
        format!("0.0.0.0:{}", port).parse()?
    } else {
        format!("{}:{}", host, port).parse()?
    };

    info!("YL Agent Runtime MCP HTTP server listening on http://{}", addr);
    info!("MCP endpoint (this machine): http://127.0.0.1:{}/mcp", port);
    if accept_any_host {
        if let Some(ip) = local_lan_ip() {
            info!("MCP endpoint (LAN devices): http://{}:{}/mcp", ip, port);
        }
    }

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            // Very common in practice: a previous `yl serve` (possibly started
            // from another terminal) is still holding the port. A raw
            // "os error 10048" tells the user nothing, so say what is wrong and
            // what to do.
            let occupied = port_is_open(port).await;
            let mut message = format!("port {port} is already in use");
            if occupied {
                message.push_str(
                    " by a listening process — most likely a `yl serve` you started \
                     earlier. If that is your runtime it is already up:\n",
                );
                message.push_str(&format!("  http://127.0.0.1:{port}/mcp\n"));
                if accept_any_host {
                    if let Some(ip) = local_lan_ip() {
                        message.push_str(&format!("  http://{ip}:{port}/mcp  (LAN)\n"));
                    }
                }
                message.push_str("Stop the other instance before starting a new one.");
            } else {
                message.push_str(
                    " by another program. Pick a different port with --port <n>.",
                );
            }
            anyhow::bail!("{message}");
        }
        Err(e) => return Err(e.into()),
    };
    axum::serve(listener, app).await?;

    Ok(())
}

/// Is anything listening on `port`? Used only to explain an address-in-use
/// error, never on the startup path.
async fn port_is_open(port: u16) -> bool {
    tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .is_ok()
}
