//! CLI command implementations

use anyhow::Result;
use axum::{
    extract::{FromRequest, Request, State},
    http::{header, HeaderName, Method, StatusCode},
    middleware,
    response::Response,
    Router,
};
use tower_http::cors::{AllowOrigin, CorsLayer};
use runtime_approval::ApprovalBroker;
use runtime_audit::{AuditService, AuditServiceImpl};
use runtime_config::Config;
use runtime_core::traits::{ExecutionRequest, PolicyEngine};
use runtime_core::types::*;
use runtime_identity::{IdentityService, IdentityServiceImpl};
use runtime_process::{ProcessService, ProcessServiceOps};
use runtime_policy::PolicyEngineImpl;
use runtime_toolchain::ToolchainDiscovery;
use runtime_undo::UndoJournal;
use runtime_workspace::{
    discovery::DiscoveryService, SensitiveMatcher, WorkspaceService, WorkspaceServiceImpl,
};
use crate::tls::{self, TlsMaterial};
use runtime_config::config::{TlsMode};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tracing::{info, warn};
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

// ---- Pairing / device CLI (talks to a running `yl serve`) ----

/// Base URL of the running runtime. Override with `YL_RUNTIME_URL` when the
/// server is on a different host/port.
fn runtime_base_url() -> String {
    std::env::var("YL_RUNTIME_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "http://127.0.0.1:8077".to_string())
}

/// Call the host API and return the JSON body, converting non-2xx responses
/// into errors using the server's `error` field when present.
async fn host_api(
    method: reqwest::Method,
    path: &str,
    body: Option<serde_json::Value>,
) -> Result<serde_json::Value> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let url = format!("{}{}", runtime_base_url(), path);
    let mut request = client.request(method, &url);
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await.map_err(|e| {
        anyhow::anyhow!(
            "cannot reach the runtime at {url} ({e}). Start it first with `yl serve`."
        )
    })?;
    let status = response.status();
    let text = response.text().await?;
    let value: serde_json::Value = serde_json::from_str(&text)
        .unwrap_or_else(|_| serde_json::json!({ "raw": text }));

    if !status.is_success() {
        let message = value
            .get("error")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .unwrap_or_else(|| text.trim().to_string());
        anyhow::bail!("{status}: {message}");
    }
    Ok(value)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Generate an ed25519 device identity. Returns the 32-byte seed and the
/// hex-encoded public key.
fn generate_device_key() -> anyhow::Result<([u8; 32], String)> {
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    Ok((seed, device_public_key_hex(&seed)?))
}

fn device_public_key_hex(seed: &[u8; 32]) -> anyhow::Result<String> {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(seed);
    let verifying_key = signing_key.verifying_key();
    Ok(hex_encode(verifying_key.as_bytes()))
}

fn sign_device_id(seed: &[u8; 32], device_id: &str) -> anyhow::Result<String> {
    use ed25519_dalek::Signer;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(seed);
    let signature = signing_key.sign(device_id.as_bytes());
    Ok(hex_encode(&signature.to_bytes()))
}

pub async fn run_pairing(action: PairingAction) -> Result<()> {
    match action {
        PairingAction::List => {
            let value = host_api(reqwest::Method::GET, "/pair/list", None).await?;
            let pairings = value
                .get("pairings")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let devices = value
                .get("devices")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();

            println!("Pending / recent pairing requests:");
            if pairings.is_empty() {
                println!("  (none)");
            } else {
                for p in &pairings {
                    let code = p.get("pairing_code").and_then(|v| v.as_str()).unwrap_or("?");
                    let name = p.get("device_name").and_then(|v| v.as_str()).unwrap_or("?");
                    let state = p.get("state").and_then(|v| v.as_str()).unwrap_or("?");
                    let device_id = p.get("device_id").and_then(|v| v.as_str());
                    match device_id {
                        Some(id) => println!("  {code}  {name:<24} {state:<10} device={id}"),
                        None => println!("  {code}  {name:<24} {state}"),
                    }
                }
            }

            println!();
            println!("Paired devices:");
            if devices.is_empty() {
                println!("  (none)");
            } else {
                for d in &devices {
                    let id = d.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                    let name = d.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                    let revoked = d
                        .get("is_revoked")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let flag = if revoked { " (revoked)" } else { "" };
                    println!("  {id}  {name}{flag}");
                }
            }
            Ok(())
        }
        PairingAction::Approve { code } => {
            let value = host_api(
                reqwest::Method::POST,
                "/pair/approve",
                Some(serde_json::json!({ "pairing_code": code })),
            )
            .await?;
            let device_id = value
                .get("device_id")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            println!("Approved. Device id: {device_id}");
            println!("The device can now call POST /pair/authenticate to get a token.");
            Ok(())
        }
        PairingAction::Reject { code } => {
            host_api(
                reqwest::Method::POST,
                "/pair/reject",
                Some(serde_json::json!({ "pairing_code": code })),
            )
            .await?;
            println!("Rejected pairing request.");
            Ok(())
        }
        PairingAction::Status { code } => {
            let value = host_api(
                reqwest::Method::GET,
                &format!("/pair/status?pairing_code={code}"),
                None,
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&value)?);
            Ok(())
        }
        PairingAction::Request { name, key_hex } => {
            // Host-side helper: behaves like a device asking to pair. Handy for
            // testing and for scripted devices that keep their own key.
            let (seed, public_hex) = match key_hex {
                Some(hex) => {
                    let bytes = decode_hex_bytes(&hex)?;
                    let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                        anyhow::anyhow!("--key-hex must be a 32-byte ed25519 seed (64 hex chars)")
                    })?;
                    let public = device_public_key_hex(&seed)?;
                    (seed, public)
                }
                None => generate_device_key()?,
            };

            let value = host_api(
                reqwest::Method::POST,
                "/pair/request",
                Some(serde_json::json!({
                    "device_name": name,
                    "public_key_hex": public_hex,
                })),
            )
            .await?;

            let code = value
                .get("pairing_code")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            println!("Pairing code: {code}");
            println!("Public key:   {public_hex}");
            println!();
            println!("Approve on the host:  yl pairing approve {code}");
            println!("Device private key (keep secret): {}", hex_encode(&seed));
            Ok(())
        }
        PairingAction::Authenticate {
            device_id,
            key_hex,
        } => {
            let seed_bytes = decode_hex_bytes(&key_hex)?;
            let seed: [u8; 32] = seed_bytes.as_slice().try_into().map_err(|_| {
                anyhow::anyhow!("--key-hex must be a 32-byte ed25519 seed (64 hex chars)")
            })?;
            let signature_hex = sign_device_id(&seed, &device_id)?;

            let value = host_api(
                reqwest::Method::POST,
                "/pair/authenticate",
                Some(serde_json::json!({
                    "device_id": device_id,
                    "signature_hex": signature_hex,
                })),
            )
            .await?;

            let token = value.get("token").and_then(|v| v.as_str()).unwrap_or("?");
            println!("Session token: {token}");
            println!();
            println!("Send it on every request:");
            println!("  Authorization: Bearer {token}");
            Ok(())
        }
    }
}

/// Decode a hex string into bytes (used for CLI key arguments).
fn decode_hex_bytes(hex: &str) -> Result<Vec<u8>> {
    let cleaned: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() % 2 != 0 {
        anyhow::bail!("hex string has odd length");
    }
    let mut bytes = Vec::with_capacity(cleaned.len() / 2);
    for i in (0..cleaned.len()).step_by(2) {
        let byte = u8::from_str_radix(&cleaned[i..i + 2], 16)
            .map_err(|e| anyhow::anyhow!("invalid hex at byte {}: {e}", i / 2))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

/// `yl devices list` — paired devices from the running server.
pub async fn list_devices() {
    match host_api(reqwest::Method::GET, "/pair/list", None).await {
        Ok(value) => {
            let devices = value
                .get("devices")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if devices.is_empty() {
                println!("Registered devices: (none)");
                return;
            }
            println!("Registered devices:");
            for d in &devices {
                let id = d.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                let name = d.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                let fingerprint = d.get("fingerprint").and_then(|v| v.as_str()).unwrap_or("?");
                let revoked = d
                    .get("is_revoked")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let flag = if revoked { "  [revoked]" } else { "" };
                println!("  {id}  {name:<24} {fingerprint}{flag}");
            }
        }
        Err(e) => println!("{e}"),
    }
}

pub async fn revoke_device(device_id: &str) {
    match host_api(
        reqwest::Method::POST,
        "/device/revoke",
        Some(serde_json::json!({ "device_id": device_id })),
    )
    .await
    {
        Ok(_) => println!("Revoked device {device_id}. Its live sessions are invalid now."),
        Err(e) => println!("{e}"),
    }
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
    pub yolo: bool,
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
    let mut config = match &opts.config {
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
    
    // YL_YOLO=1 env var bypasses approval requests (audited).
    if std::env::var("YL_YOLO").ok().as_deref() == Some("1") {
        config.policy.yolo = true;
        warn!("YOLO mode enabled via YL_YOLO=1: approval requests are bypassed (audited)");
    }

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

    // Build the policy engine before registering roots so profiles are known
    // during enforcement.
    let policy_engine: Arc<dyn runtime_policy::PolicyEngine> =
        Arc::new(runtime_policy::PolicyEngineImpl::new());

    // 4. Build the workspace service and register roots. Discovery roots are
    //    synthesized from these roots when `[discovery].roots` is empty, so
    //    register/create/browse always have an enforced boundary.
    let discovery_config = runtime_config::config::effective_discovery(
        &config.discovery,
        &roots,
        &read_only_roots,
    );
    let service = Arc::new(WorkspaceServiceImpl::with_data_dir(
        config.data_dir.clone(),
        discovery_config,
    )?);
    service.set_sensitive(SensitiveMatcher::new());
    let mut roots_pairs: Vec<(ProjectId, PathBuf)> = Vec::new();
    for root in roots {
        let id = service
            .register(root.clone(), ExecutionProfile::Development)
            .await?;
        roots_pairs.push((id, root));
        // Set the profile in the policy store so enforcement knows the project's profile.
        policy_engine.set_profile(id, ExecutionProfile::Development).await?;
    }
    let server_read_only_roots = read_only_roots.clone();
    for root in read_only_roots {
        let id = service.register(root.clone(), ExecutionProfile::Inspect).await?;
        roots_pairs.push((id, root));
        policy_engine.set_profile(id, ExecutionProfile::Inspect).await?;
    }

    // 5. Build the audit service, creating the data directory if missing.
    std::fs::create_dir_all(&config.data_dir)?;
    let audit: Arc<dyn AuditService> =
        Arc::new(AuditServiceImpl::new().with_log_path(config.data_dir.join("audit.jsonl")));

    // 6. Build the approval broker and MCP server.
    let approval_broker: Arc<dyn runtime_approval::ApprovalBroker> =
        Arc::new(runtime_approval::ApprovalBrokerImpl::new().with_log_path(
            config.data_dir.join("approvals.jsonl"),
        ));
    let process_service: Arc<dyn runtime_process::ProcessServiceOps> =
        Arc::new(runtime_process::ProcessService::new());
    let mcp_server = runtime_mcp::McpServer::new_for_fs(
        service,
        roots_pairs,
        audit,
        server_read_only_roots,
        process_service,
        policy_engine,
        approval_broker,
        Arc::new(runtime_undo::UndoJournal::new().with_log_path(
            config.data_dir.join("undo.jsonl"),
        )),
        opts.yolo || config.policy.yolo,
    ).await;

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

pub async fn run_http_server(
    host: String,
    port: u16,
    allow_remote: bool,
    yolo: bool,
    roots: Vec<String>,
    insecure_http: bool,
) -> Result<()> {
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

    // Project-level override: .yl/policy.toml can override [tools.approval]
    // settings from the global config. Project config wins.
    let mut config = config;
    if let Ok(project_policy) = Config::load_from_file(&PathBuf::from("./.yl/policy.toml")) {
        config.policy = project_policy.policy;
        info!("Loaded project-level policy overrides from .yl/policy.toml");
    }

    // CLI --yolo flag overrides config yolo setting.
    if yolo {
        config.policy.yolo = true;
        warn!("YOLO mode enabled: approval requests are bypassed (audited)");
    }
    // YL_YOLO=1 env var also enables yolo mode.
    if std::env::var("YL_YOLO").ok().as_deref() == Some("1") {
        config.policy.yolo = true;
        warn!("YOLO mode enabled via YL_YOLO=1: approval requests are bypassed (audited)");
    }

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

    // Build the policy engine before registering roots so profiles are known
    // during enforcement.
    let policy_engine: Arc<dyn runtime_policy::PolicyEngine> =
        Arc::new(runtime_policy::PolicyEngineImpl::new());

    // 4. Build the workspace service and register roots. Discovery roots are
    //    synthesized from these roots when `[discovery].roots` is empty, so
    //    register/create/browse always have an enforced boundary.
    let discovery_config = runtime_config::config::effective_discovery(
        &config.discovery,
        &roots,
        &read_only_roots,
    );
    let service = Arc::new(WorkspaceServiceImpl::with_data_dir(
        config.data_dir.clone(),
        discovery_config,
    )?);
    service.set_sensitive(SensitiveMatcher::new());
    let mut roots_pairs: Vec<(ProjectId, PathBuf)> = Vec::new();
    for root in roots {
        let id = service
            .register(root.clone(), ExecutionProfile::Development)
            .await?;
        roots_pairs.push((id, root));
        // Set the profile in the policy store so enforcement knows the project's profile.
        policy_engine.set_profile(id, ExecutionProfile::Development).await?;
    }
    let server_read_only_roots = read_only_roots.clone();
    for root in read_only_roots {
        let id = service.register(root.clone(), ExecutionProfile::Inspect).await?;
        roots_pairs.push((id, root));
        policy_engine.set_profile(id, ExecutionProfile::Inspect).await?;
    }

    // 5. Build the audit service, creating the data directory if missing.
    std::fs::create_dir_all(&config.data_dir)?;
    let audit: Arc<dyn AuditService> =
        Arc::new(AuditServiceImpl::new().with_log_path(config.data_dir.join("audit.jsonl")));

    // 6. Build the approval broker and MCP server.
    let approval_broker: Arc<dyn runtime_approval::ApprovalBroker> =
        Arc::new(runtime_approval::ApprovalBrokerImpl::new().with_log_path(
            config.data_dir.join("approvals.jsonl"),
        ));
    let process_service: Arc<dyn runtime_process::ProcessServiceOps> =
        Arc::new(runtime_process::ProcessService::new());

    // Clone everything the HTTP API needs before McpServer takes ownership.
    let api_fs = service.clone();
    let api_audit = audit.clone();
    let api_approvals = approval_broker.clone();
    let discovery = Arc::new(DiscoveryService::from_config(service.discovery_config())?);

    let mcp_server = Arc::new(runtime_mcp::McpServer::new_for_fs(
        service,
        roots_pairs,
        audit,
        server_read_only_roots,
        process_service,
        policy_engine,
        approval_broker,
        Arc::new(runtime_undo::UndoJournal::new().with_log_path(
            config.data_dir.join("undo.jsonl"),
        )),
        config.policy.yolo,
    ).await);

    // 6b. Build the identity service (pairing, sessions, device auth). The
    // JSONL log keeps paired devices and live sessions across restarts.
    let identity: Arc<IdentityServiceImpl> = Arc::new(
        IdentityServiceImpl::new().with_log_path(config.data_dir.join("identity.jsonl")),
    );
    match identity.load_persisted().await {
        Ok(applied) if applied > 0 => info!(
            "identity: restored {applied} persisted event(s) from {}",
            config.data_dir.join("identity.jsonl").display()
        ),
        Ok(_) => {}
        Err(e) => warn!("identity: cannot replay persisted state ({e}); starting empty"),
    }
    let pairing_required = config.remote.pairing_required;
    let rate_limit_per_minute = config.remote.rate_limit_per_minute;
    if pairing_required {
        info!(
            "remote pairing enforced (rate limit {}/min); pair devices with `yl pairing request|approve`",
            rate_limit_per_minute
        );
    }

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

    let mut mcp_config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false) // stateless for 2026-07-28
        .with_json_response(true)        // plain JSON replies (simpler than SSE)
        .disable_allowed_origins();      // clients may send any Origin

    if accept_any_host {
        mcp_config = mcp_config.disable_allowed_hosts();
    } else {
        mcp_config = mcp_config.with_allowed_hosts(["localhost", "127.0.0.1", "::1"]);
    }

    let mcp_server_clone = mcp_server.clone();
    let mcp_service = StreamableHttpService::new(
        move || Ok(mcp_server_clone.clone()),
        LocalSessionManager::default().into(),
        mcp_config,
    );

    // 8. Transport plan: loopback stays plain (local MCP clients keep working),
    //    every LAN address gets TLS so browsers have a secure context.
    let tls_off = matches!(config.remote.tls, TlsMode::Off);
    let insecure = insecure_http || config.remote.allow_plaintext_lan;
    let plan = tls::plan_listeners(&host, port, allow_remote, tls_off, insecure)?;

    let material: Option<TlsMaterial> = if plan.tls.is_empty() {
        None
    } else if let (Some(cert), Some(key)) = (
        config.remote.tls_cert.clone(),
        config.remote.tls_key.clone(),
    ) {
        let pem = std::fs::read_to_string(&cert).map_err(|e| {
            anyhow::anyhow!("cannot read remote.tls_cert {}: {e}", cert.display())
        })?;
        Some(TlsMaterial {
            fingerprint: tls::fingerprint_of(&tls::cert_der(&pem)?),
            cert_path: cert,
            key_path: key,
            san_ips: plan.lan_ips.clone(),
        })
    } else {
        Some(tls::ensure_certificate(&config.data_dir, &plan.lan_ips)?)
    };

    info!("MCP endpoint (this machine): http://127.0.0.1:{port}/mcp");
    info!("Console (this machine): http://127.0.0.1:{port}/ui");
    if allow_remote && plan.lan_ips.is_empty() {
        warn!("No LAN IPv4 address detected; only loopback is being served");
    }
    for addr in &plan.tls {
        info!("LAN console: https://{addr}/ui  (self-signed certificate)");
        info!("LAN MCP endpoint: https://{addr}/mcp");
    }
    for addr in &plan.plain {
        if !addr.ip().is_loopback() {
            warn!("LAN console: http://{addr}/ui  (PLAINTEXT — explicitly allowed)");
        }
    }
    if let Some(m) = &material {
        info!("Certificate SHA-256 fingerprint: {}", m.fingerprint);
    }

    // 9. Router: pairing/health/MCP (`base`) plus the authenticated API and the
    //    console. One `build_router` call keeps the middleware order testable.
    let api_state = crate::http_api::ApiState {
        fs: api_fs,
        discovery,
        approvals: api_approvals,
        identity: identity.clone(),
        audit: api_audit,
        facts: crate::http_api::DeviceFacts {
            version: env!("CARGO_PKG_VERSION"),
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            yolo: config.policy.yolo,
            pairing_required,
            tls_enabled: !plan.tls.is_empty(),
            cert_fingerprint: material.as_ref().map(|m| m.fingerprint.clone()),
            lan_urls: plan
                .tls
                .iter()
                .map(|addr| format!("https://{addr}/ui"))
                .collect(),
        },
    };
    let app_state = AppState {
        identity,
        pairing_required,
        limiter: Arc::new(RateLimiter::new(rate_limit_per_minute)),
        api: api_state,
    };

    let base: Router<AppState> = base_routes().nest_service("/mcp", mcp_service);

    let app = build_router(base, app_state);

    let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    for addr in &plan.plain {
        let listener = match tokio::net::TcpListener::bind(*addr).await {
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
                    message.push_str(&format!("  http://127.0.0.1:{port}/ui\n"));
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
        let app = app.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(e) = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            {
                warn!("plain listener stopped: {e}");
            }
        }));
    }
    for addr in &plan.tls {
        let listener = tokio::net::TcpListener::bind(*addr).await.map_err(|e| {
            anyhow::anyhow!("cannot bind TLS listener on {addr}: {e}")
        })?;
        let material = material
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("internal: TLS listener without certificate"))?;
        tasks.push(
            tls::spawn_tls_listener(listener, app.clone(), &material.cert_path, &material.key_path)
                .await?,
        );
    }

    tokio::signal::ctrl_c().await.ok();
    for task in tasks {
        task.abort();
    }

    Ok(())
}

/// Is anything listening on `port`? Used only to explain an address-in-use
/// error, never on the startup path.
async fn port_is_open(port: u16) -> bool {
    tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .is_ok()
}

// ---- Remote access: pairing endpoints, session auth, rate limiting ----
//
// Spec §7.4 (Critical): remote exposure must never be unauthenticated. The
// `/mcp` endpoint requires a session token for any non-loopback peer whenever
// `remote.pairing_required` is set. Pairing itself is split by trust level:
// a device may *request* pairing and *authenticate* remotely, but only the
// host (loopback peer, e.g. `yl pairing approve`) may approve or reject.

/// Shared state for the HTTP auth/pairing layer.
#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) identity: Arc<IdentityServiceImpl>,
    /// When false, `/mcp` is reachable from any peer without a session token
    /// (loopback development). Loopback peers are always allowed.
    pub(crate) pairing_required: bool,
    pub(crate) limiter: Arc<RateLimiter>,
    /// Domain services shared with the `/api/v1` handlers.
    pub(crate) api: crate::http_api::ApiState,
}

// Lets `/api/v1` handlers extract `State<ApiState>` while the router itself
// carries `AppState` (auth state + services).
impl axum::extract::FromRef<AppState> for crate::http_api::ApiState {
    fn from_ref(state: &AppState) -> Self {
        state.api.clone()
    }
}

/// Fixed-window per-IP request limiter (spec §7.4: rate limits for pairing
/// and authentication attempts). One window per minute.
pub(crate) struct RateLimiter {
    limit_per_minute: u32,
    windows: std::sync::Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

impl RateLimiter {
    pub(crate) fn new(limit_per_minute: u32) -> Self {
        Self {
            // A limit of 0 would lock the server out entirely; treat it as the
            // documented default instead of failing closed by accident.
            limit_per_minute: if limit_per_minute == 0 { 100 } else { limit_per_minute },
            windows: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Returns `true` when the request is within the current window.
    fn check(&self, ip: IpAddr) -> bool {
        let mut windows = match self.windows.lock() {
            Ok(guard) => guard,
            // A poisoned mutex only means an earlier caller panicked while
            // holding it; the map itself is still structurally sound.
            Err(poisoned) => poisoned.into_inner(),
        };
        let now = Instant::now();
        let entry = windows.entry(ip).or_insert((now, 0));
        if now.duration_since(entry.0) >= std::time::Duration::from_secs(60) {
            *entry = (now, 0);
        }
        if entry.1 >= self.limit_per_minute {
            return false;
        }
        entry.1 += 1;
        true
    }
}

pub(crate) fn json_error(status: StatusCode, message: impl Into<String>) -> Response {
    use axum::response::IntoResponse;
    (
        status,
        axum::Json(serde_json::json!({ "error": message.into() })),
    )
        .into_response()
}

pub(crate) fn peer_ip(req: &Request) -> Option<IpAddr> {
    req.extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip())
}

/// Only the host may approve or reject a pairing. Without connection info we
/// cannot prove the peer is local, so we refuse.
pub(crate) fn is_host_peer(ip: Option<IpAddr>) -> bool {
    ip.map(|ip| ip.is_loopback()).unwrap_or(false)
}

/// Paths a remote peer may reach without a bearer token. These either expose
/// no workspace data (`/health`, the console assets) or are required to obtain
/// a token in the first place (`/pair/*` bootstrap).
pub(crate) fn is_public_path(path: &str) -> bool {
    matches!(
        path,
        "/health" | "/pair/request" | "/pair/status" | "/pair/authenticate"
    ) || path == "/ui"
        || path.starts_with("/ui/")
}

pub(crate) fn bearer_token(req: &Request) -> Option<String> {
    req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::to_owned)
}

/// Session gate.
///
/// Order is deliberate:
/// 1. OPTIONS preflight always passes.
/// 2. Loopback always passes (the host's own CLI and MCP clients).
/// 3. A valid bearer token always passes — and is never rate limited.
/// 4. Everything else is unauthenticated remote traffic: rate limit it, then
///    allow only the bootstrap allowlist. `/api/v1/*` is gated regardless of
///    `pairing_required`; that flag relaxes `/mcp` only.
async fn require_session(
    State(state): State<AppState>,
    req: Request,
    next: middleware::Next,
) -> Response {
    if req.method() == Method::OPTIONS {
        return next.run(req).await;
    }

    let ip = peer_ip(&req);
    if ip.map(|ip| ip.is_loopback()).unwrap_or(false) {
        return next.run(req).await;
    }

    let token = bearer_token(&req);
    if let Some(token) = &token {
        if state.identity.validate_session(token.clone()).await.is_ok() {
            return next.run(req).await;
        }
    }

    // Unauthenticated remote traffic: brute-force protection for pairing and
    // authentication attempts. A legitimate polling console is authenticated
    // and never reaches this branch.
    if let Some(ip) = ip {
        if !state.limiter.check(ip) {
            return json_error(
                StatusCode::TOO_MANY_REQUESTS,
                "rate limit exceeded; retry in a minute",
            );
        }
    }

    let path = req.uri().path().to_owned();
    if is_public_path(&path) {
        return next.run(req).await;
    }

    // `pairing_required = false` is the documented local-dev opt-out for /mcp
    // only; it must never expose the management API (§7.4 Critical).
    if path == "/mcp" && !state.pairing_required {
        return next.run(req).await;
    }

    match token {
        Some(_) => json_error(
            StatusCode::UNAUTHORIZED,
            "invalid or expired session; pair this device again",
        ),
        None => json_error(
            StatusCode::UNAUTHORIZED,
            "missing bearer token; pair this device (POST /pair/request) and authenticate first",
        ),
    }
}

/// Health, pairing and device routes: everything that is *not* under `/api/v1`.
/// `run_http_server` adds `/mcp` on top; tests use this as-is.
pub(crate) fn base_routes() -> Router<AppState> {
    Router::new()
        .route("/health", axum::routing::get(health))
        .route("/pair/request", axum::routing::post(pair_request))
        .route("/pair/status", axum::routing::get(pair_status))
        .route(
            "/pair/authenticate",
            axum::routing::post(pair_authenticate),
        )
        .route("/pair/approve", axum::routing::post(pair_approve))
        .route("/pair/reject", axum::routing::post(pair_reject))
        .route("/pair/list", axum::routing::get(pair_list))
        .route("/device/revoke", axum::routing::post(device_revoke))
}

/// Assemble the public router: MCP + pairing routes (`base`), the versioned API,
/// the console assets, permissive CORS, then the session gate.
pub(crate) fn build_router(base: Router<AppState>, app_state: AppState) -> Router {
    base.nest("/api/v1", crate::http_api::routes())
        .merge(crate::http_api::ui::routes())
        .with_state(app_state.clone())
        .layer(middleware::from_fn_with_state(
            app_state,
            require_session,
        ))
        .layer(
            CorsLayer::new()
                .allow_methods([
                    Method::POST,
                    Method::GET,
                    Method::PATCH,
                    Method::DELETE,
                    Method::OPTIONS,
                ])
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
        )
}

fn decode_hex(hex: &str) -> std::result::Result<Vec<u8>, String> {
    let cleaned: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() % 2 != 0 {
        return Err("hex string has odd length".to_string());
    }
    let mut bytes = Vec::with_capacity(cleaned.len() / 2);
    for i in (0..cleaned.len()).step_by(2) {
        let byte = u8::from_str_radix(&cleaned[i..i + 2], 16)
            .map_err(|e| format!("invalid hex at byte {}: {e}", i / 2))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

#[derive(serde::Deserialize)]
struct PairRequestBody {
    device_name: String,
    /// Device ed25519 public key, hex-encoded (32 bytes / 64 chars).
    public_key_hex: String,
}

#[derive(serde::Deserialize)]
struct PairCodeBody {
    pairing_code: String,
}

#[derive(serde::Deserialize)]
struct PairAuthenticateBody {
    device_id: String,
    /// Hex-encoded ed25519 signature over the device id string.
    signature_hex: String,
}

#[derive(serde::Deserialize)]
struct PairStatusQuery {
    pairing_code: String,
}

async fn health() -> Response {
    use axum::response::IntoResponse;
    axum::Json(serde_json::json!({
        "status": "ok",
        "service": "yl-agent-runtime",
        "version": env!("CARGO_PKG_VERSION"),
    }))
    .into_response()
}

/// A device asks the host for permission to pair. Returns the 6-digit code the
/// user must read out and approve on the host.
async fn pair_request(State(state): State<AppState>, req: Request) -> Response {
    use axum::response::IntoResponse;
    let body: PairRequestBody = match axum::Json::<PairRequestBody>::from_request(req, &state).await {
        Ok(body) => body.0,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e.to_string()),
    };
    let public_key = match decode_hex(&body.public_key_hex) {
        Ok(key) if key.len() == 32 => key,
        Ok(key) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                format!("public key must be 32 bytes, got {}", key.len()),
            )
        }
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e),
    };
    if body.device_name.trim().is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "device_name must not be empty");
    }

    match state
        .identity
        .request_pairing(body.device_name.clone(), public_key)
        .await
    {
        Ok(request) => axum::Json(serde_json::json!({
            "pairing_code": request.pairing_code,
            "device_name": request.device_name,
            "expires_at": request.expires_at.to_rfc3339(),
            "state": "pending",
        }))
        .into_response(),
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// A device polls for the outcome of its pairing request.
async fn pair_status(
    State(state): State<AppState>,
    query: axum::extract::Query<PairStatusQuery>,
) -> Response {
    use axum::response::IntoResponse;
    match state.identity.list_pairings().await {
        Ok(pairings) => match pairings
            .into_iter()
            .find(|p| p.pairing_code == query.pairing_code)
        {
            Some(p) => axum::Json(serde_json::json!({
                "state": p.state,
                "device_id": p.device_id,
                "expires_at": p.expires_at.to_rfc3339(),
            }))
            .into_response(),
            None => json_error(StatusCode::NOT_FOUND, "unknown pairing code"),
        },
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// A paired device proves key possession and receives a short-lived token.
async fn pair_authenticate(State(state): State<AppState>, req: Request) -> Response {
    use axum::response::IntoResponse;
    let body: PairAuthenticateBody =
        match axum::Json::<PairAuthenticateBody>::from_request(req, &state).await {
            Ok(body) => body.0,
            Err(e) => return json_error(StatusCode::BAD_REQUEST, e.to_string()),
        };
    let device_id = match Uuid::parse_str(&body.device_id) {
        Ok(uuid) => DeviceId(uuid),
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "device_id must be a UUID"),
    };

    match state
        .identity
        .authenticate_device(device_id, body.signature_hex.clone())
        .await
    {
        Ok(token) => axum::Json(serde_json::json!({
            "token": token,
            "device_id": device_id,
            "expires_in_seconds": 1800,
        }))
        .into_response(),
        Err(e) => json_error(StatusCode::UNAUTHORIZED, e.to_string()),
    }
}

/// Host-only: approve a pending pairing code.
async fn pair_approve(State(state): State<AppState>, req: Request) -> Response {
    use axum::response::IntoResponse;
    if !is_host_peer(peer_ip(&req)) {
        return json_error(
            StatusCode::FORBIDDEN,
            "pairing approval is host-only; run 'yl pairing approve CODE' on the host",
        );
    }
    let body: PairCodeBody = match axum::Json::<PairCodeBody>::from_request(req, &state).await {
        Ok(body) => body.0,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e.to_string()),
    };

    match state.identity.approve_pairing(body.pairing_code).await {
        Ok(device_id) => {
            axum::Json(serde_json::json!({ "device_id": device_id, "state": "approved" }))
                .into_response()
        }
        Err(e) => json_error(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

/// Host-only: reject a pending pairing code.
async fn pair_reject(State(state): State<AppState>, req: Request) -> Response {
    use axum::response::IntoResponse;
    if !is_host_peer(peer_ip(&req)) {
        return json_error(
            StatusCode::FORBIDDEN,
            "pairing rejection is host-only; run `yl pairing reject <code>` on the host",
        );
    }
    let body: PairCodeBody = match axum::Json::<PairCodeBody>::from_request(req, &state).await {
        Ok(body) => body.0,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e.to_string()),
    };

    match state.identity.reject_pairing(body.pairing_code).await {
        Ok(()) => axum::Json(serde_json::json!({ "state": "rejected" })).into_response(),
        Err(e) => json_error(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

/// Host-only: list pairing requests and paired devices.
async fn pair_list(State(state): State<AppState>, req: Request) -> Response {
    use axum::response::IntoResponse;
    if !is_host_peer(peer_ip(&req)) {
        return json_error(StatusCode::FORBIDDEN, "pairing list is host-only");
    }
    let pairings = match state.identity.list_pairings().await {
        Ok(p) => p,
        Err(e) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let devices = match state.identity.list_devices().await {
        Ok(d) => d,
        Err(e) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    axum::Json(serde_json::json!({ "pairings": pairings, "devices": devices })).into_response()
}

#[derive(serde::Deserialize)]
struct DeviceIdBody {
    device_id: String,
}

/// Host-only: revoke a paired device. Live sessions for that device stop
/// validating immediately.
async fn device_revoke(State(state): State<AppState>, req: Request) -> Response {
    use axum::response::IntoResponse;
    if !is_host_peer(peer_ip(&req)) {
        return json_error(StatusCode::FORBIDDEN, "device revocation is host-only");
    }
    let body: DeviceIdBody = match axum::Json::<DeviceIdBody>::from_request(req, &state).await {
        Ok(body) => body.0,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e.to_string()),
    };
    let device_id = match Uuid::parse_str(&body.device_id) {
        Ok(uuid) => DeviceId(uuid),
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "device_id must be a UUID"),
    };

    match state.identity.revoke_device(device_id).await {
        Ok(()) => axum::Json(serde_json::json!({ "device_id": device_id, "state": "revoked" }))
            .into_response(),
        Err(e) => json_error(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

/// Run the `yl approval` subcommand against a locally running server.
///
/// Connects to the MCP server on 127.0.0.1:8077 and calls the corresponding
/// approval tool. Falls back to direct file-based inspection if the server
/// is not reachable (best-effort for offline use).
pub async fn run_approval(action: ApprovalAction) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build HTTP client: {e}"))?;
    let url = "http://127.0.0.1:8077/mcp";

    fn rpc(id: u64, method: &str, params: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        })
    }

    match action {
        ApprovalAction::Approve { approval_id } => {
            let body = rpc(1, "tools/call", serde_json::json!({
                "name": "approval.approve",
                "arguments": { "approval_id": approval_id }
            }));
            let resp = client.post(url).json(&body).send().await?;
            let text = resp.text().await?;
            println!("{text}");
        }
        ApprovalAction::Reject { approval_id, reason } => {
            let body = rpc(2, "tools/call", serde_json::json!({
                "name": "approval.reject",
                "arguments": { "approval_id": approval_id, "reason": reason.unwrap_or_default() }
            }));
            let resp = client.post(url).json(&body).send().await?;
            let text = resp.text().await?;
            println!("{text}");
        }
        ApprovalAction::List => {
            let body = rpc(3, "tools/call", serde_json::json!({
                "name": "approval.list",
                "arguments": {}
            }));
            let resp = client.post(url).json(&body).send().await?;
            let text = resp.text().await?;
            println!("{text}");
        }
    }
    Ok(())
}

#[derive(clap::Subcommand, Debug)]
pub enum ApprovalAction {
    /// Approve a pending approval by id
    Approve {
        approval_id: String,
    },
    /// Reject a pending approval by id, with an optional reason
    Reject {
        approval_id: String,
        #[arg(long, short)]
        reason: Option<String>,
    },
    /// List pending (not-yet-decided) approvals
    List,
}

/// Paired device administration.
#[derive(clap::Subcommand, Debug)]
pub enum DevicesAction {
    /// List paired devices
    List,
    /// Revoke a paired device (its live sessions stop working immediately)
    Revoke {
        device_id: String,
    },
}

/// Device pairing lifecycle against a running `yl serve`.
#[derive(clap::Subcommand, Debug)]
pub enum PairingAction {
    /// List pairing requests and paired devices
    List,
    /// Approve a pending pairing code (host only)
    Approve {
        code: String,
    },
    /// Reject a pending pairing code (host only)
    Reject {
        code: String,
    },
    /// Show the outcome of a pairing request
    Status {
        code: String,
    },
    /// Request pairing as a device (generates a key if --key-hex is omitted)
    Request {
        #[arg(long, short)]
        name: String,
        /// 32-byte ed25519 seed, hex-encoded (64 chars)
        #[arg(long)]
        key_hex: Option<String>,
    },
    /// Authenticate a paired device and print a session token
    Authenticate {
        device_id: String,
        /// 32-byte ed25519 seed, hex-encoded (64 chars)
        #[arg(long)]
        key_hex: String,
    },
}

#[derive(clap::Subcommand, Debug)]
pub enum DiscoveryAction {
    /// List configured discovery roots with their enablement and flags.
    Roots,
    /// Browse entries under a discovery root (root-relative path).
    Browse {
        root: String,
        #[arg(default_value = "")]
        path: String,
        #[arg(long, short)]
        cursor: Option<usize>,
        #[arg(long, short, default_value = "50")]
        limit: usize,
    },
    /// Detect project type for a directory under a discovery root.
    Detect {
        root: String,
        #[arg(default_value = "")]
        path: String,
    },
    /// Enable a discovery root.
    Enable { root: String },
    /// Disable a discovery root.
    Disable { root: String },
}

#[derive(clap::Subcommand, Debug)]
pub enum WorkspaceAction {
    /// List registered workspaces.
    List,
    /// Register an existing directory as a workspace.
    Register {
        path: String,
    },
    /// Unregister a workspace by ID (does not delete project files).
    Unregister {
        id: String,
    },
    /// Create a new empty project directory under a parent path and register it.
    Create {
        #[arg(help = "Parent directory under which to create the project")]
        parent: String,
        #[arg(help = "Name of the new project directory")]
        name: String,
    },
}

/// Workspace registry commands: list, register, unregister, create.
///
/// Backed by `WorkspaceServiceImpl` — the same service a future desktop
/// controller GUI would call, keeping CLI and GUI consistent.
pub async fn run_workspace(action: WorkspaceAction) -> Result<()> {
    match action {
        WorkspaceAction::List => {
            let value = host_api(reqwest::Method::GET, "/api/v1/workspaces", None).await?;
            let workspaces = value
                .get("workspaces")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if workspaces.is_empty() {
                println!("No workspaces registered.");
                return Ok(());
            }
            println!("Registered workspaces:");
            for w in workspaces {
                let id = w.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                let name = w
                    .get("display_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let root_id = w.get("root_id").and_then(|v| v.as_str()).unwrap_or("-");
                let rel = w
                    .get("relative_path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let profile = w.get("profile").and_then(|v| v.as_str()).unwrap_or("");
                println!(
                    "  {} | {} | root={}/{} | profile={} | origin={}",
                    id,
                    name,
                    root_id,
                    rel,
                    profile,
                    w.get("origin").and_then(|v| v.as_str()).unwrap_or("")
                );
            }
        }
        WorkspaceAction::Register { path } => {
            let value = host_api(
                reqwest::Method::POST,
                "/api/v1/workspaces/register",
                Some(serde_json::json!({ "root_id": "default", "relative_path": path })),
            )
            .await?;
            let id = value
                .get("workspace_id")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let already = value.get("already_registered").and_then(|v| v.as_bool()).unwrap_or(false);
            if already {
                println!("Workspace already registered: {} (reused existing id)", id);
            } else {
                println!("Registered workspace {} at {}", id, path);
            }
        }
        WorkspaceAction::Unregister { id } => {
            host_api(
                reqwest::Method::DELETE,
                &format!("/api/v1/workspaces/{id}"),
                None,
            )
            .await?;
            println!("Unregistered workspace {}", id);
        }
        WorkspaceAction::Create { parent, name } => {
            let value = host_api(
                reqwest::Method::POST,
                "/api/v1/workspaces/create",
                Some(serde_json::json!({
                    "root_id": "default",
                    "relative_path": parent,
                    "name": name,
                })),
            )
            .await?;
            let id = value
                .get("workspace_id")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            println!("Created workspace {} at {}/{}", id, parent, name);
        }
    }
    Ok(())
}

/// Discovery root commands: list, browse, detect, enable, disable.
///
/// Talks to the running server's `/api/v1/discovery/*` endpoints via
/// `host_api` — the same HTTP API the `/ui` console uses. Keeps CLI and GUI
/// consistent: both are clients of the live server.
pub async fn run_discovery(action: DiscoveryAction) -> Result<()> {
    match action {
        DiscoveryAction::Roots => {
            let value = host_api(reqwest::Method::GET, "/api/v1/discovery/roots", None).await?;
            let roots = value
                .get("roots")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if roots.is_empty() {
                println!("No discovery roots configured.");
                return Ok(());
            }
            println!("Discovery roots:");
            for root in roots {
                let id = root.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                let label = root.get("label").and_then(|v| v.as_str()).unwrap_or("");
                let enabled = root.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
                let browse = root.get("browse").and_then(|v| v.as_bool()).unwrap_or(false);
                let create = root.get("create").and_then(|v| v.as_bool()).unwrap_or(false);
                let register = root.get("register").and_then(|v| v.as_bool()).unwrap_or(false);
                let synthetic = root.get("synthetic").and_then(|v| v.as_bool()).unwrap_or(false);
                println!(
                    "  {} | {} | enabled={} browse={} create={} register={} synthetic={}",
                    id, label, enabled, browse, create, register, synthetic
                );
            }
        }
        DiscoveryAction::Browse {
            root,
            path,
            cursor,
            limit,
        } => {
            let mut params = format!("?path={path}");
            if let Some(c) = cursor {
                params.push_str(&format!("&cursor={c}"));
            }
            params.push_str(&format!("&limit={limit}"));
            let value = host_api(
                reqwest::Method::GET,
                &format!("/api/v1/discovery/roots/{root}/entries{params}"),
                None,
            )
            .await?;
            let entries = value
                .get("entries")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            println!("root={} path={}", root, path);
            for entry in entries {
                let name = entry.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let kind = if entry.get("kind").and_then(|v| v.as_str()) == Some("directory") {
                    "dir"
                } else {
                    "file"
                };
                let size = entry.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
                println!("  {kind} {name} {size}B");
            }
        }
        DiscoveryAction::Detect { root, path } => {
            let value = host_api(
                reqwest::Method::POST,
                "/api/v1/projects/detect",
                Some(serde_json::json!({ "root_id": root, "relative_path": path })),
            )
            .await?;
            let types = value
                .get("project_types")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|t| t.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            println!("root={} path={}", root, path);
            println!("project_types={types}");
            println!(
                "markers={:?}",
                value.get("markers").and_then(|v| v.as_array())
            );
            println!("confidence={:.2}", value.get("confidence").and_then(|v| v.as_f64()).unwrap_or(0.0));
        }
        DiscoveryAction::Enable { root } => {
            let value = host_api(
                reqwest::Method::PATCH,
                &format!("/api/v1/discovery/roots/{root}"),
                Some(serde_json::json!({ "enabled": true })),
            )
            .await?;
            let enabled = value.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
            println!("root {} enabled={}", root, enabled);
        }
        DiscoveryAction::Disable { root } => {
            let value = host_api(
                reqwest::Method::PATCH,
                &format!("/api/v1/discovery/roots/{root}"),
                Some(serde_json::json!({ "enabled": false })),
            )
            .await?;
            let enabled = value.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
            println!("root {} enabled={}", root, enabled);
        }
    }
    Ok(())
}
