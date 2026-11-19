//! Runtime configuration

use runtime_core::error::{Error, Result};
use runtime_core::types::*;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::collections::HashMap;

/// Runtime configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub version: String,
    pub data_dir: PathBuf,
    pub config_dir: PathBuf,
    pub log_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub daemon: DaemonConfig,
    pub policy: PolicyConfig,
    pub audit: AuditConfig,
    pub backend: BackendConfig,
    pub transport: TransportConfig,
    pub remote: RemoteConfig,
    #[serde(default)] pub workspace: WorkspaceConfig,
    #[serde(default)] pub discovery: DiscoveryConfig,
}

/// Daemon configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    pub bind_address: String,
    pub port: u16,
    pub idle_timeout_seconds: u64,
    pub max_sessions: u32,
    pub startup_timeout_seconds: u64,
}

/// Policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub default_profile: ExecutionProfile,
    pub policy_dir: PathBuf,
    pub fail_closed: bool,
    pub require_approval_for: Vec<Capability>,
    /// How long (seconds) a pending approval lives before auto-deny.
    #[serde(default = "default_approval_ttl_seconds")]
    pub approval_ttl_seconds: u64,
    /// When true, treat `Ask` policy decisions as `Allow` (bypass approval).
    /// Audited prominently. Intended for automation/CI only.
    #[serde(default)]
    pub yolo: bool,
}

fn default_approval_ttl_seconds() -> u64 {
    1800 // 30 minutes
}

/// Audit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    pub enabled: bool,
    pub retention_days: u32,
    pub max_log_size_mb: u64,
    pub export_format: String,
    pub redact_secrets: bool,
}

/// Backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    pub preferred_backend: String,
    pub enable_native: bool,
    pub enable_windows_sandbox: bool,
    pub enable_linux_sandbox: bool,
    pub enable_macos_sandbox: bool,
    pub enable_arapuca: bool,
    pub enable_virtx: bool,
}

/// Transport configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    pub enable_stdio: bool,
    pub enable_streamable_http: bool,
    pub http_bind_address: String,
    pub http_port: u16,
    pub enable_iroh: bool,
}

/// TLS mode for the LAN listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    /// Generate/load a self-signed certificate for every local LAN address.
    #[default]
    Auto,
    /// Serve plaintext on the LAN. Refused unless explicitly overridden.
    Off,
}

/// Remote configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteConfig {
    pub enabled: bool,
    pub pairing_required: bool,
    pub session_timeout_seconds: u64,
    pub rate_limit_per_minute: u32,
    pub max_request_size_mb: u64,
    /// Transport for non-loopback listeners. Defaults to TLS.
    #[serde(default)]
    pub tls: TlsMode,
    /// Operator-supplied certificate/key (both must be set to take effect).
    #[serde(default)]
    pub tls_cert: Option<PathBuf>,
    #[serde(default)]
    pub tls_key: Option<PathBuf>,
    /// Explicit opt-out: allow plaintext on a LAN interface.
    #[serde(default)]
    pub allow_plaintext_lan: bool,
}

/// Workspace configuration: registered file roots and size limits.
///
/// Roots may be relative in config; they are canonicalized (and existence
/// checked) when the MCP server starts up in `run_mcp_server`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceConfig {
    #[serde(default)] pub roots: Vec<PathBuf>,
    #[serde(default)] pub read_only_roots: Vec<PathBuf>,
    #[serde(default = "default_ws_max_file_size")] pub max_file_size: u64,
}

fn default_ws_max_file_size() -> u64 {
    10_485_760 // 10 MiB
}

impl Default for WorkspaceConfig {
    fn default() -> Self {
        Self {
            roots: Vec::new(),
            read_only_roots: Vec::new(),
            max_file_size: 10_485_760,
        }
    }
}

/// Entry kind returned by discovery browsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryEntryKind {
    File,
    Directory,
}

/// One entry discovered under a root during browsing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryBrowseEntry {
    pub name: String,
    pub relative_path: PathBuf,
    pub entry_kind: DiscoveryEntryKind,
    pub size: u64,
    pub modified_time: Option<String>,
    pub hidden: bool,
}

/// Result of a paginated browse under a discovery root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryBrowseResult {
    pub root_id: String,
    pub path: String, // root-relative path that was browsed
    pub entries: Vec<DiscoveryBrowseEntry>,
    pub cursor: Option<String>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

/// Result of bounded project detection under a discovery root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryProjectDetection {
    pub root_id: String,
    pub relative_path: String,
    pub markers: Vec<String>,
    pub project_types: Vec<String>,
    pub git_present: bool,
    pub git_branch: Option<String>,
    pub confidence: f32,
    pub scan_limits_hit: bool,
}

/// One configured discovery root: a user-authorized filesystem boundary from
/// which browsing and destination selection are allowed. It is not
/// automatically a workspace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryRoot {
    pub id: String,
    pub label: String,
    pub path: PathBuf,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub browse: bool,
    #[serde(default = "default_true")]
    pub create: bool,
    #[serde(default = "default_true")]
    pub register: bool,
    #[serde(default = "default_true")]
    pub import: bool,
    #[serde(default = "default_true")]
    pub clone: bool,
}

fn default_true() -> bool {
    true
}

/// Discovery configuration: configurable roots and browsing limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub default_root_id: Option<String>,
    #[serde(default = "default_false")]
    pub show_hidden: bool,
    #[serde(default = "default_false")]
    pub follow_symlinks: bool,
    #[serde(default = "default_max_depth")]
    pub max_depth: usize,
    #[serde(default = "default_max_entries_per_page")]
    pub max_entries_per_page: usize,
    #[serde(default)]
    pub roots: Vec<DiscoveryRoot>,
}

fn default_false() -> bool {
    false
}

fn default_max_depth() -> usize {
    12
}

fn default_max_entries_per_page() -> usize {
    250
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_root_id: None,
            show_hidden: false,
            follow_symlinks: false,
            max_depth: 12,
            max_entries_per_page: 250,
            roots: Vec::new(),
        }
    }
}

impl Config {
    pub fn default() -> Self {
        Self {
            version: "0.1.0".to_string(),
            data_dir: PathBuf::from("./data"),
            config_dir: PathBuf::from("./config"),
            log_dir: PathBuf::from("./logs"),
            cache_dir: PathBuf::from("./cache"),
            daemon: DaemonConfig {
                bind_address: "127.0.0.1".to_string(),
                port: 0, // Use IPC/named pipe by default
                idle_timeout_seconds: 3600,
                max_sessions: 100,
                startup_timeout_seconds: 5,
            },
            policy: PolicyConfig {
                default_profile: ExecutionProfile::Development,
                policy_dir: PathBuf::from("./config/policies"),
                fail_closed: true,
                require_approval_for: vec![
                    Capability::ProcessExec,
                    Capability::TerminalOpen,
                    Capability::GitCommit,
                    Capability::SystemElevate,
                ],
                approval_ttl_seconds: 1800,
                yolo: false,
            },
            audit: AuditConfig {
                enabled: true,
                retention_days: 90,
                max_log_size_mb: 100,
                export_format: "jsonl".to_string(),
                redact_secrets: true,
            },
            backend: BackendConfig {
                preferred_backend: "native".to_string(),
                enable_native: true,
                enable_windows_sandbox: true,
                enable_linux_sandbox: true,
                enable_macos_sandbox: true,
                enable_arapuca: false, // Disabled until Phase 0 verification
                enable_virtx: false,   // Disabled until Phase 5
            },
            transport: TransportConfig {
                enable_stdio: true,
                enable_streamable_http: false,
                http_bind_address: "127.0.0.1".to_string(),
                http_port: 0,
                enable_iroh: false,
            },
            remote: RemoteConfig {
                enabled: false,
                pairing_required: true,
                session_timeout_seconds: 3600,
                rate_limit_per_minute: 100,
                max_request_size_mb: 10,
                tls: TlsMode::Auto,
                tls_cert: None,
                tls_key: None,
                allow_plaintext_lan: false,
            },
            workspace: WorkspaceConfig::default(),
            discovery: DiscoveryConfig::default(),
        }
    }

    pub fn load_from_file(path: &PathBuf) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("Failed to read config file: {}", e)))?;
        let config: Config = toml::from_str(&content)
            .map_err(|e| Error::Config(format!("Failed to parse config: {}", e)))?;
        Ok(config)
    }

    pub fn save_to_file(&self, path: &PathBuf) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| Error::Config(format!("Failed to serialize config: {}", e)))?;
        std::fs::write(path, content).map_err(|e| Error::Config(format!("Failed to write config: {}", e)))?;
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::default()
    }
}

/// Configuration migration result
#[derive(Debug, Clone)]
pub struct MigrationResult {
    pub from_version: String,
    pub to_version: String,
    pub migrated: bool,
}

/// Configuration migrator
pub struct ConfigMigrator;

impl ConfigMigrator {
    pub fn migrate(config: Config, target_version: &str) -> Result<(Config, MigrationResult)> {
        if config.version == target_version {
            let from_version = config.version.clone();
            return Ok((config, MigrationResult {
                from_version,
                to_version: target_version.to_string(),
                migrated: false,
            }));
        }

        // Perform migrations
        let mut config = config;
        let mut migrated = false;

        // Example migration: add new fields
        if config.version < "0.2.0".to_string() {
            // Add any new fields introduced in 0.2.0
            migrated = true;
            config.version = "0.2.0".to_string();
        }

        let from_version = config.version.clone();
        Ok((config, MigrationResult {
            from_version,
            to_version: target_version.to_string(),
            migrated,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_toml() -> String {
        String::from(
            r#"
version = "0.1.0"
data_dir = "./data"
config_dir = "./config"
log_dir = "./logs"
cache_dir = "./cache"

[daemon]
bind_address = "127.0.0.1"
port = 0
idle_timeout_seconds = 3600
max_sessions = 100
startup_timeout_seconds = 5

[policy]
default_profile = "development"
policy_dir = "./config/policies"
fail_closed = true
require_approval_for = []

[audit]
enabled = true
retention_days = 90
max_log_size_mb = 100
export_format = "jsonl"
redact_secrets = true

[backend]
preferred_backend = "native"
enable_native = true
enable_windows_sandbox = true
enable_linux_sandbox = true
enable_macos_sandbox = true
enable_arapuca = false
enable_virtx = false

[transport]
enable_stdio = true
enable_streamable_http = false
http_bind_address = "127.0.0.1"
http_port = 0
enable_iroh = false

[remote]
enabled = false
pairing_required = true
session_timeout_seconds = 3600
rate_limit_per_minute = 100
max_request_size_mb = 10
"#,
        )
    }

    #[test]
    fn workspace_section_parses() {
        let content = format!(
            "{}\n\n[workspace]\nroots = [\"C:/x\"]\nread_only_roots = []\nmax_file_size = 10485760\n",
            base_toml()
        );
        let config: Config = toml::from_str(&content).unwrap();
        assert_eq!(config.workspace.roots, vec![PathBuf::from("C:/x")]);
        assert_eq!(config.workspace.read_only_roots, Vec::<PathBuf>::new());
        assert_eq!(config.workspace.max_file_size, 10_485_760);
    }

    #[test]
    fn workspace_defaults_when_section_absent() {
        let config: Config = toml::from_str(&base_toml()).unwrap();
        assert!(config.workspace.roots.is_empty());
        assert!(config.workspace.read_only_roots.is_empty());
        assert_eq!(config.workspace.max_file_size, 10_485_760);
    }

    #[test]
    fn discovery_section_parses() {
        let content = format!(
            "{}\n\n[discovery]\nenabled = true\ndefault_root_id = \"developments\"\nshow_hidden = false\nfollow_symlinks = false\nmax_depth = 12\nmax_entries_per_page = 250\n\n[[discovery.roots]]\nid = \"developments\"\nlabel = \"Developments\"\npath = \"E:/ylstack-space/Developments\"\nenabled = true\nbrowse = true\ncreate = true\nregister = true\nimport = true\nclone = true\n",
            base_toml()
        );
        let config: Config = toml::from_str(&content).unwrap();
        assert!(config.discovery.enabled);
        assert_eq!(
            config.discovery.default_root_id.as_deref(),
            Some("developments")
        );
        assert_eq!(config.discovery.roots.len(), 1);
        let root = &config.discovery.roots[0];
        assert_eq!(root.id, "developments");
        assert_eq!(root.label, "Developments");
        assert_eq!(root.path, PathBuf::from("E:/ylstack-space/Developments"));
        assert!(root.enabled);
        assert!(root.browse);
        assert!(root.clone);
    }

    #[test]
    fn discovery_defaults_when_section_absent() {
        let config: Config = toml::from_str(&base_toml()).unwrap();
        assert!(config.discovery.enabled);
        assert!(config.discovery.roots.is_empty());
        assert_eq!(config.discovery.max_entries_per_page, 250);
    }

    #[test]
    fn remote_config_defaults_to_tls_auto_when_fields_are_absent() {
        let config: Config = toml::from_str(&base_toml()).unwrap();
        assert!(matches!(config.remote.tls, TlsMode::Auto));
        assert!(!config.remote.allow_plaintext_lan);
        assert!(config.remote.tls_cert.is_none());
        assert!(config.remote.tls_key.is_none());
    }

    #[test]
    fn remote_config_accepts_tls_off() {
        let content = base_toml().replace(
            "max_request_size_mb = 10",
            "max_request_size_mb = 10\ntls = \"off\"\nallow_plaintext_lan = true",
        );
        let config: Config = toml::from_str(&content).unwrap();
        assert!(matches!(config.remote.tls, TlsMode::Off));
        assert!(config.remote.allow_plaintext_lan);
    }
}
