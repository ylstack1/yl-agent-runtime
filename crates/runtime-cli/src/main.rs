//! YL Agent Runtime CLI entry point
//!
//! Diagnostics, pairing, and administration per PRD section 6.2.

use clap::Parser;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

#[derive(Parser, Debug)]
#[command(author, version, about = "YL Agent Runtime CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Start the runtime daemon
    Start {
        #[arg(short, long, default_value = "./config/runtime.toml")]
        config: String,
    },
    /// Check runtime status and capabilities
    Status,
    /// Discover installed toolchains
    DiscoverTools,
    /// Pairing: request/approve/reject/status/authenticate remote devices
    #[command(subcommand)]
    Pairing(PairingAction),
    /// List registered devices
    ListDevices,
    /// Revoke a device
    RevokeDevice {
        device_id: String,
    },
    /// Paired devices: list or revoke
    #[command(subcommand)]
    Devices(DevicesAction),
    /// Register a workspace
    RegisterWorkspace {
        path: String,
    },
    /// Run the MCP server
    Mcp {
        #[arg(long = "root")]
        roots: Vec<String>,
        #[arg(long = "read-only-root")]
        read_only_roots: Vec<String>,
        #[arg(long)]
        config: Option<String>,
        #[arg(long)]
        yolo: bool,
    },
    /// Execute a command in a workspace
    Exec {
        #[arg(long)]
        project: String,
        #[arg(long)]
        program: String,
        #[arg(long)]
        args: Vec<String>,
        #[arg(long)]
        approve: bool,
        #[arg(long)]
        timeout: Option<u64>,
    },
    /// Run the MCP server over Streamable HTTP (remote access)
    Serve {
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        #[arg(short, long, default_value = "8077")]
        port: u16,
        #[arg(long)]
        allow_remote: bool,
        #[arg(long)]
        yolo: bool,
        #[arg(long = "root")]
        roots: Vec<String>,
    },
    /// Discovery roots: list, browse, detect projects under authorized roots.
    #[command(subcommand)]
    Discovery(DiscoveryAction),
    /// Workspace registry: list, register, unregister, create workspaces.
    #[command(subcommand)]
    Workspace(WorkspaceAction),
    /// Manage approval requests (approve/reject/list pending approvals)
    Approval {
        #[command(subcommand)]
        action: ApprovalAction,
    },
}

mod commands;
mod tls;

use commands::{ApprovalAction, DevicesAction, DiscoveryAction, PairingAction, WorkspaceAction};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(EnvFilter::from_default_env())
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    let cli = Cli::parse();

    match cli.command {
        Commands::Start { config } => {
            println!("Starting YL Agent Runtime with config: {}", config);
            commands::start_daemon(&config).await;
        }
        Commands::Status => {
            commands::show_status().await;
        }
        Commands::DiscoverTools => {
            commands::discover_tools().await;
        }
        Commands::Pairing(action) => {
            commands::run_pairing(action).await?;
        }
        Commands::ListDevices => {
            commands::list_devices().await;
        }
        Commands::RevokeDevice { device_id } => {
            commands::revoke_device(&device_id).await;
        }
        Commands::Devices(action) => match action {
            DevicesAction::List => commands::list_devices().await,
            DevicesAction::Revoke { device_id } => commands::revoke_device(&device_id).await,
        },
        Commands::RegisterWorkspace { path } => {
            commands::register_workspace(&path).await;
        }
        Commands::Mcp {
            roots,
            read_only_roots,
            config,
            yolo,
        } => {
            commands::run_mcp_server(commands::McpOptions {
                roots,
                read_only_roots,
                config,
                yolo,
            })
            .await?;
        }
        Commands::Exec {
            project,
            program,
            args,
            approve,
            timeout,
        } => {
            commands::exec_command(&project, &program, args, approve, timeout).await?;
        }
        Commands::Serve {
            host,
            port,
            allow_remote,
            yolo,
            roots,
        } => {
            commands::run_http_server(host, port, allow_remote, yolo, roots).await?;
        }
        Commands::Discovery(action) => {
            commands::run_discovery(action).await?;
        }
        Commands::Workspace(action) => {
            commands::run_workspace(action).await?;
        }
        Commands::Approval { action } => {
            commands::run_approval(action).await?;
        }
    }
    Ok(())
}
