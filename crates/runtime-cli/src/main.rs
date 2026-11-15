//! YL Agent Runtime CLI entry point
//!
//! Diagnostics, pairing, and administration per PRD section 6.2.

use clap::Parser;
use runtime_cli::commands;
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
    /// Pair a new device
    Pair {
        #[arg(short, long)]
        device_name: Option<String>,
    },
    /// List registered devices
    ListDevices,
    /// Revoke a device
    RevokeDevice {
        device_id: String,
    },
    /// Register a workspace
    RegisterWorkspace {
        path: String,
    },
    /// Run the MCP server
    Mcp {
        #[arg(short, long, default_value = "stdio")]
        transport: String,
    },
}

mod commands;

#[tokio::main]
async fn main() {
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
        Commands::Pair { device_name } => {
            commands::pair_device(device_name.as_deref()).await;
        }
        Commands::ListDevices => {
            commands::list_devices().await;
        }
        Commands::RevokeDevice { device_id } => {
            commands::revoke_device(&device_id).await;
        }
        Commands::RegisterWorkspace { path } => {
            commands::register_workspace(&path).await;
        }
        Commands::Mcp { transport } => {
            commands::run_mcp_server(&transport).await;
        }
    }
}