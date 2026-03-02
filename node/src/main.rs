//! # ZKSN Mix Node — Entry Point
//!
//! Starts a mix node that:
//!   1. Loads or generates a node identity
//!   2. Binds to the configured listen address
//!   3. Joins the Yggdrasil/CJDNS mesh
//!   4. Accepts Sphinx packets, delays them (Poisson), and forwards them
//!   5. Emits continuous cover traffic (LOOP + DROP messages)
//!   6. Accepts Cashu token payments per packet

use anyhow::Result;
use clap::Parser;
use tracing::{info, warn};
use tracing_subscriber::{fmt, EnvFilter};

use zksn_node::{
    config::NodeConfig,
    node::MixNode,
};

/// ZKSN Mix Node
#[derive(Parser, Debug)]
#[command(name = "zksn-node")]
#[command(about = "Zero-Knowledge Sovereign Network — Mix Node", long_about = None)]
#[command(version)]
struct Cli {
    /// Path to node configuration file
    #[arg(short, long, default_value = "node.toml")]
    config: String,

    /// Override listen address (e.g. [::1]:9001)
    #[arg(short, long)]
    listen: Option<String>,

    /// Enable verbose debug logging
    #[arg(short, long)]
    debug: bool,

    /// Run in test mode (no real payments required)
    #[arg(long)]
    testnet: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing/logging
    let log_level = if cli.debug { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(format!("zksn_node={log_level},warn")))
        )
        .with_target(false)
        .compact()
        .init();

    info!("╔══════════════════════════════════════╗");
    info!("║   ZKSN Mix Node — Starting Up        ║");
    info!("╚══════════════════════════════════════╝");

    if cli.testnet {
        warn!("Running in TESTNET mode — payments not enforced");
    }

    // Load configuration
    let mut config = NodeConfig::load(&cli.config).unwrap_or_else(|_| {
        info!("No config file found at '{}' — using defaults", cli.config);
        NodeConfig::default()
    });

    // CLI overrides
    if let Some(addr) = cli.listen {
        config.network.listen_addr = addr;
    }
    config.testnet = cli.testnet;

    info!("Node ID:      {}", config.identity.fingerprint());
    info!("Listen addr:  {}", config.network.listen_addr);
    info!("Poisson λ:    {}ms average delay", config.mixing.poisson_lambda_ms);
    info!("Cover rate:   {} packets/sec", config.mixing.cover_traffic_rate);

    // Build and run the mix node
    let node = MixNode::new(config).await?;
    node.run().await?;

    Ok(())
}
