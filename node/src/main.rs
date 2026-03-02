//! # ZKSN Mix Node — Entry Point

use anyhow::Result;
use clap::Parser;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use zksn_node::{config::NodeConfig, node::MixNode};

#[derive(Parser, Debug)]
#[command(name = "zksn-node")]
#[command(about = "Zero-Knowledge Sovereign Network — Mix Node")]
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

    /// Disable payment enforcement (testing only)
    #[arg(long)]
    testnet: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

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
        warn!("TESTNET mode — payments not enforced");
    }

    let mut config = NodeConfig::load(&cli.config).unwrap_or_else(|_| {
        info!("No config at '{}' — using defaults", cli.config);
        NodeConfig::default()
    });

    if let Some(addr) = cli.listen {
        config.network.listen_addr = addr;
    }
    config.testnet = cli.testnet;

    info!("Node ID:     {}", config.identity.fingerprint());
    info!("Listen:      {}", config.network.listen_addr);
    info!("Poisson λ:   {}ms", config.mixing.poisson_lambda_ms);
    info!("Cover rate:  {} pkt/s", config.mixing.cover_traffic_rate);
    info!("Testnet:     {}", config.testnet);

    MixNode::new(config).await?.run().await
}
