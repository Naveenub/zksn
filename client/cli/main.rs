use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use tracing_subscriber::EnvFilter;
use zksn_client::{ClientConfig, ZksnClient};

#[derive(Parser)]
#[command(name = "zksn", about = "Zero-Knowledge Sovereign Network CLI", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    #[arg(short, long, global = true)]
    key: Option<String>,
    #[arg(short, long, global = true, default_value = "[::1]:9001")]
    node: String,
    #[arg(short, long, global = true)]
    debug: bool,
    /// Disable Yggdrasil 200::/7 enforcement (development / demo only).
    /// Allows plain TCP addresses instead of requiring a Yggdrasil overlay.
    #[arg(long, global = true)]
    testnet: bool,
    /// TCP address this client listens on for incoming messages.
    /// Defaults to a random OS-assigned port when set to [::]:0.
    #[arg(long, global = true)]
    listen: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    Identity {
        #[command(subcommand)]
        action: IdentityCmd,
    },
    Send {
        recipient: String,
        message: String,
    },
    Receive,
    Wallet {
        #[command(subcommand)]
        action: WalletCmd,
    },
}

#[derive(Subcommand)]
enum IdentityCmd {
    Generate {
        #[arg(short, long)]
        output: Option<String>,
    },
    Show,
}

#[derive(Subcommand)]
enum WalletCmd {
    Balance,
    Topup { amount: u64 },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(if cli.debug { "debug" } else { "warn" })),
        )
        .with_target(false)
        .compact()
        .init();

    let config = ClientConfig {
        key_path: cli.key.clone(),
        entry_node: cli.node.clone(),
        listen_addr: cli
            .listen
            .clone()
            .unwrap_or_else(|| "[::1]:9002".to_string()),
        yggdrasil_only: !cli.testnet,
        ..ClientConfig::default()
    };

    match cli.command {
        Commands::Identity { action } => handle_identity(action, &config).await,
        Commands::Send { recipient, message } => {
            let client = ZksnClient::new(config).await?;
            println!("{}", "Sending...".dimmed());
            client.send(&recipient, message.as_bytes()).await?;
            println!("{}", "✓ Sent".green());
            Ok(())
        }
        Commands::Receive => {
            let client = ZksnClient::new(config).await?;
            println!(
                "{} {}",
                "Listening as:".dimmed(),
                client.fingerprint().cyan()
            );
            let mut rx = client.receive().await?;
            while let Some(payload) = rx.recv().await {
                println!(
                    "{} {}",
                    "▶".green().bold(),
                    String::from_utf8_lossy(&payload)
                );
            }
            Ok(())
        }
        Commands::Wallet { action } => {
            match action {
                WalletCmd::Balance => {
                    println!("{}", "Balance: (see economic/src/cashu.rs)".yellow())
                }
                WalletCmd::Topup { amount } => {
                    println!("Topup {amount}: (see economic/src/cashu.rs)")
                }
            }
            Ok(())
        }
    }
}

async fn handle_identity(action: IdentityCmd, config: &ClientConfig) -> Result<()> {
    use zeroize::Zeroize;
    use zksn_crypto::identity::ZksnIdentity;
    match action {
        IdentityCmd::Generate { output } => {
            let id = ZksnIdentity::generate();
            let pub_ = id.public();
            println!("\n{}", "═══ ZKSN Identity ═══".cyan().bold());
            println!(
                "{} {}",
                "Fingerprint:".dimmed(),
                pub_.fingerprint().yellow()
            );
            println!(
                "{} {}",
                "Public key: ".dimmed(),
                hex::encode(pub_.as_bytes()).green()
            );
            if let Some(path) = output {
                let mut s = id.to_secret_bytes();
                std::fs::write(&path, &s)?;
                s.zeroize();
                println!("{} {}", "Saved:".dimmed(), path.cyan());
            } else {
                println!("{}", "⚠ Pass --output <path> to save".yellow());
            }
        }
        IdentityCmd::Show => {
            let c = ZksnClient::new(config.clone()).await?;
            println!("{} {}", "Identity:".dimmed(), c.fingerprint().cyan());
        }
    }
    Ok(())
}
