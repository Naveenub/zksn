//! # ZKSN CLI — `zksn`
//!
//! Command-line interface for the Zero-Knowledge Sovereign Network.
//!
//! ## Commands
//!
//! ```
//! zksn identity generate          # Create a new keypair identity
//! zksn identity show              # Display current identity fingerprint
//! zksn send <recipient> <message> # Send an encrypted message
//! zksn receive                    # Listen for incoming messages
//! zksn wallet balance             # Show Cashu token balance
//! zksn wallet topup               # Acquire tokens from mint (via XMR)
//! ```

use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use tracing_subscriber::EnvFilter;

use zksn_client::{ClientConfig, ZksnClient};

#[derive(Parser)]
#[command(name = "zksn")]
#[command(about = "Zero-Knowledge Sovereign Network CLI")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Path to identity key file
    #[arg(short, long, global = true)]
    key: Option<String>,

    /// Entry mix node address
    #[arg(short, long, global = true, default_value = "[::1]:9001")]
    node: String,

    /// Enable debug logging
    #[arg(short, long, global = true)]
    debug: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Identity management
    Identity {
        #[command(subcommand)]
        action: IdentityCommands,
    },

    /// Send an encrypted message
    Send {
        /// Recipient public key (64 hex characters)
        recipient: String,

        /// Message to send (UTF-8 text)
        message: String,
    },

    /// Receive incoming messages (blocks until Ctrl+C)
    Receive,

    /// Wallet and payment management
    Wallet {
        #[command(subcommand)]
        action: WalletCommands,
    },
}

#[derive(Subcommand)]
enum IdentityCommands {
    /// Generate a new keypair identity
    Generate {
        /// Save key to this file path
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Show current identity fingerprint
    Show,
}

#[derive(Subcommand)]
enum WalletCommands {
    /// Show Cashu token balance
    Balance,
    /// Top up token balance (requires XMR)
    Topup {
        /// Amount in millisats
        amount: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                EnvFilter::new(if cli.debug { "debug" } else { "warn" })
            }),
        )
        .with_target(false)
        .compact()
        .init();

    let config = ClientConfig {
        key_path: cli.key.clone(),
        entry_node: cli.node.clone(),
        ..ClientConfig::default()
    };

    match cli.command {
        Commands::Identity { action } => handle_identity(action, &config).await,
        Commands::Send { recipient, message } => {
            let client = ZksnClient::new(config).await?;
            println!("{}", "Sending message...".dimmed());
            client.send(&recipient, message.as_bytes()).await?;
            println!("{}", "✓ Message sent".green());
            Ok(())
        }
        Commands::Receive => {
            let client = ZksnClient::new(config).await?;
            println!(
                "{}  {}",
                "Listening for messages as:".dimmed(),
                client.fingerprint().cyan()
            );
            println!("{}", "Press Ctrl+C to stop.".dimmed());

            let mut rx = client.receive().await?;
            while let Some(payload) = rx.recv().await {
                let msg = String::from_utf8_lossy(&payload);
                println!("\n{} {}", "▶ Message received:".green().bold(), msg);
            }
            Ok(())
        }
        Commands::Wallet { action } => handle_wallet(action, &config).await,
    }
}

async fn handle_identity(action: IdentityCommands, config: &ClientConfig) -> Result<()> {
    use zksn_crypto::identity::ZksnIdentity;
    use zeroize::Zeroize;

    match action {
        IdentityCommands::Generate { output } => {
            let identity = ZksnIdentity::generate();
            let public = identity.public();

            println!("\n{}", "═══ ZKSN Identity Generated ═══".cyan().bold());
            println!("{} {}", "Fingerprint:".dimmed(), public.fingerprint().yellow());
            println!("{} {}", "Public key: ".dimmed(),
                hex::encode(public.as_bytes()).green());

            if let Some(path) = output {
                let mut secret = identity.to_secret_bytes();
                std::fs::write(&path, &secret)?;
                secret.zeroize();
                println!("{} {}", "Saved to:   ".dimmed(), path.cyan());
            } else {
                println!("\n{}", "⚠ Key NOT saved — pass --output <path> to save".yellow());
            }

            println!("\n{}", "Share your fingerprint or public key so others can send you messages.".dimmed());
        }
        IdentityCommands::Show => {
            let client = ZksnClient::new(config.clone()).await?;
            println!("{} {}", "Identity:".dimmed(), client.fingerprint().cyan());
        }
    }
    Ok(())
}

async fn handle_wallet(action: WalletCommands, _config: &ClientConfig) -> Result<()> {
    match action {
        WalletCommands::Balance => {
            // TODO: query Cashu mint for token balance
            println!("{}", "Wallet balance: (not yet implemented — see economic/src/cashu.rs)".yellow());
        }
        WalletCommands::Topup { amount } => {
            println!("Top-up {amount} millisats: (not yet implemented — see economic/src/cashu.rs)");
        }
    }
    Ok(())
}
