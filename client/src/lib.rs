//! # ZKSN Client Library
//!
//! Provides a high-level API for sending and receiving messages over the
//! Zero-Knowledge Sovereign Network.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use zksn_client::{ZksnClient, ClientConfig};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let config = ClientConfig::default();
//!     let client = ZksnClient::new(config).await?;
//!
//!     // Send a message
//!     client.send(
//!         "recipient_public_key_hex",
//!         b"Hello, sovereign world!"
//!     ).await?;
//!
//!     Ok(())
//! }
//! ```

pub mod send;
pub mod receive;
pub mod config;
pub mod route;

use anyhow::Result;
use tracing::info;
use zksn_crypto::identity::{ZksnIdentity, PublicIdentity};

pub use config::ClientConfig;

/// A ZKSN client session.
///
/// Owns a keypair identity and manages message sending/receiving
/// through the mix network.
pub struct ZksnClient {
    pub config: ClientConfig,
    identity: ZksnIdentity,
}

impl ZksnClient {
    /// Create a new client with the given configuration.
    pub async fn new(config: ClientConfig) -> Result<Self> {
        let identity = if let Some(ref key_path) = config.key_path {
            let bytes = std::fs::read(key_path)?;
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes[..32]);
            ZksnIdentity::from_secret_bytes(key)
        } else {
            ZksnIdentity::generate()
        };

        info!("Client identity: {}", identity.public().fingerprint());

        Ok(Self { config, identity })
    }

    /// Your public identity — share this with others so they can send you messages.
    pub fn public_identity(&self) -> PublicIdentity {
        self.identity.public()
    }

    /// Your identity fingerprint — the human-readable form of your public key.
    pub fn fingerprint(&self) -> String {
        self.identity.public().fingerprint()
    }

    /// Send an encrypted message to a recipient identified by their public key.
    ///
    /// The message is:
    /// 1. Encrypted for the recipient's public key (X25519 + ChaCha20-Poly1305)
    /// 2. Wrapped in a Sphinx packet with a random route through the mixnet
    /// 3. Submitted to the first mix node with a Cashu payment token
    pub async fn send(&self, recipient_pubkey_hex: &str, payload: &[u8]) -> Result<()> {
        send::send_message(&self.identity, recipient_pubkey_hex, payload, &self.config).await
    }

    /// Listen for incoming messages addressed to this identity.
    ///
    /// Returns a stream of decrypted message payloads.
    pub async fn receive(&self) -> Result<tokio::sync::mpsc::Receiver<Vec<u8>>> {
        receive::start_receiver(&self.identity, &self.config).await
    }
}
