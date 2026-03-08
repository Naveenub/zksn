pub mod receive;
pub mod route;
pub mod send;

mod config;
pub use config::ClientConfig;

use anyhow::Result;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::mpsc;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zksn_crypto::identity::ZksnIdentity;
use zksn_node::peers::{PeerDiscovery, PeerInfo};

use crate::route::RouteSelector;

pub struct ZksnClient {
    identity: ZksnIdentity,
    config: ClientConfig,
    /// X25519 private key derived from Ed25519 seed (for Sphinx peeling).
    routing_privkey: [u8; 32],
    /// X25519 public key announced to the network.
    routing_pubkey: [u8; 32],
    /// Peer discovery + routing table.
    discovery: Arc<PeerDiscovery>,
    /// Route selector backed by the live peer table.
    selector: RouteSelector,
}

impl ZksnClient {
    /// Create a new client, start peer discovery, and announce self to the network.
    pub async fn new(config: ClientConfig) -> Result<Self> {
        // Load or generate Ed25519 identity
        let identity = if let Some(ref path) = config.key_path {
            let bytes = std::fs::read(path)?;
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes[..32]);
            ZksnIdentity::from_secret_bytes(key)
        } else {
            ZksnIdentity::generate()
        };

        // Derive X25519 routing keypair deterministically from Ed25519 seed
        let routing_privkey = derive_routing_key(&identity);
        let secret = StaticSecret::from(routing_privkey);
        let routing_pubkey: [u8; 32] = X25519PublicKey::from(&secret).to_bytes();

        // Peer discovery — announces this client's listen_addr + routing_pubkey
        let discovery = Arc::new(PeerDiscovery::new(
            config.listen_addr.clone(),
            routing_pubkey,
            config.bootstrap_peers.clone(),
            config.peer_store_path.clone(),
        ));

        // Start discovery in background
        let disc_run = Arc::clone(&discovery);
        tokio::spawn(async move {
            disc_run.run().await;
        });

        // Seed the peer table with the entry node if bootstrap_peers is empty
        if config.bootstrap_peers.is_empty() {
            discovery
                .table
                .upsert(PeerInfo::new(config.entry_node.clone(), [0u8; 32]))
                .await;
        }

        let selector = RouteSelector::new(Arc::clone(&discovery.table));

        Ok(Self {
            identity,
            config,
            routing_privkey,
            routing_pubkey,
            discovery,
            selector,
        })
    }

    /// Hex fingerprint of this client's Ed25519 identity.
    pub fn fingerprint(&self) -> String {
        self.identity.public().fingerprint()
    }

    /// X25519 public key used for Sphinx routing (= this client's mixnet address).
    pub fn routing_pubkey(&self) -> [u8; 32] {
        self.routing_pubkey
    }

    /// X25519 public key as hex string — share this with senders.
    pub fn routing_pubkey_hex(&self) -> String {
        hex::encode(self.routing_pubkey)
    }

    /// Send `payload` to `recipient_pubkey_hex` through the mixnet.
    pub async fn send(&self, recipient_pubkey_hex: &str, payload: &[u8]) -> Result<()> {
        let bytes = hex::decode(recipient_pubkey_hex)?;
        if bytes.len() != 32 {
            return Err(anyhow::anyhow!(
                "Recipient pubkey must be 32 bytes hex (64 chars)"
            ));
        }
        let mut recipient = [0u8; 32];
        recipient.copy_from_slice(&bytes);

        send::send_message(&self.selector, recipient, payload, self.config.hop_count).await
    }

    /// Start listening for incoming messages.
    /// Returns a channel that delivers decrypted message payloads.
    pub async fn receive(&self) -> Result<mpsc::Receiver<Vec<u8>>> {
        receive::start_receiver(self.routing_privkey, &self.config.listen_addr).await
    }

    /// Number of live peers currently in the routing table.
    pub async fn peer_count(&self) -> usize {
        self.discovery.table.len().await
    }
}

/// Derive an X25519 private key from an Ed25519 seed.
/// SHA-256("zksn-routing-v1" || ed25519_seed_bytes)
fn derive_routing_key(identity: &ZksnIdentity) -> [u8; 32] {
    let seed = identity.to_secret_bytes();
    let mut h = Sha256::new();
    h.update(b"zksn-routing-v1");
    h.update(seed);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_client_creates_with_default_config() {
        let config = ClientConfig::default();
        let client = ZksnClient::new(config).await.unwrap();
        assert_eq!(client.routing_pubkey_hex().len(), 64);
        assert_eq!(client.fingerprint().len(), 16);
    }

    #[tokio::test]
    async fn test_routing_pubkey_is_deterministic() {
        // Two clients with the same key file should produce the same routing pubkey
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("id.key").to_string_lossy().to_string();

        let id = ZksnIdentity::generate();
        std::fs::write(&key_path, id.to_secret_bytes()).unwrap();

        let cfg1 = ClientConfig {
            key_path: Some(key_path.clone()),
            ..Default::default()
        };
        let cfg2 = ClientConfig {
            key_path: Some(key_path),
            ..Default::default()
        };

        let c1 = ZksnClient::new(cfg1).await.unwrap();
        let c2 = ZksnClient::new(cfg2).await.unwrap();
        assert_eq!(c1.routing_pubkey(), c2.routing_pubkey());
    }

    #[tokio::test]
    async fn test_different_identities_have_different_routing_keys() {
        let cfg1 = ClientConfig::default();
        let cfg2 = ClientConfig::default();
        let c1 = ZksnClient::new(cfg1).await.unwrap();
        let c2 = ZksnClient::new(cfg2).await.unwrap();
        assert_ne!(c1.routing_pubkey(), c2.routing_pubkey());
    }

    #[tokio::test]
    async fn test_send_fails_without_peers() {
        // Give entry_node a blank key so it won't be usable for sphinx
        let config = ClientConfig {
            entry_node: "127.0.0.1:19999".to_string(),
            bootstrap_peers: vec![],
            ..Default::default()
        };
        let client = ZksnClient::new(config).await.unwrap();
        // With no real peers, send should return an error (not panic)
        let result = client.send(&"aa".repeat(32), b"test").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_receive_binds_successfully() {
        let config = ClientConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            ..Default::default()
        };
        let client = ZksnClient::new(config).await.unwrap();
        assert!(client.receive().await.is_ok());
    }
}
