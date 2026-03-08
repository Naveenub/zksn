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
    routing_privkey: [u8; 32],
    routing_pubkey: [u8; 32],
    discovery: Arc<PeerDiscovery>,
    selector: RouteSelector,
}

impl ZksnClient {
    pub async fn new(config: ClientConfig) -> Result<Self> {
        let identity = if let Some(ref path) = config.key_path {
            let bytes = std::fs::read(path)?;
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes[..32]);
            ZksnIdentity::from_secret_bytes(key)
        } else {
            ZksnIdentity::generate()
        };

        let routing_privkey = derive_routing_key(&identity);
        let secret = StaticSecret::from(routing_privkey);
        let routing_pubkey: [u8; 32] = X25519PublicKey::from(&secret).to_bytes();

        let discovery = Arc::new(PeerDiscovery::new(
            config.listen_addr.clone(),
            routing_pubkey,
            config.bootstrap_peers.clone(),
            config.peer_store_path.clone(),
        ));

        let disc_run = Arc::clone(&discovery);
        tokio::spawn(async move {
            disc_run.run().await;
        });

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

    pub fn fingerprint(&self) -> String {
        self.identity.public().fingerprint()
    }

    pub fn routing_pubkey(&self) -> [u8; 32] {
        self.routing_pubkey
    }

    pub fn routing_pubkey_hex(&self) -> String {
        hex::encode(self.routing_pubkey)
    }

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

    pub async fn receive(&self) -> Result<mpsc::Receiver<Vec<u8>>> {
        receive::start_receiver(self.routing_privkey, &self.config.listen_addr).await
    }

    pub async fn peer_count(&self) -> usize {
        self.discovery.table.len().await
    }
}

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
        let config = ClientConfig {
            bootstrap_peers: vec![],
            ..Default::default()
        };
        // Give entry_node a blank key so it won't be usable for sphinx
        let config = ClientConfig {
            entry_node: "127.0.0.1:19999".to_string(),
            bootstrap_peers: vec![],
            ..Default::default()
        };
        let client = ZksnClient::new(config).await.unwrap();
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
