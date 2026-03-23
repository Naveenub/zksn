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
use zksn_node::{
    network,
    peers::{PeerDiscovery, PeerInfo},
};

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
        // Enforce Yggdrasil 200::/7 on listen_addr and entry_node.
        // A client binding or connecting outside Yggdrasil exposes the real IP.
        let enforce = config.yggdrasil_only;
        network::check_bind(&config.listen_addr, enforce)?;
        network::check_peer(&config.entry_node, enforce)?;

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

        let discovery = Arc::new(PeerDiscovery::new_with_enforcement(
            config.listen_addr.clone(),
            routing_pubkey,
            config.bootstrap_peers.clone(),
            config.peer_store_path.clone(),
            config.yggdrasil_only,
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
        let mut config = ClientConfig::default();
        config.yggdrasil_only = false; // disable for CI (no Yggdrasil)
        let client = ZksnClient::new(config).await.unwrap();
        assert_eq!(client.routing_pubkey_hex().len(), 64);
        assert_eq!(client.fingerprint().len(), 16);
    }

    #[tokio::test]
    async fn test_client_rejects_non_yggdrasil_listen_addr() {
        let config = ClientConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            yggdrasil_only: true,
            ..ClientConfig::default()
        };
        let err = ZksnClient::new(config).await.err().expect("should fail");
        assert!(err.to_string().contains("200::/7"));
    }

    #[tokio::test]
    async fn test_client_rejects_non_yggdrasil_entry_node() {
        let config = ClientConfig {
            listen_addr: "[200::1]:0".to_string(),
            entry_node: "192.168.1.1:9001".to_string(),
            yggdrasil_only: true,
            ..ClientConfig::default()
        };
        let err = ZksnClient::new(config).await.err().expect("should fail");
        assert!(err.to_string().contains("200::/7"));
    }

    #[tokio::test]
    async fn test_client_accepts_yggdrasil_listen_addr() {
        let config = ClientConfig {
            listen_addr: "[200::1]:0".to_string(),
            entry_node: "[200::2]:9001".to_string(),
            yggdrasil_only: true,
            ..ClientConfig::default()
        };
        // The check_bind should pass. Actual bind may fail in CI without Yggdrasil iface.
        match ZksnClient::new(config).await {
            Ok(_) => {}
            Err(e) => {
                assert!(
                    !e.to_string().contains("200::/7"),
                    "should not be rejected by Yggdrasil check: {e}"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_routing_pubkey_is_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("id.key").to_string_lossy().to_string();

        let id = ZksnIdentity::generate();
        std::fs::write(&key_path, id.to_secret_bytes()).unwrap();

        let cfg1 = ClientConfig {
            key_path: Some(key_path.clone()),
            yggdrasil_only: false,
            ..Default::default()
        };
        let cfg2 = ClientConfig {
            key_path: Some(key_path),
            yggdrasil_only: false,
            ..Default::default()
        };

        let c1 = ZksnClient::new(cfg1).await.unwrap();
        let c2 = ZksnClient::new(cfg2).await.unwrap();
        assert_eq!(c1.routing_pubkey(), c2.routing_pubkey());
    }

    #[tokio::test]
    async fn test_different_identities_have_different_routing_keys() {
        let cfg1 = ClientConfig {
            yggdrasil_only: false,
            ..ClientConfig::default()
        };
        let cfg2 = ClientConfig {
            yggdrasil_only: false,
            ..ClientConfig::default()
        };
        let c1 = ZksnClient::new(cfg1).await.unwrap();
        let c2 = ZksnClient::new(cfg2).await.unwrap();
        assert_ne!(c1.routing_pubkey(), c2.routing_pubkey());
    }

    #[tokio::test]
    async fn test_send_fails_without_peers() {
        let config = ClientConfig {
            entry_node: "127.0.0.1:19999".to_string(),
            bootstrap_peers: vec![],
            yggdrasil_only: false,
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
            yggdrasil_only: false,
            ..Default::default()
        };
        let client = ZksnClient::new(config).await.unwrap();
        assert!(client.receive().await.is_ok());
    }
}
