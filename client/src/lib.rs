pub mod receive;
pub mod route;
pub mod send;

mod config;
pub use config::ClientConfig;

use anyhow::Result;
use tokio::sync::mpsc;
use zksn_crypto::identity::ZksnIdentity;

pub struct ZksnClient {
    identity: ZksnIdentity,
    config: ClientConfig,
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
        Ok(Self { identity, config })
    }

    pub fn fingerprint(&self) -> String {
        self.identity.public().fingerprint()
    }

    pub async fn send(&self, recipient_hex: &str, payload: &[u8]) -> Result<()> {
        send::send_message(&self.identity, recipient_hex, payload, &self.config).await
    }

    pub async fn receive(&self) -> Result<mpsc::Receiver<Vec<u8>>> {
        receive::start_receiver(&self.identity, &self.config).await
    }
}
