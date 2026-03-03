use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use zksn_crypto::identity::ZksnIdentity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub network:  NetworkConfig,
    pub mixing:   MixingConfig,
    pub economic: EconomicConfig,
    pub keys:     KeyConfig,
    #[serde(default)]
    pub testnet: bool,
    #[serde(skip)]
    pub identity: IdentityHolder,
}

impl NodeConfig {
    pub fn load(path: &str) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let mut config: NodeConfig = toml::from_str(&contents)?;
        config.identity = IdentityHolder::load_or_generate(&config.keys)?;
        Ok(config)
    }
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            network: NetworkConfig::default(), mixing: MixingConfig::default(),
            economic: EconomicConfig::default(), keys: KeyConfig::default(),
            testnet: false, identity: IdentityHolder::generate(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub listen_addr: String,
    pub max_peers: usize,
    pub connect_timeout_ms: u64,
    pub bootstrap_peers: Vec<String>,
}
impl Default for NetworkConfig {
    fn default() -> Self {
        Self { listen_addr: "[::1]:9001".to_string(), max_peers: 64,
               connect_timeout_ms: 5_000, bootstrap_peers: vec![] }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MixingConfig {
    pub poisson_lambda_ms:   u64,
    pub cover_traffic_rate:  u32,
    pub max_queue_depth:     usize,
    pub loop_cover_fraction: f32,
}
impl Default for MixingConfig {
    fn default() -> Self {
        Self { poisson_lambda_ms: 200, cover_traffic_rate: 5,
               max_queue_depth: 10_000, loop_cover_fraction: 0.3 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicConfig {
    pub cashu_mint_url: String, pub min_token_value: u64,
    pub monero_rpc_url: String, pub redemption_batch_size: usize,
}
impl Default for EconomicConfig {
    fn default() -> Self {
        Self { cashu_mint_url: "http://mint.zksn.internal:3338".to_string(),
               min_token_value: 1, monero_rpc_url: "http://127.0.0.1:18082".to_string(),
               redemption_batch_size: 100 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyConfig {
    pub key_store_path: String,
    pub persist_identity: bool,
}
impl Default for KeyConfig {
    fn default() -> Self {
        Self { key_store_path: "/var/lib/zksn/keys/identity.key".to_string(),
               persist_identity: false }
    }
}

pub struct IdentityHolder { identity: ZksnIdentity }
impl IdentityHolder {
    pub fn generate() -> Self { Self { identity: ZksnIdentity::generate() } }
    pub fn load_or_generate(config: &KeyConfig) -> Result<Self> {
        if config.persist_identity && Path::new(&config.key_store_path).exists() {
            let bytes = std::fs::read(&config.key_store_path)?;
            if bytes.len() >= 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes[..32]);
                return Ok(Self { identity: ZksnIdentity::from_secret_bytes(key) });
            }
        }
        Ok(Self::generate())
    }
    pub fn fingerprint(&self) -> String { self.identity.public().fingerprint() }
    pub fn identity(&self) -> &ZksnIdentity { &self.identity }
}
impl std::fmt::Debug for IdentityHolder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IdentityHolder({})", self.fingerprint())
    }
}
impl Clone for IdentityHolder {
    fn clone(&self) -> Self {
        let bytes = self.identity.to_secret_bytes();
        Self { identity: ZksnIdentity::from_secret_bytes(bytes) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test] fn test_default_config() {
        let c = NodeConfig::default();
        assert_eq!(c.mixing.poisson_lambda_ms, 200);
        assert!(!c.testnet);
    }
    #[test] fn test_identity_unique() {
        let a = IdentityHolder::generate();
        let b = IdentityHolder::generate();
        assert_ne!(a.fingerprint(), b.fingerprint());
    }
    #[test] fn test_identity_clone() {
        let a = IdentityHolder::generate();
        assert_eq!(a.fingerprint(), a.clone().fingerprint());
    }
    #[test] fn test_load_from_file() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "[network]\nlisten_addr=\"127.0.0.1:9001\"\nmax_peers=32\nconnect_timeout_ms=3000\nbootstrap_peers=[]\n[mixing]\npoisson_lambda_ms=500\ncover_traffic_rate=2\nmax_queue_depth=5000\nloop_cover_fraction=0.4\n[economic]\ncashu_mint_url=\"http://localhost:3338\"\nmin_token_value=1\nmonero_rpc_url=\"http://127.0.0.1:18082\"\nredemption_batch_size=50\n[keys]\nkey_store_path=\"/tmp/k\"\npersist_identity=false").unwrap();
        let c = NodeConfig::load(tmp.path().to_str().unwrap()).unwrap();
        assert_eq!(c.mixing.poisson_lambda_ms, 500);
    }
}
