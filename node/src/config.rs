use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use zksn_crypto::identity::ZksnIdentity;
use crate::i2p::I2pConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub network: NetworkConfig,
    pub mixing: MixingConfig,
    pub economic: EconomicConfig,
    pub keys: KeyConfig,
    /// I2P internal service layer configuration.
    #[serde(default)]
    pub i2p: I2pConfig,
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

    /// Returns true if Yggdrasil enforcement is active.
    ///
    /// Enforcement is disabled when:
    ///   - `testnet = true`  (development / CI)
    ///   - `network.yggdrasil_only = false`  (explicit opt-out)
    pub fn enforce_yggdrasil(&self) -> bool {
        self.network.yggdrasil_only && !self.testnet
    }
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            network: NetworkConfig::default(),
            mixing: MixingConfig::default(),
            economic: EconomicConfig::default(),
            keys: KeyConfig::default(),
            i2p: I2pConfig::default(),
            testnet: false,
            identity: IdentityHolder::generate(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub listen_addr: String,
    pub max_peers: usize,
    pub connect_timeout_ms: u64,
    pub bootstrap_peers: Vec<String>,
    /// Enforce that all addresses (bind + peers) fall inside the Yggdrasil
    /// `200::/7` prefix.  Set `false` only for development / testnet.
    /// Default: `true`.
    #[serde(default = "default_yggdrasil_only")]
    pub yggdrasil_only: bool,
}

fn default_yggdrasil_only() -> bool {
    true
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addr: "[::1]:9001".to_string(),
            max_peers: 64,
            connect_timeout_ms: 5_000,
            bootstrap_peers: vec![],
            yggdrasil_only: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MixingConfig {
    pub poisson_lambda_ms: u64,
    pub cover_traffic_rate: u32,
    pub max_queue_depth: usize,
    pub loop_cover_fraction: f32,
}
impl Default for MixingConfig {
    fn default() -> Self {
        Self {
            poisson_lambda_ms: 200,
            cover_traffic_rate: 5,
            max_queue_depth: 10_000,
            loop_cover_fraction: 0.3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicConfig {
    pub cashu_mint_url: String,
    pub min_token_value: u64,
    pub monero_rpc_url: String,
    pub redemption_batch_size: usize,
    /// Path to the node wallet JSON store.  `None` = in-memory only (lost on
    /// restart).  Set to a persistent path in production so earned proofs
    /// survive restarts.
    pub wallet_store_path: Option<String>,
}
impl Default for EconomicConfig {
    fn default() -> Self {
        Self {
            cashu_mint_url: "http://mint.zksn.internal:3338".to_string(),
            min_token_value: 1,
            monero_rpc_url: "http://127.0.0.1:18082".to_string(),
            redemption_batch_size: 100,
            wallet_store_path: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyConfig {
    pub key_store_path: String,
    pub persist_identity: bool,
}
impl Default for KeyConfig {
    fn default() -> Self {
        Self {
            key_store_path: "/var/lib/zksn/keys/identity.key".to_string(),
            persist_identity: false,
        }
    }
}

pub struct IdentityHolder {
    identity: ZksnIdentity,
}
impl IdentityHolder {
    pub fn generate() -> Self {
        Self {
            identity: ZksnIdentity::generate(),
        }
    }
    pub fn load_or_generate(config: &KeyConfig) -> Result<Self> {
        if config.persist_identity && Path::new(&config.key_store_path).exists() {
            let bytes = std::fs::read(&config.key_store_path)?;
            if bytes.len() >= 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes[..32]);
                return Ok(Self {
                    identity: ZksnIdentity::from_secret_bytes(key),
                });
            }
        }
        Ok(Self::generate())
    }
    pub fn fingerprint(&self) -> String {
        self.identity.public().fingerprint()
    }
    pub fn identity(&self) -> &ZksnIdentity {
        &self.identity
    }

    /// Derive a deterministic X25519 private key for Sphinx routing.
    /// SHA-256("zksn-routing-v1" || ed25519_secret_bytes)
    pub fn routing_private_key(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let secret = self.identity.to_secret_bytes();
        let mut h = Sha256::new();
        h.update(b"zksn-routing-v1");
        h.update(secret);
        h.finalize().into()
    }

    /// X25519 public key corresponding to the routing private key.
    pub fn routing_public_key(&self) -> [u8; 32] {
        use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
        let privkey = self.routing_private_key();
        let sk = StaticSecret::from(privkey);
        X25519PublicKey::from(&sk).to_bytes()
    }
}
impl std::fmt::Debug for IdentityHolder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IdentityHolder({})", self.fingerprint())
    }
}
impl Clone for IdentityHolder {
    fn clone(&self) -> Self {
        let bytes = self.identity.to_secret_bytes();
        Self {
            identity: ZksnIdentity::from_secret_bytes(bytes),
        }
    }
}
impl Default for IdentityHolder {
    fn default() -> Self {
        Self::generate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_default_config() {
        let c = NodeConfig::default();
        assert_eq!(c.mixing.poisson_lambda_ms, 200);
        assert!(!c.testnet);
        assert!(c.network.yggdrasil_only);
    }

    #[test]
    fn test_enforce_yggdrasil_logic() {
        let mut c = NodeConfig::default();
        // Default: yggdrasil_only=true, testnet=false → enforce
        assert!(c.enforce_yggdrasil());

        // testnet=true → no enforcement regardless of yggdrasil_only
        c.testnet = true;
        assert!(!c.enforce_yggdrasil());

        // yggdrasil_only=false, testnet=false → no enforcement
        c.testnet = false;
        c.network.yggdrasil_only = false;
        assert!(!c.enforce_yggdrasil());
    }

    #[test]
    fn test_identity_unique() {
        let a = IdentityHolder::generate();
        let b = IdentityHolder::generate();
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn test_identity_clone() {
        let a = IdentityHolder::generate();
        assert_eq!(a.fingerprint(), a.clone().fingerprint());
    }

    #[test]
    fn test_load_from_file() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "[network]\nlisten_addr=\"127.0.0.1:9001\"\nmax_peers=32\nconnect_timeout_ms=3000\nbootstrap_peers=[]\nyggdrasil_only=false\n[mixing]\npoisson_lambda_ms=500\ncover_traffic_rate=2\nmax_queue_depth=5000\nloop_cover_fraction=0.4\n[economic]\ncashu_mint_url=\"http://localhost:3338\"\nmin_token_value=1\nmonero_rpc_url=\"http://127.0.0.1:18082\"\nredemption_batch_size=50\n[keys]\nkey_store_path=\"/tmp/k\"\npersist_identity=false").unwrap();
        let c = NodeConfig::load(tmp.path().to_str().unwrap()).unwrap();
        assert_eq!(c.mixing.poisson_lambda_ms, 500);
        assert!(!c.network.yggdrasil_only);
        assert!(!c.enforce_yggdrasil());
    }

    #[test]
    fn test_yggdrasil_only_defaults_true_when_absent_from_toml() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        // No yggdrasil_only field → serde default kicks in
        writeln!(tmp, "[network]\nlisten_addr=\"[200::1]:9001\"\nmax_peers=32\nconnect_timeout_ms=3000\nbootstrap_peers=[]\n[mixing]\npoisson_lambda_ms=200\ncover_traffic_rate=5\nmax_queue_depth=10000\nloop_cover_fraction=0.3\n[economic]\ncashu_mint_url=\"http://localhost:3338\"\nmin_token_value=1\nmonero_rpc_url=\"http://127.0.0.1:18082\"\nredemption_batch_size=100\n[keys]\nkey_store_path=\"/tmp/k\"\npersist_identity=false").unwrap();
        let c = NodeConfig::load(tmp.path().to_str().unwrap()).unwrap();
        assert!(
            c.network.yggdrasil_only,
            "yggdrasil_only must default to true"
        );
    }
}
