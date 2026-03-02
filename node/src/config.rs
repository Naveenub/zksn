//! # Node Configuration
//!
//! All node settings are loaded from a TOML file and/or environment variables.
//! Sensitive fields (private keys) are never stored in the config file —
//! they are loaded from an encrypted key store at runtime.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use zksn_crypto::identity::ZksnIdentity;

/// Root configuration for a ZKSN mix node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Network transport settings
    pub network: NetworkConfig,

    /// Mixing parameters
    pub mixing: MixingConfig,

    /// Economic layer settings
    pub economic: EconomicConfig,

    /// Key storage settings
    pub keys: KeyConfig,

    /// Run in testnet mode (no real payments)
    #[serde(default)]
    pub testnet: bool,

    /// Internal: loaded identity (not from TOML)
    #[serde(skip)]
    pub identity: IdentityHolder,
}

impl NodeConfig {
    /// Load configuration from a TOML file.
    pub fn load(path: &str) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let mut config: NodeConfig = toml::from_str(&contents)?;
        config.identity = IdentityHolder::load_or_generate(&config.keys)?;
        Ok(config)
    }
}

impl Default for NodeConfig {
    fn default() -> Self {
        let identity = IdentityHolder::generate();
        Self {
            network: NetworkConfig::default(),
            mixing: MixingConfig::default(),
            economic: EconomicConfig::default(),
            keys: KeyConfig::default(),
            testnet: false,
            identity,
        }
    }
}

/// Network transport configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Address to listen on for incoming Sphinx packets.
    /// Use Yggdrasil IPv6 address in production.
    pub listen_addr: String,

    /// Maximum number of concurrent peer connections
    pub max_peers: usize,

    /// Connection timeout in milliseconds
    pub connect_timeout_ms: u64,

    /// Bootstrap peers (Yggdrasil addresses)
    pub bootstrap_peers: Vec<String>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addr: "[::1]:9001".to_string(),
            max_peers: 64,
            connect_timeout_ms: 5000,
            bootstrap_peers: vec![],
        }
    }
}

/// Poisson mixing and cover traffic parameters.
///
/// These parameters directly affect the anonymity guarantees of the network.
/// Higher λ = more delay = stronger anonymity but higher latency.
/// Higher cover rate = more bandwidth used = stronger anonymity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MixingConfig {
    /// Mean delay for Poisson mixing in milliseconds.
    /// Actual delay per packet = Exponential(1/λ).
    /// Recommended: 100–500ms for interactive use, 1000–5000ms for asynchronous.
    pub poisson_lambda_ms: u64,

    /// Cover traffic rate in packets per second.
    /// All cover packets are indistinguishable from real packets.
    /// Recommended: at least 1 cover packet per real packet expected.
    pub cover_traffic_rate: u32,

    /// Maximum queue depth before packets are dropped (DoS protection).
    pub max_queue_depth: usize,

    /// Loop cover traffic fraction (0.0–1.0).
    /// LOOP packets route back to sender to verify path liveness.
    /// DROP packets are sent to random nodes and silently discarded.
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

/// Economic layer configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicConfig {
    /// Cashu mint URL for token validation
    pub cashu_mint_url: String,

    /// Minimum token value per packet (in millisats equivalent)
    pub min_token_value: u64,

    /// Monero RPC URL for settlement
    pub monero_rpc_url: String,

    /// Batch size for token redemption (batch to reduce linkability)
    pub redemption_batch_size: usize,
}

impl Default for EconomicConfig {
    fn default() -> Self {
        Self {
            cashu_mint_url: "http://mint.zksn.internal:3338".to_string(),
            min_token_value: 1,
            monero_rpc_url: "http://127.0.0.1:18082".to_string(),
            redemption_batch_size: 100,
        }
    }
}

/// Key storage configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyConfig {
    /// Path to the encrypted key store.
    /// If empty, a fresh identity is generated each boot (stateless mode).
    pub key_store_path: String,

    /// Whether to persist the generated key (false = fully stateless/ephemeral)
    pub persist_identity: bool,
}

impl Default for KeyConfig {
    fn default() -> Self {
        Self {
            key_store_path: "/var/lib/zksn/keys/identity.key".to_string(),
            persist_identity: false, // Stateless by default
        }
    }
}

/// Holds the node's loaded identity.
/// Not serialized to/from config files.
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
}

impl std::fmt::Debug for IdentityHolder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IdentityHolder({})", self.fingerprint())
    }
}

impl Clone for IdentityHolder {
    fn clone(&self) -> Self {
        // Re-derive from secret bytes to clone — bytes are immediately zeroized
        let bytes = self.identity.to_secret_bytes();
        Self {
            identity: ZksnIdentity::from_secret_bytes(bytes),
        }
    }
}
