use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Path to Ed25519 identity key file (raw 32-byte seed).
    pub key_path: Option<String>,
    /// TCP address of the entry mix node (first hop).
    pub entry_node: String,
    /// Number of mix hops (not counting the recipient).
    pub hop_count: usize,
    /// Cashu mint URL for payment tokens.
    pub cashu_mint_url: String,
    /// TCP address this client listens on for incoming messages.
    pub listen_addr: String,
    /// Bootstrap mix nodes for peer discovery.
    pub bootstrap_peers: Vec<String>,
    /// Path to persist the peer table between sessions.
    pub peer_store_path: Option<String>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            key_path: None,
            entry_node: "[::1]:9001".to_string(),
            hop_count: 3,
            cashu_mint_url: "http://mint.zksn.internal:3338".to_string(),
            listen_addr: "[::1]:9002".to_string(),
            bootstrap_peers: vec![],
            peer_store_path: None,
        }
    }
}
