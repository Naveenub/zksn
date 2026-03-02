//! Client configuration.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Path to the client's private key file.
    /// If None, a fresh ephemeral identity is generated.
    pub key_path: Option<String>,

    /// Entry mix node address (first hop).
    pub entry_node: String,

    /// Number of mix hops (3–5 recommended)
    pub num_hops: usize,

    /// Cashu mint URL for acquiring payment tokens
    pub cashu_mint_url: String,

    /// Whether to send continuous cover traffic while the client is active
    pub send_cover_traffic: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            key_path: None,
            entry_node: "[::1]:9001".to_string(),
            num_hops: 3,
            cashu_mint_url: "http://mint.zksn.internal:3338".to_string(),
            send_cover_traffic: true,
        }
    }
}
