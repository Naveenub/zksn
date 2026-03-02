//! # Route Selection
//!
//! Selects a random path through the mix network for each message.
//!
//! ## Properties
//! - Routes are randomly sampled from the live node set
//! - No two consecutive hops should be in the same AS/jurisdiction
//! - The final hop leads to the recipient's delivery endpoint

use anyhow::Result;
use zksn_crypto::sphinx::NodeIdentity;

/// Select a random mix route of `num_hops` nodes, ending at the recipient.
///
/// In production, this queries the ZKSN node registry (DHT-based) to get
/// a current list of live mix nodes, then samples from them.
pub async fn select_route(num_hops: usize, recipient_key: &[u8; 32]) -> Result<Vec<NodeIdentity>> {
    // TODO: query live node registry from DHT / Yggdrasil mesh
    // For now: build a placeholder route

    let mut route: Vec<NodeIdentity> = (0..num_hops.saturating_sub(1))
        .map(|_| random_mix_node())
        .collect();

    // Final hop: recipient
    route.push(NodeIdentity {
        public_key: *recipient_key,
    });

    Ok(route)
}

fn random_mix_node() -> NodeIdentity {
    use rand::RngCore;
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    NodeIdentity { public_key: key }
}
