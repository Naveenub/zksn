use rand::RngCore;
use zksn_crypto::sphinx::NodeIdentity;

/// Select a random mix route of `hop_count` nodes.
/// TODO: replace with live DHT sampling from Yggdrasil registry.
pub fn select_route(hop_count: usize) -> Vec<NodeIdentity> {
    (0..hop_count)
        .map(|_| {
            let mut key = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            NodeIdentity { public_key: key }
        })
        .collect()
}
