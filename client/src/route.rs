//! Route selection — samples live peers from the DHT for Sphinx onion routing.
//!
//! A route is `[mix_1, mix_2, ..., mix_n, recipient]`.
//! The intermediate hops are sampled from the local PeerTable.
//! The recipient is the final element; its X25519 public key is the
//! delivery address the last mix node uses to resolve a TCP address.

use anyhow::{anyhow, Result};
use std::sync::Arc;
use zksn_crypto::sphinx::NodeIdentity;
use zksn_node::peers::{PeerInfo, PeerTable};

/// Holds a reference to the shared peer table and selects routes from it.
pub struct RouteSelector {
    table: Arc<PeerTable>,
}

impl RouteSelector {
    pub fn new(table: Arc<PeerTable>) -> Self {
        Self { table }
    }

    /// Select a route of `hop_count` intermediate mix nodes.
    ///
    /// Returns `(node_identities, first_hop_addr)` where:
    /// - `node_identities` is the full Sphinx route (intermediate hops only —
    ///   the caller appends the recipient as the last element).
    /// - `first_hop_addr` is the TCP address to dial for packet injection.
    pub async fn select_hops(&self, hop_count: usize) -> Result<(Vec<PeerInfo>, String)> {
        let peers = self.table.sample(hop_count).await;
        if peers.is_empty() {
            return Err(anyhow!(
                "No peers in routing table — connect to a bootstrap node first"
            ));
        }
        if peers.len() < hop_count {
            return Err(anyhow!(
                "Need {hop_count} hops but only {} peers known",
                peers.len()
            ));
        }
        let first_addr = peers[0].addr.clone();
        Ok((peers, first_addr))
    }

    /// Build a full Sphinx route including the recipient as the last hop.
    ///
    /// Returns `(identities, entry_addr)` where `entry_addr` is the TCP
    /// address of the first mix node.
    pub async fn build_route(
        &self,
        hop_count: usize,
        recipient_pubkey: [u8; 32],
    ) -> Result<(Vec<NodeIdentity>, String)> {
        let (hops, entry_addr) = self.select_hops(hop_count).await?;
        let mut identities: Vec<NodeIdentity> = hops
            .into_iter()
            .map(|p| NodeIdentity {
                public_key: p.public_key,
            })
            .collect();
        // Append recipient as final Sphinx hop
        identities.push(NodeIdentity {
            public_key: recipient_pubkey,
        });
        Ok((identities, entry_addr))
    }

    /// Resolve a recipient's X25519 public key to their TCP listen address.
    pub async fn resolve_recipient(&self, public_key: &[u8; 32]) -> Option<String> {
        self.table.resolve(public_key).await
    }

    pub fn peer_count(&self) -> Arc<PeerTable> {
        Arc::clone(&self.table)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zksn_node::peers::PeerInfo;

    async fn make_table_with_peers(n: usize) -> Arc<PeerTable> {
        let table = Arc::new(PeerTable::new([0u8; 32]));
        for i in 0..n {
            let mut key = [0u8; 32];
            key[0] = i as u8 + 1;
            table
                .upsert(PeerInfo::new(format!("10.0.0.{}:9001", i + 1), key))
                .await;
        }
        table
    }

    #[tokio::test]
    async fn test_select_hops_returns_correct_count() {
        let table = make_table_with_peers(5).await;
        let selector = RouteSelector::new(table);
        let (hops, addr) = selector.select_hops(3).await.unwrap();
        assert_eq!(hops.len(), 3);
        assert!(!addr.is_empty());
    }

    #[tokio::test]
    async fn test_build_route_appends_recipient() {
        let table = make_table_with_peers(3).await;
        let selector = RouteSelector::new(table);
        let recipient = [0xAAu8; 32];
        let (route, _) = selector.build_route(3, recipient).await.unwrap();
        assert_eq!(route.len(), 4); // 3 hops + recipient
        assert_eq!(route.last().unwrap().public_key, recipient);
    }

    #[tokio::test]
    async fn test_empty_table_returns_error() {
        let table = Arc::new(PeerTable::new([0u8; 32]));
        let selector = RouteSelector::new(table);
        assert!(selector.select_hops(3).await.is_err());
    }

    #[tokio::test]
    async fn test_insufficient_peers_returns_error() {
        let table = make_table_with_peers(2).await;
        let selector = RouteSelector::new(table);
        assert!(selector.select_hops(5).await.is_err());
    }

    #[tokio::test]
    async fn test_resolve_recipient_found() {
        let table = Arc::new(PeerTable::new([0u8; 32]));
        let key = [0x42u8; 32];
        table
            .upsert(PeerInfo::new("192.168.1.1:9002".into(), key))
            .await;
        let selector = RouteSelector::new(table);
        assert_eq!(
            selector.resolve_recipient(&key).await,
            Some("192.168.1.1:9002".to_string())
        );
    }

    #[tokio::test]
    async fn test_resolve_recipient_missing() {
        let table = Arc::new(PeerTable::new([0u8; 32]));
        let selector = RouteSelector::new(table);
        assert!(selector.resolve_recipient(&[0xFFu8; 32]).await.is_none());
    }
}
