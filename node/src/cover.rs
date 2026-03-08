use crate::config::MixingConfig;
use crate::peers::PeerTable;
use anyhow::Result;
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{trace, warn};
use zksn_crypto::sphinx::{generate_drop_packet, generate_loop_packet, NodeIdentity, SphinxPacket};

pub struct CoverTrafficGenerator {
    config: MixingConfig,
    tx: mpsc::Sender<(String, SphinxPacket)>,
    peers: Arc<PeerTable>,
}

impl CoverTrafficGenerator {
    pub fn new(
        config: MixingConfig,
        tx: mpsc::Sender<(String, SphinxPacket)>,
        peers: Arc<PeerTable>,
    ) -> Self {
        Self { config, tx, peers }
    }

    pub async fn run(&mut self) -> Result<()> {
        if self.config.cover_traffic_rate == 0 {
            return Ok(());
        }
        let tick_ms = 1000u64 / self.config.cover_traffic_rate as u64;
        let mut ticker = interval(Duration::from_millis(tick_ms));
        let mut rng = StdRng::from_entropy();
        loop {
            ticker.tick().await;
            let use_loop = rng.gen::<f32>() < self.config.loop_cover_fraction;
            let (route, first_addr) = self.build_route(&mut rng).await;
            if route.is_empty() {
                continue;
            }
            let pkt = if use_loop {
                generate_loop_packet(&route, &mut rng)
            } else {
                generate_drop_packet(&route, &mut rng)
            };
            match pkt {
                Ok(p) => {
                    trace!("Cover {}", if use_loop { "LOOP" } else { "DROP" });
                    let _ = self.tx.try_send((first_addr, p));
                }
                Err(e) => warn!("Cover packet error: {e}"),
            }
        }
    }

    /// Build a cover route using live peers when available, else random fallback.
    async fn build_route(&self, rng: &mut impl RngCore) -> (Vec<NodeIdentity>, String) {
        let peers = self.peers.sample(3).await;
        if !peers.is_empty() {
            let first_addr = peers[0].addr.clone();
            let route = peers
                .into_iter()
                .map(|p| NodeIdentity {
                    public_key: p.public_key,
                })
                .collect();
            return (route, first_addr);
        }
        // Fallback: random dummy route for cover when no peers known yet
        let route: Vec<NodeIdentity> = (0..3)
            .map(|_| {
                let mut k = [0u8; 32];
                rng.fill_bytes(&mut k);
                NodeIdentity { public_key: k }
            })
            .collect();
        (route, "127.0.0.1:9001".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peers::PeerInfo;

    #[tokio::test]
    async fn test_emits_packets() {
        let cfg = MixingConfig {
            cover_traffic_rate: 100,
            poisson_lambda_ms: 200,
            max_queue_depth: 64,
            loop_cover_fraction: 0.5,
        };
        let peers = Arc::new(PeerTable::new(16));
        let (tx, mut rx) = mpsc::channel::<(String, SphinxPacket)>(64);
        let mut gen = CoverTrafficGenerator::new(cfg, tx, peers);
        tokio::spawn(async move {
            let _ = gen.run().await;
        });
        let r = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await;
        assert!(r.is_ok() && r.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_disabled_at_zero() {
        let cfg = MixingConfig {
            cover_traffic_rate: 0,
            poisson_lambda_ms: 200,
            max_queue_depth: 64,
            loop_cover_fraction: 0.5,
        };
        let peers = Arc::new(PeerTable::new(16));
        let (tx, mut rx) = mpsc::channel::<(String, SphinxPacket)>(64);
        let mut gen = CoverTrafficGenerator::new(cfg, tx, peers);
        let h = tokio::spawn(async move { gen.run().await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(rx.try_recv().is_err());
        assert!(h.is_finished());
    }

    #[tokio::test]
    async fn test_uses_real_peers_when_available() {
        let peers = Arc::new(PeerTable::new(16));
        peers
            .upsert(PeerInfo::new("10.0.0.1:9001".into(), [1u8; 32]))
            .await;
        peers
            .upsert(PeerInfo::new("10.0.0.2:9001".into(), [2u8; 32]))
            .await;
        peers
            .upsert(PeerInfo::new("10.0.0.3:9001".into(), [3u8; 32]))
            .await;

        let mut rng = StdRng::from_entropy();
        let cfg = MixingConfig::default();
        let (tx, _rx) = mpsc::channel::<(String, SphinxPacket)>(16);
        let gen = CoverTrafficGenerator::new(cfg, tx, peers);
        let (route, addr) = gen.build_route(&mut rng).await;
        assert!(!route.is_empty());
        assert!(addr.starts_with("10.0.0."));
    }
}
