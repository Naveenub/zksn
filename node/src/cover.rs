use crate::config::MixingConfig;
use anyhow::Result;
use rand::{Rng, RngCore};
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{trace, warn};
use zksn_crypto::sphinx::{generate_drop_packet, generate_loop_packet, NodeIdentity, SphinxPacket};

pub struct CoverTrafficGenerator {
    config: MixingConfig,
    tx: mpsc::Sender<SphinxPacket>,
}

impl CoverTrafficGenerator {
    pub fn new(config: MixingConfig, tx: mpsc::Sender<SphinxPacket>) -> Self {
        Self { config, tx }
    }

    pub async fn run(&mut self) -> Result<()> {
        if self.config.cover_traffic_rate == 0 {
            return Ok(());
        }
        let tick_ms = 1000u64 / self.config.cover_traffic_rate as u64;
        let mut ticker = interval(Duration::from_millis(tick_ms));
        let mut rng = rand::thread_rng();
        loop {
            ticker.tick().await;
            let use_loop = rng.gen::<f32>() < self.config.loop_cover_fraction;
            let pkt = if use_loop {
                generate_loop_packet(&self.build_route(), &mut rng)
            } else {
                generate_drop_packet(&self.build_route(), &mut rng)
            };
            match pkt {
                Ok(p) => {
                    trace!("Cover {}", if use_loop { "LOOP" } else { "DROP" });
                    let _ = self.tx.try_send(p);
                }
                Err(e) => warn!("Cover packet error: {e}"),
            }
        }
    }

    fn build_route(&self) -> Vec<NodeIdentity> {
        (0..3)
            .map(|_| {
                let mut k = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut k);
                NodeIdentity { public_key: k }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_emits_packets() {
        let cfg = MixingConfig {
            cover_traffic_rate: 100,
            poisson_lambda_ms: 200,
            max_queue_depth: 64,
            loop_cover_fraction: 0.5,
        };
        let (tx, mut rx) = mpsc::channel::<SphinxPacket>(64);
        let mut gen = CoverTrafficGenerator::new(cfg, tx);
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
        let (tx, mut rx) = mpsc::channel::<SphinxPacket>(64);
        let mut gen = CoverTrafficGenerator::new(cfg, tx);
        let h = tokio::spawn(async move { gen.run().await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(rx.try_recv().is_err());
        assert!(h.is_finished());
    }
}
