//! # Cover Traffic Generator
//!
//! Continuously emits cover traffic packets indistinguishable from real traffic.
//!
//! **DROP** packets are sent to a random node and silently discarded there.
//! **LOOP** packets route back to the sender to verify path liveness.
//! Both are cryptographically indistinguishable from real Sphinx packets.

use anyhow::Result;
use rand::{Rng, RngCore};          // Rng for gen::<f32>(), RngCore for fill_bytes()
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{trace, warn};

use crate::config::MixingConfig;
use zksn_crypto::sphinx::{
    generate_drop_packet, generate_loop_packet, NodeIdentity, SphinxPacket,
};

pub struct CoverTrafficGenerator {
    config: MixingConfig,
    tx:     mpsc::Sender<SphinxPacket>,
}

impl CoverTrafficGenerator {
    pub fn new(config: MixingConfig, tx: mpsc::Sender<SphinxPacket>) -> Self {
        Self { config, tx }
    }

    /// Run until the channel closes. Returns immediately if rate == 0.
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

            let packet = if use_loop {
                generate_loop_packet(&self.build_loop_route(), &mut rng)
            } else {
                generate_drop_packet(&self.build_drop_route(), &mut rng)
            };

            match packet {
                Ok(p) => {
                    trace!("Emitting {} cover packet", if use_loop { "LOOP" } else { "DROP" });
                    // Non-blocking: cover packets are lower priority than real packets
                    if self.tx.try_send(p).is_err() {
                        trace!("Cover packet dropped — mixer queue full");
                    }
                }
                Err(e) => warn!("Failed to generate cover packet: {e}"),
            }
        }
    }

    fn build_drop_route(&self) -> Vec<NodeIdentity> {
        (0..3).map(|_| random_node_identity()).collect()
    }

    fn build_loop_route(&self) -> Vec<NodeIdentity> {
        (0..3).map(|_| random_node_identity()).collect()
    }
}

fn random_node_identity() -> NodeIdentity {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);  // RngCore::fill_bytes — always correct
    NodeIdentity { public_key: key }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MixingConfig;

    #[tokio::test]
    async fn test_cover_generator_emits_packets() {
        let config = MixingConfig {
            poisson_lambda_ms:   200,
            cover_traffic_rate:  100,  // fast for test
            max_queue_depth:     64,
            loop_cover_fraction: 0.5,
        };
        let (tx, mut rx) = mpsc::channel::<SphinxPacket>(64);
        let mut gen = CoverTrafficGenerator::new(config, tx);

        tokio::spawn(async move { let _ = gen.run().await; });

        let result = tokio::time::timeout(
            Duration::from_millis(300),
            rx.recv(),
        ).await;
        assert!(result.is_ok(), "Should receive at least one cover packet within 300ms");
        assert!(result.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_disabled_at_zero_rate() {
        let config = MixingConfig {
            poisson_lambda_ms:   200,
            cover_traffic_rate:  0,   // disabled
            max_queue_depth:     64,
            loop_cover_fraction: 0.5,
        };
        let (tx, mut rx) = mpsc::channel::<SphinxPacket>(64);
        let mut gen = CoverTrafficGenerator::new(config, tx);

        let handle = tokio::spawn(async move { gen.run().await });

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(rx.try_recv().is_err(), "No packets expected when rate = 0");
        assert!(handle.is_finished(), "Generator should exit immediately when rate = 0");
    }
}
