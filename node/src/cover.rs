//! # Cover Traffic Generator
//!
//! Continuously emits cover traffic packets indistinguishable from real traffic.
//!
//! ## Two Types of Cover Traffic
//!
//! ### DROP Packets
//! Sent to a random node in the network. The receiving node processes and
//! discards them (they decode to a "DROP" instruction). Neither the sender
//! nor any observer can distinguish a DROP from a real message.
//!
//! ### LOOP Packets
//! Sent through the network and routed back to the sender. The sender can
//! verify these arrive back — if they stop arriving, the sender knows the
//! path is broken. Also indistinguishable from real traffic to observers.
//!
//! ## Rate
//! Cover traffic is emitted at a configurable rate (packets per second).
//! The rate should be tuned based on expected real traffic volume.
//! A good starting point: match the expected real traffic rate.

use anyhow::Result;
use rand::{thread_rng, Rng};
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::trace;

use crate::config::MixingConfig;
use zksn_crypto::sphinx::{generate_drop_packet, generate_loop_packet, NodeIdentity, SphinxPacket};

/// Generates and emits cover traffic on a fixed schedule.
pub struct CoverTrafficGenerator {
    config: MixingConfig,
    tx: mpsc::Sender<SphinxPacket>,
}

impl CoverTrafficGenerator {
    pub fn new(config: MixingConfig, tx: mpsc::Sender<SphinxPacket>) -> Self {
        Self { config, tx }
    }

    /// Run the cover traffic generator.
    ///
    /// Emits one cover packet per tick. The tick rate is derived from
    /// `cover_traffic_rate` (packets per second).
    pub async fn run(&mut self) -> Result<()> {
        let tick_ms = 1000 / self.config.cover_traffic_rate.max(1) as u64;
        let mut ticker = interval(Duration::from_millis(tick_ms));

        let mut rng = thread_rng();

        loop {
            ticker.tick().await;

            // Decide: LOOP (verify liveness) or DROP (pure cover)
            let use_loop = rng.gen::<f32>() < self.config.loop_cover_fraction;

            let packet = if use_loop {
                let route = self.build_loop_route();
                generate_loop_packet(&route, &mut rng)
            } else {
                let route = self.build_drop_route();
                generate_drop_packet(&route, &mut rng)
            };

            match packet {
                Ok(p) => {
                    trace!("Emitting {} cover packet", if use_loop { "LOOP" } else { "DROP" });
                    // Non-blocking: if the mixer is full, drop the cover packet
                    // (real packets have higher priority)
                    let _ = self.tx.try_send(p);
                }
                Err(e) => {
                    tracing::warn!("Failed to generate cover packet: {e}");
                }
            }
        }
    }

    /// Build a random route for a DROP packet.
    /// In production, this samples from the live network topology.
    fn build_drop_route(&self) -> Vec<NodeIdentity> {
        // TODO: sample from live node registry / DHT
        // For now: placeholder with 3 hops
        (0..3).map(|_| random_node_identity()).collect()
    }

    /// Build a route that loops back to this node.
    fn build_loop_route(&self) -> Vec<NodeIdentity> {
        // TODO: build a real loop route through the mix network
        // that ends at our own node identity
        (0..3).map(|_| random_node_identity()).collect()
    }
}

/// Generate a random NodeIdentity for testing/placeholder purposes.
/// In production, nodes are sampled from the live network registry.
fn random_node_identity() -> NodeIdentity {
    let mut key = [0u8; 32];
    rand::thread_rng().fill(&mut key);
    NodeIdentity { public_key: key }
}
