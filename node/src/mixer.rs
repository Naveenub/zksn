//! # Poisson Mixer
//!
//! Implements continuous-time Poisson mixing for Sphinx packets.
//!
//! ## Why Poisson Mixing?
//!
//! A Global Passive Adversary (GPA) watching all network links can perform
//! timing correlation attacks: if a packet enters one node and a similar
//! packet exits another node milliseconds later, the adversary can link them.
//!
//! Poisson mixing defeats this by:
//! 1. Holding packets for a random delay sampled from an Exponential distribution
//! 2. Reordering packets (a packet that arrives later may leave earlier)
//! 3. Interleaving cover traffic — real and fake packets are indistinguishable
//!
//! ## Mathematical Guarantee
//!
//! If packet delays are sampled i.i.d. from Exponential(λ), then for a GPA
//! observing n packets enter and exit, the probability of correctly linking
//! any single packet is 1/n — no better than random guessing, regardless
//! of how many links the adversary can observe.
//!
//! Reference: Danezis, Dingledine, Mathewson — "Mixminion" (2003)

use anyhow::Result;
use rand::distributions::Exp;
use rand::{thread_rng, Rng};
use rand::prelude::Distribution;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration, Instant};
use tracing::debug;

use crate::config::MixingConfig;
use zksn_crypto::sphinx::SphinxPacket;

/// A packet held in the mixing pool with its scheduled release time.
struct HeldPacket {
    packet: SphinxPacket,
    /// Placeholder: in real impl, this is the decoded next-hop address
    next_hop: String,
    release_at: Instant,
}

/// The Poisson mixer.
///
/// Receives packets from two sources:
/// - `rx_real`: real incoming Sphinx packets
/// - `rx_cover`: cover traffic (DROP/LOOP) from the cover generator
///
/// Both are treated identically — cover packets get the same Poisson delay
/// as real packets. From outside, they are indistinguishable.
pub struct PoissonMixer {
    config: MixingConfig,
    rx_real: mpsc::Receiver<SphinxPacket>,
    rx_cover: mpsc::Receiver<SphinxPacket>,
    tx_out: mpsc::Sender<(String, SphinxPacket)>,
    pool: Vec<HeldPacket>,
}

impl PoissonMixer {
    pub fn new(
        config: MixingConfig,
        rx_real: mpsc::Receiver<SphinxPacket>,
        rx_cover: mpsc::Receiver<SphinxPacket>,
        tx_out: mpsc::Sender<(String, SphinxPacket)>,
    ) -> Self {
        Self {
            config,
            rx_real,
            rx_cover,
            tx_out,
            pool: Vec::new(),
        }
    }

    /// Run the mixer loop.
    ///
    /// The loop does three things every tick:
    /// 1. Drain any newly arrived packets into the pool (with Poisson delay)
    /// 2. Release any packets whose delay has expired
    /// 3. Sleep for a short poll interval
    pub async fn run(&mut self) -> Result<()> {
        // Exponential distribution parameterized by λ (rate = 1/mean)
        let lambda_secs = self.config.poisson_lambda_ms as f64 / 1000.0;
        let exp_dist = Exp::new(1.0 / lambda_secs);

        let poll_interval = Duration::from_millis(10);

        loop {
            let now = Instant::now();

            // Accept all available real packets (non-blocking drain)
            loop {
                match self.rx_real.try_recv() {
                    Ok(packet) => {
                        let delay_secs = exp_dist.sample(&mut thread_rng());
                        let delay = Duration::from_secs_f64(delay_secs);
                        let release_at = now + delay;

                        debug!(
                            "Holding real packet for {:.0}ms",
                            delay.as_millis()
                        );

                        self.pool.push(HeldPacket {
                            next_hop: extract_next_hop(&packet),
                            packet,
                            release_at,
                        });
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => return Ok(()),
                }
            }

            // Accept all available cover packets
            loop {
                match self.rx_cover.try_recv() {
                    Ok(packet) => {
                        let delay_secs = exp_dist.sample(&mut thread_rng());
                        let delay = Duration::from_secs_f64(delay_secs);
                        let release_at = now + delay;

                        self.pool.push(HeldPacket {
                            next_hop: extract_next_hop(&packet),
                            packet,
                            release_at,
                        });
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => break,
                }
            }

            // Release packets whose delay has expired
            let mut i = 0;
            while i < self.pool.len() {
                if self.pool[i].release_at <= now {
                    let held = self.pool.swap_remove(i);
                    debug!("Releasing packet to {}", held.next_hop);
                    // Ignore send errors (downstream shutdown)
                    let _ = self.tx_out.send((held.next_hop, held.packet)).await;
                } else {
                    i += 1;
                }
            }

            sleep(poll_interval).await;
        }
    }
}

/// Extract the next-hop address from a Sphinx packet's routing header.
///
/// In a full implementation, this decrypts the outer routing layer using
/// the node's private key and reads the encoded next-hop identity.
/// For now, returns a placeholder.
fn extract_next_hop(_packet: &SphinxPacket) -> String {
    // TODO: integrate with node private key to decrypt routing header
    // See crypto/src/sphinx.rs process_packet()
    "127.0.0.1:9001".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poisson_delay_distribution() {
        // Verify that sampled delays are positive and roughly exponentially distributed
        let lambda_secs = 0.2; // 200ms mean
        let exp_dist = Exp::new(1.0 / lambda_secs);
        let mut rng = thread_rng();

        let samples: Vec<f64> = (0..1000)
            .map(|_| exp_dist.sample(&mut rng))
            .collect();

        // All delays must be positive
        assert!(samples.iter().all(|&d| d > 0.0));

        // Sample mean should be close to λ (within 20% for 1000 samples)
        let mean = samples.iter().sum::<f64>() / samples.len() as f64;
        assert!(
            (mean - lambda_secs).abs() < lambda_secs * 0.20,
            "Mean delay {:.3}s deviates too far from expected {:.3}s",
            mean,
            lambda_secs
        );
    }
}
