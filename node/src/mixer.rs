//! # Poisson Mixer
//!
//! Implements continuous-time Poisson mixing for Sphinx packets.
//!
//! A Global Passive Adversary (GPA) performing timing correlation is defeated
//! because each packet is delayed by an independent Exponential(λ) random
//! variable — making the exit time of any packet statistically independent
//! of its entry time. Cover packets are delayed identically and are
//! indistinguishable from real packets.
//!
//! Reference: Danezis, Dingledine, Mathewson — "Mixminion" (2003)

use anyhow::Result;
use rand::thread_rng;
use rand_distr::{Distribution, Exp};   // rand_distr 0.4 — correct for rand 0.8
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration, Instant};
use tracing::debug;

use crate::config::MixingConfig;
use zksn_crypto::sphinx::SphinxPacket;

struct HeldPacket {
    packet:     SphinxPacket,
    next_hop:   String,
    release_at: Instant,
}

pub struct PoissonMixer {
    config:   MixingConfig,
    rx_real:  mpsc::Receiver<SphinxPacket>,
    rx_cover: mpsc::Receiver<SphinxPacket>,
    tx_out:   mpsc::Sender<(String, SphinxPacket)>,
    pool:     Vec<HeldPacket>,
}

impl PoissonMixer {
    pub fn new(
        config:   MixingConfig,
        rx_real:  mpsc::Receiver<SphinxPacket>,
        rx_cover: mpsc::Receiver<SphinxPacket>,
        tx_out:   mpsc::Sender<(String, SphinxPacket)>,
    ) -> Self {
        Self { config, rx_real, rx_cover, tx_out, pool: Vec::new() }
    }

    pub async fn run(&mut self) -> Result<()> {
        // rate = 1 / mean_seconds
        let rate = 1.0 / (self.config.poisson_lambda_ms as f64 / 1000.0);
        // Exp::new() in rand_distr 0.4 returns Result<Exp<f64>, ExpError>
        let exp_dist = Exp::new(rate).expect("Poisson rate must be finite and positive");

        let poll = Duration::from_millis(10);

        loop {
            let now = Instant::now();

            // Drain all available real packets
            loop {
                match self.rx_real.try_recv() {
                    Ok(packet) => {
                        let secs = exp_dist.sample(&mut thread_rng());
                        debug!("Holding real packet for {:.0}ms", secs * 1000.0);
                        self.pool.push(HeldPacket {
                            next_hop:   extract_next_hop(&packet),
                            packet,
                            release_at: now + Duration::from_secs_f64(secs),
                        });
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => return Ok(()),
                }
            }

            // Drain all available cover packets
            loop {
                match self.rx_cover.try_recv() {
                    Ok(packet) => {
                        let secs = exp_dist.sample(&mut thread_rng());
                        self.pool.push(HeldPacket {
                            next_hop:   extract_next_hop(&packet),
                            packet,
                            release_at: now + Duration::from_secs_f64(secs),
                        });
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => break,
                }
            }

            // Release packets whose hold has expired
            let mut i = 0;
            while i < self.pool.len() {
                if self.pool[i].release_at <= now {
                    let held = self.pool.swap_remove(i);
                    debug!("Releasing packet → {}", held.next_hop);
                    let _ = self.tx_out.send((held.next_hop, held.packet)).await;
                } else {
                    i += 1;
                }
            }

            sleep(poll).await;
        }
    }

    pub fn pool_depth(&self) -> usize {
        self.pool.len()
    }
}

/// Decode the next-hop address from a Sphinx packet.
///
/// Full implementation: calls `sphinx::process_packet()` with the node's
/// private key to decrypt the routing header and read the next hop.
/// Placeholder until X25519 ECDH is wired in.
fn extract_next_hop(_packet: &SphinxPacket) -> String {
    "127.0.0.1:9001".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exp_distribution_positive_mean() {
        let rate = 1.0 / 0.2_f64; // 200ms mean
        let dist = Exp::new(rate).unwrap();
        let samples: Vec<f64> = (0..500).map(|_| dist.sample(&mut thread_rng())).collect();

        assert!(samples.iter().all(|&d| d > 0.0), "All delays must be positive");

        let mean = samples.iter().sum::<f64>() / samples.len() as f64;
        let expected = 0.2_f64;
        assert!(
            (mean - expected).abs() < expected * 0.25,
            "Sample mean {mean:.3}s should be within 25% of {expected}s"
        );
    }

    #[test]
    fn test_exp_new_rejects_zero_rate() {
        // rand_distr 0.4: Exp::new(0.0) returns Err
        assert!(Exp::new(0.0_f64).is_err());
    }

    #[tokio::test]
    async fn test_mixer_forwards_packet() {
        use zksn_crypto::sphinx::PACKET_SIZE;

        let config = MixingConfig {
            poisson_lambda_ms:   1,   // 1ms mean → exits almost immediately
            cover_traffic_rate:  0,
            max_queue_depth:     16,
            loop_cover_fraction: 0.0,
        };

        let (tx_real,    rx_real)   = mpsc::channel::<SphinxPacket>(16);
        let (_tx_cover,  rx_cover)  = mpsc::channel::<SphinxPacket>(16);
        let (tx_out,  mut rx_out)   = mpsc::channel::<(String, SphinxPacket)>(16);

        let mut mixer = PoissonMixer::new(config, rx_real, rx_cover, tx_out);
        tokio::spawn(async move { let _ = mixer.run().await; });

        let dummy = SphinxPacket {
            ephemeral_public_key: [0u8; 32],
            routing_header:       vec![0u8; 96],
            payload:              vec![0u8; PACKET_SIZE - 128],
        };
        tx_real.send(dummy).await.unwrap();

        let result = tokio::time::timeout(
            Duration::from_millis(500),
            rx_out.recv(),
        ).await;
        assert!(result.is_ok(),          "Packet should be forwarded within 500ms");
        assert!(result.unwrap().is_some(), "Should receive a forwarded packet");
    }
}
