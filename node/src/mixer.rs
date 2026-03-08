use crate::config::MixingConfig;
use anyhow::Result;
use rand::thread_rng;
use rand_distr::{Distribution, Exp};
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration, Instant};
use tracing::debug;
use zksn_crypto::sphinx::SphinxPacket;

struct HeldPacket {
    packet: SphinxPacket,
    next_hop: String,
    release_at: Instant,
}

/// Poisson-delay mixer.
///
/// Both real packets (`rx_real`) and cover packets (`rx_cover`) arrive as
/// `(addr, packet)` pairs — the TCP address is already resolved by the caller
/// (via `PeerTable::resolve`) before entering the mixer.
pub struct PoissonMixer {
    config: MixingConfig,
    rx_real: mpsc::Receiver<(String, SphinxPacket)>,
    rx_cover: mpsc::Receiver<(String, SphinxPacket)>,
    tx_out: mpsc::Sender<(String, SphinxPacket)>,
    pool: Vec<HeldPacket>,
}

impl PoissonMixer {
    pub fn new(
        config: MixingConfig,
        rx_real: mpsc::Receiver<(String, SphinxPacket)>,
        rx_cover: mpsc::Receiver<(String, SphinxPacket)>,
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

    pub async fn run(&mut self) -> Result<()> {
        let rate = 1.0 / (self.config.poisson_lambda_ms as f64 / 1000.0);
        let exp_dist = Exp::new(rate).expect("rate must be positive");
        let poll = Duration::from_millis(10);
        loop {
            let now = Instant::now();
            loop {
                match self.rx_real.try_recv() {
                    Ok((addr, p)) => {
                        let secs = exp_dist.sample(&mut thread_rng());
                        debug!("Holding real packet {:.0}ms -> {addr}", secs * 1000.0);
                        self.pool.push(HeldPacket {
                            next_hop: addr,
                            packet: p,
                            release_at: now + Duration::from_secs_f64(secs),
                        });
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => return Ok(()),
                }
            }
            loop {
                match self.rx_cover.try_recv() {
                    Ok((addr, p)) => {
                        let secs = exp_dist.sample(&mut thread_rng());
                        self.pool.push(HeldPacket {
                            next_hop: addr,
                            packet: p,
                            release_at: now + Duration::from_secs_f64(secs),
                        });
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => break,
                }
            }
            let mut i = 0;
            while i < self.pool.len() {
                if self.pool[i].release_at <= now {
                    let h = self.pool.swap_remove(i);
                    let _ = self.tx_out.send((h.next_hop, h.packet)).await;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exp_positive() {
        let dist = Exp::new(5.0_f64).unwrap();
        let s: Vec<f64> = (0..200).map(|_| dist.sample(&mut thread_rng())).collect();
        assert!(s.iter().all(|&d| d > 0.0));
        let mean = s.iter().sum::<f64>() / s.len() as f64;
        assert!(
            (mean - 0.2).abs() < 0.1,
            "mean {mean:.3} should be near 0.2"
        );
    }
}
