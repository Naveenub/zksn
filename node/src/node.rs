use crate::{
    config::NodeConfig, cover::CoverTrafficGenerator, metrics::NodeMetrics, mixer::PoissonMixer,
    router::PacketRouter,
};
use anyhow::Result;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use zksn_crypto::sphinx::{SphinxPacket, PACKET_SIZE};

pub struct MixNode {
    config: NodeConfig,
    listener: TcpListener,
}

impl MixNode {
    pub async fn new(config: NodeConfig) -> Result<Self> {
        let listener = TcpListener::bind(&config.network.listen_addr).await?;
        info!("Listening on {}", config.network.listen_addr);
        Ok(Self { config, listener })
    }

    pub async fn run(self) -> Result<()> {
        let (tx_in, rx_in) = mpsc::channel::<SphinxPacket>(self.config.mixing.max_queue_depth);
        let (tx_out, rx_out) =
            mpsc::channel::<(String, SphinxPacket)>(self.config.mixing.max_queue_depth);
        let (tx_cov, rx_cov) = mpsc::channel::<SphinxPacket>(1024);
        let mix_cfg = self.config.mixing.clone();
        tokio::spawn(async move {
            let mut m = PoissonMixer::new(mix_cfg, rx_in, rx_cov, tx_out);
            if let Err(e) = m.run().await {
                error!("Mixer: {e}");
            }
        });
        let cov_cfg = self.config.mixing.clone();
        tokio::spawn(async move {
            let mut g = CoverTrafficGenerator::new(cov_cfg, tx_cov);
            if let Err(e) = g.run().await {
                error!("Cover: {e}");
            }
        });
        tokio::spawn(async move {
            let mut r = PacketRouter::new(rx_out);
            if let Err(e) = r.run().await {
                error!("Router: {e}");
            }
        });
        info!("Mix node ready");
        loop {
            match self.listener.accept().await {
                Ok((stream, peer)) => {
                    debug!("Connection from {peer}");
                    NodeMetrics::global().active_peers.inc();
                    let tx = tx_in.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_conn(stream, tx).await {
                            warn!("{peer}: {e}");
                        }
                        NodeMetrics::global().active_peers.dec();
                    });
                }
                Err(e) => error!("Accept: {e}"),
            }
        }
    }
}

async fn handle_conn(mut s: tokio::net::TcpStream, tx: mpsc::Sender<SphinxPacket>) -> Result<()> {
    use tokio::io::AsyncReadExt;
    let mut buf = vec![0u8; PACKET_SIZE];
    s.read_exact(&mut buf).await?;
    NodeMetrics::global().packets_received.inc();
    if let Ok(pkt) = bincode::deserialize::<SphinxPacket>(&buf) {
        tx.send(pkt).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_node_binds() {
        let mut c = NodeConfig::default();
        c.network.listen_addr = "127.0.0.1:0".to_string();
        assert!(MixNode::new(c).await.is_ok());
    }
    #[tokio::test]
    async fn test_node_invalid_addr() {
        let mut c = NodeConfig::default();
        c.network.listen_addr = "999.999.999.999:9999".to_string();
        assert!(MixNode::new(c).await.is_err());
    }
}
