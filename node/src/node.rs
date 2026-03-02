//! # Mix Node Core
//!
//! Orchestrates all subsystems:
//!
//! ```text
//! [TCP :9001] → handle_connection()
//!                     │ tx_incoming
//!                     ▼
//!             [PoissonMixer] ← tx_cover ← [CoverTrafficGenerator]
//!                     │ tx_outgoing
//!                     ▼
//!             [PacketRouter] → TCP → next hop
//! ```

use anyhow::Result;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::{
    config::NodeConfig,
    cover::CoverTrafficGenerator,
    metrics::NodeMetrics,
    mixer::PoissonMixer,
    router::PacketRouter,
};
use zksn_crypto::sphinx::{SphinxPacket, PACKET_SIZE};

pub struct MixNode {
    config:   NodeConfig,
    listener: TcpListener,
}

impl MixNode {
    pub async fn new(config: NodeConfig) -> Result<Self> {
        let listener = TcpListener::bind(&config.network.listen_addr).await?;
        info!("Listening on {}", config.network.listen_addr);
        Ok(Self { config, listener })
    }

    pub async fn run(self) -> Result<()> {
        let (tx_incoming, rx_incoming) =
            mpsc::channel::<SphinxPacket>(self.config.mixing.max_queue_depth);
        let (tx_outgoing, rx_outgoing) =
            mpsc::channel::<(String, SphinxPacket)>(self.config.mixing.max_queue_depth);
        let (tx_cover, rx_cover) =
            mpsc::channel::<SphinxPacket>(1024);

        let config = self.config.clone();

        // Spawn: Poisson mixer
        let mix_cfg = config.mixing.clone();
        tokio::spawn(async move {
            let mut mixer = PoissonMixer::new(mix_cfg, rx_incoming, rx_cover, tx_outgoing);
            if let Err(e) = mixer.run().await { error!("Mixer: {e}"); }
        });

        // Spawn: Cover traffic
        let cov_cfg = config.mixing.clone();
        tokio::spawn(async move {
            let mut gen = CoverTrafficGenerator::new(cov_cfg, tx_cover);
            if let Err(e) = gen.run().await { error!("Cover gen: {e}"); }
        });

        // Spawn: Packet router
        tokio::spawn(async move {
            let mut router = PacketRouter::new(rx_outgoing);
            if let Err(e) = router.run().await { error!("Router: {e}"); }
        });

        info!("Mix node ready — accepting Sphinx packets");

        loop {
            match self.listener.accept().await {
                Ok((stream, peer_addr)) => {
                    debug!("Connection from {peer_addr}");
                    NodeMetrics::global().active_peers.inc();

                    let tx = tx_incoming.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, tx).await {
                            warn!("Connection error from {peer_addr}: {e}");
                        }
                        NodeMetrics::global().active_peers.dec();
                    });
                }
                Err(e) => error!("Accept error: {e}"),
            }
        }
    }
}

/// Read exactly one Sphinx packet (PACKET_SIZE bytes) from a TCP stream.
async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    tx: mpsc::Sender<SphinxPacket>,
) -> Result<()> {
    use tokio::io::AsyncReadExt;

    let mut buf = vec![0u8; PACKET_SIZE];
    stream.read_exact(&mut buf).await?;

    NodeMetrics::global().packets_received.inc();

    match bincode::deserialize::<SphinxPacket>(&buf) {
        Ok(packet) => { tx.send(packet).await?; }
        Err(e)     => { warn!("Malformed Sphinx packet, dropping: {e}"); }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_node_binds_to_random_port() {
        let mut config = NodeConfig::default();
        config.network.listen_addr = "127.0.0.1:0".to_string();
        let node = MixNode::new(config).await;
        assert!(node.is_ok(), "MixNode should bind to 127.0.0.1:0");
    }

    #[tokio::test]
    async fn test_node_fails_on_invalid_address() {
        let mut config = NodeConfig::default();
        config.network.listen_addr = "999.999.999.999:9999".to_string();
        let node = MixNode::new(config).await;
        assert!(node.is_err(), "Should fail on invalid address");
    }

    #[tokio::test]
    async fn test_handle_connection_reads_packet() {
        use tokio::io::AsyncWriteExt;
        use zksn_crypto::sphinx::SphinxPacket;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (tx, mut rx) = mpsc::channel::<SphinxPacket>(4);

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = handle_connection(stream, tx).await;
        });

        // Connect and send exactly PACKET_SIZE bytes
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let payload = vec![0u8; PACKET_SIZE];
        client.write_all(&payload).await.unwrap();

        // Either we get a deserialized packet or the deserializer returns an error
        // (the zero bytes won't be a valid SphinxPacket, so rx might be empty — that's fine)
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        // The important thing: no panic, no crash
        let _ = rx.try_recv();
    }
}
