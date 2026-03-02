//! # Mix Node Core
//!
//! Orchestrates all node subsystems:
//! - Incoming packet listener
//! - Poisson delay mixer
//! - Cover traffic generator
//! - Outgoing router
//! - Metrics server

use anyhow::Result;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::{
    config::NodeConfig,
    cover::CoverTrafficGenerator,
    mixer::PoissonMixer,
    router::PacketRouter,
};
use zksn_crypto::sphinx::{SphinxPacket, PACKET_SIZE};

/// Messages passed between node subsystems.
#[derive(Debug)]
pub enum NodeMessage {
    /// An incoming Sphinx packet to be mixed and forwarded
    IncomingPacket(SphinxPacket),
    /// A cover traffic packet (DROP or LOOP)
    CoverPacket(SphinxPacket),
    /// Shutdown signal
    Shutdown,
}

/// The main mix node. Owns all subsystems.
pub struct MixNode {
    config: NodeConfig,
    listener: TcpListener,
}

impl MixNode {
    /// Create a new mix node bound to the configured listen address.
    pub async fn new(config: NodeConfig) -> Result<Self> {
        let listener = TcpListener::bind(&config.network.listen_addr).await?;
        info!("Listening on {}", config.network.listen_addr);
        Ok(Self { config, listener })
    }

    /// Run the node forever (until shutdown signal).
    ///
    /// Internal architecture:
    /// ```
    /// [TCP Listener] ──→ [tx_incoming] ──→ [PoissonMixer] ──→ [tx_outgoing] ──→ [PacketRouter]
    ///                                              ↑
    /// [CoverTrafficGenerator] ──→ [tx_cover] ─────┘
    /// ```
    pub async fn run(self) -> Result<()> {
        // Channel: raw incoming packets → mixer
        let (tx_incoming, rx_incoming) = mpsc::channel::<SphinxPacket>(
            self.config.mixing.max_queue_depth,
        );

        // Channel: mixer output → router
        let (tx_outgoing, rx_outgoing) = mpsc::channel::<(String, SphinxPacket)>(
            self.config.mixing.max_queue_depth,
        );

        // Channel: cover traffic → mixer
        let (tx_cover, rx_cover) = mpsc::channel::<SphinxPacket>(1024);

        let config = self.config.clone();

        // Spawn: Poisson mixer
        let mixer_config = config.mixing.clone();
        let tx_out_clone = tx_outgoing.clone();
        tokio::spawn(async move {
            let mut mixer = PoissonMixer::new(
                mixer_config,
                rx_incoming,
                rx_cover,
                tx_out_clone,
            );
            if let Err(e) = mixer.run().await {
                error!("Mixer failed: {e}");
            }
        });

        // Spawn: Cover traffic generator
        let cover_config = config.mixing.clone();
        let tx_cover_clone = tx_cover.clone();
        tokio::spawn(async move {
            let mut gen = CoverTrafficGenerator::new(cover_config, tx_cover_clone);
            if let Err(e) = gen.run().await {
                error!("Cover traffic generator failed: {e}");
            }
        });

        // Spawn: Packet router
        tokio::spawn(async move {
            let mut router = PacketRouter::new(rx_outgoing);
            if let Err(e) = router.run().await {
                error!("Router failed: {e}");
            }
        });

        // Main loop: accept TCP connections, read Sphinx packets
        info!("Mix node ready. Accepting packets.");
        loop {
            match self.listener.accept().await {
                Ok((stream, peer_addr)) => {
                    debug!("New connection from {peer_addr}");
                    let tx = tx_incoming.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, tx).await {
                            warn!("Connection error from {peer_addr}: {e}");
                        }
                    });
                }
                Err(e) => {
                    error!("Accept error: {e}");
                }
            }
        }
    }
}

/// Read a single Sphinx packet from a TCP connection and enqueue it.
///
/// Packets are always exactly PACKET_SIZE bytes — this is enforced here.
/// Connections that send malformed sizes are dropped immediately.
async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    tx: mpsc::Sender<SphinxPacket>,
) -> Result<()> {
    use tokio::io::AsyncReadExt;

    // Read exactly PACKET_SIZE bytes — no more, no less
    let mut buf = vec![0u8; PACKET_SIZE];
    stream.read_exact(&mut buf).await?;

    // Deserialize Sphinx packet
    match bincode::deserialize::<SphinxPacket>(&buf) {
        Ok(packet) => {
            tx.send(packet).await?;
        }
        Err(e) => {
            warn!("Malformed packet received, dropping: {e}");
        }
    }

    Ok(())
}
