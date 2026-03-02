//! # Packet Router
//!
//! Forwards mixed packets to the next hop over TCP.
//! Each packet is sent as exactly PACKET_SIZE bytes (fixed-size framing).

use anyhow::Result;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use zksn_crypto::sphinx::{SphinxPacket, PACKET_SIZE};

/// Routes packets from the mixer output to their next hop.
pub struct PacketRouter {
    rx: mpsc::Receiver<(String, SphinxPacket)>,
}

impl PacketRouter {
    pub fn new(rx: mpsc::Receiver<(String, SphinxPacket)>) -> Self {
        Self { rx }
    }

    pub async fn run(&mut self) -> Result<()> {
        while let Some((next_hop, packet)) = self.rx.recv().await {
            let next_hop_clone = next_hop.clone();
            tokio::spawn(async move {
                if let Err(e) = send_packet(&next_hop_clone, &packet).await {
                    warn!("Failed to forward packet to {next_hop_clone}: {e}");
                }
            });
        }
        Ok(())
    }
}

/// Send a Sphinx packet to a remote node.
///
/// Packets are always exactly PACKET_SIZE bytes.
/// The receiver validates this and drops malformed-length connections.
async fn send_packet(addr: &str, packet: &SphinxPacket) -> Result<()> {
    let mut stream = TcpStream::connect(addr).await?;

    // Serialize to exactly PACKET_SIZE bytes
    let mut buf = bincode::serialize(packet)?;

    // Pad or truncate to fixed size
    buf.resize(PACKET_SIZE, 0u8);

    stream.write_all(&buf).await?;
    stream.flush().await?;

    debug!("Packet forwarded to {addr}");
    Ok(())
}
