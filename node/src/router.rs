//! # Packet Router
//!
//! Forwards packets from the Poisson mixer to the next hop over TCP.
//! Every packet is sent as exactly PACKET_SIZE bytes (fixed-size framing).

use anyhow::Result;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::metrics::NodeMetrics;
use zksn_crypto::sphinx::{SphinxPacket, PACKET_SIZE};

pub struct PacketRouter {
    rx: mpsc::Receiver<(String, SphinxPacket)>,
}

impl PacketRouter {
    pub fn new(rx: mpsc::Receiver<(String, SphinxPacket)>) -> Self {
        Self { rx }
    }

    pub async fn run(&mut self) -> Result<()> {
        while let Some((next_hop, packet)) = self.rx.recv().await {
            NodeMetrics::global().packets_forwarded.inc();
            let hop = next_hop.clone();
            tokio::spawn(async move {
                if let Err(e) = send_packet(&hop, &packet).await {
                    warn!("Failed to forward to {hop}: {e}");
                }
            });
        }
        Ok(())
    }
}

/// Send a Sphinx packet to a peer node.
/// Serializes and pads to exactly PACKET_SIZE bytes.
async fn send_packet(addr: &str, packet: &SphinxPacket) -> Result<()> {
    let mut stream = TcpStream::connect(addr).await?;

    let mut buf = bincode::serialize(packet)?;
    buf.resize(PACKET_SIZE, 0u8);

    stream.write_all(&buf).await?;
    stream.flush().await?;

    debug!("Forwarded packet → {addr}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_send_packet_fixed_size() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let recv = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; PACKET_SIZE + 128]; // oversized
            let n = stream.read(&mut buf).await.unwrap();
            n
        });

        let packet = SphinxPacket {
            ephemeral_public_key: [0u8; 32],
            routing_header:       vec![0u8; 96],
            payload:              vec![0u8; PACKET_SIZE - 128],
        };

        send_packet(&addr.to_string(), &packet).await.unwrap();

        let bytes_sent = recv.await.unwrap();
        assert_eq!(bytes_sent, PACKET_SIZE, "Router must send exactly PACKET_SIZE bytes");
    }

    #[tokio::test]
    async fn test_router_forwards_to_channel() {
        let (tx, rx) = mpsc::channel::<(String, SphinxPacket)>(4);
        let mut router = PacketRouter::new(rx);

        // Drop tx so router.run() returns when channel is empty
        let packet = SphinxPacket {
            ephemeral_public_key: [1u8; 32],
            routing_header:       vec![0u8; 96],
            payload:              vec![0u8; 64],
        };

        // Close channel immediately after sending — router drains then exits
        tx.send(("127.0.0.1:1".to_string(), packet)).await.unwrap();
        drop(tx);

        // run() should return Ok after channel closes
        let result = tokio::time::timeout(
            tokio::time::Duration::from_millis(200),
            router.run(),
        ).await;
        assert!(result.is_ok(), "router.run() should return when channel closes");
    }
}
