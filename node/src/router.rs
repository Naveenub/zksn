use anyhow::Result;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, warn};
use crate::metrics::NodeMetrics;
use zksn_crypto::sphinx::{SphinxPacket, PACKET_SIZE};

pub struct PacketRouter { rx: mpsc::Receiver<(String, SphinxPacket)> }

impl PacketRouter {
    pub fn new(rx: mpsc::Receiver<(String, SphinxPacket)>) -> Self { Self { rx } }
    pub async fn run(&mut self) -> Result<()> {
        while let Some((hop, pkt)) = self.rx.recv().await {
            NodeMetrics::global().packets_forwarded.inc();
            let h = hop.clone();
            tokio::spawn(async move {
                if let Err(e) = send_packet(&h, &pkt).await { warn!("Forward to {h}: {e}"); }
            });
        }
        Ok(())
    }
}

async fn send_packet(addr: &str, pkt: &SphinxPacket) -> Result<()> {
    let mut stream = TcpStream::connect(addr).await?;
    let mut buf = bincode::serialize(pkt)?;
    buf.resize(PACKET_SIZE, 0u8);
    stream.write_all(&buf).await?;
    stream.flush().await?;
    debug!("Forwarded → {addr}");
    Ok(())
}
