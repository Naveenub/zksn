use crate::metrics::NodeMetrics;
use anyhow::Result;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::Duration;
use tracing::{debug, warn};
use zksn_crypto::sphinx::SphinxPacket;

pub struct PacketRouter {
    rx: mpsc::Receiver<(String, SphinxPacket)>,
}

impl PacketRouter {
    pub fn new(rx: mpsc::Receiver<(String, SphinxPacket)>) -> Self {
        Self { rx }
    }

    pub async fn run(&mut self) -> Result<()> {
        while let Some((addr, pkt)) = self.rx.recv().await {
            NodeMetrics::global().packets_forwarded.inc();
            let a = addr.clone();
            tokio::spawn(async move {
                if let Err(e) = send_packet(&a, &pkt).await {
                    warn!("Forward to {a}: {e}");
                }
            });
        }
        Ok(())
    }
}

async fn send_packet(addr: &str, pkt: &SphinxPacket) -> Result<()> {
    let stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow::anyhow!("connect timeout to {addr}"))?
        .map_err(|e| anyhow::anyhow!("connect {addr}: {e}"))?;

    let mut stream = stream;
    let buf = pkt.to_bytes();
    stream.write_all(&buf).await?;
    stream.flush().await?;
    debug!("Forwarded -> {addr}");
    Ok(())
}
