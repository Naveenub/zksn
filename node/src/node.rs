use crate::{
    config::NodeConfig,
    cover::CoverTrafficGenerator,
    metrics::NodeMetrics,
    mixer::PoissonMixer,
    peers::{PeerDiscovery, PeerTable},
    router::PacketRouter,
};
use anyhow::Result;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use zksn_crypto::sphinx::{peel_layer, SphinxPacket, PACKET_SIZE};

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
        let depth = self.config.mixing.max_queue_depth;

        // Channels — mixer now works with (addr, packet) pairs
        let (tx_in, rx_in) = mpsc::channel::<(String, SphinxPacket)>(depth);
        let (tx_out, rx_out) = mpsc::channel::<(String, SphinxPacket)>(depth);
        let (tx_cov, rx_cov) = mpsc::channel::<(String, SphinxPacket)>(1024);

        // Peer discovery
        let own_privkey = self.config.identity.routing_private_key();
        let own_pubkey = self.config.identity.routing_public_key();
        let discovery = Arc::new(PeerDiscovery::new(
            self.config.network.listen_addr.clone(),
            own_pubkey,
            self.config.network.bootstrap_peers.clone(),
            self.config.network.max_peers,
        ));
        let peers: Arc<PeerTable> = Arc::clone(&discovery.table);

        let disc_clone = Arc::clone(&discovery);
        tokio::spawn(async move {
            disc_clone.run().await;
        });

        // Mixer
        let mix_cfg = self.config.mixing.clone();
        tokio::spawn(async move {
            let mut m = PoissonMixer::new(mix_cfg, rx_in, rx_cov, tx_out);
            if let Err(e) = m.run().await {
                error!("Mixer: {e}");
            }
        });

        // Cover traffic
        let cov_cfg = self.config.mixing.clone();
        let cov_peers = Arc::clone(&peers);
        tokio::spawn(async move {
            let mut g = CoverTrafficGenerator::new(cov_cfg, tx_cov, cov_peers);
            if let Err(e) = g.run().await {
                error!("Cover: {e}");
            }
        });

        // Packet router
        tokio::spawn(async move {
            let mut r = PacketRouter::new(rx_out);
            if let Err(e) = r.run().await {
                error!("Router: {e}");
            }
        });

        info!("Mix node ready — peer discovery started");

        // Accept loop
        loop {
            match self.listener.accept().await {
                Ok((stream, peer_addr)) => {
                    debug!("Connection from {peer_addr}");
                    NodeMetrics::global().active_peers.inc();

                    let tx = tx_in.clone();
                    let privkey = own_privkey;
                    let peer_table = Arc::clone(&peers);
                    let disc = Arc::clone(&discovery);

                    tokio::spawn(async move {
                        if let Err(e) = handle_conn(stream, tx, &privkey, peer_table, disc).await {
                            warn!("{peer_addr}: {e}");
                        }
                        NodeMetrics::global().active_peers.dec();
                    });
                }
                Err(e) => error!("Accept: {e}"),
            }
        }
    }
}

/// Handle an incoming TCP connection.
///
/// Determines whether the incoming data is a Sphinx packet or a gossip
/// message by inspecting the first 4 bytes:
/// - If they look like a valid gossip length prefix (< 64 KiB) AND the
///   total frame size doesn't match `PACKET_SIZE`, treat as gossip.
/// - Otherwise deserialize as a Sphinx packet, peel one onion layer, and
///   forward (addr, peeled_packet) to the mixer.
async fn handle_conn(
    mut stream: tokio::net::TcpStream,
    tx: mpsc::Sender<(String, SphinxPacket)>,
    own_privkey: &[u8; 32],
    peers: Arc<PeerTable>,
    discovery: Arc<PeerDiscovery>,
) -> Result<()> {
    use tokio::io::AsyncReadExt;

    // Peek first 4 bytes to decide packet vs gossip
    let mut peek = [0u8; 4];
    stream.read_exact(&mut peek).await?;
    let possible_len = u32::from_le_bytes(peek) as usize;

    if possible_len < 65_536 && possible_len != PACKET_SIZE {
        // Gossip: prepend the 4 bytes back by handling inline
        // Re-assemble the stream with a cursor prefix
        let mut payload = vec![0u8; possible_len];
        stream.read_exact(&mut payload).await?;

        // Build a synthetic stream wrapper — use a cursor over the full frame
        use tokio::io::AsyncReadExt as _;
        let gossip_msg: crate::peers::GossipMsg = bincode::deserialize(&payload)?;

        // Delegate to discovery handler — re-inject full stream
        // For simplicity we handle the already-read message here
        match gossip_msg {
            crate::peers::GossipMsg::Announce { addr, public_key } => {
                debug!("Gossip Announce from {addr}");
                discovery
                    .table
                    .upsert(crate::peers::PeerInfo::new(addr, public_key))
                    .await;
            }
            crate::peers::GossipMsg::GetPeers => {
                discovery.handle_gossip(stream).await;
            }
            _ => {}
        }
        return Ok(());
    }

    // Sphinx packet: read remaining PACKET_SIZE - 4 bytes
    let mut rest = vec![0u8; PACKET_SIZE.saturating_sub(4)];
    stream.read_exact(&mut rest).await?;

    let mut buf = Vec::with_capacity(PACKET_SIZE);
    buf.extend_from_slice(&peek);
    buf.extend_from_slice(&rest);

    NodeMetrics::global().packets_received.inc();

    let pkt = bincode::deserialize::<SphinxPacket>(&buf)?;

    // Peel one Sphinx layer
    let (next_hop_key, peeled) =
        peel_layer(&pkt, own_privkey).map_err(|e| anyhow::anyhow!("peel_layer: {e}"))?;

    // Resolve next-hop pubkey → TCP address
    if next_hop_key == [0u8; 32] {
        // Final destination — deliver locally (stub: log for now)
        info!("Packet reached final destination — payload delivery pending DHT");
        return Ok(());
    }

    let addr = match peers.resolve(&next_hop_key).await {
        Some(a) => a,
        None => {
            warn!(
                "Unknown next-hop {}, dropping packet",
                hex::encode(&next_hop_key[..8])
            );
            return Ok(());
        }
    };

    tx.send((addr, peeled)).await?;
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
