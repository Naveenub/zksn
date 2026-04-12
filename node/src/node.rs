use crate::{
    config::NodeConfig,
    cover::CoverTrafficGenerator,
    i2p::I2pServiceBridge,
    metrics::NodeMetrics,
    mixer::PoissonMixer,
    network,
    payment::PaymentGuard,
    peers::{PeerDiscovery, PeerTable},
    router::PacketRouter,
};
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use zksn_crypto::sphinx::{peel_layer, SphinxPacket, PACKET_SIZE};

/// Magic prefix identifying a `PaymentEnvelope` frame (b"ZKSN").
///
/// Wire format:
///   [4 bytes: PAYMENT_MAGIC]
///   [4 bytes: u32 LE token_json_len]
///   [token_json_len bytes: CashuToken JSON]
///   [PACKET_SIZE bytes: Sphinx packet]
pub const PAYMENT_MAGIC: [u8; 4] = *b"ZKSN";

pub struct MixNode {
    config: NodeConfig,
    listener: TcpListener,
}

impl MixNode {
    pub async fn new(config: NodeConfig) -> Result<Self> {
        network::check_bind(&config.network.listen_addr, config.enforce_yggdrasil())?;
        let listener = TcpListener::bind(&config.network.listen_addr).await?;
        info!("Listening on {}", config.network.listen_addr);
        Ok(Self { config, listener })
    }

    pub async fn run(self) -> Result<()> {
        let depth = self.config.mixing.max_queue_depth;

        let (tx_in, rx_in) = mpsc::channel::<(String, SphinxPacket)>(depth);
        let (tx_out, rx_out) = mpsc::channel::<(String, SphinxPacket)>(depth);
        let (tx_cov, rx_cov) = mpsc::channel::<(String, SphinxPacket)>(1024);

        let own_privkey = self.config.identity.routing_private_key();
        let own_pubkey = self.config.identity.routing_public_key();
        let peer_store = self
            .config
            .keys
            .key_store_path
            .replace("identity.key", "peers.json");
        let mut discovery = PeerDiscovery::new_with_enforcement(
            self.config.network.listen_addr.clone(),
            own_pubkey,
            self.config.network.bootstrap_peers.clone(),
            Some(peer_store),
            self.config.enforce_yggdrasil(),
        );

        // ── I2P service layer ─────────────────────────────────────────────────
        // Start the bridge before wiring the petname store into discovery, so
        // the store exists before any gossip messages can arrive.
        let i2p_bridge: Option<Arc<I2pServiceBridge>> = if self.config.i2p.enabled {
            let signing_key = {
                // Derive a deterministic Ed25519 signing key from the node
                // identity for petname record signing.
                let seed = self.config.identity.identity().to_secret_bytes();
                let mut h = Sha256::new();
                h.update(b"zksn-petname-signing-v1");
                h.update(seed);
                let bytes: [u8; 32] = h.finalize().into();
                ed25519_dalek::SigningKey::from_bytes(&bytes)
            };
            match I2pServiceBridge::start(&self.config.i2p, &signing_key).await {
                Ok(bridge) => {
                    let bridge = Arc::new(bridge);
                    // Wire petname store into discovery for gossip handling.
                    discovery = discovery.with_petname_store(bridge.petname_store());
                    info!("I2P bridge: {}", bridge.b32_addr());
                    Some(bridge)
                }
                Err(e) => {
                    warn!("I2P bridge unavailable (i2pd not running?): {e}");
                    None
                }
            }
        } else {
            info!("I2P layer disabled in config");
            None
        };

        let discovery = Arc::new(discovery);
        let peers: Arc<PeerTable> = Arc::clone(&discovery.table);

        let disc_clone = Arc::clone(&discovery);
        tokio::spawn(async move {
            disc_clone.run().await;
        });

        // ── I2P inbound accept + petname republish ────────────────────────────
        if let Some(ref bridge) = i2p_bridge {
            // Spawn a task that accepts inbound I2P streams and logs/discards
            // them (application-layer services hook in here in Phase 3+).
            let bridge_accept = Arc::clone(bridge);
            tokio::spawn(async move {
                loop {
                    match bridge_accept.accept_one().await {
                        Ok((payload, peer)) => {
                            debug!(
                                "I2P inbound {} bytes from {}…",
                                payload.len(),
                                &peer[..16.min(peer.len())]
                            );
                            // TODO(phase3): dispatch to internal service router.
                        }
                        Err(e) => warn!("I2P accept error: {e}"),
                    }
                }
            });

            // Republish our petname record every 6 hours so it stays fresh.
            let disc_petname = Arc::clone(&discovery);
            let i2p_cfg = self.config.i2p.clone();
            let bridge_b32 = bridge.b32_addr();
            let identity_bytes = self.config.identity.identity().to_secret_bytes();
            tokio::spawn(async move {
                let mut h = Sha256::new();
                h.update(b"zksn-petname-signing-v1");
                h.update(identity_bytes);
                let bytes: [u8; 32] = h.finalize().into();
                let sk = ed25519_dalek::SigningKey::from_bytes(&bytes);

                let mut ticker =
                    tokio::time::interval(std::time::Duration::from_secs(6 * 3600));
                loop {
                    ticker.tick().await;
                    if let Some(ref name) = i2p_cfg.petname {
                        let full_name = format!("{}.zksn", name);
                        match crate::i2p::PetnameRecord::sign(
                            full_name.clone(),
                            bridge_b32.clone(),
                            &sk,
                        ) {
                            Ok(record) => {
                                disc_petname.announce_petname(record).await;
                                info!("Petname '{full_name}' republished");
                            }
                            Err(e) => warn!("Petname republish failed: {e}"),
                        }
                    }
                }
            });
        }

        let payment_guard = Arc::new(PaymentGuard::new_with_yggdrasil(
            &self.config.economic,
            self.config.testnet,
            self.config.enforce_yggdrasil(),
        ));

        let mix_cfg = self.config.mixing.clone();
        tokio::spawn(async move {
            let mut m = PoissonMixer::new(mix_cfg, rx_in, rx_cov, tx_out);
            if let Err(e) = m.run().await {
                error!("Mixer: {e}");
            }
        });

        let cov_cfg = self.config.mixing.clone();
        let cov_peers = Arc::clone(&peers);
        tokio::spawn(async move {
            let mut g = CoverTrafficGenerator::new(cov_cfg, tx_cov, cov_peers);
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

        info!(
            "Mix node ready ({})",
            if self.config.testnet {
                "testnet — payments not enforced"
            } else {
                "mainnet — payment enforcement active"
            }
        );

        loop {
            match self.listener.accept().await {
                Ok((stream, peer_addr)) => {
                    debug!("Connection from {peer_addr}");
                    NodeMetrics::global().active_peers.inc();

                    let tx = tx_in.clone();
                    let privkey = own_privkey;
                    let listen_addr = self.config.network.listen_addr.clone();
                    let peer_table = Arc::clone(&peers);
                    let disc = Arc::clone(&discovery);
                    let guard = Arc::clone(&payment_guard);

                    tokio::spawn(async move {
                        if let Err(e) =
                            handle_conn(stream, tx, &privkey, listen_addr, peer_table, disc, guard)
                                .await
                        {
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

async fn handle_conn(
    mut stream: tokio::net::TcpStream,
    tx: mpsc::Sender<(String, SphinxPacket)>,
    own_privkey: &[u8; 32],
    own_listen_addr: String,
    peers: Arc<PeerTable>,
    discovery: Arc<PeerDiscovery>,
    payment_guard: Arc<PaymentGuard>,
) -> Result<()> {
    use tokio::io::AsyncReadExt;

    // Reject connections from outside the Yggdrasil address space.
    if payment_guard.enforce_yggdrasil() {
        if let Ok(peer_addr) = stream.peer_addr() {
            if !network::is_yggdrasil(&peer_addr.ip()) {
                anyhow::bail!(
                    "Rejected inbound connection from non-Yggdrasil address {peer_addr}. \
                     Set network.yggdrasil_only = false in node.toml to allow non-Yggdrasil peers."
                );
            }
        }
    }

    let mut peek = [0u8; 4];
    stream.read_exact(&mut peek).await?;

    // ── PaymentEnvelope ───────────────────────────────────────────────────────
    if peek == PAYMENT_MAGIC {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let token_len = u32::from_le_bytes(len_buf) as usize;

        if token_len == 0 || token_len > 65_536 {
            return Err(anyhow::anyhow!(
                "PaymentEnvelope token_len {token_len} out of range"
            ));
        }

        let mut token_bytes = vec![0u8; token_len];
        stream.read_exact(&mut token_bytes).await?;
        let token: zksn_economic::cashu::CashuToken = serde_json::from_slice(&token_bytes)
            .map_err(|e| anyhow::anyhow!("token deserialize: {e}"))?;

        payment_guard
            .check(&token)
            .await
            .map_err(|e| anyhow::anyhow!("Payment rejected: {e}"))?;

        let mut sphinx_buf = [0u8; PACKET_SIZE];
        stream.read_exact(&mut sphinx_buf).await?;

        NodeMetrics::global().packets_received.inc();
        let pkt = SphinxPacket::from_bytes(&sphinx_buf);
        return route_packet(pkt, own_privkey, own_listen_addr, peers, tx).await;
    }

    // ── Gossip ────────────────────────────────────────────────────────────────
    let possible_len = u32::from_le_bytes(peek) as usize;
    if possible_len < 65_536 && possible_len != PACKET_SIZE {
        let mut payload = vec![0u8; possible_len];
        stream.read_exact(&mut payload).await?;

        let gossip_msg: crate::peers::GossipMsg = bincode::deserialize(&payload)?;
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

    // ── Plain Sphinx (testnet / legacy) ───────────────────────────────────────
    let mut rest = vec![0u8; PACKET_SIZE.saturating_sub(4)];
    stream.read_exact(&mut rest).await?;

    let mut buf = Vec::with_capacity(PACKET_SIZE);
    buf.extend_from_slice(&peek);
    buf.extend_from_slice(&rest);

    NodeMetrics::global().packets_received.inc();

    let buf_arr: &[u8; PACKET_SIZE] = buf.as_slice().try_into()?;
    let pkt = SphinxPacket::from_bytes(buf_arr);
    route_packet(pkt, own_privkey, own_listen_addr, peers, tx).await
}

/// Peel one Sphinx layer then forward or deliver.
async fn route_packet(
    pkt: SphinxPacket,
    own_privkey: &[u8; 32],
    own_listen_addr: String,
    peers: Arc<PeerTable>,
    tx: mpsc::Sender<(String, SphinxPacket)>,
) -> Result<()> {
    let (next_hop_key, peeled) =
        peel_layer(&pkt, own_privkey).map_err(|e| anyhow::anyhow!("peel_layer: {e}"))?;

    if next_hop_key == [0u8; 32] {
        info!("Final-hop delivery → {own_listen_addr}");
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                tokio::net::TcpStream::connect(&own_listen_addr),
            )
            .await
            {
                Ok(Ok(mut s)) => {
                    let buf = peeled.to_bytes();
                    if let Err(e) = s.write_all(&buf).await {
                        warn!("Final-hop write to {own_listen_addr}: {e}");
                    }
                }
                Ok(Err(e)) => warn!("Final-hop connect to {own_listen_addr}: {e}"),
                Err(_) => warn!("Final-hop connect timeout to {own_listen_addr}"),
            }
        });
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
        c.network.yggdrasil_only = false;
        assert!(MixNode::new(c).await.is_ok());
    }

    #[tokio::test]
    async fn test_node_invalid_addr() {
        let mut c = NodeConfig::default();
        c.network.listen_addr = "999.999.999.999:9999".to_string();
        c.network.yggdrasil_only = false;
        assert!(MixNode::new(c).await.is_err());
    }

    #[tokio::test]
    async fn test_node_rejects_non_yggdrasil_bind() {
        let mut c = NodeConfig::default();
        c.network.listen_addr = "127.0.0.1:0".to_string();
        c.network.yggdrasil_only = true;
        c.testnet = false;
        let err = MixNode::new(c).await.err().expect("should fail");
        assert!(err.to_string().contains("200::/7"));
        assert!(err.to_string().contains("yggdrasil_only"));
    }

    #[tokio::test]
    async fn test_node_testnet_bypasses_yggdrasil() {
        let mut c = NodeConfig::default();
        c.network.listen_addr = "127.0.0.1:0".to_string();
        c.network.yggdrasil_only = true;
        c.testnet = true;
        assert!(MixNode::new(c).await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_final_hop_delivers_to_listener() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
        use zksn_crypto::sphinx::{build_packet, peel_layer, NodeIdentity, PACKET_SIZE};

        let node_sk = [0x42u8; 32];
        let node_pk: [u8; 32] = X25519PublicKey::from(&StaticSecret::from(node_sk)).to_bytes();

        let delivery_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let delivery_addr = delivery_listener.local_addr().unwrap().to_string();

        let route = vec![NodeIdentity {
            public_key: node_pk,
        }];
        let pkt = build_packet(&route, b"hello final hop", &mut rand::thread_rng()).unwrap();

        let (next_hop, peeled) = peel_layer(&pkt, &node_sk).unwrap();
        assert_eq!(next_hop, [0u8; 32]);

        let addr = delivery_addr.clone();
        tokio::spawn(async move {
            let buf = peeled.to_bytes();
            let mut s = tokio::net::TcpStream::connect(&addr).await.unwrap();
            s.write_all(&buf).await.unwrap();
        });

        let (mut stream, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            delivery_listener.accept(),
        )
        .await
        .expect("accept timeout")
        .unwrap();

        let mut received = vec![0u8; PACKET_SIZE];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received.len(), PACKET_SIZE);
    }

    #[test]
    fn test_payment_magic_is_zksn() {
        assert_eq!(&PAYMENT_MAGIC, b"ZKSN");
    }
}
