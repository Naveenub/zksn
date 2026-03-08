//! Peer discovery — gossip protocol over TCP.
//!
//! ## Protocol
//!
//! Each node maintains a `PeerTable` (in-memory, `Arc<RwLock<>>`).
//! On startup the node connects to every `bootstrap_peers` address and:
//!   1. Sends `Announce` (own addr + X25519 routing pubkey).
//!   2. Sends `GetPeers` to fetch the remote's known peers.
//!   3. Merges the returned `Peers` list into its own table.
//!
//! Every `GOSSIP_INTERVAL` seconds the node re-announces itself to all
//! known peers and refreshes their peer lists.  Peers not seen within
//! `PEER_TTL` seconds are evicted.
//!
//! ## Message framing
//!
//! All gossip messages are length-prefixed: `[u32 LE][bincode payload]`.
//! Sphinx packet traffic uses a separate channel (see `node.rs`).

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};
use tracing::{debug, info, warn};

// ─── constants ──────────────────────────────────────────────────────────────

/// Seconds between gossip rounds.
const GOSSIP_INTERVAL: u64 = 60;
/// Seconds before an unresponsive peer is evicted.
const PEER_TTL: u64 = 300;
/// Max peers returned per `GetPeers` response.
const MAX_PEERS_RESPONSE: usize = 32;

// ─── peer info ───────────────────────────────────────────────────────────────

/// A known peer in the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// TCP address the peer listens on (e.g. `"1.2.3.4:9001"`).
    pub addr: String,
    /// X25519 public key used for Sphinx onion routing.
    pub public_key: [u8; 32],
    /// Unix timestamp (seconds) of last successful contact.
    pub last_seen: u64,
}

impl PeerInfo {
    pub fn new(addr: String, public_key: [u8; 32]) -> Self {
        Self {
            addr,
            public_key,
            last_seen: now_secs(),
        }
    }

    pub fn touch(&mut self) {
        self.last_seen = now_secs();
    }

    pub fn is_alive(&self) -> bool {
        now_secs().saturating_sub(self.last_seen) < PEER_TTL
    }
}

// ─── gossip messages ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub enum GossipMsg {
    /// Announce self: "I am at `addr` with routing key `public_key`."
    Announce { addr: String, public_key: [u8; 32] },
    /// Request the remote's peer list.
    GetPeers,
    /// Response: a list of known peers.
    Peers { peers: Vec<PeerInfo> },
    /// Acknowledge an Announce (no-op body, keeps connection alive for GetPeers).
    Ok,
}

// ─── peer table ──────────────────────────────────────────────────────────────

/// Shared, thread-safe in-memory peer registry.
#[derive(Clone, Default)]
pub struct PeerTable {
    inner: Arc<RwLock<HashMap<String, PeerInfo>>>,
    max_peers: usize,
}

impl PeerTable {
    pub fn new(max_peers: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            max_peers: max_peers.max(1),
        }
    }

    /// Insert or refresh a peer.
    pub async fn upsert(&self, info: PeerInfo) {
        let mut table = self.inner.write().await;
        if table.len() >= self.max_peers && !table.contains_key(&info.addr) {
            return; // table full, drop newcomer
        }
        table
            .entry(info.addr.clone())
            .and_modify(|e| e.touch())
            .or_insert(info);
    }

    /// Remove stale peers and return how many were evicted.
    pub async fn evict_stale(&self) -> usize {
        let mut table = self.inner.write().await;
        let before = table.len();
        table.retain(|_, v| v.is_alive());
        before - table.len()
    }

    /// Return up to `n` live peers.
    pub async fn sample(&self, n: usize) -> Vec<PeerInfo> {
        let table = self.inner.read().await;
        table
            .values()
            .filter(|p| p.is_alive())
            .take(n)
            .cloned()
            .collect()
    }

    /// Look up a peer by X25519 public key. Returns the TCP address if found.
    pub async fn resolve(&self, public_key: &[u8; 32]) -> Option<String> {
        let table = self.inner.read().await;
        table
            .values()
            .find(|p| &p.public_key == public_key)
            .map(|p| p.addr.clone())
    }

    /// Number of live peers currently known.
    pub async fn len(&self) -> usize {
        let table = self.inner.read().await;
        table.values().filter(|p| p.is_alive()).count()
    }

    /// All live peers as NodeIdentity values (for Sphinx route building).
    pub async fn identities(&self) -> Vec<zksn_crypto::sphinx::NodeIdentity> {
        let table = self.inner.read().await;
        table
            .values()
            .filter(|p| p.is_alive())
            .map(|p| zksn_crypto::sphinx::NodeIdentity {
                public_key: p.public_key,
            })
            .collect()
    }
}

// ─── peer discovery ──────────────────────────────────────────────────────────

/// Manages bootstrap connection and periodic gossip.
pub struct PeerDiscovery {
    /// Own listen address announced to peers.
    pub own_addr: String,
    /// Own X25519 routing public key announced to peers.
    pub own_pubkey: [u8; 32],
    /// Seed nodes from config.
    bootstrap_peers: Vec<String>,
    /// Shared peer table.
    pub table: PeerTable,
}

impl PeerDiscovery {
    pub fn new(
        own_addr: String,
        own_pubkey: [u8; 32],
        bootstrap_peers: Vec<String>,
        max_peers: usize,
    ) -> Self {
        Self {
            own_addr,
            own_pubkey,
            bootstrap_peers,
            table: PeerTable::new(max_peers),
        }
    }

    /// Run: bootstrap then gossip forever.
    pub async fn run(self: Arc<Self>) {
        // Initial bootstrap
        self.bootstrap().await;

        // Periodic gossip + eviction
        let mut ticker = interval(Duration::from_secs(GOSSIP_INTERVAL));
        loop {
            ticker.tick().await;
            self.gossip_round().await;
            let evicted = self.table.evict_stale().await;
            if evicted > 0 {
                debug!("Evicted {evicted} stale peers");
            }
            info!("Peer table: {} live peers", self.table.len().await);
        }
    }

    /// Connect to each bootstrap peer and exchange peer lists.
    async fn bootstrap(&self) {
        if self.bootstrap_peers.is_empty() {
            warn!("No bootstrap peers configured — running isolated");
            return;
        }
        for addr in &self.bootstrap_peers {
            match self.connect_and_exchange(addr).await {
                Ok(n) => info!("Bootstrap {addr}: learned {n} peers"),
                Err(e) => warn!("Bootstrap {addr} failed: {e}"),
            }
        }
    }

    /// Gossip with all currently known peers.
    async fn gossip_round(&self) {
        let peers = self.table.sample(MAX_PEERS_RESPONSE).await;
        for peer in peers {
            if let Err(e) = self.connect_and_exchange(&peer.addr).await {
                debug!("Gossip {}: {e}", peer.addr);
            }
        }
    }

    /// Open a connection, announce self, fetch peer list, merge results.
    async fn connect_and_exchange(&self, addr: &str) -> Result<usize> {
        let mut stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr))
            .await
            .map_err(|_| anyhow!("timeout"))?
            .map_err(|e| anyhow!("connect: {e}"))?;

        // Announce self
        send_msg(
            &mut stream,
            &GossipMsg::Announce {
                addr: self.own_addr.clone(),
                public_key: self.own_pubkey,
            },
        )
        .await?;

        // Request peers
        send_msg(&mut stream, &GossipMsg::GetPeers).await?;

        // Read response
        let msg = recv_msg(&mut stream).await?;
        match msg {
            GossipMsg::Peers { peers } => {
                let n = peers.len();
                for p in peers {
                    // Don't add ourselves
                    if p.addr != self.own_addr {
                        self.table.upsert(p).await;
                    }
                }
                // Add the peer we just spoke to
                self.table
                    .upsert(PeerInfo::new(addr.to_string(), [0u8; 32]))
                    .await;
                Ok(n)
            }
            _ => Err(anyhow!("unexpected response")),
        }
    }

    /// Handle an incoming gossip connection from a remote peer.
    pub async fn handle_gossip(&self, mut stream: TcpStream) {
        loop {
            let msg = match recv_msg(&mut stream).await {
                Ok(m) => m,
                Err(_) => break,
            };
            match msg {
                GossipMsg::Announce { addr, public_key } => {
                    debug!("Announce from {addr}");
                    self.table.upsert(PeerInfo::new(addr, public_key)).await;
                    let _ = send_msg(&mut stream, &GossipMsg::Ok).await;
                }
                GossipMsg::GetPeers => {
                    let peers = self.table.sample(MAX_PEERS_RESPONSE).await;
                    let _ = send_msg(&mut stream, &GossipMsg::Peers { peers }).await;
                    break; // one request per connection
                }
                _ => break,
            }
        }
    }
}

// ─── framing helpers ─────────────────────────────────────────────────────────

/// Send a length-prefixed bincode message.
async fn send_msg(stream: &mut TcpStream, msg: &GossipMsg) -> Result<()> {
    let payload = bincode::serialize(msg)?;
    let len = payload.len() as u32;
    stream.write_all(&len.to_le_bytes()).await?;
    stream.write_all(&payload).await?;
    stream.flush().await?;
    Ok(())
}

/// Receive a length-prefixed bincode message (max 64 KiB).
async fn recv_msg(stream: &mut TcpStream) -> Result<GossipMsg> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 65_536 {
        return Err(anyhow!("gossip message too large: {len}"));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(bincode::deserialize(&buf)?)
}

// ─── utility ─────────────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ─── tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_peer_table_upsert_and_sample() {
        let table = PeerTable::new(10);
        table
            .upsert(PeerInfo::new("1.2.3.4:9001".into(), [1u8; 32]))
            .await;
        table
            .upsert(PeerInfo::new("5.6.7.8:9001".into(), [2u8; 32]))
            .await;
        assert_eq!(table.len().await, 2);
        let sample = table.sample(10).await;
        assert_eq!(sample.len(), 2);
    }

    #[tokio::test]
    async fn test_peer_table_resolve() {
        let table = PeerTable::new(10);
        let key = [42u8; 32];
        table
            .upsert(PeerInfo::new("1.2.3.4:9001".into(), key))
            .await;
        let addr = table.resolve(&key).await;
        assert_eq!(addr, Some("1.2.3.4:9001".to_string()));
        let missing = table.resolve(&[0u8; 32]).await;
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn test_peer_table_max_peers() {
        let table = PeerTable::new(2);
        table
            .upsert(PeerInfo::new("1.1.1.1:9001".into(), [1u8; 32]))
            .await;
        table
            .upsert(PeerInfo::new("2.2.2.2:9001".into(), [2u8; 32]))
            .await;
        table
            .upsert(PeerInfo::new("3.3.3.3:9001".into(), [3u8; 32]))
            .await;
        // Third peer should be dropped — table capped at 2
        assert_eq!(table.len().await, 2);
    }

    #[tokio::test]
    async fn test_gossip_announce_exchange() {
        use tokio::net::TcpListener;

        // Spin up a mini gossip server
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap().to_string();

        let server_discovery = Arc::new(PeerDiscovery::new(
            server_addr.clone(),
            [0xAAu8; 32],
            vec![],
            16,
        ));
        let sd = server_discovery.clone();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                sd.handle_gossip(stream).await;
            }
        });

        // Client discovery connects and exchanges
        let client_discovery = Arc::new(PeerDiscovery::new(
            "127.0.0.1:9999".into(),
            [0xBBu8; 32],
            vec![server_addr.clone()],
            16,
        ));
        let result = client_discovery.connect_and_exchange(&server_addr).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_identities_returns_node_identities() {
        let table = PeerTable::new(10);
        table
            .upsert(PeerInfo::new("1.2.3.4:9001".into(), [7u8; 32]))
            .await;
        let ids = table.identities().await;
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].public_key, [7u8; 32]);
    }
}
