//! Peer discovery — Kademlia-lite DHT with gossip fan-out and peer persistence.
//!
//! ## Routing table: Kademlia k-buckets
//!
//! Peers are stored in 256 k-buckets indexed by XOR distance between the
//! local node ID and the peer's X25519 public key:
//!
//!   bucket_index = 255 - leading_zeros(own_id XOR peer_id)
//!
//! Each bucket holds at most K=8 peers (LRU eviction when full).
//! - resolve(pubkey)      → O(K)    one bucket scan
//! - find_closest(target) → O(K*256) bounded = O(2048) worst case
//!
//! ## Gossip fan-out
//!
//! After every exchange the node immediately dials up to FAN_OUT=3 of the
//! closest newly-discovered peers so the table grows beyond seed nodes
//! without waiting for the next gossip interval.
//!
//! ## Peer persistence
//!
//! The peer table is saved to `peer_store_path` (JSON) every GOSSIP_INTERVAL
//! seconds and loaded on startup.  If all seed nodes are unreachable the
//! node rejoins through previously persisted peers.
//!
//! ## Message framing
//!
//! All gossip messages are length-prefixed: [u32 LE][bincode payload].

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};
use tracing::{debug, info, warn};

// ─── constants ───────────────────────────────────────────────────────────────

const K: usize = 8;
const N_BUCKETS: usize = 256;
const GOSSIP_INTERVAL: u64 = 60;
const PEER_TTL: u64 = 300;
const MAX_PEERS_RESPONSE: usize = 32;
const FAN_OUT: usize = 3;

// ─── peer info ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub addr: String,
    pub public_key: [u8; 32],
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
    Announce { addr: String, public_key: [u8; 32] },
    GetPeers,
    Peers { peers: Vec<PeerInfo> },
    FindNode { target: [u8; 32] },
}

// ─── XOR distance helpers ────────────────────────────────────────────────────

fn xor_distance(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut d = [0u8; 32];
    for i in 0..32 {
        d[i] = a[i] ^ b[i];
    }
    d
}

fn leading_zeros(d: &[u8; 32]) -> usize {
    let mut count = 0usize;
    for byte in d.iter() {
        if *byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros() as usize;
            break;
        }
    }
    count
}

fn bucket_index(own_id: &[u8; 32], peer_key: &[u8; 32]) -> usize {
    if own_id == peer_key {
        return 0;
    }
    let d = xor_distance(own_id, peer_key);
    let lz = leading_zeros(&d).min(N_BUCKETS - 1);
    (N_BUCKETS - 1) - lz
}

// ─── k-bucket ────────────────────────────────────────────────────────────────

#[derive(Default, Clone, Serialize, Deserialize)]
struct KBucket {
    peers: Vec<PeerInfo>,
}

impl KBucket {
    fn upsert(&mut self, info: PeerInfo) {
        if let Some(pos) = self.peers.iter().position(|p| p.addr == info.addr) {
            let mut existing = self.peers.remove(pos);
            existing.touch();
            self.peers.push(existing);
        } else if self.peers.len() < K {
            self.peers.push(info);
        } else if let Some(pos) = self.peers.iter().position(|p| !p.is_alive()) {
            self.peers.remove(pos);
            self.peers.push(info);
        }
        // else: bucket full, all alive — drop newcomer (Kademlia long-lived preference)
    }

    fn resolve(&self, public_key: &[u8; 32]) -> Option<String> {
        self.peers
            .iter()
            .find(|p| &p.public_key == public_key)
            .map(|p| p.addr.clone())
    }

    fn live_peers(&self) -> impl Iterator<Item = &PeerInfo> {
        self.peers.iter().filter(|p| p.is_alive())
    }

    fn evict_stale(&mut self) -> usize {
        let before = self.peers.len();
        self.peers.retain(|p| p.is_alive());
        before - self.peers.len()
    }
}

// ─── peer table ──────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct PeerTable {
    own_id: [u8; 32],
    buckets: Arc<RwLock<Vec<KBucket>>>,
}

impl PeerTable {
    pub fn new(own_id: [u8; 32]) -> Self {
        Self {
            own_id,
            buckets: Arc::new(RwLock::new(vec![KBucket::default(); N_BUCKETS])),
        }
    }

    pub async fn upsert(&self, info: PeerInfo) {
        if info.public_key == self.own_id {
            return;
        }
        let idx = bucket_index(&self.own_id, &info.public_key);
        self.buckets.write().await[idx].upsert(info);
    }

    /// Resolve a peer's TCP address by exact X25519 public key. O(K).
    pub async fn resolve(&self, public_key: &[u8; 32]) -> Option<String> {
        let idx = bucket_index(&self.own_id, public_key);
        self.buckets.read().await[idx].resolve(public_key)
    }

    /// Return the `n` live peers closest to `target` by XOR distance.
    pub async fn find_closest(&self, target: &[u8; 32], n: usize) -> Vec<PeerInfo> {
        let buckets = self.buckets.read().await;
        let mut all: Vec<PeerInfo> = buckets
            .iter()
            .flat_map(|b| b.live_peers().cloned())
            .collect();
        all.sort_by(|a, b| {
            xor_distance(target, &a.public_key).cmp(&xor_distance(target, &b.public_key))
        });
        all.truncate(n);
        all
    }

    pub async fn sample(&self, n: usize) -> Vec<PeerInfo> {
        let buckets = self.buckets.read().await;
        let mut out = Vec::new();
        for bucket in buckets.iter() {
            for peer in bucket.live_peers() {
                out.push(peer.clone());
                if out.len() >= n {
                    return out;
                }
            }
        }
        out
    }

    pub async fn len(&self) -> usize {
        let buckets = self.buckets.read().await;
        buckets.iter().map(|b| b.live_peers().count()).sum()
    }

    pub async fn evict_stale(&self) -> usize {
        let mut buckets = self.buckets.write().await;
        buckets.iter_mut().map(|b| b.evict_stale()).sum()
    }

    pub async fn identities(&self) -> Vec<zksn_crypto::sphinx::NodeIdentity> {
        let buckets = self.buckets.read().await;
        buckets
            .iter()
            .flat_map(|b| b.live_peers())
            .map(|p| zksn_crypto::sphinx::NodeIdentity {
                public_key: p.public_key,
            })
            .collect()
    }

    pub async fn save(&self, path: &str) {
        let buckets = self.buckets.read().await;
        let peers: Vec<&PeerInfo> = buckets.iter().flat_map(|b| b.live_peers()).collect();
        match serde_json::to_string_pretty(&peers) {
            Ok(json) => {
                if let Err(e) = std::fs::write(path, json) {
                    warn!("Peer store write failed: {e}");
                } else {
                    debug!("Saved {} peers to {path}", peers.len());
                }
            }
            Err(e) => warn!("Peer serialization failed: {e}"),
        }
    }

    pub async fn load(&self, path: &str) {
        let data = match std::fs::read_to_string(path) {
            Ok(d) => d,
            Err(_) => return,
        };
        match serde_json::from_str::<Vec<PeerInfo>>(&data) {
            Ok(peers) => {
                let n = peers.len();
                for p in peers {
                    self.upsert(p).await;
                }
                info!("Loaded {n} peers from {path}");
            }
            Err(e) => warn!("Failed to parse peer store {path}: {e}"),
        }
    }
}

// ─── peer discovery ──────────────────────────────────────────────────────────

pub struct PeerDiscovery {
    pub own_addr: String,
    pub own_pubkey: [u8; 32],
    bootstrap_peers: Vec<String>,
    pub table: Arc<PeerTable>,
    peer_store_path: Option<String>,
}

impl PeerDiscovery {
    pub fn new(
        own_addr: String,
        own_pubkey: [u8; 32],
        bootstrap_peers: Vec<String>,
        peer_store_path: Option<String>,
    ) -> Self {
        Self {
            own_addr,
            own_pubkey,
            bootstrap_peers,
            table: Arc::new(PeerTable::new(own_pubkey)),
            peer_store_path,
        }
    }

    pub async fn run(self: Arc<Self>) {
        if let Some(path) = &self.peer_store_path {
            self.table.load(path).await;
        }

        self.bootstrap().await;

        let mut ticker = interval(Duration::from_secs(GOSSIP_INTERVAL));
        loop {
            ticker.tick().await;
            self.gossip_round().await;

            let evicted = self.table.evict_stale().await;
            if evicted > 0 {
                debug!("Evicted {evicted} stale peers");
            }

            if let Some(path) = &self.peer_store_path {
                self.table.save(path).await;
            }

            info!("Peer table: {} live peers", self.table.len().await);
        }
    }

    async fn bootstrap(&self) {
        let mut dialed = HashSet::new();

        if self.bootstrap_peers.is_empty() {
            if self.table.len().await == 0 {
                warn!("No bootstrap peers and empty peer store — node is isolated");
            } else {
                info!(
                    "No bootstrap peers — rejoining via {} persisted peers",
                    self.table.len().await
                );
                for p in self.table.sample(8).await {
                    if dialed.insert(p.addr.clone()) {
                        match self.connect_and_exchange(&p.addr).await {
                            Ok(n) => info!("Persisted {}: learned {n} peers", p.addr),
                            Err(e) => debug!("Persisted {}: {e}", p.addr),
                        }
                    }
                }
            }
            return;
        }

        for addr in &self.bootstrap_peers {
            if dialed.insert(addr.clone()) {
                match self.connect_and_exchange(addr).await {
                    Ok(n) => info!("Bootstrap {addr}: learned {n} peers"),
                    Err(e) => warn!("Bootstrap {addr} failed: {e}"),
                }
            }
        }

        self.fan_out(&mut dialed).await;
    }

    async fn gossip_round(&self) {
        let peers = self.table.sample(MAX_PEERS_RESPONSE).await;
        let mut dialed: HashSet<String> = peers.iter().map(|p| p.addr.clone()).collect();
        for peer in &peers {
            if let Err(e) = self.connect_and_exchange(&peer.addr).await {
                debug!("Gossip {}: {e}", peer.addr);
            }
        }
        self.fan_out(&mut dialed).await;
    }

    async fn fan_out(&self, already_dialed: &mut HashSet<String>) {
        let candidates = self.table.find_closest(&self.own_pubkey, FAN_OUT * 4).await;
        let mut count = 0;
        for peer in candidates {
            if count >= FAN_OUT {
                break;
            }
            if already_dialed.insert(peer.addr.clone()) {
                match self.connect_and_exchange(&peer.addr).await {
                    Ok(n) => {
                        debug!("Fan-out {}: learned {n} peers", peer.addr);
                        count += 1;
                    }
                    Err(e) => debug!("Fan-out {}: {e}", peer.addr),
                }
            }
        }
    }

    pub async fn connect_and_exchange(&self, addr: &str) -> Result<usize> {
        let mut stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr))
            .await
            .map_err(|_| anyhow!("timeout"))?
            .map_err(|e| anyhow!("connect: {e}"))?;

        send_msg(
            &mut stream,
            &GossipMsg::Announce {
                addr: self.own_addr.clone(),
                public_key: self.own_pubkey,
            },
        )
        .await?;

        send_msg(&mut stream, &GossipMsg::GetPeers).await?;

        match recv_msg(&mut stream).await? {
            GossipMsg::Peers { peers } => {
                let n = peers.len();
                for p in peers {
                    if p.addr != self.own_addr {
                        self.table.upsert(p).await;
                    }
                }
                Ok(n)
            }
            _ => Err(anyhow!("unexpected response")),
        }
    }

    pub async fn find_node(&self, addr: &str, target: [u8; 32]) -> Result<Vec<PeerInfo>> {
        let mut stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr))
            .await
            .map_err(|_| anyhow!("timeout"))?
            .map_err(|e| anyhow!("connect: {e}"))?;

        send_msg(&mut stream, &GossipMsg::FindNode { target }).await?;

        match recv_msg(&mut stream).await? {
            GossipMsg::Peers { peers } => Ok(peers),
            _ => Err(anyhow!("unexpected FindNode response")),
        }
    }

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
                }
                GossipMsg::GetPeers => {
                    let peers = self.table.sample(MAX_PEERS_RESPONSE).await;
                    let _ = send_msg(&mut stream, &GossipMsg::Peers { peers }).await;
                    break;
                }
                GossipMsg::FindNode { target } => {
                    let peers = self.table.find_closest(&target, K).await;
                    let _ = send_msg(&mut stream, &GossipMsg::Peers { peers }).await;
                    break;
                }
                _ => break,
            }
        }
    }
}

// ─── framing helpers ─────────────────────────────────────────────────────────

async fn send_msg(stream: &mut TcpStream, msg: &GossipMsg) -> Result<()> {
    let payload = bincode::serialize(msg)?;
    let len = payload.len() as u32;
    stream.write_all(&len.to_le_bytes()).await?;
    stream.write_all(&payload).await?;
    stream.flush().await?;
    Ok(())
}

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
        let table = PeerTable::new([0u8; 32]);
        table
            .upsert(PeerInfo::new("1.2.3.4:9001".into(), [1u8; 32]))
            .await;
        table
            .upsert(PeerInfo::new("5.6.7.8:9001".into(), [2u8; 32]))
            .await;
        assert_eq!(table.len().await, 2);
        assert_eq!(table.sample(10).await.len(), 2);
    }

    #[tokio::test]
    async fn test_peer_table_resolve() {
        let table = PeerTable::new([0u8; 32]);
        let key = [42u8; 32];
        table
            .upsert(PeerInfo::new("1.2.3.4:9001".into(), key))
            .await;
        assert_eq!(table.resolve(&key).await, Some("1.2.3.4:9001".to_string()));
        assert!(table.resolve(&[99u8; 32]).await.is_none());
    }

    #[tokio::test]
    async fn test_find_closest_ordering() {
        let table = PeerTable::new([0u8; 32]);
        let target = [0x10u8; 32];
        let mut close_key = [0x10u8; 32];
        close_key[31] ^= 1;
        let far_key = [0xFFu8; 32];
        table
            .upsert(PeerInfo::new("far:9001".into(), far_key))
            .await;
        table
            .upsert(PeerInfo::new("close:9001".into(), close_key))
            .await;
        let closest = table.find_closest(&target, 1).await;
        assert_eq!(closest[0].addr, "close:9001");
    }

    #[tokio::test]
    async fn test_xor_bucket_index() {
        let own = [0u8; 32];
        let mut peer = [0u8; 32];
        peer[31] = 1;
        // XOR last bit → 255 leading zeros → bucket 0
        assert_eq!(bucket_index(&own, &peer), 0);

        let mut peer2 = [0u8; 32];
        peer2[0] = 0x80;
        // XOR MSB → 0 leading zeros → bucket 255
        assert_eq!(bucket_index(&own, &peer2), 255);
    }

    #[tokio::test]
    async fn test_gossip_announce_exchange() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap().to_string();

        let server = Arc::new(PeerDiscovery::new(
            server_addr.clone(),
            [0xAAu8; 32],
            vec![],
            None,
        ));
        let sd = server.clone();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                sd.handle_gossip(stream).await;
            }
        });

        let client = Arc::new(PeerDiscovery::new(
            "127.0.0.1:9999".into(),
            [0xBBu8; 32],
            vec![server_addr.clone()],
            None,
        ));
        assert!(client.connect_and_exchange(&server_addr).await.is_ok());
    }

    #[tokio::test]
    async fn test_find_node_rpc() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap().to_string();

        let server = Arc::new(PeerDiscovery::new(
            server_addr.clone(),
            [0xAAu8; 32],
            vec![],
            None,
        ));
        server
            .table
            .upsert(PeerInfo::new("9.9.9.9:9001".into(), [0x55u8; 32]))
            .await;

        let sd = server.clone();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                sd.handle_gossip(stream).await;
            }
        });

        let client = Arc::new(PeerDiscovery::new(
            "127.0.0.1:9999".into(),
            [0xBBu8; 32],
            vec![],
            None,
        ));
        let peers = client.find_node(&server_addr, [0x55u8; 32]).await.unwrap();
        assert!(peers.iter().any(|p| p.addr == "9.9.9.9:9001"));
    }

    #[tokio::test]
    async fn test_identities_returns_node_identities() {
        let table = PeerTable::new([0u8; 32]);
        table
            .upsert(PeerInfo::new("1.2.3.4:9001".into(), [7u8; 32]))
            .await;
        let ids = table.identities().await;
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].public_key, [7u8; 32]);
    }

    #[tokio::test]
    async fn test_persistence_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.json").to_string_lossy().to_string();

        let table = PeerTable::new([0u8; 32]);
        table
            .upsert(PeerInfo::new("1.2.3.4:9001".into(), [1u8; 32]))
            .await;
        table
            .upsert(PeerInfo::new("5.6.7.8:9001".into(), [2u8; 32]))
            .await;
        table.save(&path).await;

        let table2 = PeerTable::new([0u8; 32]);
        table2.load(&path).await;
        assert_eq!(table2.len().await, 2);
        assert!(table2.resolve(&[1u8; 32]).await.is_some());
    }
}
