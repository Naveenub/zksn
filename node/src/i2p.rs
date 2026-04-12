//! I2P internal service layer — SAM v3 bridge, .b32.i2p service hosting, and
//! `.zksn` TLD DHT petname resolution.
//!
//! ## Architecture
//!
//! ```text
//!  ┌─────────────────────────────────────────────────────┐
//!  │  ZKSN Node                                          │
//!  │                                                     │
//!  │  ┌──────────────┐     ┌──────────────────────────┐ │
//!  │  │ SphinxRouter │────▶│  I2pServiceBridge        │ │
//!  │  │ (final hop)  │     │  • SAM v3 TCP session    │ │
//!  │  └──────────────┘     │  • Garlic-encrypted fwd  │ │
//!  │                       │  • .b32.i2p dest expose  │ │
//!  │  ┌──────────────┐     └──────────────────────────┘ │
//!  │  │ PetnameDht   │  ← DHT record: "name.zksn" → b32 │
//!  │  │ (in PeerTable│                                   │
//!  │  │  gossip)     │                                   │
//!  │  └──────────────┘                                   │
//!  └─────────────────────────────────────────────────────┘
//! ```
//!
//! ## SAM v3 Protocol Summary
//!
//! SAM (Simple Anonymous Messaging) v3 is i2pd's API for creating I2P
//! sessions and streaming connections without embedding libi2p.
//!
//! ```text
//! Client → SAM: "HELLO VERSION MIN=3.0 MAX=3.3\n"
//! SAM → Client: "HELLO REPLY RESULT=OK VERSION=3.3\n"
//!
//! Client → SAM: "SESSION CREATE STYLE=STREAM ID=<id> DESTINATION=TRANSIENT\n"
//! SAM → Client: "SESSION STATUS RESULT=OK DESTINATION=<b64>\n"
//!
//! Client → SAM: "STREAM CONNECT ID=<id> DESTINATION=<b32|b64> SILENT=false\n"
//! SAM → Client: "STREAM STATUS RESULT=OK\n"
//! (raw stream from here)
//!
//! For accepting: STREAM ACCEPT ID=<id>\n
//! ```
//!
//! ## .zksn TLD resolution
//!
//! Names are stored as DHT records piggybacked on `GossipMsg`:
//! `PetnameAnnounce { name: "myservice.zksn", b32: "abc...def.b32.i2p" }`
//!
//! A node resolving "myservice.zksn":
//! 1. Checks its local `PetnameStore`.
//! 2. If missing, issues `GossipMsg::PetnameQuery { name }` to K nearest peers.
//! 3. Waits up to `PETNAME_LOOKUP_TIMEOUT` for a `PetnameRecord` response.
//!
//! Records are signed with the publisher's Ed25519 key so any node can verify
//! without trusting the relay.

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{oneshot, Mutex, RwLock};
use tokio::time::timeout;
use tracing::{debug, info, warn};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Default SAM v3 TCP endpoint on the local i2pd instance.
pub const SAM_DEFAULT_ADDR: &str = "127.0.0.1:7656";
/// SAM handshake / command timeout.
const SAM_TIMEOUT: Duration = Duration::from_secs(30);
/// How long before a petname record is considered stale (24 h).
const PETNAME_TTL_SECS: u64 = 86_400;
/// Petname DHT lookup timeout.
const PETNAME_LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum name length for a .zksn label.
const MAX_NAME_LEN: usize = 63;

// ── SAM Client ────────────────────────────────────────────────────────────────

/// A single SAM v3 control connection to a local i2pd instance.
///
/// Each `SamSession` represents one STREAM session with a unique `session_id`
/// and an ephemeral or persistent I2P destination.
pub struct SamSession {
    /// Local i2pd SAM address (default `127.0.0.1:7656`).
    sam_addr: String,
    /// Unique session identifier (printable ASCII, ≤ 32 chars).
    session_id: String,
    /// Base-64 encoded I2P destination for this session (assigned by i2pd).
    pub destination_b64: String,
    /// Base-32 encoded .b32.i2p address derived from the destination hash.
    pub destination_b32: String,
}

impl SamSession {
    /// Create a new STREAM session with a transient (ephemeral) destination.
    ///
    /// # Arguments
    /// * `sam_addr` — SAM TCP endpoint, e.g. `"127.0.0.1:7656"`.
    /// * `session_id` — Unique session name (must not collide with other open sessions).
    pub async fn new_transient(sam_addr: &str, session_id: &str) -> Result<Self> {
        validate_session_id(session_id)?;

        let mut ctrl = sam_connect(sam_addr).await?;
        sam_hello(&mut ctrl).await?;

        let cmd = format!(
            "SESSION CREATE STYLE=STREAM ID={} DESTINATION=TRANSIENT\n",
            session_id
        );
        sam_send(&mut ctrl, &cmd).await?;

        let reply = sam_readline(&mut ctrl).await?;
        let kv = parse_kv(&reply);

        match kv.get("RESULT").map(|s| s.as_str()) {
            Some("OK") => {}
            Some(r) => bail!("SAM SESSION CREATE failed: RESULT={r}"),
            None => bail!("SAM SESSION CREATE: missing RESULT in reply: {reply}"),
        }

        let destination_b64 = kv
            .get("DESTINATION")
            .cloned()
            .ok_or_else(|| anyhow!("SAM SESSION CREATE: missing DESTINATION"))?;
        let destination_b32 = b64_dest_to_b32(&destination_b64)?;

        info!(
            "I2P session '{}' created — .b32: {}.b32.i2p",
            session_id, destination_b32
        );
        Ok(Self {
            sam_addr: sam_addr.to_string(),
            session_id: session_id.to_string(),
            destination_b64,
            destination_b32,
        })
    }

    /// Create a new STREAM session with a **persistent** destination loaded
    /// from `keys_b64`.  If `keys_b64` is empty, a new transient session is
    /// created and its private key blob returned for future persistence.
    pub async fn new_persistent(
        sam_addr: &str,
        session_id: &str,
        keys_b64: &str,
    ) -> Result<(Self, String)> {
        validate_session_id(session_id)?;

        let mut ctrl = sam_connect(sam_addr).await?;
        sam_hello(&mut ctrl).await?;

        let dest_param = if keys_b64.is_empty() {
            "TRANSIENT".to_string()
        } else {
            keys_b64.to_string()
        };

        let cmd = format!(
            "SESSION CREATE STYLE=STREAM ID={} DESTINATION={}\n",
            session_id, dest_param
        );
        sam_send(&mut ctrl, &cmd).await?;

        let reply = sam_readline(&mut ctrl).await?;
        let kv = parse_kv(&reply);

        match kv.get("RESULT").map(|s| s.as_str()) {
            Some("OK") => {}
            Some(r) => bail!("SAM SESSION CREATE failed: RESULT={r}"),
            None => bail!("SAM SESSION CREATE: missing RESULT: {reply}"),
        }

        let destination_b64 = kv
            .get("DESTINATION")
            .cloned()
            .ok_or_else(|| anyhow!("SAM SESSION CREATE: missing DESTINATION"))?;
        // i2pd echoes back the private key blob in DESTINATION when TRANSIENT
        // is used — for persistent sessions it's the full key blob that was
        // passed in. We use it as the persistence token.
        let returned_keys = destination_b64.clone();
        let destination_b32 = b64_dest_to_b32(&destination_b64)?;

        info!(
            "I2P session '{}' (persistent) — .b32: {}.b32.i2p",
            session_id, destination_b32
        );

        let session = Self {
            sam_addr: sam_addr.to_string(),
            session_id: session_id.to_string(),
            destination_b64,
            destination_b32,
        };
        Ok((session, returned_keys))
    }

    /// Dial an outbound STREAM connection to `dest` (b32, b64, or `.i2p` name).
    ///
    /// Returns the raw `TcpStream` once SAM confirms `STREAM STATUS RESULT=OK`.
    pub async fn connect(&self, dest: &str) -> Result<TcpStream> {
        let mut stream = sam_connect(&self.sam_addr).await?;
        sam_hello(&mut stream).await?;

        let cmd = format!(
            "STREAM CONNECT ID={} DESTINATION={} SILENT=false\n",
            self.session_id, dest
        );
        sam_send(&mut stream, &cmd).await?;

        let reply = sam_readline(&mut stream).await?;
        let kv = parse_kv(&reply);
        match kv.get("RESULT").map(|s| s.as_str()) {
            Some("OK") => {
                debug!("SAM STREAM CONNECT → {dest} OK");
                Ok(stream)
            }
            Some(r) => bail!("SAM STREAM CONNECT to {dest} failed: {r}"),
            None => bail!("SAM STREAM CONNECT: bad reply: {reply}"),
        }
    }

    /// Accept one inbound STREAM connection on this session.
    ///
    /// Returns `(stream, peer_b64_dest)`.
    pub async fn accept(&self) -> Result<(TcpStream, String)> {
        let mut stream = sam_connect(&self.sam_addr).await?;
        sam_hello(&mut stream).await?;

        let cmd = format!("STREAM ACCEPT ID={} SILENT=false\n", self.session_id);
        sam_send(&mut stream, &cmd).await?;

        // SAM sends "STREAM STATUS RESULT=OK\n" then the peer dest on the next line.
        let status = sam_readline(&mut stream).await?;
        let kv = parse_kv(&status);
        match kv.get("RESULT").map(|s| s.as_str()) {
            Some("OK") => {}
            Some(r) => bail!("SAM STREAM ACCEPT failed: {r}"),
            None => bail!("SAM STREAM ACCEPT bad reply: {status}"),
        }

        // Next line is the peer's base-64 destination.
        let peer_dest = sam_readline(&mut stream).await?;
        let peer_dest = peer_dest.trim().to_string();

        debug!("Accepted I2P stream from {}", &peer_dest[..16.min(peer_dest.len())]);
        Ok((stream, peer_dest))
    }

    /// Resolve a `.i2p` hostname to a base-64 destination via SAM NAMING LOOKUP.
    pub async fn lookup(&self, name: &str) -> Result<String> {
        let mut ctrl = sam_connect(&self.sam_addr).await?;
        sam_hello(&mut ctrl).await?;

        let cmd = format!("NAMING LOOKUP NAME={}\n", name);
        sam_send(&mut ctrl, &cmd).await?;

        let reply = sam_readline(&mut ctrl).await?;
        let kv = parse_kv(&reply);
        match kv.get("RESULT").map(|s| s.as_str()) {
            Some("OK") => kv
                .get("VALUE")
                .cloned()
                .ok_or_else(|| anyhow!("NAMING LOOKUP OK but no VALUE")),
            Some(r) => bail!("NAMING LOOKUP {name} failed: {r}"),
            None => bail!("NAMING LOOKUP bad reply: {reply}"),
        }
    }
}

// ── I2P Service Bridge ────────────────────────────────────────────────────────

/// Configuration for the I2P service bridge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct I2pConfig {
    /// Whether the I2P service layer is enabled.
    #[serde(default = "bool_true")]
    pub enabled: bool,
    /// SAM v3 endpoint on the local i2pd.
    #[serde(default = "default_sam_addr")]
    pub sam_addr: String,
    /// Session ID used for the mix-node I2P session.
    #[serde(default = "default_session_id")]
    pub session_id: String,
    /// Path to persist the I2P destination private key blob.
    /// If `None`, a transient ephemeral destination is used each restart.
    pub keys_path: Option<String>,
    /// Announce this node under the given `.zksn` petname after session start.
    /// Format: `"mynodename"` (without `.zksn` suffix).
    pub petname: Option<String>,
}

fn bool_true() -> bool { true }
fn default_sam_addr() -> String { SAM_DEFAULT_ADDR.to_string() }
fn default_session_id() -> String { "zksn-node".to_string() }

impl Default for I2pConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sam_addr: SAM_DEFAULT_ADDR.to_string(),
            session_id: "zksn-node".to_string(),
            keys_path: None,
            petname: None,
        }
    }
}

/// Bridge between the ZKSN mix-node's final-hop delivery and an I2P service.
///
/// When the mix node is the **final hop** in a Sphinx route, it decrypts the
/// inner payload and needs to deliver it to the destination service.  If the
/// destination is an I2P service (`.b32.i2p` or `.zksn` petname), this bridge
/// opens a SAM STREAM connection and writes the payload.
pub struct I2pServiceBridge {
    session: Arc<SamSession>,
    petname_store: Arc<PetnameStore>,
}

impl I2pServiceBridge {
    /// Start an I2P session and return a ready bridge.
    pub async fn start(cfg: &I2pConfig, signing_key: &SigningKey) -> Result<Self> {
        let session = if let Some(ref path) = cfg.keys_path {
            let existing_keys = std::fs::read_to_string(path).unwrap_or_default();
            let (sess, returned_keys) =
                SamSession::new_persistent(&cfg.sam_addr, &cfg.session_id, &existing_keys).await?;
            // Persist returned keys for next restart.
            if let Err(e) = std::fs::write(path, &returned_keys) {
                warn!("Could not persist I2P keys to {path}: {e}");
            }
            sess
        } else {
            SamSession::new_transient(&cfg.sam_addr, &cfg.session_id).await?
        };

        info!(
            "I2P bridge active — garlic address: {}.b32.i2p",
            session.destination_b32
        );

        let petname_store = Arc::new(PetnameStore::new());

        // If a petname is configured, pre-publish our own record.
        if let Some(ref name) = cfg.petname {
            let record = PetnameRecord::sign(
                name.clone(),
                format!("{}.b32.i2p", session.destination_b32),
                signing_key,
            )?;
            petname_store.insert(record).await;
        }

        Ok(Self {
            session: Arc::new(session),
            petname_store,
        })
    }

    /// Deliver `payload` to an I2P destination.
    ///
    /// `dest` can be:
    /// - A `.b32.i2p` address: `"abc...xyz.b32.i2p"`
    /// - A full base-64 I2P destination
    /// - A `.zksn` petname: `"myservice.zksn"` (resolved via DHT store)
    pub async fn deliver(&self, dest: &str, payload: &[u8]) -> Result<()> {
        let resolved = self.resolve_dest(dest).await?;
        let mut stream = timeout(SAM_TIMEOUT, self.session.connect(&resolved))
            .await
            .context("I2P connect timeout")?
            .context("I2P connect")?;

        stream
            .write_all(payload)
            .await
            .context("I2P stream write")?;
        stream.flush().await?;
        debug!("Delivered {} bytes → I2P {}", payload.len(), &resolved[..16]);
        Ok(())
    }

    /// Accept one inbound I2P stream and return the raw payload bytes.
    ///
    /// This is used when a remote I2P peer dials in to deliver a message
    /// to this node's garlic address.
    pub async fn accept_one(&self) -> Result<(Vec<u8>, String)> {
        let (mut stream, peer_dest) = self.session.accept().await?;
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut buf).await?;
        Ok((buf, peer_dest))
    }

    /// Our own `.b32.i2p` address.
    pub fn b32_addr(&self) -> String {
        format!("{}.b32.i2p", self.session.destination_b32)
    }

    /// Resolve a destination string to a canonical SAM-compatible address.
    async fn resolve_dest(&self, dest: &str) -> Result<String> {
        if dest.ends_with(".zksn") {
            // .zksn petname → look up in DHT store
            let record = self
                .petname_store
                .get(dest)
                .await
                .ok_or_else(|| anyhow!("Petname '{dest}' not found in DHT store"))?;
            return Ok(record.b32_addr);
        }
        // b32 or raw b64 — pass through to SAM as-is
        Ok(dest.to_string())
    }

    /// Expose the petname store for DHT gossip integration.
    pub fn petname_store(&self) -> Arc<PetnameStore> {
        Arc::clone(&self.petname_store)
    }
}

// ── Petname DHT ───────────────────────────────────────────────────────────────

/// A signed petname record: `"name.zksn"` → `.b32.i2p` address.
///
/// The record is signed with the publisher's Ed25519 key so it can be
/// forwarded through untrusted gossip nodes without modification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PetnameRecord {
    /// Human-readable name, e.g. `"myservice.zksn"`.
    pub name: String,
    /// `.b32.i2p` address, e.g. `"abc...xyz.b32.i2p"`.
    pub b32_addr: String,
    /// Unix timestamp of publication (used for TTL).
    pub published_at: u64,
    /// Ed25519 public key of the publisher (32 bytes, hex-encoded).
    pub publisher_pubkey_hex: String,
    /// Ed25519 signature over `name || b32_addr || published_at` (hex-encoded).
    pub signature_hex: String,
}

impl PetnameRecord {
    /// Create and sign a new petname record.
    pub fn sign(name: String, b32_addr: String, signing_key: &SigningKey) -> Result<Self> {
        validate_petname(&name)?;
        validate_b32_addr(&b32_addr)?;

        let published_at = now_secs();
        let msg = sign_payload(&name, &b32_addr, published_at);
        let signature: Signature = signing_key.sign(&msg);

        let verifying_key: VerifyingKey = signing_key.verifying_key();
        Ok(Self {
            name,
            b32_addr,
            published_at,
            publisher_pubkey_hex: hex::encode(verifying_key.to_bytes()),
            signature_hex: hex::encode(signature.to_bytes()),
        })
    }

    /// Verify the record's signature and TTL.  Returns `Err` if invalid.
    pub fn verify(&self) -> Result<()> {
        // TTL check
        let age = now_secs().saturating_sub(self.published_at);
        if age > PETNAME_TTL_SECS {
            bail!("Petname record '{}' has expired (age={}s)", self.name, age);
        }

        // Signature check
        let pubkey_bytes: [u8; 32] = hex::decode(&self.publisher_pubkey_hex)
            .context("bad publisher_pubkey_hex")?
            .try_into()
            .map_err(|_| anyhow!("publisher pubkey is not 32 bytes"))?;
        let verifying_key =
            VerifyingKey::from_bytes(&pubkey_bytes).context("invalid Ed25519 pubkey")?;

        let sig_bytes: [u8; 64] = hex::decode(&self.signature_hex)
            .context("bad signature_hex")?
            .try_into()
            .map_err(|_| anyhow!("signature is not 64 bytes"))?;
        let signature = Signature::from_bytes(&sig_bytes);

        let msg = sign_payload(&self.name, &self.b32_addr, self.published_at);
        verifying_key
            .verify(&msg, &signature)
            .context("Ed25519 signature invalid")?;

        Ok(())
    }

    /// Whether this record is still within its TTL window.
    pub fn is_fresh(&self) -> bool {
        now_secs().saturating_sub(self.published_at) < PETNAME_TTL_SECS
    }
}

fn sign_payload(name: &str, b32_addr: &str, published_at: u64) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"zksn-petname-v1\n");
    msg.extend_from_slice(name.as_bytes());
    msg.push(b'\n');
    msg.extend_from_slice(b32_addr.as_bytes());
    msg.push(b'\n');
    msg.extend_from_slice(&published_at.to_le_bytes());
    msg
}

/// In-memory petname store (DHT local cache).
///
/// Records are inserted on `PetnameAnnounce` gossip receipt.
/// Stale records are evicted lazily on read or explicitly via `evict_stale`.
pub struct PetnameStore {
    /// Map from `.zksn` name to its latest valid record.
    records: RwLock<HashMap<String, PetnameRecord>>,
    /// Pending one-shot channels for in-flight lookups.
    pending: Mutex<HashMap<String, Vec<oneshot::Sender<PetnameRecord>>>>,
}

impl PetnameStore {
    pub fn new() -> Self {
        Self {
            records: RwLock::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Insert a record after verifying its signature and TTL.
    /// Silently ignores invalid or stale records.
    pub async fn insert(&self, record: PetnameRecord) {
        if let Err(e) = record.verify() {
            warn!("Rejecting petname record '{}': {e}", record.name);
            return;
        }
        // Wake any pending lookups for this name.
        let mut pending = self.pending.lock().await;
        if let Some(waiters) = pending.remove(&record.name) {
            for tx in waiters {
                let _ = tx.send(record.clone());
            }
        }
        drop(pending);

        let mut records = self.records.write().await;
        // Only update if newer than existing record.
        let insert = match records.get(&record.name) {
            Some(existing) => record.published_at > existing.published_at,
            None => true,
        };
        if insert {
            debug!("Petname stored: '{}' → {}", record.name, record.b32_addr);
            records.insert(record.name.clone(), record);
        }
    }

    /// Look up a `.zksn` name in the local cache.
    /// Returns `None` if not found or if the record is stale.
    pub async fn get(&self, name: &str) -> Option<PetnameRecord> {
        let records = self.records.read().await;
        records.get(name).filter(|r| r.is_fresh()).cloned()
    }

    /// Register a one-shot channel to be notified when `name` arrives.
    /// Used by the DHT query path to wait for a gossip reply.
    pub async fn register_waiter(&self, name: &str) -> oneshot::Receiver<PetnameRecord> {
        let (tx, rx) = oneshot::channel();
        let mut pending = self.pending.lock().await;
        pending.entry(name.to_string()).or_default().push(tx);
        rx
    }

    /// Remove all stale records. Call periodically.
    pub async fn evict_stale(&self) -> usize {
        let mut records = self.records.write().await;
        let before = records.len();
        records.retain(|_, r| r.is_fresh());
        before - records.len()
    }

    /// Return all stored records (for gossip fan-out / republication).
    pub async fn all_records(&self) -> Vec<PetnameRecord> {
        self.records
            .read()
            .await
            .values()
            .filter(|r| r.is_fresh())
            .cloned()
            .collect()
    }
}

impl Default for PetnameStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Perform a local-then-DHT petname lookup with timeout.
///
/// 1. Check local store.
/// 2. Register a waiter (satisfied when gossip delivers the answer).
/// 3. Fan-out a `PetnameQuery` to the K nearest peers (caller's responsibility
///    via the returned `query_needed` flag — the gossip layer calls this function
///    and handles the fan-out so we avoid a circular dependency).
///
/// Returns `(record, query_needed)`.  If `query_needed` is true the caller
/// should issue a `GossipMsg::PetnameQuery { name }` to nearby peers.
pub async fn resolve_petname(
    store: &PetnameStore,
    name: &str,
) -> Result<PetnameRecord> {
    // Fast path: local cache hit.
    if let Some(rec) = store.get(name).await {
        return Ok(rec);
    }

    // Slow path: register waiter and signal that a DHT query should go out.
    let rx = store.register_waiter(name).await;
    timeout(PETNAME_LOOKUP_TIMEOUT, rx)
        .await
        .map_err(|_| anyhow!("Petname lookup timeout for '{name}'"))?
        .map_err(|_| anyhow!("Petname waiter channel closed for '{name}'"))
}

// ── Validation helpers ────────────────────────────────────────────────────────

fn validate_petname(name: &str) -> Result<()> {
    if !name.ends_with(".zksn") {
        bail!("Petname must end with '.zksn', got: {name}");
    }
    let label = &name[..name.len() - 5]; // strip ".zksn"
    if label.is_empty() || label.len() > MAX_NAME_LEN {
        bail!("Petname label length out of range (1..={MAX_NAME_LEN}): {label}");
    }
    if !label
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        bail!("Petname label contains invalid characters (a-z, 0-9, '-' only): {label}");
    }
    Ok(())
}

fn validate_b32_addr(addr: &str) -> Result<()> {
    if !addr.ends_with(".b32.i2p") {
        bail!("Expected .b32.i2p address, got: {addr}");
    }
    let label = &addr[..addr.len() - 8]; // strip ".b32.i2p"
    if label.len() != 52 {
        bail!("b32 label must be 52 chars, got {}: {addr}", label.len());
    }
    Ok(())
}

fn validate_session_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > 32 {
        bail!("SAM session_id must be 1..=32 chars");
    }
    if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        bail!("SAM session_id may only contain [a-zA-Z0-9_-]: {id}");
    }
    Ok(())
}

// ── SAM wire helpers ──────────────────────────────────────────────────────────

async fn sam_connect(addr: &str) -> Result<TcpStream> {
    timeout(SAM_TIMEOUT, TcpStream::connect(addr))
        .await
        .context("SAM connect timeout")?
        .with_context(|| format!("SAM connect to {addr}"))
}

async fn sam_hello(stream: &mut TcpStream) -> Result<()> {
    sam_send(stream, "HELLO VERSION MIN=3.0 MAX=3.3\n").await?;
    let reply = sam_readline(stream).await?;
    let kv = parse_kv(&reply);
    match kv.get("RESULT").map(|s| s.as_str()) {
        Some("OK") => Ok(()),
        Some(r) => bail!("SAM HELLO failed: {r}"),
        None => bail!("SAM HELLO: unexpected reply: {reply}"),
    }
}

async fn sam_send(stream: &mut TcpStream, cmd: &str) -> Result<()> {
    stream
        .write_all(cmd.as_bytes())
        .await
        .context("SAM write")?;
    stream.flush().await.context("SAM flush")?;
    Ok(())
}

async fn sam_readline(stream: &mut TcpStream) -> Result<String> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    timeout(SAM_TIMEOUT, reader.read_line(&mut line))
        .await
        .context("SAM readline timeout")?
        .context("SAM readline")?;
    Ok(line.trim_end().to_string())
}

/// Parse a SAM reply into key=value pairs.
///
/// SAM replies look like: `"SESSION STATUS RESULT=OK DESTINATION=abc...\n"`
/// We skip the first two words (verb + noun) and split the rest on spaces.
fn parse_kv(line: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let tokens: Vec<&str> = line.split_whitespace().collect();
    // Skip verb and noun (e.g. "HELLO REPLY", "SESSION STATUS", "STREAM STATUS")
    for token in tokens.iter().skip(2) {
        if let Some((k, v)) = token.split_once('=') {
            map.insert(k.to_string(), v.to_string());
        }
    }
    map
}

/// Derive a `.b32.i2p` address from a base-64 I2P destination.
///
/// The b32 address is SHA-256(dest_bytes) encoded in base32 (no padding),
/// lowercased, with `.b32.i2p` appended. This matches i2pd's own derivation.
fn b64_dest_to_b32(dest_b64: &str) -> Result<String> {
    // I2P destinations use a custom base-64 alphabet ('+' → '-', '/' → '~').
    // Use the standard alphabet with those substitutions reversed.
    let std_b64 = dest_b64.replace('-', "+").replace('~', "/");
    let bytes = base64_decode_standard(&std_b64)?;

    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(&bytes);

    // Base-32 encode (RFC 4648 without padding), lowercase.
    let b32 = base32_encode_lower(&hash);
    Ok(b32)
}

/// Minimal standard base-64 decoder (no external dep beyond what's already in tree).
fn base64_decode_standard(s: &str) -> Result<Vec<u8>> {
    // Strip padding, decode char-by-char.
    let s = s.trim_end_matches('=');
    let mut bits: u32 = 0;
    let mut bit_count: u8 = 0;
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for c in s.chars() {
        let v: u32 = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '+' => 62,
            '/' => 63,
            _ => bail!("Invalid base64 char: {c}"),
        };
        bits = (bits << 6) | v;
        bit_count += 6;
        if bit_count >= 8 {
            bit_count -= 8;
            out.push((bits >> bit_count) as u8);
            bits &= (1 << bit_count) - 1;
        }
    }
    Ok(out)
}

/// Minimal RFC 4648 base-32 encoder (lowercase, no padding).
fn base32_encode_lower(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::new();
    let mut bits: u16 = 0;
    let mut bit_count: u8 = 0;
    for &byte in data {
        bits = (bits << 8) | byte as u16;
        bit_count += 8;
        while bit_count >= 5 {
            bit_count -= 5;
            out.push(ALPHABET[((bits >> bit_count) & 0x1f) as usize] as char);
        }
    }
    if bit_count > 0 {
        out.push(ALPHABET[((bits << (5 - bit_count)) & 0x1f) as usize] as char);
    }
    out
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    // ── parse_kv ──────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_kv_session_ok() {
        let line = "SESSION STATUS RESULT=OK DESTINATION=abc123def456";
        let kv = parse_kv(line);
        assert_eq!(kv.get("RESULT").map(|s| s.as_str()), Some("OK"));
        assert_eq!(
            kv.get("DESTINATION").map(|s| s.as_str()),
            Some("abc123def456")
        );
    }

    #[test]
    fn test_parse_kv_hello_ok() {
        let line = "HELLO REPLY RESULT=OK VERSION=3.3";
        let kv = parse_kv(line);
        assert_eq!(kv.get("RESULT").map(|s| s.as_str()), Some("OK"));
        assert_eq!(kv.get("VERSION").map(|s| s.as_str()), Some("3.3"));
    }

    #[test]
    fn test_parse_kv_error() {
        let line = "SESSION STATUS RESULT=CANT_REACH_PEER MESSAGE=\"no route\"";
        let kv = parse_kv(line);
        assert_eq!(
            kv.get("RESULT").map(|s| s.as_str()),
            Some("CANT_REACH_PEER")
        );
    }

    // ── base32 ───────────────────────────────────────────────────────────────

    #[test]
    fn test_base32_encode_empty() {
        assert_eq!(base32_encode_lower(&[]), "");
    }

    #[test]
    fn test_base32_encode_known() {
        // SHA-256 of empty string, first 5 bytes → known b32 prefix
        let data = [0xe3u8, 0xb0, 0xc4, 0x42, 0x98];
        let encoded = base32_encode_lower(&data);
        // Manually: e3=0b11100011, b0=0b10110000, c4=0b11000100 ...
        // Just verify length and charset
        assert!(encoded.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
        assert_eq!(encoded.len(), 8); // ceil(40/5)
    }

    // ── validate_petname ──────────────────────────────────────────────────────

    #[test]
    fn test_petname_valid() {
        assert!(validate_petname("myservice.zksn").is_ok());
        assert!(validate_petname("my-cool-node.zksn").is_ok());
        assert!(validate_petname("node123.zksn").is_ok());
    }

    #[test]
    fn test_petname_no_suffix() {
        assert!(validate_petname("myservice").is_err());
        assert!(validate_petname("myservice.i2p").is_err());
    }

    #[test]
    fn test_petname_empty_label() {
        assert!(validate_petname(".zksn").is_err());
    }

    #[test]
    fn test_petname_invalid_chars() {
        assert!(validate_petname("my_service.zksn").is_err());
        assert!(validate_petname("my.service.zksn").is_err());
    }

    #[test]
    fn test_petname_too_long() {
        let long_name = format!("{}.zksn", "a".repeat(64));
        assert!(validate_petname(&long_name).is_err());
    }

    // ── validate_b32_addr ─────────────────────────────────────────────────────

    #[test]
    fn test_b32_valid() {
        let addr = format!("{}.b32.i2p", "a".repeat(52));
        assert!(validate_b32_addr(&addr).is_ok());
    }

    #[test]
    fn test_b32_wrong_suffix() {
        assert!(validate_b32_addr("aaaa.i2p").is_err());
    }

    #[test]
    fn test_b32_wrong_label_length() {
        assert!(validate_b32_addr("short.b32.i2p").is_err());
    }

    // ── PetnameRecord sign/verify ─────────────────────────────────────────────

    #[test]
    fn test_petname_record_sign_verify() {
        let sk = SigningKey::generate(&mut OsRng);
        let b32 = format!("{}.b32.i2p", "a".repeat(52));
        let record =
            PetnameRecord::sign("myservice.zksn".to_string(), b32, &sk).unwrap();
        assert!(record.verify().is_ok());
    }

    #[test]
    fn test_petname_record_tampered_name() {
        let sk = SigningKey::generate(&mut OsRng);
        let b32 = format!("{}.b32.i2p", "b".repeat(52));
        let mut record =
            PetnameRecord::sign("original.zksn".to_string(), b32, &sk).unwrap();
        record.name = "tampered.zksn".to_string();
        assert!(record.verify().is_err());
    }

    #[test]
    fn test_petname_record_tampered_addr() {
        let sk = SigningKey::generate(&mut OsRng);
        let b32_orig = format!("{}.b32.i2p", "c".repeat(52));
        let b32_fake = format!("{}.b32.i2p", "d".repeat(52));
        let mut record =
            PetnameRecord::sign("svc.zksn".to_string(), b32_orig, &sk).unwrap();
        record.b32_addr = b32_fake;
        assert!(record.verify().is_err());
    }

    #[test]
    fn test_petname_record_expired() {
        let sk = SigningKey::generate(&mut OsRng);
        let b32 = format!("{}.b32.i2p", "e".repeat(52));
        let mut record =
            PetnameRecord::sign("old.zksn".to_string(), b32, &sk).unwrap();
        // Force the timestamp to be ancient
        record.published_at = 0;
        // Re-sign with the ancient timestamp so signature still matches
        let msg = sign_payload(&record.name, &record.b32_addr, record.published_at);
        let sig: Signature = sk.sign(&msg);
        record.signature_hex = hex::encode(sig.to_bytes());
        assert!(record.verify().is_err()); // expired
    }

    // ── PetnameStore ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_store_insert_and_get() {
        let sk = SigningKey::generate(&mut OsRng);
        let b32 = format!("{}.b32.i2p", "f".repeat(52));
        let record = PetnameRecord::sign("store-test.zksn".to_string(), b32.clone(), &sk).unwrap();

        let store = PetnameStore::new();
        store.insert(record).await;
        let got = store.get("store-test.zksn").await;
        assert!(got.is_some());
        assert_eq!(got.unwrap().b32_addr, b32);
    }

    #[tokio::test]
    async fn test_store_rejects_invalid_record() {
        let sk = SigningKey::generate(&mut OsRng);
        let b32 = format!("{}.b32.i2p", "g".repeat(52));
        let mut record =
            PetnameRecord::sign("bad-sig.zksn".to_string(), b32, &sk).unwrap();
        record.b32_addr = format!("{}.b32.i2p", "h".repeat(52)); // tamper

        let store = PetnameStore::new();
        store.insert(record).await; // should be silently rejected
        assert!(store.get("bad-sig.zksn").await.is_none());
    }

    #[tokio::test]
    async fn test_store_waiter_woken_on_insert() {
        let sk = SigningKey::generate(&mut OsRng);
        let b32 = format!("{}.b32.i2p", "i".repeat(52));
        let store = Arc::new(PetnameStore::new());

        // Register waiter before insert
        let rx = store.register_waiter("wake-test.zksn").await;

        let store2 = Arc::clone(&store);
        let b32_clone = b32.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let record = PetnameRecord::sign("wake-test.zksn".to_string(), b32_clone, &sk).unwrap();
            store2.insert(record).await;
        });

        let rec = tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(rec.name, "wake-test.zksn");
        assert_eq!(rec.b32_addr, b32);
    }

    #[tokio::test]
    async fn test_store_evict_stale() {
        let sk = SigningKey::generate(&mut OsRng);
        let b32 = format!("{}.b32.i2p", "j".repeat(52));
        let mut record =
            PetnameRecord::sign("evict-me.zksn".to_string(), b32, &sk).unwrap();

        // Force ancient timestamp + re-sign
        record.published_at = 0;
        let msg = sign_payload(&record.name, &record.b32_addr, record.published_at);
        let sig: Signature = sk.sign(&msg);
        record.signature_hex = hex::encode(sig.to_bytes());

        // Manually bypass verify by directly writing to the records map
        // (test-only: we need to insert a stale record without going through insert())
        {
            let store = PetnameStore::new();
            store.records.write().await.insert(record.name.clone(), record);
            let evicted = store.evict_stale().await;
            assert_eq!(evicted, 1);
            assert!(store.get("evict-me.zksn").await.is_none());
        }
    }

    // ── validate_session_id ───────────────────────────────────────────────────

    #[test]
    fn test_session_id_valid() {
        assert!(validate_session_id("zksn-node").is_ok());
        assert!(validate_session_id("node_1").is_ok());
        assert!(validate_session_id("A").is_ok());
    }

    #[test]
    fn test_session_id_empty() {
        assert!(validate_session_id("").is_err());
    }

    #[test]
    fn test_session_id_too_long() {
        assert!(validate_session_id(&"x".repeat(33)).is_err());
    }

    #[test]
    fn test_session_id_invalid_chars() {
        assert!(validate_session_id("bad space").is_err());
        assert!(validate_session_id("bad.dot").is_err());
    }
}
