//! Internal service-hosting layer for the I2P bridge.
//!
//! I2P/SAM gives a node exactly one inbound destination (`accept_one` in
//! `i2p.rs`), so every service reachable over `.b32.i2p` / `.zksn` shares
//! that single stream. This module is the application layer that was
//! missing: a one-byte service-tag envelope prefixing each inbound payload,
//! and a `ServiceRouter` that dispatches the remainder to the addressed
//! service instead of discarding it.
//!
//! ## Wire format
//!
//!   [1 byte: ServiceTag][remaining bytes: service-specific payload]
//!
//! Senders prefix the tag with [`envelope`] before calling
//! `I2pServiceBridge::deliver`.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::warn;

/// Per-node inbox cap — bounds memory against an inbound-flood DoS, since
/// any I2P peer that knows this node's address can deliver a message.
const MAX_INBOX: usize = 1000;

// ─── envelope ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceTag {
    Messaging,
    Presence,
}

impl ServiceTag {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Messaging),
            0x02 => Some(Self::Presence),
            _ => None,
        }
    }

    pub fn to_byte(self) -> u8 {
        match self {
            Self::Messaging => 0x01,
            Self::Presence => 0x02,
        }
    }
}

/// Prefix `payload` with `tag` for delivery via `I2pServiceBridge::deliver`.
pub fn envelope(tag: ServiceTag, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(tag.to_byte());
    out.extend_from_slice(payload);
    out
}

// ─── messaging service ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StoredMessage {
    pub from: String,
    pub payload: Vec<u8>,
    pub received_at: u64,
}

/// Minimal store-and-forward inbox. Any I2P peer that knows this node's
/// `.b32.i2p` / `.zksn` address can deliver a message; local retrieval
/// (CLI/API) is out of scope here — see `drain`.
pub struct MessagingService {
    inbox: RwLock<VecDeque<StoredMessage>>,
}

impl MessagingService {
    pub fn new() -> Self {
        Self {
            inbox: RwLock::new(VecDeque::new()),
        }
    }

    async fn receive(&self, from: &str, payload: &[u8]) {
        let mut inbox = self.inbox.write().await;
        if inbox.len() >= MAX_INBOX {
            inbox.pop_front();
        }
        inbox.push_back(StoredMessage {
            from: from.to_string(),
            payload: payload.to_vec(),
            received_at: now_secs(),
        });
    }

    /// Drain all pending messages (oldest first).
    pub async fn drain(&self) -> Vec<StoredMessage> {
        self.inbox.write().await.drain(..).collect()
    }

    pub async fn len(&self) -> usize {
        self.inbox.read().await.len()
    }
}

impl Default for MessagingService {
    fn default() -> Self {
        Self::new()
    }
}

// ─── presence service ────────────────────────────────────────────────────────

/// Tracks last-seen timestamps for peers that ping this node. No outbound
/// pinging here — that's the caller's responsibility via `envelope`.
pub struct PresenceService {
    last_seen: RwLock<std::collections::HashMap<String, u64>>,
}

impl PresenceService {
    pub fn new() -> Self {
        Self {
            last_seen: RwLock::new(std::collections::HashMap::new()),
        }
    }

    async fn receive(&self, from: &str) {
        self.last_seen.write().await.insert(from.to_string(), now_secs());
    }

    /// Seconds since `dest` last pinged, or `None` if never seen.
    pub async fn last_seen_secs_ago(&self, dest: &str) -> Option<u64> {
        self.last_seen
            .read()
            .await
            .get(dest)
            .map(|t| now_secs().saturating_sub(*t))
    }
}

impl Default for PresenceService {
    fn default() -> Self {
        Self::new()
    }
}

// ─── router ──────────────────────────────────────────────────────────────────

/// Dispatches inbound I2P payloads to the service addressed by their leading
/// tag byte. Replaces the Phase-3 stub that discarded every inbound stream.
pub struct ServiceRouter {
    pub messaging: Arc<MessagingService>,
    pub presence: Arc<PresenceService>,
}

impl ServiceRouter {
    pub fn new() -> Self {
        Self {
            messaging: Arc::new(MessagingService::new()),
            presence: Arc::new(PresenceService::new()),
        }
    }

    /// Route one inbound stream's raw payload. `from` is the sender's I2P
    /// destination (b32 or full b64), as reported by `accept_one`.
    pub async fn dispatch(&self, from: &str, raw: &[u8]) {
        let (tag_byte, body) = match raw.split_first() {
            Some((t, b)) => (*t, b),
            None => {
                warn!("Service dispatch: empty payload from {}", short(from));
                return;
            }
        };
        match ServiceTag::from_byte(tag_byte) {
            Some(ServiceTag::Messaging) => self.messaging.receive(from, body).await,
            Some(ServiceTag::Presence) => self.presence.receive(from).await,
            None => warn!(
                "Service dispatch: unknown service tag 0x{tag_byte:02x} from {}",
                short(from)
            ),
        }
    }
}

impl Default for ServiceRouter {
    fn default() -> Self {
        Self::new()
    }
}

fn short(dest: &str) -> &str {
    &dest[..16.min(dest.len())]
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
    async fn test_dispatch_routes_messaging() {
        let router = ServiceRouter::new();
        let raw = envelope(ServiceTag::Messaging, b"hello");
        router.dispatch("abcd1234efgh5678.b32.i2p", &raw).await;
        assert_eq!(router.messaging.len().await, 1);
        let msgs = router.messaging.drain().await;
        assert_eq!(msgs[0].payload, b"hello");
        assert_eq!(msgs[0].from, "abcd1234efgh5678.b32.i2p");
    }

    #[tokio::test]
    async fn test_dispatch_ignores_unknown_tag() {
        let router = ServiceRouter::new();
        router.dispatch("peer.b32.i2p", &[0xFF, 1, 2, 3]).await;
        assert_eq!(router.messaging.len().await, 0);
    }

    #[tokio::test]
    async fn test_dispatch_ignores_empty_payload() {
        let router = ServiceRouter::new();
        router.dispatch("peer.b32.i2p", &[]).await;
        assert_eq!(router.messaging.len().await, 0);
    }

    #[tokio::test]
    async fn test_inbox_bounded() {
        let svc = MessagingService::new();
        for i in 0..(MAX_INBOX + 10) {
            svc.receive("peer", format!("{i}").as_bytes()).await;
        }
        assert_eq!(svc.len().await, MAX_INBOX);
    }

    #[tokio::test]
    async fn test_drain_empties_inbox() {
        let svc = MessagingService::new();
        svc.receive("peer", b"a").await;
        svc.receive("peer", b"b").await;
        assert_eq!(svc.drain().await.len(), 2);
        assert_eq!(svc.len().await, 0);
    }

    #[tokio::test]
    async fn test_dispatch_routes_presence() {
        let router = ServiceRouter::new();
        let raw = envelope(ServiceTag::Presence, b"");
        router.dispatch("peer.b32.i2p", &raw).await;
        assert!(router.presence.last_seen_secs_ago("peer.b32.i2p").await.is_some());
    }

    #[tokio::test]
    async fn test_presence_unknown_peer_is_none() {
        let svc = PresenceService::new();
        assert!(svc.last_seen_secs_ago("nobody").await.is_none());
    }
}
