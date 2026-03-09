//! Message sending — constructs a Sphinx onion packet and injects it into
//! the mixnet via TCP.
//!
//! ## Payload framing
//!
//! The 1856-byte Sphinx payload is structured as:
//!   [4 bytes: u32 LE message length][message bytes][zero padding]
//!
//! This lets the recipient strip padding after the final peel.

use crate::route::RouteSelector;
use anyhow::{anyhow, Result};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::Duration;
use tracing::{debug, info};
use zksn_crypto::sphinx::{build_packet, SphinxPacket};

/// Maximum message size: PAYLOAD_LEN - 4 bytes for length prefix.
pub const MAX_MESSAGE_LEN: usize = 1852;

/// Send `payload` through the mixnet to `recipient_pubkey`.
///
/// `recipient_pubkey` is the X25519 public key of the recipient (hex or raw).
/// The route is selected from live peers in `selector`.
pub async fn send_message(
    selector: &RouteSelector,
    recipient_pubkey: [u8; 32],
    payload: &[u8],
    hop_count: usize,
) -> Result<()> {
    if payload.len() > MAX_MESSAGE_LEN {
        return Err(anyhow!(
            "Message too large: {} bytes (max {MAX_MESSAGE_LEN})",
            payload.len()
        ));
    }

    // Build route: [mix_1 .. mix_n, recipient]
    let (route, entry_addr) = selector.build_route(hop_count, recipient_pubkey).await?;

    debug!(
        "Sending {} bytes via {} hops, entry={}",
        payload.len(),
        route.len(),
        entry_addr
    );

    // Frame: [u32 LE len | payload | padding]
    let framed = frame_payload(payload)?;

    // Build Sphinx packet
    let pkt = build_packet(&route, &framed, &mut rand::thread_rng())
        .map_err(|e| anyhow!("Sphinx build_packet: {e:?}"))?;

    // Inject into mixnet
    inject_packet(&entry_addr, &pkt).await?;

    info!(
        "Sent {} bytes → {} hops → entry {}",
        payload.len(),
        route.len(),
        entry_addr
    );
    Ok(())
}

/// Frame `payload` into a fixed-size Sphinx payload buffer.
pub fn frame_payload(payload: &[u8]) -> Result<Vec<u8>> {
    use zksn_crypto::sphinx::PACKET_SIZE;
    // PAYLOAD_LEN = PACKET_SIZE - 32 (ephemeral key) - 160 (header) = 1856
    const PAYLOAD_LEN: usize = PACKET_SIZE - 32 - 160;

    if payload.len() > PAYLOAD_LEN - 4 {
        return Err(anyhow!("Payload too large for Sphinx packet"));
    }

    let mut buf = vec![0u8; PAYLOAD_LEN];
    let len = payload.len() as u32;
    buf[..4].copy_from_slice(&len.to_le_bytes());
    buf[4..4 + payload.len()].copy_from_slice(payload);
    Ok(buf)
}

/// TCP-connect to `addr` and write a serialised Sphinx packet.
async fn inject_packet(addr: &str, pkt: &SphinxPacket) -> Result<()> {
    let mut stream = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow!("Connection timeout to entry node {addr}"))?
        .map_err(|e| anyhow!("Cannot connect to entry node {addr}: {e}"))?;

    let buf = pkt.to_bytes();
    stream.write_all(&buf).await?;
    stream.flush().await?;
    debug!("Injected packet → {addr}");
    Ok(())
}

/// Extract the message from a framed Sphinx payload (after final peel).
pub fn unframe_payload(payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() < 4 {
        return Err(anyhow!("Payload too short to unframe"));
    }
    let len = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
    if len > payload.len() - 4 {
        return Err(anyhow!("Framed length {len} exceeds payload"));
    }
    Ok(payload[4..4 + len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_unframe_roundtrip() {
        let msg = b"hello zksn";
        let framed = frame_payload(msg).unwrap();
        assert_eq!(framed.len(), 1856);
        let recovered = unframe_payload(&framed).unwrap();
        assert_eq!(recovered, msg);
    }

    #[test]
    fn test_frame_empty_message() {
        let framed = frame_payload(b"").unwrap();
        assert_eq!(framed.len(), 1856);
        let recovered = unframe_payload(&framed).unwrap();
        assert_eq!(recovered, b"");
    }

    #[test]
    fn test_frame_max_size() {
        let msg = vec![0xABu8; MAX_MESSAGE_LEN];
        let framed = frame_payload(&msg).unwrap();
        assert_eq!(unframe_payload(&framed).unwrap(), msg);
    }

    #[test]
    fn test_frame_oversized_rejected() {
        let msg = vec![0u8; MAX_MESSAGE_LEN + 1];
        assert!(frame_payload(&msg).is_err());
    }

    #[test]
    fn test_unframe_garbage_length_rejected() {
        let mut buf = vec![0u8; 1856];
        // Set length to 9999 — far beyond buffer
        buf[..4].copy_from_slice(&9999u32.to_le_bytes());
        assert!(unframe_payload(&buf).is_err());
    }
}

// ── Payment-wrapped send ──────────────────────────────────────────────────────

/// Send `payload` through the mixnet with a Cashu `PaymentEnvelope`.
///
/// Wire format written to the entry node's TCP stream:
/// ```text
/// [4 bytes: b"ZKSN"]
/// [4 bytes: u32 LE token_json_len]
/// [token_json_len bytes: CashuToken JSON]
/// [PACKET_SIZE bytes: Sphinx packet]
/// ```
///
/// Use this in mainnet mode.  `send_message` (no token) is for testnet only.
pub async fn send_message_with_payment(
    selector: &RouteSelector,
    recipient_pubkey: [u8; 32],
    payload: &[u8],
    hop_count: usize,
    token: &zksn_economic::cashu::CashuToken,
) -> Result<()> {
    if payload.len() > MAX_MESSAGE_LEN {
        return Err(anyhow!(
            "Message too large: {} bytes (max {MAX_MESSAGE_LEN})",
            payload.len()
        ));
    }

    let (route, entry_addr) = selector.build_route(hop_count, recipient_pubkey).await?;
    let framed = frame_payload(payload)?;
    let pkt = build_packet(&route, &framed, &mut rand::thread_rng())
        .map_err(|e| anyhow!("Sphinx build_packet: {e:?}"))?;

    inject_packet_with_payment(&entry_addr, &pkt, token).await?;

    info!(
        "Sent {} bytes (payment attached) → {} hops → entry {}",
        payload.len(),
        route.len(),
        entry_addr
    );
    Ok(())
}

/// Write a `PaymentEnvelope` frame to `addr`.
async fn inject_packet_with_payment(
    addr: &str,
    pkt: &SphinxPacket,
    token: &zksn_economic::cashu::CashuToken,
) -> Result<()> {
    use zksn_node::node::PAYMENT_MAGIC;

    let token_json = serde_json::to_vec(token)?;
    let token_len = token_json.len() as u32;

    let mut stream = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow!("Connection timeout to {addr}"))??;

    stream.write_all(&PAYMENT_MAGIC).await?;
    stream.write_all(&token_len.to_le_bytes()).await?;
    stream.write_all(&token_json).await?;
    stream.write_all(&pkt.to_bytes()).await?;
    stream.flush().await?;

    debug!("Injected PaymentEnvelope → {addr}");
    Ok(())
}

#[cfg(test)]
mod payment_tests {
    use super::*;
    use zksn_economic::cashu::{CashuToken, Proof};

    fn make_token() -> CashuToken {
        CashuToken {
            mint: "http://mint.test:3338".into(),
            proofs: vec![Proof {
                amount: 1,
                id: "id1".into(),
                secret: "s1".into(),
                c: "c1".into(),
            }],
        }
    }

    #[test]
    fn test_payment_envelope_token_serializes() {
        let t = make_token();
        let json = serde_json::to_vec(&t).unwrap();
        let rt: CashuToken = serde_json::from_slice(&json).unwrap();
        assert_eq!(rt.total_value(), 1);
    }

    #[test]
    fn test_payment_envelope_magic_bytes() {
        use zksn_node::node::PAYMENT_MAGIC;
        assert_eq!(&PAYMENT_MAGIC, b"ZKSN");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_inject_packet_with_payment_roundtrip() {
        use tokio::io::AsyncReadExt;
        use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
        use zksn_crypto::sphinx::{build_packet, NodeIdentity, PACKET_SIZE};
        use zksn_node::node::PAYMENT_MAGIC;

        let sk = [0x11u8; 32];
        let pk: [u8; 32] = X25519PublicKey::from(&StaticSecret::from(sk)).to_bytes();
        let route = vec![NodeIdentity { public_key: pk }];
        let pkt = build_packet(&route, b"pay me", &mut rand::thread_rng()).unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let token = make_token();
        let pkt_c = pkt.clone();
        let addr_c = addr.clone();
        let tok_c = token.clone();
        tokio::spawn(async move {
            inject_packet_with_payment(&addr_c, &pkt_c, &tok_c)
                .await
                .unwrap();
        });

        let (mut s, _) = tokio::time::timeout(std::time::Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();

        let mut magic = [0u8; 4];
        s.read_exact(&mut magic).await.unwrap();
        assert_eq!(magic, PAYMENT_MAGIC);

        let mut len_buf = [0u8; 4];
        s.read_exact(&mut len_buf).await.unwrap();
        let token_len = u32::from_le_bytes(len_buf) as usize;
        assert!(token_len > 0);

        let mut token_bytes = vec![0u8; token_len];
        s.read_exact(&mut token_bytes).await.unwrap();
        let rt: CashuToken = serde_json::from_slice(&token_bytes).unwrap();
        assert_eq!(rt.total_value(), 1);

        let mut sphinx = vec![0u8; PACKET_SIZE];
        s.read_exact(&mut sphinx).await.unwrap();
        assert_eq!(sphinx, pkt.to_bytes());
    }
}
