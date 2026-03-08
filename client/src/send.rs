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
use zksn_crypto::sphinx::{build_packet, SphinxPacket, PACKET_SIZE};

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

    let mut buf = bincode::serialize(pkt)?;
    buf.resize(PACKET_SIZE, 0u8);
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
