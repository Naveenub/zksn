//! Sphinx packet format — fixed 2048-byte onion packets.
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

pub const PACKET_SIZE: usize    = 2048;
pub const MAX_HOPS: usize       = 5;
pub const HOP_HEADER_SIZE: usize = 32;

#[derive(Debug, Error)]
pub enum SphinxError {
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed — MAC mismatch or wrong key")]
    DecryptionFailed,
    #[error("Packet too large")]
    PacketTooLarge,
    #[error("Invalid route — must be 1 to {MAX_HOPS} hops")]
    InvalidRoute,
}

/// A node identity for routing purposes (X25519 public key).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeIdentity {
    pub public_key: [u8; 32],
}

impl NodeIdentity {
    pub fn from_x25519_public(key: X25519PublicKey) -> Self {
        Self { public_key: key.to_bytes() }
    }
}

/// Cover traffic packet type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PacketType {
    /// Real message payload.
    Message,
    /// DROP: sent to random node, silently discarded.
    Drop,
    /// LOOP: routes back to sender, verifies path liveness.
    Loop,
}

/// A fixed-size Sphinx onion packet.
/// Always exactly PACKET_SIZE bytes when serialized.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SphinxPacket {
    /// Ephemeral X25519 public key for this hop.
    pub ephemeral_public_key: [u8; 32],
    /// Layered-encrypted routing header.
    pub routing_header: Vec<u8>,
    /// Encrypted payload (application data).
    pub payload: Vec<u8>,
}

/// Per-hop key material derived during packet processing.
pub struct HopKeys {
    pub shared_secret: [u8; 32],
    pub cipher_key:    [u8; 32],
}

/// Build a Sphinx packet for the given route and payload.
pub fn build_packet(
    route:   &[NodeIdentity],
    payload: &[u8],
    _rng:    &mut impl rand::Rng,
) -> Result<SphinxPacket, SphinxError> {
    if route.is_empty() || route.len() > MAX_HOPS {
        return Err(SphinxError::InvalidRoute);
    }
    if payload.len() > PACKET_SIZE - HOP_HEADER_SIZE * MAX_HOPS - 32 {
        return Err(SphinxError::PacketTooLarge);
    }

    // Generate ephemeral X25519 keypair
    let ephemeral_secret  = EphemeralSecret::random_from_rng(rand::thread_rng());
    let ephemeral_public  = X25519PublicKey::from(&ephemeral_secret);

    // TODO: perform X25519 ECDH with each hop's public key to derive
    // per-hop shared secrets, then layer-encrypt the routing header
    // and payload using ChaCha20-Poly1305.
    // This stub preserves packet structure for integration testing.

    let mut padded_payload = vec![0u8; PACKET_SIZE - HOP_HEADER_SIZE * MAX_HOPS - 32];
    let copy_len = payload.len().min(padded_payload.len());
    padded_payload[..copy_len].copy_from_slice(&payload[..copy_len]);

    Ok(SphinxPacket {
        ephemeral_public_key: ephemeral_public.to_bytes(),
        routing_header:       vec![0u8; HOP_HEADER_SIZE * MAX_HOPS],
        payload:              padded_payload,
    })
}

/// Encrypt a payload symmetrically (single-hop, for testing).
pub fn encrypt_payload(key: &[u8; 32], payload: &[u8]) -> Result<Vec<u8>, SphinxError> {
    let cipher    = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce_arr = [0u8; 12];
    let nonce     = Nonce::from_slice(&nonce_arr);
    cipher.encrypt(nonce, payload).map_err(|_| SphinxError::EncryptionFailed)
}

/// Decrypt a payload symmetrically (single-hop, for testing).
pub fn decrypt_payload(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, SphinxError> {
    let cipher    = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce_arr = [0u8; 12];
    let nonce     = Nonce::from_slice(&nonce_arr);
    cipher.decrypt(nonce, ciphertext).map_err(|_| SphinxError::DecryptionFailed)
}

/// Generate a DROP cover packet.
pub fn generate_drop_packet(
    route: &[NodeIdentity],
    rng:   &mut impl rand::Rng,
) -> Result<SphinxPacket, SphinxError> {
    let mut payload = vec![0u8; 64];
    rng.fill_bytes(&mut payload);
    let mut pkt = build_packet(route, &payload, rng)?;
    // Mark as DROP in routing header first byte
    if !pkt.routing_header.is_empty() { pkt.routing_header[0] = 0xDD; }
    Ok(pkt)
}

/// Generate a LOOP cover packet.
pub fn generate_loop_packet(
    route: &[NodeIdentity],
    rng:   &mut impl rand::Rng,
) -> Result<SphinxPacket, SphinxError> {
    let mut payload = vec![0u8; 64];
    rng.fill_bytes(&mut payload);
    let mut pkt = build_packet(route, &payload, rng)?;
    // Mark as LOOP in routing header first byte
    if !pkt.routing_header.is_empty() { pkt.routing_header[0] = 0xAA; }
    Ok(pkt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_route(n: usize) -> Vec<NodeIdentity> {
        (0..n).map(|i| NodeIdentity { public_key: [i as u8; 32] }).collect()
    }

    #[test] fn test_build_packet_returns_correct_structure() {
        let mut rng = rand::thread_rng();
        let pkt = build_packet(&dummy_route(3), b"hello", &mut rng).unwrap();
        assert_eq!(pkt.ephemeral_public_key.len(), 32);
        assert_eq!(pkt.routing_header.len(), HOP_HEADER_SIZE * MAX_HOPS);
    }
    #[test] fn test_packet_payload_fixed_size() {
        let mut rng = rand::thread_rng();
        let pkt = build_packet(&dummy_route(3), b"short msg", &mut rng).unwrap();
        let total = 32 + pkt.routing_header.len() + pkt.payload.len();
        assert!(total <= PACKET_SIZE, "packet must fit within PACKET_SIZE");
    }
    #[test] fn test_empty_route_rejected() {
        let mut rng = rand::thread_rng();
        assert!(build_packet(&[], b"msg", &mut rng).is_err());
    }
    #[test] fn test_too_many_hops_rejected() {
        let mut rng = rand::thread_rng();
        assert!(build_packet(&dummy_route(MAX_HOPS + 1), b"msg", &mut rng).is_err());
    }
    #[test] fn test_encrypt_decrypt_roundtrip() {
        let key     = [42u8; 32];
        let plain   = b"secret message";
        let ct      = encrypt_payload(&key, plain).unwrap();
        let decoded = decrypt_payload(&key, &ct).unwrap();
        assert_eq!(decoded, plain);
    }
    #[test] fn test_wrong_key_fails_decryption() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let ct   = encrypt_payload(&key1, b"data").unwrap();
        assert!(decrypt_payload(&key2, &ct).is_err());
    }
    #[test] fn test_drop_packet_generated() {
        let mut rng = rand::thread_rng();
        let pkt = generate_drop_packet(&dummy_route(3), &mut rng);
        assert!(pkt.is_ok());
    }
    #[test] fn test_loop_packet_generated() {
        let mut rng = rand::thread_rng();
        let pkt = generate_loop_packet(&dummy_route(3), &mut rng);
        assert!(pkt.is_ok());
    }
}
