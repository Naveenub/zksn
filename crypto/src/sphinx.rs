//! Sphinx packet format — fixed 2048-byte onion packets.
//!
//! ## Per-hop key blinding
//!
//! Each mix node blinds the ephemeral public key before forwarding:
//!
//! ```text
//! b_i     = SHA-256("sphinx-blinding" ‖ shared_secret_i ‖ α_i)
//! α_{i+1} = b_i ×_clamped α_i
//! ```
//!
//! Because ×_clamped is commutative over the Montgomery group, the sender
//! pre-computes each hop's shared secret as:
//!
//! ```text
//! s_i = e ×_clamped (b_{i-1} ×_clamped … ×_clamped (b_0 ×_clamped pk_i))
//! ```
//!
//! Every node in the route sees a unique ephemeral public key, eliminating
//! the correlation attack available to colluding nodes in unblinded Sphinx.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use curve25519_dalek::MontgomeryPoint;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

pub const PACKET_SIZE: usize = 2048;
pub const MAX_HOPS: usize = 5;
pub const HOP_HEADER_SIZE: usize = 32;

const HEADER_LEN: usize = HOP_HEADER_SIZE * MAX_HOPS; // 160 bytes
const PAYLOAD_LEN: usize = PACKET_SIZE - 32 - HEADER_LEN; // 1856 bytes

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeIdentity {
    pub public_key: [u8; 32],
}

impl NodeIdentity {
    pub fn from_x25519_public(key: X25519PublicKey) -> Self {
        Self {
            public_key: key.to_bytes(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PacketType {
    Message,
    Drop,
    Loop,
}

/// A fixed-size Sphinx onion packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SphinxPacket {
    /// Ephemeral X25519 public key — blinded at each hop before forwarding.
    pub ephemeral_public_key: [u8; 32],
    pub routing_header: Vec<u8>,
    pub payload: Vec<u8>,
}

impl SphinxPacket {
    /// Serialize to exactly `PACKET_SIZE` bytes (no length prefixes).
    /// Layout: [32 ephemeral_public_key | 160 routing_header | 1856 payload]
    pub fn to_bytes(&self) -> [u8; PACKET_SIZE] {
        let mut buf = [0u8; PACKET_SIZE];
        buf[..32].copy_from_slice(&self.ephemeral_public_key);
        buf[32..32 + HEADER_LEN].copy_from_slice(&self.routing_header);
        buf[32 + HEADER_LEN..].copy_from_slice(&self.payload);
        buf
    }

    pub fn from_bytes(buf: &[u8; PACKET_SIZE]) -> Self {
        let mut ephemeral_public_key = [0u8; 32];
        ephemeral_public_key.copy_from_slice(&buf[..32]);
        let routing_header = buf[32..32 + HEADER_LEN].to_vec();
        let payload = buf[32 + HEADER_LEN..].to_vec();
        Self {
            ephemeral_public_key,
            routing_header,
            payload,
        }
    }
}

pub struct HopKeys {
    pub shared_secret: [u8; 32],
    pub cipher_key: [u8; 32],
}

// ─── Internal helpers ──────────────────────────────────────────────────────

fn derive_key(label: &[u8], shared_secret: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(label);
    h.update(shared_secret);
    h.finalize().into()
}

fn keystream(key: &[u8; 32], label: &[u8], length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(length + 32);
    let mut counter = 0u32;
    while out.len() < length {
        let mut h = Sha256::new();
        h.update(key);
        h.update(label);
        h.update(counter.to_le_bytes());
        out.extend_from_slice(&h.finalize());
        counter += 1;
    }
    out.truncate(length);
    out
}

fn xor_bytes(buf: &mut [u8], stream: &[u8]) {
    for (b, s) in buf.iter_mut().zip(stream.iter()) {
        *b ^= s;
    }
}

/// X25519 scalar multiplication using `mul_clamped` — matches x25519-dalek.
fn x25519_mul(scalar: [u8; 32], point: [u8; 32]) -> [u8; 32] {
    MontgomeryPoint(point).mul_clamped(scalar).0
}

/// X25519 base-point multiplication.
fn x25519_basepoint(scalar: [u8; 32]) -> [u8; 32] {
    curve25519_dalek::constants::X25519_BASEPOINT
        .mul_clamped(scalar)
        .0
}

/// b_i = SHA-256("sphinx-blinding" ‖ shared_secret ‖ alpha)
fn blinding_factor(shared_secret: &[u8; 32], alpha: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"sphinx-blinding");
    h.update(shared_secret);
    h.update(alpha);
    h.finalize().into()
}

// ─── Public API ────────────────────────────────────────────────────────────

pub fn build_packet(
    route: &[NodeIdentity],
    payload: &[u8],
    rng: &mut impl rand::Rng,
) -> Result<SphinxPacket, SphinxError> {
    if route.is_empty() || route.len() > MAX_HOPS {
        return Err(SphinxError::InvalidRoute);
    }
    if payload.len() > PAYLOAD_LEN {
        return Err(SphinxError::PacketTooLarge);
    }

    let n = route.len();
    let secret_bytes: [u8; 32] = rng.gen();
    let ephemeral_public = x25519_basepoint(secret_bytes);

    // Per-hop shared secrets with key blinding.
    //
    // For hop i: s_i = e ×_clamped (b_{i-1} ×_clamped … ×_clamped (b_0 ×_clamped pk_i))
    //
    // We accumulate blinding factors and apply all preceding ones to pk_i.
    // ×_clamped commutativity guarantees the receiver (using sk_i ×_clamped α_i)
    // arrives at the same shared secret.
    let mut alpha = ephemeral_public;
    let mut blind_factors: Vec<[u8; 32]> = Vec::with_capacity(n);
    let mut cipher_keys: Vec<[u8; 32]> = Vec::with_capacity(n);

    for i in 0..n {
        // Apply all preceding blinding factors to pk_i (n ≤ MAX_HOPS = 5).
        let mut blinded_pk = route[i].public_key;
        for bf in &blind_factors {
            blinded_pk = x25519_mul(*bf, blinded_pk);
        }

        let s_i = x25519_mul(secret_bytes, blinded_pk);
        cipher_keys.push(derive_key(b"sphinx-cipher", &s_i));

        let b_i = blinding_factor(&s_i, &alpha);
        blind_factors.push(b_i);
        alpha = x25519_mul(b_i, alpha);
    }

    // Build onion routing header — back to front.
    let mut header = vec![0u8; HEADER_LEN];
    for i in (0..n).rev() {
        header.copy_within(0..HEADER_LEN - HOP_HEADER_SIZE, HOP_HEADER_SIZE);
        if i + 1 < n {
            header[..HOP_HEADER_SIZE].copy_from_slice(&route[i + 1].public_key);
        } else {
            header[..HOP_HEADER_SIZE].fill(0);
        }
        let ks = keystream(&cipher_keys[i], b"header", HEADER_LEN);
        xor_bytes(&mut header, &ks);
    }

    // Onion-encrypt payload — back to front.
    let mut enc_payload = vec![0u8; PAYLOAD_LEN];
    enc_payload[..payload.len()].copy_from_slice(payload);
    for i in (0..n).rev() {
        let ks = keystream(&cipher_keys[i], b"payload", PAYLOAD_LEN);
        xor_bytes(&mut enc_payload, &ks);
    }

    Ok(SphinxPacket {
        ephemeral_public_key: ephemeral_public,
        routing_header: header,
        payload: enc_payload,
    })
}

/// Process a received Sphinx packet.
///
/// Returns `(next_hop_pubkey, peeled_packet)`. The forwarded packet carries
/// a freshly blinded `ephemeral_public_key` so downstream nodes each see a
/// distinct value — preventing correlation by colluding nodes.
pub fn peel_layer(
    packet: &SphinxPacket,
    own_private_key: &[u8; 32],
) -> Result<([u8; 32], SphinxPacket), SphinxError> {
    // Shared secret via x25519-dalek (matches build_packet's x25519_mul).
    let own_secret = StaticSecret::from(*own_private_key);
    let ephem_pubkey = X25519PublicKey::from(packet.ephemeral_public_key);
    let shared = own_secret.diffie_hellman(&ephem_pubkey);
    let shared_bytes = shared.to_bytes();
    let cipher_key = derive_key(b"sphinx-cipher", &shared_bytes);

    // Decrypt and consume routing header.
    let mut header = packet.routing_header.clone();
    let ks = keystream(&cipher_key, b"header", HEADER_LEN);
    xor_bytes(&mut header, &ks);

    let mut next_hop = [0u8; HOP_HEADER_SIZE];
    next_hop.copy_from_slice(&header[..HOP_HEADER_SIZE]);

    header.copy_within(HOP_HEADER_SIZE..HEADER_LEN, 0);
    header[HEADER_LEN - HOP_HEADER_SIZE..].fill(0);

    // Peel payload layer.
    let mut payload = packet.payload.clone();
    let ks_pay = keystream(&cipher_key, b"payload", payload.len());
    xor_bytes(&mut payload, &ks_pay);

    // Blind ephemeral key for next hop: α_{i+1} = b_i ×_clamped α_i
    let b_i = blinding_factor(&shared_bytes, &packet.ephemeral_public_key);
    let next_alpha = x25519_mul(b_i, packet.ephemeral_public_key);

    Ok((
        next_hop,
        SphinxPacket {
            ephemeral_public_key: next_alpha,
            routing_header: header,
            payload,
        },
    ))
}

// ─── Utility ───────────────────────────────────────────────────────────────

pub fn encrypt_payload(key: &[u8; 32], payload: &[u8]) -> Result<Vec<u8>, SphinxError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(&[0u8; 12]);
    cipher
        .encrypt(nonce, payload)
        .map_err(|_| SphinxError::EncryptionFailed)
}

pub fn decrypt_payload(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, SphinxError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(&[0u8; 12]);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| SphinxError::DecryptionFailed)
}

pub fn generate_drop_packet(
    route: &[NodeIdentity],
    rng: &mut impl rand::Rng,
) -> Result<SphinxPacket, SphinxError> {
    let mut payload = vec![0u8; 64];
    rng.fill_bytes(&mut payload);
    let mut pkt = build_packet(route, &payload, rng)?;
    if !pkt.routing_header.is_empty() {
        pkt.routing_header[0] = 0xDD;
    }
    Ok(pkt)
}

pub fn generate_loop_packet(
    route: &[NodeIdentity],
    rng: &mut impl rand::Rng,
) -> Result<SphinxPacket, SphinxError> {
    let mut payload = vec![0u8; 64];
    rng.fill_bytes(&mut payload);
    let mut pkt = build_packet(route, &payload, rng)?;
    if !pkt.routing_header.is_empty() {
        pkt.routing_header[0] = 0xAA;
    }
    Ok(pkt)
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    fn real_route(n: usize) -> (Vec<NodeIdentity>, Vec<[u8; 32]>) {
        let mut rng = rand::thread_rng();
        let mut identities = Vec::new();
        let mut privkeys = Vec::new();
        for _ in 0..n {
            let sk_bytes: [u8; 32] = rng.gen();
            let sk = StaticSecret::from(sk_bytes);
            let pk = X25519PublicKey::from(&sk);
            identities.push(NodeIdentity::from_x25519_public(pk));
            privkeys.push(sk_bytes);
        }
        (identities, privkeys)
    }

    fn dummy_route(n: usize) -> Vec<NodeIdentity> {
        (0..n)
            .map(|i| NodeIdentity {
                public_key: [i as u8 + 1; 32],
            })
            .collect()
    }

    #[test]
    fn test_build_packet_returns_correct_structure() {
        let mut rng = rand::thread_rng();
        let pkt = build_packet(&dummy_route(3), b"hello", &mut rng).unwrap();
        assert_eq!(pkt.ephemeral_public_key.len(), 32);
        assert_eq!(pkt.routing_header.len(), HOP_HEADER_SIZE * MAX_HOPS);
    }

    #[test]
    fn test_packet_payload_fixed_size() {
        let mut rng = rand::thread_rng();
        let pkt = build_packet(&dummy_route(3), b"short msg", &mut rng).unwrap();
        let total = 32 + pkt.routing_header.len() + pkt.payload.len();
        assert!(total <= PACKET_SIZE, "packet must fit within PACKET_SIZE");
    }

    #[test]
    fn test_empty_route_rejected() {
        let mut rng = rand::thread_rng();
        assert!(build_packet(&[], b"msg", &mut rng).is_err());
    }

    #[test]
    fn test_too_many_hops_rejected() {
        let mut rng = rand::thread_rng();
        assert!(build_packet(&dummy_route(MAX_HOPS + 1), b"msg", &mut rng).is_err());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let plain = b"secret message";
        let ct = encrypt_payload(&key, plain).unwrap();
        let decoded = decrypt_payload(&key, &ct).unwrap();
        assert_eq!(decoded, plain);
    }

    #[test]
    fn test_wrong_key_fails_decryption() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let ct = encrypt_payload(&key1, b"data").unwrap();
        assert!(decrypt_payload(&key2, &ct).is_err());
    }

    #[test]
    fn test_drop_packet_generated() {
        let mut rng = rand::thread_rng();
        assert!(generate_drop_packet(&dummy_route(3), &mut rng).is_ok());
    }

    #[test]
    fn test_loop_packet_generated() {
        let mut rng = rand::thread_rng();
        assert!(generate_loop_packet(&dummy_route(3), &mut rng).is_ok());
    }

    #[test]
    fn test_onion_peel_roundtrip_3_hops() {
        let mut rng = rand::thread_rng();
        let (route, privkeys) = real_route(3);
        let plaintext = b"sovereign network message";

        let pkt = build_packet(&route, plaintext, &mut rng).unwrap();

        let (next1, pkt1) = peel_layer(&pkt, &privkeys[0]).unwrap();
        assert_eq!(next1, route[1].public_key, "hop 0 must point to hop 1");

        let (next2, pkt2) = peel_layer(&pkt1, &privkeys[1]).unwrap();
        assert_eq!(next2, route[2].public_key, "hop 1 must point to hop 2");

        let (next3, pkt3) = peel_layer(&pkt2, &privkeys[2]).unwrap();
        assert_eq!(next3, [0u8; 32], "final hop must have zero next-hop");

        assert_eq!(&pkt3.payload[..plaintext.len()], plaintext.as_ref());
    }

    #[test]
    fn test_onion_peel_single_hop() {
        let mut rng = rand::thread_rng();
        let (route, privkeys) = real_route(1);
        let plaintext = b"direct message";

        let pkt = build_packet(&route, plaintext, &mut rng).unwrap();
        let (next, peeled) = peel_layer(&pkt, &privkeys[0]).unwrap();

        assert_eq!(next, [0u8; 32]);
        assert_eq!(&peeled.payload[..plaintext.len()], plaintext.as_ref());
    }

    #[test]
    fn test_onion_peel_max_hops() {
        let mut rng = rand::thread_rng();
        let (route, privkeys) = real_route(MAX_HOPS);
        let plaintext = b"five hop message";

        let mut pkt = build_packet(&route, plaintext, &mut rng).unwrap();
        for i in 0..MAX_HOPS {
            let (next, peeled) = peel_layer(&pkt, &privkeys[i]).unwrap();
            pkt = peeled;
            if i < MAX_HOPS - 1 {
                assert_eq!(next, route[i + 1].public_key, "hop {i} wrong next-hop");
            } else {
                assert_eq!(next, [0u8; 32]);
            }
        }
        assert_eq!(&pkt.payload[..plaintext.len()], plaintext.as_ref());
    }

    #[test]
    fn test_wrong_privkey_garbles_payload() {
        let mut rng = rand::thread_rng();
        let (route, _privkeys) = real_route(1);
        let plaintext = b"secret";

        let pkt = build_packet(&route, plaintext, &mut rng).unwrap();
        let wrong_key = [0xFFu8; 32];
        let (_next, bad) = peel_layer(&pkt, &wrong_key).unwrap();

        assert_ne!(&bad.payload[..plaintext.len()], plaintext.as_ref());
    }

    /// Core blinding test: every hop sees a DIFFERENT ephemeral public key.
    #[test]
    fn test_ephemeral_key_differs_per_hop() {
        let mut rng = rand::thread_rng();
        let (route, privkeys) = real_route(MAX_HOPS);

        let pkt = build_packet(&route, b"blinding test", &mut rng).unwrap();
        let mut seen: Vec<[u8; 32]> = vec![pkt.ephemeral_public_key];

        let mut current = pkt;
        for privkey in &privkeys[..MAX_HOPS - 1] {
            let (_next, peeled) = peel_layer(&current, privkey).unwrap();
            assert_ne!(
                peeled.ephemeral_public_key,
                *seen.last().unwrap(),
                "ephemeral key must change each hop"
            );
            assert!(
                !seen.contains(&peeled.ephemeral_public_key),
                "ephemeral key must be unique across all hops"
            );
            seen.push(peeled.ephemeral_public_key);
            current = peeled;
        }
    }

    /// Blinding is deterministic across independent peel runs.
    #[test]
    fn test_blinding_is_deterministic() {
        let mut rng = rand::thread_rng();
        let (route, privkeys) = real_route(3);
        let pkt = build_packet(&route, b"deterministic", &mut rng).unwrap();

        let (_, p1a) = peel_layer(&pkt, &privkeys[0]).unwrap();
        let (_, p2a) = peel_layer(&p1a, &privkeys[1]).unwrap();
        let (_, p1b) = peel_layer(&pkt, &privkeys[0]).unwrap();
        let (_, p2b) = peel_layer(&p1b, &privkeys[1]).unwrap();

        assert_eq!(p1a.ephemeral_public_key, p1b.ephemeral_public_key);
        assert_eq!(p2a.ephemeral_public_key, p2b.ephemeral_public_key);
    }

    /// to_bytes / from_bytes roundtrip preserves all fields and peels correctly.
    #[test]
    fn test_wire_serialization_roundtrip() {
        let mut rng = rand::thread_rng();
        let (route, privkeys) = real_route(2);
        let plaintext = b"wire format";

        let original = build_packet(&route, plaintext, &mut rng).unwrap();
        let restored = SphinxPacket::from_bytes(&original.to_bytes());

        assert_eq!(original.ephemeral_public_key, restored.ephemeral_public_key);
        assert_eq!(original.routing_header, restored.routing_header);
        assert_eq!(original.payload, restored.payload);

        let (next, peeled) = peel_layer(&restored, &privkeys[0]).unwrap();
        assert_eq!(next, route[1].public_key);
        let (_, final_pkt) = peel_layer(&peeled, &privkeys[1]).unwrap();
        assert_eq!(&final_pkt.payload[..plaintext.len()], plaintext.as_ref());
    }
}
