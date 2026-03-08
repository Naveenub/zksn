//! Sphinx packet format — fixed 2048-byte onion packets.
//!
//! ## Cryptographic design
//!
//! The sender generates an ephemeral X25519 keypair and performs ECDH with
//! each hop's long-term public key to derive a unique per-hop shared secret.
//! These secrets are used to:
//!
//! 1. **Onion-encrypt the routing header** (back → front) so each node learns
//!    only the immediate next hop.
//! 2. **Onion-encrypt the payload** (back → front) so only the final
//!    recipient can read the plaintext.
//!
//! ## Header construction invariant
//!
//! Header is `MAX_HOPS × HOP_HEADER_SIZE` bytes. Build proceeds in reverse:
//! prepend the next-hop address, then XOR-encrypt the full header with the
//! current hop's keystream. On receipt, a node XOR-decrypts the header and
//! reads the first `HOP_HEADER_SIZE` bytes as its next-hop address, then
//! shifts the header left and zero-pads before forwarding. The decryption
//! invariant holds because each node reads only position `[0..32]`, which is
//! always correctly reconstructed regardless of keystream truncation.
//!
//! ## Limitations (v0.1-alpha)
//!
//! The ephemeral public key is not blinded between hops, so colluding nodes
//! could correlate packets by the shared ephemeral key. Per-hop key blinding
//! (`α_i = b_{i−1} · α_{i−1}`) will be added in a future release.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

pub const PACKET_SIZE: usize = 2048;
pub const MAX_HOPS: usize = 5;
pub const HOP_HEADER_SIZE: usize = 32;

const HEADER_LEN: usize = HOP_HEADER_SIZE * MAX_HOPS; // 160 bytes
const PAYLOAD_LEN: usize = PACKET_SIZE - 32 - HEADER_LEN; // 1856 bytes

// ─── Error type ────────────────────────────────────────────────────────────

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

// ─── Public types ──────────────────────────────────────────────────────────

/// A node identity for routing purposes — wraps an X25519 public key.
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

/// Cover traffic packet type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PacketType {
    /// Real message payload.
    Message,
    /// DROP: sent to a random node and silently discarded.
    Drop,
    /// LOOP: routed back to the sender to verify path liveness.
    Loop,
}

/// A fixed-size Sphinx onion packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SphinxPacket {
    /// Sender's ephemeral X25519 public key (all hops use this for ECDH).
    pub ephemeral_public_key: [u8; 32],
    /// Layered-encrypted routing header (`HEADER_LEN` bytes).
    pub routing_header: Vec<u8>,
    /// Onion-encrypted payload (`PAYLOAD_LEN` bytes).
    pub payload: Vec<u8>,
}

impl SphinxPacket {
    /// Serialize to exactly `PACKET_SIZE` bytes:
    ///   [32 ephemeral_public_key | 160 routing_header | 1856 payload]
    /// No length prefixes — direct memory layout for wire transmission.
    pub fn to_bytes(&self) -> [u8; PACKET_SIZE] {
        let mut buf = [0u8; PACKET_SIZE];
        buf[..32].copy_from_slice(&self.ephemeral_public_key);
        buf[32..32 + HEADER_LEN].copy_from_slice(&self.routing_header);
        buf[32 + HEADER_LEN..].copy_from_slice(&self.payload);
        buf
    }

    /// Deserialize from exactly `PACKET_SIZE` bytes.
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

/// Per-hop key material — exposed for diagnostics and testing.
pub struct HopKeys {
    pub shared_secret: [u8; 32],
    pub cipher_key: [u8; 32],
}

// ─── Internal key-derivation helpers ───────────────────────────────────────

/// Derive a 32-byte key:  SHA-256(label ‖ shared_secret).
fn derive_key(label: &[u8], shared_secret: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(label);
    h.update(shared_secret);
    h.finalize().into()
}

/// Produce `length` pseudo-random bytes via SHA-256 counter-mode:
/// block_i = SHA-256(key ‖ label ‖ i_le32).
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

/// XOR `buf` in-place with `stream` (zip length).
fn xor_bytes(buf: &mut [u8], stream: &[u8]) {
    for (b, s) in buf.iter_mut().zip(stream.iter()) {
        *b ^= s;
    }
}

// ─── Public API ────────────────────────────────────────────────────────────

/// Build a Sphinx onion packet for `route` carrying `payload`.
///
/// # Routing header construction (back → front)
///
/// ```text
/// Start:  header = [0; HEADER_LEN]
/// For i = n-1 .. 0:
///   header[HOP_HEADER_SIZE..] = header[..HEADER_LEN-HOP_HEADER_SIZE]  // shift right
///   header[0..HOP_HEADER_SIZE] = route[i+1].public_key                 // prepend next-hop
///   header ^= keystream(cipher_key[i], "header", HEADER_LEN)           // encrypt layer
/// ```
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

    // 1. Ephemeral X25519 keypair (sender-side only; not stored in packet secret).
    let secret_bytes: [u8; 32] = rng.gen();
    let ephemeral_secret = StaticSecret::from(secret_bytes);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

    // 2. Per-hop shared secrets → cipher keys via ECDH.
    //    cipher_key[i] = SHA-256("sphinx-cipher" ‖ DH(ephemeral_secret, route[i].pubkey))
    let cipher_keys: Vec<[u8; 32]> = route
        .iter()
        .map(|hop| {
            let hop_pubkey = X25519PublicKey::from(hop.public_key);
            let shared = ephemeral_secret.diffie_hellman(&hop_pubkey);
            derive_key(b"sphinx-cipher", &shared.to_bytes())
        })
        .collect();

    // 3. Build onion routing header — back to front.
    let mut header = vec![0u8; HEADER_LEN];

    for i in (0..n).rev() {
        // Shift existing header right by HOP_HEADER_SIZE to make room at the front.
        header.copy_within(0..HEADER_LEN - HOP_HEADER_SIZE, HOP_HEADER_SIZE);

        // Write next-hop address at position 0 ([0;32] signals end of route).
        if i + 1 < n {
            header[..HOP_HEADER_SIZE].copy_from_slice(&route[i + 1].public_key);
        } else {
            header[..HOP_HEADER_SIZE].fill(0);
        }

        // Encrypt (XOR) entire header under this hop's cipher key.
        let ks = keystream(&cipher_keys[i], b"header", HEADER_LEN);
        xor_bytes(&mut header, &ks);
    }

    // 4. Onion-encrypt payload — back to front.
    //    Each hop peels one layer; after all n peels the plaintext is recovered.
    let mut enc_payload = vec![0u8; PAYLOAD_LEN];
    enc_payload[..payload.len()].copy_from_slice(payload);

    for i in (0..n).rev() {
        let ks = keystream(&cipher_keys[i], b"payload", PAYLOAD_LEN);
        xor_bytes(&mut enc_payload, &ks);
    }

    Ok(SphinxPacket {
        ephemeral_public_key: ephemeral_public.to_bytes(),
        routing_header: header,
        payload: enc_payload,
    })
}

/// Process a received Sphinx packet at a mix node.
///
/// Returns `(next_hop_pubkey, peeled_packet)`. The node should forward
/// `peeled_packet` to `next_hop_pubkey`. If `next_hop_pubkey == [0u8; 32]`
/// this node is the final destination.
///
/// # Header peeling
///
/// ```text
/// header ^= keystream(cipher_key, "header", HEADER_LEN)  // decrypt layer
/// next_hop = header[0..HOP_HEADER_SIZE]                  // read routing info
/// header = header[HOP_HEADER_SIZE..] ++ [0; HOP_HEADER_SIZE]  // consume slot
/// ```
pub fn peel_layer(
    packet: &SphinxPacket,
    own_private_key: &[u8; 32],
) -> Result<([u8; 32], SphinxPacket), SphinxError> {
    // ECDH: same shared secret the sender computed for this hop.
    let own_secret = StaticSecret::from(*own_private_key);
    let ephem_pubkey = X25519PublicKey::from(packet.ephemeral_public_key);
    let shared = own_secret.diffie_hellman(&ephem_pubkey);
    let cipher_key = derive_key(b"sphinx-cipher", &shared.to_bytes());

    // Decrypt routing header.
    let mut header = packet.routing_header.clone();
    let ks = keystream(&cipher_key, b"header", HEADER_LEN);
    xor_bytes(&mut header, &ks);

    // First HOP_HEADER_SIZE bytes = next-hop address.
    let mut next_hop = [0u8; HOP_HEADER_SIZE];
    next_hop.copy_from_slice(&header[..HOP_HEADER_SIZE]);

    // Consume this node's routing slot: shift left, zero-pad right.
    header.copy_within(HOP_HEADER_SIZE..HEADER_LEN, 0);
    header[HEADER_LEN - HOP_HEADER_SIZE..].fill(0);

    // Peel one payload encryption layer.
    let mut payload = packet.payload.clone();
    let ks_pay = keystream(&cipher_key, b"payload", payload.len());
    xor_bytes(&mut payload, &ks_pay);

    Ok((
        next_hop,
        SphinxPacket {
            ephemeral_public_key: packet.ephemeral_public_key,
            routing_header: header,
            payload,
        },
    ))
}

// ─── Utility: single-hop symmetric encryption (ChaCha20-Poly1305) ──────────

/// Encrypt `payload` with a 32-byte key using ChaCha20-Poly1305 (AEAD).
pub fn encrypt_payload(key: &[u8; 32], payload: &[u8]) -> Result<Vec<u8>, SphinxError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(&[0u8; 12]);
    cipher
        .encrypt(nonce, payload)
        .map_err(|_| SphinxError::EncryptionFailed)
}

/// Decrypt `ciphertext` with a 32-byte key using ChaCha20-Poly1305 (AEAD).
pub fn decrypt_payload(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, SphinxError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(&[0u8; 12]);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| SphinxError::DecryptionFailed)
}

// ─── Cover traffic ─────────────────────────────────────────────────────────

/// Generate a DROP cover packet (random payload, first header byte = 0xDD).
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

/// Generate a LOOP cover packet (random payload, first header byte = 0xAA).
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

    /// Build a route of `n` real X25519 keypairs.
    /// Returns (identities for the packet, private keys for peeling).
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

    /// Dummy route with arbitrary (non-zero) bytes for structure-only tests.
    fn dummy_route(n: usize) -> Vec<NodeIdentity> {
        (0..n)
            .map(|i| NodeIdentity {
                public_key: [i as u8 + 1; 32],
            })
            .collect()
    }

    // ── Existing structure tests (unchanged) ───────────────────────────────

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

    // ── New ECDH onion-routing tests ───────────────────────────────────────

    /// Core test: build a 3-hop packet, peel all layers in order.
    /// Each hop must reveal the correct next-hop address, and the final
    /// payload must equal the original plaintext.
    #[test]
    fn test_onion_peel_roundtrip_3_hops() {
        let mut rng = rand::thread_rng();
        let (route, privkeys) = real_route(3);
        let plaintext = b"sovereign network message";

        let pkt = build_packet(&route, plaintext, &mut rng).unwrap();

        // Hop 0 → reveals hop 1's address.
        let (next1, pkt1) = peel_layer(&pkt, &privkeys[0]).unwrap();
        assert_eq!(next1, route[1].public_key, "hop 0 must point to hop 1");

        // Hop 1 → reveals hop 2's address.
        let (next2, pkt2) = peel_layer(&pkt1, &privkeys[1]).unwrap();
        assert_eq!(next2, route[2].public_key, "hop 1 must point to hop 2");

        // Hop 2 (final) → next-hop is the zero sentinel.
        let (next3, pkt3) = peel_layer(&pkt2, &privkeys[2]).unwrap();
        assert_eq!(next3, [0u8; 32], "final hop must have zero next-hop");

        // Payload fully decrypted after all peels.
        assert_eq!(&pkt3.payload[..plaintext.len()], plaintext.as_ref());
    }

    /// Single-hop end-to-end roundtrip.
    #[test]
    fn test_onion_peel_single_hop() {
        let mut rng = rand::thread_rng();
        let (route, privkeys) = real_route(1);
        let plaintext = b"direct message";

        let pkt = build_packet(&route, plaintext, &mut rng).unwrap();
        let (next, peeled) = peel_layer(&pkt, &privkeys[0]).unwrap();

        assert_eq!(next, [0u8; 32], "single hop has no next");
        assert_eq!(&peeled.payload[..plaintext.len()], plaintext.as_ref());
    }

    /// MAX_HOPS (5) end-to-end roundtrip.
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
                assert_eq!(next, [0u8; 32], "last hop must have zero next-hop");
            }
        }
        assert_eq!(&pkt.payload[..plaintext.len()], plaintext.as_ref());
    }

    /// Wrong private key must NOT recover the plaintext payload.
    #[test]
    fn test_wrong_privkey_garbles_payload() {
        let mut rng = rand::thread_rng();
        let (route, _privkeys) = real_route(1);
        let plaintext = b"secret";

        let pkt = build_packet(&route, plaintext, &mut rng).unwrap();
        let wrong_key = [0xFFu8; 32];
        let (_next, bad) = peel_layer(&pkt, &wrong_key).unwrap();

        assert_ne!(
            &bad.payload[..plaintext.len()],
            plaintext.as_ref(),
            "wrong key must not recover plaintext"
        );
    }
}
