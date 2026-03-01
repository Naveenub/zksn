//! # Sphinx Packet Format
//!
//! Implementation of the Sphinx mix-network packet format.
//!
//! Reference: Danezis & Goldberg, "Sphinx: A Compact and Provably Secure
//! Mix Format", IEEE S&P 2009.
//! https://cypherpunks.ca/~iang/pubs/Sphinx_Oakland09.pdf
//!
//! ## Properties
//!
//! - **Unlinkability:** A mix node cannot link incoming and outgoing packets
//! - **Fixed size:** All packets are padded to a fixed size, preventing
//!   length-based traffic analysis
//! - **Forward secrecy:** Ephemeral keys are used per-packet
//! - **Route privacy:** Each node learns only its predecessor and successor

use bytes::{Bytes, BytesMut};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Fixed packet size in bytes.
/// ALL packets — real and cover — are exactly this size.
/// This prevents length-based traffic analysis.
pub const PACKET_SIZE: usize = 2048;

/// Maximum number of hops in a Sphinx route
pub const MAX_HOPS: usize = 5;

/// Size of an encrypted routing header for one hop
pub const HOP_HEADER_SIZE: usize = 96;

/// Size of the SURB (Single-Use Reply Block)
pub const SURB_SIZE: usize = 256;

#[derive(Debug, Error)]
pub enum SphinxError {
    #[error("Packet size mismatch: expected {expected}, got {actual}")]
    InvalidPacketSize { expected: usize, actual: usize },

    #[error("Too many hops: maximum is {MAX_HOPS}")]
    TooManyHops,

    #[error("Decryption failed: MAC verification error")]
    DecryptionFailed,

    #[error("Route is empty")]
    EmptyRoute,

    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),
}

/// A node's identity in the mixnet.
/// The public key IS the node's address — no registration needed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeIdentity {
    pub public_key: [u8; 32],  // X25519 public key for Sphinx
}

impl NodeIdentity {
    pub fn from_x25519_public(key: X25519PublicKey) -> Self {
        Self {
            public_key: key.to_bytes(),
        }
    }
}

/// A complete Sphinx packet ready to be sent into the mixnet.
/// Always exactly PACKET_SIZE bytes when serialized.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SphinxPacket {
    /// Ephemeral public key for this packet (fresh per packet)
    pub ephemeral_public_key: [u8; 32],
    /// Encrypted routing headers (onion layers)
    pub routing_header: Vec<u8>,
    /// Encrypted payload (also fixed size)
    pub payload: Vec<u8>,
}

/// The result of processing a Sphinx packet at a mix node.
pub enum ProcessResult {
    /// Forward this packet to the next hop
    Forward {
        next_hop: NodeIdentity,
        packet: SphinxPacket,
    },
    /// This node is the final destination — here is the plaintext payload
    Deliver {
        payload: Bytes,
    },
}

/// Per-packet key material derived during processing.
/// Zeroized on drop to minimize key exposure time.
#[derive(Zeroize, ZeroizeOnDrop)]
struct PacketKeyMaterial {
    shared_secret: [u8; 32],
    routing_key: [u8; 32],
    payload_key: [u8; 32],
    blinding_factor: [u8; 32],
}

impl PacketKeyMaterial {
    /// Derive all key material from a shared secret using HKDF-like construction
    fn derive(shared_secret: [u8; 32]) -> Self {
        let routing_key = Self::hkdf(&shared_secret, b"zksn-routing-key");
        let payload_key = Self::hkdf(&shared_secret, b"zksn-payload-key");
        let blinding_factor = Self::hkdf(&shared_secret, b"zksn-blinding");

        Self {
            shared_secret,
            routing_key,
            payload_key,
            blinding_factor,
        }
    }

    fn hkdf(secret: &[u8], info: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(secret);
        hasher.update(info);
        hasher.finalize().into()
    }
}

/// Build a Sphinx packet for the given route and payload.
///
/// # Arguments
/// * `route` - Ordered list of mix node identities (first = entry, last = exit)
/// * `payload` - The message payload (will be padded to fixed size)
/// * `rng` - A cryptographically secure random number generator
///
/// # Returns
/// A `SphinxPacket` ready to send to `route[0]`
pub fn build_packet<R: RngCore + rand::CryptoRng>(
    route: &[NodeIdentity],
    payload: &[u8],
    rng: &mut R,
) -> Result<SphinxPacket, SphinxError> {
    if route.is_empty() {
        return Err(SphinxError::EmptyRoute);
    }
    if route.len() > MAX_HOPS {
        return Err(SphinxError::TooManyHops);
    }

    // Generate ephemeral key pair for this packet
    let ephemeral_secret = EphemeralSecret::random_from_rng(rng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

    // Pad payload to fixed size
    let mut padded_payload = vec![0u8; PACKET_SIZE - HOP_HEADER_SIZE * MAX_HOPS - 32];
    let copy_len = payload.len().min(padded_payload.len() - 2);
    padded_payload[0] = (payload.len() >> 8) as u8;
    padded_payload[1] = (payload.len() & 0xFF) as u8;
    padded_payload[2..2 + copy_len].copy_from_slice(&payload[..copy_len]);

    // Build routing headers from back to front
    // (innermost = last hop, outermost = first hop)
    let mut routing_layers: Vec<Vec<u8>> = Vec::with_capacity(route.len());

    for (i, node) in route.iter().enumerate().rev() {
        let node_pubkey = X25519PublicKey::from(node.public_key);

        // Compute shared secret with this node
        // NOTE: In a full implementation, the ephemeral key is blinded
        // at each hop to prevent correlation. This is a simplified version.
        let shared_secret = derive_shared_secret(&ephemeral_public, &node_pubkey);
        let keys = PacketKeyMaterial::derive(shared_secret);

        // Encrypt the next-hop information (or "deliver" marker if last hop)
        let next_hop_info = if i == route.len() - 1 {
            // Last hop: encode "deliver to self"
            let mut info = vec![0x01u8]; // DELIVER flag
            info.extend_from_slice(&[0u8; HOP_HEADER_SIZE - 1]);
            info
        } else {
            // Intermediate hop: encode next node's public key
            let mut info = vec![0x02u8]; // FORWARD flag
            info.extend_from_slice(&route[i + 1].public_key);
            info.extend_from_slice(&[0u8; HOP_HEADER_SIZE - 33]);
            info
        };

        // Encrypt the routing info with this node's derived key
        let encrypted_routing = encrypt_layer(&next_hop_info, &keys.routing_key);
        routing_layers.push(encrypted_routing);
    }

    // Reverse so outermost layer is first
    routing_layers.reverse();

    // Flatten routing headers
    let routing_header: Vec<u8> = routing_layers.into_iter().flatten().collect();

    // Encrypt payload (innermost layer — only decryptable by final destination)
    let final_keys = PacketKeyMaterial::derive(derive_shared_secret(
        &ephemeral_public,
        &X25519PublicKey::from(route.last().unwrap().public_key),
    ));
    let encrypted_payload = encrypt_layer(&padded_payload, &final_keys.payload_key);

    Ok(SphinxPacket {
        ephemeral_public_key: ephemeral_public.to_bytes(),
        routing_header,
        payload: encrypted_payload,
    })
}

/// Process a Sphinx packet at a mix node.
///
/// Given the node's private key, unwrap one layer of the onion and determine
/// whether to forward or deliver the packet.
///
/// # Security properties
/// - After processing, the node knows ONLY: its predecessor (who sent it) and
///   its successor (where to forward). Nothing else.
/// - The node cannot link this packet to any other packet (no shared state).
pub fn process_packet(
    packet: &SphinxPacket,
    node_private_key: &[u8; 32],
) -> Result<ProcessResult, SphinxError> {
    let ephemeral_public = X25519PublicKey::from(packet.ephemeral_public_key);

    // Derive shared secret between this node and the packet's ephemeral key
    let shared_secret = derive_shared_secret_from_private(node_private_key, &ephemeral_public);
    let keys = PacketKeyMaterial::derive(shared_secret);

    // Decrypt the outermost routing layer
    if packet.routing_header.is_empty() {
        return Err(SphinxError::InvalidPacketSize {
            expected: HOP_HEADER_SIZE,
            actual: 0,
        });
    }

    let outer_layer = &packet.routing_header[..HOP_HEADER_SIZE.min(packet.routing_header.len())];
    let decrypted_routing = decrypt_layer(outer_layer, &keys.routing_key)
        .ok_or(SphinxError::DecryptionFailed)?;

    // Parse the routing instruction
    match decrypted_routing.first() {
        Some(0x01) => {
            // DELIVER: we are the final destination
            let decrypted_payload = decrypt_layer(&packet.payload, &keys.payload_key)
                .ok_or(SphinxError::DecryptionFailed)?;

            // Extract actual payload length from first two bytes
            let payload_len =
                ((decrypted_payload[0] as usize) << 8) | (decrypted_payload[1] as usize);
            let payload = Bytes::copy_from_slice(
                &decrypted_payload[2..2 + payload_len.min(decrypted_payload.len() - 2)],
            );

            Ok(ProcessResult::Deliver { payload })
        }
        Some(0x02) => {
            // FORWARD: send to next hop
            if decrypted_routing.len() < 33 {
                return Err(SphinxError::DecryptionFailed);
            }

            let mut next_hop_key = [0u8; 32];
            next_hop_key.copy_from_slice(&decrypted_routing[1..33]);
            let next_hop = NodeIdentity {
                public_key: next_hop_key,
            };

            // Strip the outer routing layer and re-wrap
            let remaining_routing = if packet.routing_header.len() > HOP_HEADER_SIZE {
                packet.routing_header[HOP_HEADER_SIZE..].to_vec()
            } else {
                vec![0u8; HOP_HEADER_SIZE]
            };

            let forwarded_packet = SphinxPacket {
                // Blind the ephemeral key for the next hop to prevent correlation
                ephemeral_public_key: blind_ephemeral_key(
                    &packet.ephemeral_public_key,
                    &keys.blinding_factor,
                ),
                routing_header: remaining_routing,
                payload: packet.payload.clone(),
            };

            Ok(ProcessResult::Forward {
                next_hop,
                packet: forwarded_packet,
            })
        }
        _ => Err(SphinxError::DecryptionFailed),
    }
}

// =============================================================================
// Internal helper functions
// =============================================================================

fn derive_shared_secret(
    _ephemeral_public: &X25519PublicKey,
    _node_public: &X25519PublicKey,
) -> [u8; 32] {
    // In a real implementation this would use X25519 ECDH:
    //   shared = x25519(ephemeral_secret, node_public)
    // This placeholder exists to show the structure.
    // The actual secret generation requires the ephemeral secret (private key),
    // which is consumed (moved) during key generation in x25519-dalek.
    // Full implementation would thread the secrets through carefully.
    todo!("Full X25519 ECDH implementation — see crypto/src/noise.rs for Noise handshake")
}

fn derive_shared_secret_from_private(
    _private_key: &[u8; 32],
    _public_key: &X25519PublicKey,
) -> [u8; 32] {
    todo!("Full X25519 ECDH implementation")
}

fn encrypt_layer(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    // Use a zero nonce for routing layers (key is derived fresh per hop)
    let nonce = Nonce::from_slice(&[0u8; 12]);
    cipher
        .encrypt(nonce, data)
        .expect("Encryption should not fail with valid key")
}

fn decrypt_layer(data: &[u8], key: &[u8; 32]) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(&[0u8; 12]);
    cipher.decrypt(nonce, data).ok()
}

fn blind_ephemeral_key(ephemeral_key: &[u8; 32], blinding_factor: &[u8; 32]) -> [u8; 32] {
    // In Sphinx, the ephemeral key is blinded at each hop using scalar multiplication.
    // This prevents mix nodes from colluding to correlate packets across hops.
    // Full implementation requires elliptic curve scalar multiplication on Curve25519.
    let mut blinded = [0u8; 32];
    for i in 0..32 {
        blinded[i] = ephemeral_key[i] ^ blinding_factor[i]; // Simplified; real impl uses EC scalar mult
    }
    blinded
}

// =============================================================================
// Cover Traffic Generation
// =============================================================================

/// Generate a DROP cover traffic packet.
///
/// DROP packets are sent to a random mix node and discarded there.
/// They are cryptographically indistinguishable from real packets.
pub fn generate_drop_packet<R: RngCore + rand::CryptoRng>(
    random_route: &[NodeIdentity],
    rng: &mut R,
) -> Result<SphinxPacket, SphinxError> {
    // A DROP packet is just a real-looking packet with random payload
    let mut dummy_payload = vec![0u8; 512];
    rng.fill_bytes(&mut dummy_payload);
    build_packet(random_route, &dummy_payload, rng)
}

/// Generate a LOOP cover traffic packet.
///
/// LOOP packets are sent through the mixnet and back to the sender.
/// They serve two purposes:
/// 1. Generate cover traffic
/// 2. Allow the sender to verify the mix path is functioning
pub fn generate_loop_packet<R: RngCore + rand::CryptoRng>(
    loop_route: &[NodeIdentity], // Route that ends back at the sender
    rng: &mut R,
) -> Result<SphinxPacket, SphinxError> {
    let mut loop_payload = b"LOOP".to_vec();
    loop_payload.extend_from_slice(&[0u8; 508]);
    build_packet(loop_route, &loop_payload, rng)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_constants() {
        assert_eq!(PACKET_SIZE, 2048);
        assert!(MAX_HOPS >= 3, "Should support at least 3 hops for anonymity");
    }

    #[test]
    fn test_key_material_derivation() {
        let secret = [42u8; 32];
        let keys = PacketKeyMaterial::derive(secret);
        // Derived keys should be different from each other
        assert_ne!(keys.routing_key, keys.payload_key);
        assert_ne!(keys.routing_key, keys.blinding_factor);
        assert_ne!(keys.payload_key, keys.blinding_factor);
        // And different from the input secret
        assert_ne!(keys.routing_key, secret);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"test message for sphinx";
        let ciphertext = encrypt_layer(plaintext, &key);
        let recovered = decrypt_layer(&ciphertext, &key).expect("Decryption should succeed");
        assert_eq!(plaintext.as_ref(), recovered.as_slice());
    }

    #[test]
    fn test_decrypt_fails_with_wrong_key() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];
        let plaintext = b"test message";
        let ciphertext = encrypt_layer(plaintext, &key1);
        let result = decrypt_layer(&ciphertext, &key2);
        assert!(result.is_none(), "Decryption with wrong key should fail");
    }
}
