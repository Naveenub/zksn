//! # Noise Protocol Handshake
//!
//! Implements the Noise_XX handshake pattern for node-to-node authentication.
//!
//! ## Why Noise?
//!
//! Noise provides:
//! - **Mutual authentication**: both parties prove they hold a private key
//! - **Forward secrecy**: session keys are ephemeral; past sessions are safe
//!   even if long-term keys are compromised later
//! - **Identity hiding**: static public keys are transmitted encrypted,
//!   so a passive observer cannot learn who is connecting to whom
//! - **Zero infrastructure**: no certificate authorities, no PKI, no DNS
//!
//! ## Pattern: Noise_XX
//!
//! ```text
//! → e
//! ← e, ee, s, es
//! → s, se
//! ```
//!
//! After the handshake, both parties have:
//! - Verified each other's static public keys
//! - Established a shared session key (Diffie-Hellman based)
//! - All subsequent communication is encrypted + authenticated
//!
//! Reference: https://noiseprotocol.org/noise.html

use anyhow::Result;
use snow::{Builder, HandshakeState, TransportState};
use thiserror::Error;

/// Noise protocol parameters used throughout ZKSN.
const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

#[derive(Debug, Error)]
pub enum NoiseError {
    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("Message decryption failed")]
    DecryptionFailed,

    #[error("Invalid state: {0}")]
    InvalidState(String),
}

/// Initiator side of a Noise_XX handshake.
///
/// The initiator is the node that opens the connection.
pub struct NoiseInitiator {
    state: HandshakeState,
}

impl NoiseInitiator {
    /// Create a new initiator with our static keypair.
    pub fn new(static_private_key: &[u8]) -> Result<Self, NoiseError> {
        let builder = Builder::new(NOISE_PARAMS.parse().map_err(|e| {
            NoiseError::InvalidState(format!("Bad params: {e}"))
        })?);

        let state = builder
            .local_private_key(static_private_key)
            .map_err(|e| NoiseError::HandshakeFailed(e.to_string()))?
            .build_initiator()
            .map_err(|e| NoiseError::HandshakeFailed(e.to_string()))?;

        Ok(Self { state })
    }

    /// Generate the first handshake message to send to the responder.
    /// (`→ e` in the pattern)
    pub fn write_message_1(&mut self) -> Result<Vec<u8>, NoiseError> {
        let mut buf = vec![0u8; 65535];
        let len = self.state
            .write_message(&[], &mut buf)
            .map_err(|e| NoiseError::HandshakeFailed(e.to_string()))?;
        Ok(buf[..len].to_vec())
    }

    /// Process the responder's reply. (`← e, ee, s, es`)
    pub fn read_message_2(&mut self, message: &[u8]) -> Result<(), NoiseError> {
        let mut buf = vec![0u8; 65535];
        self.state
            .read_message(message, &mut buf)
            .map_err(|e| NoiseError::HandshakeFailed(e.to_string()))?;
        Ok(())
    }

    /// Generate the final handshake message. (`→ s, se`)
    /// Returns the completed transport session.
    pub fn write_message_3(mut self) -> Result<(Vec<u8>, NoiseSession), NoiseError> {
        let mut buf = vec![0u8; 65535];
        let len = self.state
            .write_message(&[], &mut buf)
            .map_err(|e| NoiseError::HandshakeFailed(e.to_string()))?;

        let transport = self.state
            .into_transport_mode()
            .map_err(|e| NoiseError::HandshakeFailed(e.to_string()))?;

        Ok((buf[..len].to_vec(), NoiseSession { transport }))
    }
}

/// Responder side of a Noise_XX handshake.
pub struct NoiseResponder {
    state: HandshakeState,
}

impl NoiseResponder {
    pub fn new(static_private_key: &[u8]) -> Result<Self, NoiseError> {
        let builder = Builder::new(NOISE_PARAMS.parse().map_err(|e| {
            NoiseError::InvalidState(format!("Bad params: {e}"))
        })?);

        let state = builder
            .local_private_key(static_private_key)
            .map_err(|e| NoiseError::HandshakeFailed(e.to_string()))?
            .build_responder()
            .map_err(|e| NoiseError::HandshakeFailed(e.to_string()))?;

        Ok(Self { state })
    }

    /// Read the initiator's first message. (`→ e`)
    pub fn read_message_1(&mut self, message: &[u8]) -> Result<(), NoiseError> {
        let mut buf = vec![0u8; 65535];
        self.state
            .read_message(message, &mut buf)
            .map_err(|e| NoiseError::HandshakeFailed(e.to_string()))?;
        Ok(())
    }

    /// Generate response. (`← e, ee, s, es`)
    pub fn write_message_2(&mut self) -> Result<Vec<u8>, NoiseError> {
        let mut buf = vec![0u8; 65535];
        let len = self.state
            .write_message(&[], &mut buf)
            .map_err(|e| NoiseError::HandshakeFailed(e.to_string()))?;
        Ok(buf[..len].to_vec())
    }

    /// Read the final handshake message. (`→ s, se`)
    /// Returns the remote party's static public key and the transport session.
    pub fn read_message_3(mut self, message: &[u8]) -> Result<(Vec<u8>, NoiseSession), NoiseError> {
        let mut buf = vec![0u8; 65535];
        self.state
            .read_message(message, &mut buf)
            .map_err(|e| NoiseError::HandshakeFailed(e.to_string()))?;

        // Get remote static public key (now authenticated)
        let remote_static = self.state
            .get_remote_static()
            .ok_or_else(|| NoiseError::InvalidState("No remote static key".to_string()))?
            .to_vec();

        let transport = self.state
            .into_transport_mode()
            .map_err(|e| NoiseError::HandshakeFailed(e.to_string()))?;

        Ok((remote_static, NoiseSession { transport }))
    }
}

/// An established Noise session — all messages are encrypted + authenticated.
pub struct NoiseSession {
    transport: TransportState,
}

impl NoiseSession {
    /// Encrypt a message for the remote party.
    pub fn send(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let mut buf = vec![0u8; plaintext.len() + 16]; // 16 bytes AEAD tag
        let len = self.transport
            .write_message(plaintext, &mut buf)
            .map_err(|_| NoiseError::DecryptionFailed)?;
        Ok(buf[..len].to_vec())
    }

    /// Decrypt a message from the remote party.
    pub fn receive(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let mut buf = vec![0u8; ciphertext.len()];
        let len = self.transport
            .read_message(ciphertext, &mut buf)
            .map_err(|_| NoiseError::DecryptionFailed)?;
        Ok(buf[..len].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_keypair() -> ([u8; 32], [u8; 32]) {
        // Generate a test X25519 keypair using snow's builder
        let builder = Builder::new(NOISE_PARAMS.parse().unwrap());
        let keypair = builder.generate_keypair().unwrap();
        let mut private = [0u8; 32];
        let mut public = [0u8; 32];
        private.copy_from_slice(&keypair.private);
        public.copy_from_slice(&keypair.public);
        (private, public)
    }

    #[test]
    fn test_full_handshake() {
        let (init_private, _) = generate_keypair();
        let (resp_private, _) = generate_keypair();

        let mut initiator = NoiseInitiator::new(&init_private).unwrap();
        let mut responder = NoiseResponder::new(&resp_private).unwrap();

        // Handshake: → e
        let msg1 = initiator.write_message_1().unwrap();

        // ← e, ee, s, es
        responder.read_message_1(&msg1).unwrap();
        let msg2 = responder.write_message_2().unwrap();

        // → s, se
        initiator.read_message_2(&msg2).unwrap();
        let (msg3, mut init_session) = initiator.write_message_3().unwrap();

        let (remote_key, mut resp_session) = responder.read_message_3(&msg3).unwrap();

        // Verify authenticated public key
        assert_eq!(remote_key.len(), 32);

        // Test encrypted communication
        let plaintext = b"Hello from initiator to responder";
        let ciphertext = init_session.send(plaintext).unwrap();
        let decrypted = resp_session.receive(&ciphertext).unwrap();
        assert_eq!(plaintext.as_ref(), decrypted.as_slice());

        // Test reverse direction
        let reply = b"Hello back from responder";
        let encrypted_reply = resp_session.send(reply).unwrap();
        let decrypted_reply = init_session.receive(&encrypted_reply).unwrap();
        assert_eq!(reply.as_ref(), decrypted_reply.as_slice());
    }

    #[test]
    fn test_decryption_fails_with_tampered_ciphertext() {
        let (init_private, _) = generate_keypair();
        let (resp_private, _) = generate_keypair();

        let mut initiator = NoiseInitiator::new(&init_private).unwrap();
        let mut responder = NoiseResponder::new(&resp_private).unwrap();

        let msg1 = initiator.write_message_1().unwrap();
        responder.read_message_1(&msg1).unwrap();
        let msg2 = responder.write_message_2().unwrap();
        initiator.read_message_2(&msg2).unwrap();
        let (msg3, mut init_session) = initiator.write_message_3().unwrap();
        let (_, mut resp_session) = responder.read_message_3(&msg3).unwrap();

        let plaintext = b"secret message";
        let mut ciphertext = init_session.send(plaintext).unwrap();

        // Tamper with the ciphertext
        ciphertext[0] ^= 0xFF;

        // Decryption must fail
        assert!(resp_session.receive(&ciphertext).is_err());
    }
}
