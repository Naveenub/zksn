//! Ed25519 identity keypair — sign, verify, fingerprint.
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::ZeroizeOnDrop;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("Signature verification failed")]
    VerificationFailed,
    #[error("Invalid key bytes")]
    InvalidKeyBytes,
}

/// A node's long-term Ed25519 signing identity.
#[derive(ZeroizeOnDrop)]
pub struct ZksnIdentity {
    signing_key: SigningKey,
}

/// The public half of a ZKSN identity.
#[derive(Debug, Clone)]
pub struct ZksnPublicKey {
    verifying_key: VerifyingKey,
}

impl ZksnIdentity {
    /// Generate a fresh identity from OS entropy.
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    /// Restore from a 32-byte secret seed.
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&bytes),
        }
    }

    /// Export the 32-byte secret seed. Zeroize the returned bytes when done.
    pub fn to_secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.signing_key.sign(message).to_bytes().to_vec()
    }

    /// Return the public half.
    pub fn public(&self) -> ZksnPublicKey {
        ZksnPublicKey {
            verifying_key: self.signing_key.verifying_key(),
        }
    }
}

impl ZksnPublicKey {
    /// Verify a signature produced by the corresponding private key.
    pub fn verify(&self, message: &[u8], signature_bytes: &[u8]) -> Result<(), IdentityError> {
        let sig_arr: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| IdentityError::VerificationFailed)?;
        let sig = Signature::from_bytes(&sig_arr);
        self.verifying_key
            .verify(message, &sig)
            .map_err(|_| IdentityError::VerificationFailed)
    }

    /// Short human-readable identifier: first 8 bytes of SHA-256(pubkey).
    pub fn fingerprint(&self) -> String {
        let hash = Sha256::digest(self.verifying_key.as_bytes());
        hex::encode(&hash[..8])
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.verifying_key.as_bytes()
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, IdentityError> {
        VerifyingKey::from_bytes(bytes)
            .map(|vk| Self { verifying_key: vk })
            .map_err(|_| IdentityError::InvalidKeyBytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_is_unique() {
        let a = ZksnIdentity::generate();
        let b = ZksnIdentity::generate();
        assert_ne!(a.public().fingerprint(), b.public().fingerprint());
    }
    #[test]
    fn test_sign_verify_roundtrip() {
        let id = ZksnIdentity::generate();
        let msg = b"test message";
        let sig = id.sign(msg);
        assert!(id.public().verify(msg, &sig).is_ok());
    }
    #[test]
    fn test_wrong_message_fails() {
        let id = ZksnIdentity::generate();
        let sig = id.sign(b"correct");
        assert!(id.public().verify(b"wrong", &sig).is_err());
    }
    #[test]
    fn test_from_secret_bytes_roundtrip() {
        let id = ZksnIdentity::generate();
        let bytes = id.to_secret_bytes();
        let restored = ZksnIdentity::from_secret_bytes(bytes);
        assert_eq!(id.public().fingerprint(), restored.public().fingerprint());
    }
    #[test]
    fn test_fingerprint_is_16_hex_chars() {
        let id = ZksnIdentity::generate();
        assert_eq!(id.public().fingerprint().len(), 16);
    }
}
