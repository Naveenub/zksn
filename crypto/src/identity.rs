//! # Identity Management
//!
//! ZKSN identity is a cryptographic keypair only.
//! There is no username, no email, no registration.
//!
//! The public key IS the identity. The fingerprint IS the "address".

use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("Invalid key material: {0}")]
    InvalidKey(String),

    #[error("Signature verification failed")]
    VerificationFailed,

    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),
}

/// A ZKSN identity — a keypair.
///
/// The private key is zeroized on drop to minimize exposure.
/// Never serialize the full identity (including private key) over a network.
/// Only `ZksnIdentity::public()` should ever be transmitted.
#[derive(ZeroizeOnDrop)]
pub struct ZksnIdentity {
    signing_key: SigningKey,
}

impl ZksnIdentity {
    /// Generate a new random identity.
    /// Uses the OS entropy source (cryptographically secure).
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Load an identity from raw secret key bytes.
    /// The bytes are zeroized after use.
    pub fn from_secret_bytes(mut bytes: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&bytes);
        bytes.zeroize();
        Self { signing_key }
    }

    /// Export the secret key bytes.
    ///
    /// # Security
    /// Handle the returned bytes with extreme care. Zeroize after use.
    /// Never transmit over a network. Store only in encrypted form.
    pub fn to_secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Get the public identity (safe to share).
    pub fn public(&self) -> PublicIdentity {
        PublicIdentity {
            verifying_key: self.signing_key.verifying_key(),
        }
    }

    /// Sign a message with this identity.
    pub fn sign(&self, message: &[u8]) -> IdentitySignature {
        let signature = self.signing_key.sign(message);
        IdentitySignature { signature }
    }

    /// Get the human-readable fingerprint of this identity.
    pub fn fingerprint(&self) -> String {
        self.public().fingerprint()
    }
}

/// The public half of a ZKSN identity.
/// This is what you share with others. It IS your address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicIdentity {
    #[serde(with = "verifying_key_serde")]
    pub verifying_key: VerifyingKey,
}

impl PublicIdentity {
    /// Get the raw public key bytes (32 bytes)
    pub fn as_bytes(&self) -> &[u8] {
        self.verifying_key.as_bytes()
    }

    /// Compute the SHA-256 fingerprint of this identity.
    ///
    /// The fingerprint is a human-readable representation of the public key,
    /// formatted as hex octets: "ab:cd:ef:..."
    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.verifying_key.as_bytes());
        let hash = hasher.finalize();

        hash.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":")
    }

    /// Verify a signature against this identity.
    pub fn verify(&self, message: &[u8], signature: &IdentitySignature) -> Result<(), IdentityError> {
        self.verifying_key
            .verify(message, &signature.signature)
            .map_err(|_| IdentityError::VerificationFailed)
    }
}

/// A signature produced by a ZKSN identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentitySignature {
    #[serde(with = "signature_serde")]
    signature: Signature,
}

// Serde helpers for ed25519 types
mod verifying_key_serde {
    use ed25519_dalek::VerifyingKey;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(key: &VerifyingKey, s: S) -> Result<S::Ok, S::Error> {
        key.as_bytes().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<VerifyingKey, D::Error> {
        let bytes = <[u8; 32]>::deserialize(d)?;
        VerifyingKey::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

mod signature_serde {
    use ed25519_dalek::Signature;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(sig: &Signature, s: S) -> Result<S::Ok, S::Error> {
        sig.to_bytes().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Signature, D::Error> {
        let bytes = <[u8; 64]>::deserialize(d)?;
        Ok(Signature::from_bytes(&bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_generation() {
        let identity = ZksnIdentity::generate();
        let public = identity.public();

        // Fingerprint should be 32 bytes × 2 hex chars + 31 colons = 95 chars
        let fp = public.fingerprint();
        assert_eq!(fp.len(), 95);
        assert!(fp.contains(':'));
    }

    #[test]
    fn test_sign_and_verify() {
        let identity = ZksnIdentity::generate();
        let message = b"test message for ZKSN";

        let signature = identity.sign(message);
        let public = identity.public();

        assert!(public.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_verify_fails_on_wrong_message() {
        let identity = ZksnIdentity::generate();
        let message = b"original message";
        let wrong_message = b"tampered message";

        let signature = identity.sign(message);
        let public = identity.public();

        assert!(public.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_verify_fails_with_different_identity() {
        let identity1 = ZksnIdentity::generate();
        let identity2 = ZksnIdentity::generate();
        let message = b"test message";

        let signature = identity1.sign(message);
        let public2 = identity2.public();

        assert!(public2.verify(message, &signature).is_err());
    }

    #[test]
    fn test_two_identities_are_different() {
        let id1 = ZksnIdentity::generate();
        let id2 = ZksnIdentity::generate();

        assert_ne!(id1.public().fingerprint(), id2.public().fingerprint());
    }

    #[test]
    fn test_secret_key_roundtrip() {
        let identity = ZksnIdentity::generate();
        let secret_bytes = identity.to_secret_bytes();

        let recovered = ZksnIdentity::from_secret_bytes(secret_bytes);
        assert_eq!(
            identity.public().fingerprint(),
            recovered.public().fingerprint()
        );
    }
}
