//! # Zero-Knowledge Proof Utilities
//!
//! Helpers for generating and verifying ZK membership credentials
//! used in ZKSN DAO governance.
//!
//! ## Credential Structure
//!
//! A ZKSN membership credential proves that a node:
//! - Has operated for a minimum number of days
//! - Has forwarded a minimum number of packets
//! - Is in the current membership Merkle tree
//!
//! Without revealing WHICH node it is.
//!
//! ## Nullifier
//!
//! To prevent double-voting without linking votes to identities,
//! we use a Poseidon-hash-based nullifier:
//!
//! ```text
//! nullifier = Hash(credential_secret || proposal_id)
//! ```
//!
//! The contract stores nullifiers (preventing reuse) but cannot reverse
//! them to find the original credential.
//!
//! ## Implementation Note
//!
//! A full ZK circuit (Groth16 or PLONK) requires a trusted setup or
//! transparent setup ceremony. This module provides the off-chain
//! primitives for credential issuance and nullifier computation.
//! The on-chain verifier interface is in `governance/contracts/IVerifier.sol`.
//!
//! Recommended circuit toolchains:
//! - **Noir** (Aztec) — Rust-friendly, no trusted setup
//! - **Circom** + snarkjs — Most tooling available
//! - **Halo2** — Best for custom gates, no trusted setup

use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Error)]
pub enum ZkpError {
    #[error("Invalid credential length")]
    InvalidCredential,

    #[error("Proof generation failed: {0}")]
    ProofFailed(String),

    #[error("Proof verification failed")]
    VerificationFailed,
}

/// A ZKSN membership credential (private, never shared).
///
/// This is a secret scalar associated with a node's identity and
/// a commitment that is placed in the membership Merkle tree.
///
/// The credential is zeroized on drop.
#[derive(ZeroizeOnDrop)]
pub struct MembershipCredential {
    secret: [u8; 32],
}

impl MembershipCredential {
    /// Generate a new random credential.
    pub fn generate() -> Self {
        let mut secret = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut secret);
        Self { secret }
    }

    /// Load from raw bytes (e.g., derived from identity key).
    pub fn from_bytes(mut bytes: [u8; 32]) -> Self {
        let cred = Self { secret: bytes };
        bytes.zeroize();
        cred
    }

    /// Compute the public commitment for this credential.
    ///
    /// The commitment is placed in the membership Merkle tree.
    /// It is safe to publish — it reveals nothing about the secret.
    pub fn commitment(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"zksn-credential-commitment");
        hasher.update(&self.secret);
        hasher.finalize().into()
    }

    /// Compute the nullifier for a specific proposal.
    ///
    /// The nullifier prevents double-voting:
    /// - It is deterministic: same credential + same proposal = same nullifier
    /// - It is unlinkable: given the nullifier, you cannot find the credential
    /// - It is proposal-specific: the same credential produces different
    ///   nullifiers for different proposals
    ///
    /// `nullifier = SHA256("zksn-nullifier" || credential_secret || proposal_id)`
    pub fn nullifier(&self, proposal_id: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"zksn-nullifier");
        hasher.update(&self.secret);
        hasher.update(proposal_id);
        hasher.finalize().into()
    }

    /// Export secret bytes for backup (handle with extreme care).
    pub fn to_secret_bytes(&self) -> [u8; 32] {
        self.secret
    }
}

/// A simple binary Merkle tree for membership proofs.
///
/// In production, use a Poseidon-hash Merkle tree compatible with
/// your ZK circuit (Poseidon is ZK-friendly; SHA-256 has high circuit cost).
///
/// This implementation uses SHA-256 and is suitable for off-chain tooling.
pub struct MembershipTree {
    leaves: Vec<[u8; 32]>,
}

impl MembershipTree {
    pub fn new(commitments: Vec<[u8; 32]>) -> Self {
        Self { leaves: commitments }
    }

    /// Compute the Merkle root of all membership commitments.
    pub fn root(&self) -> [u8; 32] {
        if self.leaves.is_empty() {
            return [0u8; 32];
        }
        merkle_root(&self.leaves)
    }

    /// Generate a Merkle proof for the given leaf index.
    ///
    /// The proof is a list of sibling hashes from leaf to root.
    /// It proves the leaf is in the tree without revealing other leaves.
    pub fn proof(&self, index: usize) -> Option<MerkleProof> {
        if index >= self.leaves.len() {
            return None;
        }

        let mut proof_path = Vec::new();
        let mut current_index = index;
        let mut current_level = self.leaves.clone();

        while current_level.len() > 1 {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            let sibling = if sibling_index < current_level.len() {
                current_level[sibling_index]
            } else {
                current_level[current_index] // Duplicate last node if odd count
            };

            proof_path.push((sibling, current_index % 2 == 0));
            current_index /= 2;
            current_level = next_level(&current_level);
        }

        Some(MerkleProof {
            leaf: self.leaves[index],
            path: proof_path,
        })
    }
}

/// A Merkle membership proof.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    pub leaf: [u8; 32],
    /// (sibling_hash, is_left_sibling)
    pub path: Vec<([u8; 32], bool)>,
}

impl MerkleProof {
    /// Verify this proof against a known root.
    pub fn verify(&self, root: &[u8; 32]) -> bool {
        let mut current = self.leaf;

        for (sibling, is_left) in &self.path {
            current = if *is_left {
                hash_pair(&current, sibling)
            } else {
                hash_pair(sibling, &current)
            };
        }

        &current == root
    }
}

// ============================================================================
// Internal helpers
// ============================================================================

fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"zksn-merkle");
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.len() == 1 {
        return leaves[0];
    }
    let upper = next_level(leaves);
    merkle_root(&upper)
}

fn next_level(nodes: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut level = Vec::new();
    let mut i = 0;
    while i < nodes.len() {
        let left = nodes[i];
        let right = if i + 1 < nodes.len() {
            nodes[i + 1]
        } else {
            nodes[i] // Duplicate last node
        };
        level.push(hash_pair(&left, &right));
        i += 2;
    }
    level
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_generation() {
        let cred = MembershipCredential::generate();
        let commitment = cred.commitment();

        // Commitment is deterministic
        assert_eq!(commitment, cred.commitment());

        // Different credential produces different commitment
        let cred2 = MembershipCredential::generate();
        assert_ne!(commitment, cred2.commitment());
    }

    #[test]
    fn test_nullifier_is_proposal_specific() {
        let cred = MembershipCredential::generate();
        let proposal1 = [0x01u8; 32];
        let proposal2 = [0x02u8; 32];

        let n1 = cred.nullifier(&proposal1);
        let n2 = cred.nullifier(&proposal2);

        assert_ne!(n1, n2, "Same credential must produce different nullifiers for different proposals");
    }

    #[test]
    fn test_nullifier_is_deterministic() {
        let cred = MembershipCredential::generate();
        let proposal = [0xABu8; 32];

        assert_eq!(
            cred.nullifier(&proposal),
            cred.nullifier(&proposal),
            "Nullifier must be deterministic"
        );
    }

    #[test]
    fn test_merkle_tree_proof() {
        let creds: Vec<MembershipCredential> = (0..8)
            .map(|_| MembershipCredential::generate())
            .collect();
        let commitments: Vec<[u8; 32]> = creds.iter().map(|c| c.commitment()).collect();

        let tree = MembershipTree::new(commitments);
        let root = tree.root();

        // Verify proof for each leaf
        for i in 0..8 {
            let proof = tree.proof(i).expect("Proof should exist");
            assert!(proof.verify(&root), "Proof for leaf {i} should verify");
        }
    }

    #[test]
    fn test_invalid_proof_fails() {
        let commitments: Vec<[u8; 32]> = (0..4)
            .map(|i| {
                let mut c = [0u8; 32];
                c[0] = i as u8;
                c
            })
            .collect();

        let tree = MembershipTree::new(commitments.clone());
        let wrong_root = [0xFF u8; 32];

        let proof = tree.proof(0).unwrap();
        assert!(!proof.verify(&wrong_root), "Proof against wrong root must fail");
    }
}
