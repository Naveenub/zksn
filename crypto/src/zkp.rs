//! ZK credential system — Merkle membership tree and nullifiers for DAO voting.
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Error)]
pub enum ZkpError {
    #[error("Invalid proof")]
    InvalidProof,
    #[error("Nullifier already used")]
    NullifierReused,
    #[error("Not a member")]
    NotMember,
}

/// A membership credential — the secret held by a DAO member.
#[derive(ZeroizeOnDrop)]
pub struct MemberCredential {
    secret: [u8; 32],
    nonce: [u8; 32],
}

impl MemberCredential {
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut secret = [0u8; 32];
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        rand::thread_rng().fill_bytes(&mut nonce);
        Self { secret, nonce }
    }

    pub fn from_bytes(mut bytes: [u8; 32]) -> Self {
        let mut nonce = [0u8; 32];
        nonce[0] = 1;
        let s = Self {
            secret: bytes,
            nonce,
        };
        bytes.zeroize();
        s
    }

    /// Commitment placed in the Merkle tree: SHA-256(secret || nonce).
    /// Note: production should use Poseidon hash for ZK-SNARK efficiency.
    pub fn commitment(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(&self.secret);
        h.update(&self.nonce);
        h.finalize().into()
    }

    /// Nullifier for a specific proposal: SHA-256(secret || proposal_id).
    /// Unique per (member, proposal) — prevents double-voting without revealing identity.
    pub fn nullifier(&self, proposal_id: &[u8; 32]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(&self.secret);
        h.update(proposal_id);
        h.finalize().into()
    }
}

/// Binary Merkle tree over member commitments.
/// Root is stored on-chain in ZKSNGovernance.sol.
pub struct MerkleTree {
    leaves: Vec<[u8; 32]>,
}

impl MerkleTree {
    pub fn new(leaves: Vec<[u8; 32]>) -> Self {
        Self { leaves }
    }

    /// Compute the Merkle root.
    pub fn root(&self) -> [u8; 32] {
        if self.leaves.is_empty() {
            return [0u8; 32];
        }
        let mut layer = self.leaves.clone();
        while layer.len() > 1 {
            if layer.len() % 2 == 1 {
                layer.push(*layer.last().unwrap()); // duplicate last node
            }
            layer = layer
                .chunks(2)
                .map(|pair| hash_pair(&pair[0], &pair[1]))
                .collect();
        }
        layer[0]
    }

    /// Generate a Merkle proof for leaf at `index`.
    pub fn proof(&self, index: usize) -> Vec<[u8; 32]> {
        let mut proof = Vec::new();
        let mut layer = self.leaves.clone();
        let mut idx = index;

        while layer.len() > 1 {
            if layer.len() % 2 == 1 {
                layer.push(*layer.last().unwrap());
            }
            let sibling = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            if sibling < layer.len() {
                proof.push(layer[sibling]);
            }
            layer = layer
                .chunks(2)
                .map(|pair| hash_pair(&pair[0], &pair[1]))
                .collect();
            idx /= 2;
        }
        proof
    }

    /// Verify a Merkle proof.
    pub fn verify(root: &[u8; 32], leaf: &[u8; 32], proof: &[[u8; 32]], index: usize) -> bool {
        let mut current = *leaf;
        let mut idx = index;

        for sibling in proof {
            current = if idx % 2 == 0 {
                hash_pair(&current, sibling)
            } else {
                hash_pair(sibling, &current)
            };
            idx /= 2;
        }
        &current == root
    }
}

fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(left);
    h.update(right);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commitment_is_deterministic() {
        let c = MemberCredential::generate();
        assert_eq!(c.commitment(), c.commitment());
    }

    #[test]
    fn test_nullifier_unique_per_proposal() {
        let c = MemberCredential::generate();
        let p1 = [1u8; 32];
        let p2 = [2u8; 32];
        assert_ne!(c.nullifier(&p1), c.nullifier(&p2));
    }

    #[test]
    fn test_nullifier_same_proposal_same_result() {
        let c = MemberCredential::generate();
        let p = [7u8; 32];
        assert_eq!(c.nullifier(&p), c.nullifier(&p));
    }

    #[test]
    fn test_merkle_root_single_leaf() {
        let leaf = [1u8; 32];
        let tree = MerkleTree::new(vec![leaf]);
        assert_eq!(tree.root(), leaf);
    }

    #[test]
    fn test_merkle_proof_verify() {
        let leaves: Vec<[u8; 32]> = (0u8..4).map(|i| [i; 32]).collect();
        let tree = MerkleTree::new(leaves.clone());
        let root = tree.root();

        for i in 0..leaves.len() {
            let proof = tree.proof(i);
            assert!(
                MerkleTree::verify(&root, &leaves[i], &proof, i),
                "Proof for leaf {i} must verify"
            );
        }
    }

    #[test]
    fn test_merkle_wrong_leaf_fails() {
        let leaves: Vec<[u8; 32]> = (0u8..4).map(|i| [i; 32]).collect();
        let tree = MerkleTree::new(leaves);
        let root = tree.root();
        let proof = tree.proof(0);
        let wrong = [99u8; 32];
        assert!(!MerkleTree::verify(&root, &wrong, &proof, 0));
    }
}
