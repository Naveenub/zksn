//! ZK credential system — Merkle membership tree and nullifiers for DAO voting.
//!
//! Every hash in this module MUST match `circuits/MembershipVote.circom`
//! exactly, or a real proof will never verify on-chain:
//!   - leaf       = Poseidon(1)(secret)                    — no nonce, single input
//!   - nullifier  = Poseidon(2)(secret, proposal_id)
//!   - tree pair  = Poseidon(2)(left, right)
//!   - tree depth = fixed 20 (circuit is `MembershipVote(20)`), left-packed,
//!     empty slots default to the zero leaf (`0`), matching a standard
//!     incremental Merkle tree (Tornado/Semaphore-style) rather than the
//!     variable-depth, odd-node-duplicating tree this module used to build.
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};
use std::sync::OnceLock;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Fixed tree depth — must match `MembershipVote(20)` in the circuit.
pub const DEPTH: usize = 20;

#[derive(Debug, Error)]
pub enum ZkpError {
    #[error("Invalid proof")]
    InvalidProof,
    #[error("Nullifier already used")]
    NullifierReused,
    #[error("Not a member")]
    NotMember,
}

fn poseidon1(input: Fr) -> Fr {
    Poseidon::<Fr>::new_circom(1)
        .expect("circom Poseidon(1) parameters are static and always valid")
        .hash(&[input])
        .expect("single in-field input never fails to hash")
}

fn poseidon2(left: Fr, right: Fr) -> Fr {
    Poseidon::<Fr>::new_circom(2)
        .expect("circom Poseidon(2) parameters are static and always valid")
        .hash(&[left, right])
        .expect("two in-field inputs never fail to hash")
}

fn fr_from_bytes(bytes: &[u8; 32]) -> Fr {
    // Reduces mod the BN254 scalar field, matching how proposalId is now
    // reduced on-chain (ZKSNGovernance.sol: `% SCALAR_FIELD_R`) and how the
    // circuit's witness generator reduces any field-typed input.
    Fr::from_be_bytes_mod_order(bytes)
}

fn fr_to_bytes(fr: Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    let be = fr.into_bigint().to_bytes_be();
    out[32 - be.len()..].copy_from_slice(&be);
    out
}

/// zeros[0] = empty-leaf value (0). zeros[i] = Poseidon2(zeros[i-1], zeros[i-1]).
/// Precomputed once — lets the tree stay "left-packed" (real leaves occupy a
/// contiguous prefix) without materializing all 2^20 slots.
fn zero_hashes() -> &'static [Fr; DEPTH + 1] {
    static ZEROS: OnceLock<[Fr; DEPTH + 1]> = OnceLock::new();
    ZEROS.get_or_init(|| {
        let mut z = [Fr::from(0u64); DEPTH + 1];
        for i in 1..=DEPTH {
            z[i] = poseidon2(z[i - 1], z[i - 1]);
        }
        z
    })
}

/// A membership credential — the secret held by a DAO member.
#[derive(ZeroizeOnDrop)]
pub struct MemberCredential {
    secret: [u8; 32],
}

impl MemberCredential {
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        Self { secret }
    }

    pub fn from_bytes(mut bytes: [u8; 32]) -> Self {
        let s = Self { secret: bytes };
        bytes.zeroize();
        s
    }

    /// Leaf commitment placed in the Merkle tree: Poseidon(1)(secret).
    /// Matches `leafHasher = Poseidon(1); leafHasher.inputs[0] <== secret;`
    /// in MembershipVote.circom.
    pub fn commitment(&self) -> [u8; 32] {
        fr_to_bytes(poseidon1(fr_from_bytes(&self.secret)))
    }

    /// Nullifier for a specific proposal: Poseidon(2)(secret, proposal_id).
    /// Unique per (member, proposal) — prevents double-voting without
    /// revealing identity. Matches `nullifierHasher` in the circuit.
    pub fn nullifier(&self, proposal_id: &[u8; 32]) -> [u8; 32] {
        let out = poseidon2(fr_from_bytes(&self.secret), fr_from_bytes(proposal_id));
        fr_to_bytes(out)
    }
}

/// Fixed depth-20 binary Merkle tree over member commitments, left-packed
/// with a zero-value default leaf. Root is stored on-chain in
/// ZKSNGovernance.sol and must match `MembershipVote(20)`'s public
/// `membershipRoot` signal bit-for-bit.
pub struct MerkleTree {
    leaves: Vec<Fr>,
}

impl MerkleTree {
    pub fn new(leaves: Vec<[u8; 32]>) -> Self {
        assert!(
            leaves.len() <= 1 << DEPTH,
            "membership set exceeds depth-{DEPTH} tree capacity (2^{DEPTH} leaves)"
        );
        Self {
            leaves: leaves.iter().map(fr_from_bytes).collect(),
        }
    }

    pub fn root(&self) -> [u8; 32] {
        let zeros = zero_hashes();
        let mut layer = self.leaves.clone();
        for level in 0..DEPTH {
            layer = Self::hash_layer(&layer, zeros[level]);
        }
        fr_to_bytes(layer.first().copied().unwrap_or(zeros[DEPTH]))
    }

    /// Generate a Merkle proof for the leaf at `index`.
    /// Returns (pathElements, pathIndices) sized exactly `DEPTH`, matching
    /// the circuit's `pathElements[depth]` / `pathIndices[depth]` inputs.
    pub fn proof(&self, index: usize) -> ([[u8; 32]; DEPTH], [u8; DEPTH]) {
        assert!(index < 1 << DEPTH, "leaf index exceeds tree capacity");
        let zeros = zero_hashes();
        let mut layer = self.leaves.clone();
        let mut idx = index;
        let mut elements = [[0u8; 32]; DEPTH];
        let mut indices = [0u8; DEPTH];

        for level in 0..DEPTH {
            let sibling_idx = idx ^ 1;
            let sibling = layer.get(sibling_idx).copied().unwrap_or(zeros[level]);
            elements[level] = fr_to_bytes(sibling);
            indices[level] = (idx % 2) as u8;

            layer = Self::hash_layer(&layer, zeros[level]);
            idx /= 2;
        }
        (elements, indices)
    }

    /// Hash one tree level: pairs consecutive leaves, padding a dangling
    /// last leaf with `zero` (the default for this level) rather than
    /// duplicating it — duplication would silently diverge from the
    /// circuit's fixed-depth, zero-padded tree.
    fn hash_layer(layer: &[Fr], zero: Fr) -> Vec<Fr> {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        let mut i = 0;
        while i < layer.len() {
            let left = layer[i];
            let right = layer.get(i + 1).copied().unwrap_or(zero);
            next.push(poseidon2(left, right));
            i += 2;
        }
        next
    }

    /// Verify a Merkle proof, matching the circuit's Mux1-based ordering:
    /// pathIndices[i] == 0 → current node is the left child, sibling is right.
    /// pathIndices[i] == 1 → current node is the right child, sibling is left.
    pub fn verify(
        root: &[u8; 32],
        leaf: &[u8; 32],
        path_elements: &[[u8; 32]; DEPTH],
        path_indices: &[u8; DEPTH],
    ) -> bool {
        let mut current = fr_from_bytes(leaf);
        for i in 0..DEPTH {
            let sibling = fr_from_bytes(&path_elements[i]);
            current = if path_indices[i] == 0 {
                poseidon2(current, sibling)
            } else {
                poseidon2(sibling, current)
            };
        }
        fr_to_bytes(current) == *root
    }
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
    fn test_empty_tree_root_is_top_zero_hash() {
        let tree = MerkleTree::new(vec![]);
        assert_eq!(tree.root(), fr_to_bytes(zero_hashes()[DEPTH]));
    }

    #[test]
    fn test_merkle_proof_verify_roundtrip() {
        let leaves: Vec<[u8; 32]> = (0u8..5).map(|i| fr_to_bytes(Fr::from(i as u64 + 1))).collect();
        let tree = MerkleTree::new(leaves.clone());
        let root = tree.root();

        for i in 0..leaves.len() {
            let (elements, indices) = tree.proof(i);
            assert!(
                MerkleTree::verify(&root, &leaves[i], &elements, &indices),
                "Proof for leaf {i} must verify"
            );
        }
    }

    #[test]
    fn test_merkle_wrong_leaf_fails() {
        let leaves: Vec<[u8; 32]> = (0u8..4).map(|i| fr_to_bytes(Fr::from(i as u64 + 1))).collect();
        let tree = MerkleTree::new(leaves);
        let root = tree.root();
        let (elements, indices) = tree.proof(0);
        let wrong = fr_to_bytes(Fr::from(999u64));
        assert!(!MerkleTree::verify(&root, &wrong, &elements, &indices));
    }

    #[test]
    fn test_single_leaf_matches_circuit_shape() {
        // A single-leaf tree's root must equal DEPTH-many Poseidon2 pairings
        // of that leaf against the precomputed zero hashes — this is exactly
        // what MerkleProof(20) computes in-circuit when all pathIndices == 0.
        let leaf = fr_from_bytes(&fr_to_bytes(Fr::from(42u64)));
        let tree = MerkleTree::new(vec![fr_to_bytes(leaf)]);
        let zeros = zero_hashes();
        let mut expected = leaf;
        for level in 0..DEPTH {
            expected = poseidon2(expected, zeros[level]);
        }
        assert_eq!(tree.root(), fr_to_bytes(expected));
    }
}
