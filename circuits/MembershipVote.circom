pragma circom 2.1.6;

/*
 * ZKSN Anonymous Governance — Membership Vote Circuit
 *
 * Proves that a voter:
 *   1. Knows a `secret` whose Poseidon hash is a leaf in the membership
 *      Merkle tree with root `membershipRoot` (membership proof).
 *   2. Derives a per-proposal nullifier = Poseidon(secret, proposalId) that
 *      prevents double-voting without linking votes across proposals.
 *
 * Public signals (must match ZKSNGovernance.castVote signal layout):
 *   [0] nullifierHash  — Poseidon(secret, proposalId)
 *   [1] proposalId     — the proposal being voted on
 *   [2] voteYes        — 1 = yes, 0 = no
 *   [3] membershipRoot — current Merkle root from ZKSNGovernance
 *
 * Private inputs:
 *   secret             — voter's private key (32-byte field element)
 *   pathElements[20]   — Merkle sibling hashes along the proof path
 *   pathIndices[20]    — 0 = leaf is left child, 1 = right child (per level)
 *
 * Tree depth: 20 levels → supports up to 2^20 = 1,048,576 members.
 *
 * Hash function: Poseidon over BN254 scalar field.
 * Poseidon is ZK-friendly (much cheaper than SHA-256 in a circuit),
 * collision-resistant, and the on-chain PoseidonHasher.sol computes
 * the same values so membership roots can be verified without a circuit.
 *
 * Compile:
 *   circom circuits/MembershipVote.circom \
 *     --r1cs --wasm --sym --c \
 *     -l node_modules \
 *     -o build/circuits/
 *
 * Trusted setup (Groth16, Powers of Tau phase 2):
 *   snarkjs groth16 setup build/circuits/MembershipVote.r1cs \
 *     pot20_final.ptau build/circuits/MembershipVote_0000.zkey
 *   snarkjs zkey contribute build/circuits/MembershipVote_0000.zkey \
 *     build/circuits/MembershipVote_final.zkey --name="Contributor 1" -e="entropy"
 *   snarkjs zkey export verificationkey \
 *     build/circuits/MembershipVote_final.zkey build/circuits/verification_key.json
 *
 * Generate Solidity verifier (replace Groth16Verifier.sol after ceremony):
 *   snarkjs zkey export solidityverifier \
 *     build/circuits/MembershipVote_final.zkey \
 *     governance/contracts/Groth16Verifier.sol
 */

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/mux1.circom";
include "node_modules/circomlib/circuits/comparators.circom";

// ── Merkle inclusion proof (depth D) ─────────────────────────────────────────

template MerkleProof(depth) {
    signal input  leaf;
    signal input  pathElements[depth];
    signal input  pathIndices[depth];   // 0 = go left, 1 = go right
    signal output root;

    component hashers[depth];
    component muxes[depth];

    // levelHashes[0] is the leaf; levelHashes[depth] is the root
    signal levelHashes[depth + 1];
    levelHashes[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        // Choose ordering: if pathIndices[i] = 0 → (current, sibling)
        //                   if pathIndices[i] = 1 → (sibling, current)
        muxes[i] = Mux1();
        muxes[i].c[0] <== levelHashes[i];
        muxes[i].c[1] <== pathElements[i];
        muxes[i].s    <== pathIndices[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== muxes[i].out;
        hashers[i].inputs[1] <== muxes[i].c[1 - pathIndices[i]];

        levelHashes[i + 1] <== hashers[i].out;
    }

    root <== levelHashes[depth];
}

// ── MembershipVote — main circuit ────────────────────────────────────────────

template MembershipVote(depth) {
    // ── private inputs ───────────────────────────────────────────────────────
    signal input secret;                    // voter's private key
    signal input pathElements[depth];       // Merkle proof siblings
    signal input pathIndices[depth];        // Merkle proof directions

    // ── public inputs ────────────────────────────────────────────────────────
    signal input  nullifierHash;            // signals[0] in castVote
    signal input  proposalId;              // signals[1] in castVote
    signal input  voteYes;                 // signals[2] in castVote (0 or 1)
    signal input  membershipRoot;          // signals[3] in castVote

    // ── Step 1: derive membership leaf = Poseidon(secret) ────────────────────
    component leafHasher = Poseidon(1);
    leafHasher.inputs[0] <== secret;
    signal leaf <== leafHasher.out;

    // ── Step 2: verify Merkle inclusion ──────────────────────────────────────
    component merkle = MerkleProof(depth);
    merkle.leaf              <== leaf;
    merkle.pathElements      <== pathElements;
    merkle.pathIndices       <== pathIndices;

    // Constrain: computed root must equal the public membershipRoot
    merkle.root === membershipRoot;

    // ── Step 3: derive nullifier = Poseidon(secret, proposalId) ──────────────
    component nullifierHasher = Poseidon(2);
    nullifierHasher.inputs[0] <== secret;
    nullifierHasher.inputs[1] <== proposalId;

    // Constrain: computed nullifier must equal the public nullifierHash
    nullifierHasher.out === nullifierHash;

    // ── Step 4: constrain voteYes ∈ {0, 1} ───────────────────────────────────
    // A boolean constraint: voteYes * (1 - voteYes) == 0
    signal voteCheck;
    voteCheck <== voteYes * (1 - voteYes);
    voteCheck === 0;
}

// Instantiate with depth = 20 (1M members max)
component main {public [nullifierHash, proposalId, voteYes, membershipRoot]} =
    MembershipVote(20);
