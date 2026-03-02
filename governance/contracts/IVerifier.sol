// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IVerifier
 * @notice Interface for the ZK-SNARK proof verifier.
 *
 * @dev This interface must be implemented by the verifier contract generated
 * by your ZK circuit toolchain (Circom/snarkjs, Noir, Halo2, etc.).
 *
 * The verifier checks a ZK proof that simultaneously proves:
 *   1. The voter holds a valid membership credential
 *      (credential commitment is a leaf in the current membershipRoot)
 *   2. The nullifier was correctly computed from the credential
 *      (nullifierHash = Poseidon(credential, proposalId))
 *   3. The vote value matches the committed value in the proof
 *
 * Circuit public inputs (in order):
 *   [0] nullifierHash  — unique per (credential, proposalId) pair
 *   [1] proposalId     — the proposal being voted on
 *   [2] voteValue      — 1 = yes, 0 = no
 *   [3] membershipRoot — Merkle root of valid credentials (from contract state)
 *
 * Circuit private inputs (not in this interface):
 *   - credential_secret  — the voter's private credential scalar
 *   - merkle_path        — proof of inclusion in the membership tree
 *   - path_indices       — left/right indicators for each Merkle level
 */
interface IVerifier {
    /**
     * @notice Verify a ZK proof.
     * @param proof     The serialized proof bytes (format depends on backend)
     * @param publicSignals The 4 public inputs: [nullifierHash, proposalId, voteValue, membershipRoot]
     * @return true if the proof is valid, false otherwise
     */
    function verifyProof(
        bytes calldata proof,
        uint256[4] calldata publicSignals
    ) external view returns (bool);
}
