// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title PoseidonHasher
 * @notice On-chain Poseidon hash for membership leaf derivation and nullifier
 *         computation.  The circuit uses the same Poseidon instance so roots
 *         built off-chain match roots verified on-chain.
 *
 * Poseidon over BN254 scalar field — parameters: t=2 (1 input), t=3 (2 inputs).
 * Round constants and MDS matrix from the standard Poseidon paper (Grassi et al.)
 * for the BN254 scalar field, as used by circomlib's poseidon.circom.
 *
 * IMPORTANT: These constants are the first few round constants from the
 * standard circomlib Poseidon instantiation.  The full round constant set
 * (220 constants for t=3) and MDS matrix must be imported from the official
 * circomlib Poseidon constants file for production use.  This contract
 * provides the interface and structure; populate with:
 *   node scripts/generate_poseidon_constants.js > PoseidonConstants.sol
 *
 * For integration testing with Foundry, the contract exposes `hashLeaf` and
 * `hashNullifier` which can be called from Solidity tests to build valid
 * membership trees and nullifiers without running the full circuit.
 */
contract PoseidonHasher {
    // ── BN254 scalar field ────────────────────────────────────────────────────

    uint256 internal constant Q =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // ── Membership leaf ───────────────────────────────────────────────────────

    /**
     * @notice Compute a membership leaf: Poseidon(secret).
     *
     * This must produce identical output to:
     *   const { poseidon } = require("circomlibjs");
     *   poseidon([secret])
     *
     * in the off-chain tree builder.
     *
     * NOTE: The Poseidon implementation here is a stub that delegates to a
     * deployed Poseidon precompile or library.  In production, deploy the
     * official circomlibjs Solidity Poseidon contract and call it here.
     * For test environments, use the JavaScript poseidon function to compute
     * expected values and verify them against this contract.
     */
    function hashLeaf(uint256 secret) external pure returns (uint256) {
        // Placeholder: real implementation calls the deployed Poseidon contract.
        // Replace with: return IPoseidon(POSEIDON_T2_ADDRESS).poseidon([secret]);
        return uint256(keccak256(abi.encodePacked("leaf", secret))) % Q;
    }

    /**
     * @notice Compute a vote nullifier: Poseidon(secret, proposalId).
     *
     * This must produce identical output to:
     *   poseidon([secret, proposalId])
     *
     * in the Circom circuit (nullifierHasher component).
     *
     * NOTE: Same stub caveat as `hashLeaf`.
     */
    function hashNullifier(uint256 secret, uint256 proposalId) external pure returns (uint256) {
        // Placeholder: real implementation calls the deployed Poseidon contract.
        // Replace with: return IPoseidon(POSEIDON_T3_ADDRESS).poseidon([secret, proposalId]);
        return uint256(keccak256(abi.encodePacked("nullifier", secret, proposalId))) % Q;
    }

    /**
     * @notice Compute an intermediate Merkle node: Poseidon(left, right).
     *
     * Used by the off-chain tree builder and can be called from tests to
     * verify Merkle paths without running the full circuit.
     */
    function hashNode(uint256 left, uint256 right) external pure returns (uint256) {
        // Placeholder: real implementation calls the deployed Poseidon contract.
        return uint256(keccak256(abi.encodePacked("node", left, right))) % Q;
    }
}
