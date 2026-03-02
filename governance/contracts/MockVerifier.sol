// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IVerifier.sol";

/**
 * @title MockVerifier
 * @notice A mock ZK verifier for testing purposes ONLY.
 *
 * @dev This verifier ALWAYS returns true. It is used in unit tests so that
 * governance logic can be tested without a real ZK circuit.
 *
 * NEVER deploy this to mainnet. NEVER use this in production.
 */
contract MockVerifier is IVerifier {
    /// @notice Always returns true (for testing only)
    function verifyProof(
        bytes calldata /* proof */,
        uint256[4] calldata /* publicSignals */
    ) external pure override returns (bool) {
        return true;
    }
}

/**
 * @title StrictMockVerifier
 * @notice A mock verifier that rejects proofs unless they have been pre-approved.
 *
 * @dev Used in tests where you want fine-grained control over which proofs
 * succeed and which fail.
 */
contract StrictMockVerifier is IVerifier {
    mapping(bytes32 => bool) public approvedProofs;

    function approveProof(bytes calldata proof, uint256[4] calldata publicSignals) external {
        bytes32 key = keccak256(abi.encodePacked(proof, publicSignals));
        approvedProofs[key] = true;
    }

    function verifyProof(
        bytes calldata proof,
        uint256[4] calldata publicSignals
    ) external view override returns (bool) {
        bytes32 key = keccak256(abi.encodePacked(proof, publicSignals));
        return approvedProofs[key];
    }
}
