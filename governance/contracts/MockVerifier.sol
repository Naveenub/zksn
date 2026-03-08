// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "./IVerifier.sol";

/// Always returns true — for testing only.
contract MockVerifier is IVerifier {
    function verifyProof(bytes calldata, uint256[4] calldata) external pure returns (bool) {
        return true;
    }
}

/// Returns true only for pre-approved proofs — for strict testing.
contract StrictMockVerifier is IVerifier {
    mapping(bytes32 => bool) public approved;

    function approve(bytes calldata proof) external {
        approved[keccak256(proof)] = true;
    }

    function verifyProof(bytes calldata proof, uint256[4] calldata) external view returns (bool) {
        return approved[keccak256(proof)];
    }
}
