// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../contracts/ZKSNGovernance.sol";
import "../contracts/MockVerifier.sol";

/**
 * @title Deploy
 * @notice Deployment script for ZKSN governance contracts.
 *
 * Usage (testnet):
 *   forge script scripts/Deploy.s.sol \
 *     --rpc-url $RPC_URL \
 *     --private-key $PRIVATE_KEY \
 *     --broadcast \
 *     --verify
 *
 * Usage (local anvil):
 *   anvil &
 *   forge script scripts/Deploy.s.sol \
 *     --rpc-url http://localhost:8545 \
 *     --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
 *     --broadcast
 *
 * Note on the verifier:
 *   - For testing: deploys MockVerifier (always returns true)
 *   - For production: deploy your actual ZK circuit verifier first,
 *     then pass its address to ZKSNGovernance constructor
 *
 * Note on the membership root:
 *   - Start with a hash of the initial set of node public keys
 *   - Updated via governance as nodes join/leave
 */
contract Deploy is Script {
    function run() external {
        uint256 deployerPrivKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivKey);

        console2.log("=== ZKSN Governance Deployment ===");
        console2.log("Deployer:", deployer);
        console2.log("Chain ID:", block.chainid);
        console2.log("");

        vm.startBroadcast(deployerPrivKey);

        // 1. Deploy verifier
        // In production: replace MockVerifier with your ZK circuit verifier
        MockVerifier verifier = new MockVerifier();
        console2.log("MockVerifier deployed at:", address(verifier));

        // 2. Compute initial membership root
        // In production: compute this from the actual initial member set
        bytes32 initialMembershipRoot = computeInitialRoot();
        console2.log("Initial membership root:", vm.toString(initialMembershipRoot));

        // 3. Deploy governance contract
        ZKSNGovernance governance = new ZKSNGovernance(
            address(verifier),
            initialMembershipRoot
        );
        console2.log("ZKSNGovernance deployed at:", address(governance));

        vm.stopBroadcast();

        console2.log("");
        console2.log("=== Deployment Complete ===");
        console2.log("Verifier:    ", address(verifier));
        console2.log("Governance:  ", address(governance));
        console2.log("Member root: ", vm.toString(initialMembershipRoot));
        console2.log("");
        console2.log("Save these addresses. Update docs/GOVERNANCE_DEPLOYMENT.md.");
    }

    /// Compute an initial membership root from placeholder values.
    /// In production: replace with actual node commitment hashes.
    function computeInitialRoot() internal pure returns (bytes32) {
        // Placeholder: hash of "genesis" + chain id
        // Production: Merkle root of initial node commitments
        return keccak256(abi.encodePacked("zksn-genesis-membership-root-v1"));
    }
}
