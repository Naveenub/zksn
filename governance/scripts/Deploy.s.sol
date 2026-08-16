// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "forge-std/Script.sol";
import "../contracts/ZKSNGovernance.sol";
import "../contracts/Groth16Verifier.sol";

contract Deploy is Script {
    function run() external {
        vm.startBroadcast();
        Groth16Verifier verifier = new Groth16Verifier();
        bytes32 initialRoot = keccak256(abi.encodePacked("initial_member_root"));
        ZKSNGovernance gov = new ZKSNGovernance(address(verifier), initialRoot);
        console.log("Groth16Verifier:", address(verifier));
        console.log("ZKSNGovernance: ", address(gov));
        vm.stopBroadcast();
    }
}
