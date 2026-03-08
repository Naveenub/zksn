// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "forge-std/Test.sol";
import "../contracts/ZKSNGovernance.sol";
import "../contracts/MockVerifier.sol";

contract ZKSNGovernanceTest is Test {
    ZKSNGovernance gov;
    MockVerifier mock;
    StrictMockVerifier strict;
    bytes32 constant ROOT = keccak256("initial_root");
    bytes constant PROOF = hex"deadbeef";

    function setUp() public {
        mock = new MockVerifier();
        strict = new StrictMockVerifier();
        gov = new ZKSNGovernance(address(mock), ROOT);
    }

    function _proposal() internal returns (bytes32) {
        return gov.createProposal(keccak256("change"), address(0), "");
    }

    function test_CreateProposal() public {
        bytes32 id = _proposal();
        (bytes32 ch,,,,,) = gov.getProposal(id);
        assertEq(ch, keccak256("change"));
    }

    function test_VoteYes() public {
        bytes32 id = _proposal();
        bytes32 nul = keccak256("voter1");
        gov.castVote(id, nul, true, PROOF);
        (,, uint256 yes,,,) = gov.getProposal(id);
        assertEq(yes, 1);
    }

    function test_VoteNo() public {
        bytes32 id = _proposal();
        bytes32 nul = keccak256("voter1");
        gov.castVote(id, nul, false, PROOF);
        (,,, uint256 no,,) = gov.getProposal(id);
        assertEq(no, 1);
    }

    function test_DoubleVotePrevented() public {
        bytes32 id = _proposal();
        bytes32 nul = keccak256("voter1");
        gov.castVote(id, nul, true, PROOF);
        vm.expectRevert("Already voted");
        gov.castVote(id, nul, true, PROOF);
    }

    function test_VoteAfterDeadlineFails() public {
        bytes32 id = _proposal();
        vm.warp(block.timestamp + 8 days);
        vm.expectRevert("Voting period ended");
        gov.castVote(id, keccak256("late"), true, PROOF);
    }

    function test_InvalidProofRejected() public {
        ZKSNGovernance strictGov = new ZKSNGovernance(address(strict), ROOT);
        bytes32 id = strictGov.createProposal(keccak256("c"), address(0), "");
        vm.expectRevert("Invalid ZK proof");
        strictGov.castVote(id, keccak256("v1"), true, hex"badbad");
    }

    function test_QuorumRequired() public {
        bytes32 id = _proposal();
        // vote with 9 unique nullifiers (below quorum of 10)
        for (uint256 i = 0; i < 9; i++) {
            gov.castVote(id, keccak256(abi.encode("v", i)), true, PROOF);
        }
        vm.warp(block.timestamp + 8 days);
        gov.finalizeProposal(id);
        (,,,,, bool passed) = gov.getProposal(id);
        assertFalse(passed);
    }

    function test_PassesWithMajority() public {
        bytes32 id = _proposal();
        for (uint256 i = 0; i < 11; i++) {
            gov.castVote(id, keccak256(abi.encode("v", i)), true, PROOF);
        }
        vm.warp(block.timestamp + 8 days);
        gov.finalizeProposal(id);
        (,,,,, bool passed) = gov.getProposal(id);
        assertTrue(passed);
    }

    function test_FailsWithoutMajority() public {
        bytes32 id = _proposal();
        for (uint256 i = 0; i < 6; i++) {
            gov.castVote(id, keccak256(abi.encode("y", i)), true, PROOF);
        }
        for (uint256 i = 0; i < 6; i++) {
            gov.castVote(id, keccak256(abi.encode("n", i)), false, PROOF);
        }
        vm.warp(block.timestamp + 8 days);
        gov.finalizeProposal(id);
        (,,,,, bool passed) = gov.getProposal(id);
        assertFalse(passed);
    }

    function test_TimeLockEnforced() public {
        bytes32 id = _proposal();
        for (uint256 i = 0; i < 11; i++) {
            gov.castVote(id, keccak256(abi.encode("v", i)), true, PROOF);
        }
        vm.warp(block.timestamp + 8 days);
        gov.finalizeProposal(id);
        vm.expectRevert("Time-lock active");
        gov.execute(id);
    }

    function test_ExecuteAfterTimeLock() public {
        bytes32 id = _proposal();
        for (uint256 i = 0; i < 11; i++) {
            gov.castVote(id, keccak256(abi.encode("v", i)), true, PROOF);
        }
        vm.warp(block.timestamp + 8 days);
        gov.finalizeProposal(id);
        vm.warp(block.timestamp + 3 days);
        gov.execute(id);
        (,,,, bool executed,) = gov.getProposal(id);
        assertTrue(executed);
    }

    function test_DoubleExecutionPrevented() public {
        bytes32 id = _proposal();
        for (uint256 i = 0; i < 11; i++) {
            gov.castVote(id, keccak256(abi.encode("v", i)), true, PROOF);
        }
        vm.warp(block.timestamp + 10 days);
        gov.finalizeProposal(id);
        gov.execute(id);
        vm.expectRevert("Already executed");
        gov.execute(id);
    }

    function test_HasVoted() public {
        bytes32 id = _proposal();
        bytes32 nul = keccak256("voter_check");
        assertFalse(gov.hasVoted(nul));
        gov.castVote(id, nul, true, PROOF);
        assertTrue(gov.hasVoted(nul));
    }

    function test_MembershipRootUpdateOnlyViaGovernance() public {
        vm.expectRevert("Only via governance");
        gov.updateMembershipRoot(keccak256("new_root"));
    }

    function test_ProposalNotFound() public {
        vm.expectRevert("Proposal not found");
        gov.castVote(bytes32(0), keccak256("v"), true, PROOF);
    }

    function test_ExecuteFailedProposalReverts() public {
        bytes32 id = _proposal();
        vm.warp(block.timestamp + 8 days);
        gov.finalizeProposal(id);
        vm.expectRevert("Proposal did not pass");
        gov.execute(id);
    }
}
