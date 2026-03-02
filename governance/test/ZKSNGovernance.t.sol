// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../contracts/ZKSNGovernance.sol";
import "../contracts/MockVerifier.sol";

/**
 * @title ZKSNGovernanceTest
 * @notice Full test suite for the ZKSN governance contract.
 *
 * Run with: forge test -vvv
 */
contract ZKSNGovernanceTest is Test {

    ZKSNGovernance  governance;
    MockVerifier    verifier;

    bytes32 constant MEMBERSHIP_ROOT = keccak256("initial-membership-root");
    bytes32 constant CONTENT_HASH    = keccak256("proposal-content-ipfs-hash");

    // Placeholder proof and nullifiers (MockVerifier accepts all proofs)
    bytes   constant VALID_PROOF     = hex"deadbeef";
    bytes32 constant NULLIFIER_1     = keccak256("voter-1-nullifier");
    bytes32 constant NULLIFIER_2     = keccak256("voter-2-nullifier");
    bytes32 constant NULLIFIER_3     = keccak256("voter-3-nullifier");

    function setUp() public {
        verifier    = new MockVerifier();
        governance  = new ZKSNGovernance(address(verifier), MEMBERSHIP_ROOT);
    }

    // =========================================================================
    // Proposal Creation
    // =========================================================================

    function test_ProposeCreatesProposal() public {
        bytes32 id = governance.propose(CONTENT_HASH, address(0), "");

        ZKSNGovernance.Proposal memory p = governance.getProposal(id);

        assertEq(p.contentHash, CONTENT_HASH);
        assertGt(p.votingEndsAt, block.timestamp);
        assertEq(p.yesVotes, 0);
        assertEq(p.noVotes, 0);
        assertFalse(p.passed);
        assertFalse(p.executed);
    }

    function test_ProposeEmitsEvent() public {
        vm.expectEmit(true, false, false, false);
        emit ZKSNGovernance.ProposalCreated(bytes32(0), CONTENT_HASH, 0, address(this));
        governance.propose(CONTENT_HASH, address(0), "");
    }

    function test_CannotCreateDuplicateProposal() public {
        // Two proposals with same content hash but different timestamps are ok
        bytes32 id1 = governance.propose(CONTENT_HASH, address(0), "");
        vm.warp(block.timestamp + 1);
        bytes32 id2 = governance.propose(CONTENT_HASH, address(0), "");
        assertTrue(id1 != id2, "Different timestamps = different IDs");
    }

    // =========================================================================
    // Voting
    // =========================================================================

    function test_VoteYes() public {
        bytes32 id = governance.propose(CONTENT_HASH, address(0), "");

        governance.vote(id, true, NULLIFIER_1, VALID_PROOF);

        ZKSNGovernance.Proposal memory p = governance.getProposal(id);
        assertEq(p.yesVotes, 1);
        assertEq(p.noVotes, 0);
    }

    function test_VoteNo() public {
        bytes32 id = governance.propose(CONTENT_HASH, address(0), "");

        governance.vote(id, false, NULLIFIER_1, VALID_PROOF);

        ZKSNGovernance.Proposal memory p = governance.getProposal(id);
        assertEq(p.yesVotes, 0);
        assertEq(p.noVotes, 1);
    }

    function test_VoteEmitsEvent() public {
        bytes32 id = governance.propose(CONTENT_HASH, address(0), "");

        vm.expectEmit(true, true, false, true);
        emit ZKSNGovernance.VoteCast(id, NULLIFIER_1, true);
        governance.vote(id, true, NULLIFIER_1, VALID_PROOF);
    }

    function test_CannotDoubleVote() public {
        bytes32 id = governance.propose(CONTENT_HASH, address(0), "");

        governance.vote(id, true, NULLIFIER_1, VALID_PROOF);

        vm.expectRevert("Already voted");
        governance.vote(id, false, NULLIFIER_1, VALID_PROOF);
    }

    function test_DifferentNullifiersCanVote() public {
        bytes32 id = governance.propose(CONTENT_HASH, address(0), "");

        governance.vote(id, true,  NULLIFIER_1, VALID_PROOF);
        governance.vote(id, true,  NULLIFIER_2, VALID_PROOF);
        governance.vote(id, false, NULLIFIER_3, VALID_PROOF);

        ZKSNGovernance.Proposal memory p = governance.getProposal(id);
        assertEq(p.yesVotes, 2);
        assertEq(p.noVotes,  1);
    }

    function test_CannotVoteAfterDeadline() public {
        bytes32 id = governance.propose(CONTENT_HASH, address(0), "");

        // Fast-forward past voting period
        vm.warp(block.timestamp + governance.VOTING_PERIOD() + 1);

        vm.expectRevert("Voting has ended");
        governance.vote(id, true, NULLIFIER_1, VALID_PROOF);
    }

    function test_CannotVoteOnNonExistentProposal() public {
        bytes32 fakeId = keccak256("does-not-exist");
        vm.expectRevert("Proposal does not exist");
        governance.vote(fakeId, true, NULLIFIER_1, VALID_PROOF);
    }

    function test_InvalidProofRejected() public {
        // Deploy strict verifier that rejects all proofs by default
        StrictMockVerifier strictVerifier = new StrictMockVerifier();
        ZKSNGovernance strictGov = new ZKSNGovernance(
            address(strictVerifier),
            MEMBERSHIP_ROOT
        );

        bytes32 id = strictGov.propose(CONTENT_HASH, address(0), "");

        vm.expectRevert("Invalid ZK proof");
        strictGov.vote(id, true, NULLIFIER_1, hex"badbadbadbad");
    }

    // =========================================================================
    // Finalization
    // =========================================================================

    function test_FinalizePassesWithQuorumAndMajority() public {
        bytes32 id = governance.propose(CONTENT_HASH, address(0), "");

        // Cast enough yes votes to meet quorum and threshold
        for (uint256 i = 0; i < governance.QUORUM(); i++) {
            bytes32 nullifier = keccak256(abi.encodePacked("voter", i));
            governance.vote(id, true, nullifier, VALID_PROOF);
        }

        // Move past voting period
        vm.warp(block.timestamp + governance.VOTING_PERIOD() + 1);

        vm.expectEmit(true, false, false, false);
        emit ZKSNGovernance.ProposalPassed(id, 0);
        governance.finalize(id);

        ZKSNGovernance.Proposal memory p = governance.getProposal(id);
        assertTrue(p.passed);
        assertGt(p.executeAfter, block.timestamp);
    }

    function test_FinalizeFailsWithoutQuorum() public {
        bytes32 id = governance.propose(CONTENT_HASH, address(0), "");

        // Cast fewer votes than quorum
        uint256 quorum = governance.QUORUM();
        for (uint256 i = 0; i < quorum - 1; i++) {
            bytes32 nullifier = keccak256(abi.encodePacked("voter", i));
            governance.vote(id, true, nullifier, VALID_PROOF);
        }

        vm.warp(block.timestamp + governance.VOTING_PERIOD() + 1);

        vm.expectEmit(true, false, false, false);
        emit ZKSNGovernance.ProposalFailed(id);
        governance.finalize(id);

        ZKSNGovernance.Proposal memory p = governance.getProposal(id);
        assertFalse(p.passed);
    }

    function test_FinalizeFailsWithMajorityNo() public {
        bytes32 id = governance.propose(CONTENT_HASH, address(0), "");

        uint256 quorum = governance.QUORUM();
        // 1 yes, quorum-1 no
        governance.vote(id, true, NULLIFIER_1, VALID_PROOF);
        for (uint256 i = 1; i < quorum; i++) {
            bytes32 nullifier = keccak256(abi.encodePacked("no-voter", i));
            governance.vote(id, false, nullifier, VALID_PROOF);
        }

        vm.warp(block.timestamp + governance.VOTING_PERIOD() + 1);

        governance.finalize(id);
        ZKSNGovernance.Proposal memory p = governance.getProposal(id);
        assertFalse(p.passed);
    }

    function test_CannotFinalizeBeforeVotingEnds() public {
        bytes32 id = governance.propose(CONTENT_HASH, address(0), "");

        vm.expectRevert("Voting still active");
        governance.finalize(id);
    }

    // =========================================================================
    // Execution
    // =========================================================================

    function test_ExecuteAfterTimeLock() public {
        bytes32 id = _passProposal(address(0), "");

        // Still in time lock
        vm.expectRevert("Time lock active");
        governance.execute(id);

        // Fast-forward past time lock
        vm.warp(block.timestamp + governance.EXECUTION_TIMELOCK() + 1);

        vm.expectEmit(true, false, false, false);
        emit ZKSNGovernance.ProposalExecuted(id);
        governance.execute(id);

        ZKSNGovernance.Proposal memory p = governance.getProposal(id);
        assertTrue(p.executed);
    }

    function test_CannotExecuteTwice() public {
        bytes32 id = _passProposal(address(0), "");

        vm.warp(block.timestamp + governance.EXECUTION_TIMELOCK() + 1);
        governance.execute(id);

        vm.expectRevert("Already executed");
        governance.execute(id);
    }

    function test_CannotExecuteFailedProposal() public {
        bytes32 id = governance.propose(CONTENT_HASH, address(0), "");
        vm.warp(block.timestamp + governance.VOTING_PERIOD() + 1);
        governance.finalize(id); // fails (no votes)

        vm.expectRevert("Proposal has not passed");
        governance.execute(id);
    }

    // =========================================================================
    // Membership Root Update via Governance
    // =========================================================================

    function test_MembershipRootUpdatableViaGovernance() public {
        bytes32 newRoot = keccak256("new-membership-root");

        // Encode the updateMembershipRoot call as the execution payload
        bytes memory payload = abi.encodeWithSelector(
            governance.updateMembershipRoot.selector,
            newRoot
        );

        bytes32 id = _passProposal(address(governance), payload);

        vm.warp(block.timestamp + governance.EXECUTION_TIMELOCK() + 1);
        governance.execute(id);

        assertEq(governance.membershipRoot(), newRoot);
    }

    function test_CannotUpdateMembershipRootDirectly() public {
        vm.expectRevert("Only governance can update membership root");
        governance.updateMembershipRoot(keccak256("attacker-root"));
    }

    // =========================================================================
    // hasVoted view
    // =========================================================================

    function test_HasVotedReturnsTrueAfterVoting() public {
        bytes32 id = governance.propose(CONTENT_HASH, address(0), "");
        assertFalse(governance.hasVoted(id, NULLIFIER_1));

        governance.vote(id, true, NULLIFIER_1, VALID_PROOF);
        assertTrue(governance.hasVoted(id, NULLIFIER_1));
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /// Create and pass a proposal by casting enough yes votes, then finalize.
    function _passProposal(
        address target,
        bytes memory payload
    ) internal returns (bytes32 id) {
        id = governance.propose(CONTENT_HASH, target, payload);

        uint256 quorum = governance.QUORUM();
        for (uint256 i = 0; i < quorum; i++) {
            bytes32 nullifier = keccak256(abi.encodePacked("helper-voter", i));
            governance.vote(id, true, nullifier, VALID_PROOF);
        }

        vm.warp(block.timestamp + governance.VOTING_PERIOD() + 1);
        governance.finalize(id);
    }
}
