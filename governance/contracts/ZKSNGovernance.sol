// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IVerifier.sol";

/**
 * @title ZKSNGovernance
 * @notice Anonymous on-chain governance. No multisig. No admin. No upgradeable proxy.
 * Votes are ZK-SNARK proofs of membership + nullifier (prevents double-voting).
 * Proposals execute autonomously after passing vote + 2-day time-lock.
 */
contract ZKSNGovernance {
    event ProposalCreated(
        bytes32 indexed proposalId, bytes32 contentHash, uint256 votingEndsAt, address indexed proposer
    );
    event VoteCast(bytes32 indexed proposalId, bytes32 indexed nullifierHash, bool voteYes);
    event ProposalPassed(bytes32 indexed proposalId);
    event ProposalFailed(bytes32 indexed proposalId);
    event ProposalExecuted(bytes32 indexed proposalId);
    event MembershipRootUpdated(bytes32 newRoot);

    struct Proposal {
        bytes32 contentHash;
        uint256 votingEndsAt;
        uint256 executionAllowedAt;
        uint256 yesVotes;
        uint256 noVotes;
        bool executed;
        bool passed;
        address target;
        bytes callData;
    }

    IVerifier public immutable verifier;
    bytes32 public membershipRoot;
    uint256 public constant VOTING_PERIOD = 7 days;
    uint256 public constant TIME_LOCK = 2 days;
    uint256 public constant QUORUM = 10;
    uint256 public constant PASS_THRESHOLD = 50;

    mapping(bytes32 => Proposal) public proposals;
    mapping(bytes32 => bool) public nullifierUsed;

    constructor(address _verifier, bytes32 _initialMembershipRoot) {
        verifier = IVerifier(_verifier);
        membershipRoot = _initialMembershipRoot;
    }

    function createProposal(bytes32 contentHash, address target, bytes calldata callData)
        external
        returns (bytes32 proposalId)
    {
        proposalId = keccak256(abi.encodePacked(contentHash, block.timestamp, msg.sender));
        proposals[proposalId] = Proposal({
            contentHash: contentHash,
            votingEndsAt: block.timestamp + VOTING_PERIOD,
            executionAllowedAt: block.timestamp + VOTING_PERIOD + TIME_LOCK,
            yesVotes: 0,
            noVotes: 0,
            executed: false,
            passed: false,
            target: target,
            callData: callData
        });
        emit ProposalCreated(proposalId, contentHash, block.timestamp + VOTING_PERIOD, msg.sender);
    }

    function castVote(bytes32 proposalId, bytes32 nullifierHash, bool voteYes, bytes calldata proof) external {
        Proposal storage p = proposals[proposalId];
        require(p.votingEndsAt > 0, "Proposal not found");
        require(block.timestamp < p.votingEndsAt, "Voting period ended");
        require(!nullifierUsed[nullifierHash], "Already voted");

        uint256[4] memory signals =
            [uint256(nullifierHash), uint256(proposalId), voteYes ? 1 : 0, uint256(membershipRoot)];
        require(verifier.verifyProof(proof, signals), "Invalid ZK proof");

        nullifierUsed[nullifierHash] = true;
        if (voteYes) p.yesVotes++;
        else p.noVotes++;
        emit VoteCast(proposalId, nullifierHash, voteYes);
    }

    function finalizeProposal(bytes32 proposalId) external {
        Proposal storage p = proposals[proposalId];
        require(p.votingEndsAt > 0, "Proposal not found");
        require(block.timestamp >= p.votingEndsAt, "Still voting");
        require(!p.executed, "Already executed");

        uint256 total = p.yesVotes + p.noVotes;
        bool quorumMet = total >= QUORUM;
        bool majorityYes = total > 0 && (p.yesVotes * 100 / total) > PASS_THRESHOLD;

        if (quorumMet && majorityYes) {
            p.passed = true;
            emit ProposalPassed(proposalId);
        } else {
            emit ProposalFailed(proposalId);
        }
    }

    function execute(bytes32 proposalId) external {
        Proposal storage p = proposals[proposalId];
        require(p.passed, "Proposal did not pass");
        require(!p.executed, "Already executed");
        require(block.timestamp >= p.executionAllowedAt, "Time-lock active");

        p.executed = true;
        emit ProposalExecuted(proposalId);

        if (p.target != address(0) && p.callData.length > 0) {
            (bool ok,) = p.target.call(p.callData);
            require(ok, "Execution failed");
        }
    }

    function updateMembershipRoot(bytes32 newRoot) external {
        require(msg.sender == address(this), "Only via governance");
        membershipRoot = newRoot;
        emit MembershipRootUpdated(newRoot);
    }

    function hasVoted(bytes32 nullifierHash) external view returns (bool) {
        return nullifierUsed[nullifierHash];
    }

    function getProposal(bytes32 proposalId)
        external
        view
        returns (
            bytes32 contentHash,
            uint256 votingEndsAt,
            uint256 yesVotes,
            uint256 noVotes,
            bool executed,
            bool passed
        )
    {
        Proposal storage p = proposals[proposalId];
        return (p.contentHash, p.votingEndsAt, p.yesVotes, p.noVotes, p.executed, p.passed);
    }
}
