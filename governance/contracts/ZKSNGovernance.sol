// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ZKSNGovernance
 * @notice Anonymous on-chain governance for the Zero-Knowledge Sovereign Network.
 *
 * @dev Voting is done via ZK-SNARK proofs that prove:
 *   1. The voter holds a valid ZKSN membership credential
 *   2. The voter has not voted on this proposal before (nullifier)
 *   3. Without revealing WHO the voter is
 *
 * This contract stores:
 *   - Proposals (proposed protocol changes)
 *   - Vote tallies (yes/no counts)
 *   - Nullifier hashes (to prevent double-voting)
 *   - Execution queue (passed proposals, time-locked)
 *
 * No multisig. No named administrators. No upgradeable proxy.
 * Protocol changes execute autonomously after passing a vote + time lock.
 */

interface IVerifier {
    /**
     * @notice Verify a ZK proof of membership and voting intent.
     * @param proof The ZK-SNARK proof bytes
     * @param publicSignals [nullifierHash, proposalId, voteValue, membershipRoot]
     */
    function verifyProof(
        bytes calldata proof,
        uint256[4] calldata publicSignals
    ) external view returns (bool);
}

contract ZKSNGovernance {

    // =========================================================================
    // Events
    // =========================================================================

    event ProposalCreated(
        bytes32 indexed proposalId,
        bytes32 contentHash,
        uint256 votingEndsAt,
        address indexed proposer  // May be address(0) if anonymous
    );

    event VoteCast(
        bytes32 indexed proposalId,
        bytes32 indexed nullifierHash,  // Identifies the vote without identifying the voter
        bool support
    );

    event ProposalPassed(bytes32 indexed proposalId, uint256 executeAfter);
    event ProposalFailed(bytes32 indexed proposalId);
    event ProposalExecuted(bytes32 indexed proposalId);

    // =========================================================================
    // State
    // =========================================================================

    struct Proposal {
        // IPFS hash of the full proposal text (stored off-chain)
        bytes32 contentHash;
        // Unix timestamp when voting closes
        uint256 votingEndsAt;
        // Vote tallies
        uint256 yesVotes;
        uint256 noVotes;
        // Execution
        bool passed;
        bool executed;
        uint256 executeAfter;   // Timestamp: proposal cannot execute before this
        bytes executionPayload; // Calldata to execute if passed
        address executionTarget;
    }

    /// Proposals by their ID (keccak256 of contentHash + block.timestamp)
    mapping(bytes32 => Proposal) public proposals;

    /// Nullifier hashes — marks that a particular credential has voted on a proposal
    /// nullifierHashes[proposalId][nullifierHash] = true if used
    mapping(bytes32 => mapping(bytes32 => bool)) public nullifierHashes;

    /// Merkle root of current valid membership credentials
    bytes32 public membershipRoot;

    /// ZK proof verifier contract
    IVerifier public immutable verifier;

    /// Voting period in seconds
    uint256 public constant VOTING_PERIOD = 7 days;

    /// Time lock period: passed proposals cannot execute for this long
    uint256 public constant EXECUTION_TIMELOCK = 2 days;

    /// Quorum: minimum total votes for a result to be valid
    uint256 public constant QUORUM = 10;

    /// Pass threshold: percentage of yes votes required (in basis points, 5000 = 50%)
    uint256 public constant PASS_THRESHOLD_BPS = 5000;

    // =========================================================================
    // Constructor
    // =========================================================================

    constructor(address _verifier, bytes32 _initialMembershipRoot) {
        verifier = IVerifier(_verifier);
        membershipRoot = _initialMembershipRoot;
    }

    // =========================================================================
    // Proposal Creation
    // =========================================================================

    /**
     * @notice Create a new governance proposal.
     * @param contentHash IPFS CID (as bytes32) of the proposal document
     * @param executionTarget Contract to call if the proposal passes (address(0) for signal votes)
     * @param executionPayload Calldata to send to executionTarget
     */
    function propose(
        bytes32 contentHash,
        address executionTarget,
        bytes calldata executionPayload
    ) external returns (bytes32 proposalId) {
        proposalId = keccak256(abi.encodePacked(contentHash, block.timestamp, msg.sender));

        require(proposals[proposalId].votingEndsAt == 0, "Proposal already exists");

        proposals[proposalId] = Proposal({
            contentHash: contentHash,
            votingEndsAt: block.timestamp + VOTING_PERIOD,
            yesVotes: 0,
            noVotes: 0,
            passed: false,
            executed: false,
            executeAfter: 0,
            executionPayload: executionPayload,
            executionTarget: executionTarget
        });

        emit ProposalCreated(proposalId, contentHash, proposals[proposalId].votingEndsAt, msg.sender);
    }

    // =========================================================================
    // Voting
    // =========================================================================

    /**
     * @notice Cast an anonymous vote using a ZK membership proof.
     *
     * @param proposalId   The proposal to vote on
     * @param support      true = yes, false = no
     * @param nullifierHash Unique hash that prevents double-voting without revealing identity
     * @param proof        ZK-SNARK proof bytes
     *
     * @dev The proof must demonstrate:
     *   - The voter's credential is in the current membershipRoot
     *   - nullifierHash = Poseidon(credential, proposalId) — ties the nullifier to this proposal
     *   - support matches the committed vote value in the proof
     *
     * The nullifier prevents double-voting: the same credential always produces the
     * same nullifier for the same proposal, but reveals nothing about the credential itself.
     */
    function vote(
        bytes32 proposalId,
        bool support,
        bytes32 nullifierHash,
        bytes calldata proof
    ) external {
        Proposal storage p = proposals[proposalId];

        require(p.votingEndsAt > 0, "Proposal does not exist");
        require(block.timestamp < p.votingEndsAt, "Voting has ended");
        require(!nullifierHashes[proposalId][nullifierHash], "Already voted");

        // Verify the ZK proof
        uint256[4] memory publicSignals = [
            uint256(nullifierHash),
            uint256(proposalId),
            support ? 1 : 0,
            uint256(membershipRoot)
        ];

        require(
            verifier.verifyProof(proof, publicSignals),
            "Invalid ZK proof"
        );

        // Record nullifier (prevents double-voting)
        nullifierHashes[proposalId][nullifierHash] = true;

        // Count vote
        if (support) {
            p.yesVotes++;
        } else {
            p.noVotes++;
        }

        emit VoteCast(proposalId, nullifierHash, support);
    }

    // =========================================================================
    // Finalization
    // =========================================================================

    /**
     * @notice Finalize a proposal after its voting period ends.
     * Anyone can call this — no privileged finalizer.
     */
    function finalize(bytes32 proposalId) external {
        Proposal storage p = proposals[proposalId];

        require(p.votingEndsAt > 0, "Proposal does not exist");
        require(block.timestamp >= p.votingEndsAt, "Voting still active");
        require(!p.passed && !p.executed, "Already finalized");

        uint256 totalVotes = p.yesVotes + p.noVotes;

        if (
            totalVotes >= QUORUM &&
            p.yesVotes * 10000 / totalVotes >= PASS_THRESHOLD_BPS
        ) {
            p.passed = true;
            p.executeAfter = block.timestamp + EXECUTION_TIMELOCK;
            emit ProposalPassed(proposalId, p.executeAfter);
        } else {
            emit ProposalFailed(proposalId);
        }
    }

    /**
     * @notice Execute a passed proposal after the time lock expires.
     * Anyone can call this — no privileged executor.
     */
    function execute(bytes32 proposalId) external {
        Proposal storage p = proposals[proposalId];

        require(p.passed, "Proposal has not passed");
        require(!p.executed, "Already executed");
        require(block.timestamp >= p.executeAfter, "Time lock active");

        p.executed = true;

        if (p.executionTarget != address(0) && p.executionPayload.length > 0) {
            (bool success, ) = p.executionTarget.call(p.executionPayload);
            require(success, "Execution failed");
        }

        emit ProposalExecuted(proposalId);
    }

    // =========================================================================
    // Membership Root Updates
    // =========================================================================

    /**
     * @notice Update the membership credential root.
     *
     * This is itself a governed action — the membership root can only be updated
     * by passing a governance proposal. The execution payload for such a proposal
     * would call this function.
     *
     * @dev Only callable via governance execution (i.e., only from this contract itself)
     */
    function updateMembershipRoot(bytes32 newRoot) external {
        require(msg.sender == address(this), "Only governance can update membership root");
        membershipRoot = newRoot;
    }

    // =========================================================================
    // View Functions
    // =========================================================================

    function getProposal(bytes32 proposalId) external view returns (Proposal memory) {
        return proposals[proposalId];
    }

    function hasVoted(bytes32 proposalId, bytes32 nullifierHash) external view returns (bool) {
        return nullifierHashes[proposalId][nullifierHash];
    }
}
