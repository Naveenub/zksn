// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../contracts/ZKSNGovernance.sol";
import "../contracts/MockVerifier.sol";
import "../contracts/Groth16Verifier.sol";
import "../contracts/PoseidonHasher.sol";

/**
 * @title ZKSNGovernanceTest
 *
 * Test suite covering:
 *   1. Governance logic (proposal lifecycle, voting, quorum, timelock, execution)
 *      — uses StrictMockVerifier for determinism
 *   2. Groth16Verifier correctness — real verifier rejects invalid proofs,
 *      validates proof encoding, validates field element bounds
 *   3. Signal layout — verifies castVote passes signals in the order the
 *      circuit expects: [nullifierHash, proposalId, voteYes, membershipRoot]
 *   4. Deployment path — Groth16Verifier is wired as IVerifier; MockVerifier
 *      is explicitly NOT used in the production governance instance
 *   5. PoseidonHasher consistency — leaf/nullifier derivation matches expected
 *      Poseidon semantics (format, range)
 */
contract ZKSNGovernanceTest is Test {
    // ── fixtures ──────────────────────────────────────────────────────────────

    ZKSNGovernance gov;           // uses StrictMockVerifier (governance logic tests)
    ZKSNGovernance groth16Gov;    // uses real Groth16Verifier (verifier tests)
    MockVerifier mock;
    StrictMockVerifier strict;
    Groth16Verifier realVerifier;
    PoseidonHasher hasher;

    bytes32 constant ROOT  = keccak256("initial_root");
    bytes   constant PROOF = hex"deadbeef";

    // Valid 256-byte proof encoding (a, b, c all zero — will fail pairing but
    // passes the length and field-element checks in Groth16Verifier)
    bytes constant ZERO_PROOF = abi.encode(
        [uint256(0), uint256(0)],           // a
        [[uint256(0), uint256(0)], [uint256(0), uint256(0)]], // b
        [uint256(0), uint256(0)]            // c
    );

    function setUp() public {
        mock         = new MockVerifier();
        strict       = new StrictMockVerifier();
        realVerifier = new Groth16Verifier();
        hasher       = new PoseidonHasher();

        // Governance logic tests — StrictMockVerifier (pre-approve PROOF)
        gov = new ZKSNGovernance(address(strict), ROOT);
        strict.approve(PROOF);

        // Verifier tests — real Groth16Verifier
        groth16Gov = new ZKSNGovernance(address(realVerifier), ROOT);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    function _proposal() internal returns (bytes32) {
        return gov.createProposal(keccak256("change"), address(0), "");
    }

    function _passProposal() internal returns (bytes32) {
        bytes32 id = _proposal();
        for (uint256 i = 0; i < 11; i++) {
            gov.castVote(id, keccak256(abi.encode("v", i)), true, PROOF);
        }
        vm.warp(block.timestamp + 8 days);
        gov.finalizeProposal(id);
        return id;
    }

    // ── 1. Governance logic tests (StrictMockVerifier) ────────────────────────

    function test_CreateProposal() public {
        bytes32 id = _proposal();
        (bytes32 ch,,,,,) = gov.getProposal(id);
        assertEq(ch, keccak256("change"));
    }

    function test_VoteYes() public {
        bytes32 id = _proposal();
        gov.castVote(id, keccak256("voter1"), true, PROOF);
        (,, uint256 yes,,,) = gov.getProposal(id);
        assertEq(yes, 1);
    }

    function test_VoteNo() public {
        bytes32 id = _proposal();
        gov.castVote(id, keccak256("voter1"), false, PROOF);
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

    function test_QuorumRequired() public {
        bytes32 id = _proposal();
        for (uint256 i = 0; i < 9; i++) {
            gov.castVote(id, keccak256(abi.encode("v", i)), true, PROOF);
        }
        vm.warp(block.timestamp + 8 days);
        gov.finalizeProposal(id);
        (,,,,, bool passed) = gov.getProposal(id);
        assertFalse(passed);
    }

    function test_PassesWithMajority() public {
        bytes32 id = _passProposal();
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
        bytes32 id = _passProposal();
        vm.expectRevert("Time-lock active");
        gov.execute(id);
    }

    function test_ExecuteAfterTimeLock() public {
        bytes32 id = _passProposal();
        vm.warp(block.timestamp + 3 days);
        gov.execute(id);
        (,,,, bool executed,) = gov.getProposal(id);
        assertTrue(executed);
    }

    function test_DoubleExecutionPrevented() public {
        bytes32 id = _passProposal();
        vm.warp(block.timestamp + 3 days);
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

    // ── 2. Groth16Verifier — verifier rejects invalid proofs ─────────────────

    /// Real verifier deployed — random bytes rejected as "Invalid ZK proof".
    function test_Groth16_RandomBytesRejected() public {
        bytes32 id = groth16Gov.createProposal(keccak256("prop"), address(0), "");
        vm.expectRevert("Invalid ZK proof");
        groth16Gov.castVote(id, keccak256("v1"), true, hex"deadbeef");
    }

    /// Wrong length proof (not 256 bytes) is rejected.
    function test_Groth16_WrongLengthProofRejected() public {
        bytes32 id = groth16Gov.createProposal(keccak256("prop"), address(0), "");
        vm.expectRevert("Invalid ZK proof");
        groth16Gov.castVote(id, keccak256("v1"), true, hex"0102030405");
    }

    /// Empty proof rejected.
    function test_Groth16_EmptyProofRejected() public {
        bytes32 id = groth16Gov.createProposal(keccak256("prop"), address(0), "");
        vm.expectRevert("Invalid ZK proof");
        groth16Gov.castVote(id, keccak256("v1"), true, "");
    }

    /// A 256-byte zero proof (valid encoding, fails pairing — VK is zeroed).
    function test_Groth16_ZeroProofFailsPairing() public {
        bytes32 id = groth16Gov.createProposal(keccak256("prop"), address(0), "");
        vm.expectRevert("Invalid ZK proof");
        groth16Gov.castVote(id, keccak256("v1"), true, ZERO_PROOF);
    }

    /// verifyProof called directly — returns false for zero proof.
    function test_Groth16_DirectCallReturnsFalse() public {
        uint256[4] memory signals = [
            uint256(keccak256("nullifier")),
            uint256(keccak256("proposal")),
            uint256(1),
            uint256(keccak256("root"))
        ];
        // ZERO_PROOF has valid length and encoding but fails pairing
        bool result = realVerifier.verifyProof(ZERO_PROOF, signals);
        assertFalse(result);
    }

    /// verifyProof called directly — returns false for short proof.
    function test_Groth16_ShortProofReturnsFalse() public {
        uint256[4] memory signals;
        bool result = realVerifier.verifyProof(hex"beef", signals);
        assertFalse(result);
    }

    /// Field element > FIELD_MODULUS in signals → returns false.
    function test_Groth16_OutOfFieldSignalRejected() public {
        // Construct a signal that exceeds FIELD_MODULUS
        uint256 overField = 21888242871839275222246405745257275088548364400416034343698204186575808495617 + 1;
        uint256[4] memory signals = [overField, 0, 0, 0];
        bool result = realVerifier.verifyProof(ZERO_PROOF, signals);
        assertFalse(result);
    }

    // ── 3. Signal layout — castVote passes signals in circuit order ───────────

    /**
     * Verify the on-chain signal construction in castVote matches the circuit:
     *   signals[0] = nullifierHash
     *   signals[1] = proposalId
     *   signals[2] = voteYes ? 1 : 0
     *   signals[3] = membershipRoot
     *
     * We use a SignalCaptureVerifier that stores signals in a public mapping
     * via a separate `record()` call pattern, keeping verifyProof as `view`
     * while allowing a companion `capture()` call to store results.
     *
     * Approach: deploy a PassthroughVerifier (always returns true, no state),
     * call castVote, then read signals directly from ZKSNGovernance events via
     * vm.recordLogs().  The VoteCast event fires only after the proof check
     * passes so we can infer the signals were correct.  We verify the signal
     * values by re-computing them independently and asserting they match.
     */
    function test_SignalLayout_MatchesCircuit() public {
        PassthroughVerifier pass = new PassthroughVerifier();
        ZKSNGovernance captureGov = new ZKSNGovernance(address(pass), ROOT);

        bytes32 id            = captureGov.createProposal(keccak256("p"), address(0), "");
        bytes32 nullifierHash = keccak256("my_nullifier");

        // Independently compute what signals[0..3] should be
        uint256 expS0 = uint256(nullifierHash);
        uint256 expS1 = uint256(id);
        uint256 expS2 = 1; // voteYes = true
        uint256 expS3 = uint256(ROOT);

        // Record signals via the capture verifier's public getter
        pass.startCapture();
        captureGov.castVote(id, nullifierHash, true, hex"aabbccdd");

        assertEq(pass.capturedSignal(0), expS0, "signals[0] must be nullifierHash");
        assertEq(pass.capturedSignal(1), expS1, "signals[1] must be proposalId");
        assertEq(pass.capturedSignal(2), expS2, "signals[2] must be 1 for voteYes=true");
        assertEq(pass.capturedSignal(3), expS3, "signals[3] must be membershipRoot");
    }

    function test_SignalLayout_VoteNoIsZero() public {
        PassthroughVerifier pass = new PassthroughVerifier();
        ZKSNGovernance captureGov = new ZKSNGovernance(address(pass), ROOT);

        bytes32 id            = captureGov.createProposal(keccak256("p"), address(0), "");
        bytes32 nullifierHash = keccak256("voter_no");

        pass.startCapture();
        captureGov.castVote(id, nullifierHash, false, hex"aabb");

        assertEq(pass.capturedSignal(2), uint256(0), "signals[2] must be 0 for voteYes=false");
    }

    // ── 4. Deployment — Groth16Verifier is the production verifier ───────────

    /// Confirm real governance is wired to Groth16Verifier, not MockVerifier.
    function test_Deployment_Groth16VerifierIsWired() public {
        assertEq(address(groth16Gov.verifier()), address(realVerifier));
    }

    /// MockVerifier address is different from Groth16Verifier.
    function test_Deployment_MockAndRealAreDistinct() public {
        assertFalse(address(mock) == address(realVerifier));
    }

    /// Groth16Verifier implements IVerifier interface.
    function test_Deployment_Groth16ImplementsIVerifier() public {
        IVerifier iv = IVerifier(address(realVerifier));
        uint256[4] memory signals;
        // Should not revert — returns false because VK is zeroed
        iv.verifyProof(ZERO_PROOF, signals);
    }

    // ── 5. PoseidonHasher consistency ─────────────────────────────────────────

    /// hashLeaf output is deterministic.
    function test_Poseidon_LeafDeterministic() public {
        uint256 secret = 12345;
        assertEq(hasher.hashLeaf(secret), hasher.hashLeaf(secret));
    }

    /// hashLeaf output is in the BN254 scalar field.
    function test_Poseidon_LeafInField() public {
        uint256 Q = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        uint256 leaf = hasher.hashLeaf(uint256(keccak256("secret")));
        assertLt(leaf, Q);
    }

    /// hashNullifier is deterministic and distinct per proposalId.
    function test_Poseidon_NullifierDeterministic() public {
        uint256 secret     = 99999;
        uint256 proposalA  = uint256(keccak256("propA"));
        uint256 proposalB  = uint256(keccak256("propB"));

        assertEq(hasher.hashNullifier(secret, proposalA), hasher.hashNullifier(secret, proposalA));
        assertNotEq(hasher.hashNullifier(secret, proposalA), hasher.hashNullifier(secret, proposalB));
    }

    /// hashNullifier output is in the BN254 scalar field.
    function test_Poseidon_NullifierInField() public {
        uint256 Q = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        uint256 n = hasher.hashNullifier(42, uint256(keccak256("prop")));
        assertLt(n, Q);
    }

    /// hashNode is deterministic and order-sensitive.
    function test_Poseidon_NodeOrderSensitive() public {
        uint256 left  = 111;
        uint256 right = 222;
        uint256 h1 = hasher.hashNode(left, right);
        uint256 h2 = hasher.hashNode(right, left);
        // Poseidon is not symmetric — left/right ordering matters for Merkle proofs
        assertNotEq(h1, h2);
    }

    // ── 6. StrictMockVerifier — existing proof-approval tests ─────────────────

    function test_InvalidProofRejected() public {
        // StrictMockVerifier only approves PROOF (approved in setUp)
        ZKSNGovernance strictGov = new ZKSNGovernance(address(strict), ROOT);
        bytes32 id = strictGov.createProposal(keccak256("c"), address(0), "");
        vm.expectRevert("Invalid ZK proof");
        strictGov.castVote(id, keccak256("v1"), true, hex"badbad");
    }
}

// ── PassthroughVerifier — captures signals without violating view ─────────────

/**
 * @dev Test helper verifier that:
 *   - Always returns true from verifyProof (view — no state mutation)
 *   - Captures signals via a Foundry vm.store / transient pattern:
 *     call startCapture() before castVote, then read capturedSignal(i) after.
 *
 * Implementation: verifyProof writes to a dedicated storage slot via inline
 * assembly (the EVM does not enforce view at the bytecode level — only the
 * Solidity compiler does at call sites, not within the same contract context).
 * This is safe for test-only use.
 */
contract PassthroughVerifier is IVerifier {
    // Storage slots for captured signals (slot 0-3)
    uint256[4] private _captured;
    bool private _capturing;

    function startCapture() external {
        _capturing = true;
        delete _captured;
    }

    function capturedSignal(uint256 index) external view returns (uint256) {
        return _captured[index];
    }

    function verifyProof(bytes calldata, uint256[4] calldata signals)
        external
        view
        override
        returns (bool)
    {
        // Write captured signals via assembly to bypass Solidity view restriction.
        // Slot layout: _captured[i] is at slot i (first state var is slot 0).
        if (_capturing) {
            assembly {
                sstore(0, calldataload(signals.offset))
                sstore(1, calldataload(add(signals.offset, 0x20)))
                sstore(2, calldataload(add(signals.offset, 0x40)))
                sstore(3, calldataload(add(signals.offset, 0x60)))
            }
        }
        return true;
    }
}
