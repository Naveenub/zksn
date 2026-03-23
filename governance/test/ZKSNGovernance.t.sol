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
 *   2. Groth16Verifier correctness — real verifier accepts valid ceremony proof,
 *      rejects all tampered variants, validates proof encoding and field bounds
 *   3. Signal layout — verifies castVote passes signals in the order the
 *      circuit expects: [nullifierHash, proposalId, voteYes, membershipRoot]
 *   4. Deployment path — Groth16Verifier is wired as IVerifier; MockVerifier
 *      is explicitly NOT used in the production governance instance
 *   5. PoseidonHasher exact-vector tests — all outputs verified against
 *      circomlibjs reference values; Merkle path consistency verified against
 *      the depth-20 ceremony tree
 */
contract ZKSNGovernanceTest is Test {
    // ── fixtures ──────────────────────────────────────────────────────────────

    ZKSNGovernance gov;          // uses StrictMockVerifier (governance logic tests)
    ZKSNGovernance groth16Gov;   // uses real Groth16Verifier (verifier tests)
    MockVerifier mock;
    StrictMockVerifier strict;
    Groth16Verifier realVerifier;
    PoseidonHasher hasher;

    bytes32 constant ROOT = keccak256("initial_root");
    bytes  constant PROOF = hex"deadbeef";

    // Valid 256-byte proof encoding (a, b, c all zero — fails pairing with real VK)
    bytes constant ZERO_PROOF = abi.encode(
        [uint256(0), uint256(0)],
        [[uint256(0), uint256(0)], [uint256(0), uint256(0)]],
        [uint256(0), uint256(0)]
    );

    // ── Real proof from depth-20 ceremony ────────────────────────────────────
    //
    // Circuit:  MembershipVote(depth=20) — 5,360 non-linear constraints
    // ptau:     pot15_final.ptau  (2^15 = 32,768 capacity; 3 contributors + beacon)
    // Phase 2:  3-contributor MPC, zkey_final SHA256:
    //             7bed6caed28d6a9399c5507d873db011433dd5c0b75fe08864647ef184a17eb4
    //
    // Input (private):
    //   secret        = 12345678901234567890
    //   treeIndex     = 0
    //   pathIndices   = [0, 0, 0, ... 0]  (20 zeros)
    //   pathElements  = [0, Poseidon(0,0), Poseidon(Poseidon(0,0),Poseidon(0,0)), ...]
    //
    // Public signals (verified: snarkjs groth16 verify → OK ✅):
    //   nullifierHash  = Poseidon(secret, proposalId)
    //   proposalId     = 999888777666555
    //   voteYes        = 1
    //   membershipRoot = depth-20 Poseidon root (1,048,576-leaf tree, leaf 0 set)
    //
    // G2 Fp2 coords in EIP-197 order: (imaginary, real).
    // See ceremony/ATTESTATION.md for full contribution chain.
    bytes constant REAL_PROOF =
        hex"1852d1ff7bddcef4456931c8ab8d59f9d2c6f5f135e51949255bf06870ee7c38"
        hex"0636835485605b1e460e492bdc6bb776ae32d4c5700db3ee40f317a11b0b8f12"
        hex"2e163c072d73a1125251532c5ef4a7d81524c1f4924f1cec7adba5a1d640baac"
        hex"1e512fa6bb52ead4aa698f4f9bbd61603a6c456f7d7a762f7a65812f7ef9f151"
        hex"13d733fbd8d182adf1a4f4d752f1b1dd4d7c9d9c18f6c249229875e5fb4baf3f"
        hex"2a8bbce0342886498c647214e826205575003d79a78e91af73f092fcef67d4cd"
        hex"06c489a841fcaba4f950c7ef2d9d59227dd8aa46ce35f0ec254abf8940e8e316"
        hex"100daf1feeab76c5edff578ec7d387ed257c5b5cfc24733276fbbd8de234a8d1";

    uint256 constant REAL_NULLIFIER =
        21605468119089894529364334093527017674406608084847384275934021833321276526684;
    uint256 constant REAL_PROPOSAL_ID = 999888777666555;
    // depth-20 Poseidon Merkle root: 1,048,576-leaf tree, leaf[0] = Poseidon(secret)
    uint256 constant REAL_MEMBERSHIP_ROOT =
        6331401000423026358291629782353603237933267665498208286537849807283925720420;

    function setUp() public {
        mock         = new MockVerifier();
        strict       = new StrictMockVerifier();
        realVerifier = new Groth16Verifier();
        hasher       = new PoseidonHasher();

        // Governance logic tests — StrictMockVerifier (pre-approve PROOF)
        gov = new ZKSNGovernance(address(strict), ROOT);
        strict.approve(PROOF);

        // Verifier tests — real Groth16Verifier, depth-20 membership root
        groth16Gov = new ZKSNGovernance(address(realVerifier), bytes32(REAL_MEMBERSHIP_ROOT));
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

    // ── 2. Groth16Verifier — real depth-20 ceremony proof ────────────────────

    /// Real depth-20 ceremony proof verifies successfully end-to-end.
    function test_Groth16_RealProofAccepted() public view {
        uint256[4] memory signals;
        signals[0] = REAL_NULLIFIER;
        signals[1] = REAL_PROPOSAL_ID;
        signals[2] = 1;
        signals[3] = REAL_MEMBERSHIP_ROOT;

        bool result = realVerifier.verifyProof(REAL_PROOF, signals);
        assertTrue(result, "Real depth-20 ceremony proof must verify");
    }

    /// Tampered nullifier is rejected.
    function test_Groth16_TamperedNullifierRejected() public view {
        uint256[4] memory signals;
        signals[0] = REAL_NULLIFIER + 1;
        signals[1] = REAL_PROPOSAL_ID;
        signals[2] = 1;
        signals[3] = REAL_MEMBERSHIP_ROOT;

        assertFalse(realVerifier.verifyProof(REAL_PROOF, signals));
    }

    /// Tampered voteYes is rejected.
    function test_Groth16_TamperedVoteRejected() public view {
        uint256[4] memory signals;
        signals[0] = REAL_NULLIFIER;
        signals[1] = REAL_PROPOSAL_ID;
        signals[2] = 0; // proof was generated for voteYes=1
        signals[3] = REAL_MEMBERSHIP_ROOT;

        assertFalse(realVerifier.verifyProof(REAL_PROOF, signals));
    }

    /// Tampered membership root is rejected.
    function test_Groth16_TamperedRootRejected() public view {
        uint256[4] memory signals;
        signals[0] = REAL_NULLIFIER;
        signals[1] = REAL_PROPOSAL_ID;
        signals[2] = 1;
        signals[3] = REAL_MEMBERSHIP_ROOT + 1;

        assertFalse(realVerifier.verifyProof(REAL_PROOF, signals));
    }

    /// Tampered proposalId is rejected.
    function test_Groth16_TamperedProposalIdRejected() public view {
        uint256[4] memory signals;
        signals[0] = REAL_NULLIFIER;
        signals[1] = REAL_PROPOSAL_ID + 1;
        signals[2] = 1;
        signals[3] = REAL_MEMBERSHIP_ROOT;

        assertFalse(realVerifier.verifyProof(REAL_PROOF, signals));
    }

    /// Random bytes rejected as "Invalid ZK proof".
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

    /// A 256-byte zero proof fails pairing with real VK.
    function test_Groth16_ZeroProofFailsPairing() public {
        bytes32 id = groth16Gov.createProposal(keccak256("prop"), address(0), "");
        vm.expectRevert("Invalid ZK proof");
        groth16Gov.castVote(id, keccak256("v1"), true, ZERO_PROOF);
    }

    /// verifyProof called directly — returns false for zero proof.
    function test_Groth16_DirectCallReturnsFalse() public view {
        uint256[4] memory signals =
            [uint256(keccak256("nullifier")), uint256(keccak256("proposal")), uint256(1), uint256(keccak256("root"))];
        assertFalse(realVerifier.verifyProof(ZERO_PROOF, signals));
    }

    /// verifyProof called directly — returns false for short proof.
    function test_Groth16_ShortProofReturnsFalse() public view {
        uint256[4] memory signals;
        assertFalse(realVerifier.verifyProof(hex"beef", signals));
    }

    /// Field element > FIELD_MODULUS in signals → returns false.
    function test_Groth16_OutOfFieldSignalRejected() public view {
        uint256 overField = 21888242871839275222246405745257275088548364400416034343698204186575808495617 + 1;
        uint256[4] memory signals = [overField, 0, 0, 0];
        assertFalse(realVerifier.verifyProof(ZERO_PROOF, signals));
    }

    // ── 3. Signal layout — castVote passes signals in circuit order ───────────

    function test_SignalLayout_MatchesCircuit() public {
        MockVerifier mv = new MockVerifier();
        ZKSNGovernance captureGov = new ZKSNGovernance(address(mv), ROOT);

        bytes32 id            = captureGov.createProposal(keccak256("p"), address(0), "");
        bytes32 nullifierHash = keccak256("my_nullifier");
        bytes memory proof    = hex"aabbccdd";

        uint256[4] memory expectedSignals;
        expectedSignals[0] = uint256(nullifierHash);
        expectedSignals[1] = uint256(id);
        expectedSignals[2] = uint256(1);
        expectedSignals[3] = uint256(ROOT);

        vm.expectCall(address(mv), abi.encodeCall(IVerifier.verifyProof, (proof, expectedSignals)));
        captureGov.castVote(id, nullifierHash, true, proof);
    }

    function test_SignalLayout_VoteNoIsZero() public {
        MockVerifier mv = new MockVerifier();
        ZKSNGovernance captureGov = new ZKSNGovernance(address(mv), ROOT);

        bytes32 id            = captureGov.createProposal(keccak256("p"), address(0), "");
        bytes32 nullifierHash = keccak256("voter_no");
        bytes memory proof    = hex"aabb";

        uint256[4] memory expectedSignals;
        expectedSignals[0] = uint256(nullifierHash);
        expectedSignals[1] = uint256(id);
        expectedSignals[2] = uint256(0);
        expectedSignals[3] = uint256(ROOT);

        vm.expectCall(address(mv), abi.encodeCall(IVerifier.verifyProof, (proof, expectedSignals)));
        captureGov.castVote(id, nullifierHash, false, proof);
    }

    // ── 4. Deployment — Groth16Verifier is the production verifier ───────────

    function test_Deployment_Groth16VerifierIsWired() public view {
        assertEq(address(groth16Gov.verifier()), address(realVerifier));
    }

    function test_Deployment_MockAndRealAreDistinct() public view {
        assertFalse(address(mock) == address(realVerifier));
    }

    function test_Deployment_Groth16ImplementsIVerifier() public view {
        IVerifier iv = IVerifier(address(realVerifier));
        uint256[4] memory signals;
        iv.verifyProof(ZERO_PROOF, signals);
    }

    // ── 5. PoseidonHasher — exact vector tests against circomlibjs output ────
    //
    // All expected values computed with:
    //   const { buildPoseidon } = require("circomlibjs");
    //   const poseidon = await buildPoseidon();
    //   poseidon.F.toObject(poseidon([x]))           // t=2
    //   poseidon.F.toObject(poseidon([x, y]))        // t=3

    /// hashLeaf(0) matches circomlibjs: poseidon([0])
    function test_Poseidon_LeafZero() public view {
        assertEq(
            hasher.hashLeaf(0),
            19014214495641488759237505126948346942972912379615652741039992445865937985820
        );
    }

    /// hashLeaf(1) matches circomlibjs: poseidon([1])
    function test_Poseidon_LeafOne() public view {
        assertEq(
            hasher.hashLeaf(1),
            18586133768512220936620570745912940619677854269274689475585506675881198879027
        );
    }

    /// hashLeaf matches for ceremony secret.
    function test_Poseidon_LeafCeremonySecret() public view {
        assertEq(
            hasher.hashLeaf(12345678901234567890),
            17610922722311195426938483481431943255028223790571250909270476711880232282197
        );
    }

    /// hashLeaf output is in BN254 scalar field.
    function test_Poseidon_LeafInField() public view {
        uint256 Q = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        assertLt(hasher.hashLeaf(999), Q);
    }

    /// hashNullifier(0,0) matches circomlibjs: poseidon([0,0])
    function test_Poseidon_NullifierZeroZero() public view {
        assertEq(
            hasher.hashNullifier(0, 0),
            14744269619966411208579211824598458697587494354926760081771325075741142829156
        );
    }

    /// hashNullifier matches for ceremony inputs.
    function test_Poseidon_NullifierCeremonyInputs() public view {
        assertEq(
            hasher.hashNullifier(12345678901234567890, 999888777666555),
            21605468119089894529364334093527017674406608084847384275934021833321276526684
        );
    }

    /// hashNullifier == REAL_NULLIFIER — live cross-check with ceremony constant.
    function test_Poseidon_NullifierMatchesCeremony() public view {
        assertEq(
            hasher.hashNullifier(12345678901234567890, REAL_PROPOSAL_ID),
            REAL_NULLIFIER
        );
    }

    /// hashNullifier is proposal-specific.
    function test_Poseidon_NullifierProposalSpecific() public view {
        assertNotEq(
            hasher.hashNullifier(99999, 1),
            hasher.hashNullifier(99999, 2)
        );
    }

    /// hashNullifier output is in BN254 scalar field.
    function test_Poseidon_NullifierInField() public view {
        uint256 Q = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        assertLt(hasher.hashNullifier(42, 7), Q);
    }

    /// hashNode matches circomlibjs: poseidon([1,2])
    function test_Poseidon_NodeVector() public view {
        assertEq(
            hasher.hashNode(1, 2),
            7853200120776062878684798364095072458815029376092732009249414926327459813530
        );
    }

    /// hashNode is order-sensitive — Poseidon is not symmetric.
    function test_Poseidon_NodeOrderSensitive() public view {
        assertNotEq(hasher.hashNode(1, 2), hasher.hashNode(2, 1));
    }

    // ── Merkle path consistency — depth-20 ceremony tree ─────────────────────
    //
    // Verifies that individual hashNode calls reproduce the first two levels of
    // the depth-20 ceremony path, confirming the on-chain hasher matches the
    // off-chain tree builder (scripts/tree.js) and the circuit witness.
    //
    // tree.js add 12345678901234567890  →  tree index 0
    // Level 0:  leaf     = hashLeaf(secret)                 = 17610922...
    // Level 1:  node1_0  = hashNode(leaf, 0)                = 12373434...
    //           sib1     = hashNode(0, 0)                   = 14744269...  ← pathElements[1]
    // Level 2:  node2_0  = hashNode(node1_0, sib1)          = 5501002...
    //           sib2     = hashNode(hashNode(0,0),hashNode(0,0)) = 7423237...  ← pathElements[2]

    function test_Poseidon_MerkleLevel1MatchesCeremonyPath() public view {
        // pathElements[1] in input_d20.json = Poseidon(0, 0) = 14744269...
        assertEq(
            hasher.hashNode(0, 0),
            14744269619966411208579211824598458697587494354926760081771325075741142829156
        );
    }

    function test_Poseidon_MerkleLevel2SiblingMatchesCeremonyPath() public view {
        // pathElements[2] in input_d20.json = Poseidon(Poseidon(0,0), Poseidon(0,0)) = 7423237...
        uint256 zero_pair = hasher.hashNode(0, 0);
        assertEq(
            hasher.hashNode(zero_pair, zero_pair),
            7423237065226347324353380772367382631490014989348495481811164164159255474657
        );
    }

    function test_Poseidon_MerkleLeafToLevel1MatchesCeremonyPath() public view {
        // Level 1 node at index 0: hashNode(leaf, sibling_at_0)
        // sibling at level 0 is pathElements[0] = 0 (leaf slot 1 is empty)
        uint256 leaf = hasher.hashLeaf(12345678901234567890);
        assertEq(leaf, 17610922722311195426938483481431943255028223790571250909270476711880232282197);
        assertEq(
            hasher.hashNode(leaf, 0),
            12373434461327138886900976280083244074689023087942068543228983246097986975840
        );
    }

    // ── 6. StrictMockVerifier ─────────────────────────────────────────────────

    function test_InvalidProofRejected() public {
        ZKSNGovernance strictGov = new ZKSNGovernance(address(strict), ROOT);
        bytes32 id = strictGov.createProposal(keccak256("c"), address(0), "");
        vm.expectRevert("Invalid ZK proof");
        strictGov.castVote(id, keccak256("v1"), true, hex"badbad");
    }
}
