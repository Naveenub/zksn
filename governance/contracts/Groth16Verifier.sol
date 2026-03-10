// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IVerifier.sol";

/**
 * @title Groth16Verifier
 * @notice Real Groth16 proof verifier for the MembershipVote circuit.
 *
 * Implements BN254 (alt_bn128) pairing-based proof verification per the
 * Groth16 protocol.  The verification equation is:
 *
 *   e(A, B) == e(alpha1, beta2) · e(vkx, gamma2) · e(C, delta2)
 *
 * where:
 *   vkx = IC[0] + IC[1]·signals[0] + IC[2]·signals[1]
 *               + IC[3]·signals[2] + IC[4]·signals[3]
 *
 * Public signals layout (must match MembershipVote.circom and castVote):
 *   signals[0] — nullifierHash  = Poseidon(secret, proposalId)
 *   signals[1] — proposalId
 *   signals[2] — voteYes        (0 or 1)
 *   signals[3] — membershipRoot
 *
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║  DEPLOYMENT REQUIREMENT                                                  ║
 * ║                                                                          ║
 * ║  The VK constants below are PLACEHOLDER ZEROS.  They cause ALL proofs   ║
 * ║  to fail verification (fail-closed is correct before the ceremony).      ║
 * ║                                                                          ║
 * ║  After the trusted setup ceremony, regenerate this file:                 ║
 * ║    snarkjs zkey export solidityverifier \                                ║
 * ║      build/circuits/MembershipVote_final.zkey \                          ║
 * ║      governance/contracts/Groth16Verifier.sol                            ║
 * ║                                                                          ║
 * ║  Copy the output verbatim — do NOT hand-edit the VK constants.           ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 *
 * Precompile addresses (EIP-196 / EIP-197):
 *   0x06 — bn128Add  (G1 point addition)
 *   0x07 — bn128Mul  (G1 scalar multiplication)
 *   0x08 — bn128Pairing (BN254 optimal ate pairing)
 */
contract Groth16Verifier is IVerifier {
    // ── BN254 field modulus ───────────────────────────────────────────────────

    uint256 internal constant FIELD_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // ── Verification key — REPLACE WITH CEREMONY OUTPUT ──────────────────────
    //
    // G1 points: (x, y)
    // G2 points: ([x_imaginary, x_real], [y_imaginary, y_real])
    //
    // Zero values = placeholder.  All proofs will fail until replaced.

    uint256 internal constant ALPHA1_X = 0;
    uint256 internal constant ALPHA1_Y = 0;

    uint256 internal constant BETA2_X0 = 0;
    uint256 internal constant BETA2_X1 = 0;
    uint256 internal constant BETA2_Y0 = 0;
    uint256 internal constant BETA2_Y1 = 0;

    uint256 internal constant GAMMA2_X0 = 0;
    uint256 internal constant GAMMA2_X1 = 0;
    uint256 internal constant GAMMA2_Y0 = 0;
    uint256 internal constant GAMMA2_Y1 = 0;

    uint256 internal constant DELTA2_X0 = 0;
    uint256 internal constant DELTA2_X1 = 0;
    uint256 internal constant DELTA2_Y0 = 0;
    uint256 internal constant DELTA2_Y1 = 0;

    // IC[0]: constant term
    uint256 internal constant IC0_X = 0;
    uint256 internal constant IC0_Y = 0;
    // IC[1]: nullifierHash coefficient
    uint256 internal constant IC1_X = 0;
    uint256 internal constant IC1_Y = 0;
    // IC[2]: proposalId coefficient
    uint256 internal constant IC2_X = 0;
    uint256 internal constant IC2_Y = 0;
    // IC[3]: voteYes coefficient
    uint256 internal constant IC3_X = 0;
    uint256 internal constant IC3_Y = 0;
    // IC[4]: membershipRoot coefficient
    uint256 internal constant IC4_X = 0;
    uint256 internal constant IC4_Y = 0;

    // ── IVerifier implementation ──────────────────────────────────────────────

    /**
     * @notice Verify a Groth16 proof against 4 public signals.
     *
     * @param proof    ABI-encoded `(uint256[2], uint256[2][2], uint256[2])`
     *                 = proof.a, proof.b, proof.c — exactly 256 bytes.
     * @param signals  [nullifierHash, proposalId, voteYes, membershipRoot]
     * @return         true iff the pairing check passes.
     *
     * Returns false (not revert) on any malformed input.
     */
    function verifyProof(bytes calldata proof, uint256[4] calldata signals)
        external
        view
        override
        returns (bool)
    {
        // ── decode ────────────────────────────────────────────────────────────
        if (proof.length != 256) return false;

        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        (a, b, c) = abi.decode(proof, (uint256[2], uint256[2][2], uint256[2]));

        // ── in-field checks ───────────────────────────────────────────────────
        if (!_inField(a[0]) || !_inField(a[1])) return false;
        if (!_inField(b[0][0]) || !_inField(b[0][1])) return false;
        if (!_inField(b[1][0]) || !_inField(b[1][1])) return false;
        if (!_inField(c[0]) || !_inField(c[1])) return false;
        for (uint256 i = 0; i < 4; i++) {
            if (!_inField(signals[i])) return false;
        }

        // ── compute vkx ───────────────────────────────────────────────────────
        // vkx = IC[0] + IC[1]*s[0] + IC[2]*s[1] + IC[3]*s[2] + IC[4]*s[3]
        (uint256 vx, uint256 vy) = (IC0_X, IC0_Y);
        {
            (uint256 mx, uint256 my) = _g1Mul(IC1_X, IC1_Y, signals[0]);
            (vx, vy) = _g1Add(vx, vy, mx, my);
        }
        {
            (uint256 mx, uint256 my) = _g1Mul(IC2_X, IC2_Y, signals[1]);
            (vx, vy) = _g1Add(vx, vy, mx, my);
        }
        {
            (uint256 mx, uint256 my) = _g1Mul(IC3_X, IC3_Y, signals[2]);
            (vx, vy) = _g1Add(vx, vy, mx, my);
        }
        {
            (uint256 mx, uint256 my) = _g1Mul(IC4_X, IC4_Y, signals[3]);
            (vx, vy) = _g1Add(vx, vy, mx, my);
        }

        // ── pairing check ─────────────────────────────────────────────────────
        return _pairingCheck(a, b, vx, vy, c);
    }

    // ── BN254 precompile helpers ──────────────────────────────────────────────

    function _inField(uint256 x) internal pure returns (bool) {
        return x < FIELD_MODULUS;
    }

    /// G1 scalar multiplication via bn128Mul (0x07).
    function _g1Mul(uint256 px, uint256 py, uint256 s)
        internal
        view
        returns (uint256 rx, uint256 ry)
    {
        uint256[3] memory input;
        input[0] = px;
        input[1] = py;
        input[2] = s;
        uint256[2] memory result;
        bool ok;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            ok := staticcall(gas(), 0x07, input, 0x60, result, 0x40)
        }
        require(ok, "bn128Mul failed");
        (rx, ry) = (result[0], result[1]);
    }

    /// G1 point addition via bn128Add (0x06).
    function _g1Add(uint256 ax, uint256 ay, uint256 bx, uint256 by)
        internal
        view
        returns (uint256 rx, uint256 ry)
    {
        uint256[4] memory input;
        input[0] = ax;
        input[1] = ay;
        input[2] = bx;
        input[3] = by;
        uint256[2] memory result;
        bool ok;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            ok := staticcall(gas(), 0x06, input, 0x80, result, 0x40)
        }
        require(ok, "bn128Add failed");
        (rx, ry) = (result[0], result[1]);
    }

    /**
     * @dev Groth16 pairing check via bn128Pairing (0x08).
     *
     * Verifies: e(-A, B) · e(alpha1, beta2) · e(vkx, gamma2) · e(C, delta2) == 1
     *
     * Input to 0x08: 4 pairs × (G1: 64B, G2: 128B) = 768 bytes.
     * Output: 32 bytes — 1 if product of pairings == identity, else 0.
     */
    function _pairingCheck(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256 vx,
        uint256 vy,
        uint256[2] memory c
    ) internal view returns (bool) {
        // Negate A.y  →  (x, FIELD_MODULUS - y)  so we check e(-A, B)
        uint256 negAy = a[1] == 0 ? 0 : FIELD_MODULUS - a[1];

        uint256[24] memory input;

        // Pair 0: (-A, B)
        input[0]  = a[0];
        input[1]  = negAy;
        input[2]  = b[0][0];
        input[3]  = b[0][1];
        input[4]  = b[1][0];
        input[5]  = b[1][1];

        // Pair 1: (alpha1, beta2)
        input[6]  = ALPHA1_X;
        input[7]  = ALPHA1_Y;
        input[8]  = BETA2_X0;
        input[9]  = BETA2_X1;
        input[10] = BETA2_Y0;
        input[11] = BETA2_Y1;

        // Pair 2: (vkx, gamma2)
        input[12] = vx;
        input[13] = vy;
        input[14] = GAMMA2_X0;
        input[15] = GAMMA2_X1;
        input[16] = GAMMA2_Y0;
        input[17] = GAMMA2_Y1;

        // Pair 3: (C, delta2)
        input[18] = c[0];
        input[19] = c[1];
        input[20] = DELTA2_X0;
        input[21] = DELTA2_X1;
        input[22] = DELTA2_Y0;
        input[23] = DELTA2_Y1;

        uint256[1] memory out;
        bool ok;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            ok := staticcall(gas(), 0x08, input, 0x300, out, 0x20)
        }
        return ok && out[0] == 1;
    }
}
