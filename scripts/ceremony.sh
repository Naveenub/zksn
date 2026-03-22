#!/usr/bin/env bash
# scripts/ceremony.sh — ZKSN Groth16 multi-party trusted setup
#
# Usage:
#   Coordinator:   bash scripts/ceremony.sh init
#   Contributor N: bash scripts/ceremony.sh contribute <n> <input.zkey> <output.zkey>
#   Coordinator:   bash scripts/ceremony.sh finalize [n_contributors]
#   Anyone:        bash scripts/ceremony.sh verify
#
# Mainnet upgrade path (replace pot15 with Hermez pot28):
#   wget https://hermez.s3-eu-west-1.amazonaws.com/powersoftau28_hez_final.ptau \
#        -O ceremony/pot28_final.ptau
#   Edit PTAU below, then re-run this script — everything else is identical.

set -euo pipefail

CIRCUIT_R1CS="build/MembershipVote.r1cs"
CIRCUIT_WASM="build/MembershipVote_js/MembershipVote.wasm"
PTAU="ceremony/pot15_final.ptau"       # swap for pot28 on mainnet
CEREMONY_DIR="ceremony"
SNARKJS="npx snarkjs"

# ── Beacon ────────────────────────────────────────────────────────────────────
# Dev beacon (deterministic). Replace before mainnet with a future block hash:
#   BEACON=$(cast block --rpc-url https://eth.llamarpc.com latest | grep hash | awk '{print $2}' | sed 's/0x//')
BEACON="0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
BEACON_ITERATIONS=10

# ─────────────────────────────────────────────────────────────────────────────

init() {
    echo "=== ZKSN Phase 2 — Init (depth-20) ==="
    mkdir -p "$CEREMONY_DIR"

    if [[ ! -f "$CIRCUIT_R1CS" ]]; then
        echo "Compiling circuit (depth=20)..."
        npx circom2 circuits/MembershipVote.circom \
            --r1cs --wasm --sym \
            -l node_modules \
            -o build/
        echo "Compiled: $(du -h build/MembershipVote.r1cs | cut -f1) r1cs"
    fi

    echo "Phase 2 setup against $PTAU..."
    $SNARKJS groth16 setup \
        "$CIRCUIT_R1CS" \
        "$PTAU" \
        "$CEREMONY_DIR/zkey_0000.zkey"

    echo ""
    echo "✅ Phase 2 initialised: $CEREMONY_DIR/zkey_0000.zkey"
    echo "   → Send zkey_0000.zkey to Contributor 1"
    echo "   → Each contributor runs: bash scripts/ceremony.sh contribute <n> <in.zkey> <out.zkey>"
}

contribute() {
    local N="$1"
    local INPUT="$2"
    local OUTPUT="$3"

    echo "=== ZKSN Phase 2 — Contributor $N ==="
    echo "Input:  $INPUT"
    echo "Output: $OUTPUT"
    echo ""

    local ENTROPY
    read -rsp "Enter additional entropy (any text, not stored): " USER_ENTROPY
    echo ""
    ENTROPY="zksn_contrib${N}_$(openssl rand -hex 32)_${USER_ENTROPY}_$(date +%s%N)"
    unset USER_ENTROPY

    $SNARKJS zkey contribute \
        "$INPUT" \
        "$OUTPUT" \
        --name="ZKSN Contributor $N — Anonymous" \
        -e="$ENTROPY"

    unset ENTROPY

    local HASH
    HASH=$(sha256sum "$OUTPUT" | awk '{print $1}')
    echo ""
    echo "✅ Contribution $N complete"
    echo "   Output SHA256: $HASH"
    echo ""
    echo "Please attest (append to ceremony/ATTESTATION.md):"
    echo "  - Contributor number: $N"
    echo "  - Output SHA256:      $HASH"
    echo "  - Confirmation:       entropy was generated fresh and not retained"
    echo ""
    echo "→ Send $OUTPUT to the next contributor or back to the coordinator"
}

finalize() {
    local N="${1:-3}"
    local LAST_ZKEY="$CEREMONY_DIR/zkey_$(printf '%04d' "$N").zkey"

    echo "=== ZKSN Phase 2 — Finalize ==="
    echo "Applying beacon to: $LAST_ZKEY"

    $SNARKJS zkey beacon \
        "$LAST_ZKEY" \
        "$CEREMONY_DIR/zkey_final.zkey" \
        "$BEACON" \
        "$BEACON_ITERATIONS" \
        -n="ZKSN Multi-Party Final Beacon"

    echo ""
    echo "=== Exporting VK and Solidity verifier ==="

    $SNARKJS zkey export verificationkey \
        "$CEREMONY_DIR/zkey_final.zkey" \
        "$CEREMONY_DIR/verification_key.json"

    $SNARKJS zkey export solidityverifier \
        "$CEREMONY_DIR/zkey_final.zkey" \
        "$CEREMONY_DIR/Groth16Verifier_generated.sol"

    local FINAL_HASH
    FINAL_HASH=$(sha256sum "$CEREMONY_DIR/zkey_final.zkey" | awk '{print $1}')

    echo ""
    echo "✅ Ceremony finalized"
    echo "   zkey_final SHA256: $FINAL_HASH"
    echo ""
    echo "Next steps:"
    echo "  1. Update VK constants in governance/contracts/Groth16Verifier.sol"
    echo "     (copy deltax1/deltax2/deltay1/deltay2 and IC0..IC4 from verification_key.json)"
    echo "  2. Regenerate proof:  node scripts/tree.js input <secret> <proposalId> 1 > input.json"
    echo "     then:              npx snarkjs groth16 prove ..."
    echo "  3. Update REAL_PROOF / REAL_MEMBERSHIP_ROOT in governance/test/ZKSNGovernance.t.sol"
    echo "  4. forge test"
    echo "  5. Commit: 'feat/ceremony-mainnet: depth-20 N-party trusted setup'"
}

verify() {
    echo "=== ZKSN Phase 2 — Verification ==="

    $SNARKJS zkey verify \
        "$CIRCUIT_R1CS" \
        "$PTAU" \
        "$CEREMONY_DIR/zkey_final.zkey"

    echo ""
    echo "=== Sample proof round-trip ==="

    $SNARKJS groth16 prove \
        "$CEREMONY_DIR/zkey_final.zkey" \
        "$CEREMONY_DIR/witness.wtns" \
        "$CEREMONY_DIR/proof.json" \
        "$CEREMONY_DIR/public.json"

    $SNARKJS groth16 verify \
        "$CEREMONY_DIR/verification_key.json" \
        "$CEREMONY_DIR/public.json" \
        "$CEREMONY_DIR/proof.json"
}

case "${1:-}" in
    init)       init ;;
    contribute) contribute "$2" "$3" "$4" ;;
    finalize)   finalize "${2:-3}" ;;
    verify)     verify ;;
    *)
        echo "Usage: bash scripts/ceremony.sh {init|contribute <n> <in> <out>|finalize [n]|verify}"
        exit 1
        ;;
esac
