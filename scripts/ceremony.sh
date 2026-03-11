#!/usr/bin/env bash
# scripts/ceremony.sh — ZKSN Groth16 multi-party trusted setup
#
# Usage:
#   Coordinator:   bash scripts/ceremony.sh init
#   Contributor N: bash scripts/ceremony.sh contribute <n> <input.zkey> <output.zkey>
#   Coordinator:   bash scripts/ceremony.sh finalize
#   Anyone:        bash scripts/ceremony.sh verify
#
# Mainnet upgrade path:
#   1. Replace PTAU with Hermez pot28:
#      wget https://hermez.s3-eu-west-1.amazonaws.com/powersoftau28_hez_final.ptau
#   2. Recompile circuit at depth 20:
#      circom circuits/MembershipVote.circom --r1cs --wasm -l node_modules -o build/
#   3. Re-run this script — everything else is identical.

set -euo pipefail

CIRCUIT_R1CS="build/MembershipVote.r1cs"
CIRCUIT_WASM="build/MembershipVote_js/MembershipVote.wasm"
PTAU="ceremony/pot12_final.ptau"           # swap for pot28 on mainnet
CEREMONY_DIR="ceremony/phase2"
SNARKJS="npx snarkjs"

# ── Beacon — use a future Bitcoin/Ethereum block hash for mainnet ─────────────
# Dev beacon (deterministic). Replace before mainnet:
#   BEACON=$(curl -s https://blockchain.info/q/latesthash)
BEACON="0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
BEACON_ITERATIONS=10

# ─────────────────────────────────────────────────────────────────────────────

init() {
    echo "=== ZKSN Phase 2 — Init ==="
    mkdir -p "$CEREMONY_DIR"

    if [[ ! -f "$CIRCUIT_R1CS" ]]; then
        echo "Compiling circuit..."
        npx circom2 circuits/MembershipVote.circom \
            --r1cs --wasm -l node_modules -o build/
    fi

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

    # Generate entropy from OS CSPRNG mixed with user prompt
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
    echo "  - Output SHA256: $HASH"
    echo "  - Confirmation: entropy was generated fresh and not retained"
    echo ""
    echo "→ Send $OUTPUT to the next contributor or back to the coordinator"
}

finalize() {
    local N="${1:-3}"   # number of contributors
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
    echo "=== Exporting verification key and Solidity verifier ==="

    $SNARKJS zkey export verificationkey \
        "$CEREMONY_DIR/zkey_final.zkey" \
        "ceremony/verification_key.json"

    $SNARKJS zkey export solidityverifier \
        "$CEREMONY_DIR/zkey_final.zkey" \
        "ceremony/Groth16Verifier_generated.sol"

    local FINAL_HASH
    FINAL_HASH=$(sha256sum "$CEREMONY_DIR/zkey_final.zkey" | awk '{print $1}')

    echo ""
    echo "✅ Ceremony finalized"
    echo "   zkey_final SHA256: $FINAL_HASH"
    echo ""
    echo "Next steps:"
    echo "  1. cp ceremony/Groth16Verifier_generated.sol governance/contracts/Groth16Verifier.sol"
    echo "  2. Update REAL_PROOF and signal constants in test/ZKSNGovernance.t.sol"
    echo "  3. Run: forge test"
    echo "  4. Commit with message: 'feat/ceremony-mainnet: N-party trusted setup'"
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
        "ceremony/witness.wtns" \
        "ceremony/proof.json" \
        "ceremony/public.json"

    $SNARKJS groth16 verify \
        "ceremony/verification_key.json" \
        "ceremony/public.json" \
        "ceremony/proof.json"
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
