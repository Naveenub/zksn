#!/usr/bin/env bash
# scripts/ceremony.sh — ZKSN Groth16 multi-party trusted setup
#
# ── Quick start ───────────────────────────────────────────────────────────────
#
# Mainnet (recommended — Hermez pot28, 1000+ contributors):
#   bash scripts/download_ptau.sh          # ~3.2 GB, one-time
#   bash scripts/ceremony.sh init
#   bash scripts/ceremony.sh contribute 1 ceremony/zkey_0000.zkey ceremony/zkey_0001.zkey
#   bash scripts/ceremony.sh contribute 2 ceremony/zkey_0001.zkey ceremony/zkey_0002.zkey
#   bash scripts/ceremony.sh contribute 3 ceremony/zkey_0002.zkey ceremony/zkey_0003.zkey
#   bash scripts/ceremony.sh finalize
#   bash scripts/ceremony.sh verify
#
# Dev (no download needed — pot15, 3 project contributors):
#   PTAU=ceremony/pot15_final.ptau bash scripts/ceremony.sh init
#   ... (same contribute / finalize / verify steps)
#
# ── How to update the Solidity verifier after a new ceremony ──────────────────
#   1. Run finalize — produces ceremony/verification_key.json
#   2. Update VK constants in governance/contracts/Groth16Verifier.sol
#      (copy delta* and IC0..IC4 from verification_key.json)
#   3. Regenerate proof:
#        node scripts/tree.js add <secret>
#        node scripts/tree.js input <secret> <proposalId> 1 > ceremony/input.json
#        node build/MembershipVote_js/generate_witness.js \
#             build/MembershipVote_js/MembershipVote.wasm \
#             ceremony/input.json ceremony/witness.wtns
#        npx snarkjs groth16 prove ceremony/zkey_final.zkey \
#             ceremony/witness.wtns ceremony/proof.json ceremony/public.json
#   4. Update REAL_PROOF / REAL_MEMBERSHIP_ROOT in governance/test/ZKSNGovernance.t.sol
#   5. forge test
#   6. Commit: 'feat/ceremony-mainnet: pot28 N-party trusted setup'

set -euo pipefail

CIRCUIT_R1CS="build/MembershipVote.r1cs"
CIRCUIT_WASM="build/MembershipVote_js/MembershipVote.wasm"
CEREMONY_DIR="ceremony"
SNARKJS="npx snarkjs"

# ── ptau selection ────────────────────────────────────────────────────────────
# Default: Hermez pot28 (mainnet).
# Override: PTAU=ceremony/pot15_final.ptau bash scripts/ceremony.sh init
if [[ -z "${PTAU:-}" ]]; then
  PTAU="$CEREMONY_DIR/pot28_final.ptau"
fi

# ── Beacon ────────────────────────────────────────────────────────────────────
# Dev beacon (deterministic). Replace before mainnet with a future block hash:
#   BEACON=$(cast block latest --rpc-url https://eth.llamarpc.com | grep 'hash' | awk '{print $2}' | sed 's/0x//')
BEACON="0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
BEACON_ITERATIONS=10

# ─────────────────────────────────────────────────────────────────────────────

init() {
    echo "=== ZKSN Phase 2 — Init ==="
    echo "ptau: $PTAU"
    mkdir -p "$CEREMONY_DIR"

    if [[ ! -f "$PTAU" ]]; then
        if [[ "$PTAU" == *"pot28"* ]]; then
            echo ""
            echo "pot28 not found. Download it first:"
            echo "  bash scripts/download_ptau.sh"
            echo ""
            echo "Or use the dev pot15 (3 project contributors, not for mainnet):"
            echo "  PTAU=ceremony/pot15_final.ptau bash scripts/ceremony.sh init"
            exit 1
        else
            echo "ptau file not found: $PTAU"
            exit 1
        fi
    fi

    if [[ ! -f "$CIRCUIT_R1CS" ]]; then
        echo "Compiling circuit (depth=20)..."
        npx circom2 circuits/MembershipVote.circom \
            --r1cs --wasm --sym \
            -l node_modules \
            -o build/
        echo "Compiled: $(du -h "$CIRCUIT_R1CS" | cut -f1) r1cs"
    fi

    echo "Phase 2 setup..."
    $SNARKJS groth16 setup \
        "$CIRCUIT_R1CS" \
        "$PTAU" \
        "$CEREMONY_DIR/zkey_0000.zkey"

    local HASH
    HASH=$(sha256sum "$CEREMONY_DIR/zkey_0000.zkey" | awk '{print $1}')
    echo ""
    echo "✅ Phase 2 initialised"
    echo "   zkey_0000 SHA256: $HASH"
    echo "   ptau used:        $PTAU"
    echo ""
    echo "→ Send zkey_0000.zkey to Contributor 1"
    echo "→ Each contributor runs:"
    echo "    bash scripts/ceremony.sh contribute <n> <in.zkey> <out.zkey>"
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
    echo "  - Contributor: $N"
    echo "  - Output SHA256: $HASH"
    echo "  - Confirmation: entropy was generated fresh and not retained"
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
    echo "=== Post-ceremony checklist ==="
    echo ""
    echo "1. Update Groth16Verifier.sol VK constants:"
    echo "   — open ceremony/verification_key.json"
    echo "   — copy alphax/alphay, betax1/betax2, betay1/betay2,"
    echo "     deltax1/deltax2, deltay1/deltay2, IC0..IC4"
    echo "   — replace in governance/contracts/Groth16Verifier.sol"
    echo "   — update comment: 'Generated from: MembershipVote.circom (depth=20), pot28_final.ptau'"
    echo ""
    echo "2. Regenerate test proof:"
    echo "   node scripts/tree.js add 12345678901234567890"
    echo "   node scripts/tree.js input 12345678901234567890 999888777666555 1 > ceremony/input.json"
    echo "   node build/MembershipVote_js/generate_witness.js \\"
    echo "        build/MembershipVote_js/MembershipVote.wasm \\"
    echo "        ceremony/input.json ceremony/witness.wtns"
    echo "   npx snarkjs groth16 prove ceremony/zkey_final.zkey \\"
    echo "        ceremony/witness.wtns ceremony/proof.json ceremony/public.json"
    echo ""
    echo "3. Encode proof for Solidity (EIP-197 order — swap pi_b Fp2 coords):"
    echo "   node scripts/encode_proof.js ceremony/proof.json"
    echo ""
    echo "4. Update in governance/test/ZKSNGovernance.t.sol:"
    echo "   — REAL_PROOF          (output of encode_proof.js)"
    echo "   — REAL_MEMBERSHIP_ROOT (from ceremony/public.json index 3)"
    echo "   — Comment header (ptau source, zkey SHA256)"
    echo ""
    echo "5. forge test   (all 47 tests must pass)"
    echo ""
    echo "6. Update ceremony/ATTESTATION.md with new contribution hashes + SHA256s"
    echo ""
    echo "7. Commit: 'feat/ceremony-mainnet: pot28 N-party trusted setup'"
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

    echo ""
    echo "✅ Ceremony verified"
}

case "${1:-}" in
    init)       init ;;
    contribute) contribute "$2" "$3" "$4" ;;
    finalize)   finalize "${2:-3}" ;;
    verify)     verify ;;
    *)
        echo "Usage: bash scripts/ceremony.sh {init|contribute <n> <in> <out>|finalize [n]|verify}"
        echo ""
        echo "Quick start:"
        echo "  bash scripts/download_ptau.sh          # download Hermez pot28"
        echo "  bash scripts/ceremony.sh init"
        echo "  bash scripts/ceremony.sh contribute 1 ceremony/zkey_0000.zkey ceremony/zkey_0001.zkey"
        echo "  bash scripts/ceremony.sh contribute 2 ceremony/zkey_0001.zkey ceremony/zkey_0002.zkey"
        echo "  bash scripts/ceremony.sh contribute 3 ceremony/zkey_0002.zkey ceremony/zkey_0003.zkey"
        echo "  bash scripts/ceremony.sh finalize"
        echo "  bash scripts/ceremony.sh verify"
        exit 1
        ;;
esac
