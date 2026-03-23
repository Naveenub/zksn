#!/usr/bin/env bash
# scripts/download_ptau.sh — Download and verify the Hermez pot28 Powers of Tau file
#
# The Hermez pot28 file is the strongest available phase 1 trusted setup:
#   - 2^28 capacity (268M constraints — far exceeds ZKSN's 11,313)
#   - 1,000+ independent contributors from the 2021 Hermez ceremony
#   - Widely used by Tornado Cash, Semaphore, Worldcoin, and others
#   - Verified by the ZK community at large
#
# Usage:
#   bash scripts/download_ptau.sh               # download to ceremony/
#   bash scripts/download_ptau.sh /path/to/dir  # download to custom dir
#
# After downloading, run the ceremony:
#   bash scripts/ceremony.sh init
#   bash scripts/ceremony.sh contribute 1 ceremony/zkey_0000.zkey ceremony/zkey_0001.zkey
#   bash scripts/ceremony.sh contribute 2 ceremony/zkey_0001.zkey ceremony/zkey_0002.zkey
#   bash scripts/ceremony.sh contribute 3 ceremony/zkey_0002.zkey ceremony/zkey_0003.zkey
#   bash scripts/ceremony.sh finalize

set -euo pipefail

DEST_DIR="${1:-ceremony}"
PTAU_FILE="$DEST_DIR/pot28_final.ptau"

# ── Known-good SHA256 (from Hermez ceremony announcement) ────────────────────
# https://blog.hermez.io/hermez-cryptographic-setup/
POT28_SHA256="55c77ce8562366c91e7cda394cf7b7c15a06c12d8c905e8b36ba9cf5e13eb37d"

# ── Download URLs (try in order) ─────────────────────────────────────────────
URLS=(
  "https://hermez.s3-eu-west-1.amazonaws.com/powersoftau28_hez_final.ptau"
  "https://storage.googleapis.com/zkevm/ptau/powersoftau28_hez_final.ptau"
)

mkdir -p "$DEST_DIR"

if [[ -f "$PTAU_FILE" ]]; then
  echo "File already exists: $PTAU_FILE"
  echo "Verifying SHA256..."
else
  echo "Downloading Hermez pot28 (~3.2 GB) to $PTAU_FILE ..."
  echo "This will take several minutes depending on your connection."
  echo ""

  DOWNLOADED=0
  for URL in "${URLS[@]}"; do
    echo "Trying: $URL"
    if curl -L --progress-bar --retry 3 --retry-delay 5 -o "$PTAU_FILE" "$URL"; then
      DOWNLOADED=1
      break
    else
      echo "Failed, trying next mirror..."
      rm -f "$PTAU_FILE"
    fi
  done

  if [[ $DOWNLOADED -eq 0 ]]; then
    echo ""
    echo "❌ All download mirrors failed."
    echo "   Download manually:"
    echo "   ${URLS[0]}"
    echo "   Save to: $PTAU_FILE"
    exit 1
  fi
fi

# ── Verify integrity ──────────────────────────────────────────────────────────
echo ""
echo "Verifying SHA256..."
if command -v sha256sum &>/dev/null; then
  ACTUAL=$(sha256sum "$PTAU_FILE" | awk '{print $1}')
elif command -v shasum &>/dev/null; then
  ACTUAL=$(shasum -a 256 "$PTAU_FILE" | awk '{print $1}')
else
  echo "⚠️  No sha256sum or shasum found — skipping integrity check."
  echo "   Verify manually against: $POT28_SHA256"
  exit 0
fi

if [[ "$ACTUAL" == "$POT28_SHA256" ]]; then
  SIZE=$(du -h "$PTAU_FILE" | cut -f1)
  echo "✅ SHA256 verified: $ACTUAL"
  echo "   File: $PTAU_FILE ($SIZE)"
  echo ""
  echo "Next step: bash scripts/ceremony.sh init"
else
  echo "❌ SHA256 MISMATCH — file may be corrupt or tampered."
  echo "   Expected: $POT28_SHA256"
  echo "   Actual:   $ACTUAL"
  rm -f "$PTAU_FILE"
  exit 1
fi
