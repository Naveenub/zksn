#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DIR="${1:-$HOME/.zksn}"
mkdir -p "$OUTPUT_DIR"
chmod 700 "$OUTPUT_DIR"

echo "Generating ZKSN Ed25519 identity..."

# Generate 32 bytes of secure random key material
KEY_FILE="$OUTPUT_DIR/identity.key"
PUB_FILE="$OUTPUT_DIR/identity.pub"

dd if=/dev/urandom bs=32 count=1 2>/dev/null > "$KEY_FILE"
chmod 600 "$KEY_FILE"

# Derive public fingerprint via zksn CLI if available
if command -v zksn &>/dev/null; then
    zksn --key "$KEY_FILE" identity show > "$PUB_FILE"
else
    # Fallback: show hex of key file for manual use
    echo "Public key (hex): $(xxd -p -c 64 "$KEY_FILE")" > "$PUB_FILE"
fi

echo ""
echo "Identity generated:"
echo "  Private key: $KEY_FILE  (NEVER share this)"
echo "  Public info: $PUB_FILE  (share this)"
echo ""
echo "Keep $KEY_FILE secure. It cannot be recovered if lost."
