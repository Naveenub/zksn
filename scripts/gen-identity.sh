#!/usr/bin/env bash
# =============================================================================
# ZKSN Identity Generator
# Generates an Ed25519 keypair for use as a ZKSN node or user identity.
# The public key IS your identity — no registration, no email, no username.
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

OUTPUT_DIR="${1:-.}"
IDENTITY_KEY="${OUTPUT_DIR}/identity.key"
IDENTITY_PUB="${OUTPUT_DIR}/identity.pub"
IDENTITY_FINGERPRINT="${OUTPUT_DIR}/identity.fingerprint"

echo -e "${BLUE}"
echo "  ███████╗██╗  ██╗███████╗███╗   ██╗"
echo "  ╚══███╔╝██║ ██╔╝██╔════╝████╗  ██║"
echo "    ███╔╝ █████╔╝ ███████╗██╔██╗ ██║"
echo "   ███╔╝  ██╔═██╗ ╚════██║██║╚██╗██║"
echo "  ███████╗██║  ██╗███████║██║ ╚████║"
echo "  ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝"
echo -e "${NC}"
echo "  Zero-Knowledge Sovereign Network — Identity Generator"
echo "  ======================================================"
echo ""

# --- Prerequisite Check ---
if ! command -v openssl &> /dev/null; then
    echo -e "${RED}ERROR: openssl is required but not installed.${NC}"
    exit 1
fi

OPENSSL_VERSION=$(openssl version | awk '{print $2}')
echo -e "  ${GREEN}✓${NC} OpenSSL ${OPENSSL_VERSION} found"

# --- Check output directory ---
if [ ! -d "${OUTPUT_DIR}" ]; then
    mkdir -p "${OUTPUT_DIR}"
fi

# --- Check for existing keys ---
if [ -f "${IDENTITY_KEY}" ] || [ -f "${IDENTITY_PUB}" ]; then
    echo ""
    echo -e "  ${YELLOW}⚠ WARNING: Identity files already exist in ${OUTPUT_DIR}${NC}"
    echo -e "  ${YELLOW}  Overwriting will permanently destroy your existing identity.${NC}"
    echo ""
    read -r -p "  Overwrite existing identity? [y/N] " response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        echo "  Aborted. Existing identity preserved."
        exit 0
    fi
fi

echo ""
echo "  Generating Ed25519 keypair..."

# --- Generate Ed25519 private key ---
openssl genpkey -algorithm ed25519 -out "${IDENTITY_KEY}" 2>/dev/null

# --- Extract public key ---
openssl pkey -in "${IDENTITY_KEY}" -pubout -out "${IDENTITY_PUB}" 2>/dev/null

# --- Generate fingerprint (SHA-256 of DER-encoded public key) ---
FINGERPRINT=$(openssl pkey -in "${IDENTITY_KEY}" -pubout -outform DER 2>/dev/null | \
              openssl dgst -sha256 -binary | \
              xxd -p | \
              tr -d '\n' | \
              sed 's/../&:/g' | \
              sed 's/:$//')

echo "${FINGERPRINT}" > "${IDENTITY_FINGERPRINT}"

# --- Set permissions ---
chmod 600 "${IDENTITY_KEY}"
chmod 644 "${IDENTITY_PUB}"
chmod 644 "${IDENTITY_FINGERPRINT}"

# --- Display results ---
echo ""
echo -e "  ${GREEN}✓ Identity generated successfully${NC}"
echo ""
echo "  Files created:"
echo -e "    ${YELLOW}${IDENTITY_KEY}${NC}         ← PRIVATE KEY — never share this"
echo -e "    ${GREEN}${IDENTITY_PUB}${NC}         ← Public key  — this is your identity"
echo -e "    ${BLUE}${IDENTITY_FINGERPRINT}${NC}  ← Fingerprint — human-readable ID"
echo ""
echo "  Your ZKSN identity fingerprint:"
echo -e "    ${BLUE}${FINGERPRINT}${NC}"
echo ""

# --- Display public key ---
echo "  Your public key (share this freely):"
echo "  ──────────────────────────────────────────────────────"
cat "${IDENTITY_PUB}"
echo "  ──────────────────────────────────────────────────────"
echo ""

# --- Security reminders ---
echo -e "  ${RED}⚠ SECURITY REMINDERS:${NC}"
echo "    1. Your PRIVATE KEY (identity.key) must NEVER be shared or transmitted"
echo "    2. Store your private key on an encrypted medium (LUKS2, VeraCrypt)"
echo "    3. For maximum security, generate keys on an air-gapped machine (Tails OS)"
echo "    4. Consider storing a backup of the private key in a secure offline location"
echo "    5. Your identity has NO recovery mechanism — if you lose the private key,"
echo "       your identity is permanently lost"
echo ""
echo "  For RAM-only / stateless operation:"
echo "    Store identity.key on an encrypted USB drive, NOT on the node itself"
echo "    The node loads the key at runtime and never writes it to disk"
echo ""
