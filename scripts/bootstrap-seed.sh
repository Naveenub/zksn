#!/usr/bin/env bash
# =============================================================================
# ZKSN Seed Node Bootstrap
# =============================================================================
# Bootstraps the first seed nodes for a new ZKSN deployment.
# Run this on a fresh NixOS or Debian/Ubuntu machine.
#
# What this script does:
#   1. Installs Yggdrasil
#   2. Generates a node identity
#   3. Configures and starts i2pd
#   4. Optionally configures a Cashu mint
#   5. Prints the node's Yggdrasil address for peer lists
#
# Usage:
#   sudo bash bootstrap-seed.sh [--with-mint] [--testnet]
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

WITH_MINT=false
TESTNET=false

for arg in "$@"; do
  case $arg in
    --with-mint) WITH_MINT=true ;;
    --testnet)   TESTNET=true  ;;
  esac
done

echo -e "${BLUE}"
echo "  ╔══════════════════════════════════════╗"
echo "  ║   ZKSN Seed Node Bootstrap           ║"
echo "  ╚══════════════════════════════════════╝"
echo -e "${NC}"

# Root check
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}ERROR: This script must be run as root (sudo).${NC}"
  exit 1
fi

OS=$(uname -s)
ARCH=$(uname -m)

echo -e "  OS:   ${OS}"
echo -e "  Arch: ${ARCH}"
echo ""

# =============================================================================
# Step 1: Install dependencies
# =============================================================================

step() { echo -e "\n${BLUE}[STEP]${NC} $1"; }
ok()   { echo -e "${GREEN}  ✓${NC} $1"; }
warn() { echo -e "${YELLOW}  ⚠${NC} $1"; }

step "Installing dependencies"

if command -v apt-get &>/dev/null; then
  apt-get update -qq
  apt-get install -y -qq curl wget gpg jq i2pd
  ok "apt packages installed"
elif command -v nix-env &>/dev/null; then
  nix-env -iA nixpkgs.yggdrasil nixpkgs.i2pd nixpkgs.jq
  ok "nix packages installed"
else
  warn "Unknown package manager — install yggdrasil and i2pd manually"
fi

# =============================================================================
# Step 2: Install Yggdrasil
# =============================================================================

step "Installing Yggdrasil"

if ! command -v yggdrasil &>/dev/null; then
  case "${OS}-${ARCH}" in
    Linux-x86_64)
      YGGDRASIL_URL="https://github.com/yggdrasil-network/yggdrasil-go/releases/latest/download/yggdrasil-latest-amd64.deb"
      wget -q "$YGGDRASIL_URL" -O /tmp/yggdrasil.deb
      dpkg -i /tmp/yggdrasil.deb
      rm /tmp/yggdrasil.deb
      ;;
    Linux-aarch64|Linux-arm64)
      YGGDRASIL_URL="https://github.com/yggdrasil-network/yggdrasil-go/releases/latest/download/yggdrasil-latest-arm64.deb"
      wget -q "$YGGDRASIL_URL" -O /tmp/yggdrasil.deb
      dpkg -i /tmp/yggdrasil.deb
      rm /tmp/yggdrasil.deb
      ;;
    *)
      warn "Unsupported platform — install Yggdrasil manually from https://yggdrasil-network.github.io/"
      ;;
  esac
fi

if command -v yggdrasil &>/dev/null; then
  ok "Yggdrasil $(yggdrasil -version | head -1) installed"
fi

# =============================================================================
# Step 3: Generate Yggdrasil config
# =============================================================================

step "Configuring Yggdrasil"

YGGDRASIL_CONF="/etc/yggdrasil.conf"

if [ ! -f "$YGGDRASIL_CONF" ]; then
  yggdrasil -genconf > "$YGGDRASIL_CONF"
  ok "Yggdrasil config generated at $YGGDRASIL_CONF"
else
  warn "Yggdrasil config already exists at $YGGDRASIL_CONF — skipping generation"
fi

# Extract the node's Yggdrasil address
if command -v yggdrasilctl &>/dev/null && systemctl is-active --quiet yggdrasil 2>/dev/null; then
  YGGDRASIL_ADDR=$(yggdrasilctl getSelf 2>/dev/null | jq -r '.self | keys[0]' 2>/dev/null || echo "unknown")
else
  YGGDRASIL_ADDR="(start Yggdrasil to determine)"
fi

# =============================================================================
# Step 4: Generate ZKSN node identity
# =============================================================================

step "Generating node identity"

IDENTITY_DIR="/var/lib/zksn/keys"
mkdir -p "$IDENTITY_DIR"
chmod 700 "$IDENTITY_DIR"

if [ ! -f "$IDENTITY_DIR/identity.key" ]; then
  # Use gen-identity.sh if available, otherwise use openssl directly
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  if [ -f "$SCRIPT_DIR/gen-identity.sh" ]; then
    bash "$SCRIPT_DIR/gen-identity.sh" "$IDENTITY_DIR"
  else
    openssl genpkey -algorithm ed25519 -out "$IDENTITY_DIR/identity.key" 2>/dev/null
    openssl pkey -in "$IDENTITY_DIR/identity.key" -pubout -out "$IDENTITY_DIR/identity.pub" 2>/dev/null
    chmod 600 "$IDENTITY_DIR/identity.key"
  fi
  ok "Node identity generated"
else
  warn "Identity already exists at $IDENTITY_DIR — skipping generation"
fi

FINGERPRINT=$(openssl pkey -in "$IDENTITY_DIR/identity.key" -pubout -outform DER 2>/dev/null | \
              openssl dgst -sha256 -hex 2>/dev/null | awk '{print $2}' | \
              sed 's/../&:/g; s/:$//')

# =============================================================================
# Step 5: Configure i2pd
# =============================================================================

step "Configuring i2pd"

cat > /etc/i2pd/i2pd.conf << 'CONF'
# ZKSN i2pd configuration
# Generated by bootstrap-seed.sh

[general]
loglevel = warn
ipv6 = true

[ntcp2]
enabled = true

[ssu2]
enabled = true

[httpproxy]
enabled = true
address = 127.0.0.1
port = 4444

[socksproxy]
enabled = true
address = 127.0.0.1
port = 4447

[http]
enabled = true
address = 127.0.0.1
port = 7070
CONF

ok "i2pd configured"

# =============================================================================
# Step 6: Start services
# =============================================================================

step "Starting services"

systemctl enable --now yggdrasil 2>/dev/null && ok "Yggdrasil started" || warn "Could not start Yggdrasil (systemd required)"
systemctl enable --now i2pd     2>/dev/null && ok "i2pd started"      || warn "Could not start i2pd (systemd required)"

# =============================================================================
# Step 7: Optional Cashu mint
# =============================================================================

if [ "$WITH_MINT" = true ]; then
  step "Setting up Cashu mint"

  if command -v pip3 &>/dev/null; then
    pip3 install cashu --quiet
    ok "Cashu installed"
    echo ""
    echo -e "  Start mint with: ${CYAN}mint --host 127.0.0.1 --port 3338${NC}"
  else
    warn "pip3 not found — install Python 3 and run: pip3 install cashu"
  fi
fi

# =============================================================================
# Summary
# =============================================================================

echo ""
echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo -e "${GREEN}  Seed Node Bootstrap Complete             ${NC}"
echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BLUE}Node identity fingerprint:${NC}"
echo -e "  ${YELLOW}${FINGERPRINT}${NC}"
echo ""
echo -e "  ${BLUE}Yggdrasil address:${NC}"
echo -e "  ${YELLOW}${YGGDRASIL_ADDR}${NC}"
echo ""
echo -e "  ${BLUE}Next steps:${NC}"
echo "  1. Add peers to /etc/yggdrasil.conf (Peers section)"
echo "  2. Restart Yggdrasil: systemctl restart yggdrasil"
echo "  3. Build and start the mix node: cargo build --release && ./target/release/zksn-node"
echo "  4. Share your Yggdrasil address with other ZKSN operators"
echo ""

if [ "$TESTNET" = true ]; then
  echo -e "  ${YELLOW}⚠ Running in TESTNET mode${NC}"
fi
