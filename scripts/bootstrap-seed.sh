#!/usr/bin/env bash
# Bootstrap a ZKSN seed node: Yggdrasil + i2pd + identity + Cashu mint
set -euo pipefail

echo "=== ZKSN Seed Node Bootstrap ==="

# 1. Generate node identity
echo "[1/5] Generating node identity..."
./scripts/gen-identity.sh /var/lib/zksn/keys

# 2. Configure Yggdrasil
echo "[2/5] Configuring Yggdrasil..."
if command -v yggdrasil &>/dev/null; then
    yggdrasil -genconf > /etc/yggdrasil.conf
    echo "Yggdrasil config written to /etc/yggdrasil.conf"
else
    echo "WARNING: yggdrasil not found. Install via: nix develop"
fi

# 3. Configure i2pd
echo "[3/5] Configuring i2pd..."
cp infra/docker/config/i2pd.conf /etc/i2pd/i2pd.conf 2>/dev/null || \
    echo "WARNING: could not copy i2pd config"

# 4. Copy node config
echo "[4/5] Setting up node config..."
cp node/node.toml.example /etc/zksn/node.toml
echo "Edit /etc/zksn/node.toml to set your Yggdrasil address and bootstrap peers."

# 5. Done
echo "[5/5] Bootstrap complete."
echo ""
echo "Next steps:"
echo "  1. Edit /etc/zksn/node.toml"
echo "  2. Start: zksn-node --config /etc/zksn/node.toml"
echo "  3. Share your Yggdrasil address with other node operators"
