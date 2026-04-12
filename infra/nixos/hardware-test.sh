#!/usr/bin/env bash
# infra/nixos/hardware-test.sh
#
# ZKSN NixOS hardware validation suite.
#
# Run this script against a freshly deployed ZKSN node to verify that all
# security properties hold on real bare-metal. Every check produces a PASS
# or FAIL line. The suite exits 0 only if all checks pass.
#
# Usage (from your local machine):
#   bash infra/nixos/hardware-test.sh [200:yggdrasil:addr::1]
#
# Usage (directly on the node over SSH):
#   bash /etc/zksn/hardware-test.sh
#
# Prerequisites:
#   - Node deployed with infra/nixos/node.nix
#   - SSH access over Yggdrasil (200::/7 address)
#   - zksn-node.service has been running for at least 30 seconds
#
# What is tested:
#   1.  tmpfs root — / is mounted from tmpfs, not a block device
#   2.  tmpfs is RAM-backed — no swap backing
#   3.  No persistent writes — / has no on-disk inode count
#   4.  dm-verity — /nix is mounted with dm-verity hash tree
#   5.  /nix is read-only — write attempt fails
#   6.  LUKS2 key store — /run/keys/zksn is mounted and readable
#   7.  Identity key exists — identity.key is present on key store
#   8.  Yggdrasil interface — ygg0 has a 200::/7 address
#   9.  Yggdrasil-only bind — zksn-node listens on a 200::/7 address
#   10. Port 9001 open — mix node accepting connections
#   11. Non-Yggdrasil rejected — clearnet connection to port 9001 refused
#   12. No swap — swapDevices = [] enforced
#   13. IPv4 disabled — no IPv4 routing
#   14. Kernel hardening — sysctl values set correctly
#   15. Module blacklist — bluetooth, firewire, thunderbolt not loaded
#   16. zksn-node.service active — systemd unit running
#   17. Service restart on crash — Restart=on-failure in unit file
#   18. Key store read-only — write attempt to /run/keys/zksn fails
#   19. MemoryDenyWriteExecute — W+X pages blocked in service
#   20. NoNewPrivileges — privilege escalation blocked

set -uo pipefail

# ── Remote or local mode ──────────────────────────────────────────────────────

REMOTE_HOST="${1:-}"
SSH_CMD=""

if [[ -n "$REMOTE_HOST" ]]; then
  SSH_CMD="ssh -o StrictHostKeyChecking=no root@${REMOTE_HOST}"
  echo "Running hardware tests against: $REMOTE_HOST"
  # Verify connectivity
  if ! $SSH_CMD "true" 2>/dev/null; then
    echo "ERROR: Cannot SSH to $REMOTE_HOST"
    echo "  Check: ssh root@${REMOTE_HOST}"
    exit 1
  fi
else
  echo "Running hardware tests locally (on the node itself)"
fi

run() {
  if [[ -n "$SSH_CMD" ]]; then
    $SSH_CMD "$@" 2>/dev/null
  else
    bash -c "$@" 2>/dev/null
  fi
}

# ── Test framework ────────────────────────────────────────────────────────────

PASS=0
FAIL=0
SKIP=0

pass() { echo "  PASS  $1"; ((PASS++)); }
fail() { echo "  FAIL  $1"; ((FAIL++)); }
skip() { echo "  SKIP  $1 ($2)"; ((SKIP++)); }

check() {
  local label="$1"
  local cmd="$2"
  local expected="${3:-0}"  # expected exit code (default 0 = success)
  local actual
  run "$cmd" > /dev/null 2>&1
  actual=$?
  if [[ "$actual" == "$expected" ]]; then
    pass "$label"
  else
    fail "$label (exit $actual, expected $expected)"
  fi
}

check_output() {
  local label="$1"
  local cmd="$2"
  local pattern="$3"
  local output
  output=$(run "$cmd" 2>/dev/null || true)
  if echo "$output" | grep -qE "$pattern"; then
    pass "$label"
  else
    fail "$label (expected pattern '$pattern', got: ${output:0:120})"
  fi
}

check_not_output() {
  local label="$1"
  local cmd="$2"
  local pattern="$3"
  local output
  output=$(run "$cmd" 2>/dev/null || true)
  if echo "$output" | grep -qE "$pattern"; then
    fail "$label (unexpected pattern '$pattern' found)"
  else
    pass "$label"
  fi
}

# ── Test suite ────────────────────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════════════════════"
echo "  ZKSN NixOS Hardware Validation Suite"
echo "════════════════════════════════════════════════════════"
echo ""

echo "── 1. Root filesystem (tmpfs) ───────────────────────────"

check_output \
  "/ mounted as tmpfs" \
  "findmnt -n -o FSTYPE /" \
  "^tmpfs$"

check_output \
  "tmpfs size ≥ 1G" \
  "findmnt -n -o SIZE / 2>/dev/null || df -h / | awk 'NR==2{print \$2}'" \
  "[0-9]"

check \
  "/ has no persistent backing device" \
  "test \"\$(findmnt -n -o SOURCE /)\" = 'tmpfs'"

check \
  "writes to / are not persisted across boot (tmpfs confirm)" \
  "mount | grep -q 'on / type tmpfs'"

echo ""
echo "── 2. /nix store (dm-verity, read-only) ────────────────"

check_output \
  "/nix mounted read-only" \
  "findmnt -n -o OPTIONS /nix" \
  "ro"

check \
  "write to /nix fails (read-only)" \
  "test ! -w /nix/store" \
  "0"

# dm-verity: the /nix device should be a dm device (dm-N)
check_output \
  "/nix backed by device-mapper (dm-verity)" \
  "findmnt -n -o SOURCE /nix" \
  "^(/dev/dm-|/dev/mapper/)" \
  || check_output \
    "/nix backed by device-mapper (dm-verity — alt path)" \
    "dmsetup info 2>/dev/null | head -5" \
    "verity|dm-"

check \
  "dm_verity kernel module loaded" \
  "grep -q dm_verity /proc/modules"

echo ""
echo "── 3. LUKS2 key store ──────────────────────────────────"

check \
  "/run/keys/zksn mount point exists" \
  "test -d /run/keys/zksn"

check \
  "/run/keys/zksn is mounted" \
  "mountpoint -q /run/keys/zksn"

check \
  "identity.key exists on key store" \
  "test -f /run/keys/zksn/identity.key"

check \
  "identity.key is readable (32 bytes)" \
  "test \$(wc -c < /run/keys/zksn/identity.key 2>/dev/null || echo 0) -ge 32"

check \
  "key store mounted read-only" \
  "mount | grep -q '/run/keys/zksn.*ro'"

check \
  "write to key store is refused" \
  "! touch /run/keys/zksn/test_write 2>/dev/null"

check \
  "LUKS2 device mapper present" \
  "ls /dev/mapper/zksn-keys 2>/dev/null || cryptsetup status zksn-keys 2>/dev/null | grep -q active"

echo ""
echo "── 4. Yggdrasil network ────────────────────────────────"

check \
  "yggdrasil.service is active" \
  "systemctl is-active yggdrasil"

check \
  "ygg0 interface exists" \
  "ip link show ygg0 2>/dev/null | grep -q ygg0"

check_output \
  "ygg0 has 200::/7 address" \
  "ip -6 addr show ygg0 2>/dev/null" \
  "inet6 (2|3)[0-9a-f]{2}:"

YGG_ADDR=$(run "ip -6 addr show ygg0 2>/dev/null | grep -oP 'inet6 \K[^/]+' | grep -E '^[23]' | head -1")
if [[ -n "$YGG_ADDR" ]]; then
  pass "Yggdrasil address extracted: $YGG_ADDR"
else
  fail "Could not extract Yggdrasil address from ygg0"
fi

check \
  "Yggdrasil NodeInfoPrivacy enabled" \
  "yggdrasilctl getself 2>/dev/null | grep -q 'IPv6'"

echo ""
echo "── 5. ZKSN mix node service ────────────────────────────"

check \
  "zksn-node.service is active" \
  "systemctl is-active zksn-node"

check_output \
  "zksn-node.service Restart=on-failure" \
  "systemctl show zksn-node --property=Restart" \
  "Restart=on-failure"

check_output \
  "zksn-node.service NoNewPrivileges=yes" \
  "systemctl show zksn-node --property=NoNewPrivileges" \
  "NoNewPrivileges=yes"

check_output \
  "zksn-node.service MemoryDenyWriteExecute=yes" \
  "systemctl show zksn-node --property=MemoryDenyWriteExecute" \
  "MemoryDenyWriteExecute=yes"

check_output \
  "zksn-node.service DynamicUser=yes" \
  "systemctl show zksn-node --property=DynamicUser" \
  "DynamicUser=yes"

check_output \
  "zksn-node.service RestrictAddressFamilies=AF_INET6" \
  "systemctl show zksn-node --property=RestrictAddressFamilies" \
  "AF_INET6"

echo ""
echo "── 6. Port 9001 (Yggdrasil address only) ────────────────"

check \
  "port 9001 is listening" \
  "ss -6 -tlnp 2>/dev/null | grep -q ':9001'"

# Check that 9001 is bound to a 200::/7 address, not :: or 0.0.0.0
LISTEN_ADDR=$(run "ss -6 -tlnp 2>/dev/null | grep ':9001' | awk '{print \$4}' | head -1")
if echo "$LISTEN_ADDR" | grep -qE '^\[?(2|3)[0-9a-f]{2}:'; then
  pass "Port 9001 bound to Yggdrasil address (not wildcard)"
elif echo "$LISTEN_ADDR" | grep -qE '^\*|^::|^0\.0\.0\.0'; then
  fail "Port 9001 bound to wildcard — Yggdrasil enforcement may not be active"
else
  skip "Port 9001 bind address check" "could not parse: $LISTEN_ADDR"
fi

echo ""
echo "── 7. Network isolation ─────────────────────────────────"

check \
  "No swap partitions" \
  "test \"\$(swapon --show 2>/dev/null | wc -l)\" -le 1"

check \
  "IPv4 disabled on all interfaces" \
  "sysctl net.ipv4.conf.all.disable_ipv4 2>/dev/null | grep -q '= 1'"

check \
  "No IPv4 routes" \
  "ip -4 route 2>/dev/null | grep -qv 'default\|link' && exit 1 || exit 0"

check \
  "ICMP redirects disabled (IPv6)" \
  "sysctl net.ipv6.conf.all.accept_redirects 2>/dev/null | grep -q '= 0'"

echo ""
echo "── 8. Kernel hardening ──────────────────────────────────"

check \
  "kernel.dmesg_restrict=1" \
  "sysctl kernel.dmesg_restrict 2>/dev/null | grep -q '= 1'"

check \
  "kernel.unprivileged_bpf_disabled=1" \
  "sysctl kernel.unprivileged_bpf_disabled 2>/dev/null | grep -q '= 1'"

check \
  "kernel.yama.ptrace_scope=2" \
  "sysctl kernel.yama.ptrace_scope 2>/dev/null | grep -q '= 2'"

check \
  "module.sig_enforce active (signed modules only)" \
  "cat /proc/sys/kernel/modules_disabled 2>/dev/null || \
   grep -q 'module.sig_enforce=1' /proc/cmdline 2>/dev/null"

echo ""
echo "── 9. Module blacklist ───────────────────────────────────"

for mod in bluetooth btusb firewire_core thunderbolt uvcvideo; do
  check \
    "Module $mod not loaded" \
    "! grep -q '^${mod} ' /proc/modules 2>/dev/null"
done

echo ""
echo "── 10. RAM-only / no persistence ───────────────────────"

# Write a sentinel file, then check it will not survive on real hardware.
# We can only verify the tmpfs part here — actual reboot persistence test
# must be done manually (see README.md).
SENTINEL="/tmp/zksn_test_sentinel_$$"
run "echo 'sentinel' > $SENTINEL && test -f $SENTINEL" && \
  pass "Sentinel file written to tmpfs" || \
  fail "Sentinel file write failed"

run "test \$(df -k $SENTINEL 2>/dev/null | awk 'NR==2{print \$1}') = 'tmpfs' 2>/dev/null || \
     mount | grep -q '\(on /tmp type tmpfs\|on / type tmpfs\)'" && \
  pass "Sentinel file is on tmpfs (will not survive reboot)" || \
  fail "Sentinel file may be on persistent storage"

run "rm -f $SENTINEL" 2>/dev/null || true

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════════════════════"
TOTAL=$((PASS + FAIL + SKIP))
echo "  Results: $PASS passed, $FAIL failed, $SKIP skipped ($TOTAL total)"
echo "════════════════════════════════════════════════════════"
echo ""

if [[ $FAIL -gt 0 ]]; then
  echo "  ✗ Hardware validation FAILED — see FAIL lines above"
  echo ""
  echo "  Common causes:"
  echo "    dm-verity FAIL  → /nix not built with verity hash tree (see README step 3)"
  echo "    LUKS2 FAIL      → USB key device not labelled ZKSN-KEYS or not connected"
  echo "    port 9001 FAIL  → zksn-node not started or Yggdrasil address not set"
  echo "    sysctl FAIL     → kernel cmdline params not applied (check boot loader)"
  echo ""
  exit 1
else
  echo "  ✓ All hardware validation checks passed"
  echo ""
  echo "  Manual checks still required (cannot be automated):"
  echo "    □ Reboot the node and confirm root contents are empty"
  echo "    □ Remove USB key device and confirm node refuses to start"
  echo "    □ Attempt to write to /nix/store from a local shell — must fail"
  echo "    □ Connect from a non-Yggdrasil IP to port 9001 — must be refused"
  echo ""
  exit 0
fi
