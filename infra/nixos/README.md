# ZKSN NixOS Node — Deployment and Hardware Testing Guide

## Overview

This directory contains the NixOS configuration for a production ZKSN mix node.
The design goal is **zero forensic footprint**: physical seizure of the hardware
yields no user data, no keys, and no routing history.

### Security properties

| Property | Mechanism | Verified by |
|---|---|---|
| No persistent writes | `tmpfs` root — all writes to RAM | `hardware-test.sh` check 1–3 |
| Verified boot | `dm-verity` on read-only `/nix` partition | `hardware-test.sh` check 4–6 |
| Encrypted key material | LUKS2 on removable USB device | `hardware-test.sh` check 7–13 |
| Stable Yggdrasil address | Key persisted on LUKS2 USB | `hardware-test.sh` check 14–18 |
| Yggdrasil-only traffic | IPv6 firewall + Rust socket enforcement | `hardware-test.sh` check 19–22 |
| Kernel hardening | `sysctl` + module blacklist | `hardware-test.sh` check 23–29 |

---

## Prerequisites

- A bare-metal x86_64 machine with EFI boot
- A USB drive (≥ 512 MB) for the LUKS2 key store
- NixOS 24.x installer USB
- A working Yggdrasil peer address (see https://publicpeers.neilalexander.dev/)
- The ZKSN repository cloned locally with Nix flakes enabled

```bash
nix develop   # enter the dev shell with all tools
```

---

## Step 1 — Partition the target disk

Boot the NixOS installer. Partition the target disk with three partitions:

```bash
# Identify your disk (usually /dev/sda or /dev/nvme0n1)
lsblk

# Partition layout:
#   sda1  512M   EFI       label: ZKSN-BOOT
#   sda2  rest   ext4      label: ZKSN-NIX   (will be made read-only + dm-verity)

parted /dev/sda -- mklabel gpt
parted /dev/sda -- mkpart ESP  fat32 1MB 512MB
parted /dev/sda -- mkpart Nix  ext4  512MB 100%
parted /dev/sda -- set 1 esp on

mkfs.fat  -F 32 -n ZKSN-BOOT /dev/sda1
mkfs.ext4       -L ZKSN-NIX  /dev/sda2
```

---

## Step 2 — Set up the LUKS2 USB key store

Using a separate USB drive (not the installer):

```bash
# Identify the USB device
lsblk

# Format with LUKS2 (strong KDF: argon2id)
cryptsetup luksFormat --type luks2 \
  --pbkdf argon2id \
  --label ZKSN-KEYS \
  /dev/sdb

# Open it
cryptsetup luksOpen /dev/sdb zksn-keys

# Create ext4 filesystem
mkfs.ext4 -L ZKSN-KEYS /dev/mapper/zksn-keys
mount /dev/mapper/zksn-keys /mnt/keys

# Generate the node's Ed25519 identity key (32 bytes)
dd if=/dev/urandom bs=32 count=1 > /mnt/keys/identity.key
chmod 600 /mnt/keys/identity.key

# Generate Yggdrasil config with a stable private key
yggdrasil -genconf > /mnt/keys/yggdrasil.conf
chmod 600 /mnt/keys/yggdrasil.conf

# Note the Yggdrasil address for use in step 4
YGGDRASIL_ADDR=$(yggdrasil -useconf -normaliseconf < /mnt/keys/yggdrasil.conf | \
  yggdrasil -useconf -address 2>/dev/null || \
  grep -oP '"Address":\s*"\K[^"]+' /mnt/keys/yggdrasil.conf | head -1)
echo "Your Yggdrasil address: $YGGDRASIL_ADDR"

umount /mnt/keys
cryptsetup luksClose zksn-keys
```

---

## Step 3 — Build the dm-verity nix store image

**This step runs on your build machine, not the target node.**

```bash
cd /path/to/zksn

# Build the NixOS system
nix build .#nixosConfigurations.zksn-node.config.system.build.toplevel

# Install to the target disk (target must be mounted at /mnt)
# Replace /dev/sda2 with your actual Nix partition
mount /dev/sda2 /mnt/nix
NIXOS_INSTALL_BOOTLOADER=1 nixos-install \
  --system ./result \
  --root /mnt

# Generate dm-verity hash tree for the nix partition
# Store the root hash — you will need it in the boot parameters
veritysetup format /dev/sda2 /dev/sda2-verity.img \
  | tee /tmp/verity-info.txt
ROOT_HASH=$(grep "Root hash:" /tmp/verity-info.txt | awk '{print $3}')
echo "dm-verity root hash: $ROOT_HASH"

# Add the root hash to the kernel command line in the boot loader
# Edit /mnt/boot/loader/entries/*.conf and add:
# options ... dm-mod.create="vroot,,,ro,0 $(blockdev --getsz /dev/sda2) verity 1 /dev/sda2 /dev/sda2 4096 4096 $(blockdev --getsz /dev/sda2)/8 0 sha256 $ROOT_HASH ..."
```

---

## Step 4 — Add your Yggdrasil peers

Edit `infra/nixos/node.nix`, find the `services.yggdrasil.settings.Peers` list,
and add at least two public peers:

```nix
services.yggdrasil.settings.Peers = [
  "tcp://your.peer.example.com:9002"
  "tls://another.peer.example.com:9003"
];
```

Find peers at: https://publicpeers.neilalexander.dev/

---

## Step 5 — Deploy

From your build machine, with the target node booted into the NixOS installer
and connected to your Yggdrasil network:

```bash
nixos-rebuild switch \
  --target-host root@[200:your:node:addr::1] \
  --flake .#zksn-node
```

Or for first deployment (target booted from installer, not yet running NixOS):

```bash
nixos-install \
  --system $(nix build .#nixosConfigurations.zksn-node.config.system.build.toplevel --print-out-paths) \
  --root /mnt
```

---

## Step 6 — Run the hardware validation suite

After the node boots and `zksn-node.service` is active (wait ~30 seconds):

```bash
# From your local machine
bash infra/nixos/hardware-test.sh [200:your:node:addr::1]

# Or copy to the node and run locally
scp infra/nixos/hardware-test.sh root@[200:your:node::1]:/tmp/
ssh root@[200:your:node::1] bash /tmp/hardware-test.sh
```

Expected output (all 30 automated checks passing):

```
════════════════════════════════════════════════════════
  ZKSN NixOS Hardware Validation Suite
════════════════════════════════════════════════════════

── 1. Root filesystem (tmpfs) ───────────────────────────
  PASS  / mounted as tmpfs
  PASS  tmpfs size ≥ 1G
  PASS  / has no persistent backing device
  PASS  writes to / are not persisted across boot (tmpfs confirm)

── 2. /nix store (dm-verity, read-only) ────────────────
  PASS  /nix mounted read-only
  PASS  write to /nix fails (read-only)
  PASS  /nix backed by device-mapper (dm-verity)
  PASS  dm_verity kernel module loaded

── 3. LUKS2 key store ──────────────────────────────────
  PASS  /run/keys/zksn mount point exists
  PASS  /run/keys/zksn is mounted
  PASS  identity.key exists on key store
  PASS  identity.key is readable (32 bytes)
  PASS  key store mounted read-only
  PASS  write to key store is refused
  PASS  LUKS2 device mapper present

── 4. Yggdrasil network ────────────────────────────────
  PASS  yggdrasil.service is active
  PASS  ygg0 interface exists
  PASS  ygg0 has 200::/7 address
  PASS  Yggdrasil address extracted: 200:abcd::1
  PASS  Yggdrasil NodeInfoPrivacy enabled

── 5. ZKSN mix node service ────────────────────────────
  PASS  zksn-node.service is active
  PASS  zksn-node.service Restart=on-failure
  PASS  zksn-node.service NoNewPrivileges=yes
  PASS  zksn-node.service MemoryDenyWriteExecute=yes
  PASS  zksn-node.service DynamicUser=yes
  PASS  zksn-node.service RestrictAddressFamilies=AF_INET6

── 6. Port 9001 (Yggdrasil address only) ────────────────
  PASS  port 9001 is listening
  PASS  Port 9001 bound to Yggdrasil address (not wildcard)

── 7. Network isolation ─────────────────────────────────
  PASS  No swap partitions
  PASS  IPv4 disabled on all interfaces
  PASS  No IPv4 routes
  PASS  ICMP redirects disabled (IPv6)

── 8. Kernel hardening ──────────────────────────────────
  PASS  kernel.dmesg_restrict=1
  PASS  kernel.unprivileged_bpf_disabled=1
  PASS  kernel.yama.ptrace_scope=2
  PASS  module.sig_enforce active

── 9. Module blacklist ───────────────────────────────────
  PASS  Module bluetooth not loaded
  PASS  Module btusb not loaded
  PASS  Module firewire_core not loaded
  PASS  Module thunderbolt not loaded
  PASS  Module uvcvideo not loaded

── 10. RAM-only / no persistence ───────────────────────
  PASS  Sentinel file written to tmpfs
  PASS  Sentinel file is on tmpfs (will not survive reboot)

════════════════════════════════════════════════════════
  Results: 37 passed, 0 failed, 0 skipped (37 total)
════════════════════════════════════════════════════════

  ✓ All hardware validation checks passed
```

---

## Step 7 — Manual checks (cannot be automated)

After the automated suite passes, perform these four manual checks:

### 7.1 Reboot persistence test

```bash
# On the node: create a sentinel file
echo "this should not survive" > /tmp/reboot-test

# Reboot the node
reboot
# (wait for it to come back up)

# Check the file is gone
ssh root@[200:your:node::1] "test ! -f /tmp/reboot-test && echo PASS || echo FAIL"
# Expected: PASS
```

### 7.2 USB key removal test

```bash
# On the node: physically remove the USB key device
# (simulate seizure of separate hardware)

# Check that the node refused to start zksn-node without the key
ssh root@[200:your:node::1] "systemctl status zksn-node"
# Expected: zksn-node.service failed or inactive
# (identity.key not accessible → preStart fails)

# Re-insert the USB and reboot
# Expected: node comes back up cleanly
```

### 7.3 Read-only nix store test

```bash
# On the node: attempt to write to /nix/store
ssh root@[200:your:node::1] "touch /nix/store/test && echo FAIL || echo PASS"
# Expected: PASS (write refused)
```

### 7.4 Non-Yggdrasil connection test

```bash
# From a machine NOT on Yggdrasil (a plain internet machine):
nc -z -w 3 <clearnet-ip-of-node> 9001
# Expected: connection refused or timeout
# (firewall drops all non-200::/7 inbound on port 9001)
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| dm-verity FAIL | `/nix` not built with verity hash tree | Re-run step 3 with `veritysetup format` |
| LUKS2 FAIL | USB not labelled `ZKSN-KEYS` or not connected | `cryptsetup luksOpen /dev/sdX zksn-keys --label ZKSN-KEYS` |
| Yggdrasil FAIL | No peers configured or peer unreachable | Add peers to `node.nix` and redeploy |
| Port 9001 FAIL | `YGGDRASIL_ADDR_PLACEHOLDER` not patched | Check `preStart` log: `journalctl -u zksn-node` |
| sysctl FAIL | Kernel cmdline params not applied | Verify `/proc/cmdline` contains `module.sig_enforce=1` |
| Module FAIL | Module loaded by another service | Add to `boot.blacklistedKernelModules` and rebuild |
