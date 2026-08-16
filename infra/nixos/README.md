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

Boot the NixOS installer. Partition the target disk with four partitions:

```bash
# Identify your disk (usually /dev/sda or /dev/nvme0n1)
lsblk

# Partition layout:
#   sda1  512M   EFI       label: ZKSN-BOOT
#   sda2  rest-1G ext4     label: ZKSN-NIX-DATA  (nix store, dm-verity data device)
#   sda3  1G     (none)    label: ZKSN-NIX-HASH  (dm-verity hash tree — raw device, no fs)

parted /dev/sda -- mklabel gpt
parted /dev/sda -- mkpart ESP   fat32 1MB    512MB
parted /dev/sda -- mkpart Nix   ext4  512MB  -1GB
parted /dev/sda -- mkpart Hash  ""    -1GB   100%
parted /dev/sda -- set 1 esp on

mkfs.fat  -F 32 -n ZKSN-BOOT      /dev/sda1
mkfs.ext4       -L ZKSN-NIX-DATA  /dev/sda2
# sda3 is left unformatted — veritysetup writes its own hash-tree superblock.
```

The hash tree lives on its own raw partition, not a loopback file: `dm-verity`
must open it as a block device during initrd, before any filesystem-backed
storage is available.

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

## Step 3 — Build and install, then seal it with dm-verity

**This step runs on your build machine, not the target node.**

```bash
cd /path/to/zksn

# Build the NixOS system
nix build .#nixosConfigurations.zksn-node.config.system.build.toplevel

# Install to the target disk (target must be mounted at /mnt)
mount /dev/sda2 /mnt/nix
NIXOS_INSTALL_BOOTLOADER=1 nixos-install \
  --system ./result \
  --root /mnt

# Generate the dm-verity hash tree from the now-installed nix store.
# Data device = the partition just populated by nixos-install.
# Hash device = the raw sda3 partition — do NOT put the hash tree in a
# loopback file; initrd can only open real block devices pre-root.
veritysetup format /dev/sda2 /dev/sda3 | tee /tmp/verity-info.txt
ROOT_HASH=$(grep "Root hash:" /tmp/verity-info.txt | awk '{print $3}')
echo "dm-verity root hash: $ROOT_HASH"

# Write the hash to the unprotected ESP — NOT into the nix store — so it
# never becomes part of the data being hashed (self-reference is
# unsolvable: any value baked into the store changes the store, which
# changes the hash). node.nix's postDeviceCommands reads it from the
# kernel cmdline at boot; extraInstallCommands re-attaches it to every
# new generation's boot entry automatically, so this write is one-time.
echo "$ROOT_HASH" > /mnt/boot/zksn-verity-hash.txt

# Re-run the bootloader install so extraInstallCommands picks up the
# hash file just written and appends zksn.verityhash= to the entry.
nixos-enter --root /mnt -- /run/current-system/bin/switch-to-configuration boot
```

On every subsequent `nixos-rebuild switch --target-host ...`, the same
`extraInstallCommands` hook re-reads `/boot/zksn-verity-hash.txt` (which
persists on the ESP across redeploys) and re-attaches it to the new
generation's entry automatically — no manual edit needed after the first
install, unless the store itself gets a full re-image (new data partition
contents), which requires repeating the `veritysetup format` step above.

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

## Step 5b — Pre-deploy VM smoke test (no hardware required)

Before touching physical gear, sanity-check the config in a QEMU VM. This
catches sysctl typos, systemd hardening regressions, and service startup
failures early — it does **not** exercise dm-verity, LUKS2, or actual
power-loss behavior, since those need real block devices (see the table
above; run `hardware-test.sh` on real hardware for those).

```bash
nix-build infra/nixos/vm-test.nix
# or, with flakes:
nix build -f infra/nixos/vm-test.nix
```

A clean run exits 0 with all subtests passing. Any failure here means don't
bother provisioning hardware yet — fix it in the VM first.

---

## Step 6 — Run the hardware validation suite

After the node boots and `zksn-node.service` is active (wait ~30 seconds):

```bash
# From your local machine — pass a second argument to also write a
# machine-readable JSON attestation record (see infra/nixos/ATTESTATION.md)
bash infra/nixos/hardware-test.sh [200:your:node:addr::1] infra/nixos/attestation-$(date +%Y%m%d).json

# Or copy to the node and run locally
scp infra/nixos/hardware-test.sh root@[200:your:node::1]:/tmp/
ssh root@[200:your:node::1] bash /tmp/hardware-test.sh "" /tmp/attestation.json
```

After a clean run, fill in `infra/nixos/ATTESTATION.md` with the output above,
the four manual checks in Step 7, and commit the JSON record — this is the
checked-in proof that phase 5 has actually been validated on real hardware.

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
