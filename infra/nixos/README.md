# ZKSN NixOS Node Deployment

This directory contains NixOS configuration for deploying ZKSN mix nodes.

## Prerequisites

- A machine (physical or VPS) with NixOS installed, OR
- An existing Linux machine where you'll install NixOS fresh

**Recommended hardware:**
- x86_64 or ARM64 (Raspberry Pi 4/5 supported)
- 2GB RAM minimum (4GB+ recommended)
- No persistent storage required (RAM-only operation)

## Quick Deploy

### 1. Install NixOS

Follow the [official NixOS installation guide](https://nixos.org/manual/nixos/stable/#sec-installation).

For a RAM-boot live node, generate an ISO:

```bash
# Requires nixos-generators
nix run github:nix-community/nixos-generators -- \
  -f iso \
  -c node.nix \
  -o result/

# Flash to USB
sudo dd if=result/iso/*.iso of=/dev/sdX bs=4M status=progress
```

### 2. Generate Node Identity

Before booting:

```bash
# On a SEPARATE air-gapped machine (Tails OS recommended)
../../scripts/gen-identity.sh ./keys/
```

Store the generated `identity.key` on an encrypted USB (LUKS2):

```bash
# Create encrypted partition
sudo cryptsetup luksFormat /dev/sdY
sudo cryptsetup open /dev/sdY zksn-keys
sudo mkfs.ext4 /dev/mapper/zksn-keys
sudo mount /dev/mapper/zksn-keys /mnt/keys
sudo cp ./keys/identity.key /mnt/keys/
sudo umount /mnt/keys
sudo cryptsetup close zksn-keys
```

### 3. Configure Yggdrasil Peers

Edit `node.nix` and add peers to the `Peers` list:

```nix
Peers = [
  "tcp://[peer-yggdrasil-address]:9001"
];
```

Find public peers at: https://publicpeers.neilalexander.dev/

### 4. Deploy

```bash
sudo nixos-rebuild switch -I nixos-config=./node.nix
```

### 5. Verify

```bash
# Check Yggdrasil is running and has peers
sudo yggdrasilctl getPeers

# Check your Yggdrasil address
sudo yggdrasilctl getSelf

# Check i2pd is running
curl http://127.0.0.1:7070/  # i2pd web console
```

## Production Hardening Checklist

- [ ] Uncomment `kernel.modules_disabled = 1` in kernel sysctl (prevents LKM attacks)
- [ ] Change SSH listen address to your Yggdrasil address only
- [ ] Add your SSH public key to `operator.openssh.authorizedKeys`
- [ ] Set `security.sudo.wheelNeedsPassword = true`
- [ ] Configure dm-verity for boot image verification
- [ ] Enable LUKS2 encrypted key storage mount
- [ ] Remove `tcpdump` from system packages
- [ ] Review and minimize firewall rules

## Raspberry Pi Specific

For Pi 4/5 deployment:

```nix
# Add to node.nix
{
  # Pi-specific hardware support
  imports = [ "${nixpkgs}/nixos/modules/installer/sd-card/sd-image-aarch64.nix" ];
  
  # Pi-specific boot
  boot.loader.grub.enable = false;
  boot.loader.generic-extlinux-compatible.enable = true;
}
```

Generate SD card image:
```bash
nix run github:nix-community/nixos-generators -- \
  -f sd-aarch64 \
  -c node.nix
```
