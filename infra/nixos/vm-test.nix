# infra/nixos/vm-test.nix — QEMU-based pre-deploy smoke test for node.nix
#
# Validates the subset of node.nix's security properties that don't require
# real hardware. dm-verity partitions, LUKS2 USB unlock, and actual
# power-loss/seizure behavior stay manual/physical — see hardware-test.sh
# checks 4–13 and infra/nixos/README.md.
#
# This file intentionally does NOT import node.nix: node.nix's fileSystems
# reference real block devices by label (ZKSN-NIX-DATA, ZKSN-KEYS, ...) that
# don't exist in a VM, so importing it here would just fail to boot. Instead
# this re-declares the hardware-independent subset (kernel hardening, systemd
# service sandboxing, yggdrasil/i2pd services, firewall) so it can be checked
# in isolation. Keep this in sync with node.nix when those sections change.
#
# Run:
#   nix-build infra/nixos/vm-test.nix
# or, with flakes:
#   nix build -f infra/nixos/vm-test.nix

{ pkgs ? import <nixpkgs> {} }:

pkgs.nixosTest {
  name = "zksn-node-vm-smoke-test";

  nodes.node = { config, pkgs, lib, ... }: {
    # ── Mirrors node.nix boot.kernel.sysctl ────────────────────────────────
    boot.kernel.sysctl = {
      "kernel.dmesg_restrict"              = 1;
      "net.core.bpf_jit_enable"            = 0;
      "kernel.unprivileged_bpf_disabled"   = 1;
      "net.ipv6.conf.all.accept_redirects" = 0;
      "kernel.yama.ptrace_scope"           = 2;
      "net.ipv4.conf.all.disable_ipv4"     = 1;
      "net.ipv4.conf.default.disable_ipv4" = 1;
    };

    # ── Mirrors node.nix boot.blacklistedKernelModules ────────────────────
    boot.blacklistedKernelModules = [
      "bluetooth" "btusb" "firewire_core" "thunderbolt" "uvcvideo"
      "snd" "snd_hda_intel"
    ];

    # ── Mirrors node.nix networking.firewall ───────────────────────────────
    networking.firewall = {
      enable          = true;
      allowPing       = false;
      rejectPackets   = true;
      allowedTCPPorts = [ 9010 ];
      extraCommands = ''
        ip6tables -A INPUT -s 200::/7 -p tcp --dport 9001 -j ACCEPT
        ip6tables -A INPUT -s 200::/7 -p tcp --dport 22   -j ACCEPT
        ip6tables -A INPUT -j DROP
      '';
      extraStopCommands = ''
        ip6tables -D INPUT -s 200::/7 -p tcp --dport 9001 -j ACCEPT 2>/dev/null || true
        ip6tables -D INPUT -s 200::/7 -p tcp --dport 22   -j ACCEPT 2>/dev/null || true
      '';
    };

    # ── Mirrors node.nix services.yggdrasil ────────────────────────────────
    services.yggdrasil = {
      enable = true;
      settings = {
        NodeInfoPrivacy = true;
        IfName          = "ygg0";
        IfMTU           = 65535;
      };
    };

    # ── Mirrors node.nix services.i2pd ──────────────────────────────────────
    services.i2pd = {
      enable  = true;
      address = "127.0.0.1";
      proto.sam.enable  = true;
      proto.sam.address = "127.0.0.1";
      proto.sam.port    = 7656;
    };

    # ── Stub of zksn-node.service — same systemd sandboxing directives as
    # node.nix, standing in for the real Rust binary (building it from
    # source is out of scope for a boot-property smoke test; the binary
    # itself is exercised in CI, not here).
    systemd.services.zksn-node-stub = {
      description = "ZKSN Mix Node (VM test stub)";
      wantedBy    = [ "multi-user.target" ];
      serviceConfig = {
        ExecStart                = "${pkgs.coreutils}/bin/sleep infinity";
        Restart                  = "on-failure";
        DynamicUser              = true;
        PrivateTmp               = true;
        ProtectSystem            = "strict";
        ProtectHome              = true;
        NoNewPrivileges          = true;
        CapabilityBoundingSet    = "";
        RestrictAddressFamilies  = [ "AF_INET" "AF_INET6" ];
        LockPersonality          = true;
        MemoryDenyWriteExecute   = true;
        RestrictRealtime         = true;
        SystemCallFilter         = "@system-service";
      };
    };

    swapDevices          = [];
    users.mutableUsers   = false;
    system.stateVersion  = "24.11";
  };

  testScript = ''
    node.wait_for_unit("multi-user.target")

    with subtest("kernel hardening sysctls applied"):
        node.succeed("sysctl kernel.dmesg_restrict | grep -q '= 1'")
        node.succeed("sysctl kernel.unprivileged_bpf_disabled | grep -q '= 1'")
        node.succeed("sysctl kernel.yama.ptrace_scope | grep -q '= 2'")
        node.succeed("sysctl net.ipv4.conf.all.disable_ipv4 | grep -q '= 1'")

    with subtest("blacklisted modules not loaded"):
        for mod in ["bluetooth", "btusb", "firewire_core", "thunderbolt", "uvcvideo"]:
            node.fail(f"grep -q '^{mod} ' /proc/modules")

    with subtest("zksn-node-stub sandboxing directives applied"):
        node.wait_for_unit("zksn-node-stub.service")
        node.succeed("systemctl show zksn-node-stub --property=NoNewPrivileges | grep -q yes")
        node.succeed("systemctl show zksn-node-stub --property=MemoryDenyWriteExecute | grep -q yes")
        node.succeed("systemctl show zksn-node-stub --property=DynamicUser | grep -q yes")
        node.succeed("systemctl show zksn-node-stub --property=RestrictAddressFamilies | grep -q AF_INET6")

    with subtest("yggdrasil and i2pd services reach active"):
        node.wait_for_unit("yggdrasil.service")
        node.wait_for_unit("i2pd.service")

    with subtest("firewall drops non-allowlisted inbound"):
        node.succeed("ip6tables -L INPUT | grep -q DROP")
  '';
}
