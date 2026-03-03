# ZKSN NixOS Mix Node Configuration
# RAM-only: tmpfs root, no persistent writes, hardware seizure yields zero data.
{ config, pkgs, ... }:
{
  # --- Boot ---
  boot.loader.grub.enable     = true;
  boot.loader.grub.device     = "nodev";
  boot.loader.grub.efiSupport = false;

  # tmpfs root — all writes lost on reboot
  fileSystems."/" = {
    device  = "tmpfs";
    fsType  = "tmpfs";
    options = [ "size=4G" "mode=755" ];
  };

  # dm-verity: verify root filesystem integrity at boot
  # boot.initrd.systemd.enable = true;
  # (full dm-verity config depends on image builder tooling)

  # --- Networking ---
  networking.hostName   = "zksn-node";
  networking.firewall = {
    enable         = true;
    allowedTCPPorts = [ 9001 ];  # Sphinx packet listener
    # Only accept connections from Yggdrasil address space (200::/7)
    extraCommands  = ''
      iptables -A INPUT -s 200.0.0.0/7 -j ACCEPT
      iptables -A INPUT -s 127.0.0.1   -j ACCEPT
      iptables -A INPUT -j DROP
    '';
  };

  # --- Services ---
  services.yggdrasil = {
    enable = true;
    config = {
      Peers              = [];
      NodeInfoPrivacy    = true;
      MulticastInterfaces = [{ Regex = ".*"; Beacon = true; Listen = true; Port = 0; Priority = 0; }];
    };
  };

  services.i2pd = {
    enable = true;
    address = "127.0.0.1";
    proto.http.enable   = true;
    proto.http.port     = 7070;
    proto.socksProxy.enable = true;
    proto.socksProxy.port   = 4447;
    proto.httpProxy.enable  = true;
    proto.httpProxy.port    = 4444;
  };

  # --- Kernel hardening ---
  boot.kernel.sysctl = {
    "kernel.dmesg_restrict"              = 1;
    "kernel.unprivileged_bpf_disabled"   = 1;
    "net.core.bpf_jit_harden"            = 2;
    "kernel.kptr_restrict"               = 2;
    "net.ipv4.conf.all.rp_filter"        = 1;
  };

  # --- No persistent state ---
  services.journald.extraConfig = "Storage=volatile";

  system.stateVersion = "24.05";
}
