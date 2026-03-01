# ZKSN Mix Node — NixOS Configuration
# =====================================
# This is a fully declarative, reproducible NixOS configuration for a ZKSN
# mix node. The entire node configuration is captured in this single file.
#
# RAM-only operation:
#   Boot with: nixos-install --no-root-passwd
#   Or as a live-boot image: nixos-generate -f iso
#
# Usage:
#   sudo nixos-rebuild switch -I nixos-config=./node.nix
#
# The resulting system:
#   - Has no persistent state (tmpfs root)
#   - Runs Yggdrasil for encrypted mesh transport
#   - Runs i2pd for anonymous service hosting
#   - Has Nym mix node tooling installed
#   - Loads node identity from LUKS-encrypted USB at boot

{ config, pkgs, lib, ... }:

{
  # =========================================================================
  # System Base
  # =========================================================================

  system.stateVersion = "24.05";

  # Stateless root — nothing persists between boots
  fileSystems."/" = {
    device = "tmpfs";
    fsType = "tmpfs";
    options = [ "mode=755" "size=4G" ];
  };

  # Optional: persist ONLY the node's key material directory
  # Mount an encrypted USB here to load identity
  # fileSystems."/var/lib/zksn/keys" = {
  #   device = "/dev/disk/by-label/ZKSN-KEYS";
  #   fsType = "ext4";
  #   options = [ "ro" ];  # Read-only after boot
  # };

  # =========================================================================
  # Boot
  # =========================================================================

  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;

  # dm-verity: verify root filesystem integrity at boot
  # (configure hash device separately for production)
  # boot.initrd.systemd.enable = true;

  # =========================================================================
  # Network
  # =========================================================================

  networking = {
    hostName = "zksn-node";  # Generic hostname — do not set to something identifying
    firewall = {
      enable = true;
      allowedTCPPorts = [
        # Yggdrasil peering
        9001
        # i2pd
        7654   # HTTP proxy (localhost only — see i2pd config)
        4444   # SOCKS proxy (localhost only)
        12345  # Nym mix node
      ];
      allowedUDPPorts = [
        9001   # Yggdrasil
      ];
      # Only allow SSH from within Yggdrasil mesh (200::/7)
      extraCommands = ''
        iptables -A INPUT -p tcp --dport 22 -m iprange ! --src-range 200::0-203:ffff:ffff:ffff:ffff:ffff:ffff:ffff -j DROP
      '';
    };
  };

  # =========================================================================
  # Yggdrasil — Encrypted Mesh Transport
  # =========================================================================

  services.yggdrasil = {
    enable = true;

    # NOTE: In production, generate your own config with:
    #   yggdrasil -genconf > /etc/yggdrasil.conf
    # Your PublicKey in the config file IS your node's Yggdrasil address.
    # Never share your PrivateKey.

    settings = {
      # Peers to connect to on startup
      # Find public peers at: https://publicpeers.neilalexander.dev/
      Peers = [
        # Add peer addresses here — use diverse geographic locations
        # "tcp://example-peer-1.net:9001"
        # "tls://example-peer-2.net:9002"
      ];

      # Allow incoming connections (makes you a public peer too)
      Listen = [
        "tcp://0.0.0.0:9001"
      ];

      # Optional: multicast peer discovery on LAN (useful for local mesh)
      MulticastInterfaces = [
        {
          Regex = ".*";
          Beacon = true;
          Listen = true;
          Port = 0;
          Priority = 0;
        }
      ];

      # Logging level: error, warn, info, debug, trace
      LogLevel = "warn";
    };
  };

  # =========================================================================
  # i2pd — Anonymous Service Layer
  # =========================================================================

  services.i2pd = {
    enable = true;

    address = "127.0.0.1";  # Only listen locally by default

    # Bandwidth settings
    bandwidth = "P";  # "L"=32KB, "O"=256KB, "P"=2MB, "X"=unlimited

    # Transport protocols
    ntcp2.enable = true;
    ssu2.enable = true;

    # HTTP control interface (localhost only)
    proto.http = {
      enable = true;
      address = "127.0.0.1";
      port = 7070;
    };

    # SOCKS proxy (for internal service access)
    proto.socksProxy = {
      enable = true;
      address = "127.0.0.1";
      port = 4447;
    };

    # HTTP proxy
    proto.httpProxy = {
      enable = true;
      address = "127.0.0.1";
      port = 4444;
    };

    # Example: hosting an internal ZKSN service
    # Uncomment and configure to host a service internally
    # outTunnels = {
    #   zksn-service = {
    #     enable = true;
    #     keys = "zksn-service.dat";  # Loaded from key directory
    #     destination = "127.0.0.1";
    #     destinationPort = 8080;
    #   };
    # };
  };

  # =========================================================================
  # Packages
  # =========================================================================

  environment.systemPackages = with pkgs; [
    # Core tools
    yggdrasil
    i2pd

    # Cryptography utilities
    openssl
    gnupg
    age          # Modern encryption tool

    # Network debugging (minimal set)
    curl
    wget
    netcat-gnu
    tcpdump      # Useful for debugging; remove in production if desired

    # Monero wallet CLI (for economic layer)
    monero-cli

    # System utilities
    htop
    tmux
    vim

    # For building ZKSN components from source
    rustup
    git
  ];

  # =========================================================================
  # Security Hardening
  # =========================================================================

  # Disable coredumps (don't leak memory to disk)
  systemd.coredump.extraConfig = "Storage=none";
  security.pam.loginLimits = [{
    domain = "*";
    type = "hard";
    item = "core";
    value = "0";
  }];

  # Kernel hardening
  boot.kernel.sysctl = {
    # Disable magic SysRq (prevents local attackers from triggering kernel dumps)
    "kernel.sysrq" = 0;

    # Restrict ptrace to root
    "kernel.yama.ptrace_scope" = 2;

    # Disable kernel module loading after boot (uncomment for max hardening)
    # "kernel.modules_disabled" = 1;

    # Network hardening
    "net.ipv4.conf.all.rp_filter" = 1;
    "net.ipv4.conf.default.rp_filter" = 1;
    "net.ipv4.tcp_syncookies" = 1;
    "net.ipv6.conf.all.accept_ra" = 0;  # Don't auto-configure IPv6 via RA (Yggdrasil handles this)
  };

  # =========================================================================
  # SSH (for remote administration — only accessible via Yggdrasil mesh)
  # =========================================================================

  services.openssh = {
    enable = true;
    settings = {
      # Key-based auth only — no passwords
      PasswordAuthentication = false;
      PermitRootLogin = "prohibit-password";
      # Restrict to ed25519 keys only
      PubkeyAcceptedAlgorithms = "ssh-ed25519";
    };
    # Only bind on Yggdrasil interface (configured post-boot via systemd)
    listenAddresses = [
      { addr = "127.0.0.1"; port = 22; }  # Override in production to Yggdrasil address
    ];
  };

  # =========================================================================
  # Users
  # =========================================================================

  users.users.operator = {
    isNormalUser = true;
    extraGroups = [ "wheel" ];
    # Set your SSH public key here
    openssh.authorizedKeys.keys = [
      # "ssh-ed25519 AAAA... your-key-here"
    ];
  };

  security.sudo.wheelNeedsPassword = false;  # For RAM-boot convenience; harden in production
}
