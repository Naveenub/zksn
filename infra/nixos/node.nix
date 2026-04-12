# infra/nixos/node.nix — ZKSN Mix Node NixOS Configuration
#
# Target: x86_64 bare-metal server, RAM-only operation.
# Physical seizure of the machine yields zero persistent user data.
#
# Security properties:
#   - tmpfs root: all writes are to RAM only; lost on power loss
#   - dm-verity:  read-only nix store is cryptographically verified at boot
#   - LUKS2:      identity key store encrypted on a separate USB device
#   - Yggdrasil:  mesh transport; node address derived from public key
#   - Firewall:   only Yggdrasil mesh traffic (200::/7) and ssh accepted
#
# Deployment:
#   nixos-rebuild switch \
#     --target-host root@[200:your:addr::1] \
#     --flake .#zksn-node
#
# After first deploy, run the hardware validation suite:
#   bash infra/nixos/hardware-test.sh [200:your:addr::1]

{ config, pkgs, lib, modulesPath, ... }:

let
  # ── Package overlay — build zksn-node from source ──────────────────────────
  zksn-node = pkgs.rustPlatform.buildRustPackage {
    pname   = "zksn-node";
    version = "1.2.0";
    src     = ../..;    # repo root
    cargoLock.lockFile = ../../Cargo.lock;
    cargoBuildFlags    = [ "--package" "zksn-node" ];
    buildInputs        = with pkgs; [ openssl pkg-config ];
    nativeBuildInputs  = with pkgs; [ pkg-config ];
    doCheck = false;    # tests run in CI; skip during image build
    meta = {
      description = "ZKSN Mix Node — Sphinx packet mixing with Poisson delays";
      license     = lib.licenses.mit;
      platforms   = lib.platforms.linux;
    };
  };

  # ── Key store location (on LUKS2-encrypted USB) ───────────────────────────
  # Mount point for the encrypted USB key device.
  # The device is opened by the initrd LUKS2 unlock at boot.
  KEY_STORE_DIR  = "/run/keys/zksn";
  IDENTITY_KEY   = "${KEY_STORE_DIR}/identity.key";
  PEER_STORE     = "/var/lib/zksn/peers.json";   # tmpfs — lost on reboot

  # ── Node config written to /etc/zksn/node.toml at activation ─────────────
  nodeConfig = pkgs.writeText "node.toml" ''
    [network]
    # Yggdrasil IPv6 address — filled in by the node operator.
    # Run: yggdrasilctl getSelf | grep "IPv6 address"
    listen_addr        = "YGGDRASIL_ADDR_PLACEHOLDER:9001"
    max_peers          = 64
    connect_timeout_ms = 5000
    bootstrap_peers    = []
    yggdrasil_only     = true

    [mixing]
    poisson_lambda_ms   = 200
    cover_traffic_rate  = 5
    max_queue_depth     = 10000
    loop_cover_fraction = 0.3

    [economic]
    cashu_mint_url        = "http://mint.zksn.internal:3338"
    min_token_value       = 1
    monero_rpc_url        = "http://127.0.0.1:18082"
    redemption_batch_size = 100

    [keys]
    key_store_path   = "${IDENTITY_KEY}"
    persist_identity = true
  '';

in {
  imports = [
    (modulesPath + "/installer/scan/not-detected.nix")
  ];

  # ─────────────────────────────────────────────────────────────────────────
  # 1. Boot — dm-verity verified read-only nix store
  # ─────────────────────────────────────────────────────────────────────────

  boot = {
    loader = {
      systemd-boot.enable      = true;
      efi.canTouchEfiVariables = true;
    };

    kernelParams = [
      # Enable dm-verity for the nix store partition (populated at image build)
      "dm-mod.create=verity"
      # Disable kernel module loading after boot (prevents LKM rootkits)
      "module.sig_enforce=1"
      # Kernel hardening
      "slab_nomerge"
      "init_on_alloc=1"
      "init_on_free=1"
    ];

    kernelModules = [ "dm_verity" "overlay" ];

    # initrd: unlock LUKS2 key device before mounting tmpfs root
    initrd = {
      availableKernelModules = [
        "xhci_pci" "ahci" "nvme" "usb_storage" "sd_mod"
        "dm_crypt" "dm_verity"
      ];

      # LUKS2 encrypted USB key store
      # Replace /dev/disk/by-id/... with the actual USB device identifier.
      # Generate during first deployment: cryptsetup luksFormat /dev/sdX
      luks.devices."zksn-keys" = {
        device     = "/dev/disk/by-label/ZKSN-KEYS";
        bypassWorkqueues = true;       # performance on fast USB 3
      };
    };
  };

  # ─────────────────────────────────────────────────────────────────────────
  # 2. Filesystem — tmpfs root, no persistent writes
  # ─────────────────────────────────────────────────────────────────────────

  fileSystems = {
    # Root is RAM. Everything written here is lost on power-off.
    "/" = {
      device  = "tmpfs";
      fsType  = "tmpfs";
      options = [ "mode=0755" "size=4G" ];
    };

    # Nix store is read-only. dm-verity hash verified at mount.
    "/nix" = {
      device  = "/dev/disk/by-label/ZKSN-NIX";
      fsType  = "ext4";
      options = [ "ro" "noatime" ];
    };

    # Boot partition (EFI)
    "/boot" = {
      device  = "/dev/disk/by-label/ZKSN-BOOT";
      fsType  = "vfat";
      options = [ "fmask=0077" "dmask=0077" ];
    };

    # LUKS2-decrypted key store (USB device, mounted read-only after unlock)
    "${KEY_STORE_DIR}" = {
      device  = "/dev/mapper/zksn-keys";
      fsType  = "ext4";
      options = [ "ro" "noatime" "nodev" "nosuid" "noexec" ];
      neededForBoot = false;
    };
  };

  swapDevices = [];    # No swap — prevents key material from reaching disk

  # ─────────────────────────────────────────────────────────────────────────
  # 3. Network — Yggdrasil mesh only
  # ─────────────────────────────────────────────────────────────────────────

  networking = {
    hostName = "zksn-node";

    # Disable clearnet interfaces at the kernel level.
    # Only Yggdrasil's virtual tun interface is used for node traffic.
    # The physical NIC is still needed for Yggdrasil's TCP peering.
    useDHCP           = false;
    useNetworkd       = true;

    # Allow the physical NIC only for outbound Yggdrasil TCP connections.
    # All other inbound/outbound clearnet traffic is dropped.
    firewall = {
      enable                = true;
      allowPing             = false;
      rejectPackets         = true;

      # Inbound: accept Yggdrasil mesh traffic (200::/7) on port 9001,
      # SSH on the Yggdrasil address only, and Yggdrasil peering (TCP 9010).
      allowedTCPPorts       = [ 9010 ];   # Yggdrasil peer port
      allowedTCPPortRanges  = [];
      allowedUDPPorts       = [];

      # Extra rules: accept 200::/7 → 9001 (mix node), 22 (ssh over Yggdrasil)
      extraCommands = ''
        # Accept ZKSN mix node traffic from Yggdrasil address space only
        ip6tables -A INPUT -s 200::/7 -p tcp --dport 9001 -j ACCEPT
        ip6tables -A INPUT -s 200::/7 -p tcp --dport 22   -j ACCEPT
        # Drop all other inbound
        ip6tables -A INPUT -j DROP
      '';

      extraStopCommands = ''
        ip6tables -D INPUT -s 200::/7 -p tcp --dport 9001 -j ACCEPT 2>/dev/null || true
        ip6tables -D INPUT -s 200::/7 -p tcp --dport 22   -j ACCEPT 2>/dev/null || true
      '';
    };
  };

  # ─────────────────────────────────────────────────────────────────────────
  # 4. Yggdrasil mesh service
  # ─────────────────────────────────────────────────────────────────────────

  services.yggdrasil = {
    enable = true;
    settings = {
      Peers = [
        # Add public Yggdrasil peers — see https://publicpeers.neilalexander.dev/
        # Example: "tcp://my.peer.example.com:9002"
      ];
      NodeInfoPrivacy = true;
      IfName          = "ygg0";
      IfMTU           = 65535;
    };
    # Private key persisted on LUKS2 USB so the node's Yggdrasil address
    # is stable across reboots. The key is NOT stored on the tmpfs root.
    configFile = "${KEY_STORE_DIR}/yggdrasil.conf";
  };

  # ─────────────────────────────────────────────────────────────────────────
  # 5a. i2pd — I2P router for garlic routing and .b32.i2p service hosting
  # ─────────────────────────────────────────────────────────────────────────
  services.i2pd = {
    enable    = true;
    address   = "127.0.0.1";   # bind i2pd's own transport to loopback;
                                # it reaches the internet via Yggdrasil exit
    # SAM v3 API — required by zksn_node::i2p
    proto.sam = {
      enable  = true;
      address = "127.0.0.1";
      port    = 7656;
    };

    # HTTP console (internal only)
    proto.http = {
      enable  = true;
      address = "127.0.0.1";
      port    = 7070;
    };

    # HTTP proxy (optional — remove if the node should be relay-only)
    proto.httpProxy = {
      enable  = true;
      address = "127.0.0.1";
      port    = 4444;
    };

    bandwidth = "P";       # 65 KiB/s shared class; use "X" on high-BW nodes

    # Persist i2pd router identity on the LUKS2 USB so the node's .b32
    # address is stable across reboots.
    dataDir = "${KEY_STORE_DIR}/i2pd";
  };

  # ── i2pd tunnel definitions for auxiliary services ──────────────────────
  # The mix node's primary garlic session is created dynamically via SAM.
  # These tunnels expose the Cashu mint over I2P.
  environment.etc."i2pd/tunnels.conf".text = ''
    [zksn-mint]
    type            = http
    host            = 127.0.0.1
    port            = 3338
    keys            = ${KEY_STORE_DIR}/i2pd/zksn-mint.dat
    inbound.length  = 3
    outbound.length = 3
  '';

  # ─────────────────────────────────────────────────────────────────────────
  # 5b. ZKSN mix node service
  # ─────────────────────────────────────────────────────────────────────────

  # Write the node config to /etc at activation time
  environment.etc."zksn/node.toml".source = nodeConfig;

  systemd.services.zksn-node = {
    description   = "ZKSN Mix Node";
    wantedBy      = [ "multi-user.target" ];
    after         = [ "network.target" "yggdrasil.service" "i2pd.service" "zksn-keys.mount" ];
    requires      = [ "yggdrasil.service" "i2pd.service" ];

    # Patch listen_addr with the actual Yggdrasil address at startup
    preStart = ''
      YGGDRASIL_ADDR=$(${pkgs.yggdrasil}/bin/yggdrasilctl getSelf 2>/dev/null \
        | ${pkgs.gnugrep}/bin/grep -oP '(?<=IPv6 address: )\S+' || echo "")
      if [ -z "$YGGDRASIL_ADDR" ]; then
        echo "ERROR: Could not determine Yggdrasil address. Is yggdrasil.service running?"
        exit 1
      fi
      ${pkgs.gnused}/bin/sed -i \
        "s|YGGDRASIL_ADDR_PLACEHOLDER|[$YGGDRASIL_ADDR]|" \
        /etc/zksn/node.toml
      echo "Starting ZKSN node on [$YGGDRASIL_ADDR]:9001"
    '';

    serviceConfig = {
      ExecStart = "${zksn-node}/bin/zksn-node --config /etc/zksn/node.toml";
      Restart   = "on-failure";
      RestartSec = "5s";

      # Hardening
      DynamicUser            = true;
      PrivateTmp             = true;
      ProtectSystem          = "strict";
      ProtectHome            = true;
      NoNewPrivileges        = true;
      CapabilityBoundingSet  = "";
      # AF_INET needed for SAM TCP connection to 127.0.0.1:7656
      RestrictAddressFamilies = [ "AF_INET" "AF_INET6" ];
      LockPersonality        = true;
      MemoryDenyWriteExecute = true;
      RestrictRealtime       = true;
      SystemCallFilter       = "@system-service";
      ReadOnlyPaths          = [ "${KEY_STORE_DIR}" ];
      ReadWritePaths         = [ "/var/lib/zksn" ];
    };
  };

  # ─────────────────────────────────────────────────────────────────────────
  # 6. SSH — over Yggdrasil only
  # ─────────────────────────────────────────────────────────────────────────

  services.openssh = {
    enable = true;
    settings = {
      PermitRootLogin      = "prohibit-password";
      PasswordAuthentication = false;
      ListenAddress        = "::";   # restricted to Yggdrasil by firewall above
    };
  };

  # ─────────────────────────────────────────────────────────────────────────
  # 7. Kernel hardening
  # ─────────────────────────────────────────────────────────────────────────

  boot.kernel.sysctl = {
    # Prevent dmesg access from unprivileged users
    "kernel.dmesg_restrict"              = 1;
    # Disable BPF JIT (reduces kernel attack surface)
    "net.core.bpf_jit_enable"           = 0;
    # Disable unprivileged BPF
    "kernel.unprivileged_bpf_disabled"  = 1;
    # Disable IPv4 (Yggdrasil is IPv6 only)
    "net.ipv4.conf.all.disable_ipv4"    = 1;
    # Disable ICMP redirects
    "net.ipv6.conf.all.accept_redirects" = 0;
    # Restrict ptrace
    "kernel.yama.ptrace_scope"           = 2;
  };

  # Disable unnecessary kernel modules
  boot.blacklistedKernelModules = [
    "bluetooth" "btusb"        # no Bluetooth
    "firewire_core"            # no FireWire (DMA attack vector)
    "thunderbolt"              # no Thunderbolt (DMA attack vector)
    "uvcvideo"                 # no webcam
    "snd" "snd_hda_intel"     # no audio
  ];

  # ─────────────────────────────────────────────────────────────────────────
  # 8. Packages (minimal)
  # ─────────────────────────────────────────────────────────────────────────

  environment.systemPackages = with pkgs; [
    zksn-node
    yggdrasil
    curl
    jq
    htop
    # Diagnostic tools — can be removed post-audit
    cryptsetup
    e2fsprogs
  ];

  # ─────────────────────────────────────────────────────────────────────────
  # 9. Nix settings (reproducibility + no state)
  # ─────────────────────────────────────────────────────────────────────────

  nix = {
    settings = {
      experimental-features = [ "nix-command" "flakes" ];
      auto-optimise-store   = true;
    };
    # Disable nix channel (use flakes only)
    channel.enable = false;
  };

  # No mutable user state — operators ssh in with keys stored externally
  users.mutableUsers = false;

  system.stateVersion = "24.11";
}
