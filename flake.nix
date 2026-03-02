{
  description = "Zero-Knowledge Sovereign Network — development environment";

  inputs = {
    nixpkgs.url       = "github:NixOS/nixpkgs/nixos-24.05";
    rust-overlay.url  = "github:oxalica/rust-overlay";
    flake-utils.url   = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };

        # Pinned Rust toolchain — deterministic builds
        rustToolchain = pkgs.rust-bin.stable."1.78.0".default.override {
          extensions = [ "rust-src" "rust-analyzer" "clippy" "rustfmt" "llvm-tools" ];
          targets    = [ "x86_64-unknown-linux-gnu" "aarch64-unknown-linux-gnu" ];
        };

      in {
        # =====================================================================
        # Development shell: nix develop
        # =====================================================================
        devShells.default = pkgs.mkShell {
          name = "zksn-dev";

          buildInputs = with pkgs; [
            # Rust toolchain
            rustToolchain
            cargo-watch         # cargo watch -x test
            cargo-audit         # dependency CVE scanning
            cargo-expand        # macro expansion
            cargo-flamegraph    # performance profiling

            # ZKSN infrastructure
            yggdrasil           # encrypted mesh transport
            i2pd                # anonymous service layer

            # Smart contract toolchain (governance)
            foundry             # forge + cast + anvil

            # Cryptography
            openssl
            gnupg
            age                 # modern encryption

            # Development utilities
            just                # command runner (Justfile)
            jq                  # JSON processing
            curl
            wget
            git

            # Nix tooling
            nixfmt              # .nix file formatter
          ];

          shellHook = ''
            echo ""
            echo "  ╔══════════════════════════════════════════╗"
            echo "  ║    ZKSN Development Environment          ║"
            echo "  ╚══════════════════════════════════════════╝"
            echo ""
            echo "  Rust:       $(rustc --version)"
            echo "  Cargo:      $(cargo --version)"
            echo ""
            echo "  Commands:"
            echo "    just           — list all available commands"
            echo "    just test      — run all tests"
            echo "    just build     — build all crates"
            echo "    just node      — start a local dev mix node"
            echo "    just devnet    — start local Docker devnet"
            echo ""
            export RUST_BACKTRACE=1
            export RUST_LOG=zksn=debug,warn
          '';
        };

        # =====================================================================
        # Production node package
        # =====================================================================
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname   = "zksn-node";
          version = "0.1.0";
          src     = ./.;

          cargoLock.lockFile = ./Cargo.lock;

          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs       = [ pkgs.openssl pkgs.openssl.dev ];

          meta = {
            description  = "Zero-Knowledge Sovereign Network — Mix Node";
            homepage     = "https://github.com/Naveenob/zksn";
            license      = pkgs.lib.licenses.mit;
            maintainers  = [];
          };
        };
      }
    );
}
