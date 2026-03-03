{
  description = "ZKSN — Zero-Knowledge Sovereign Network dev environment";

  inputs = {
    nixpkgs.url       = "github:NixOS/nixpkgs/nixos-24.05";
    rust-overlay.url  = "github:oxalica/rust-overlay";
    flake-utils.url   = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays     = [ (import rust-overlay) ];
        pkgs         = import nixpkgs { inherit system overlays; };
        rustToolchain = pkgs.rust-bin.stable."1.78.0".default.override {
          extensions = [ "rust-src" "rust-analyzer" "clippy" "rustfmt" "llvm-tools" ];
        };
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustToolchain
            yggdrasil
            i2pd
            just
            jq
            curl
            git
            openssl
            pkg-config
          ];
          shellHook = ''
            echo "ZKSN dev environment ready."
            echo "  just --list    # see all commands"
            echo "  just test-all  # run all tests"
          '';
        };
      });
}
