# Changelog

All notable changes to ZKSN will be documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### Added
- Initial repository scaffold
- `crypto` crate: Ed25519 identity, Noise_XX handshake, Sphinx packet format (partial), ZKP membership utilities
- `node` crate: Poisson mixer, cover traffic generator, TCP listener, packet router, Prometheus metrics
- `client` crate: Send/receive API, CLI (`zksn identity|send|receive|wallet`)
- `economic` crate: Cashu ecash wallet, Monero RPC interface, per-packet token format
- `governance/`: ZKSNGovernance Solidity contract with ZK-proof voting, MockVerifier, Foundry test suite
- `infra/nixos/`: RAM-only NixOS node configuration with dm-verity and kernel hardening
- `infra/docker/`: Multi-service dev compose environment (mix nodes, i2pd, Cashu mint, Yggdrasil)
- `scripts/gen-identity.sh`: Ed25519 keypair generator
- `scripts/bootstrap-seed.sh`: Automated seed node deployment
- `flake.nix`: Reproducible Nix development shell
- `Justfile`: Common developer commands
- CI pipeline: build, test, clippy, fmt, cargo-audit, shellcheck
- Full documentation: ARCHITECTURE.md, THREAT_MODEL.md, LEGAL.md, ROADMAP.md

### Security
- All private key types implement `ZeroizeOnDrop`
- Packet size is fixed at 2048 bytes (prevents length-based analysis)
- Node identity never written to disk in stateless mode
- Noise_XX handshake provides forward secrecy + mutual authentication
