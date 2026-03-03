# Changelog

## [0.1.0-alpha] — 2024

### Added
- `crypto`: Ed25519 identity, Sphinx packets, Noise_XX handshake, ZKP Merkle tree
- `node`: Mix node with Poisson delay, cover traffic (DROP/LOOP), router, Prometheus metrics
- `client`: Client library, CLI (identity/send/receive/wallet)
- `economic`: Cashu NUT-00 wallet, Monero RPC stubs, PacketToken
- `governance`: ZKSNGovernance.sol (ZK voting, time-lock, autonomous execution), 14+ Foundry tests
- `infra/nixos`: RAM-only NixOS node config (tmpfs, dm-verity, LUKS2, Yggdrasil, i2pd)
- `infra/docker`: 7-service devnet (3 mix nodes, 2 Yggdrasil, i2pd, Cashu mint)
- `flake.nix`: Reproducible Nix dev shell (Rust 1.78, Foundry, just, Yggdrasil, i2pd)
- `Justfile`: 26 developer commands
- CI: GitHub Actions (Rust build/test/lint + Foundry forge test)
