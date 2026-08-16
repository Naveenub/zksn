# ZKSN Development Roadmap

| Phase | Description | Status |
|---|---|---|
| 0 — Crypto Foundations | Ed25519, X25519, Noise_XX, Sphinx, ZKP | 🟢 Done — X25519 ECDH wired into Sphinx (`crypto/src/sphinx.rs`) and peer routing keys (`node/src/config.rs`) |
| 1 — Mesh Transport | Yggdrasil, CJDNS, seed nodes, DHT | 🟢 Done — Kademlia-lite DHT with gossip fan-out and peer persistence (`node/src/peers.rs`) |
| 2 — Mixnet | Poisson mixing, cover traffic, Sphinx routing | 🟢 Done — mixer, cover traffic, and Sphinx ECDH all wired end-to-end |
| 3 — Internal Services | i2pd, .zksn TLD, DHT petnames, messaging | 🟡 i2pd bridge, `.zksn` petname DHT resolution, and `ServiceRouter` messaging tag live (`node/src/i2p.rs`, `node/src/services.rs`); only the `Messaging` service tag exists — additional service types not yet added |
| 4 — Economic Layer | Cashu NUT-00, per-packet tokens, XMR | 🟢 Done — mint client (quote/swap/melt/verify) and wallet in `economic/src/mint.rs`, Monero JSON-RPC client in `economic/src/monero.rs` (no longer a stub) |
| 5 — Stateless OS | NixOS live-boot, dm-verity, LUKS2 | 🟡 Config + VM smoke test done (`infra/nixos/vm-test.nix`); `hardware-test.sh` validation suite written but no attestation of a completed bare-metal run is checked into the repo |
| 6 — DAO Governance | ZK-SNARK voting contracts, credentials | 🟡 Circuit, trusted-setup ceremony, and `Groth16Verifier.sol` all complete (`ceremony/ATTESTATION.md`); `governance/scripts/Deploy.s.sol` still deploys `MockVerifier` — cutover to the real verifier for production deploys is pending |
| 7 — Client SDK | Rust library, Python bindings, full CLI | 🟢 Done — DHT-backed route sampling (`client/src/route.rs`), Python bindings, and CLI (identity/send/receive/wallet) |
| 8 — Audit | External crypto audit, GPA simulation | 🔴 Not started — scope, threat model, and findings template are prepared (`docs/AUDIT_SCOPE.md`) but no third-party audit has been conducted |

## MVP Definition
Phases 0–3 substantially complete: anonymous identity, metadata-free messaging, and internal service hosting all work end-to-end; remaining gap is expanding `ServiceRouter` beyond the single messaging tag.
