# ZKSN Development Roadmap

| Phase | Description | Status |
|---|---|---|
| 0 — Crypto Foundations | Ed25519, X25519, Noise_XX, Sphinx, ZKP | 🟡 X25519 ECDH pending |
| 1 — Mesh Transport | Yggdrasil, CJDNS, seed nodes, DHT | 🟡 Infra scaffolded, DHT pending |
| 2 — Mixnet | Poisson mixing, cover traffic, Sphinx routing | 🟡 Core done, ECDH wiring pending |
| 3 — Internal Services | i2pd, .zksn TLD, DHT petnames, messaging | 🔴 Not started |
| 4 — Economic Layer | Cashu NUT-00, per-packet tokens, XMR | 🟡 Scaffolded, mint integration pending |
| 5 — Stateless OS | NixOS live-boot, dm-verity, LUKS2 | 🟡 Config written, testing pending |
| 6 — DAO Governance | ZK-SNARK voting contracts, credentials | 🟡 Solidity done, ZK circuit pending |
| 7 — Client SDK | Rust library, Python bindings, full CLI | 🟡 Scaffolded, DHT routes pending |
| 8 — Audit | External crypto audit, GPA simulation | 🔴 Not started |

## MVP Definition
Phases 0–3 complete: anonymous identity + metadata-free messaging + internal service hosting.
