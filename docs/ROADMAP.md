# ZKSN Development Roadmap

## Phase 0 — Cryptographic Foundations
**Status:** 🔴 Not started

- [ ] Ed25519 identity keypair generation utilities
- [ ] X25519 session key derivation
- [ ] Noise_XX handshake implementation (or integration with existing library)
- [ ] Sphinx packet format implementation
  - [ ] Fixed-size packet construction
  - [ ] Layered encryption/decryption
  - [ ] SURB (Single-Use Reply Block) generation
- [ ] Unit test suite for all crypto primitives
- [ ] Security audit of crypto layer

## Phase 1 — Mesh Transport Layer
**Status:** 🔴 Not started

- [ ] Yggdrasil integration and configuration tooling
- [ ] CJDNS integration (fallback)
- [ ] Seed node bootstrap scripts
- [ ] Peer discovery via DHT
- [ ] NixOS configuration module for Yggdrasil node
- [ ] Docker compose for local dev/test mesh

## Phase 2 — Mixnet Layer
**Status:** 🔴 Not started

- [ ] Nym mix node integration
- [ ] Poisson delay parameter configuration
- [ ] Cover traffic generation (LOOP and DROP messages)
- [ ] Mix node incentive/payment interface
- [ ] Mixnet topology management
- [ ] Anonymity set monitoring tools

## Phase 3 — Internal Service Layer
**Status:** 🔴 Not started

- [ ] i2pd integration and configuration
- [ ] .zksn internal DNS-equivalent (DHT-based petname resolution)
- [ ] Internal HTTP/S service hosting tooling
- [ ] Internal messaging protocol
- [ ] Internal file transfer protocol
- [ ] Service discovery mechanism

## Phase 4 — Economic Layer
**Status:** 🔴 Not started

- [ ] Cashu mint implementation integration
- [ ] Blind-signed token issuance
- [ ] Per-packet token attachment to Sphinx packets
- [ ] Mix node token redemption batching
- [ ] Monero RPC interface for settlement
- [ ] XMR → ecash token swap flow
- [ ] Economic audit and attack analysis

## Phase 5 — Stateless Node OS
**Status:** 🔴 Not started

- [ ] NixOS live-boot configuration (full node)
- [ ] RAM-only operation (no persistent writes)
- [ ] dm-verity boot image verification
- [ ] LUKS2 encrypted key storage (USB)
- [ ] Reproducible build pipeline (Nix flakes)
- [ ] Hardware compatibility testing (x86_64, ARM64)
- [ ] Raspberry Pi node image

## Phase 6 — DAO Governance
**Status:** 🔴 Not started

- [ ] ZK-SNARK membership credential system
- [ ] Anonymous on-chain voting (ZK-proven ballot)
- [ ] Proposal creation and time-lock execution
- [ ] No multisig with named signers (trustless execution)
- [ ] Governance documentation and process

## Phase 7 — Client SDK & CLI
**Status:** 🔴 Not started

- [ ] Client library (Rust, primary)
- [ ] Python bindings
- [ ] CLI tool (`zksn-cli`)
  - [ ] Identity management
  - [ ] Send/receive messages
  - [ ] Browse internal services
  - [ ] Payment channel management
- [ ] Comprehensive API documentation

## Phase 8 — Hardening & Audit
**Status:** 🔴 Not started

- [ ] Full cryptographic audit (external)
- [ ] Network-level traffic analysis testing
- [ ] Sybil resistance testing
- [ ] Long-term GPA simulation
- [ ] Documentation review
- [ ] Security bug bounty program

---

## Milestone: Minimum Viable Network (MVP)

The MVP is defined as: **Phases 0–3 complete**, enabling:
- Anonymous identity creation
- Message exchange between two parties with no metadata leakage
- Internal service hosting with no server IP exposure
- Basic node-to-node operation on Yggdrasil mesh

Target: when the community gets there.

---

## Contributing to the Roadmap

Open an issue or submit a PR to propose changes to this roadmap. All roadmap changes are subject to community discussion.
