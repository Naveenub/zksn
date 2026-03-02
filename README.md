# Zero-Knowledge Sovereign Network (ZKSN)

> **A metadata-resistant, jurisdictionally-agnostic, cryptographically-sovereign peer-to-peer network.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Status: Pre-Alpha](https://img.shields.io/badge/Status-Pre--Alpha-red.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](./CONTRIBUTING.md)

---

## ⚠️ Disclaimer

This is a research and educational project in applied cryptography and distributed systems. Running network infrastructure may have legal implications depending on your jurisdiction. Contributors and operators are responsible for their own compliance with applicable laws. See [LEGAL.md](./docs/LEGAL.md).

---

## What is ZKSN?

ZKSN is an open-source blueprint and reference implementation for a **closed-loop, privacy-preserving network** that operates on the following principles:

| Principle | Implementation |
|---|---|
| Identity Nullification | Ed25519 keypairs only — no email, no username, no IP |
| Metadata Erasure | Sphinx-packet Mixnet with Poisson delays + mandatory cover traffic |
| Economic Sovereignty | Monero (XMR) settlement + Chaumian ecash (Cashu) per-packet micropayments |
| Hardware Agnosticism | NixOS RAM-only live-boot node images |
| Jurisdictional Decentralization | DAO governance, no incorporated entity, no central servers |

---

## Architecture Overview

```
[User Application]
        │
        ▼
[Identity Plane]       Ed25519/X25519 keypair. No PII. Ever.
        │
        ▼
[Mixnet Plane]         Sphinx-packet routing w/ Poisson delays & cover traffic
        │
        ▼
[Transport Plane]      Yggdrasil / CJDNS encrypted mesh overlay
        │
        ▼
[Economic Plane]       Cashu ecash micropayment channels + XMR settlement
        │
        ▼
[Destination]          Internal (.i2p / .zksn) service OR gated exit module
```

See [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md) for the full technical blueprint.

---

## Repository Structure

```
zksn/
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   └── feature_request.md
│   ├── workflows/
│   │   └── ci.yml
│   └── PULL_REQUEST_TEMPLATE.md
├── docs/                   # Full technical documentation
│   ├── ARCHITECTURE.md     # System design & data flow
│   ├── THREAT_MODEL.md     # Adversary model & mitigations
│   ├── LEGAL.md            # Jurisdictional analysis
│   └── ROADMAP.md          # Development phases
├── node/                   # Mix node implementation
│   ├── src/
│   │   ├── config.rs
│   │   ├── cover.rs
│   │   ├── lib.rs
│   │   ├── main.rs
│   │   ├── metrics.rs
│   │   ├── mixer.rs
│   │   ├── node.rs
│   │   └── router.rs
│   ├── Cargo.toml
│   ├── node.toml.example
│   └── README.md
├── client/                 # Client library & CLI
│   ├── src/
│   │   ├── config.rs
│   │   ├── lib.rs
│   │   ├── receive.rs
│   │   ├── route.rs
│   │   ├── send.rs
│   ├── cli/
│   │   └── main.rs
│   └── README.md
├── crypto/                 # Cryptographic primitives
│   ├── src/
│   │   ├── identity.rs
│   │   ├── lib.rs
│   │   ├── noise.rs
│   │   ├── sphinx.rs
│   │   └── zkp.rs
│   └── Cargo.toml
├── economic/               # Payment layer
│   ├── src/
│   │   ├── cashu.rs
│   │   ├── lib.rs
│   │   ├── monero.rs
│   │   └── token.rs
│   ├── Cargo.toml               
│   └── README.md
├── governance/             # DAO smart contracts
│   ├── contracts/
│   │   ├── IVerifier.sol
│   │   ├── MockVerifier.sol
│   │   └── ZKSNGovernance.sol
│   ├── scripts/
│   │   └── Deploy.s.sol
│   ├── test/
│   │   └── ZKSNGovernance.t.sol
│   ├── foundry.toml
│   └── README.md
├── infra/                  # Node deployment tooling
│   ├── nixos/              # NixOS node configuration
│   │   ├── node.nix
│   │   └── README.md
│   └── docker/             # Dev/test environment only
│       ├── config/
│       │   ├── cashu.env
│       │   ├── i2pd.conf
│       │   ├── tunnels.conf
│       │   ├── yggdrasil-peer.conf
│       │   └── yggdrasil-seed.conf
│       ├── docker-compose.yml
│       ├── Dockerfile.client
│       └── Dockerfile.mixnode
├── scripts/                # Utility scripts
│   ├── bootstrap-seed.sh
│   └── gen-identity.sh
├── .gitignore
├── Cargo.toml
├── CHANGELOG.md
├── CONTRIBUTING.md
├── flake.nix
├── Justfile
├── SECURITY.md
├── LICENSE
└── README.md
```

---

## Quick Start

### Generate Your Identity

```bash
# Clone the repository
git clone https://github.com/YOUR_ORG/zksn.git
cd zksn

# Generate a node identity keypair (Ed25519)
chmod +x scripts/gen-identity.sh
./scripts/gen-identity.sh

# Output: identity.pub (share this) + identity.key (NEVER share this)
```

### Run a Dev Node (Docker — for testing only, not production)

```bash
cd infra/docker
docker compose up
```

### Deploy a Production Seed Node (NixOS)

See [infra/nixos/README.md](./infra/nixos/README.md) for full instructions.

---

## Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| Mesh Transport | [Yggdrasil](https://yggdrasil-network.github.io/) | Encrypted IPv6 mesh, no central routing |
| Mesh Transport (alt) | [CJDNS](https://github.com/cjdelisle/cjdns) | Redundant mesh overlay |
| Mixnet | [Nym](https://nymtech.net/) | Sphinx packet mixing w/ cover traffic |
| Anonymous Services | [I2P / i2pd](https://i2pd.website/) | Internal .i2p service hosting |
| Identity Handshake | [Noise Protocol](https://noiseprotocol.org/) | Forward-secret key exchange |
| Packet Format | [Sphinx](https://cypherpunks.ca/~iang/pubs/Sphinx_Oakland09.pdf) | Unlinkable onion packets |
| Settlement Currency | [Monero (XMR)](https://getmonero.org/) | Private on-chain settlement |
| Micropayments | [Cashu](https://cashu.space/) | Chaumian blind-signature ecash |
| Node OS | [NixOS](https://nixos.org/) | Reproducible, declarative, RAM-bootable |
| DAO Governance | ZK-SNARK voting contracts | Anonymous on-chain governance |

---

## Development Phases

- [ ] **Phase 0** — Cryptographic identity primitives
- [ ] **Phase 1** — Yggdrasil mesh bootstrap + seed node tooling  
- [ ] **Phase 2** — Nym mixnet node integration
- [ ] **Phase 3** — I2P internal service layer
- [ ] **Phase 4** — Cashu + XMR economic layer
- [ ] **Phase 5** — NixOS live-boot node image
- [ ] **Phase 6** — DAO governance contracts
- [ ] **Phase 7** — Client SDK + CLI

See [docs/ROADMAP.md](./docs/ROADMAP.md) for detailed milestones.

---

## Contributing

Contributions are welcome and encouraged. Please read [CONTRIBUTING.md](./CONTRIBUTING.md) before submitting a PR.

**Note on contributor anonymity:** You are not required to contribute under your real name. GPG-signed commits from anonymous keypairs are accepted and respected.

---

## Security

If you discover a vulnerability, please read [SECURITY.md](./SECURITY.md) before disclosing. We operate a responsible disclosure policy.

---

## License

MIT License — see [LICENSE](./LICENSE). You are free to use, modify, and distribute this software.
