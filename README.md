# Zero-Knowledge Sovereign Network (ZKSN)

> **A metadata-resistant, jurisdictionally-agnostic, cryptographically-sovereign peer-to-peer network.**  
> No central servers. No corporate entity. No IP leakage. No registration.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Status: Pre-Release](https://img.shields.io/badge/Status-Pre--Release-orange.svg)](https://github.com/Naveenub/zksn/releases/latest)
[![CI](https://github.com/Naveenub/zksn/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Naveenub/zksn/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.20-blue.svg)](https://soliditylang.org/)
[![Tests](https://img.shields.io/badge/Tests-252%20passing-brightgreen.svg)](https://github.com/Naveenub/zksn/actions)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](./CONTRIBUTING.md)

---

## Table of Contents

1. [What is ZKSN?](#what-is-zksn)
2. [Core Principles](#core-principles)
3. [Architecture](#architecture)
4. [Repository Structure](#repository-structure)
5. [Tech Stack](#tech-stack)
6. [Quick Start](#quick-start)
7. [Running a Mix Node](#running-a-mix-node)
8. [Client CLI](#client-cli)
9. [Configuration Reference](#configuration-reference)
10. [Cryptographic Design](#cryptographic-design)
11. [Economic Layer](#economic-layer)
12. [Governance](#governance)
13. [Infrastructure & Deployment](#infrastructure--deployment)
14. [Development](#development)
15. [Threat Model](#threat-model)
16. [Legal](#legal)
17. [Roadmap](#roadmap)
18. [Contributing](#contributing)
19. [Security](#security)
20. [License](#license)

---

## What is ZKSN?

ZKSN is a production-grade reference implementation of a **closed-loop, privacy-preserving P2P network**. Every layer is designed around a single invariant: **no participant, node, observer, or operator should be able to learn who is communicating with whom, about what, or when.**

The network achieves this through five orthogonal, independently verifiable mechanisms:

1. **Sphinx onion packets** — each mix node unwraps exactly one encryption layer. It sees only a previous hop and a next hop. Never source or destination.
2. **Poisson delay mixing** — packets are held for `Exp(1/λ)` random intervals before forwarding. Timing correlation attacks fail even against a Global Passive Adversary watching all links.
3. **Mandatory cover traffic** — nodes continuously emit `DROP` and `LOOP` packets indistinguishable from real traffic. Silence is not permitted at the protocol level.
4. **Chaumian ecash payments** — per-packet micropayments use blind-signed tokens. Even the mint cannot link issuance to redemption.
5. **Stateless node operation** — NixOS nodes boot from RAM. Seizure of hardware yields nothing.

---

## Core Principles

| Principle | Implementation | Guarantee |
|---|---|---|
| Identity Nullification | Ed25519 keypair only | No email, username, phone, or IP ever stored |
| Metadata Erasure | Sphinx + Poisson mixing + cover traffic | Sender, receiver, timing, and content all hidden |
| Transport Sovereignty | Yggdrasil encrypted IPv6 mesh (`200::/7`, enforced at Rust socket level) | No IANA, no ASN, no routing authority |
| Anonymous Services | I2P SAM v3.1 + i2pd · `.zksn` DHT petnames | Server IP never exposed to clients; `.b32.i2p` + `name.zksn` addressing |
| Economic Sovereignty | Cashu (Chaumian ecash) + Monero (XMR) | Unlinkable micropayments, private settlement |
| Node Amnesia | NixOS tmpfs root, no persistent writes | Hardware seizure yields zero data |
| Trustless Governance | ZK-SNARK on-chain voting (Groth16, BN254, pot28 VK) | Anonymous, non-coercible, fully autonomous execution |
| Code as Speech | MIT license, no foundation | Cannot be seized; protected under *Bernstein v. DOJ* |

---

## Architecture

### System Layer Diagram

```
┌─────────────────────────────────────────────────────┐
│                  User Application                   │
└──────────────────────────┬──────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────┐
│              Layer 4 — Identity Plane               │
│  Ed25519 keypair · X25519 session exchange          │
│  Noise_XX handshake · No PII · Ever                 │
└──────────────────────────┬──────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────┐
│              Layer 3 — Economic Plane               │
│  Cashu blind-signed ecash · Per-packet token        │
│  Monero XMR settlement · Batch redemption           │
└──────────────────────────┬──────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────┐
│              Layer 2 — Mixnet Plane                 │
│  Sphinx packets · Fixed 2048-byte size              │
│  Poisson(λ) delays · DROP + LOOP cover traffic      │
└──────────────────────────┬──────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────┐
│              Layer 1 — Anonymous Service Plane      │
│  I2P / i2pd · .b32.i2p addressing                   │
│  .zksn internal TLD · DHT petname resolution        │
└──────────────────────────┬──────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────┐
│              Layer 0 — Mesh Transport Plane         │
│  Yggdrasil IPv6 mesh · Address = SHA-512(pubkey)    │
│  200::/7 enforced in Rust · CJDNS fallback          │
└─────────────────────────────────────────────────────┘
```

---

## Repository Structure

```
zksn/
├── .github/                            # CI workflows · issue templates · PR checklist
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md              # Bug report template
│   │   └── feature_request.md         # Feature request template
│   ├── workflows/
│   │   ├── ci.yml                     # Rust · Security Audit · Governance · Ceremony
│   │   └── ceremony_mainnet.yml       # Automated pot28 trusted setup
│   └── PULL_REQUEST_TEMPLATE.md       # Crypto review checklist
├── ceremony/
│   ├── ATTESTATION.md                 # pot28 contribution hashes + SHA256 fingerprints
│   ├── input.json                     # Ceremony test vector
│   ├── proof.json                     # Ceremony test proof
│   ├── public.json                    # Public signals: nullifier · proposalId · root
│   └── verification_key.json          # Groth16 VK (Hermez pot28, 1000+ contributors)
├── circuits/
│   └── MembershipVote.circom          # Groth16 circuit: depth-20 Merkle + nullifier
├── client/
│   ├── cli/
│   │   └── main.rs                    # zksn CLI: identity · send · receive · --testnet · --listen
│   ├── src/
│   │   ├── config.rs                  # ClientConfig · yggdrasil_only · listen_addr
│   │   ├── lib.rs                     # ZksnClient API · Yggdrasil enforcement at construction
│   │   ├── receive.rs                 # TCP listener · Sphinx peel · payload delivery
│   │   ├── route.rs                   # RouteSelector — DHT-based hop selection
│   │   └── send.rs                    # Sphinx build · PaymentEnvelope inject
│   ├── Cargo.toml                     # zksn-client · zksn binary · clap · colored · indicatif
│   └── README.md                      # Client library and CLI usage guide
├── crypto/
│   ├── src/
│   │   ├── identity.rs                # Ed25519 keypair · fingerprint · zeroize-on-drop
│   │   ├── lib.rs                     # Crate exports
│   │   ├── noise.rs                   # Noise_XX mutual auth · forward secrecy
│   │   ├── sphinx.rs                  # Sphinx 2048B onion packets · per-hop key blinding
│   │   └── zkp.rs                     # Merkle membership · nullifiers · commitments
│   └── Cargo.toml                     # zksn-crypto · ed25519-dalek · x25519-dalek · snow
├── docs/
│   ├── ARCHITECTURE.md                # Full 5-layer technical blueprint
│   ├── LEGAL.md                       # Mere conduit · Bernstein · Tornado Cash analysis
│   ├── ROADMAP.md                     # Development phases and milestones
│   └── THREAT_MODEL.md                # 6 adversary classes with mitigations
├── economic/
│   ├── src/
│   │   ├── cashu.rs                   # NUT-00 blind-DH · hash_to_curve · B_=Y+r·G · C=C_-r·K
│   │   ├── lib.rs                     # Crate exports
│   │   ├── mint.rs                    # MintClient NUT-01/03/05/07 · NodeWallet · MeltManager
│   │   ├── monero.rs                  # Monero RPC · stealth addresses · piconero conversion
│   │   └── token.rs                   # PacketToken — Cashu token attached to Sphinx packets
│   ├── Cargo.toml                     # reqwest 0.13 (RUSTSEC-2026-0049 patched)
│   └── README.md                      # Economic layer overview
├── governance/
│   ├── contracts/
│   │   ├── Groth16Verifier.sol        # BN254 pairing · pot28 VK · depth-20 · 1000+ contributors
│   │   ├── IVerifier.sol              # Interface: verifyProof(bytes, uint256[4])
│   │   ├── MockVerifier.sol           # Always-true + StrictMock verifiers for tests
│   │   ├── PoseidonHasher.sol         # circomlibjs bytecode · hashLeaf/hashNullifier/hashNode
│   │   └── ZKSNGovernance.sol         # DAO · ZK voting · 7-day period · 2-day timelock
│   ├── scripts/
│   │   └── Deploy.s.sol               # Foundry deployment script
│   ├── test/
│   │   └── ZKSNGovernance.t.sol       # 47 tests: governance lifecycle + exact Poseidon vectors
│   ├── foundry.toml                   # Solidity 0.8.20 · forge-std
│   └── README.md                      # Governance overview
├── infra/
│   ├── docker/
│   │   ├── config/
│   │   │   ├── cashu.env              # Cashu mint env (FakeWallet for dev)
│   │   │   ├── i2pd.conf              # i2pd: HTTP 4444 · SOCKS 4447 · console 7070
│   │   │   ├── tunnels.conf           # i2pd tunnel definitions
│   │   │   ├── yggdrasil-peer.conf    # Peer node — connects to seed
│   │   │   └── yggdrasil-seed.conf    # Seed node — multicast discovery
│   │   ├── Dockerfile.client          # Multi-stage Rust build → Debian slim
│   │   ├── Dockerfile.mixnode         # Multi-stage Rust build → Debian slim
│   │   └── docker-compose.yml         # 7-service devnet: 3 nodes + Yggdrasil + i2pd + Cashu
│   └── nixos/
│       ├── node.nix                   # RAM-only NixOS · tmpfs · dm-verity · LUKS2 · Yggdrasil
│       └── README.md                  # NixOS deployment guide
├── node/
│   ├── src/
│   │   ├── config.rs                  # NodeConfig · yggdrasil_only · enforce_yggdrasil()
│   │   ├── cover.rs                   # DROP + LOOP cover traffic generator
│   │   ├── i2p.rs                     # SAM v3.1 client · garlic routing · .zksn petname DHT
│   │   ├── lib.rs                     # Crate exports
│   │   ├── main.rs                    # CLI entry point · clap · config load · tracing init
│   │   ├── metrics.rs                 # Prometheus counters · gauges · histograms (local only)
│   │   ├── mixer.rs                   # Poisson delay pool · Exp(λ) sampling · reordering
│   │   ├── network.rs                 # is_yggdrasil() · check_bind() · check_peer() — 200::/7
│   │   ├── node.rs                    # TCP listener · Yggdrasil bind/accept enforcement
│   │   ├── payment.rs                 # PaymentGuard NUT-07 · MeltManager threshold withdrawal
│   │   ├── peers.rs                   # Kademlia DHT · 256 k-buckets · gossip · peer persistence
│   │   └── router.rs                  # TCP packet forwarding · fixed-size framing
│   ├── Cargo.toml                     # zksn-node binary · tokio · clap · prometheus
│   ├── node.toml.example              # Fully annotated config template
│   └── README.md                      # Mix node operation guide
├── scripts/
│   ├── bootstrap-seed.sh              # Seed node setup: Yggdrasil + i2pd + identity + mint
│   ├── ceremony.sh                    # Full pot28 ceremony runbook (init/contribute/finalize)
│   ├── demo.sh                        # End-to-end local devnet — one command
│   ├── download_ptau.sh               # Hermez pot28 download + SHA256 integrity check
│   ├── encode_proof.js                # EIP-197 proof encoding (swaps G2 Fp2 coords for Solidity)
│   ├── gen-identity.sh                # Ed25519 keypair generator · secure permissions
│   ├── patch_ceremony.js              # Auto-patch Groth16Verifier.sol + test constants post-ceremony
│   ├── tree.js                        # Sparse depth-20 Poseidon membership tree builder
│   └── tree_ci.js                     # Stateless tree input generator for ceremony workflow
├── .gitignore                         # target/ · *.key · node_modules/ · build/
├── CHANGELOG.md                       # Release history
├── CONTRIBUTING.md                    # Anonymous contribution guide · GPG · Tor/I2P push
├── Cargo.lock                         # Pinned dependency versions
├── Cargo.toml                         # Workspace: node · client · crypto · economic
├── flake.nix                          # Nix dev shell: Rust · Foundry · Yggdrasil · i2pd · just
├── Justfile                           # 30+ developer commands
├── LICENSE                            # MIT
├── README.md                          # This file
├── RELEASE.md                         # Latest release notes
└── SECURITY.md                        # Responsible disclosure · severity matrix
```

---

## Tech Stack

| Component | Technology | Version | Purpose |
|---|---|---|---|
| Node implementation | Rust | 1.75+ | Mix node, client, crypto primitives |
| Async runtime | Tokio | 1.x | All async I/O |
| Mesh transport | [Yggdrasil](https://yggdrasil-network.github.io/) | latest | Encrypted IPv6 mesh, `200::/7` enforced in Rust |
| Anonymous services | [I2P (i2pd)](https://i2pd.website/) + SAM v3.1 | latest | Garlic routing · `.b32.i2p` service hosting · `.zksn` DHT petnames |
| Packet format | Sphinx | custom | Fixed 2048B onion packets, per-hop key blinding |
| Node handshake | [Noise Protocol](https://noiseprotocol.org/) `XX` | snow 0.9 | Mutual auth, forward secrecy |
| Signing | Ed25519 | ed25519-dalek 2 | Node identity |
| Key exchange | X25519 | x25519-dalek 2 | Session ECDH |
| Encryption | ChaCha20-Poly1305 | chacha20poly1305 0.10 | Packet payload |
| Micropayments | [Cashu](https://cashu.space/) | NUT-00/01/03/05/07 | Blind-signed per-packet ecash |
| Settlement | [Monero (XMR)](https://getmonero.org/) | RPC v2 | Private on-chain settlement |
| Governance | Solidity 0.8.20 + Foundry | — | ZK-SNARK anonymous voting DAO |
| ZK circuit | Circom 2.1.4 + circomlib | depth-20 | Poseidon Merkle membership + nullifier |
| ZK ceremony | Groth16 / BN254 | pot28 (1000+) | Hermez trusted setup, 2^15 capacity |
| ZK library | snarkjs 0.7.6 | — | Proving, verification, VK export |
| On-chain hash | PoseidonHasher | circomlibjs bytecode | Matches circuit exactly |
| Node OS | [NixOS](https://nixos.org/) | 24.x | RAM-only, reproducible builds |
| CI | GitHub Actions | — | Rust · Audit · Foundry · Ceremony |

---

## Quick Start

### Run the full demo (one command)

```bash
git clone https://github.com/Naveenub/zksn.git
cd zksn

# Install Node.js deps (for ZK proof step)
npm install

# Run the full end-to-end demo:
#   3 mix nodes + anonymous message + governance vote with ZK proof
bash scripts/demo.sh
```

Expected output:
```
══ Prerequisites ══
✓ cargo: cargo 1.xx.x
✓ node:  v22.x.x

══ Build ══
   Finished release [optimized] target(s)
✓ zksn-node: 8.2M

══ Starting Mix Nodes ══
✓ node1  listening on 127.0.0.1:9101
✓ node2  listening on 127.0.0.1:9102
✓ node3  listening on 127.0.0.1:9103

══ Sending Anonymous Message  (Alice → Bob) ══
✓ Message sent through mixnet

══ Anonymous Governance Vote  (ZK proof) ══
✓ Membership tree root: 6331401000423026...
✓ Proof verified ✅  (snarkjs groth16 verify → OK)
✓ Anonymous vote proof complete
✓ The contract cannot link this vote to the voter's secret

══ Demo Complete ══
```

Flags:
```bash
bash scripts/demo.sh --skip-vote   # mix only, skip ZK proof
bash scripts/demo.sh --skip-mint   # no Docker mint required
```

### Build and test

```bash
# All Rust tests
cargo test --workspace

# Governance contracts (47 Solidity tests)
cd governance && forge install foundry-rs/forge-std --no-git && forge test -vv

# Everything
cargo test --workspace && cd governance && forge test -vv
```

---

## Running a Mix Node

### 1. Configure

```bash
cp node/node.toml.example node.toml
$EDITOR node.toml
```

```toml
[network]
# Production: Yggdrasil IPv6 address (200::/7 — enforced by the binary)
listen_addr        = "[200:your:yggdrasil:addr::1]:9001"
max_peers          = 64
bootstrap_peers    = ["[200:seed1::1]:9001"]
yggdrasil_only     = true   # default — set false for testnet/dev only

[mixing]
poisson_lambda_ms   = 200   # mean delay ms; higher = more anonymity
cover_traffic_rate  = 5     # cover packets/sec
max_queue_depth     = 10000
loop_cover_fraction = 0.3

[economic]
cashu_mint_url        = "http://mint.zksn.internal:3338"
min_token_value       = 1
monero_rpc_url        = "http://127.0.0.1:18082"
redemption_batch_size = 100

[keys]
key_store_path   = "/var/lib/zksn/keys/identity.key"
persist_identity = false   # false = ephemeral key per boot (fully stateless)

# Optional: I2P internal service layer
# Requires i2pd running on this machine (systemctl start i2pd)
[i2p]
enabled          = false           # set true to enable garlic routing
sam_addr         = "127.0.0.1:7656"
session_id       = "zksn-node"
private_key_path = "/run/keys/zksn/i2p.key"   # stable .b32.i2p address
petname          = "mynode"        # registers "mynode.zksn" in the DHT
```

### 2. Run

```bash
# Production
./target/release/zksn-node --config node.toml

# Development (disables Yggdrasil enforcement, allows 127.0.0.1)
./target/release/zksn-node --config node.toml --testnet

# Debug logging
./target/release/zksn-node --config node.toml --debug
```

### Yggdrasil address enforcement

The node binary enforces `200::/7` at three levels:

- **Bind** — refuses to start if `listen_addr` is not a Yggdrasil address
- **Accept** — drops inbound connections from outside `200::/7` before reading any data
- **Dial** — refuses to connect to peers outside `200::/7`

Override with `yggdrasil_only = false` in `node.toml` or `--testnet` flag.

---

## Client CLI

```bash
cargo build --release --package zksn-client
```

```
zksn [OPTIONS] <COMMAND>

Options:
  -k, --key      <FILE>    Identity key file
  -n, --node     <ADDR>    Entry mix node  (default: [::1]:9001)
  -l, --listen   <ADDR>    Listen address for incoming messages
      --testnet            Disable Yggdrasil enforcement (dev/demo only)
  -d, --debug              Debug logging

Commands:
  identity generate [--output <file>]    Create a new Ed25519 keypair
  identity show                          Display identity fingerprint
  send <recipient-pubkey-hex> <message>  Send encrypted message through mixnet
  receive                                Listen for incoming messages
  wallet balance                         Show Cashu token balance
  wallet topup <sats>                    Top up via mint
```

```bash
# Generate identity
zksn identity generate --output ~/.zksn/identity.key

# Send (production — requires Yggdrasil)
zksn --key ~/.zksn/identity.key \
     --node [200:abcd::1]:9001 \
     send <recipient-pubkey-hex> "Hello"

# Send (testnet / demo)
zksn --key ~/.zksn/identity.key \
     --node 127.0.0.1:9101 \
     --testnet \
     send <recipient-pubkey-hex> "Hello"

# Receive
zksn --key ~/.zksn/identity.key \
     --listen 127.0.0.1:9201 \
     --testnet \
     receive
```

---

## Configuration Reference

### `yggdrasil_only` (node + client)

| Value | Behaviour |
|---|---|
| `true` (default) | Enforce `200::/7` at bind, accept, and dial |
| `false` | Allow any address — development and testnet only |

The `--testnet` CLI flag sets `yggdrasil_only = false` and also disables payment enforcement on the node.

---

## Cryptographic Design

### Sphinx Packets (`crypto/src/sphinx.rs`)

- **Fixed size:** 2048 bytes — all packets identical length, no length-based correlation
- **Ephemeral key:** 32-byte X25519 public key per packet
- **Per-hop key blinding:** `α_{i+1} = b_i ×_clamped α_i` — colluding nodes cannot correlate packets across hops
- **Cover types:** `DROP` (random destination) and `LOOP` (routes back to self)

### I2P Service Layer (`node/src/i2p.rs`)

ZKSN mix nodes optionally expose a garlic-routed I2P destination in addition to
their Yggdrasil address. This allows clients to reach nodes without knowing
any Yggdrasil address — useful for bootstrapping and for clients behind
restrictive networks.

| Component | Detail |
|---|---|
| Protocol | I2P SAM v3.1 (`STREAM` sessions) |
| SAM bridge | i2pd on `127.0.0.1:7656` (default) |
| Address | `.b32.i2p` (SHA-256 of destination key, base32-encoded) |
| Key persistence | Optional — stable address across restarts when key file is set |
| Petnames | `.zksn` TLD registered in the Kademlia DHT |
| Fallback | Disabled gracefully if i2pd is not running (`i2p.enabled = false`) |

**`.zksn` petname resolution** — human-readable names map to `.b32.i2p` destinations
via signed DHT records:

```
DHT key  = SHA-256("zksn:" || name.lowercase())
Record   = { name, b32_addr, published_at, ttl, pubkey, ed25519_signature }
```

Records are signed with the node's Ed25519 identity key. Any node can verify
a record; forged entries are rejected at the DHT layer. Records expire after 24
hours and are re-announced every 12 hours by the registrant.

```toml
# node.toml
[i2p]
enabled          = true
sam_addr         = "127.0.0.1:7656"
petname          = "mynode"           # registers mynode.zksn
private_key_path = "/run/keys/zksn/i2p.key"
```

### Governance ZK (`governance/contracts/`)

| Component | Detail |
|---|---|
| Circuit | `MembershipVote(depth=20)` — 5,360 constraints |
| Max members | 2^20 = 1,048,576 |
| Trusted setup | Hermez pot28 (1,000+ contributors) |
| Curve | BN254 |
| Hash | Poseidon (circomlibjs bytecode, exact match to circuit) |
| Proof system | Groth16 (256-byte proofs, ~215k gas to verify) |
| Nullifier | `Poseidon(secret, proposalId)` — unique per (member, proposal) |

### Trust model

The governance circuit's security rests on:
- **Phase 1:** Hermez pot28 — at least 1 of 1,000+ contributors must have discarded toxic waste
- **Phase 2:** 3-contributor MPC (`ceremony/ATTESTATION.md`) — at least 1 of 3 must have discarded

---

## Economic Layer

Full Cashu NUT-00/01/03/05/07 implementation:

```
secret → hash_to_curve → Y
r (random) → r·G
B_ = Y + r·G          → sent to mint (blinded)
C_ = k·B_              ← returned by mint (blind signature)
C  = C_ - r·K          → valid Cashu proof (unblinded)
```

`MeltManager` runs as a background task — when the node wallet reaches `threshold_sats` it fires `POST /v1/melt` to pay a Lightning invoice.

---

## Governance

```
No multisig. No admin. No upgradeable proxy.
Protocol changes execute autonomously after vote + timelock.
```

| Parameter | Value |
|---|---|
| Voting period | 7 days |
| Time-lock | 2 days |
| Quorum | 10 votes |
| Pass threshold | >50% yes |
| Max members | 1,048,576 |
| Proof size | 256 bytes |

---

## Infrastructure & Deployment

### Local devnet (Docker Compose)

```bash
cd infra/docker
docker compose up
# 3 mix nodes + 2 Yggdrasil nodes + i2pd + Cashu mint
```

### Production (NixOS)

```bash
nixos-rebuild switch --target-host root@[200:your:node::1] --flake .#zksn-node
```

RAM-only. `tmpfs` root. `dm-verity`. No persistent writes. Hardware seizure yields zero data.

---

## Development

### Test coverage

| Crate / Contract | Tests |
|---|---|
| `zksn-crypto` | 29 |
| `zksn-node` | 76 (incl. 28 Yggdrasil + 25 I2P/petname tests) |
| `zksn-economic` | 32 |
| `zksn-client` | 68 (incl. 7 Yggdrasil enforcement tests) |
| `ZKSNGovernance.sol` | 47 |
| **Total** | **252** |

```bash
cargo test --workspace        # 180 Rust tests
cd governance && forge test   # 47 Solidity tests
```

### CI jobs

| Job | Runs |
|---|---|
| Rust | fmt · build · test · clippy |
| Security Audit | cargo audit (with auto `cargo update -p rustls-webpki`) |
| Governance Contracts | forge build --sizes · forge test -vv |
| Ceremony | pot28 download · 3-MPC phase 2 · forge test (manual trigger) |

---

## Threat Model

| Adversary | Capability | Defence | Residual Risk |
|---|---|---|---|
| Local Passive | One link | Sphinx + fixed packet size | None at link |
| Global Passive (GPA) | All links | Poisson(λ) mixing + mandatory cover traffic | Statistical correlation (open research) |
| Active | Injects / drops / modifies | Noise MAC · drop triggers retry | n-1 partially mitigated |
| Compromised nodes | Subset of mix nodes | Multi-hop · single node sees one hop | Path correlation at entry+exit |
| Legal / seizure | Hardware, subpoenas | RAM-only · no corporate entity | Operators in hostile jurisdictions |
| Sybil | Many fake nodes | Economic stake · DHT reputation | Capitalized governance capture |

See [docs/THREAT_MODEL.md](./docs/THREAT_MODEL.md) for full analysis.

---

## Legal

No incorporated entity. No foundation. No officers. No registered agents.

Code is speech (*Bernstein v. DOJ*, 1999). Mix node operators are mere conduits — they transmit encrypted packets they cannot read and do not control.

See [docs/LEGAL.md](./docs/LEGAL.md) for full jurisdictional analysis.

> **This is not legal advice.** Consult qualified legal counsel for your situation.

---

## Roadmap

| Phase | Status |
|---|---|
| 0 — Cryptographic foundations (Ed25519, Sphinx, Noise_XX, ZKP) | ✅ Complete |
| 1 — Mesh transport (Yggdrasil, Kademlia DHT, `200::/7` enforcement) | ✅ Complete |
| 2 — Mixnet (Poisson, cover traffic, Sphinx routing, PaymentEnvelope) | ✅ Complete |
| 3 — Economic layer (Cashu NUT-00/01/03/05/07, NodeWallet, MeltManager) | ✅ Complete |
| 4 — DAO governance (depth-20 circuit, Groth16, pot28, PoseidonHasher) | ✅ Complete |
| 5 — Transport enforcement (Yggdrasil 200::/7 at Rust socket level) | ✅ Complete |
| 6 — Demo + developer experience (scripts/demo.sh, full devnet) | ✅ Complete |
| 7 — Stateless node OS (NixOS, tmpfs, dm-verity) | 🟡 Config written, hardware testing pending |
| 8 — Internal service layer (i2pd SAM, .zksn DHT petnames, garlic routing) | ✅ Complete |
| 9 — External security audit + bug bounty | 🟡 In progress → **v1.0.0 final gate** |

---

## Contributing

Contributions welcome. Anonymity respected.

```bash
git config user.name  "anon"
git config user.email "anon@zksn.invalid"

# Push over Tor
GIT_SSH_COMMAND="ssh -o ProxyCommand='nc -x 127.0.0.1:9050 %h %p'" git push
```

Before contributing cryptographic code: read the implementation, understand the threat model, open an issue before submitting changes to any core crypto path.

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the full guide.

---

## Security

**Do not open public GitHub issues for vulnerabilities.**

Report via GitHub Security Advisory (private) or GPG-encrypted to `keys/security.asc`.

| Severity | Target fix |
|---|---|
| Critical — deanonymises users, exposes IPs | 7 days |
| High — breaks economic layer or anonymity set | 30 days |
| Medium — DoS, non-privacy leaks | 90 days |
| Low | Best effort |

See [SECURITY.md](./SECURITY.md) for full policy.

---

## License

[MIT](./LICENSE) — use, modify, and distribute freely.

Research and educational purposes. See [docs/LEGAL.md](./docs/LEGAL.md) for jurisdictional guidance.
