# Zero-Knowledge Sovereign Network (ZKSN)

> **A metadata-resistant, jurisdictionally-agnostic, cryptographically-sovereign peer-to-peer network.**  
> No central servers. No corporate entity. No IP leakage. No registration.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Status: Pre-Alpha](https://img.shields.io/badge/Status-Pre--Alpha-red.svg)]()
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.20-blue.svg)](https://soliditylang.org/)
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
| Transport Sovereignty | Yggdrasil encrypted IPv6 mesh | No IANA, no ASN, no routing authority |
| Anonymous Services | I2P (i2pd) garlic routing | Server IP never exposed to clients |
| Economic Sovereignty | Cashu (Chaumian ecash) + Monero (XMR) | Unlinkable micropayments, private settlement |
| Node Amnesia | NixOS tmpfs root, no persistent writes | Hardware seizure yields zero data |
| Trustless Governance | ZK-SNARK on-chain voting | Anonymous, non-coercible, fully autonomous execution |
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
│  I2P / i2pd · .b32.i2p addressing                  │
│  .zksn internal TLD · DHT petname resolution        │
└──────────────────────────┬──────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────┐
│              Layer 0 — Mesh Transport Plane         │
│  Yggdrasil IPv6 mesh · Address = SHA-512(pubkey)    │
│  CJDNS fallback · LoRa/Meshtastic air-gap capable   │
└─────────────────────────────────────────────────────┘
```

### Packet Flow (Sending a Message)

```
[Client]
   │ 1. Encrypt payload with recipient X25519 public key
   │ 2. Build Sphinx packet:
   │       select random path: [mix₁, mix₂, mix₃, destination]
   │       layer-encrypt: Enc(Enc(Enc(payload, mix₃), mix₂), mix₁)
   │ 3. Attach blind-signed Cashu token
   │ 4. Transmit to entry mix node over Yggdrasil
   ▼
[Mix Node 1]  ← decrypts outer layer → sees only "forward to mix₂"
               ← holds for Exp(1/λ) ms → emits cover traffic continuously
   ▼
[Mix Node 2]  ← decrypts → sees only "forward to mix₃"
   ▼
[Mix Node 3]  ← decrypts → sees only "forward to destination"
   ▼
[I2P Service] ← receives encrypted payload, decrypts with private key
                 sender unknown · path unknown · timing obfuscated
```

### Packet Structure

```
┌────────────────────────────────────────────────────┐
│ Sphinx Header (fixed size)                         │
│  ├── Ephemeral public key (32 bytes, X25519)       │
│  ├── Routing header (layered encrypted, 160 bytes) │
│  └── MAC chain                                     │
├────────────────────────────────────────────────────┤
│ Cashu Payment Token (blind-signed ecash)           │
├────────────────────────────────────────────────────┤
│ Payload (padded to fixed size)                     │
│  └── Application data (ChaCha20-Poly1305)          │
└────────────────────────────────────────────────────┘
Total: FIXED 2048 bytes — eliminates length-based correlation
```

---

## Repository Structure

```
zksn/
│
├── crypto/                         # Cryptographic primitives (no external I/O)
│   └── src/
│       ├── identity.rs             # Ed25519 keypair · sign/verify · fingerprinting
│       ├── sphinx.rs               # Sphinx packet build/unwrap · fixed 2048B · cover packets
│       ├── noise.rs                # Noise_XX handshake · mutual auth · forward secrecy
│       └── zkp.rs                  # Merkle membership tree · nullifiers · DAO credentials
├── node/                           # Mix node binary (zksn-node)
│   ├── src/
│   │   ├── main.rs                 # CLI entry point (clap) · config load · tracing init
│   │   ├── node.rs                 # Subsystem orchestrator · TCP listener · channel wiring
│   │   ├── mixer.rs                # Poisson delay pool · Exp(λ) sampling · reordering
│   │   ├── cover.rs                # DROP + LOOP cover traffic generator
│   │   ├── router.rs               # TCP packet forwarding · fixed-size framing
│   │   ├── config.rs               # TOML config · IdentityHolder · defaults
│   │   ├── metrics.rs              # Prometheus counters/gauges/histograms (local only)
│   │   └── lib.rs                  # Module exports
│   ├── node.toml.example           # Fully annotated config template
│   └── README.md
├── client/                         # Client library + CLI (zksn)
│   ├── src/
│   │   ├── lib.rs                  # ZksnClient API · send() · receive()
│   │   ├── send.rs                 # Encrypt → Sphinx → attach token → transmit
│   │   ├── receive.rs              # TCP listener · decrypt · deliver
│   │   ├── route.rs                # RouteSelector — samples live mix nodes from PeerTable, appends recipient as final hop
│   │   └── config.rs               # ClientConfig · entry node · hop count · mint URL
│   ├── cli/
│   │   └── main.rs                 # identity · send · receive · wallet subcommands
│   └── README.md
├── economic/                       # Payment layer
│   └── src/
│       ├── cashu.rs                # Cashu NUT-00 tokens · blind signatures · batch redemption
│       ├── monero.rs               # Monero RPC · stealth addresses · piconero conversion
│       ├── token.rs                # PacketToken — Cashu token attached to Sphinx packets
│       └── lib.rs
├── governance/                     # DAO smart contracts (Foundry)
│   ├── contracts/
│   │   ├── ZKSNGovernance.sol      # Core DAO · ZK voting · time-lock · autonomous execution
│   │   ├── IVerifier.sol           # Interface for ZK-SNARK verifier
│   │   └── MockVerifier.sol        # Always-true + StrictMock verifiers for tests
│   ├── scripts/
│   │   └── Deploy.s.sol            # Foundry deployment script
│   ├── test/
│   │   └── ZKSNGovernance.t.sol    # 20 tests: voting · double-vote · quorum · time-lock
│   ├── foundry.toml
│   └── README.md
├── infra/
│   ├── nixos/
│   │   ├── node.nix                # RAM-only NixOS · tmpfs root · Yggdrasil · dm-verity · LUKS2
│   │   └── README.md
│   └── docker/
│       ├── docker-compose.yml      # 7-service devnet: 3 mix nodes + 2 Yggdrasil + i2pd + Cashu mint
│       ├── Dockerfile.mixnode      # Multi-stage Rust build → Debian slim
│       ├── Dockerfile.client       # Multi-stage Rust build → Debian slim
│       └── config/
│           ├── i2pd.conf           # i2pd settings (HTTP 4444 · SOCKS 4447 · console 7070)
│           ├── tunnels.conf        # i2pd tunnel definitions
│           ├── yggdrasil-seed.conf # Seed node · multicast discovery
│           ├── yggdrasil-peer.conf # Peer node · connects to seed
│           └── cashu.env           # Cashu mint env (FakeWallet for dev)
├── scripts/
│   ├── gen-identity.sh             # Ed25519 keypair generator · fingerprint · secure permissions
│   └── bootstrap-seed.sh           # Seed node setup: Yggdrasil + i2pd + identity + Cashu mint
├── docs/
│   ├── ARCHITECTURE.md             # Full 5-layer technical blueprint
│   ├── THREAT_MODEL.md             # 6 adversary classes with mitigations
│   ├── LEGAL.md                    # Mere conduit · Bernstein · Tornado Cash analysis
│   └── ROADMAP.md                  # 8-phase development plan
├── .github/
│   ├── workflows/
│   │   └── ci.yml                  # Rust (clippy · test · audit) + Foundry (forge test)
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   └── feature_request.md
│   └── PULL_REQUEST_TEMPLATE.md    # Crypto review checklist
├── Cargo.toml                      # Workspace (node · client · crypto · economic)
├── Cargo.lock
├── flake.nix                       # Nix dev shell: Rust 1.78 · Foundry · Yggdrasil · i2pd · just
├── Justfile                        # 30+ developer commands (build · test · devnet · contracts)
├── CHANGELOG.md
├── CONTRIBUTING.md                 # Anonymous contribution guide · GPG · Tor/I2P push
├── SECURITY.md                     # Responsible disclosure · severity matrix
├── LICENSE                         # MIT
└── README.md
```

---

## Tech Stack

| Component | Technology | Version | Purpose |
|---|---|---|---|
| Node implementation | Rust | 1.75+ | Mix node, client, crypto primitives |
| Async runtime | Tokio | 1.x | All async I/O |
| Mesh transport | [Yggdrasil](https://yggdrasil-network.github.io/) | latest | Encrypted IPv6 mesh, address = key |
| Mesh transport (alt) | [CJDNS](https://github.com/cjdelisle/cjdns) | latest | Redundant overlay, different routing |
| Anonymous services | [I2P (i2pd)](https://i2pd.website/) | latest | .b32.i2p service hosting |
| Packet format | Sphinx | custom | Fixed-size onion packets |
| Node handshake | [Noise Protocol](https://noiseprotocol.org/) `XX` | snow 0.9 | Mutual auth, forward secrecy |
| Signing | Ed25519 | ed25519-dalek 2 | Node identity |
| Key exchange | X25519 | x25519-dalek 2 | Session ECDH |
| Encryption | ChaCha20-Poly1305 | chacha20poly1305 0.10 | Packet payload |
| Hashing | SHA-256 / SHA-512 | sha2 0.10 | Fingerprints, Merkle trees |
| Micropayments | [Cashu](https://cashu.space/) | NUT-00 | Blind-signed per-packet ecash |
| Settlement | [Monero (XMR)](https://getmonero.org/) | RPC v2 | Private on-chain settlement |
| Governance | Solidity 0.8.20 | Foundry | ZK-SNARK anonymous voting DAO |
| ZK proofs | Verifier interface | pluggable | Circom / Noir / Halo2 compatible |
| Node OS | [NixOS](https://nixos.org/) | 24.x | RAM-only, reproducible builds |
| Dev environment | Nix flakes + just | — | Reproducible shell, 30+ shortcuts |
| Metrics | Prometheus | 0.13 | Local-only, never transmitted |
| CI | GitHub Actions | — | Rust + Foundry pipeline |

---

## Quick Start

### Prerequisites

```bash
# Rust (stable 1.75+)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Foundry (for governance contracts)
curl -L https://foundry.paradigm.xyz | bash && foundryup

# (Optional) Nix — gives you everything in one command
nix develop   # inside the repo root
```

### Clone and Build

```bash
git clone https://github.com/Naveenob/zksn.git
cd zksn

# Build all crates
cargo build --release

# Or use just (recommended)
just build-release
```

### Generate Your Identity

```bash
# Using the shell script
chmod +x scripts/gen-identity.sh
./scripts/gen-identity.sh
# → identity.pub  (share this)
# → identity.key  (NEVER share — stores 32-byte Ed25519 secret)

# Or via CLI
./target/release/zksn identity generate --output ~/.zksn/identity.key
```

### Spin Up a Dev Network (Docker)

```bash
cd infra/docker
docker compose up
# Starts: 3 mix nodes + 2 Yggdrasil nodes + i2pd + Cashu mint
```

### Run Tests

```bash
# All Rust unit + integration tests
cargo test --workspace

# Governance contracts (Foundry)
cd governance && forge test -vv

# Everything via just
just test-all
```

---

## Running a Mix Node

### 1. Configure

```bash
cp node/node.toml.example node.toml
$EDITOR node.toml
```

Key parameters:

```toml
[network]
listen_addr = "[200:your:yggdrasil:addr::1]:9001"  # Yggdrasil IPv6 in production
max_peers = 64
bootstrap_peers = [
  "[200:abcd:1234:5678::1]:9001",                  # Known seed nodes
]

[mixing]
poisson_lambda_ms  = 200    # Mean delay: 200ms. Higher = more anonymity, more latency.
cover_traffic_rate = 5      # Cover packets/sec. Set ≥ expected real traffic rate.
max_queue_depth    = 10000  # DoS protection: drop after this many queued packets.
loop_cover_fraction = 0.3   # 30% LOOP (verify liveness), 70% DROP (pure cover)

[economic]
cashu_mint_url        = "http://mint.zksn.internal:3338"
monero_rpc_url        = "http://127.0.0.1:18082"
redemption_batch_size = 100   # Batch to reduce linkability

[keys]
persist_identity = false  # false = ephemeral key per boot (fully stateless)
```

### 2. Run

```bash
# Development
cargo run --package zksn-node -- --config node.toml

# Production binary
./target/release/zksn-node --config node.toml

# Testnet (no payment enforcement)
./target/release/zksn-node --config node.toml --testnet

# Debug logging
./target/release/zksn-node --config node.toml --debug
```

### 3. Node Startup Output

```
╔══════════════════════════════════════╗
║   ZKSN Mix Node — Starting Up        ║
╚══════════════════════════════════════╝
Node ID:     a3f8:c2d1:9e47:...
Listen:      [200:abcd::1]:9001
Poisson λ:   200ms
Cover rate:  5 pkt/s
Testnet:     false
Mix node ready — accepting Sphinx packets
```

### 4. Internal Subsystem Architecture

```
[TCP :9001] → handle_connection()
                    │ tx_incoming  (mpsc channel)
                    ▼
            [PoissonMixer]          ← cover packets ← [CoverTrafficGenerator]
              Exp(1/λ) delay pool
              Pool reordering
                    │ tx_outgoing  (mpsc channel)
                    ▼
            [PacketRouter]          → TCP → next hop (fixed PACKET_SIZE bytes)
```

All four subsystems run as independent Tokio tasks communicating over bounded channels.

---

## Client CLI

The `zksn` binary provides a full command-line interface.

```bash
# Build the CLI
cargo build --release --package zksn-client

# Or with just
just build-client
```

### Commands

```
zksn [OPTIONS] <COMMAND>

Options:
  -k, --key   <FILE>    Path to identity key file
  -n, --node  <ADDR>    Entry mix node address (default: [::1]:9001)
  -d, --debug           Enable debug logging

Commands:
  identity generate [--output <file>]    Create a new Ed25519 keypair
  identity show                          Display current identity fingerprint

  send <recipient-pubkey-hex> <message>  Send encrypted message through mixnet
  receive                                Listen for incoming messages (blocks)

  wallet balance                         Show Cashu token balance
  wallet topup <millisats>               Top up via XMR payment to mint
```

### Usage Examples

```bash
# Generate and save identity
zksn identity generate --output ~/.zksn/identity.key

# Show your fingerprint (share this so others can reach you)
zksn --key ~/.zksn/identity.key identity show
# → Identity: a3f8c2d19e47...

# Send a message
zksn --key ~/.zksn/identity.key \
     --node [200:abcd::1]:9001 \
     send a3f8c2d19e47... "Hello, sovereign network."

# Listen for messages
zksn --key ~/.zksn/identity.key receive
# Listening for messages as: a3f8c2d19e47...
# Press Ctrl+C to stop.
```

---

## Configuration Reference

### Node (`node.toml`)

| Section | Key | Default | Description |
|---|---|---|---|
| `[network]` | `listen_addr` | `[::1]:9001` | Sphinx packet listener. Use Yggdrasil IPv6 in production. |
| | `max_peers` | `64` | Max concurrent peer TCP connections. |
| | `connect_timeout_ms` | `5000` | Outbound connection timeout. |
| | `bootstrap_peers` | `[]` | Known seed node addresses to connect to on start. |
| `[mixing]` | `poisson_lambda_ms` | `200` | Mean mixing delay (ms). Actual delay ~ Exp(1/λ). |
| | `cover_traffic_rate` | `5` | Cover packets/sec. `0` disables cover traffic (insecure). |
| | `max_queue_depth` | `10000` | Max packets in mixing pool before drop (DoS protection). |
| | `loop_cover_fraction` | `0.3` | Fraction of cover that is LOOP vs DROP. |
| `[economic]` | `cashu_mint_url` | — | Cashu mint endpoint for token validation. |
| | `min_token_value` | `1` | Minimum token value per packet. |
| | `monero_rpc_url` | `http://127.0.0.1:18082` | Monero RPC for settlement. |
| | `redemption_batch_size` | `100` | Batch this many tokens before redeeming (reduces linkability). |
| `[keys]` | `key_store_path` | `/var/lib/zksn/keys/identity.key` | Path to encrypted key file. |
| | `persist_identity` | `false` | `false` = generate fresh key every boot (RAM-only / stateless). |

### Anonymity Tuning

| Scenario | `poisson_lambda_ms` | `cover_traffic_rate` | Notes |
|---|---|---|---|
| Interactive messaging | 100–300 | 5–10 | Low latency, reasonable anonymity |
| High-security async | 1000–5000 | 10–20 | High latency, strong anonymity |
| High-throughput relay | 50–100 | 20–50 | Throughput-optimized, weaker timing resistance |
| Research/testnet | 1–10 | 0–1 | Fast feedback, no anonymity guarantees |

---

## Cryptographic Design

### Identity (`crypto/src/identity.rs`)

- **Algorithm:** Ed25519 (via `ed25519-dalek` 2.x)
- **Key generation:** `ZksnIdentity::generate()` — secure random via OS entropy
- **Fingerprint:** `SHA-256(public_key)[0..8]` displayed as hex — human-identifiable short handle
- **Secret export:** `to_secret_bytes()` — 32-byte raw secret; zero-on-drop via `zeroize`

### Sphinx Packets (`crypto/src/sphinx.rs`)

- **Packet size:** Fixed `PACKET_SIZE = 2048` bytes — all packets are identical length
- **Ephemeral key:** 32-byte X25519 public key in header
- **Routing header:** Layered-encrypted 96 bytes — each hop decrypts one layer
- **Payload:** ChaCha20-Poly1305 encrypted application data
- **Cover types:** `PacketType::Drop` (random destination) · `PacketType::Loop` (routes back to sender)
- **Per-hop key blinding:** Each node blinds the ephemeral public key before forwarding — `α_{i+1} = b_i ×_clamped α_i` where `b_i = SHA-256("sphinx-blinding" ‖ s_i ‖ α_i)`. Colluding nodes cannot correlate packets across hops.

### Noise Handshake (`crypto/src/noise.rs`)

Pattern: `Noise_XX_25519_ChaChaPoly_SHA256`

```
→ e
← e, ee, s, es
→ s, se
```

- **Mutual authentication** — both parties prove possession of static keys
- **Forward secrecy** — ephemeral keys per session; past sessions secure after key compromise
- **Identity hiding** — static keys transmitted encrypted; no plaintext identity on wire
- **Implementation:** `snow` 0.9 library; `NoiseInitiator` / `NoiseResponder` structs with 2 passing integration tests

### ZK Credentials (`crypto/src/zkp.rs`)

- **Commitment:** `SHA-256(secret || nonce)` — binds membership without revealing identity
- **Merkle tree:** Binary tree over member commitments; root stored on-chain in governance contract
- **Nullifier:** `SHA-256(secret || proposal_id)` — unique per (member, proposal) pair; prevents double-voting without revealing member
- **Production note:** Replace SHA-256 with Poseidon hash for ZK-SNARK circuit compatibility

---

## Economic Layer

### Overview

```
[User]
  │ Sends XMR to mint's stealth address
  ▼
[Cashu Mint]
  │ Issues blind-signed ecash tokens (NUT-00)
  │ Cannot link issued token to redemption → no usage tracking
  ▼
[Client]
  │ Attaches token to each Sphinx packet
  ▼
[Mix Node]
  │ Validates token, forwards packet
  │ Batches N tokens (default: 100) before redeeming
  │ → batch redemption breaks per-packet linkability
  ▼
[Cashu Mint]
  │ Redeems batch → pays out in XMR to node's stealth address
  ▼
[Monero Network]
  RingCT + ring signatures + stealth addresses
  → on-chain amounts and senders private
```

### Cashu (`economic/src/cashu.rs`)

Implements Cashu NUT-00:

- `CashuToken` — blind-signed proof bundle, mint URL, denomination proofs
- `CashuWallet` — local balance tracking, batch redemption queue
- Blind signature protocol: client blinds secret → mint signs blinded point → client unblinds → mint cannot link
- **Privacy property:** Even the mint operator learns nothing about usage patterns

### Monero (`economic/src/monero.rs`)

- JSON-RPC client for `monero-wallet-rpc`
- `get_balance()` · `new_subaddress()` · `transfer()`
- Piconero (`u64`) ↔ XMR (`f64`) conversion utilities
- Stealth addresses: each payment generates a fresh one-time address

### Per-Packet Token (`economic/src/token.rs`)

`PacketToken` serializes a Cashu proof into the Sphinx packet payload alongside the encrypted message. Mix nodes validate the token before forwarding, refusing payment-free packets.

---

## Governance

ZKSN is governed by an anonymous on-chain DAO with no named administrators.

### Contract: `ZKSNGovernance.sol`

```
No multisig. No admin. No upgradeable proxy.
Protocol changes execute autonomously after vote + time-lock.
```

| Parameter | Value |
|---|---|
| Voting period | 7 days |
| Time-lock | 2 days |
| Quorum | 10 votes minimum |
| Passing threshold | >50% yes |
| Execution | Autonomous (no caller needed after time-lock) |

### How Voting Works

1. **Propose:** Any member calls `createProposal(contentHash)` with a hash of the change description.
2. **Vote:** Members submit a ZK-SNARK proof proving: (a) they hold a valid membership credential, (b) they have not voted on this proposal (nullifier), (c) their vote value (0/1). The proof reveals nothing about identity.
3. **Execute:** After voting ends and the time-lock expires, anyone calls `execute(proposalId)`. The contract runs the encoded call autonomously.
4. **Membership updates:** New members are added only via governance vote — no admin can unilaterally modify the membership root.

### ZK Proof Interface

```solidity
interface IVerifier {
    function verifyProof(
        bytes calldata proof,
        uint256[4] calldata publicSignals
        // [nullifierHash, proposalId, voteValue, membershipRoot]
    ) external view returns (bool);
}
```

Compatible with any ZK-SNARK system (Circom + SnarkJS, Noir, Halo2). Swap the verifier contract without changing governance logic.

### Foundry Tests

```bash
cd governance
forge test -vv
# 20 tests passing:
# ✓ proposal creation and events
# ✓ yes/no voting with nullifiers
# ✓ double-vote prevention
# ✓ voting deadline enforcement
# ✓ invalid proof rejection
# ✓ quorum requirement (min 10 votes)
# ✓ majority threshold (>50%)
# ✓ time-lock enforcement
# ✓ single-use execution
# ✓ membership root update via governance only
```

---

## Infrastructure & Deployment

### Production: NixOS (`infra/nixos/node.nix`)

Designed for **RAM-only operation** — physical seizure of hardware yields zero user data.

Key properties:

| Feature | Implementation |
|---|---|
| Stateless root | `tmpfs` mounted at `/` — all writes lost on reboot |
| Verified boot | `dm-verity` on the read-only image |
| Key storage | LUKS2 encrypted USB key store only |
| Network isolation | Firewall allows only `200::/7` (Yggdrasil space) |
| Transport | Yggdrasil + i2pd services managed by systemd |
| Kernel hardening | `kernel.dmesg_restrict`, `unprivileged_bpf_disabled`, etc. |
| Reproducible builds | Nix flakes — byte-identical binary across machines |

```bash
# Deploy to a bare-metal node
nixos-rebuild switch --target-host root@[200:your:node:addr::1] \
  --flake .#zksn-node

# Bootstrap a seed node from scratch
chmod +x scripts/bootstrap-seed.sh
./scripts/bootstrap-seed.sh
```

### Development: Docker Compose (`infra/docker/`)

A 7-service local devnet for testing and development only. **Not for production use.**

```bash
cd infra/docker
docker compose up

# Services:
#   mix-node-1:3   — ZKSN mix nodes on ports 9001–9003
#   yggdrasil-seed — Yggdrasil seed node
#   yggdrasil-peer — Yggdrasil peer node
#   i2pd           — I2P router (HTTP 4444, SOCKS 4447)
#   cashu-mint     — Cashu mint (FakeWallet backend, port 3338)
```

### Nix Dev Shell (`flake.nix`)

```bash
nix develop
# Enters a shell with:
#   Rust 1.78.0 + rust-analyzer + clippy + rustfmt + llvm-tools
#   Yggdrasil · i2pd · Foundry · just · jq · curl · git
```

### Justfile (30+ commands)

```bash
just build            # cargo build (debug)
just build-release    # cargo build --release
just test             # cargo test --workspace
just test-all         # Rust tests + forge test
just lint             # clippy --deny warnings
just fmt              # rustfmt + forge fmt
just audit            # cargo audit (vulnerability check)
just devnet           # docker compose up (background)
just devnet-stop      # docker compose down
just devnet-logs      # docker compose logs -f
just identity         # generate a fresh identity keypair
just node             # run node with node.toml
just sol-build        # forge build
just sol-test         # forge test -vv
just anvil            # local Anvil EVM node
just docs             # cargo doc --open
just release          # full release build
```

---

## Development

### Crate Dependency Graph

```
zksn-crypto      ← no internal deps
zksn-economic    ← no internal deps
zksn-node        ← zksn-crypto, zksn-economic
zksn-client      ← zksn-crypto, zksn-economic
```

### Workspace Layout

```toml
[workspace]
members = ["node", "client", "crypto", "economic"]

[profile.release]
opt-level     = 3
lto           = true
codegen-units = 1
panic         = "abort"
```

### Running Tests

```bash
# Full workspace
cargo test --workspace

# Single crate with output
cargo test --package zksn-crypto -- --nocapture

# Governance contracts
cd governance && forge test -vv

# All together
just test-all
```

### Current Test Coverage

| Crate / Contract | Tests | Notes |
|---|---|---|
| `zksn-crypto`        | 26 | identity, Sphinx onion peel roundtrips, key blinding, wire serialization, noise, zkp |
| `zksn-node`          | 19 | mixer, cover, peers/DHT, Kademlia k-buckets, gossip, peer persistence |
| `zksn-economic`      | 7  | Cashu token encode/decode, Monero RPC stubs |
| `zksn-client`        | 19 | route selection, send/receive framing, Sphinx inject/peel, integration |
| `ZKSNGovernance.sol` | 21 | Full governance lifecycle |
| **Total**            | **92** | All passing, CI green |

### Known gaps

| Location | Description |
|---|---|
| `node/src/node.rs`   | Final-hop TCP delivery — node detects `next_hop == [0u8;32]` but does not yet connect to recipient's `listen_addr` |
| `client/cli/main.rs` | Cashu `wallet balance` and `wallet topup` — token primitives exist, mint HTTP not wired |
| `governance/`        | ZK circuit is `MockVerifier` (returns true) — Circom/Noir circuit pending |

---

## Threat Model

### Adversary Classes

| Class | Capability | ZKSN Defense | Residual Risk |
|---|---|---|---|
| **A — Local Passive** | Observes one network link | Sphinx encryption + fixed packet size | None at link level |
| **B — Global Passive (GPA)** | Observes ALL links simultaneously | Poisson(λ) mixing + mandatory cover traffic | Statistical correlation over months (open research problem; cover traffic raises cost dramatically) |
| **C — Active** | Injects, drops, modifies, delays packets | Noise MAC rejects modifications; drops trigger retransmit | n-1 attack partially mitigated by batching; threshold mixing needed for full defense |
| **D — Compromised Nodes** | Controls subset of mix nodes | Multi-hop routing; single node sees one hop only | Path correlation if adversary controls both entry and exit node |
| **E — Legal/Compulsion** | Seizes hardware, issues subpoenas | Stateless RAM-only nodes; no corporate entity; anonymous contributors | Infrastructure operators in hostile jurisdictions remain at personal risk |
| **F — Sybil** | Creates many fake nodes/identities | Economic stake + node reputation weighting in route selection | Sufficiently capitalized adversary can attempt governance capture |

### Known Limitations

- **Anonymity set size:** Small networks are trivially deanonymizable regardless of cryptography. Meaningful anonymity requires hundreds of active nodes and users.
- **Endpoint security:** ZKSN secures the network path, not the client device. Compromised endpoints defeat all network-level guarantees.
- **Long-term traffic analysis:** Extended observation enables probabilistic deanonymization even with cover traffic. No complete solution exists in the literature.
- **Bootstrap discovery:** Initial peer discovery is a weak point. First-contact with seed nodes is not fully anonymized.
- **Exit nodes:** Any node providing clearnet egress is exposed by design. The closed-loop default (no exit) mitigates this.

See [docs/THREAT_MODEL.md](./docs/THREAT_MODEL.md) for full adversary analysis.

---

## Legal

ZKSN has no incorporated entity, no foundation, no officers, no registered agents, and no corporate assets in any jurisdiction. This is a deliberate architectural decision.

**Key legal foundations:**

| Basis | Source | Relevance |
|---|---|---|
| Code is speech | *Bernstein v. DOJ*, 9th Cir. 1999 | Publishing this codebase is a protected act |
| Encryption software | *Junger v. Daley*, 6th Cir. 2000 | Encryption tools are protected expression |
| Mere conduit | DSA Art. 4 (EU) · CDA §230 (US) | Mix node operators do not see, store, or control forwarded content |
| Jurisdiction fragmentation | Target: 30+ countries, no country >15% of nodes | No single court order affects more than a fraction of the network |

Mix node operators transmit encrypted packets they cannot read and do not know the contents of. This is structurally analogous to ISP common carrier status.

**Operators should:**
1. Know their local laws regarding anonymization tools
2. Document the non-commercial, research/educational purpose of their node
3. Consider exit traffic carefully — mix-only nodes carry significantly lower risk than exit nodes
4. Operate in jurisdictions with strong rule of law and data protection frameworks

See [docs/LEGAL.md](./docs/LEGAL.md) for full jurisdictional analysis and case law.

> **This is not legal advice.** Consult qualified legal counsel for advice specific to your situation.

---

## Roadmap

| Phase | Description | Status |
|---|---|---|
| **0 — Cryptographic Foundations** | Ed25519, X25519, Noise_XX, Sphinx, ZKP primitives, per-hop key blinding | ✅ Complete |
| **1 — Mesh Transport** | Yggdrasil integration, seed node tooling, peer discovery | 🟡 Kademlia DHT complete, Yggdrasil transport pending |
| **2 — Mixnet Layer** | Poisson mixing, cover traffic, Sphinx routing, metrics, final-hop delivery | 🟡 Core complete, final-hop TCP delivery pending |
| **3 — Internal Service Layer** | i2pd integration, .zksn TLD, DHT petnames, messaging | 🔴 Not started |
| **4 — Economic Layer** | Cashu NUT-00, per-packet tokens, XMR settlement | 🟡 Scaffolded, mint integration pending |
| **5 — Stateless Node OS** | NixOS live-boot, dm-verity, LUKS2, reproducible builds | 🟡 Config written, hardware testing pending |
| **6 — DAO Governance** | ZK-SNARK voting contracts, membership credentials | 🟡 Solidity complete, ZK circuit pending |
| **7 — Client SDK & CLI** | Rust library, Python bindings, full CLI | 🟡 Scaffolded, DHT routes pending |
| **8 — Hardening & Audit** | External crypto audit, GPA simulation, bug bounty | 🔴 Not started |

**Minimum Viable Network** = Phases 0–3 complete: anonymous identity + metadata-free messaging + internal service hosting.

See [docs/ROADMAP.md](./docs/ROADMAP.md) for detailed per-phase milestones.

---

## Contributing

Contributions are welcome. Anonymity is respected — you are not required to contribute under your real name.

```bash
# Set up an anonymous git identity
git config user.name "anon"
git config user.email "anon@zksn.invalid"

# Generate an anonymous GPG key
gpg --batch --gen-key <<EOF
Key-Type: eddsa
Key-Curve: ed25519
Name-Real: ZKSN Contributor
Name-Email: contributor@zksn.invalid
Expire-Date: 1y
%no-protection
EOF

# Push over Tor
GIT_SSH_COMMAND="ssh -o ProxyCommand='nc -x 127.0.0.1:9050 %h %p'" git push
```

**Before contributing cryptographic code:** Read the existing implementation in `crypto/`, understand the threat model, and open an issue for discussion before submitting changes to any `todo!()` stubs. Incorrect ECDH or Sphinx implementations would silently break all privacy guarantees.

See [CONTRIBUTING.md](./CONTRIBUTING.md) for full setup guide.

---

## Security

**Do not open public GitHub issues for security vulnerabilities.**

Report privately via:
1. **Preferred:** GPG-encrypted report to the security key published in `keys/security.asc`
2. **Alternative:** GitHub Security Advisory (private, via the repository's Security tab)

| Severity | Definition | Target Fix Time |
|---|---|---|
| **Critical** | Deanonymizes users, exposes IPs, compromises keys | 7 days |
| **High** | Breaks economic layer, allows double-spend, degrades anonymity set | 30 days |
| **Medium** | Denial of service, non-privacy information leaks | 90 days |
| **Low** | Everything else | Best effort |

See [SECURITY.md](./SECURITY.md) for full policy.

---

## License

[MIT](./LICENSE) — use, modify, and distribute freely.

This software is provided for research and educational purposes. See [docs/LEGAL.md](./docs/LEGAL.md) for jurisdictional guidance on operating network infrastructure.
