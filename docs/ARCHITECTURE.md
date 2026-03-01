# ZKSN Architecture

## Table of Contents

1. [Design Principles](#design-principles)
2. [System Layers](#system-layers)
3. [Data Flow](#data-flow)
4. [The Entrance/Exit Problem](#the-entranceexit-problem)
5. [Closed-Loop Architecture](#closed-loop-architecture)
6. [Threat Model Summary](#threat-model-summary)

---

## Design Principles

### 1. Defense in Depth Through Separation of Concerns
No single layer knows the full picture. Each plane (identity, transport, mixing, payment) is cryptographically isolated from the others. Compromise of one layer does not cascade.

### 2. Closed-Loop By Default
The network is a sovereign environment for its own services first. Clearnet access is an isolated, optional, audited exit module — never the primary use case.

### 3. Cryptographic Identity Only
A participant is their public key. There is no registration, no email verification, no username. The keypair is generated locally and never transmitted in plaintext.

### 4. Mandatory Cover Traffic
Silence is not allowed at the protocol level. Nodes and clients continuously emit cover traffic indistinguishable from real traffic, defeating Global Passive Adversary (GPA) timing correlation.

---

## System Layers

### Layer 0 — Physical Mesh Transport

**Primary:** Yggdrasil Network
- Self-arranging encrypted IPv6 mesh
- Node addresses cryptographically derived from public keys
- No central routing authority, no IANA, no ASN required
- Supports tunneling over any underlying transport (TCP, UDP, TLS, even serial links)

**Secondary:** CJDNS
- Redundant mesh overlay with different routing algorithm
- Cross-compatible nodes provide resilience

**Tertiary (air-gap capable):** Meshtastic (LoRa), GoTenna
- Physical radio mesh for infrastructure-independent connectivity
- Yggdrasil tunnels over LoRa links for true off-grid operation

**Addressing:**
```
Yggdrasil IPv6 = SHA-512(public_key)[0:16] mapped to 200::/7 range
No DNS. No registry. Address IS the key.
```

### Layer 1 — Mixnet (Anonymity Engine)

**Implementation:** Nym Network mix nodes

**Packet Format:** Sphinx
- Each packet is fixed-size (eliminates length-based correlation)
- Layered encryption: each mix node unwraps exactly one layer
- A mix node knows only: previous hop + next hop. Never source or final destination.

**Mixing Strategy:** Continuous-time Poisson mixing
```
delay ~ Poisson(λ)   where λ is tunable per node
```
Packets are held and released according to independent Poisson processes, destroying timing correlation even against a GPA that observes all links simultaneously.

**Cover Traffic:**
- `LOOP` messages: client sends packet that routes back to itself
- `DROP` messages: sent to random nodes, discarded silently
- Both are cryptographically indistinguishable from real traffic

### Layer 2 — Anonymous Service Layer

**Implementation:** I2P (i2pd C++ implementation)

- Internal `.b32.i2p` addresses derived from keypairs
- Garlic routing (multi-message bundling for efficiency)
- No exposure of server IP address to clients
- Hosts: web services, messaging, file sharing, APIs — all internal

**ZKSN Native Addressing:** `.zksn` TLD (internal only)
- Petname system: users assign local nicknames to public keys
- No global namespace server
- No DNS, no certificate authority

### Layer 3 — Identity & Key Exchange

**Long-term identity:** Ed25519 keypairs
**Session key exchange:** X25519 (ECDH)
**Handshake protocol:** Noise Framework (`Noise_XX` pattern)

```
Noise_XX handshake:
  → e
  ← e, ee, s, es
  → s, se
```

Provides:
- Mutual authentication by public key
- Forward secrecy (ephemeral keys per session)
- Identity hiding (static keys transmitted encrypted)
- Zero metadata about participant identities on the wire

### Layer 4 — Economic Sovereignty

**Settlement Layer:** Monero (XMR)
- Stealth addresses: recipient unlinkability
- RingCT: transaction amount confidentiality
- Ring signatures: sender ambiguity set
- Node-to-node bandwidth settlement at configurable intervals

**Micropayment Layer:** Cashu (Chaumian Ecash)
```
Flow:
1. User deposits XMR to mint's stealth address
2. Mint issues blind-signed ecash tokens (W-DAI style)
3. Each packet carries an encrypted, unlinkable token
4. Mix nodes batch-redeem tokens → no per-packet linkability
5. Redemption settled on-chain in XMR
```

Blind signature property: mint cannot link issued token to redeemed token. Even the mint operator learns nothing about usage patterns.

---

## Data Flow

### Sending a Message (Internal Service)

```
[Client]
  │
  │ 1. Encrypt payload for destination public key (X25519 + ChaCha20-Poly1305)
  │
  │ 2. Wrap in Sphinx packet:
  │    - Select random path: [mix1, mix2, mix3, destination]
  │    - Layer encrypt: encrypt(encrypt(encrypt(payload, mix3), mix2), mix1)
  │    - Attach Cashu token (blind-signed, unlinkable)
  │
  ▼
[Mix Node 1]  — unwraps outer layer, sees only: "forward to mix2"
               — holds packet for Poisson(λ) time
               — emits cover traffic continuously
  │
  ▼
[Mix Node 2]  — unwraps, sees only: "forward to mix3"
  │
  ▼
[Mix Node 3]  — unwraps, sees only: "forward to destination"
  │
  ▼
[I2P Service] — receives encrypted payload, decrypts with private key
               — sender is unknown
               — path is unknown
               — timing is obfuscated
```

### Packet Structure

```
┌─────────────────────────────────────────────┐
│ Sphinx Header (fixed size)                  │
│  ├── Routing information (layered encrypted) │
│  ├── SURB (Single-Use Reply Block)          │
│  └── MAC chain                              │
├─────────────────────────────────────────────┤
│ Cashu Payment Token (blind-signed)          │
├─────────────────────────────────────────────┤
│ Payload (fixed size, padded)                │
│  └── Application data (encrypted)           │
└─────────────────────────────────────────────┘
Total packet size: FIXED (e.g., 2048 bytes)
Padding: PKCS#7 to fixed size
```

Fixed packet size eliminates message-length traffic analysis.

---

## The Entrance/Exit Problem

When any node in a private network connects to the clearnet, that node becomes a **chokepoint**:
- It sees the clearnet destination
- Its IP is exposed to the destination server
- It is identifiable and locatable by law enforcement
- It bears legal liability for traffic it forwards

This is why Tor exit nodes have been seized and their operators visited by federal agents.

### ZKSN's Solution: Tiered Exit Architecture

**Tier 0 (Default): No Exit**
All services are internal. No clearnet access by default. This is the closed-loop architecture.

**Tier 1: Voluntary Distributed Exit**
- Nodes opt-in to exit functionality with explicit policy files
- Policy file specifies: allowed ports, blocked destinations, rate limits
- Modeled on Tor Project's exit policy (legally tested in multiple jurisdictions)
- No single node handles enough traffic to be a meaningful legal target
- Exit node operators are protected by "mere conduit" doctrine (DSA Article 4 / CDA Section 230 analog)

**Tier 2: Probabilistic Residential Exit**
- Consenting residential nodes share bandwidth for exit
- Traffic distributed across hundreds of nodes
- No individual node handles sufficient traffic to trigger legal scrutiny
- Opt-in, time-limited, bandwidth-capped

---

## Closed-Loop Architecture

The network's primary value is as a **sovereign namespace**:

```
ZKSN Internal Services:
├── Messaging (I2P-based, no metadata)
├── File sharing (I2P torrents)
├── Web services (.zksn domains)
├── DNS equivalent (DHT-based petname resolution)
├── Code repositories (git over I2P)
└── DAO governance interface
```

Services are reachable only from within the network. Their operators' IP addresses are never exposed. There is no central server to seize.

---

## Threat Model Summary

| Threat | Mitigation | Residual Risk |
|---|---|---|
| Global Passive Adversary | Poisson mixing + cover traffic | Statistical attacks over very long periods |
| Entry/Exit correlation | Closed-loop default + distributed exit | Voluntary exit nodes remain soft target |
| Sybil attack on governance | Proof-of-stake + web-of-trust | Wealthy adversary can still attempt capture |
| Node seizure | Stateless RAM-only OS | Physical hardware attack still possible |
| Developer identification | Anonymous contribution, no foundation | Long-term OPSEC failure |
| Protocol-level deanonymization | Sphinx + Noise + fixed packet size | Theoretical future cryptanalysis |
| Endpoint compromise | Stateless OS + air-gap key material | Hardware-level attacks (IME, firmware) |

See [THREAT_MODEL.md](./THREAT_MODEL.md) for full adversary analysis.
