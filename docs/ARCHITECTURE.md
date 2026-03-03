# ZKSN Architecture

## Design Principles

1. **Defense in depth** — No single layer knows the full picture. Identity, transport, mixing, and payment planes are cryptographically isolated.
2. **Closed-loop by default** — All services are internal. Clearnet access is an isolated, optional, audited exit module.
3. **Cryptographic identity only** — A participant is their public key. No registration, no email, no username.
4. **Mandatory cover traffic** — Silence is not allowed. Nodes continuously emit traffic indistinguishable from real messages.

## System Layers

### Layer 0 — Mesh Transport
- **Primary:** Yggdrasil — self-arranging encrypted IPv6 mesh. Address = SHA-512(pubkey). No IANA, no ASN.
- **Fallback:** CJDNS — redundant mesh, different routing algorithm.
- **Air-gap:** Meshtastic (LoRa) — physical radio mesh for infrastructure-independent connectivity.

### Layer 1 — Mixnet
- **Packet format:** Sphinx — fixed 2048 bytes, layered encryption, each node sees one hop only.
- **Mixing:** Poisson(λ) continuous-time delays. Defeats timing correlation even against a Global Passive Adversary.
- **Cover traffic:** DROP (discarded at random node) + LOOP (returns to sender). Both indistinguishable from real traffic.

### Layer 2 — Anonymous Services
- **i2pd** — .b32.i2p addressing, garlic routing, server IP never exposed.
- **.zksn TLD** — DHT-based petname resolution. No DNS, no CA.

### Layer 3 — Identity
- Ed25519 long-term keypairs. X25519 session ECDH. Noise_XX handshake.
- Forward secrecy, mutual authentication, identity hiding on the wire.

### Layer 4 — Economics
- **Cashu** — Chaumian blind-signed ecash. Mint cannot link issuance to redemption.
- **Monero XMR** — Stealth addresses, RingCT, ring signatures. Private on-chain settlement.

## Data Flow

```
[Client]
  │ 1. Encrypt payload (X25519 + ChaCha20-Poly1305)
  │ 2. Build Sphinx packet: layer-encrypt for [mix1, mix2, mix3, dest]
  │ 3. Attach Cashu token
  │ 4. Send over Yggdrasil TCP
  ▼
[Mix1] unwrap outer layer → hold Exp(λ) → forward
[Mix2] unwrap → hold → forward
[Mix3] unwrap → hold → forward to I2P service
  ▼
[Destination] decrypt payload — sender unknown, path unknown, timing obfuscated
```

## Threat Model Summary

| Threat | Mitigation | Residual Risk |
|---|---|---|
| Global Passive Adversary | Poisson mixing + cover traffic | Statistical attacks over very long periods |
| Node seizure | Stateless RAM-only NixOS | Physical hardware attack |
| Sybil governance attack | ZK PoS voting | Wealthy adversary can attempt capture |
| Developer identification | Anonymous contribution | Long-term OPSEC failure |
