# ZKSN Security Brief

**For:** External security auditors  
**Repository:** https://github.com/Naveenob/zksn  
**Version:** v1.2.0-pre  
**Date:** March 2026

This document is written for a security reviewer with cryptographic expertise
who has not seen the codebase before. It explains what the system is, how it
works at the level relevant to security review, and what the highest-risk areas
are in the reviewer's opinion of the implementation team.

---

## What ZKSN is

A metadata-resistant peer-to-peer network. The design goal is that no
participant — including node operators, the payment mint, network observers,
or law enforcement with full network visibility — can determine who is
communicating with whom, about what, or when.

The system has five independent layers of protection:

1. **Sphinx onion routing** — messages are wrapped in multiple layers of
   authenticated encryption. Each mix node decrypts exactly one layer and
   sees only its predecessor and successor in the path. No node sees both
   sender and receiver.

2. **Poisson delay mixing** — packets are held for a random interval drawn
   from `Exp(1/λ)` before forwarding. This is the primary defence against
   timing correlation attacks.

3. **Cover traffic** — every node continuously emits packets
   indistinguishable from real traffic (`DROP` type discarded at a random
   node, `LOOP` type routed back to the sender). The cover traffic rate is
   configurable but defaults to 5 packets/second.

4. **Chaumian ecash payments** — each packet carries a blind-signed Cashu
   token. The mint cannot link token issuance to redemption, so the payment
   layer does not leak routing information.

5. **Yggdrasil mesh transport** — the network operates over an encrypted
   IPv6 overlay where node addresses are derived from public keys
   (`SHA-512(pubkey)`). Physical IP addresses are not used. The binary
   enforces `200::/7` (the Yggdrasil address space) at bind, inbound
   accept, and outbound dial.

---

## Trust model

**What an honest node operator knows:**
- Their own Yggdrasil address
- The addresses of their immediate peers (Kademlia table)
- That packets pass through them (but not source or destination)
- How much ecash they have earned

**What an honest node operator does NOT know:**
- Who sent any packet
- Who will receive any packet
- What any packet contains
- Which other nodes are in any routing path

**What the Cashu mint knows:**
- That a blinded point was submitted for signing
- That a proof was later verified as unspent
- The denomination values involved

**What the Cashu mint does NOT know:**
- The identity of the token issuer
- The identity of the token redeemer
- That the issuer and redeemer are related

---

## Cryptographic stack

### Sphinx (`crypto/src/sphinx.rs`)

The Sphinx format is a fixed-size (2048-byte) onion packet. The key
construction:

```
For a path [mix_1, ..., mix_n, recipient]:

Ephemeral keypair: (x, α_0 = x·G)
Per-hop shared secrets: s_i = x · pubkey_i  (X25519 ECDH)
Per-hop key blinding:
  b_0 = SHA-256("sphinx-blinding" || s_0 || α_0)
  α_1 = b_0 · α_0   (scalar multiplication, clamped)
  b_i = SHA-256("sphinx-blinding" || s_i || α_i)
  α_{i+1} = b_i · α_i

Header: layered HMAC chains over routing information
Payload: ChaCha20-Poly1305, one layer per hop
```

The per-hop key blinding means colluding nodes cannot correlate the
ephemeral key they see across hops — each node observes a different `α_i`.

A packet is 32 bytes (ephemeral key) + 160 bytes (routing header) +
1,856 bytes (payload) = 2,048 bytes exactly. All packets are identical
length including cover packets.

### Noise_XX (`crypto/src/noise.rs`)

Used for node-to-node session establishment. Pattern:

```
→ e
← e, ee, s, es
→ s, se
```

Both parties authenticate their static keys. The session provides:
- Forward secrecy (ephemeral keys)
- Mutual authentication (static key possession)
- Identity hiding (static keys transmitted encrypted)

Implementation uses the `snow` crate (0.9.x) with
`Noise_XX_25519_ChaChaPoly_BLAKE2s` parameters.

### Cashu blind-DH (`economic/src/mint.rs`)

NUT-00 secp256k1 Chaumian ecash:

```
secret (32 bytes, random)
Y = hash_to_curve(secret)       // NUT-00 §3: SHA-256 prefix + counter loop
r = random scalar
B_ = Y + r·G                    // blinded output — sent to mint
C_ = k·B_                       // mint's blind signature (k = keyset private key)
K  = k·G                        // mint's public key (from GET /v1/keys)
C  = C_ - r·K                   // unblinded: C = k·Y, valid Cashu proof
```

Verification: `C == k·Y` iff the token was signed by the mint. The mint
never sees `r`, so it cannot link `B_` (what it signed) to `C` (what is
redeemed), even if it colluded with the verifier.

### ZK governance (`circuits/MembershipVote.circom`)

Circuit: `MembershipVote(depth=20)` — a Groth16 proof that:

1. The prover knows a `secret` such that `Poseidon(secret)` is a leaf in a
   depth-20 Poseidon Merkle tree with the claimed `membershipRoot`
2. `nullifierHash == Poseidon(secret, proposalId)` (no other proposal can
   reuse this nullifier)
3. `voteYes ∈ {0, 1}` (boolean constraint: `voteYes * (1 - voteYes) == 0`)

Public inputs: `[nullifierHash, proposalId, voteYes, membershipRoot]`  
Private inputs: `[secret, pathElements[20], pathIndices[20]]`

The proof is 256 bytes (Groth16 constant-size). Verification costs ~215k
gas via the BN254 pairing precompile.

Trusted setup: Hermez pot28 (1,000+ contributors, phase 1) + 3 project
contributors (phase 2). The phase 1 is sound if any one of the 1,000+
participants discarded their toxic waste. The phase 2 is sound if any one
of the 3 discarded theirs.

---

## High-risk areas (implementation team's assessment)

These are the areas where we believe bugs are most likely to have
security consequences. We are not asserting these contain bugs — we are
flagging them as the highest-value targets for review time.

### 1. Sphinx per-hop key blinding (CRITICAL IF WRONG)

File: `crypto/src/sphinx.rs`, function `peel_layer()`

The per-hop key blinding is the property that prevents colluding nodes
from correlating packets. If the blinding factor `b_i` is computed
incorrectly, or if the scalar multiplication is not performed on the
correct curve point, colluding nodes at positions `i` and `j` could
compare their observed ephemeral keys and determine they saw the same
packet. This would break the unlinkability guarantee across the entire
path.

The implementation uses `x25519-dalek` for the ECDH and custom SHA-256
for the blinding factor. The clamping step on `b_i` is critical — X25519
requires the scalar to be clamped (set bits 0,1,2,255 appropriately).

### 2. EIP-197 G2 Fp2 coordinate ordering in Groth16Verifier.sol (CRITICAL IF WRONG)

File: `governance/contracts/Groth16Verifier.sol`

The BN254 precompile (EIP-197) expects G2 points in `[x_imaginary, x_real, y_imaginary, y_real]` order. The `snarkjs` verification key JSON stores them in `[imaginary, real]` order in the VK, but the `proof.json` stores them in `[real, imaginary]` order.

A coordinate swap would produce a verifier that silently returns `false`
for all valid proofs (no proof would ever verify) while appearing
structurally correct. This is a silent failure mode. The patching script
`scripts/patch_ceremony.js` handles this swap — review that the constants
in `Groth16Verifier.sol` are correctly ordered against the VK JSON.

### 3. Cashu `hash_to_curve` (HIGH)

File: `economic/src/mint.rs`, function `hash_to_curve()`

This implements NUT-00 §3. The algorithm must produce a secp256k1 point
from a secret without leaking the discrete log relationship. If the
implementation diverges from the spec (wrong prefix, wrong counter
encoding, wrong compressed point format), tokens produced by this node
will fail validation at the mint — but more seriously, if the secret
can be recovered from the curve point, the token's privacy guarantee
is broken.

### 4. Double-spend prevention under restart (MEDIUM)

File: `node/src/payment.rs`, `PaymentGuard`

The in-memory `HashSet<String>` of seen proof secrets is lost on process
restart. The mint's `check_state` call is the fallback guard, but there
is a window between token acceptance and the background `verify_and_claim`
call completing. If the node crashes in that window, the same token could
be accepted again on restart. This is an acknowledged limitation — review
whether the window is exploitably wide.

### 5. Kademlia gossip message flooding (MEDIUM)

File: `node/src/peers.rs`, `handle_gossip()`

Gossip messages are accepted from any connecting peer before any
authentication. The `recv_msg` function enforces a 65,536-byte maximum
message size but there is no rate limiting on gossip connections. A
targeted DoS via gossip flood could exhaust connection resources or
artificially inflate the peer table with stale entries.

### 6. Circuit under-constraint check (CRITICAL IF PRESENT)

File: `circuits/MembershipVote.circom`

Verify that every signal that influences a public output is included in at
least one constraint. An under-constrained signal can be set to any value
by the prover without affecting proof validity, which would allow a prover
to claim any `membershipRoot` or `nullifierHash` without actually knowing
a valid `secret`. Run `circom --inspect` and review the constraint count
(expected: 5,360 non-linear + 5,953 linear = 11,313 total).

---

## What has already been reviewed internally

- **227 automated tests** — covering all crates and the Solidity suite
- **Cargo audit** — `rustls-webpki` patched to `>= 0.103.10` in CI
- **Solidity test coverage** — 47 tests including exact Poseidon vector
  tests that pin every hash function output to known circomlibjs values,
  tampered-signal rejection for all 4 public signals, and a
  `test_Groth16_RealProofAccepted` test that verifies the ceremony proof
  end-to-end
- **EIP-197 encoding validation** — `test_Groth16_RealProofAccepted`
  would fail (as it did during development, twice) if the G2 coordinate
  swap is wrong
- **Yggdrasil enforcement** — 28 tests covering both boundaries of the
  `200::/7` prefix, enforcement on/off paths, testnet bypass, and all
  three enforcement points (bind, accept, dial)

---

## How to set up the review environment

```bash
# Clone
git clone https://github.com/Naveenob/zksn.git
cd zksn
git checkout v1.2.0-pre

# Rust (requires cargo)
cargo test --workspace                   # 180 tests
cargo clippy --workspace --all-targets   # should be warning-free

# Solidity (requires Foundry)
cd governance
forge install foundry-rs/forge-std --no-git
forge test -vv                           # 47 tests

# ZK circuit verification (requires Node.js 18+)
npm install snarkjs circomlibjs circomlib
# Verify the ceremony proof
npx snarkjs groth16 verify \
  ceremony/verification_key.json \
  ceremony/public.json \
  ceremony/proof.json
# Expected: "OK!"

# Inspect circuit constraints
./node_modules/.bin/circom2 circuits/MembershipVote.circom \
  --r1cs --sym -l node_modules -o /tmp/
# Expected: non-linear constraints: 5360, linear constraints: 5953
```

---

## Appendix: Key constants

```
PACKET_SIZE      = 2048 bytes
MAX_HOPS         = 5
HEADER_LEN       = 160 bytes
PAYLOAD_LEN      = 1856 bytes
PAYMENT_MAGIC    = b"ZKSN"
BN254 field mod  = 21888242871839275222246405745257275088548364400416034343698204186575808495617
Circuit depth    = 20 (2^20 = 1,048,576 members)
Constraints      = 5,360 non-linear / 5,953 linear
Proof size       = 256 bytes (Groth16 constant)
Poseidon T2 (t=2, 1 input)  → hashLeaf
Poseidon T3 (t=3, 2 inputs) → hashNullifier, hashNode
Yggdrasil prefix = 200::/7 (first byte & 0xFE == 0x02)
```
