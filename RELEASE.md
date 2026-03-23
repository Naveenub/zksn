# ZKSN v1.2.0 — demo.sh, full end-to-end devnet in one command
**⚠️ Pre-release. Not yet production-audited.**

## What's in this release

### feat/demo — single-command local devnet

`scripts/demo.sh` runs the full ZKSN protocol end-to-end on localhost
with no external dependencies beyond cargo and node. No Yggdrasil,
no real Lightning, no Ethereum node required.

```bash
bash scripts/demo.sh
```

What it does:

1. Builds `zksn-node` and `zksn` from source
2. Writes configs for 3 mix nodes (testnet mode, 127.0.0.1, Poisson λ=50ms)
3. Optionally starts a Nutshell Cashu mint via Docker (skipped gracefully if absent)
4. Starts 3 mix nodes, waits for gossip to settle
5. Generates Alice and Bob identities
6. Starts Bob's receiver
7. Sends an anonymous message Alice → Bob through the 3-hop mix
8. Generates an anonymous governance vote:
   - Adds voter to a depth-20 Poseidon membership tree
   - Generates circuit witness from the tree path
   - Produces a Groth16 proof (using the pot28 ceremony zkey)
   - Verifies: `snarkjs groth16 verify → OK`
   - Encodes the proof for `ZKSNGovernance.castVote()`
9. Shows what the contract sees: nullifierHash, proposalId, voteYes,
   membershipRoot — the voter's secret is never revealed

Flags:
```bash
bash scripts/demo.sh --skip-vote   # mix only, no ZK proof step
bash scripts/demo.sh --skip-mint   # no Docker mint
```

### `client/cli/main.rs` — two new flags

The `zksn` CLI gains `--testnet` and `--listen`:

```bash
# Before: no way to run without Yggdrasil
zksn send <pubkey> "hello"  # would fail: 200::/7 check

# After:
zksn send <pubkey> "hello" --testnet --node 127.0.0.1:9101
zksn receive --testnet --listen 127.0.0.1:9201
```

`--testnet` sets `yggdrasil_only = false`.
`--listen` overrides the default receive address.

---

## Files changed

```
scripts/demo.sh          ← NEW
client/cli/main.rs       ← --testnet and --listen flags
RELEASE.md               ← this file
```

---

## Running the demo

### Minimal (mix only)
```bash
# Install Rust and Node.js, then:
bash scripts/demo.sh --skip-vote --skip-mint
```

### Full (mix + ZK vote)
```bash
# Requires ceremony/zkey_final.zkey (already in repo after pot28 ceremony)
bash scripts/demo.sh
```

### Full (mix + ZK vote + Cashu mint)
```bash
# Requires Docker
bash scripts/demo.sh
```

Expected output:
```
══ Prerequisites ══
✓ cargo: cargo 1.xx.x
✓ node:  v22.x.x

══ Build ══
   Compiling zksn-node v0.1.0
   Finished release [optimized] target(s)
✓ zksn-node: 8.2M
✓ zksn:      6.4M

══ Starting Mix Nodes ══
✓ node1  listening on 127.0.0.1:9101
✓ node2  listening on 127.0.0.1:9102
✓ node3  listening on 127.0.0.1:9103

══ Sending Anonymous Message  (Alice → Bob) ══
  Message: "Hello from ZKSN 14:22:07"
  Route: Alice → node1 → node2 → node3 → Bob
✓ Message sent through mixnet

══ Anonymous Governance Vote  (ZK proof) ══
  Adding voter to depth-20 Poseidon membership tree...
✓ Membership tree root: 6331401000423026...
  Generating Groth16 proof...
✓ Proof verified ✅  (snarkjs groth16 verify → OK)
  nullifierHash  : 21605468119089894...
  proposalId     : 42000000000001
  voteYes        : 1
  membershipRoot : 6331401000423026...
✓ Anonymous vote proof complete
✓ The contract cannot link this vote to the voter's secret

══ Demo Complete ══
✓ 3 mix nodes running
✓ Anonymous message sent Alice → Bob through the mix
✓ Anonymous governance vote (Groth16 proof, pot28 VK)
```

---

## Remaining gap

None. Protocol is feature-complete.

The next step is an external security audit before v1.0.0 final.

---

## Cumulative state at v1.2.0

**Solid ✅ — everything**
- Ed25519, Sphinx, Noise_XX, ZKP primitives
- Mix node — Poisson, cover traffic, Kademlia, PaymentEnvelope
- Client — send/receive/RouteSelector, `--testnet` + `--listen` CLI flags
- Economic — blind token full cycle, MeltManager
- Governance — depth-20 circuit, BN254 pairing, pot28 VK (1000+ contributors)
- PoseidonHasher + sparse depth-20 tree builder + encode_proof.js
- Yggdrasil `200::/7` enforced at bind, accept, dial
- `scripts/demo.sh` — full flow in one command

**No remaining protocol gaps.**

## Next

External security audit → v1.0.0 final.
