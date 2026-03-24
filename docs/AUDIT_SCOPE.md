# ZKSN Security Audit — Scope Document

**Version:** 1.0  
**Prepared for:** External security auditors  
**Repository:** https://github.com/Naveenob/zksn  
**Release tag:** v1.2.0-pre  
**Date prepared:** March 2026

---

## Engagement overview

ZKSN requests an independent security audit of its cryptographic primitives,
mixnet implementation, anonymous governance system, and transport-layer
anonymity enforcement. The codebase is feature-complete and has a passing CI
test suite. No prior third-party audit has been conducted.

The audit has two distinct sub-scopes that may be assigned to different teams:

| Sub-scope | Languages | Primary concern |
|---|---|---|
| **A — Rust cryptography and mixnet** | Rust | Protocol correctness, side-channels, DoS vectors |
| **B — ZK circuit and governance contracts** | Circom, Solidity | Circuit soundness, verifier correctness, contract logic |

Both sub-scopes should be reviewed; the teams may work in parallel.

---

## Codebase metrics

| Scope | Files | SLOC |
|---|---|---|
| Rust (all crates) | 26 `.rs` files | ~5,500 |
| Solidity contracts | 7 `.sol` files | ~930 |
| Circom circuit | 1 `.circom` file | 72 |
| Shell / JS scripts | 9 files | ~900 |

The Rust codebase is structured as a Cargo workspace with four crates:

```
zksn-crypto      — cryptographic primitives (no I/O, no async)
zksn-economic    — Cashu and Monero payment layer
zksn-node        — mix node binary
zksn-client      — client library and CLI
```

---

## Sub-scope A — Rust cryptography and mixnet

### Files in scope

| File | SLOC | What to review |
|---|---|---|
| `crypto/src/sphinx.rs` | 534 | Sphinx packet build and peel; per-hop key blinding; fixed-size enforcement |
| `crypto/src/noise.rs` | 210 | Noise_XX handshake; `NoiseInitiator` / `NoiseResponder` |
| `crypto/src/identity.rs` | ~150 | Ed25519 keypair generation; secret material zeroization |
| `crypto/src/zkp.rs` | ~120 | Merkle commitment scheme; nullifier construction |
| `node/src/node.rs` | 325 | TCP accept loop; PaymentEnvelope dispatch; inbound Yggdrasil check |
| `node/src/network.rs` | 236 | `is_yggdrasil()` predicate; `check_bind()`; `check_peer()` |
| `node/src/peers.rs` | 642 | Kademlia DHT; gossip fan-out; peer persistence; outbound dial enforcement |
| `node/src/mixer.rs` | ~200 | Poisson delay pool; `Exp(λ)` sampling; packet reordering |
| `node/src/payment.rs` | 404 | Double-spend prevention; `HashSet` seen-secrets; mint `check_state` call |
| `economic/src/mint.rs` | 1,259 | `MintClient` NUT-01/03/05/07; blind-DH unblinding; `NodeWallet`; `MeltManager` |
| `economic/src/cashu.rs` | ~200 | `CashuToken`; proof structure; `is_valid()` |
| `client/src/lib.rs` | 235 | `ZksnClient::new()` address enforcement; `send()` / `receive()` |
| `client/src/send.rs` | ~300 | `frame_payload`; `inject_packet`; `inject_packet_with_payment` |
| `client/src/receive.rs` | ~150 | `start_receiver`; `handle_delivery`; Sphinx peel |

### Files explicitly out of scope (sub-scope A)

- `node/src/cover.rs` — cover traffic generation (low risk, deterministically testable)
- `node/src/metrics.rs` — Prometheus counters (no security surface)
- `node/src/router.rs` — TCP packet forwarding (simple fixed-size write)
- `client/cli/main.rs` — CLI argument parsing only

### Key questions for sub-scope A

1. **Sphinx correctness** — Does `peel_layer()` correctly validate the MAC before peeling? Is the per-hop key blinding `α_{i+1} = b_i ×_clamped α_i` correctly implemented? Can a malformed packet cause a panic or information leak?

2. **Noise_XX** — Are the handshake state transitions correct? Is the transcript hash properly chained? Is the `snow` library being used in a way that preserves the security properties of the pattern?

3. **Key material handling** — Are Ed25519 secret bytes zeroized on drop in all code paths? Is there any stack copying that bypasses `zeroize`?

4. **Poisson mixing** — Is the `Exp(λ)` sampling correct and unbiased? Could an attacker learn timing information from the pool draining behaviour?

5. **Yggdrasil enforcement** — Is the `200::/7` predicate (`first_byte & 0xFE == 0x02`) correct? Are there any TOCTOU races between `check_bind()`/`check_peer()` and the actual socket operation?

6. **Cashu blind-DH** — Is the unblinding formula `C = C_ - r·K` correctly implemented against the `k256` library? Are scalar operations performed in the correct field? Is `hash_to_curve` faithful to the NUT-00 spec?

7. **Double-spend prevention** — Is the in-memory `HashSet<String>` in `PaymentGuard` the only local guard? What happens if the node restarts between token receipt and the mint's `check_state` response?

8. **DoS vectors** — Can a remote peer cause unbounded memory growth in the Kademlia table, the mixing pool, or the gossip message queue?

---

## Sub-scope B — ZK circuit and governance contracts

### Files in scope

| File | SLOC | What to review |
|---|---|---|
| `circuits/MembershipVote.circom` | 72 | Circuit constraints; completeness; soundness |
| `governance/contracts/Groth16Verifier.sol` | 199 | VK constant encoding; EIP-197 G2 Fp2 order; pairing call |
| `governance/contracts/PoseidonHasher.sol` | 152 | Bytecode embedding; deploy correctness; hash consistency with circuit |
| `governance/contracts/ZKSNGovernance.sol` | ~200 | Proposal lifecycle; nullifier uniqueness; timelock; execution |
| `governance/contracts/IVerifier.sol` | ~20 | Interface correctness |
| `ceremony/verification_key.json` | — | VK constants match deployed Groth16Verifier.sol |
| `ceremony/ATTESTATION.md` | — | Ceremony contribution chain; SHA256 fingerprints |

### Files explicitly out of scope (sub-scope B)

- `governance/contracts/MockVerifier.sol` — test fixture only
- `governance/test/ZKSNGovernance.t.sol` — test file, not deployed
- `scripts/patch_ceremony.js` — dev tooling

### Key questions for sub-scope B

1. **Circuit soundness** — Does `MembershipVote(20)` correctly enforce all three constraints: (a) Poseidon leaf membership in the Merkle tree, (b) nullifier derivation `Poseidon(secret, proposalId)`, (c) `voteYes ∈ {0, 1}`? Is there any constraint that can be satisfied by a malformed witness?

2. **Under-constrained signals** — Are all circuit signals that influence the public outputs fully constrained? Could a prover manipulate `membershipRoot` or `nullifierHash` without the correct `secret`?

3. **Groth16Verifier.sol — EIP-197 encoding** — The G2 Fp2 coordinates in the VK are stored with specific `[imaginary, real]` ordering in the JSON and `[real, imaginary]` in the Solidity constants. Is this swap applied correctly for all constants (alpha, beta, gamma, delta)? A one-bit error in coordinate ordering silently produces a verifier that accepts no valid proofs.

4. **Groth16Verifier.sol — assembly** — The `_verifyProof` function uses inline assembly to call the `bn128Pairing` precompile (address `0x08`). Is the memory layout correct? Is the `g1_mulAccC` accumulation correct for the linear combination `vk_x = IC[0] + Σ signals[i] * IC[i+1]`?

5. **PoseidonHasher.sol — bytecode** — The Poseidon contracts are deployed via `CREATE` from embedded bytecodes. Are the bytecodes identical to `circomlibjs poseidonContract.createCode(1)` and `createCode(2)`? Is the EVM execution environment (chain ID, `SELFDESTRUCT`) safe for pure computation contracts?

6. **Nullifier collision** — Is `Poseidon(secret, proposalId)` a collision-resistant nullifier? Is there any path where two different `(secret, proposalId)` pairs could produce the same `nullifierHash`?

7. **Governance contract** — Is the nullifier stored and checked correctly to prevent double-voting? Is the `membershipRoot` update path (only via governance) correctly enforced? Are there any re-entrancy vectors in `execute()`?

8. **Trusted setup** — The ceremony used `powersOfTau28_hez_final_15.ptau` (Hermez, 1,000+ contributors, 2^15 capacity) for phase 1. Three project contributors provided phase 2 entropy. Is there any toxic waste concern given the phase 2 contributor count? Is the zkey chain verifiable?

---

## Cryptographic assumptions

The following assumptions underpin the security model. Auditors should flag any finding that depends on violating one of these:

| Assumption | Used in |
|---|---|
| Discrete logarithm hardness on Curve25519 | Ed25519, X25519, Sphinx |
| ChaCha20-Poly1305 IND-CPA + INT-CTXT | Sphinx payload encryption |
| Noise_XX security under the Noise specification | Node-to-node handshake |
| Groth16 knowledge soundness under the BN254 discrete log assumption | Governance ZK proofs |
| Poseidon collision resistance in the BN254 scalar field | Merkle tree, nullifiers, PoseidonHasher |
| `rustls-webpki >= 0.103.10` (RUSTSEC-2026-0049 patched) | Cashu mint TLS |

---

## Known non-findings (explicitly acknowledged)

The following are known design choices or accepted limitations, not findings:

1. **Single `#[tokio::main]` executor** — The mix node runs all subsystems on a single Tokio runtime. This is by design for simplicity; the mixing and cover traffic tasks are latency-sensitive.

2. **`bincode 1.3.3` (RUSTSEC-2025-0141 warning)** — Marked unmaintained, not vulnerable. Gossip messages are length-prefixed and the bincode format is not attacker-controlled beyond size bounds. Migration to bincode 2 is planned but not in scope.

3. **`number_prefix 0.4.0` (RUSTSEC-2025-0119 warning)** — Transitive dependency of `indicatif` (CLI progress bars). Not security-relevant.

4. **`cover_traffic_rate = 0` disables cover traffic** — This is documented as insecure. Nodes choosing to disable cover traffic accept weakened anonymity properties. The binary does not prevent this.

5. **Depth-4 test circuit** — The `ceremony/` directory contains artifacts from a prior depth-4 development ceremony. These are superseded by the depth-20 pot28 ceremony and are present only for historical reference.

---

## Deliverables requested

| Deliverable | Format |
|---|---|
| Audit report | PDF + Markdown |
| Finding severity ratings | Use template in `docs/AUDIT_FINDINGS_TEMPLATE.md` |
| Re-test confirmation | After fixes are applied |
| Public disclosure | 90 days post-fix, or at our discretion if fixes are merged |

---

## Point of contact

Repository: https://github.com/Naveenob/zksn  
Security contact: See `SECURITY.md` and `keys/security.asc`  
Response SLA: 48 hours for scoping questions

---

## Suggested engagement structure

Given the two-sub-scope split:

1. **Week 1–2:** Sub-scope A kickoff — Rust crypto and mixnet. Initial findings triage.
2. **Week 2–3:** Sub-scope B kickoff — ZK circuit and Solidity. Can run in parallel with A.
3. **Week 3–4:** Fix window. Auditors re-test critical and high findings.
4. **Week 5:** Final report delivery.

Total estimated engagement: **4–5 weeks**, **2–3 auditor-weeks** depending on firm staffing.
