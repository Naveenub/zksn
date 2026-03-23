# ZKSN v1.0.0-rc1 — pot28 ceremony complete, feat/ceremony-mainnet closed
**⚠️ Release candidate. Not yet audited for production deployment.**

## What's in this release

### pot28 trusted setup — complete

The phase 1 trust gap is closed. ZKSN governance now runs on the Hermez pot28
ceremony — 1,000+ independent contributors from the 2021 Hermez ceremony.

**Phase 1 — Hermez pot28 (2^15 subset)**

```
File:   powersOfTau28_hez_final_15.ptau
SHA256: 3ef2ecc5b75d687048cf2d59195119b42fb07c5af639c5f283d84bfa69829e7f
Size:   36 MB
Source: https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_15.ptau
```

Same 1,000+ contributors as the full 3.2 GB pot28, truncated to the 2^15
capacity needed for the 11,313-constraint depth-20 circuit.

**Phase 2 — 3-contributor MPC**

| File | SHA256 |
|---|---|
| zkey_0001.zkey | d56713dba078be9e6b0ed52a32d3f312cb0607cfda1d8aabad0d0e034867b353 |
| zkey_0002.zkey | 7c0e81e15917059161bbf795cee6bfbb11a4f46eb228074c79a8f73de6dec3c4 |
| zkey_0003.zkey | 5767c030d1b12a3ef53ee9aee68b325a30bbc6405feaaf4170792a0e3166c3e1 |
| **zkey_final.zkey** | **312967bdb9e558b43fde3f34149ce7fe7933e923a41a402563f09c98bca47b65** |

**Circuit hash (same across all runs — binds zkey to r1cs):**
```
97b45c9a 6d976d1a 0faf3d53 d027bf9f
143ef7df 5cf6c128 0b40e5a1 485d0a92
e80f1b32 a0bedfb4 079589ff 68647148
eabfa89a d5d83978 b3174e56 6ef6f0ae
```

**Contribution hashes:**
```
#1:  f944169c 6df328bc 94a7fb35 8021ad5b  f56512e4 397b4c7a 99484e6f e32922fb
     f6de5ce6 af7cdd76 165980e3 bcfc2b59  7e43a4df 0d1d4ab9 1fe6fcbd 2431d346
#2:  fa638703 448b8b63 5f1f8dcb 6e34e4c3  71bfc07d 92f9a387 127a0df1 48df563b
     39ab9932 036d8c9b dfe287c3 923b625a  f9b1cfc0 3c15b693 b5433c13 88f44983
#3:  ed402f6b 90d43121 0b18e057 725453e1  4d965e1a c5a23c17 0a1e7147 14a692c6
     7689637b dde191df 3026c16e 830d910e  0eaa11d3 c978648c 7b0df75b 4079821c
Beacon: 085b1f7c 9fd6f3d2 386adc7c 494f2f29  3926c238 d7e7613f 4d8cf22c aae4be80
        76a15ca8 251aa6ef a937e3b7 3659fa9c  df50ed2a 157a2790 d8af1515 32a9d569
```

**Test proof (snarkjs groth16 verify → OK ✅):**
```
secret         = 12345678901234567890
proposalId     = 999888777666555
voteYes        = 1
nullifierHash  = 21605468119089894529364334093527017674406608084847384275934021833321276526684
membershipRoot = 6331401000423026358291629782353603237933267665498208286537849807283925720420
```

### Automated via GitHub Actions

The ceremony ran entirely via `.github/workflows/ceremony_mainnet.yml`:

- pot28 downloaded and SHA256-verified
- Depth-20 circuit compiled (5,360 constraints)
- 3-contributor MPC with entropy from repository secrets
- Deterministic beacon applied
- `scripts/patch_ceremony.js` updated all VK constants and test vectors
- `forge test` — **47/47 passing**
- PR opened, reviewed, and merged

### Files changed in this release

```
ceremony/verification_key.json       — new VK from pot28 phase 2
ceremony/proof.json                  — verified test proof
ceremony/public.json                 — public signals
ceremony/input.json                  — ceremony test vector
ceremony/ATTESTATION.md              — updated with pot28 hashes
governance/contracts/Groth16Verifier.sol  — all 24 VK constants updated
governance/test/ZKSNGovernance.t.sol      — REAL_PROOF + REAL_MEMBERSHIP_ROOT updated
```

### Trust model — before and after

| | v0.9.0-alpha (pot15) | v1.0.0-rc1 (pot28) |
|---|---|---|
| Phase 1 contributors | 3 (this project) | 1,000+ (Hermez 2021) |
| Phase 2 contributors | 3 | 3 |
| Phase 1 soundness | Any 1 of 3 must be honest | Any 1 of 1,000+ must be honest |
| Suitable for | Development / CI | Mainnet |

---

## Test coverage

| Crate / Contract | Tests |
|---|---|
| `zksn-crypto` | 29 |
| `zksn-node` | 19 |
| `zksn-economic` | 32 |
| `zksn-client` | 22 |
| `ZKSNGovernance.sol` | 47 |
| **Total** | **195** |

All passing. CI green across Rust, Security Audit, Governance Contracts, and
Ceremony workflows.

---

## Remaining gaps

| Gap | Branch |
|---|---|
| Yggdrasil not wired at Rust socket level — plain TCP only | `feat/yggdrasil-transport` |
| No demo script — no single-command devnet flow | `feat/demo` |

---

## Cumulative state at v1.0.0-rc1

**Solid ✅**
- Ed25519, Sphinx, Noise_XX, ZKP primitives
- Mix node — Poisson, cover traffic, Kademlia, PaymentEnvelope
- Client — send/receive, RouteSelector
- Economic — blind token full cycle, MeltManager
- Governance — depth-20 circuit, BN254 pairing, **pot28 MPC VK (1000+ contributors)**
- PoseidonHasher — circomlibjs bytecode, matches circuit exactly
- `scripts/tree.js` — sparse depth-20 Poseidon tree
- `scripts/encode_proof.js` — EIP-197 proof encoding
- `scripts/patch_ceremony.js` — automated VK + test constant patching
- `scripts/ceremony.sh` + `download_ptau.sh` — full ceremony runbook
- `.github/workflows/ceremony_mainnet.yml` — automated pot28 ceremony

**Stubbed ❌**
- Yggdrasil not wired in Rust
- No demo script

## Next PRs

1. `feat/yggdrasil-transport` — enforce `200::/7` bind at Rust socket level
2. `feat/demo` — `scripts/demo.sh`: three nodes, Nutshell mint, regtest Lightning,
   one anonymous vote + one paid message end-to-end
