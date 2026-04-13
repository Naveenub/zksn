# ZKSN v1.0.0-rc2 — pot28 ceremony merged, audit-ready

**⚠️ Release candidate. Awaiting external security audit before v1.0.0 final.**

---

## What changed in rc2

### feat/ceremony-mainnet — pot28 trusted setup merged

The `feat/ceremony-mainnet` branch has been merged into `main` via PR #1.
The ZKSN governance circuit is now backed by the Hermez pot28 ceremony —
1,000+ independent contributors from the 2021 Hermez MPC. This is the
strongest publicly available phase 1 for the BN254 scalar field.

**Phase 1 — Hermez pot28 (2^15 subset)**

```
File:   powersOfTau28_hez_final_15.ptau
SHA256: 3ef2ecc5b75d687048cf2d59195119b42fb07c5af639c5f283d84bfa69829e7f
Source: https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_15.ptau
```

**Phase 2 — 3-contributor MPC (this ceremony run, 2026-03-23)**

| File | SHA256 |
|---|---|
| zkey_0001.zkey | 99d6d1aa1d47482b48ff00e922d9f83acd019de6b52f2f7425bbeb2b4b64536c |
| zkey_0002.zkey | 2f70f8e89a5438c085970bb6e4d286251057b11a1b9532ae08b87812042a9542 |
| zkey_0003.zkey | 46766f31eeb3ccb01d3554ed931e300f6571bd3719eec0bfc20684ee8ae730ca |
| **zkey_final.zkey** | **8cd2611cdc03429e39b48c4c838653440b7109d871adcf8bc117165c9dba86f7** |

**Circuit hash (binds zkey to r1cs — same across all runs):**
```
97b45c9a 6d976d1a 0faf3d53 d027bf9f
143ef7df 5cf6c128 0b40e5a1 485d0a92
e80f1b32 a0bedfb4 079589ff 68647148
eabfa89a d5d83978 b3174e56 6ef6f0ae
```

**Test proof (snarkjs groth16 verify → OK ✅):**
```
secret         = 12345678901234567890
proposalId     = 999888777666555
voteYes        = 1
nullifierHash  = 21605468119089894529364334093527017674406608084847384275934021833321276526684
membershipRoot = 6331401000423026358291629782353603237933267665498208286537849807283925720420
```

**Files changed in this merge:**

```
ceremony/verification_key.json       — new VK from pot28 phase 2
ceremony/proof.json                  — verified test proof
ceremony/public.json                 — public signals
governance/contracts/Groth16Verifier.sol  — updated VK constants (delta + IC)
governance/test/ZKSNGovernance.t.sol      — updated REAL_PROOF + REAL_MEMBERSHIP_ROOT
```

**Verify yourself:**
```bash
# Verify the ceremony proof against the VK
npx snarkjs groth16 verify \
  ceremony/verification_key.json \
  ceremony/public.json \
  ceremony/proof.json
# → [INFO] snarkJS: OK!

# Run all 47 Solidity tests
cd governance && forge test -vv
# → 47 passed; 0 failed
```

---

## Trust model at rc2

| | Previous (rc1) | Now (rc2) |
|---|---|---|
| Phase 1 contributors | 3 (this project only) | 1,000+ (Hermez 2021) |
| Phase 2 contributors | 3 | 3 |
| Phase 1 soundness | Any 1 of 3 must be honest | Any 1 of 1,000+ must be honest |
| Suitable for | Development / CI | **Mainnet — pending audit** |

---

## Full cumulative state at v1.0.0-rc2

### Protocol — complete ✅

| Layer | Status |
|---|---|
| Ed25519, Sphinx X25519, per-hop key blinding, Noise_XX | ✅ |
| Poisson mixing, cover traffic (DROP + LOOP), Kademlia DHT | ✅ |
| Cashu NUT-00/01/03/05/07, NodeWallet, MeltManager | ✅ |
| Groth16 governance — depth-20, BN254, **pot28 VK (1000+)** | ✅ |
| PoseidonHasher — circomlibjs bytecode, exact circuit match | ✅ |
| Yggdrasil 200::/7 enforced at Rust bind / accept / dial | ✅ |
| I2P SAM v3.1, .b32.i2p addressing, .zksn DHT petnames | ✅ |
| NixOS node.nix — tmpfs root, dm-verity, LUKS2, 37-check validation | ✅ |
| scripts/demo.sh — single-command devnet | ✅ |
| Benchmarks — Sphinx, Cashu, mixer, peer table | ✅ |
| docs/AUDIT_SCOPE.md + SECURITY_BRIEF.md + FINDINGS_TEMPLATE.md | ✅ |

### Tests

| Crate / Contract | Tests |
|---|---|
| `zksn-crypto` | 29 |
| `zksn-node` | 76 |
| `zksn-economic` | 32 |
| `zksn-client` | 68 |
| `ZKSNGovernance.sol` | 47 |
| **Total** | **252** |

CI: Rust · Security Audit · Governance Contracts · Ceremony — all green.

### One remaining gap

| Gap | Status |
|---|---|
| External security audit | Audit documents prepared. Firms contacted: Trail of Bits, Zellic, Least Authority. Awaiting engagement. |

---

## Next

Audit engagement → fixes (if any) → v1.0.0 final.
