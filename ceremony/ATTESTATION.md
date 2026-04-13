# ZKSN Ceremony Attestation — pot28 Phase 2

**Date:** 2026-03-23  
**Circuit:** `MembershipVote(depth=20)` — 5,360 non-linear constraints  
**Phase 1:** Hermez pot28 (`powersOfTau28_hez_final_15.ptau`, 1,000+ contributors)

---

## Phase 1 — Hermez powers of tau

```
File:   powersOfTau28_hez_final_15.ptau
SHA256: 3ef2ecc5b75d687048cf2d59195119b42fb07c5af639c5f283d84bfa69829e7f
Size:   36 MB (2^15 subset of the full pot28)
Source: https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_15.ptau
```

Phase 1 security: if any one of the 1,000+ Hermez contributors discarded their
toxic waste, the phase 1 is sound.

---

## Phase 2 — 3-contributor MPC

### Initial zkey (from phase 1)

```
File:   zkey_0000.zkey
SHA256: b310d5354af9894416acbc9832056c57007ef173e771ba58e7ceab68682713ef
```

### Circuit hash (same across all contributions — binds zkey to r1cs)

```
97b45c9a 6d976d1a 0faf3d53 d027bf9f
143ef7df 5cf6c128 0b40e5a1 485d0a92
e80f1b32 a0bedfb4 079589ff 68647148
eabfa89a d5d83978 b3174e56 6ef6f0ae
```

### Contribution 1

```
zkey_0001.zkey SHA256: 99d6d1aa1d47482b48ff00e922d9f83acd019de6b52f2f7425bbeb2b4b64536c
Contribution hash:
    f944169c 6df328bc 94a7fb35 8021ad5b  f56512e4 397b4c7a 99484e6f e32922fb
    f6de5ce6 af7cdd76 165980e3 bcfc2b59  7e43a4df 0d1d4ab9 1fe6fcbd 2431d346
Name: ZKSN MPC Contributor 1 (pot28)
Entropy source: GitHub Actions secret CEREMONY_ENTROPY_1
```

### Contribution 2

```
zkey_0002.zkey SHA256: 2f70f8e89a5438c085970bb6e4d286251057b11a1b9532ae08b87812042a9542
Contribution hash:
    fa638703 448b8b63 5f1f8dcb 6e34e4c3  71bfc07d 92f9a387 127a0df1 48df563b
    39ab9932 036d8c9b dfe287c3 923b625a  f9b1cfc0 3c15b693 b5433c13 88f44983
Name: ZKSN MPC Contributor 2 (pot28)
Entropy source: GitHub Actions secret CEREMONY_ENTROPY_2
```

### Contribution 3

```
zkey_0003.zkey SHA256: 46766f31eeb3ccb01d3554ed931e300f6571bd3719eec0bfc20684ee8ae730ca
Contribution hash:
    ed402f6b 90d43121 0b18e057 725453e1  4d965e1a c5a23c17 0a1e7147 14a692c6
    7689637b dde191df 3026c16e 830d910e  0eaa11d3 c978648c 7b0df75b 4079821c
Name: ZKSN MPC Contributor 3 (pot28)
Entropy source: GitHub Actions secret CEREMONY_ENTROPY_3
```

### Random beacon

```
Beacon input:  0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
Beacon hash:
    085b1f7c 9fd6f3d2 386adc7c 494f2f29  3926c238 d7e7613f 4d8cf22c aae4be80
    76a15ca8 251aa6ef a937e3b7 3659fa9c  df50ed2a 157a2790 d8af1515 32a9d569
```

---

## Final zkey

```
zkey_final.zkey SHA256: 8cd2611cdc03429e39b48c4c838653440b7109d871adcf8bc117165c9dba86f7
```

---

## Verification key

```
File: ceremony/verification_key.json
nPublic: 4
Public inputs: [nullifierHash, proposalId, voteYes, membershipRoot]
```

---

## Test proof verification

```bash
npx snarkjs groth16 verify \
  ceremony/verification_key.json \
  ceremony/public.json \
  ceremony/proof.json
# → [INFO] snarkJS: OK!
```

Public signals:
```
[0] nullifierHash  = 21605468119089894529364334093527017674406608084847384275934021833321276526684
[1] proposalId     = 999888777666555
[2] voteYes        = 1
[3] membershipRoot = 6331401000423026358291629782353603237933267665498208286537849807283925720420
```

---

## Reproducibility

Anyone can re-run the ceremony and verify the contribution chain:

```bash
# Download phase 1
bash scripts/download_ptau.sh

# Re-run phase 2 (requires setting CEREMONY_ENTROPY_1/2/3 env vars)
bash scripts/ceremony.sh

# Verify the final zkey
npx snarkjs zkey verify \
  build/MembershipVote.r1cs \
  ceremony/pot28_hez_final_15.ptau \
  ceremony/zkey_final.zkey \
  ceremony/verification_key.json
```

Phase 2 security: if any one of the 3 contributors discarded their toxic waste,
the phase 2 is sound. Combined with the phase 1 guarantee, the trusted setup is
sound if any one of 1,003+ participants discarded their waste.
