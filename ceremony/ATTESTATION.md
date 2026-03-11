# ZKSN Trusted Setup Ceremony — Attestation

**Circuit:** `circuits/MembershipVote.circom` (depth=4, BN254)
**Protocol:** Groth16
**Date:** 2026-03-11

---

## Security model

This is a 1-of-N honest party ceremony. The toxic waste (the discrete log of the
delta G1 point) is destroyed if **any single contributor** was honest and deleted
their randomness. A valid forgery requires **all** contributors to collude and
retain their entropy.

---

## Phase 1 — Powers of Tau

| Parameter | Value |
|---|---|
| Curve | BN254 (bn128) |
| Power | 12 (supports up to 2^12 = 4,096 constraints) |
| Circuit constraints | 1,440 non-linear + 1,569 linear |
| Phase 1 type | Dev ptau (single-contributor + beacon) |
| **Mainnet note** | Replace with Hermez perpetual pot28: `https://hermez.s3-eu-west-1.amazonaws.com/powersoftau28_hez_final.ptau` |

Phase 1 beacon:
```
0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
iterations: 2^10
```

---

## Phase 2 — Circuit-specific (Groth16)

### Contribution #1 — ZKSN Contributor 1 (Anonymous)

```
contribution hash:
  6c0b8208 653962a5 131a9cb7 dae4bc42
  a11059c6 c8efa2e6 a63d5219 2ab32c06
  681ee8bf 63951ace c02c6af5 5a8d5cac
  1709cb18 9f93f87e ce0a33bb ee755b46

zkey SHA256: 7cbfb28d88079c4a68a7abab5583ce7f81c2ee9c3a51cec854a57637b112be5c
```

Attestation: entropy generated with OS CSPRNG (`/dev/urandom`), not retained.

### Contribution #2 — ZKSN Contributor 2 (Anonymous)

```
contribution hash:
  e854a2d7 42334ba0 10034ae4 e2c9d521
  89bd2fb6 a7e3a76f 1db5ed61 7e2da9d8
  3396a20c f01a6f70 5c375bbf 4be5ce03
  b12229bf d7e3a092 8d7efd0c 9ff0536c

zkey SHA256: f7311790d08ee8140b98624c4954665b714f220b8eb7b488992c97844f3ff037
```

Attestation: entropy generated with OS CSPRNG (`/dev/urandom`), not retained.

### Contribution #3 — ZKSN Contributor 3 (Anonymous)

```
contribution hash:
  19308480 4ecb6cd4 a45a2915 6829b0c1
  c4c52a4e bd0c7994 c04b2018 07f57be0
  78e4193a e1376fe5 b06317ba f49ecd50
  45cec04f 8e39959b 02c8f674 edd84e3d

zkey SHA256: af8f5c0a39d7e87bf80598590b3ea80bfcd5a0ce2aef6d739e28032fed0db5c2
```

Attestation: entropy generated with OS CSPRNG (`/dev/urandom`), not retained.

### Final beacon — Contribution #4

```
beacon hash:    0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
iterations:     2^10
label:          ZKSN Multi-Party Final Beacon

contribution hash:
  a3eaf963 fa1630bc 72317c8d f1115410
  119b2fd3 9bd6a627 a89d2ab9 da214764
  f316ee3b 46b55700 20af7a28 69858779
  61d96b5c 37ab273e 79e7a1bd cd9dd246
```

**Final zkey SHA256:** `ca292c3ae4a7991a493113e29b35262685fec5cfdea23023bfe308a18849992b`

---

## Verification key — delta point (changes each ceremony)

```
deltax1 = 13239159455209854885391344814099895864201722858832508895368568224256652230794
deltax2 = 12520334176007677924902946848108088073222406722938884588262680500371838060834
deltay1 =  9734361884712003728854433748012913745997966556128862002686768677239144794689
deltay2 =  1551210958028365771293531825981023128179307938762357170746470836686196907097
```

alpha/beta/gamma and IC points are circuit-structure constants — they do not change
across phase 2 reruns.

---

## Verification

Anyone can verify the full contribution chain:

```bash
npm install snarkjs
npx snarkjs zkey verify \
  build/MembershipVote.r1cs \
  pot12_final.ptau \
  ceremony/zkey_final.zkey
# → ZKey Ok!
```

Sample proof round-trip:

```bash
# Generate witness
node build/MembershipVote_js/generate_witness.js \
  build/MembershipVote_js/MembershipVote.wasm \
  ceremony/input.json ceremony/witness.wtns

# Prove
npx snarkjs groth16 prove \
  ceremony/zkey_final.zkey ceremony/witness.wtns \
  ceremony/proof.json ceremony/public.json

# Verify off-chain
npx snarkjs groth16 verify \
  ceremony/verification_key.json \
  ceremony/public.json ceremony/proof.json
# → [INFO] snarkJS: OK!
```

---

## Known limitations — upgrade path

| Limitation | Fix |
|---|---|
| Phase 1 is dev ptau (single-contributor) | Replace with Hermez pot28 (`feat/ceremony-mainnet`) |
| Circuit depth 4 → 16 members max | Recompile at depth 20, re-run phase 2 with pot22 (`feat/ceremony-mainnet`) |
| Contributors are anonymous, no public attestation URLs | Open contribution round with signed attestations |

For mainnet: download Hermez pot28 → recompile circuit at depth 20 →
run a public multi-party phase 2 with external contributors → re-export verifier.
