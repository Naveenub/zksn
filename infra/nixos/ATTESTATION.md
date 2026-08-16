# ZKSN NixOS Node — Bare-Metal Hardware Attestation

> **Status: TEMPLATE — not yet filled in.**
> This phase is not complete until a real bare-metal run has been performed
> and this file has been replaced with actual results (including the JSON
> record from `hardware-test.sh`). Do not mark Roadmap phase 5 as 🟢 Done
> until this file no longer says TEMPLATE.

**Date:**
**Operator:**
**Hardware:** (make/model, CPU, RAM, boot mode — e.g. "Dell OptiPlex 7090, i5-11500, 16GB, UEFI")
**NixOS generation / commit:** (output of `nixos-version` and the repo commit deployed)

---

## How to produce this attestation

```bash
# From your local machine, against the deployed node:
bash infra/nixos/hardware-test.sh [200:your:node:addr::1] infra/nixos/attestation-$(date +%Y%m%d).json
```

This runs all 37 automated checks and writes a machine-readable JSON record
(host, kernel, timestamp, per-check pass/fail) to the given path. Commit that
JSON file alongside this document.

---

## 1. Automated suite (`hardware-test.sh`)

Paste the full terminal output below, and commit the JSON record produced
alongside it (`infra/nixos/attestation-YYYYMMDD.json`).

```
<paste full hardware-test.sh output here>
```

**Result:** `<PASS/FAIL count>` — attach `attestation-YYYYMMDD.json`

---

## 2. Manual checks (cannot be automated — see README.md Step 7)

### 2.1 Reboot persistence test

```
<paste command output>
```
**Result:** PASS / FAIL

### 2.2 USB key removal test

```
<paste command output>
```
**Result:** PASS / FAIL

### 2.3 Read-only nix store test

```
<paste command output>
```
**Result:** PASS / FAIL

### 2.4 Non-Yggdrasil connection test

```
<paste command output>
```
**Result:** PASS / FAIL

---

## Summary

| Check category | Result |
|---|---|
| Automated suite (37 checks) | |
| Reboot persistence | |
| USB key removal | |
| Read-only /nix | |
| Non-Yggdrasil rejection | |

**Overall:** PASS / FAIL

Once all rows above are PASS and the JSON record is committed, update
`docs/ROADMAP.md` phase 5 to 🟢 Done and link this file as evidence.
