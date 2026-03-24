# ZKSN Audit Findings Template

Use this template for all findings. Submit as a single Markdown document
with one section per finding, ordered by severity (Critical → High →
Medium → Low → Informational).

---

## Severity definitions

| Severity | Definition | Expected response |
|---|---|---|
| **Critical** | Direct loss of anonymity, key compromise, proof forgery, or ability to impersonate any participant without the correct secret | Fix before any production deployment. Re-audit required. |
| **High** | Significant weakening of anonymity guarantees, double-spend without mint collusion, governance manipulation, or remote code execution | Fix before mainnet. Re-test required. |
| **Medium** | Partial anonymity degradation, DoS against individual nodes, economic manipulation requiring special conditions, or deviation from spec without immediate exploitability | Fix before mainnet. Documentation of accepted risk acceptable. |
| **Low** | Minor spec deviation, defence-in-depth gap, best-practice violation, or finding requiring significant attacker resources and yielding minimal gain | Fix or document before mainnet. |
| **Informational** | Code quality, dead code, missing tests, unclear documentation, or design observations with no direct security impact | Address at discretion. |

---

## Finding template

Copy this block once per finding.

---

### ZKSN-XXX: [Short title]

| Field | Value |
|---|---|
| **ID** | ZKSN-XXX |
| **Severity** | Critical / High / Medium / Low / Informational |
| **Status** | Open / Fixed / Acknowledged / Won't Fix |
| **Sub-scope** | A (Rust) / B (ZK + Solidity) |
| **File(s)** | `path/to/file.rs` line N |
| **Commit** | (hash where introduced, if known) |
| **Fix commit** | (hash of fix, filled in during re-test) |

#### Description

Clear, concise description of the finding. Explain what the code does,
what it should do, and why the difference matters.

#### Impact

What can an attacker do if this finding is exploited? Be specific: does
it break unlinkability, allow proof forgery, enable double-spend, etc.?
Quantify the attacker's resources required if possible.

#### Proof of concept

```
Steps to reproduce or demonstrate the finding.
Include code, inputs, or protocol traces as appropriate.
```

#### Recommendation

Specific, actionable remediation guidance. If a fix exists in the
literature (e.g. a well-known mitigation for the Sphinx n-1 attack),
cite it.

#### References

- [Reference 1]
- [Reference 2]

---

## Example: filled-in finding

### ZKSN-001: Example — Sphinx blinding factor not clamped

| Field | Value |
|---|---|
| **ID** | ZKSN-001 |
| **Severity** | Critical |
| **Status** | Open |
| **Sub-scope** | A (Rust) |
| **File(s)** | `crypto/src/sphinx.rs` line 142 |
| **Commit** | abc1234 |
| **Fix commit** | (pending) |

#### Description

The per-hop blinding factor `b_i` is applied to `α_i` via scalar
multiplication, but the scalar is not clamped to the X25519 cofactor
subgroup. X25519 requires bits 0, 1, 2, and 255 of the scalar to be
set/cleared appropriately. Without clamping, the resulting `α_{i+1}` may
land in a small-order subgroup, allowing a colluding pair of nodes to
test whether two observed packets share a common blinding path.

#### Impact

Two colluding mix nodes at positions `i` and `j` can correlate packets
originating from the same sender even without controlling the entry node.
This reduces the anonymity set to the subset of packets that pass through
both colluding nodes, which could be as few as 1 in a low-traffic network.

#### Proof of concept

```python
# Blinding factor b is not clamped:
b = sha256("sphinx-blinding" || s || alpha)
alpha_next = scalar_mult(b, alpha)  # b unclamped → small subgroup possible
```

#### Recommendation

Apply X25519 clamping to `b_i` before scalar multiplication:
```rust
b[0]  &= 248;
b[31] &= 127;
b[31] |= 64;
```
This is the standard X25519 scalar preparation as specified in RFC 7748.

#### References

- RFC 7748, Section 5 (X25519 scalar preparation)
- Sphinx paper, Danezis & Goldberg 2009, Section 3.2

---

## Summary table

Fill this in as findings are added.

| ID | Title | Severity | Status | Sub-scope |
|---|---|---|---|---|
| ZKSN-001 | | | | |
| ZKSN-002 | | | | |
| ZKSN-003 | | | | |

---

## Re-test sign-off

After fixes are applied, auditors confirm each Critical and High finding:

| ID | Fix description | Fix verified | Auditor |
|---|---|---|---|
| ZKSN-001 | | ☐ | |
| ZKSN-002 | | ☐ | |

---

## Disclosure timeline

| Date | Event |
|---|---|
| (kickoff) | Audit begins |
| (draft) | Draft report delivered |
| (triage) | Fix window begins |
| (re-test) | Re-test of Critical/High findings |
| (final) | Final report delivered |
| (disclosure) | Public disclosure (90 days after final, or sooner by mutual agreement) |
