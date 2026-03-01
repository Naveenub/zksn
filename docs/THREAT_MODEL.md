# ZKSN Threat Model

## Adversary Classification

### Class A: Local Passive Adversary (LPA)
Can observe traffic on a single network link.
**ZKSN Defense:** Sphinx packet encryption + fixed packet size. LPA learns nothing.

### Class B: Global Passive Adversary (GPA)
Can observe ALL network links simultaneously (e.g., nation-state with backbone access).
**ZKSN Defense:** Poisson mixing with cover traffic. GPA cannot perform timing correlation.
**Residual Risk:** Statistical correlation over months/years of observation is theoretically possible. This is an open research problem. Cover traffic significantly raises the cost.

### Class C: Active Adversary
Can inject, drop, modify, or delay packets.
**ZKSN Defense:** Noise protocol MACs detect modification. Dropped packets trigger retransmit. Injected packets are rejected (fail MAC).
**Residual Risk:** Selective packet dropping (n-1 attack) is partially mitigated by batching; full mitigation requires threshold mixing.

### Class D: Compromised Node Adversary
Controls a subset of mix nodes.
**ZKSN Defense:** Multi-hop routing means a single compromised node learns only one hop. Corrupting the full path requires controlling all nodes in a route.
**Residual Risk:** If adversary controls entry AND exit node, path correlation is possible. Route selection algorithm should maximize geographic/AS diversity.

### Class E: Legal/Compulsion Adversary
Seizes hardware, issues subpoenas, compels testimony.
**ZKSN Defense:** Stateless RAM-only nodes yield no stored data on seizure. No corporate entity to subpoena. Anonymous contributors cannot be compelled to testify about things they don't know.
**Residual Risk:** Operators of infrastructure in hostile jurisdictions remain at personal risk. See LEGAL.md.

### Class F: Sybil Adversary
Creates many fake nodes/identities to influence network behavior.
**ZKSN Defense:** PoS governance with economic cost. Long-standing node reputation weighting.
**Residual Risk:** Sufficiently capitalized adversary can still attempt governance capture.

---

## Known Limitations

1. **Anonymity set size:** The network requires a minimum number of active users to provide meaningful anonymity. Small networks are trivially deanonymizable regardless of cryptography.

2. **Endpoint security is out of scope:** ZKSN secures the network. It cannot protect against compromised client devices, malware, or hardware-level attacks (Intel ME, AMD PSP).

3. **Long-term traffic analysis:** An adversary observing traffic patterns for extended periods can build probabilistic deanonymization models even against cover traffic. This is an active research area with no complete solution.

4. **Bootstrap problem:** New nodes must find peers somehow. Initial peer discovery remains a weak point.

5. **Exit node exposure:** Any node providing clearnet access is exposed. The closed-loop architecture mitigates this by making clearnet access optional and isolated.
