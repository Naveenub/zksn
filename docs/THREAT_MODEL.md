# ZKSN Threat Model

## Adversary Classes

### Class A — Local Passive (LPA)
Observes one network link. **Defense:** Sphinx encryption + fixed packet size. **Residual:** None at link level.

### Class B — Global Passive (GPA)
Observes ALL links simultaneously. **Defense:** Poisson(λ) mixing + mandatory cover traffic. **Residual:** Statistical correlation over months. Active research area.

### Class C — Active
Injects, drops, modifies packets. **Defense:** Noise MACs reject modifications; drops trigger retransmit. **Residual:** n-1 attack partially mitigated by batching.

### Class D — Compromised Nodes
Controls subset of mix nodes. **Defense:** Multi-hop; single node sees one hop. **Residual:** Entry+exit control enables path correlation.

### Class E — Legal/Compulsion
Seizes hardware, subpoenas. **Defense:** Stateless RAM-only nodes; no corporate entity. **Residual:** Operators in hostile jurisdictions remain at personal risk.

### Class F — Sybil
Creates fake nodes/identities. **Defense:** Economic stake + node reputation. **Residual:** Capitalized adversary can attempt governance capture.

## Known Limitations

1. **Anonymity set size** — Small networks are trivially deanonymizable.
2. **Endpoint security** — ZKSN secures the network path, not the device.
3. **Long-term traffic analysis** — Extended observation enables probabilistic deanonymization.
4. **Bootstrap discovery** — Initial peer discovery is a weak point.
5. **Exit nodes** — Any clearnet exit node is exposed. Closed-loop default mitigates this.
