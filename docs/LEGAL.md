# ZKSN Legal Analysis

> This is not legal advice. Consult qualified legal counsel for your situation.

## Structural Design for Legal Resilience

**No incorporated entity.** ZKSN has no foundation, LLC, or registered entity in any jurisdiction. No officers, directors, or registered agents. No corporate assets to seize. This is a deliberate architectural decision informed by the Tornado Cash prosecution (US v. Storm, SDNY 2023).

**Code is protected speech.** *Bernstein v. DOJ* (9th Cir. 1999) established source code is protected expression under the First Amendment. *Junger v. Daley* (6th Cir. 2000) extended this to encryption software.

**Mere conduit doctrine.** Mix node operators transmit encrypted packets they cannot read, do not know the contents of, and have no control over. This is structurally analogous to ISP common carrier status under EU DSA Article 4 and US CDA Section 230.

**Jurisdiction fragmentation.** Target: 30+ countries, no country >15% of nodes. No single court order affects more than a fraction of the network.

## For Node Operators

1. Know your local laws regarding anonymization tools.
2. Document the non-commercial, research/educational purpose of your node.
3. Mix-only nodes carry significantly lower risk than exit nodes.
4. Operate in jurisdictions with strong rule of law and data protection frameworks.
5. Consider joining legal defense networks that support Tor relay operators.

## Relevant Precedents

| Case | Jurisdiction | Relevance |
|---|---|---|
| Bernstein v. DOJ (1999) | US 9th Cir. | Source code = protected speech |
| Junger v. Daley (2000) | US 6th Cir. | Encryption software = protected speech |
| US v. Storm (2023) | US SDNY | Tornado Cash; foundation was a target |
| Tor relay cases | Various | Relay operators generally not liable for forwarded traffic |
