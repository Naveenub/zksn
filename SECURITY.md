# Security Policy

## Scope

Security vulnerabilities in ZKSN are taken extremely seriously. The entire purpose of this project is to provide strong privacy and anonymity guarantees — a security flaw could have severe consequences for users who depend on the network.

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

To report a vulnerability:

1. **Preferred:** Encrypt your report with the project's security PGP key (published in `keys/security.asc`) and email it to the security contact listed there.

2. **Alternative:** If GPG is not available to you, open a GitHub Security Advisory (private, via GitHub's interface) in this repository.

Include in your report:
- Description of the vulnerability
- Which component(s) are affected
- Steps to reproduce
- Your assessment of severity and exploitability
- Your suggested fix (if you have one)

## Response Timeline

- **Acknowledgment:** Within 72 hours
- **Initial assessment:** Within 7 days
- **Fix or mitigation:** Varies by severity
  - Critical (active deanonymization): Target 7 days
  - High: Target 30 days
  - Medium/Low: Target 90 days

## Disclosure Policy

We follow coordinated disclosure:
1. Reporter submits vulnerability privately
2. Maintainers assess and develop a fix
3. Fix is staged and reviewed
4. Public disclosure occurs after fix is available
5. Reporter is credited (or anonymous, at their preference)

## Severity Classification

**Critical:** Can deanonymize users, expose IP addresses, or compromise private keys.

**High:** Can compromise the economic layer, allow double-spend, or degrade anonymity set significantly.

**Medium:** Denial of service, non-privacy-impacting information leaks.

**Low:** Everything else.

## Security Design Assumptions

ZKSN's security guarantees are predicated on:

1. The Sphinx packet format being cryptographically sound
2. The Noise protocol handshake providing forward secrecy
3. Mix node operators being independently operated (not colluding)
4. Cover traffic parameters being correctly tuned
5. The anonymity set being large enough (see threat model)

Vulnerabilities that invalidate these assumptions are Critical severity.
