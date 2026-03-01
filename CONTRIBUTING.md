# Contributing to ZKSN

Thank you for your interest in contributing to ZKSN.

---

## Principles for Contributors

1. **Anonymity is respected.** You are not required to contribute under your real name. GPG-signed commits from anonymous keypairs are fully accepted. No contributor PII is collected or required.

2. **Code quality over quantity.** Cryptographic and network security code must be correct. Take your time. Write tests.

3. **Security-first mindset.** When in doubt, err on the side of caution. Flag potential security issues even if you're unsure — see SECURITY.md for responsible disclosure.

4. **No central authority.** This is a collaborative project with no BDFL. Significant changes should go through community discussion before implementation.

---

## Anonymous Contribution Setup

To contribute without revealing your identity:

```bash
# Create a dedicated anonymous git identity
git config user.name "anon"
git config user.email "anon@zksn.invalid"

# Sign commits with an anonymous GPG key
# Generate anonymous GPG key (no real name/email required)
gpg --batch --gen-key <<EOF
Key-Type: eddsa
Key-Curve: ed25519
Name-Real: ZKSN Contributor
Name-Email: contributor@zksn.invalid
Expire-Date: 1y
%no-protection
EOF

# Configure git to sign commits
git config commit.gpgsign true
git config user.signingkey <YOUR_KEY_ID>
```

Route your git traffic through Tor or I2P when pushing:

```bash
# Via Tor (requires tor running locally)
GIT_SSH_COMMAND="ssh -o ProxyCommand='nc -x 127.0.0.1:9050 %h %p'" git push

# Or set in git config
git config core.sshCommand "ssh -o ProxyCommand='nc -x 127.0.0.1:9050 %h %p'"
```

---

## Development Environment Setup

### Prerequisites

- Rust (stable, 1.75+) — primary implementation language
- Python 3.11+ — tooling and economic layer
- Nix (optional but strongly recommended for reproducibility)
- Docker + Docker Compose — local test networks

### With Nix (Recommended)

```bash
git clone https://github.com/YOUR_ORG/zksn.git
cd zksn
nix develop  # enters reproducible dev shell with all dependencies
```

### Without Nix

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone and build
git clone https://github.com/YOUR_ORG/zksn.git
cd zksn
cargo build
```

---

## Making Changes

### For Bug Fixes

1. Fork the repository
2. Create a branch: `git checkout -b fix/description-of-fix`
3. Make your changes with tests
4. Ensure all tests pass: `cargo test`
5. Submit a pull request with a clear description

### For New Features

1. Open an issue first to discuss the feature
2. Wait for community feedback before investing significant time
3. Follow the same branch/PR process as bug fixes

### For Cryptographic Changes

Cryptographic changes require:
- A detailed writeup of the change and its security rationale
- Reference to relevant literature or prior art
- Review by at least two contributors familiar with the relevant cryptographic domain
- A clear statement of what threat model properties the change improves or trades off

---

## Code Style

**Rust:**
- `cargo fmt` before committing
- `cargo clippy` must pass with no warnings
- Document public APIs with `///` doc comments
- Prefer `Result<T, E>` over panics in library code

**Python:**
- `black` formatter
- `ruff` linter
- Type hints required for all public functions

**Documentation:**
- Write for someone who is competent but unfamiliar with this specific codebase
- Explain *why*, not just *what*
- Keep ARCHITECTURE.md up to date when making structural changes

---

## What We Need Help With

See [docs/ROADMAP.md](./docs/ROADMAP.md) for the full picture. High-priority areas:

- **Rust implementation of Sphinx packet format**
- **Noise protocol integration**
- **i2pd configuration tooling**
- **NixOS module development**
- **Cashu integration**
- **Documentation and technical writing**
- **Security review and testing**

---

## Code of Conduct

Be constructive. Engage on the technical merits. Personal attacks, harassment, and bad-faith participation are not welcome. This is a focused technical project — keep discussions on topic.
