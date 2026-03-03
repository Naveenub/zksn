# Contributing to ZKSN

Anonymity is respected. You are not required to contribute under your real name.
GPG-signed commits from anonymous keypairs are fully accepted.

## Anonymous Setup

```bash
git config user.name "anon"
git config user.email "anon@zksn.invalid"
# Generate anonymous GPG key, configure signing
git config commit.gpgsign true
# Push over Tor
GIT_SSH_COMMAND="ssh -o ProxyCommand='nc -x 127.0.0.1:9050 %h %p'" git push
```

## Development

```bash
# Enter Nix dev shell (recommended)
nix develop

# Or install manually: Rust 1.75+, Foundry
just check     # fmt + lint + test
just test-all  # Rust + Foundry
```

## Cryptographic Code

Before modifying any `crypto/` code or the `todo!()` stubs:
1. Open an issue first for discussion
2. Link to the relevant academic paper
3. Add tests proving the cryptographic property
4. Request review from at least one other contributor

## Code Style

- `cargo fmt` before every commit
- `cargo clippy` with no new warnings
- Tests for all non-trivial logic
- No `unwrap()` in production paths (use `?` or explicit error handling)
