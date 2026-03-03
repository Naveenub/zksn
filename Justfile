# ZKSN Developer Commands
# Usage: just <command>

default:
    @just --list

# ── Build ──────────────────────────────────────────
build:
    cargo build --workspace

build-release:
    cargo build --workspace --release

build-node:
    cargo build --package zksn-node

build-client:
    cargo build --package zksn-client

# ── Test ───────────────────────────────────────────
test:
    cargo test --workspace

test-v:
    cargo test --workspace -- --nocapture

test-crypto:
    cargo test --package zksn-crypto -- --nocapture

test-node:
    cargo test --package zksn-node -- --nocapture

test-governance:
    cd governance && forge test -vv

test-all: test test-governance

# ── Quality ────────────────────────────────────────
fmt:
    cargo fmt --all
    cd governance && forge fmt

lint:
    cargo clippy --workspace --all-targets

audit:
    cargo audit

check: fmt lint test

# ── Dev ────────────────────────────────────────────
identity:
    cargo run --package zksn-client -- identity generate

node:
    cargo run --package zksn-node -- --config node.toml --testnet

devnet:
    cd infra/docker && docker compose up -d

devnet-stop:
    cd infra/docker && docker compose down

devnet-logs:
    cd infra/docker && docker compose logs -f

# ── Contracts ──────────────────────────────────────
sol-build:
    cd governance && forge build --sizes

sol-test:
    cd governance && forge test -vv

sol-fmt:
    cd governance && forge fmt

anvil:
    anvil

# ── Docs ───────────────────────────────────────────
docs:
    cargo doc --workspace --open

# ── Release ────────────────────────────────────────
release: check build-release
    @echo "Release build complete: target/release/"

clean:
    cargo clean
    cd governance && forge clean
