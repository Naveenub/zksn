# ZKSN Development Commands
# Install: https://github.com/casey/just
# Run:     just <command>

# Default: list all commands
default:
    @just --list

# ============================================================================
# Build
# ============================================================================

# Build all crates (debug)
build:
    cargo build --workspace

# Build all crates (release)
build-release:
    cargo build --workspace --release

# Build just the mix node
build-node:
    cargo build --package zksn-node --release

# Build just the CLI client
build-client:
    cargo build --package zksn-client --release

# ============================================================================
# Test
# ============================================================================

# Run all Rust tests
test:
    cargo test --workspace

# Run tests with output (verbose)
test-v:
    cargo test --workspace -- --nocapture

# Run only crypto tests
test-crypto:
    cargo test --package zksn-crypto

# Run Foundry governance tests
test-governance:
    cd governance && forge test -vvv

# Run all tests (Rust + Foundry)
test-all: test test-governance

# ============================================================================
# Code Quality
# ============================================================================

# Format all Rust code
fmt:
    cargo fmt --all

# Lint with Clippy
lint:
    cargo clippy --workspace --all-targets -- -D warnings

# Run security audit on dependencies
audit:
    cargo audit

# Check everything (fmt + lint + test)
check: fmt lint test
    @echo "✓ All checks passed"

# ============================================================================
# Development Node
# ============================================================================

# Generate a fresh identity keypair
identity:
    ./scripts/gen-identity.sh ./keys/

# Start a local dev mix node (single instance)
node:
    cargo run --package zksn-node -- --config node/node.toml.example --debug --testnet

# Start the local Docker development network
devnet:
    docker compose -f infra/docker/docker-compose.yml up

# Stop the development network
devnet-stop:
    docker compose -f infra/docker/docker-compose.yml down

# View devnet logs
devnet-logs:
    docker compose -f infra/docker/docker-compose.yml logs -f

# ============================================================================
# Smart Contracts
# ============================================================================

# Compile governance contracts
sol-build:
    cd governance && forge build

# Run governance tests
sol-test:
    cd governance && forge test -vvv

# Format Solidity files
sol-fmt:
    cd governance && forge fmt

# Start local Ethereum node for testing
anvil:
    anvil

# ============================================================================
# Documentation
# ============================================================================

# Build Rust API docs
docs:
    cargo doc --workspace --no-deps --open

# ============================================================================
# Release
# ============================================================================

# Build release binaries for current platform
release: build-release
    @echo "Binaries at:"
    @echo "  target/release/zksn-node"
    @echo "  target/release/zksn"

# Clean build artifacts
clean:
    cargo clean
    cd governance && forge clean || true
