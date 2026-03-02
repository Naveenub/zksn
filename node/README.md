# ZKSN Mix Node

The mix node is the core infrastructure component of ZKSN. It receives Sphinx packets, applies Poisson delay mixing, emits cover traffic, and forwards packets toward their destination — all without learning the source, destination, or content of any message.

## Running

```bash
# Copy and edit the config
cp node.toml.example node.toml
vim node.toml

# Run (development)
cargo run --package zksn-node -- --config node.toml

# Run (production binary)
cargo build --release
./target/release/zksn-node --config node.toml
```

## Configuration

All settings are in `node.toml`. Key parameters:

| Parameter | Default | Description |
|---|---|---|
| `network.listen_addr` | `[::1]:9001` | Yggdrasil IPv6 listen address |
| `mixing.poisson_lambda_ms` | `200` | Mean mixing delay (ms) |
| `mixing.cover_traffic_rate` | `5` | Cover packets per second |
| `keys.persist_identity` | `false` | Stateless: fresh key each boot |

## Architecture

```
[TCP :9001] → handle_connection()
                    ↓
              [PoissonMixer]  ← CoverTrafficGenerator
                    ↓
              [PacketRouter] → next hop TCP
```

See `src/mixer.rs` for the Poisson delay implementation and `src/cover.rs` for cover traffic generation.
