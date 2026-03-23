# ZKSN v1.1.0 — Yggdrasil 200::/7 enforced at Rust socket level
**⚠️ Release candidate. Not yet production-audited.**

## What's in this release

### feat/yggdrasil-transport — transport anonymity enforced in Rust

Previously: nodes bound to plain TCP, peer connections were accepted and
initiated regardless of address family. A misconfigured node would bind to
a non-Yggdrasil interface and expose its real IP. The Yggdrasil requirement
existed only in Docker/Nix infra config, invisible to the Rust binary.

Now: the binary itself refuses to start, accept, or dial unless every address
is inside the Yggdrasil `200::/7` prefix — unless explicitly opted out.

---

### New module: `node/src/network.rs`

Core predicate and enforcement helpers.

```rust
// 200::/7: first 7 bits = 0000 001 → first byte ∈ {0x02, 0x03}
pub fn is_yggdrasil(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V6(v6) => v6.octets()[0] & 0xFE == 0x02,
        IpAddr::V4(_)  => false,
    }
}

pub fn check_bind(addr: &str, enforce: bool) -> anyhow::Result<()>
pub fn check_peer(addr: &str, enforce: bool) -> anyhow::Result<()>
```

Both `check_*` functions no-op when `enforce = false`, so development
and testnet flows require zero code changes.

---

### Three enforcement points

**1. Bind — `MixNode::new()`**

```rust
network::check_bind(&config.network.listen_addr, config.enforce_yggdrasil())?;
let listener = TcpListener::bind(&config.network.listen_addr).await?;
```

A node with a non-Yggdrasil `listen_addr` fails at startup:
```
Error: Listen address '127.0.0.1:9001' is not in the Yggdrasil address
space (200::/7). Set network.yggdrasil_only = false in node.toml to override.
```

**2. Inbound accept — `handle_conn()`**

```rust
if payment_guard.enforce_yggdrasil() {
    if let Ok(peer_addr) = stream.peer_addr() {
        if !network::is_yggdrasil(&peer_addr.ip()) {
            anyhow::bail!("Rejected inbound connection from non-Yggdrasil address {peer_addr}");
        }
    }
}
```

Connections from outside `200::/7` are dropped before any data is read.

**3. Outbound dial — `PeerDiscovery`**

```rust
// in connect_and_exchange() and find_node()
crate::network::check_peer(addr, self.enforce_yggdrasil)?;
```

Kademlia gossip and bootstrap dials to non-Yggdrasil peers are rejected
before `TcpStream::connect`. Peer addresses received from gossip that are
outside `200::/7` are also checked before any connection attempt.

---

### Configuration

`node.toml` (node) and `client.toml` (client) gain one new field:

```toml
[network]
yggdrasil_only = true   # default — enforce 200::/7
# yggdrasil_only = false  # development / testnet / CI
```

**`NodeConfig::enforce_yggdrasil()`** — single source of truth:
```rust
pub fn enforce_yggdrasil(&self) -> bool {
    self.network.yggdrasil_only && !self.testnet
}
```

`testnet = true` always overrides `yggdrasil_only` — setting either one
disables enforcement. The `yggdrasil_only` field defaults to `true` via
serde, so existing config files without the field get enforcement for free
on upgrade.

The existing `--testnet` CLI flag continues to disable enforcement as before.

---

### Client enforcement

`ZksnClient::new()` checks both `listen_addr` and `entry_node` at
construction time before any sockets are opened:

```rust
network::check_bind(&config.listen_addr, config.yggdrasil_only)?;
network::check_peer(&config.entry_node,  config.yggdrasil_only)?;
```

---

## Test coverage

| Crate / File | v1.0.0-rc1 | v1.1.0 | New |
|---|---|---|---|
| `node/src/network.rs` | — | 21 | +21 |
| `node/src/config.rs` | 4 | 6 | +2 |
| `node/src/node.rs` | 4 | 6 | +2 |
| `node/src/peers.rs` | 8 | 11 | +3 |
| `client/src/lib.rs` | 5 | 8 | +4 (incl. 3 Yggdrasil) |
| All other | 174 | 174 | — |
| **Total** | **195** | **227** | **+32** |

New tests verify: boundary addresses (`200::` and `3ff:ffff:...`),
non-Yggdrasil addresses (`::1`, `2001:db8::`, `192.168.x.x`, `127.0.0.1`),
string-form address parsing, enforcement on/off modes, testnet bypass,
`check_bind`/`check_peer` error messages, and peer rejection at both
connect and accept paths.

---

## Files changed

```
node/src/network.rs          ← NEW — is_yggdrasil(), check_bind(), check_peer()
node/src/lib.rs              ← add pub mod network
node/src/config.rs           ← yggdrasil_only field, enforce_yggdrasil()
node/src/node.rs             ← check_bind on startup, check inbound peer_addr
node/src/payment.rs          ← enforce_yggdrasil() accessor on PaymentGuard
node/src/peers.rs            ← check_peer on all outbound dials
client/src/config.rs         ← yggdrasil_only field
client/src/lib.rs            ← check_bind + check_peer in ZksnClient::new()
```

---

## Remaining gap

| Gap | Branch |
|---|---|
| No demo script — no single-command devnet flow | `feat/demo` |

---

## Cumulative state at v1.1.0

**Solid ✅**
- Ed25519, Sphinx, Noise_XX, ZKP primitives
- Mix node — Poisson, cover traffic, Kademlia, PaymentEnvelope
- Client — send/receive, RouteSelector
- Economic — blind token full cycle, MeltManager
- Governance — depth-20 circuit, BN254 pairing, pot28 VK (1,000+ contributors)
- PoseidonHasher — circomlibjs bytecode, matches circuit exactly
- `scripts/tree.js` — sparse depth-20 Poseidon tree
- **Yggdrasil `200::/7` enforced at bind, accept, and dial**

**Stubbed ❌**
- No demo script
