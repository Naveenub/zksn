# ZKSN Client

The client library and CLI for sending and receiving messages over ZKSN.

## CLI Usage

```bash
# Generate a new identity
zksn identity generate --output ~/.zksn/identity.key

# Show your current identity fingerprint
zksn identity show --key ~/.zksn/identity.key

# Send a message
zksn send \
  --key ~/.zksn/identity.key \
  <recipient_pubkey_hex> \
  "Hello, sovereign world!"

# Listen for incoming messages
zksn receive --key ~/.zksn/identity.key

# Check wallet balance
zksn wallet balance

# Top up wallet with XMR
zksn wallet topup 10000
```

## Library Usage

```rust
use zksn_client::{ZksnClient, ClientConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = ClientConfig {
        key_path: Some("/home/user/.zksn/identity.key".to_string()),
        entry_node: "[200:abcd::1]:9001".to_string(),
        ..ClientConfig::default()
    };

    let client = ZksnClient::new(config).await?;

    println!("My identity: {}", client.fingerprint());

    // Send
    client.send("recipient_pubkey_hex", b"hello").await?;

    // Receive
    let mut rx = client.receive().await?;
    while let Some(msg) = rx.recv().await {
        println!("Got: {}", String::from_utf8_lossy(&msg));
    }

    Ok(())
}
```

## Build

```bash
cargo build --release --package zksn-client
./target/release/zksn --help
```
