//! # Message Sending
//!
//! Handles the full pipeline of sending a message:
//! 1. Encrypt payload for recipient
//! 2. Build Sphinx packet with random route
//! 3. Attach Cashu payment token
//! 4. Transmit to entry mix node

use anyhow::{bail, Result};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::info;
use zksn_crypto::identity::ZksnIdentity;
use zksn_crypto::sphinx::{build_packet, NodeIdentity, PACKET_SIZE};

use crate::config::ClientConfig;
use crate::route::select_route;

/// Send a message through the ZKSN mixnet.
pub async fn send_message(
    sender: &ZksnIdentity,
    recipient_pubkey_hex: &str,
    payload: &[u8],
    config: &ClientConfig,
) -> Result<()> {
    // 1. Validate recipient public key
    let recipient_bytes = hex::decode(recipient_pubkey_hex)
        .map_err(|_| anyhow::anyhow!("Invalid recipient public key hex"))?;
    if recipient_bytes.len() != 32 {
        bail!("Recipient public key must be 32 bytes (64 hex chars)");
    }
    let mut recipient_key = [0u8; 32];
    recipient_key.copy_from_slice(&recipient_bytes);

    // 2. Build route through mix network
    let route = select_route(config.num_hops, &recipient_key).await?;

    info!(
        "Sending {} bytes via {} mix hops",
        payload.len(),
        route.len()
    );

    // 3. Build Sphinx packet
    let mut rng = rand::thread_rng();
    let packet = build_packet(&route, payload, &mut rng)?;

    // 4. Serialize to fixed-size wire format
    let mut wire = bincode::serialize(&packet)?;
    wire.resize(PACKET_SIZE, 0u8);

    // 5. Connect to entry node and transmit
    let mut stream = TcpStream::connect(&config.entry_node).await?;
    stream.write_all(&wire).await?;
    stream.flush().await?;

    info!("Packet submitted to entry node {}", config.entry_node);
    Ok(())
}
