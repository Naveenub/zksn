//! # Message Receiving
//!
//! Listens for incoming Sphinx packets addressed to this client's identity.
//! Decrypts and delivers them to the application layer.

use anyhow::Result;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{debug, warn};
use zksn_crypto::identity::ZksnIdentity;

use crate::config::ClientConfig;

/// Start listening for incoming messages.
///
/// Returns a channel receiver. Each item is a decrypted message payload.
pub async fn start_receiver(
    identity: &ZksnIdentity,
    config: &ClientConfig,
) -> Result<mpsc::Receiver<Vec<u8>>> {
    // Listen on a local port for the final-hop delivery from the mix network
    // In a real deployment this would be an I2P tunnel endpoint or
    // a Nym SURB (Single-Use Reply Block) listener.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_addr = listener.local_addr()?;
    tracing::info!("Receiving on {local_addr}");

    let (tx, rx) = mpsc::channel::<Vec<u8>>(256);

    // Extract identity private key bytes for decryption
    let secret_bytes = identity.to_secret_bytes();

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((mut stream, peer)) => {
                    debug!("Delivery from {peer}");
                    let tx2 = tx.clone();
                    let key = secret_bytes;
                    tokio::spawn(async move {
                        use tokio::io::AsyncReadExt;
                        use zksn_crypto::sphinx::PACKET_SIZE;

                        let mut buf = vec![0u8; PACKET_SIZE];
                        if stream.read_exact(&mut buf).await.is_ok() {
                            // TODO: decrypt Sphinx packet final layer with private key
                            // For now, strip the fixed header and emit the payload
                            let payload = buf[64..].to_vec();
                            let _ = tx2.send(payload).await;
                        }
                    });
                }
                Err(e) => {
                    warn!("Receive error: {e}");
                }
            }
        }
    });

    Ok(rx)
}
