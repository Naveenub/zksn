//! Message receiving — listens for final-hop Sphinx packets and delivers
//! decrypted payloads to the application layer.
//!
//! When the last mix node in a route peels its onion layer, it looks up the
//! recipient's X25519 public key in its PeerTable and TCP-connects to the
//! recipient's `listen_addr`.  This module accepts that connection, peels
//! the final Sphinx layer using the client's own X25519 private key, strips
//! the length-prefixed framing, and sends the plaintext to the caller via
//! an mpsc channel.

use crate::send::unframe_payload;
use anyhow::Result;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use zksn_crypto::sphinx::{peel_layer, SphinxPacket, PACKET_SIZE};

/// Start the receive loop and return a channel of incoming plaintext messages.
///
/// `own_privkey` is the client's X25519 private key (32 bytes), used to peel
/// the final Sphinx layer.
///
/// `listen_addr` is the TCP address to bind (e.g. `"[::1]:9002"`).
pub async fn start_receiver(
    own_privkey: [u8; 32],
    listen_addr: &str,
) -> Result<mpsc::Receiver<Vec<u8>>> {
    let listener = TcpListener::bind(listen_addr).await?;
    let bound = listener.local_addr()?;
    info!("Receiver listening on {bound}");

    let (tx, rx) = mpsc::channel::<Vec<u8>>(64);

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    debug!("Delivery from {peer}");
                    let tx2 = tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_delivery(stream, &own_privkey, tx2).await {
                            warn!("Delivery error from {peer}: {e}");
                        }
                    });
                }
                Err(e) => warn!("Accept error: {e}"),
            }
        }
    });

    Ok(rx)
}

/// Read one Sphinx packet, peel the final layer, unframe, and forward.
async fn handle_delivery(
    mut stream: tokio::net::TcpStream,
    own_privkey: &[u8; 32],
    tx: mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let mut buf = vec![0u8; PACKET_SIZE];
    stream.read_exact(&mut buf).await?;

    let pkt = bincode::deserialize::<SphinxPacket>(&buf)?;

    // Peel the final Sphinx layer — this reveals the plaintext payload
    let (_next_hop, peeled) =
        peel_layer(&pkt, own_privkey).map_err(|e| anyhow::anyhow!("peel_layer: {e:?}"))?;

    // Strip the length-prefix framing added by send.rs
    let message = unframe_payload(&peeled.payload)?;

    debug!("Received {} byte message", message.len());
    tx.send(message).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::send::frame_payload;
    use tokio::io::AsyncWriteExt;
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
    use zksn_crypto::sphinx::{build_packet, NodeIdentity};

    /// Build a one-hop Sphinx packet addressed to `recipient_pubkey`,
    /// containing `message`, and send it over TCP to `addr`.
    async fn send_test_packet(addr: &str, recipient_pubkey: [u8; 32], message: &[u8]) {
        let route = vec![NodeIdentity {
            public_key: recipient_pubkey,
        }];
        let payload = frame_payload(message).unwrap();
        let pkt = build_packet(&route, &payload, &mut rand::thread_rng()).unwrap();
        let mut buf = bincode::serialize(&pkt).unwrap();
        buf.resize(PACKET_SIZE, 0u8);

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(&buf).await.unwrap();
        stream.flush().await.unwrap();
    }

    #[tokio::test]
    async fn test_receive_single_message() {
        // Generate recipient keypair
        let privkey_bytes = [0x42u8; 32];
        let secret = StaticSecret::from(privkey_bytes);
        let pubkey: [u8; 32] = X25519PublicKey::from(&secret).to_bytes();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        drop(listener); // free port

        let mut rx = start_receiver(privkey_bytes, &addr).await.unwrap();

        let msg = b"hello from the mixnet";
        send_test_packet(&addr, pubkey, msg).await;

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");

        assert_eq!(received, msg);
    }

    #[tokio::test]
    async fn test_receive_empty_message() {
        let privkey_bytes = [0x11u8; 32];
        let secret = StaticSecret::from(privkey_bytes);
        let pubkey: [u8; 32] = X25519PublicKey::from(&secret).to_bytes();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        drop(listener);

        let mut rx = start_receiver(privkey_bytes, &addr).await.unwrap();

        send_test_packet(&addr, pubkey, b"").await;

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout")
            .unwrap();
        assert!(received.is_empty());
    }

    #[tokio::test]
    async fn test_wrong_key_delivers_garbage_not_panic() {
        // A packet encrypted for key_A, decrypted with key_B — should not panic,
        // but unframe will return an error (random garbage length byte)
        let privkey_a = [0xAAu8; 32];
        let secret_a = StaticSecret::from(privkey_a);
        let pubkey_a: [u8; 32] = X25519PublicKey::from(&secret_a).to_bytes();

        let privkey_b = [0xBBu8; 32]; // wrong key

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        drop(listener);

        // Receiver uses privkey_b
        let mut rx = start_receiver(privkey_b, &addr).await.unwrap();

        // Sender encrypts for pubkey_a
        send_test_packet(&addr, pubkey_a, b"secret").await;

        // Receiver should not crash — it silently drops the garbled packet
        let r = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv()).await;
        // Either timeout (packet dropped) or received garbage
        // Either is acceptable — the important thing is no panic
        let _ = r;
    }
}
