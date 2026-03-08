//! Message receiving — listens for final-hop Sphinx packets and delivers
//! decrypted payloads to the application layer.

use crate::send::unframe_payload;
use anyhow::Result;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use zksn_crypto::sphinx::{peel_layer, SphinxPacket, PACKET_SIZE};

/// Start the receive loop bound to `listen_addr`.
pub async fn start_receiver(
    own_privkey: [u8; 32],
    listen_addr: &str,
) -> Result<mpsc::Receiver<Vec<u8>>> {
    let listener = TcpListener::bind(listen_addr).await?;
    start_receiver_on(own_privkey, listener).await
}

/// Start the receive loop on an already-bound `TcpListener`.
/// Used in tests to avoid bind→drop→rebind port races.
pub async fn start_receiver_on(
    own_privkey: [u8; 32],
    listener: TcpListener,
) -> Result<mpsc::Receiver<Vec<u8>>> {
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

async fn handle_delivery(
    mut stream: tokio::net::TcpStream,
    own_privkey: &[u8; 32],
    tx: mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let mut buf = vec![0u8; PACKET_SIZE];
    stream.read_exact(&mut buf).await?;

    let buf_arr: &[u8; PACKET_SIZE] = buf.as_slice().try_into()?;
    let pkt = SphinxPacket::from_bytes(buf_arr);

    let (_next_hop, peeled) =
        peel_layer(&pkt, own_privkey).map_err(|e| anyhow::anyhow!("peel_layer: {e:?}"))?;

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

    async fn send_test_packet(addr: &str, recipient_pubkey: [u8; 32], message: &[u8]) {
        let route = vec![NodeIdentity {
            public_key: recipient_pubkey,
        }];
        let payload = frame_payload(message).unwrap();
        let pkt = build_packet(&route, &payload, &mut rand::thread_rng()).unwrap();
        let buf = pkt.to_bytes();
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(&buf).await.unwrap();
        stream.flush().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_receive_single_message() {
        let privkey_bytes = [0x42u8; 32];
        let secret = StaticSecret::from(privkey_bytes);
        let pubkey: [u8; 32] = X25519PublicKey::from(&secret).to_bytes();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let mut rx = start_receiver_on(privkey_bytes, listener).await.unwrap();

        send_test_packet(&addr, pubkey, b"hello from the mixnet").await;

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");

        assert_eq!(received, b"hello from the mixnet");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_receive_empty_message() {
        let privkey_bytes = [0x11u8; 32];
        let secret = StaticSecret::from(privkey_bytes);
        let pubkey: [u8; 32] = X25519PublicKey::from(&secret).to_bytes();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let mut rx = start_receiver_on(privkey_bytes, listener).await.unwrap();

        send_test_packet(&addr, pubkey, b"").await;

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout")
            .unwrap();
        assert!(received.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_wrong_key_delivers_garbage_not_panic() {
        let privkey_a = [0xAAu8; 32];
        let secret_a = StaticSecret::from(privkey_a);
        let pubkey_a: [u8; 32] = X25519PublicKey::from(&secret_a).to_bytes();

        let privkey_b = [0xBBu8; 32];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let mut rx = start_receiver_on(privkey_b, listener).await.unwrap();

        send_test_packet(&addr, pubkey_a, b"secret").await;

        let r = tokio::time::timeout(std::time::Duration::from_millis(300), rx.recv()).await;
        let _ = r; // timeout or garbage — either fine, must not panic
    }
}
