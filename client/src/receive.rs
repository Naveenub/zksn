use anyhow::Result;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{info, warn};
use zksn_crypto::identity::ZksnIdentity;
use zksn_crypto::sphinx::{SphinxPacket, PACKET_SIZE};
use crate::config::ClientConfig;

pub async fn start_receiver(
    identity: &ZksnIdentity,
    config:   &ClientConfig,
) -> Result<mpsc::Receiver<Vec<u8>>> {
    let listen_addr = config.entry_node.replace("9001", "9002");
    let listener    = TcpListener::bind(&listen_addr).await?;
    let (tx, rx)    = mpsc::channel::<Vec<u8>>(64);
    let _fp         = identity.public().fingerprint();

    info!("Listening for incoming messages on {listen_addr}");

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((mut stream, _)) => {
                    use tokio::io::AsyncReadExt;
                    let mut buf = vec![0u8; PACKET_SIZE];
                    if stream.read_exact(&mut buf).await.is_ok() {
                        if let Ok(pkt) = bincode::deserialize::<SphinxPacket>(&buf) {
                            // TODO: decrypt final Sphinx layer with identity private key
                            let _ = pkt;
                            let payload = b"(decryption pending — see sphinx.rs)".to_vec();
                            let _ = tx.send(payload).await;
                        }
                    }
                }
                Err(e) => warn!("Receive error: {e}"),
            }
        }
    });

    Ok(rx)
}
