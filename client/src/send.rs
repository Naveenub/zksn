use anyhow::Result;
use tracing::info;
use zksn_crypto::identity::ZksnIdentity;
use zksn_crypto::sphinx::build_packet;
use crate::config::ClientConfig;
use crate::route::select_route;

pub async fn send_message(
    identity:      &ZksnIdentity,
    recipient_hex: &str,
    payload:       &[u8],
    config:        &ClientConfig,
) -> Result<()> {
    let _ = recipient_hex;
    let route = select_route(config.hop_count);
    let pkt = build_packet(&route, payload, &mut rand::thread_rng())?;
    let _ = (identity, pkt);
    // TODO: attach Cashu token + transmit over Yggdrasil TCP to entry node
    info!("Message queued for sending ({} bytes, {} hops)", payload.len(), config.hop_count);
    Ok(())
}
