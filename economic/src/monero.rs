//! Monero RPC interface for XMR settlement.
use anyhow::Result;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MoneroError {
    #[error("RPC error: {0}")] Rpc(String),
    #[error("Insufficient funds")]  InsufficientFunds,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoneroBalance { pub balance: u64, pub unlocked_balance: u64 }

pub struct MoneroRpc { pub rpc_url: String }

impl MoneroRpc {
    pub fn new(rpc_url: String) -> Self { Self { rpc_url } }

    pub async fn get_balance(&self) -> Result<MoneroBalance, MoneroError> {
        // TODO: implement via reqwest HTTP call to monero-wallet-rpc
        Ok(MoneroBalance { balance: 0, unlocked_balance: 0 })
    }

    pub async fn new_subaddress(&self) -> Result<String, MoneroError> {
        // TODO: implement via reqwest
        Ok("placeholder_xmr_address".to_string())
    }

    pub async fn transfer(&self, address: &str, amount_piconero: u64) -> Result<String, MoneroError> {
        // TODO: implement via reqwest
        let _ = (address, amount_piconero);
        Ok("placeholder_tx_id".to_string())
    }
}

pub fn xmr_to_piconero(xmr: f64) -> u64 { (xmr * 1_000_000_000_000.0) as u64 }
pub fn piconero_to_xmr(p: u64) -> f64 { p as f64 / 1_000_000_000_000.0 }

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn test_xmr_conversion() {
        assert_eq!(xmr_to_piconero(1.0), 1_000_000_000_000);
        assert!((piconero_to_xmr(1_000_000_000_000) - 1.0).abs() < 1e-9);
    }
    #[tokio::test] async fn test_get_balance_stub() {
        let rpc = MoneroRpc::new("http://127.0.0.1:18082".into());
        let bal = rpc.get_balance().await.unwrap();
        assert_eq!(bal.balance, 0);
    }
}
