//! # Monero (XMR) Integration
//!
//! Provides an interface to the Monero RPC daemon for:
//! - Checking wallet balance
//! - Creating transactions (node-to-node settlement)
//! - Verifying incoming payments (for Cashu mint top-up)
//!
//! All Monero transactions use:
//! - **Stealth addresses**: recipient address changes per transaction
//! - **RingCT**: amount is hidden from all observers
//! - **Ring signatures**: sender is hidden among a ring of decoys
//!
//! Reference: https://www.getmonero.org/resources/developer-guides/wallet-rpc.html

use anyhow::Result;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MoneroError {
    #[error("RPC connection failed: {0}")]
    RpcError(String),

    #[error("Insufficient balance: need {need} XMR, have {have} XMR")]
    InsufficientFunds { need: f64, have: f64 },

    #[error("Transaction failed: {0}")]
    TransactionFailed(String),

    #[error("Invalid address")]
    InvalidAddress,
}

/// Configuration for the Monero RPC connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoneroConfig {
    /// Monero wallet RPC URL (e.g., http://127.0.0.1:18082)
    pub rpc_url: String,
    /// RPC username (if configured)
    pub rpc_user: Option<String>,
    /// RPC password (if configured)  
    pub rpc_password: Option<String>,
}

impl Default for MoneroConfig {
    fn default() -> Self {
        Self {
            rpc_url: "http://127.0.0.1:18082".to_string(),
            rpc_user: None,
            rpc_password: None,
        }
    }
}

/// A Monero wallet client (via RPC).
pub struct MoneroWallet {
    config: MoneroConfig,
}

impl MoneroWallet {
    pub fn new(config: MoneroConfig) -> Self {
        Self { config }
    }

    /// Get the current wallet balance in XMR (unlocked balance).
    #[cfg(feature = "http")]
    pub async fn balance(&self) -> Result<f64, MoneroError> {
        // Monero RPC: get_balance
        // POST /json_rpc {"method": "get_balance", "params": {"account_index": 0}}
        // Returns: {"balance": <piconeros>, "unlocked_balance": <piconeros>}
        // 1 XMR = 1_000_000_000_000 piconeros

        // TODO: implement via reqwest
        Ok(0.0)
    }

    /// Generate a new stealth (subaddress) for receiving funds.
    ///
    /// Each payment should use a fresh subaddress to prevent linkability.
    /// Monero subaddresses are derived from the wallet's view key and
    /// are cryptographically unlinkable to each other from outside.
    #[cfg(feature = "http")]
    pub async fn new_subaddress(&self, label: &str) -> Result<String, MoneroError> {
        // Monero RPC: create_address
        // POST /json_rpc {"method": "create_address", "params": {"account_index": 0, "label": label}}
        // Returns: {"address": "<subaddress>", "address_index": <index>}

        // TODO: implement via reqwest
        Ok("placeholder_xmr_address".to_string())
    }

    /// Send XMR to a destination address (node-to-node settlement).
    ///
    /// Uses the highest available ring size for maximum privacy.
    /// Amount is always in piconeros (1 XMR = 10^12 piconeros).
    #[cfg(feature = "http")]
    pub async fn transfer(
        &self,
        destination: &str,
        amount_xmr: f64,
    ) -> Result<String, MoneroError> {
        let amount_piconero = (amount_xmr * 1_000_000_000_000.0) as u64;

        // Monero RPC: transfer
        // POST /json_rpc {
        //   "method": "transfer",
        //   "params": {
        //     "destinations": [{"amount": amount_piconero, "address": destination}],
        //     "ring_size": 16,
        //     "get_tx_key": true
        //   }
        // }

        // TODO: implement via reqwest
        tracing::info!(
            "Transferring {} XMR ({} piconero) to {}",
            amount_xmr,
            amount_piconero,
            &destination[..8]  // Only log first 8 chars of address
        );

        Ok("placeholder_tx_id".to_string())
    }
}

/// Convert piconeros to XMR (human-readable).
pub fn piconero_to_xmr(piconeros: u64) -> f64 {
    piconeros as f64 / 1_000_000_000_000.0
}

/// Convert XMR to piconeros.
pub fn xmr_to_piconero(xmr: f64) -> u64 {
    (xmr * 1_000_000_000_000.0) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xmr_conversion() {
        assert_eq!(xmr_to_piconero(1.0), 1_000_000_000_000);
        assert_eq!(xmr_to_piconero(0.5), 500_000_000_000);
        assert!((piconero_to_xmr(1_000_000_000_000) - 1.0).abs() < f64::EPSILON);
    }
}
