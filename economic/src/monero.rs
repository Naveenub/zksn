//! Monero RPC interface for XMR settlement.
//!
//! Talks JSON-RPC 2.0 to a local `monero-wallet-rpc` daemon, following the
//! same client shape as `MintClient` in `mint.rs`: a `reqwest::Client` with
//! a bounded timeout, request/response structs per method, and RPC errors
//! mapped into `MoneroError` rather than swallowed.
use anyhow::Result;
use reqwest::Client;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MoneroError {
    #[error("RPC error: {0}")]
    Rpc(String),
    #[error("Insufficient funds")]
    InsufficientFunds,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoneroBalance {
    pub balance: u64,
    pub unlocked_balance: u64,
}

pub struct MoneroRpc {
    pub rpc_url: String,
    client: Client,
}

// ── JSON-RPC 2.0 envelope ───────────────────────────────────────────────────

#[derive(Serialize)]
struct JsonRpcRequest<'a, P: Serialize> {
    jsonrpc: &'a str,
    id: &'a str,
    method: &'a str,
    params: P,
}

#[derive(Deserialize)]
struct JsonRpcResponse<R> {
    #[serde(default)]
    result: Option<R>,
    #[serde(default)]
    error: Option<JsonRpcErrorBody>,
}

#[derive(Deserialize)]
struct JsonRpcErrorBody {
    code: i64,
    message: String,
}

impl MoneroRpc {
    pub fn new(rpc_url: String) -> Self {
        Self {
            rpc_url: rpc_url.trim_end_matches('/').to_string(),
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
        }
    }

    /// `POST /json_rpc` — issue one JSON-RPC call and unwrap `result`.
    ///
    /// RPC errors whose message mentions insufficient balance are mapped to
    /// `MoneroError::InsufficientFunds` (`monero-wallet-rpc` uses code -4,
    /// message "not enough money", for this case); all other failures
    /// (transport, non-2xx, malformed body, other RPC errors) become
    /// `MoneroError::Rpc`.
    async fn call<P: Serialize, R: DeserializeOwned>(
        &self,
        method: &str,
        params: P,
    ) -> Result<R, MoneroError> {
        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            id: "0",
            method,
            params,
        };

        let resp = self
            .client
            .post(format!("{}/json_rpc", self.rpc_url))
            .json(&req)
            .send()
            .await
            .map_err(|e| MoneroError::Rpc(format!("{method}: connection failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(MoneroError::Rpc(format!(
                "{method} → HTTP {}",
                resp.status()
            )));
        }

        let body: JsonRpcResponse<R> = resp
            .json()
            .await
            .map_err(|e| MoneroError::Rpc(format!("{method}: bad response body: {e}")))?;

        if let Some(err) = body.error {
            if err.message.to_lowercase().contains("not enough") {
                return Err(MoneroError::InsufficientFunds);
            }
            return Err(MoneroError::Rpc(format!(
                "{method} → RPC error {}: {}",
                err.code, err.message
            )));
        }

        body.result
            .ok_or_else(|| MoneroError::Rpc(format!("{method}: empty result")))
    }

    /// `get_balance` — account 0's total and unlocked balance, in piconero.
    pub async fn get_balance(&self) -> Result<MoneroBalance, MoneroError> {
        #[derive(Serialize)]
        struct Params {
            account_index: u32,
        }
        #[derive(Deserialize)]
        struct Res {
            balance: u64,
            unlocked_balance: u64,
        }
        let r: Res = self
            .call("get_balance", Params { account_index: 0 })
            .await?;
        Ok(MoneroBalance {
            balance: r.balance,
            unlocked_balance: r.unlocked_balance,
        })
    }

    /// `create_address` — mint a fresh subaddress on account 0.
    pub async fn new_subaddress(&self) -> Result<String, MoneroError> {
        #[derive(Serialize)]
        struct Params {
            account_index: u32,
        }
        #[derive(Deserialize)]
        struct Res {
            address: String,
        }
        let r: Res = self
            .call("create_address", Params { account_index: 0 })
            .await?;
        Ok(r.address)
    }

    /// `transfer` — send `amount_piconero` to `address`, requesting the tx
    /// key so the caller can later prove payment if needed.
    pub async fn transfer(
        &self,
        address: &str,
        amount_piconero: u64,
    ) -> Result<String, MoneroError> {
        #[derive(Serialize)]
        struct Destination {
            amount: u64,
            address: String,
        }
        #[derive(Serialize)]
        struct Params {
            destinations: Vec<Destination>,
            priority: u32,
            get_tx_key: bool,
        }
        #[derive(Deserialize)]
        struct Res {
            tx_hash: String,
        }
        let params = Params {
            destinations: vec![Destination {
                amount: amount_piconero,
                address: address.to_string(),
            }],
            priority: 0,
            get_tx_key: true,
        };
        let r: Res = self.call("transfer", params).await?;
        Ok(r.tx_hash)
    }
}

pub fn xmr_to_piconero(xmr: f64) -> u64 {
    (xmr * 1_000_000_000_000.0) as u64
}
pub fn piconero_to_xmr(p: u64) -> f64 {
    p as f64 / 1_000_000_000_000.0
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_xmr_conversion() {
        assert_eq!(xmr_to_piconero(1.0), 1_000_000_000_000);
        assert!((piconero_to_xmr(1_000_000_000_000) - 1.0).abs() < 1e-9);
    }

    // Port 1 is never listening — deterministic, fast connection-refused,
    // matching the pattern MintClient's own unreachable-mint tests use.
    #[tokio::test]
    async fn test_get_balance_unreachable_rpc() {
        let rpc = MoneroRpc::new("http://127.0.0.1:1".into());
        assert!(matches!(
            rpc.get_balance().await,
            Err(MoneroError::Rpc(_))
        ));
    }

    #[tokio::test]
    async fn test_new_subaddress_unreachable_rpc() {
        let rpc = MoneroRpc::new("http://127.0.0.1:1".into());
        assert!(matches!(
            rpc.new_subaddress().await,
            Err(MoneroError::Rpc(_))
        ));
    }

    #[tokio::test]
    async fn test_transfer_unreachable_rpc() {
        let rpc = MoneroRpc::new("http://127.0.0.1:1".into());
        assert!(matches!(
            rpc.transfer("some_address", 1_000).await,
            Err(MoneroError::Rpc(_))
        ));
    }

    #[test]
    fn test_rpc_url_trims_trailing_slash() {
        let rpc = MoneroRpc::new("http://127.0.0.1:18082/".into());
        assert_eq!(rpc.rpc_url, "http://127.0.0.1:18082");
    }
}
