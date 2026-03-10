//! Per-packet payment enforcement.
//!
//! `PaymentGuard` sits in the hot path of `handle_conn`.  Every incoming
//! `PaymentEnvelope` frame is checked here before the Sphinx layer is peeled.
//!
//! ## Enforcement model
//!
//! 1. **Local double-spend prevention** — a `HashSet` of proof secrets seen
//!    during this node's lifetime.  Proofs already in the set are rejected
//!    immediately, without contacting the mint.
//!
//! 2. **Mint verification** — `POST /v1/checkstate` asks the mint whether each
//!    proof is UNSPENT.  If the mint is unreachable the node falls back to
//!    local-only enforcement and warns.
//!
//! 3. **Async claim** — after accepting the packet, a background task calls
//!    `MintClient::verify_and_claim` (checkstate + swap) to atomically mark
//!    proofs as SPENT.  The swap is best-effort; a failed swap is logged but
//!    does not retro-actively reject the packet.
//!
//! ## Testnet mode
//!
//! When `testnet = true` all verification is skipped and `check` always returns
//! `Ok(())`.  This is the right behaviour for a development network where no
//! real mint is running.

use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, warn};
use zksn_economic::cashu::{CashuError, CashuToken};
use zksn_economic::mint::{MintClient, NodeWallet};

use crate::config::EconomicConfig;

/// Shared payment enforcement state.
pub struct PaymentGuard {
    testnet: bool,
    min_value: u64,
    mint: MintClient,
    /// Secrets of proofs seen during this session — prevents double-spend
    /// within a single node instance even if the mint is temporarily offline.
    seen_secrets: Arc<Mutex<HashSet<String>>>,
    /// Persistent wallet — accumulates earned proofs from successful swaps.
    wallet: NodeWallet,
}

impl PaymentGuard {
    pub fn new(config: &EconomicConfig, testnet: bool) -> Self {
        let wallet = if let Some(ref path) = config.wallet_store_path {
            NodeWallet::new_persistent(path)
        } else {
            NodeWallet::new_in_memory()
        };
        Self {
            testnet,
            min_value: config.min_token_value,
            mint: MintClient::new(config.cashu_mint_url.clone()),
            seen_secrets: Arc::new(Mutex::new(HashSet::new())),
            wallet,
        }
    }

    /// Current node wallet balance in satoshis.
    pub fn balance(&self) -> u64 {
        self.wallet.balance()
    }

    /// Verify `token` and claim its proofs.
    ///
    /// Returns `Ok(())` if the payment is acceptable and the packet should be
    /// forwarded.  Returns `Err` if the payment must be rejected.
    ///
    /// In testnet mode this is a no-op and always succeeds.
    pub async fn check(&self, token: &CashuToken) -> Result<(), CashuError> {
        if self.testnet {
            debug!("testnet: payment check skipped");
            return Ok(());
        }

        // ── structure check (before value so InvalidToken fires first) ───────
        if !token.is_valid() {
            return Err(CashuError::InvalidToken);
        }

        // ── value check ───────────────────────────────────────────────────────
        let total = token.total_value();
        if total < self.min_value {
            return Err(CashuError::InsufficientBalance {
                need: self.min_value,
                have: total,
            });
        }

        // ── local double-spend prevention ─────────────────────────────────────
        let secrets: Vec<String> = token.proofs.iter().map(|p| p.secret.clone()).collect();
        {
            let seen = self.seen_secrets.lock().await;
            for s in &secrets {
                if seen.contains(s) {
                    warn!("Double-spend attempt: proof secret already seen");
                    return Err(CashuError::AlreadySpent);
                }
            }
        }

        // ── mint check_state (best-effort) ────────────────────────────────────
        match self.mint.check_state(&token.proofs).await {
            Ok(states) => {
                use zksn_economic::mint::ProofState;
                for entry in &states {
                    if entry.state != ProofState::Unspent {
                        warn!("Proof {} is {:?} at mint", entry.y, entry.state);
                        return Err(CashuError::AlreadySpent);
                    }
                }
                debug!("Mint confirmed {} proofs UNSPENT", states.len());
            }
            Err(CashuError::MintUnreachable(ref e)) => {
                warn!("Mint unreachable ({e}) — accepting on local check only");
                // Fall through: local seen-secrets is the only guard
            }
            Err(e) => return Err(e),
        }

        // ── record secrets locally ────────────────────────────────────────────
        {
            let mut seen = self.seen_secrets.lock().await;
            for s in secrets {
                seen.insert(s);
            }
        }

        // ── async background claim (best-effort swap + unblinding) ────────────
        let mint = self.mint.clone();
        let proofs = token.proofs.clone();
        let wallet = self.wallet.clone();
        tokio::spawn(async move {
            match mint.verify_and_claim(proofs, &wallet).await {
                Ok(sats) => debug!("Background claim succeeded: {sats} sats earned"),
                Err(e) => warn!("Background claim failed (will retry next restart): {e}"),
            }
        });

        Ok(())
    }
}

// ── MeltManager ───────────────────────────────────────────────────────────────

/// Threshold-triggered Lightning withdrawal manager.
///
/// `MeltManager` runs as a background task alongside the mix node.  It polls
/// the `NodeWallet` balance and fires `POST /v1/melt` (NUT-05) whenever the
/// balance crosses `threshold_sats`.
///
/// ## Usage
///
/// ```rust,ignore
/// let melt_mgr = MeltManager::new(
///     mint_client.clone(),
///     wallet.clone(),
///     500,                         // fire melt when wallet ≥ 500 sats
///     "lnbc500...".to_string(),    // operator's withdrawal invoice
///     Duration::from_secs(60),     // poll interval
/// );
/// tokio::spawn(melt_mgr.run());
/// ```
///
/// In production the invoice should be replaced with a callback or a fresh
/// BOLT-11 per melt cycle (static invoices have amount limits).  A single
/// static invoice is sufficient for development and testing.
pub struct MeltManager {
    mint: MintClient,
    wallet: NodeWallet,
    /// Wallet balance (sats) that triggers a melt attempt.
    threshold_sats: u64,
    /// BOLT-11 invoice to pay on each melt.
    invoice: String,
    /// How often to check the wallet balance.
    poll_interval: std::time::Duration,
}

impl MeltManager {
    pub fn new(
        mint: MintClient,
        wallet: NodeWallet,
        threshold_sats: u64,
        invoice: String,
        poll_interval: std::time::Duration,
    ) -> Self {
        Self {
            mint,
            wallet,
            threshold_sats,
            invoice,
            poll_interval,
        }
    }

    /// Run the melt loop.  Call via `tokio::spawn(melt_mgr.run())`.
    ///
    /// Loops forever — designed to run for the lifetime of the node process.
    /// Exits only if the tokio runtime shuts down.
    pub async fn run(self) {
        use tracing::info;
        info!(
            "MeltManager started: threshold={} sats, poll={:?}",
            self.threshold_sats, self.poll_interval
        );

        loop {
            tokio::time::sleep(self.poll_interval).await;

            let balance = self.wallet.balance();
            if balance < self.threshold_sats {
                debug!("MeltManager: balance {balance} sats below threshold — waiting");
                continue;
            }

            info!(
                "MeltManager: balance {balance} sats ≥ threshold {} — initiating melt",
                self.threshold_sats
            );

            match self.mint.melt_wallet(&self.wallet, &self.invoice).await {
                Ok(result) => {
                    info!(
                        "MeltManager: melt succeeded — {} sats withdrawn, {} proofs spent, preimage={}",
                        result.total_sats, result.proofs_spent, result.payment_preimage
                    );
                }
                Err(CashuError::InsufficientBalance { need, have }) => {
                    warn!(
                        "MeltManager: insufficient balance for melt (need {need}, have {have}) — waiting"
                    );
                }
                Err(CashuError::MintUnreachable(ref e)) => {
                    warn!("MeltManager: mint unreachable ({e}) — will retry next poll");
                }
                Err(e) => {
                    warn!("MeltManager: melt failed ({e}) — will retry next poll");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zksn_economic::cashu::{CashuToken, Proof};

    fn make_config() -> EconomicConfig {
        EconomicConfig {
            cashu_mint_url: "http://127.0.0.1:1".to_string(), // unreachable
            min_token_value: 1,
            monero_rpc_url: "http://127.0.0.1:18082".to_string(),
            redemption_batch_size: 50,
            wallet_store_path: None,
        }
    }

    fn make_token(amount: u64, secret: &str) -> CashuToken {
        CashuToken {
            mint: "http://127.0.0.1:1".into(),
            proofs: vec![Proof {
                amount,
                id: "id1".into(),
                secret: secret.into(),
                c: "c".into(),
            }],
        }
    }

    #[tokio::test]
    async fn test_testnet_always_passes() {
        let guard = PaymentGuard::new(&make_config(), true);
        // Even an invalid token passes in testnet mode
        let bad = CashuToken {
            mint: "".into(),
            proofs: vec![],
        };
        assert!(guard.check(&bad).await.is_ok());
    }

    #[tokio::test]
    async fn test_invalid_token_rejected() {
        let guard = PaymentGuard::new(&make_config(), false);
        let bad = CashuToken {
            mint: "".into(),
            proofs: vec![],
        };
        assert!(matches!(
            guard.check(&bad).await,
            Err(CashuError::InvalidToken)
        ));
    }

    #[tokio::test]
    async fn test_insufficient_value_rejected() {
        let mut cfg = make_config();
        cfg.min_token_value = 100;
        let guard = PaymentGuard::new(&cfg, false);
        let token = make_token(1, "secret_low");
        assert!(matches!(
            guard.check(&token).await,
            Err(CashuError::InsufficientBalance { .. })
        ));
    }

    #[tokio::test]
    async fn test_double_spend_rejected() {
        let guard = PaymentGuard::new(&make_config(), false);
        let token = make_token(10, "secret_abc");

        // First submission: mint unreachable → local-only check passes
        assert!(guard.check(&token).await.is_ok());

        // Second submission: same secret → local double-spend detection
        assert!(matches!(
            guard.check(&token).await,
            Err(CashuError::AlreadySpent)
        ));
    }

    #[tokio::test]
    async fn test_different_secrets_both_accepted() {
        let guard = PaymentGuard::new(&make_config(), false);
        assert!(guard.check(&make_token(10, "secret_1")).await.is_ok());
        assert!(guard.check(&make_token(10, "secret_2")).await.is_ok());
    }

    #[tokio::test]
    async fn test_mint_unreachable_falls_back_to_local() {
        // Mint at port 1 — guaranteed unreachable
        let guard = PaymentGuard::new(&make_config(), false);
        let token = make_token(5, "secret_fallback");
        // Should succeed: local check passes, mint unreachable → best-effort
        assert!(guard.check(&token).await.is_ok());
    }

    // ── MeltManager ───────────────────────────────────────────────────────────

    #[test]
    fn test_melt_manager_constructs() {
        use std::time::Duration;
        use zksn_economic::mint::{MintClient, NodeWallet};
        let m = MeltManager::new(
            MintClient::new("http://127.0.0.1:1".into()),
            NodeWallet::new_in_memory(),
            500,
            "lnbc500...".into(),
            Duration::from_secs(60),
        );
        assert_eq!(m.threshold_sats, 500);
        assert_eq!(m.invoice, "lnbc500...");
    }

    /// Verify that `MeltManager::run` does NOT drain the wallet when balance
    /// is below threshold.  Run for one poll tick then abort.
    #[tokio::test]
    async fn test_melt_manager_below_threshold_no_drain() {
        use std::time::Duration;
        use zksn_economic::cashu::Proof;
        use zksn_economic::mint::{MintClient, NodeWallet};

        let wallet = NodeWallet::new_in_memory();
        wallet.credit(vec![Proof {
            amount: 10,
            id: "id".into(),
            secret: "s".into(),
            c: "c".into(),
        }]);

        let mgr = MeltManager::new(
            MintClient::new("http://127.0.0.1:1".into()),
            wallet.clone(),
            500, // threshold: 500 sats — wallet has only 10
            "lnbc500...".into(),
            Duration::from_millis(10), // fast poll for test
        );

        // Run for one tick — balance (10) < threshold (500) so no drain fires
        tokio::select! {
            _ = mgr.run() => {}
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }

        // Wallet untouched
        assert_eq!(wallet.balance(), 10);
    }
}
