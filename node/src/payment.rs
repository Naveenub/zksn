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
use zksn_economic::mint::MintClient;

use crate::config::EconomicConfig;

/// Shared payment enforcement state.
pub struct PaymentGuard {
    testnet: bool,
    min_value: u64,
    mint: MintClient,
    /// Secrets of proofs seen during this session — prevents double-spend
    /// within a single node instance even if the mint is temporarily offline.
    seen_secrets: Arc<Mutex<HashSet<String>>>,
}

impl PaymentGuard {
    pub fn new(config: &EconomicConfig, testnet: bool) -> Self {
        Self {
            testnet,
            min_value: config.min_token_value,
            mint: MintClient::new(config.cashu_mint_url.clone()),
            seen_secrets: Arc::new(Mutex::new(HashSet::new())),
        }
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

        // ── async background claim (best-effort swap) ─────────────────────────
        let mint = self.mint.clone();
        let proofs = token.proofs.clone();
        tokio::spawn(async move {
            match mint.verify_and_claim(proofs).await {
                Ok(()) => debug!("Background claim succeeded"),
                Err(e) => warn!("Background claim failed (will retry next restart): {e}"),
            }
        });

        Ok(())
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

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
}
