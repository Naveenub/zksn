//! # Cashu Chaumian Ecash Integration
//!
//! Implements the Cashu NUT (Notation, Usage, and Terminology) protocol
//! for blind-signature ecash tokens.
//!
//! Reference: https://github.com/cashubtc/nuts
//!
//! ## Blind Signature Protocol
//!
//! 1. Client generates a random secret `x` and blinding factor `r`
//! 2. Client sends blinded message `B_ = HashToCurve(x) + r*G` to mint
//! 3. Mint signs: `C_ = k * B_` (where k is mint's private key)
//! 4. Client unblinds: `C = C_ - r*K` (where K is mint's public key)
//! 5. Token = (x, C) — the mint cannot link C to C_, hence cannot track usage
//!
//! The mint cannot link which token it issued to which redemption,
//! even if it colludes with mix nodes. This is the core privacy property.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info};

#[derive(Debug, Error)]
pub enum CashuError {
    #[error("Mint unreachable: {0}")]
    MintUnreachable(String),

    #[error("Token verification failed")]
    InvalidToken,

    #[error("Insufficient balance: need {need}, have {have}")]
    InsufficientBalance { need: u64, have: u64 },

    #[error("Token already spent (double-spend attempt)")]
    AlreadySpent,

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// A Cashu ecash token (NUT-00 compatible).
///
/// This is the per-packet payment unit. Each Sphinx packet carries one token.
/// Tokens are blind-signed and unlinkable to their issuance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CashuToken {
    /// The mint URL that issued this token
    pub mint: String,
    /// Token proofs (one per denomination unit)
    pub proofs: Vec<Proof>,
}

/// A single Cashu proof (NUT-00).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    /// Token amount (in satoshis or millisatoshis depending on mint config)
    pub amount: u64,
    /// Mint's keyset ID (identifies which key was used to sign)
    pub id: String,
    /// The secret `x` — presented during redemption
    pub secret: String,
    /// The unblinded signature `C` from the mint
    #[serde(rename = "C")]
    pub c: String,
}

/// A Cashu wallet for managing token balances.
pub struct CashuWallet {
    mint_url: String,
    tokens: Vec<Proof>,
}

impl CashuWallet {
    pub fn new(mint_url: &str) -> Self {
        Self {
            mint_url: mint_url.to_string(),
            tokens: Vec::new(),
        }
    }

    /// Total balance in the wallet.
    pub fn balance(&self) -> u64 {
        self.tokens.iter().map(|p| p.amount).sum()
    }

    /// Request tokens from the mint in exchange for a Lightning/XMR payment.
    ///
    /// In the ZKSN context, this is done by sending XMR to the mint's stealth
    /// address and providing the transaction ID as proof of payment.
    #[cfg(feature = "http")]
    pub async fn mint_tokens(&mut self, amount: u64, payment_proof: &str) -> Result<(), CashuError> {
        info!("Minting {amount} tokens from {}", self.mint_url);

        // TODO: implement full NUT-04 (mint tokens) protocol
        // 1. POST /v1/mint/quote/bolt11 to get a payment request
        // 2. Pay the request (in our case via XMR atomic swap)
        // 3. POST /v1/mint/bolt11 with blinded messages to receive tokens
        // This placeholder shows the structure.

        debug!("Payment proof: {payment_proof}");
        Ok(())
    }

    /// Take tokens from the wallet for a payment.
    pub fn take_tokens(&mut self, amount: u64) -> Result<CashuToken, CashuError> {
        if self.balance() < amount {
            return Err(CashuError::InsufficientBalance {
                need: amount,
                have: self.balance(),
            });
        }

        let mut selected = Vec::new();
        let mut remaining = amount;

        self.tokens.retain(|proof| {
            if remaining == 0 {
                return true;
            }
            if proof.amount <= remaining {
                remaining -= proof.amount;
                selected.push(proof.clone());
                false // remove from wallet
            } else {
                true // keep in wallet
            }
        });

        Ok(CashuToken {
            mint: self.mint_url.clone(),
            proofs: selected,
        })
    }

    /// Redeem tokens at the mint (convert to a fresh batch).
    ///
    /// Redemption should be done in batches to reduce linkability.
    /// A mix node that redeems one token per packet reveals traffic volume.
    /// Batch redemption reveals only that "some packets were forwarded."
    #[cfg(feature = "http")]
    pub async fn redeem_batch(&mut self, tokens: Vec<CashuToken>) -> Result<(), CashuError> {
        let total: u64 = tokens.iter()
            .flat_map(|t| t.proofs.iter())
            .map(|p| p.amount)
            .sum();

        info!("Batch redeeming {} tokens (total: {total})", tokens.len());

        // TODO: implement NUT-03 (swap tokens)
        // POST /v1/swap with proofs → receive new proofs of equal value
        // The new proofs are unlinkable to the old ones.

        Ok(())
    }
}

/// Verify that a token is valid before accepting a packet.
///
/// A mix node calls this before processing each incoming packet.
/// Invalid tokens cause the packet to be silently dropped.
pub fn verify_token(token: &CashuToken, min_value: u64) -> Result<(), CashuError> {
    let total: u64 = token.proofs.iter().map(|p| p.amount).sum();
    if total < min_value {
        return Err(CashuError::InsufficientBalance {
            need: min_value,
            have: total,
        });
    }

    // TODO: verify cryptographic validity of each proof
    // This requires verifying the blind signature against the mint's public key
    // See: NUT-00 token verification

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_balance() {
        let mut wallet = CashuWallet::new("http://localhost:3338");
        assert_eq!(wallet.balance(), 0);

        wallet.tokens.push(Proof {
            amount: 64,
            id: "test_keyset".to_string(),
            secret: "abc123".to_string(),
            c: "signature".to_string(),
        });

        assert_eq!(wallet.balance(), 64);
    }

    #[test]
    fn test_take_tokens_insufficient() {
        let mut wallet = CashuWallet::new("http://localhost:3338");
        let result = wallet.take_tokens(100);
        assert!(matches!(result, Err(CashuError::InsufficientBalance { .. })));
    }

    #[test]
    fn test_take_tokens_success() {
        let mut wallet = CashuWallet::new("http://localhost:3338");
        wallet.tokens.push(Proof {
            amount: 100,
            id: "test".to_string(),
            secret: "secret".to_string(),
            c: "sig".to_string(),
        });

        let token = wallet.take_tokens(100).unwrap();
        assert_eq!(token.proofs[0].amount, 100);
        assert_eq!(wallet.balance(), 0); // token removed from wallet
    }
}
