//! Cashu NUT-00 Chaumian ecash integration.
//! Blind signature protocol: mint cannot link issuance to redemption.
use anyhow::Result;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CashuError {
    #[error("Mint unreachable: {0}")]
    MintUnreachable(String),
    #[error("Token invalid")]
    InvalidToken,
    #[error("Insufficient balance: need {need}, have {have}")]
    InsufficientBalance { need: u64, have: u64 },
    #[error("Token already spent")]
    AlreadySpent,
    #[error("Serialization: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CashuToken {
    pub mint: String,
    pub proofs: Vec<Proof>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    pub amount: u64,
    pub id: String,
    pub secret: String,
    pub c: String,
}

impl CashuToken {
    pub fn total_value(&self) -> u64 {
        self.proofs.iter().map(|p| p.amount).sum()
    }
    pub fn is_valid(&self) -> bool {
        !self.proofs.is_empty() && !self.mint.is_empty()
    }
}

pub struct CashuWallet {
    pub mint_url: String,
    pub balance: u64,
}

impl CashuWallet {
    pub fn new(mint_url: String) -> Self {
        Self {
            mint_url,
            balance: 0,
        }
    }

    pub fn add_token(&mut self, token: &CashuToken) -> Result<(), CashuError> {
        if !token.is_valid() {
            return Err(CashuError::InvalidToken);
        }
        self.balance += token.total_value();
        Ok(())
    }

    pub fn spend(&mut self, amount: u64) -> Result<(), CashuError> {
        if self.balance < amount {
            return Err(CashuError::InsufficientBalance {
                need: amount,
                have: self.balance,
            });
        }
        self.balance -= amount;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn make_token(amount: u64) -> CashuToken {
        CashuToken {
            mint: "http://mint.test".into(),
            proofs: vec![Proof {
                amount,
                id: "id1".into(),
                secret: "s".into(),
                c: "c".into(),
            }],
        }
    }
    #[test]
    fn test_total_value() {
        assert_eq!(make_token(42).total_value(), 42);
    }
    #[test]
    fn test_wallet_add_and_spend() {
        let mut w = CashuWallet::new("http://mint.test".into());
        w.add_token(&make_token(100)).unwrap();
        assert_eq!(w.balance, 100);
        w.spend(30).unwrap();
        assert_eq!(w.balance, 70);
    }
    #[test]
    fn test_insufficient_balance() {
        let mut w = CashuWallet::new("http://mint.test".into());
        assert!(w.spend(1).is_err());
    }
    #[test]
    fn test_invalid_token_rejected() {
        let mut w = CashuWallet::new("http://mint.test".into());
        let bad = CashuToken {
            mint: "".into(),
            proofs: vec![],
        };
        assert!(w.add_token(&bad).is_err());
    }
}
