//! # ZKSN Economic Layer
//!
//! Two-tier payment system for anonymous per-packet billing:
//!
//! ## Tier 1 — Cashu (Chaumian Ecash) — Micropayments
//!
//! Cashu implements David Chaum's blind signature scheme.
//! Tokens are issued by a mint and cannot be linked to their issuance event
//! even by the mint operator. This provides unconditional payment privacy.
//!
//! Flow:
//! ```text
//! User → [deposit XMR] → Mint
//! Mint → [blind-sign tokens] → User
//! User → [attach token to each Sphinx packet] → Mix node
//! Mix node → [batch-redeem tokens] → Mint
//! Mint → [settle in XMR] → Mix node
//! ```
//!
//! ## Tier 2 — Monero (XMR) — Settlement
//!
//! Monero provides mandatory protocol-level transaction privacy:
//! - Stealth addresses: one-time recipient addresses
//! - RingCT: confidential transaction amounts
//! - Ring signatures: ambiguous sender set
//!
//! All settlement between nodes happens in XMR.

pub mod cashu;
pub mod monero;
pub mod token;
