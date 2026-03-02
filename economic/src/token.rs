//! # Per-Packet Payment Token
//!
//! Defines how Cashu tokens are attached to Sphinx packets.
//! Each Sphinx packet carries exactly one token payload alongside it.
//!
//! The token is validated by the mix node BEFORE processing the packet.
//! Invalid or missing tokens cause the packet to be silently dropped —
//! no error response is sent (to avoid oracle attacks).

use serde::{Deserialize, Serialize};
use crate::cashu::CashuToken;

/// A payment token attached to a Sphinx packet.
///
/// Serialized and prepended to the Sphinx packet wire format.
/// The mix node reads and validates this before touching the Sphinx header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketToken {
    /// The Cashu token (blind-signed, unlinkable)
    pub token: CashuToken,
    /// Protocol version for forward compatibility
    pub version: u8,
}

impl PacketToken {
    pub fn new(token: CashuToken) -> Self {
        Self { token, version: 1 }
    }

    /// Serialize to bytes for wire transmission.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Deserialize from wire bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }

    /// Total token value in this payment.
    pub fn value(&self) -> u64 {
        self.token.proofs.iter().map(|p| p.amount).sum()
    }
}
