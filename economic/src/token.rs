use crate::cashu::CashuToken;
use serde::{Deserialize, Serialize};

/// A Cashu payment token attached to a Sphinx packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketToken {
    pub token: CashuToken,
    pub amount: u64,
}

impl PacketToken {
    pub fn new(token: CashuToken, amount: u64) -> Self {
        Self { token, amount }
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cashu::{CashuToken, Proof};
    #[test]
    fn test_packet_token_roundtrip() {
        let token = CashuToken {
            mint: "http://mint.test".into(),
            proofs: vec![Proof {
                amount: 10,
                id: "test_id".into(),
                secret: "secret".into(),
                c: "sig".into(),
            }],
        };
        let pt = PacketToken::new(token, 10);
        let bytes = pt.to_bytes();
        let restored = PacketToken::from_bytes(&bytes).unwrap();
        assert_eq!(restored.amount, 10);
    }
}
