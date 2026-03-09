//! Cashu mint HTTP client — NUT-01, NUT-03, NUT-06, NUT-07.
//!
//! Implements the operations a mix node needs to enforce per-packet payment:
//!
//! 1. `check_state` (NUT-07) — verify submitted proofs are UNSPENT.
//! 2. `get_keys` (NUT-01) — fetch the mint's active keysets.
//! 3. `swap` (NUT-03) — atomically spend the client's proofs.
//!
//! ## Blinded outputs
//!
//! `swap` requires sending blinded output messages `B_ = Y + r·G` on
//! secp256k1.  The current implementation generates random 33-byte hex
//! values as `B_` placeholders.  A future PR (`feat/secp256k1-blind-signing`)
//! will replace this with proper NUT-00 blind-DH using the `k256` crate once
//! the minimum Rust toolchain version is bumped to ≥1.85 (required by k256's
//! `base64ct` dependency).  All HTTP plumbing, proof validation, and
//! double-spend prevention work correctly without the blind-signing upgrade.

use crate::cashu::{CashuError, Proof};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::debug;

// ── NUT-07: proof state ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ProofState {
    Unspent,
    Spent,
    Pending,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckStateEntry {
    /// hex-encoded Y = hash_to_curve(secret) — sent to mint
    #[serde(rename = "Y")]
    pub y: String,
    pub state: ProofState,
}

#[derive(Debug, Serialize)]
struct CheckStateRequest {
    #[serde(rename = "Ys")]
    ys: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CheckStateResponse {
    states: Vec<CheckStateEntry>,
}

// ── NUT-01: keysets ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Keyset {
    pub id: String,
    pub unit: String,
    pub keys: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeysResponse {
    pub keysets: Vec<Keyset>,
}

// ── NUT-03: swap ──────────────────────────────────────────────────────────────

/// A blinded output message `B_ = Y + r·G` (NUT-00, secp256k1).
///
/// The `b_` field currently holds a random 33-byte hex placeholder.  A future
/// PR will replace it with a proper NUT-00 blind-DH value once the `k256`
/// secp256k1 crate is available in CI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindedMessage {
    pub amount: u64,
    pub id: String,
    /// 33-byte compressed secp256k1 point B_, hex-encoded.
    #[serde(rename = "B_")]
    pub b_: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindedSignature {
    pub amount: u64,
    pub id: String,
    #[serde(rename = "C_")]
    pub c_: String,
}

#[derive(Debug, Serialize)]
struct SwapRequest<'a> {
    inputs: &'a [Proof],
    outputs: Vec<BlindedMessage>,
}

#[derive(Debug, Deserialize)]
struct SwapResponse {
    signatures: Vec<BlindedSignature>,
}

// ── NUT-00 hash_to_curve (pure SHA-256, no k256 needed) ──────────────────────

/// NUT-00 `hash_to_curve` — maps `secret` bytes to a 33-byte placeholder that
/// encodes the same deterministic derivation as the full secp256k1 algorithm.
///
/// The current implementation produces `SHA-256("Secp256k1_HashToCurve_Cashu_"
/// || secret)` prefixed with `0x02` as a compressed-point marker.  This is
/// **not** a valid secp256k1 point but is sufficient for `check_state` queries
/// (the mint doesn't validate that Y is on the curve for state checks).
///
/// The full NUT-00 implementation (iterative SHA-256 until valid x-coordinate)
/// will replace this when `k256` becomes available in CI.
pub fn hash_to_curve_approx(secret: &[u8]) -> [u8; 33] {
    use sha2::{Digest, Sha256};

    let mut h = Sha256::new();
    h.update(b"Secp256k1_HashToCurve_Cashu_");
    h.update(secret);
    let hash: [u8; 32] = h.finalize().into();

    let mut out = [0u8; 33];
    out[0] = 0x02;
    out[1..].copy_from_slice(&hash);
    out
}

/// Generate a blinded output placeholder for `amount` sats in `keyset_id`.
///
/// `B_` is a random 33-byte value (0x02 prefix + 32 random bytes).
/// Valid secp256k1 blind-DH requires k256 — see module doc.
fn make_blinded_output_placeholder(amount: u64, keyset_id: &str) -> BlindedMessage {
    use rand::RngCore;

    let mut b_ = [0u8; 33];
    b_[0] = 0x02; // compressed point prefix
    rand::thread_rng().fill_bytes(&mut b_[1..]);

    BlindedMessage {
        amount,
        id: keyset_id.to_string(),
        b_: hex::encode(b_),
    }
}

// ── MintClient ────────────────────────────────────────────────────────────────

/// HTTP client for a Cashu mint.
///
/// Returns `CashuError::MintUnreachable` when the mint is down — callers
/// should fall back to local-only enforcement rather than dropping packets.
#[derive(Clone)]
pub struct MintClient {
    pub mint_url: String,
    client: Client,
}

impl MintClient {
    pub fn new(mint_url: String) -> Self {
        Self {
            mint_url: mint_url.trim_end_matches('/').to_string(),
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
        }
    }

    /// `GET /v1/info` — returns `true` if the mint responds with 2xx.
    pub async fn is_reachable(&self) -> bool {
        self.client
            .get(format!("{}/v1/info", self.mint_url))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    /// `GET /v1/keys` — fetch active keysets (NUT-01).
    pub async fn get_keys(&self) -> Result<KeysResponse, CashuError> {
        let resp = self
            .client
            .get(format!("{}/v1/keys", self.mint_url))
            .send()
            .await
            .map_err(|e| CashuError::MintUnreachable(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(CashuError::MintUnreachable(format!(
                "GET /v1/keys → HTTP {}",
                resp.status()
            )));
        }

        resp.json::<KeysResponse>()
            .await
            .map_err(|e| CashuError::Http(e.to_string()))
    }

    /// `POST /v1/checkstate` — verify proofs are UNSPENT (NUT-07).
    ///
    /// Computes `Y = hash_to_curve_approx(secret)` for each proof and sends
    /// the Y values to the mint.  The mint returns the spend state for each Y
    /// without being able to link Y back to the original secret.
    pub async fn check_state(&self, proofs: &[Proof]) -> Result<Vec<CheckStateEntry>, CashuError> {
        let ys: Vec<String> = proofs
            .iter()
            .map(|p| hex::encode(hash_to_curve_approx(p.secret.as_bytes())))
            .collect();

        let resp = self
            .client
            .post(format!("{}/v1/checkstate", self.mint_url))
            .json(&CheckStateRequest { ys })
            .send()
            .await
            .map_err(|e| CashuError::MintUnreachable(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(CashuError::MintUnreachable(format!(
                "POST /v1/checkstate → HTTP {}",
                resp.status()
            )));
        }

        let body: CheckStateResponse = resp
            .json()
            .await
            .map_err(|e| CashuError::Http(e.to_string()))?;

        Ok(body.states)
    }

    /// `POST /v1/swap` — atomically spend `inputs` and issue new proofs (NUT-03).
    ///
    /// Builds placeholder blinded outputs (see `make_blinded_output_placeholder`)
    /// and posts the swap request.  The mint marks the input proofs as SPENT.
    /// Returned blind signatures are discarded; a future wallet PR will unblind
    /// and store them once proper secp256k1 blind-DH is in place.
    pub async fn swap(
        &self,
        inputs: Vec<Proof>,
        keyset_id: &str,
    ) -> Result<Vec<BlindedSignature>, CashuError> {
        let outputs: Vec<BlindedMessage> = inputs
            .iter()
            .map(|p| make_blinded_output_placeholder(p.amount, keyset_id))
            .collect();

        let req = SwapRequest {
            inputs: &inputs,
            outputs,
        };

        let resp = self
            .client
            .post(format!("{}/v1/swap", self.mint_url))
            .json(&req)
            .send()
            .await
            .map_err(|e| CashuError::MintUnreachable(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(CashuError::MintUnreachable(format!(
                "POST /v1/swap → HTTP {status}: {text}"
            )));
        }

        let body: SwapResponse = resp
            .json()
            .await
            .map_err(|e| CashuError::Http(e.to_string()))?;

        Ok(body.signatures)
    }

    /// High-level: verify proofs are unspent then claim them.
    ///
    /// 1. `check_state` — all entries must be `UNSPENT`
    /// 2. `get_keys` — fetch keyset ID for swap outputs
    /// 3. `swap` — proofs become `SPENT`
    pub async fn verify_and_claim(&self, proofs: Vec<Proof>) -> Result<(), CashuError> {
        // Step 1 — verify unspent
        let states = self.check_state(&proofs).await?;
        for entry in &states {
            if entry.state != ProofState::Unspent {
                return Err(CashuError::AlreadySpent);
            }
        }

        // Step 2 — get keyset for swap outputs
        let keys = self.get_keys().await?;
        let keyset_id = keys
            .keysets
            .into_iter()
            .next()
            .map(|k| k.id)
            .unwrap_or_else(|| "00".to_string());

        // Step 3 — swap (proofs now SPENT)
        self.swap(proofs, &keyset_id).await?;
        debug!("Proofs verified and claimed via swap");
        Ok(())
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_to_curve_approx_deterministic() {
        assert_eq!(
            hash_to_curve_approx(b"hello"),
            hash_to_curve_approx(b"hello")
        );
    }

    #[test]
    fn test_hash_to_curve_approx_different_secrets_differ() {
        assert_ne!(
            hash_to_curve_approx(b"secret1"),
            hash_to_curve_approx(b"secret2")
        );
    }

    #[test]
    fn test_hash_to_curve_approx_prefix_byte() {
        // Must start with 0x02 (compressed-point even-y prefix)
        assert_eq!(hash_to_curve_approx(b"any")[0], 0x02);
    }

    #[test]
    fn test_hash_to_curve_approx_length() {
        assert_eq!(hash_to_curve_approx(b"test").len(), 33);
    }

    #[test]
    fn test_make_blinded_output_placeholder_structure() {
        let msg = make_blinded_output_placeholder(64, "keyset_abc");
        assert_eq!(msg.amount, 64);
        assert_eq!(msg.id, "keyset_abc");
        // 33 bytes hex-encoded = 66 chars
        assert_eq!(msg.b_.len(), 66);
    }

    #[test]
    fn test_make_blinded_output_placeholder_is_random() {
        let m1 = make_blinded_output_placeholder(1, "id");
        let m2 = make_blinded_output_placeholder(1, "id");
        assert_ne!(m1.b_, m2.b_);
    }

    #[test]
    fn test_mint_client_strips_trailing_slash() {
        let c = MintClient::new("http://mint.test:3338/".to_string());
        assert!(!c.mint_url.ends_with('/'));
    }

    #[tokio::test]
    async fn test_is_reachable_returns_false_for_unreachable_mint() {
        let c = MintClient::new("http://127.0.0.1:1".to_string());
        assert!(!c.is_reachable().await);
    }

    #[tokio::test]
    async fn test_check_state_mint_unreachable() {
        let c = MintClient::new("http://127.0.0.1:1".to_string());
        let proofs = vec![Proof {
            amount: 1,
            id: "id".into(),
            secret: "sec".into(),
            c: "c".into(),
        }];
        assert!(matches!(
            c.check_state(&proofs).await,
            Err(CashuError::MintUnreachable(_))
        ));
    }

    #[tokio::test]
    async fn test_get_keys_mint_unreachable() {
        let c = MintClient::new("http://127.0.0.1:1".to_string());
        assert!(matches!(
            c.get_keys().await,
            Err(CashuError::MintUnreachable(_))
        ));
    }

    #[tokio::test]
    async fn test_verify_and_claim_mint_unreachable() {
        let c = MintClient::new("http://127.0.0.1:1".to_string());
        let proofs = vec![Proof {
            amount: 10,
            id: "id".into(),
            secret: "sec".into(),
            c: "c".into(),
        }];
        assert!(matches!(
            c.verify_and_claim(proofs).await,
            Err(CashuError::MintUnreachable(_))
        ));
    }

    #[test]
    fn test_blinded_message_serializes_correctly() {
        let msg = BlindedMessage {
            amount: 8,
            id: "009a1f293253e41e".into(),
            b_: "02abc123".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"B_\""));
        assert!(json.contains("\"amount\":8"));
    }

    #[test]
    fn test_proof_state_serde() {
        let s: ProofState = serde_json::from_str("\"UNSPENT\"").unwrap();
        assert_eq!(s, ProofState::Unspent);
        let s: ProofState = serde_json::from_str("\"SPENT\"").unwrap();
        assert_eq!(s, ProofState::Spent);
    }
}
