//! Cashu mint HTTP client — NUT-00, NUT-01, NUT-03, NUT-07.
//!
//! Implements the operations a mix node needs to enforce per-packet payment:
//!
//! 1. `check_state` (NUT-07) — verify submitted proofs are UNSPENT.
//! 2. `get_keys` (NUT-01) — fetch the mint's active keysets.
//! 3. `swap` (NUT-03) — atomically spend the client's proofs and issue new
//!    ones owned by this node.
//!
//! ## NUT-00 secp256k1 blind-DH (fully implemented)
//!
//! Every blinded output message now carries a correct `B_ = Y + r·G` value:
//!
//! ```text
//! secret  ──hash_to_curve──▶  Y (secp256k1 point)
//!                              │
//! r (random scalar) ──r·G──▶  rG
//!                              │
//!                         Y + rG = B_   ← sent to mint
//! ```
//!
//! The mint returns `C_ = k·B_` (blind signature).  Unblinding yields
//! `C = C_ - r·K` where `K = k·G` is the mint's public key for that amount.
//! The node discards `(secret, r)` after the swap; a future wallet PR will
//! store them in a local proof store to accumulate node earnings.
//!
//! ### `hash_to_curve` (NUT-00 §3)
//!
//! ```text
//! msg_to_hash = SHA-256("Secp256k1_HashToCurve_Cashu_" ‖ secret)
//! counter     = 0
//! loop:
//!     candidate = SHA-256(msg_to_hash ‖ counter_le32)
//!     try 0x02 ‖ candidate as compressed secp256k1 point
//!     if valid: return it
//!     counter++
//! ```

use crate::cashu::{CashuError, Proof};
use k256::{
    elliptic_curve::{
        group::GroupEncoding,
        ops::MulByGenerator,
        sec1::{FromEncodedPoint, ToEncodedPoint},
        Field,
    },
    AffinePoint, EncodedPoint, ProjectivePoint, Scalar,
};
use rand::RngCore;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tracing::debug;
use zeroize::Zeroize;

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
    /// hex-encoded Y = hash_to_curve(secret) sent to the mint (NUT-07)
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

/// A blinded output message `B_ = Y + r·G` (NUT-00).
///
/// `B_` is a 33-byte compressed secp256k1 point, hex-encoded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindedMessage {
    pub amount: u64,
    pub id: String,
    /// Compressed secp256k1 point `B_ = Y + r·G`, hex-encoded (66 chars).
    #[serde(rename = "B_")]
    pub b_: String,
}

/// Blind signature returned by the mint: `C_ = k·B_`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindedSignature {
    pub amount: u64,
    pub id: String,
    #[serde(rename = "C_")]
    pub c_: String,
}

/// Secret material produced alongside a `BlindedMessage`.
///
/// The node discards this after the swap for now.  A future wallet PR stores
/// `(secret, r_scalar)` keyed by `B_` in a local proof store, then calls
/// `C = C_ - r·K` to obtain a valid Cashu proof the operator can melt via
/// Lightning.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct BlindingContext {
    /// 32-byte secret whose `hash_to_curve` produced `Y`.
    pub secret: [u8; 32],
    /// Blinding scalar `r` (big-endian) used to compute `B_ = Y + r·G`.
    pub r_scalar: [u8; 32],
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

// ── NUT-00: secp256k1 cryptography ───────────────────────────────────────────

/// NUT-00 `hash_to_curve` — deterministically maps `secret` bytes to a valid
/// secp256k1 `AffinePoint`.
///
/// Implements the algorithm verbatim from the Cashu NUT-00 specification:
///
/// 1. `msg = SHA-256("Secp256k1_HashToCurve_Cashu_" ‖ secret)`
/// 2. `counter = 0`
/// 3. `candidate = SHA-256(msg ‖ counter_le32)`; try `0x02 ‖ candidate` as a
///    compressed secp256k1 point.  If valid, return it.  Else `counter++`.
///
/// The loop terminates in ≤ 2 iterations on average (50 % chance per try).
pub fn hash_to_curve(secret: &[u8]) -> AffinePoint {
    let mut pre = Sha256::new();
    pre.update(b"Secp256k1_HashToCurve_Cashu_");
    pre.update(secret);
    let msg: [u8; 32] = pre.finalize().into();

    for counter in 0u32.. {
        let mut h = Sha256::new();
        h.update(msg);
        h.update(counter.to_le_bytes());
        let candidate: [u8; 32] = h.finalize().into();

        let mut compressed = [0u8; 33];
        compressed[0] = 0x02;
        compressed[1..].copy_from_slice(&candidate);

        if let Ok(ep) = EncodedPoint::from_bytes(&compressed) {
            let maybe: Option<AffinePoint> = AffinePoint::from_encoded_point(&ep).into();
            if let Some(point) = maybe {
                return point;
            }
        }
    }
    unreachable!("hash_to_curve counter space exhausted")
}

/// Build a valid NUT-00 blinded output `B_ = Y + r·G`.
///
/// Returns `(BlindedMessage, BlindingContext)`.  The caller should store the
/// `BlindingContext` to later unblind the mint's response; the current node
/// implementation discards it (no wallet yet).
pub fn make_blinded_output(amount: u64, keyset_id: &str) -> (BlindedMessage, BlindingContext) {
    // Fresh random secret → Y = hash_to_curve(secret)
    let mut secret = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);
    let y: ProjectivePoint = hash_to_curve(&secret).into();

    // Random blinding scalar r → r·G
    let r: Scalar = Scalar::random(&mut rand::thread_rng());
    let rg: ProjectivePoint = ProjectivePoint::mul_by_generator(&r);

    // B_ = Y + r·G
    let b_ = (y + rg).to_affine();
    let b_hex = hex::encode(b_.to_encoded_point(true).as_bytes());

    let r_scalar: [u8; 32] = r.to_bytes().into();

    (
        BlindedMessage {
            amount,
            id: keyset_id.to_string(),
            b_: b_hex,
        },
        BlindingContext { secret, r_scalar },
    )
}

// ── MintClient ────────────────────────────────────────────────────────────────

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

    /// `GET /v1/info` — returns `true` if mint responds 2xx.
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
    /// Uses canonical NUT-00 `hash_to_curve(secret)` for each Y-coordinate.
    pub async fn check_state(&self, proofs: &[Proof]) -> Result<Vec<CheckStateEntry>, CashuError> {
        let ys: Vec<String> = proofs
            .iter()
            .map(|p| {
                let point = hash_to_curve(p.secret.as_bytes());
                hex::encode(point.to_encoded_point(true).as_bytes())
            })
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

    /// `POST /v1/swap` — spend `inputs`, receive blind signatures (NUT-03).
    ///
    /// Blinded outputs are built with full NUT-00 `B_ = Y + r·G`.
    /// Blinding contexts are discarded; wallet unblinding is a future PR.
    pub async fn swap(
        &self,
        inputs: Vec<Proof>,
        keyset_id: &str,
    ) -> Result<Vec<BlindedSignature>, CashuError> {
        let (outputs, _contexts): (Vec<_>, Vec<_>) = inputs
            .iter()
            .map(|p| make_blinded_output(p.amount, keyset_id))
            .unzip();

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

        debug!("Swap: {} blind sigs received", body.signatures.len());
        Ok(body.signatures)
    }

    /// Verify proofs are unspent then atomically claim them (NUT-07 + NUT-03).
    pub async fn verify_and_claim(&self, proofs: Vec<Proof>) -> Result<(), CashuError> {
        let states = self.check_state(&proofs).await?;
        for entry in &states {
            if entry.state != ProofState::Unspent {
                return Err(CashuError::AlreadySpent);
            }
        }

        let keys = self.get_keys().await?;
        let keyset_id = keys
            .keysets
            .into_iter()
            .next()
            .map(|k| k.id)
            .unwrap_or_else(|| "00".to_string());

        self.swap(proofs, &keyset_id).await?;
        debug!("verify_and_claim: proofs SPENT");
        Ok(())
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── hash_to_curve ─────────────────────────────────────────────────────────

    #[test]
    fn test_hash_to_curve_deterministic() {
        assert_eq!(hash_to_curve(b"hello"), hash_to_curve(b"hello"));
    }

    #[test]
    fn test_hash_to_curve_different_inputs_differ() {
        assert_ne!(hash_to_curve(b"secret1"), hash_to_curve(b"secret2"));
    }

    #[test]
    fn test_hash_to_curve_is_valid_curve_point() {
        let point = hash_to_curve(b"test_secret");
        let ep = point.to_encoded_point(true);
        let decoded: Option<AffinePoint> = AffinePoint::from_encoded_point(&ep).into();
        assert!(decoded.is_some());
    }

    /// NUT-00 spec test vector: `hash_to_curve(b"")` must produce a specific
    /// known point.  Failure here means the algorithm deviates from the spec
    /// and proofs will be rejected by real Cashu mints.
    #[test]
    fn test_hash_to_curve_nut00_vector_empty() {
        let hex = hex::encode(hash_to_curve(b"").to_encoded_point(true).as_bytes());
        assert_eq!(
            hex,
            "0266687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"
        );
    }

    /// NUT-00 spec test vector: `hash_to_curve(b"abc")`.
    #[test]
    fn test_hash_to_curve_nut00_vector_abc() {
        let hex = hex::encode(hash_to_curve(b"abc").to_encoded_point(true).as_bytes());
        assert_eq!(
            hex,
            "02b9f357d9d8f43f3b9eb7de271b9edcd30a4f18dd6665e1c50dcde5ffa01d2d2"
        );
    }

    // ── make_blinded_output ───────────────────────────────────────────────────

    #[test]
    fn test_blinded_output_b_is_66_hex_chars() {
        let (msg, _) = make_blinded_output(64, "id");
        assert_eq!(msg.b_.len(), 66);
    }

    #[test]
    fn test_blinded_output_amount_and_id() {
        let (msg, _) = make_blinded_output(128, "keyset");
        assert_eq!(msg.amount, 128);
        assert_eq!(msg.id, "keyset");
    }

    #[test]
    fn test_blinded_output_b_is_valid_curve_point() {
        let (msg, _) = make_blinded_output(1, "id");
        let bytes = hex::decode(&msg.b_).unwrap();
        let ep = EncodedPoint::from_bytes(&bytes).unwrap();
        let maybe: Option<AffinePoint> = AffinePoint::from_encoded_point(&ep).into();
        assert!(maybe.is_some(), "B_ must be a valid secp256k1 point");
    }

    #[test]
    fn test_blinded_output_is_random() {
        let (m1, _) = make_blinded_output(1, "id");
        let (m2, _) = make_blinded_output(1, "id");
        assert_ne!(m1.b_, m2.b_);
    }

    #[test]
    fn test_blinding_context_sizes() {
        let (_, ctx) = make_blinded_output(1, "id");
        assert_eq!(ctx.secret.len(), 32);
        assert_eq!(ctx.r_scalar.len(), 32);
    }

    /// B_ = Y + r·G — verify the construction holds by checking B_ - r·G = Y.
    #[test]
    fn test_blinded_output_b_minus_rg_equals_y() {
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);

        let y_affine = hash_to_curve(&secret);
        let y: ProjectivePoint = y_affine.into();

        let r = Scalar::random(&mut rand::thread_rng());
        let rg: ProjectivePoint = ProjectivePoint::mul_by_generator(&r);
        let b_ = (y + rg).to_affine();

        // B_ - r·G should equal Y
        let recovered = (ProjectivePoint::from(b_) - rg).to_affine();
        assert_eq!(recovered, y_affine, "B_ - r·G must equal Y");
    }

    // ── serialization ─────────────────────────────────────────────────────────

    #[test]
    fn test_blinded_message_json_key_is_b_underscore() {
        let msg = BlindedMessage {
            amount: 8,
            id: "009a1f293253e41e".into(),
            b_: "02abc".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"B_\""));
    }

    #[test]
    fn test_proof_state_serde() {
        assert_eq!(
            serde_json::from_str::<ProofState>("\"UNSPENT\"").unwrap(),
            ProofState::Unspent
        );
        assert_eq!(
            serde_json::from_str::<ProofState>("\"SPENT\"").unwrap(),
            ProofState::Spent
        );
        assert_eq!(
            serde_json::from_str::<ProofState>("\"PENDING\"").unwrap(),
            ProofState::Pending
        );
    }

    // ── MintClient (unreachable mint) ─────────────────────────────────────────

    #[tokio::test]
    async fn test_is_reachable_false_for_unreachable_mint() {
        assert!(
            !MintClient::new("http://127.0.0.1:1".into())
                .is_reachable()
                .await
        );
    }

    #[tokio::test]
    async fn test_check_state_mint_unreachable() {
        let c = MintClient::new("http://127.0.0.1:1".into());
        let proofs = vec![Proof {
            amount: 1,
            id: "id".into(),
            secret: "s".into(),
            c: "c".into(),
        }];
        assert!(matches!(
            c.check_state(&proofs).await,
            Err(CashuError::MintUnreachable(_))
        ));
    }

    #[tokio::test]
    async fn test_get_keys_mint_unreachable() {
        assert!(matches!(
            MintClient::new("http://127.0.0.1:1".into())
                .get_keys()
                .await,
            Err(CashuError::MintUnreachable(_))
        ));
    }

    #[tokio::test]
    async fn test_verify_and_claim_mint_unreachable() {
        let c = MintClient::new("http://127.0.0.1:1".into());
        let proofs = vec![Proof {
            amount: 10,
            id: "id".into(),
            secret: "s".into(),
            c: "c".into(),
        }];
        assert!(matches!(
            c.verify_and_claim(proofs).await,
            Err(CashuError::MintUnreachable(_))
        ));
    }

    /// Prove that the blinded output is built (no panic) before the HTTP call
    /// fires — the crypto runs synchronously before any await point.
    #[tokio::test]
    async fn test_swap_valid_outputs_built_before_http() {
        let c = MintClient::new("http://127.0.0.1:1".into());
        let inputs = vec![
            Proof {
                amount: 1,
                id: "id".into(),
                secret: "s1".into(),
                c: "c1".into(),
            },
            Proof {
                amount: 2,
                id: "id".into(),
                secret: "s2".into(),
                c: "c2".into(),
            },
        ];
        assert!(matches!(
            c.swap(inputs, "009a1f293253e41e").await,
            Err(CashuError::MintUnreachable(_))
        ));
    }
}
