//! Cashu mint HTTP client — NUT-00, NUT-01, NUT-03, NUT-07.
//!
//! Implements the full economic loop for a mix node:
//!
//! 1. `check_state` (NUT-07) — verify submitted proofs are UNSPENT.
//! 2. `get_keys` (NUT-01) — fetch the mint's active keysets.
//! 3. `swap` (NUT-03) — spend input proofs, unblind the returned signatures,
//!    and accumulate the resulting proofs in the node's `NodeWallet`.
//!
//! ## NUT-00 secp256k1 blind-DH — full round-trip
//!
//! ```text
//! [Client sends payment]
//!
//!   secret  ──hash_to_curve──▶  Y
//!   r (random scalar) ──r·G──▶  rG
//!                           B_ = Y + r·G   →  sent to mint
//!
//! [Mint returns blind signature]
//!
//!   C_ = k·B_                              ←  received from mint
//!
//! [Node unblinds]
//!
//!   K  = mint's public key for this amount (from GET /v1/keys)
//!   C  = C_ - r·K                         →  valid Cashu proof
//!
//! [Node wallet stores (secret, C) as a Proof the operator can melt]
//! ```
//!
//! ### `hash_to_curve` (NUT-00 §3)
//!
//! ```text
//! msg = SHA-256("Secp256k1_HashToCurve_Cashu_" ‖ secret)
//! counter = 0
//! loop:
//!     candidate = SHA-256(msg ‖ counter_le32)
//!     try 0x02 ‖ candidate as compressed secp256k1 point
//!     if valid: return it
//!     counter++
//! ```

use crate::cashu::{CashuError, Proof};
use k256::{
    elliptic_curve::{
        ops::MulByGenerator,
        sec1::{FromEncodedPoint, ToEncodedPoint},
        Field, ScalarPrimitive,
    },
    AffinePoint, EncodedPoint, ProjectivePoint, Scalar, Secp256k1,
};
use rand::RngCore;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use tracing::{debug, warn};
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
    /// amount (as decimal string) → hex-encoded 33-byte compressed secp256k1 pubkey
    pub keys: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeysResponse {
    pub keysets: Vec<Keyset>,
}

// ── NUT-03: swap ──────────────────────────────────────────────────────────────

/// A blinded output message `B_ = Y + r·G` (NUT-00).
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
    /// Compressed secp256k1 point `C_ = k·B_`, hex-encoded.
    #[serde(rename = "C_")]
    pub c_: String,
}

/// Secret material produced alongside a `BlindedMessage`.
///
/// Used immediately after the swap to unblind `C_ = k·B_` into a valid
/// Cashu proof via `C = C_ - r·K`.  Zeroize-on-drop.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct BlindingContext {
    /// 32-byte random secret whose `hash_to_curve` produced `Y`.
    /// Becomes `Proof.secret` (hex-encoded) after unblinding.
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

// ── NodeWallet ────────────────────────────────────────────────────────────────

/// Persistent wallet for the mix node operator.
///
/// Accumulates `Proof` objects earned from forwarding payments.  Each proof
/// was produced by unblinding a blind signature from the mint and can be
/// redeemed via `POST /v1/melt` (NUT-05, future PR).
///
/// Thread-safe via `Arc<Mutex<_>>`.  Persists to a JSON lines file on every
/// credit so earnings survive process restarts.
#[derive(Debug, Clone)]
pub struct NodeWallet {
    inner: Arc<Mutex<WalletInner>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct WalletInner {
    proofs: Vec<Proof>,
    store_path: Option<PathBuf>,
}

impl NodeWallet {
    /// Create an in-memory wallet with no persistence.
    pub fn new_in_memory() -> Self {
        Self {
            inner: Arc::new(Mutex::new(WalletInner {
                proofs: Vec::new(),
                store_path: None,
            })),
        }
    }

    /// Create a wallet backed by a JSON file at `path`.
    ///
    /// Existing proofs are loaded on creation.  Every `credit()` call
    /// appends to the file atomically.
    pub fn new_persistent(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref().to_path_buf();
        let proofs = Self::load_from_file(&path).unwrap_or_default();
        let count = proofs.len();
        let wallet = Self {
            inner: Arc::new(Mutex::new(WalletInner {
                proofs,
                store_path: Some(path.clone()),
            })),
        };
        debug!("NodeWallet loaded {} proofs from {:?}", count, path);
        wallet
    }

    /// Add earned proofs to the wallet and flush to disk if persistent.
    pub fn credit(&self, new_proofs: Vec<Proof>) {
        let mut inner = self.inner.lock().unwrap();
        let count = new_proofs.len();
        let total: u64 = new_proofs.iter().map(|p| p.amount).sum();

        if let Some(ref path) = inner.store_path {
            if let Err(e) = Self::append_to_file(path, &new_proofs) {
                warn!("NodeWallet: failed to persist {} proofs: {}", count, e);
            }
        }

        inner.proofs.extend(new_proofs);
        debug!(
            "NodeWallet: credited {} proofs ({} sats), total balance {} sats",
            count,
            total,
            inner.proofs.iter().map(|p| p.amount).sum::<u64>()
        );
    }

    /// Total spendable balance in satoshis.
    pub fn balance(&self) -> u64 {
        self.inner
            .lock()
            .unwrap()
            .proofs
            .iter()
            .map(|p| p.amount)
            .sum()
    }

    /// All stored proofs (clone).
    pub fn proofs(&self) -> Vec<Proof> {
        self.inner.lock().unwrap().proofs.clone()
    }

    /// Drain all proofs — call before `POST /v1/melt`.
    pub fn drain(&self) -> Vec<Proof> {
        let mut inner = self.inner.lock().unwrap();
        std::mem::take(&mut inner.proofs)
    }

    // ── persistence helpers ───────────────────────────────────────────────────

    fn load_from_file(path: &Path) -> Option<Vec<Proof>> {
        let data = std::fs::read_to_string(path).ok()?;
        let proofs: Vec<Proof> = serde_json::from_str(&data).ok()?;
        Some(proofs)
    }

    fn append_to_file(path: &Path, proofs: &[Proof]) -> std::io::Result<()> {
        use std::io::Write;
        // Read existing, merge, rewrite atomically via temp file
        let mut existing: Vec<Proof> = std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        existing.extend_from_slice(proofs);
        let json = serde_json::to_string_pretty(&existing)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        // Write to .tmp then rename for atomicity
        let tmp = path.with_extension("tmp");
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(json.as_bytes())?;
        f.flush()?;
        std::fs::rename(tmp, path)?;
        Ok(())
    }
}

// ── NUT-00: secp256k1 cryptography ───────────────────────────────────────────

/// NUT-00 `hash_to_curve` — deterministically maps `secret` bytes to a valid
/// secp256k1 `AffinePoint`.
///
/// Algorithm (NUT-00 spec):
/// 1. `msg = SHA-256("Secp256k1_HashToCurve_Cashu_" ‖ secret)`
/// 2. `counter = 0`
/// 3. `candidate = SHA-256(msg ‖ counter_le32)`; try `0x02 ‖ candidate` as a
///    compressed secp256k1 point.  If valid, return it.  Else `counter++`.
///
/// Terminates in ≤ 2 iterations on average.
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
/// Returns `(BlindedMessage, BlindingContext)`.  The `BlindingContext` must be
/// retained until the mint's swap response arrives so the blind signature can
/// be unblinded into a spendable proof.
pub fn make_blinded_output(amount: u64, keyset_id: &str) -> (BlindedMessage, BlindingContext) {
    let mut secret = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);
    let y: ProjectivePoint = hash_to_curve(&secret).into();

    let r: Scalar = Scalar::random(&mut rand::thread_rng());
    let rg: ProjectivePoint = ProjectivePoint::mul_by_generator(&r);

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

/// Unblind a mint blind signature into a spendable Cashu `Proof`.
///
/// Formula (NUT-00): `C = C_ - r·K`
///
/// - `c_hex`   — hex-encoded 33-byte compressed point `C_ = k·B_` from the mint
/// - `ctx`     — `BlindingContext` produced alongside the `BlindedMessage`
/// - `k_hex`   — hex-encoded 33-byte mint pubkey `K` for this denomination
///               (from `KeysResponse.keys[amount.to_string()]`)
/// - `amount`  — denomination in satoshis
/// - `keyset_id` — keyset ID for the resulting proof
///
/// Returns a `Proof` that is valid at the mint and can be redeemed via melt.
pub fn unblind(
    c_hex: &str,
    ctx: &BlindingContext,
    k_hex: &str,
    amount: u64,
    keyset_id: &str,
) -> Result<Proof, CashuError> {
    // Parse C_ from mint
    let c_bytes = hex::decode(c_hex).map_err(|e| CashuError::Http(format!("C_ hex: {e}")))?;
    let c_ep = EncodedPoint::from_bytes(&c_bytes)
        .map_err(|_| CashuError::Http("C_ not a valid point encoding".into()))?;
    let c_affine: AffinePoint = AffinePoint::from_encoded_point(&c_ep)
        .into_option()
        .ok_or_else(|| CashuError::Http("C_ not on secp256k1 curve".into()))?;
    let c_proj: ProjectivePoint = c_affine.into();

    // Parse mint pubkey K for this denomination
    let k_bytes = hex::decode(k_hex).map_err(|e| CashuError::Http(format!("K hex: {e}")))?;
    let k_ep = EncodedPoint::from_bytes(&k_bytes)
        .map_err(|_| CashuError::Http("K not a valid point encoding".into()))?;
    let k_affine: AffinePoint = AffinePoint::from_encoded_point(&k_ep)
        .into_option()
        .ok_or_else(|| CashuError::Http("K not on secp256k1 curve".into()))?;
    let k_proj: ProjectivePoint = k_affine.into();

    // Reconstruct r scalar from big-endian bytes
    let r_bytes = k256::FieldBytes::from(ctx.r_scalar);
    let r_prim = ScalarPrimitive::<Secp256k1>::from_bytes(&r_bytes);
    let r: Scalar = if r_prim.is_some().into() {
        r_prim.unwrap().into()
    } else {
        return Err(CashuError::Http(
            "r_scalar is not a valid secp256k1 scalar".into(),
        ));
    };

    // C = C_ - r·K
    let rk: ProjectivePoint = k_proj * r;
    let c = (c_proj - rk).to_affine();
    let c_hex_out = hex::encode(c.to_encoded_point(true).as_bytes());

    // secret is hex-encoded 32-byte random value
    let secret_hex = hex::encode(ctx.secret);

    Ok(Proof {
        amount,
        id: keyset_id.to_string(),
        secret: secret_hex,
        c: c_hex_out,
    })
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

    /// `POST /v1/swap` — spend `inputs`, unblind the returned signatures,
    /// and return spendable `Proof` objects (NUT-03 + NUT-00 unblinding).
    ///
    /// This is the complete economic loop:
    /// 1. Build `B_ = Y + r·G` for each input proof
    /// 2. POST swap request — mint marks inputs SPENT, returns `C_ = k·B_`
    /// 3. For each `(C_, ctx)` pair: look up mint pubkey `K` for the amount,
    ///    compute `C = C_ - r·K` → valid Cashu `Proof`
    ///
    /// If the keyset has no pubkey for a given amount, that signature is
    /// logged as a warning and skipped rather than failing the whole swap.
    pub async fn swap(
        &self,
        inputs: Vec<Proof>,
        keyset: &Keyset,
    ) -> Result<Vec<Proof>, CashuError> {
        // Build blinded outputs — keep contexts for unblinding
        let (outputs, contexts): (Vec<BlindedMessage>, Vec<BlindingContext>) = inputs
            .iter()
            .map(|p| make_blinded_output(p.amount, &keyset.id))
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

        debug!(
            "Swap: {} blind sigs received — unblinding",
            body.signatures.len()
        );

        // Unblind each signature: C = C_ - r·K
        let mut earned: Vec<Proof> = Vec::with_capacity(body.signatures.len());
        for (sig, ctx) in body.signatures.iter().zip(contexts.iter()) {
            let amount_key = sig.amount.to_string();
            match keyset.keys.get(&amount_key) {
                Some(k_hex) => match unblind(&sig.c_, ctx, k_hex, sig.amount, &sig.id) {
                    Ok(proof) => earned.push(proof),
                    Err(e) => warn!("Unblind failed for {} sats: {}", sig.amount, e),
                },
                None => warn!(
                    "No mint pubkey for {} sats in keyset {} — skipping",
                    sig.amount, keyset.id
                ),
            }
        }

        debug!("Swap complete: {} proofs earned", earned.len());
        Ok(earned)
    }

    /// Verify proofs are unspent, claim them via swap, unblind, and credit
    /// the resulting proofs to `wallet`.
    ///
    /// Full flow: NUT-07 checkstate → NUT-01 get_keys → NUT-03 swap +
    /// NUT-00 unblinding → `NodeWallet::credit`.
    pub async fn verify_and_claim(
        &self,
        proofs: Vec<Proof>,
        wallet: &NodeWallet,
    ) -> Result<u64, CashuError> {
        // Step 1 — verify UNSPENT
        let states = self.check_state(&proofs).await?;
        for entry in &states {
            if entry.state != ProofState::Unspent {
                return Err(CashuError::AlreadySpent);
            }
        }

        // Step 2 — fetch keyset (need pubkeys for unblinding)
        let keys = self.get_keys().await?;
        let keyset = keys
            .keysets
            .into_iter()
            .next()
            .ok_or_else(|| CashuError::Http("Mint returned empty keyset list".into()))?;

        // Step 3 — swap + unblind → spendable proofs
        let earned = self.swap(proofs, &keyset).await?;
        let earned_sats: u64 = earned.iter().map(|p| p.amount).sum();

        // Step 4 — credit wallet
        wallet.credit(earned);

        debug!(
            "verify_and_claim: {} sats credited to node wallet",
            earned_sats
        );
        Ok(earned_sats)
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

    #[test]
    fn test_hash_to_curve_stable_output() {
        let secret = b"zksn-test-secret";
        let a = hex::encode(hash_to_curve(secret).to_encoded_point(true).as_bytes());
        let b = hex::encode(hash_to_curve(secret).to_encoded_point(true).as_bytes());
        assert_eq!(a, b);
        assert_eq!(a.len(), 66);
        assert!(a.starts_with("02") || a.starts_with("03"));
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

    #[test]
    fn test_blinded_output_b_minus_rg_equals_y() {
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);

        let y_affine = hash_to_curve(&secret);
        let y: ProjectivePoint = y_affine.into();

        let r = Scalar::random(&mut rand::thread_rng());
        let rg: ProjectivePoint = ProjectivePoint::mul_by_generator(&r);
        let b_ = (y + rg).to_affine();

        let recovered = (ProjectivePoint::from(b_) - rg).to_affine();
        assert_eq!(recovered, y_affine, "B_ - r·G must equal Y");
    }

    // ── unblind ───────────────────────────────────────────────────────────────

    /// Full round-trip: build B_, simulate mint signing (C_ = k·B_),
    /// unblind to C, verify C == k·Y (the correct Cashu signature relation).
    ///
    /// This test uses a synthetic mint keypair (k, K=k·G) so no live mint
    /// is required.  It proves `unblind` produces a valid proof without a
    /// network call.
    #[test]
    fn test_unblind_roundtrip() {
        // Synthetic mint keypair: k (private), K = k·G (public)
        let k: Scalar = Scalar::random(&mut rand::thread_rng());
        let k_pub: AffinePoint = ProjectivePoint::mul_by_generator(&k).to_affine();
        let k_hex = hex::encode(k_pub.to_encoded_point(true).as_bytes());

        // Build blinded output
        let (msg, ctx) = make_blinded_output(64, "test-keyset");

        // Simulate mint: C_ = k · B_
        let b_bytes = hex::decode(&msg.b_).unwrap();
        let b_ep = EncodedPoint::from_bytes(&b_bytes).unwrap();
        let b_affine: AffinePoint = AffinePoint::from_encoded_point(&b_ep).unwrap();
        let b_proj: ProjectivePoint = b_affine.into();
        let c_proj = b_proj * k;
        let c_hex = hex::encode(c_proj.to_affine().to_encoded_point(true).as_bytes());

        // Unblind: C = C_ - r·K
        let proof = unblind(&c_hex, &ctx, &k_hex, 64, "test-keyset").unwrap();

        // Verify: C should equal k·Y
        let y: ProjectivePoint = hash_to_curve(&ctx.secret).into();
        let expected = (y * k).to_affine();
        let expected_hex = hex::encode(expected.to_encoded_point(true).as_bytes());

        assert_eq!(proof.c, expected_hex, "C must equal k·Y");
        assert_eq!(proof.amount, 64);
        assert_eq!(proof.id, "test-keyset");
        assert_eq!(proof.secret, hex::encode(ctx.secret));
    }

    #[test]
    fn test_unblind_rejects_invalid_c_hex() {
        let (_, ctx) = make_blinded_output(1, "id");
        let k_pub =
            ProjectivePoint::mul_by_generator(&Scalar::random(&mut rand::thread_rng())).to_affine();
        let k_hex = hex::encode(k_pub.to_encoded_point(true).as_bytes());

        let result = unblind("not-hex!!", &ctx, &k_hex, 1, "id");
        assert!(matches!(result, Err(CashuError::Http(_))));
    }

    #[test]
    fn test_unblind_rejects_invalid_k_hex() {
        let (msg, ctx) = make_blinded_output(1, "id");
        let result = unblind(&msg.b_, &ctx, "deadbeef", 1, "id");
        assert!(matches!(result, Err(CashuError::Http(_))));
    }

    // ── NodeWallet ────────────────────────────────────────────────────────────

    #[test]
    fn test_wallet_starts_empty() {
        let w = NodeWallet::new_in_memory();
        assert_eq!(w.balance(), 0);
        assert!(w.proofs().is_empty());
    }

    #[test]
    fn test_wallet_credit_updates_balance() {
        let w = NodeWallet::new_in_memory();
        w.credit(vec![
            Proof {
                amount: 64,
                id: "id".into(),
                secret: "s1".into(),
                c: "c1".into(),
            },
            Proof {
                amount: 32,
                id: "id".into(),
                secret: "s2".into(),
                c: "c2".into(),
            },
        ]);
        assert_eq!(w.balance(), 96);
    }

    #[test]
    fn test_wallet_credit_accumulates() {
        let w = NodeWallet::new_in_memory();
        w.credit(vec![Proof {
            amount: 10,
            id: "id".into(),
            secret: "s1".into(),
            c: "c".into(),
        }]);
        w.credit(vec![Proof {
            amount: 20,
            id: "id".into(),
            secret: "s2".into(),
            c: "c".into(),
        }]);
        assert_eq!(w.balance(), 30);
        assert_eq!(w.proofs().len(), 2);
    }

    #[test]
    fn test_wallet_drain_empties_balance() {
        let w = NodeWallet::new_in_memory();
        w.credit(vec![Proof {
            amount: 100,
            id: "id".into(),
            secret: "s".into(),
            c: "c".into(),
        }]);
        let drained = w.drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].amount, 100);
        assert_eq!(w.balance(), 0);
    }

    #[test]
    fn test_wallet_persistent_roundtrip() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "zksn-wallet-test-{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let w1 = NodeWallet::new_persistent(&path);
        w1.credit(vec![
            Proof {
                amount: 8,
                id: "id".into(),
                secret: "s1".into(),
                c: "c1".into(),
            },
            Proof {
                amount: 16,
                id: "id".into(),
                secret: "s2".into(),
                c: "c2".into(),
            },
        ]);
        assert_eq!(w1.balance(), 24);
        drop(w1);

        // Reload from disk
        let w2 = NodeWallet::new_persistent(&path);
        assert_eq!(w2.balance(), 24);
        assert_eq!(w2.proofs().len(), 2);

        let _ = std::fs::remove_file(&path);
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
        let w = NodeWallet::new_in_memory();
        let proofs = vec![Proof {
            amount: 10,
            id: "id".into(),
            secret: "s".into(),
            c: "c".into(),
        }];
        assert!(matches!(
            c.verify_and_claim(proofs, &w).await,
            Err(CashuError::MintUnreachable(_))
        ));
        // Wallet untouched — mint was unreachable before swap
        assert_eq!(w.balance(), 0);
    }

    #[tokio::test]
    async fn test_swap_mint_unreachable() {
        let c = MintClient::new("http://127.0.0.1:1".into());
        let keyset = Keyset {
            id: "test".into(),
            unit: "sat".into(),
            keys: HashMap::new(),
        };
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
            c.swap(inputs, &keyset).await,
            Err(CashuError::MintUnreachable(_))
        ));
    }
}
