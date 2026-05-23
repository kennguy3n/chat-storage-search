//! Hybrid Ed25519 + ML-DSA-65 manifest signing.
//!
//! `docs/DESIGN.md §2.1` defines the device signing key used to
//! sign every backup and archive manifest in the chain. To maintain
//! security under both classical and post-quantum adversaries we
//! sign each canonical manifest payload **twice**:
//!
//! * **Ed25519** — fast, well-audited classical EdDSA. Survives
//!   classical attackers and matches the signature shape every
//!   downstream tool (delivery service, audit log, etc.) already
//!   knows how to consume.
//! * **ML-DSA-65** — FIPS 204 module-lattice signature, NIST
//!   Category 3. Survives a CRQC ("cryptographically relevant
//!   quantum computer") via Shor's algorithm.
//!
//! Verification re-derives the canonical payload and checks **both**
//! signatures; the manifest is rejected if either signature fails.
//!
//! The two key pairs are independent — they share no entropy and
//! are stored side-by-side in the device's secure storage. The
//! orchestrator reads them out, hands a [`HybridSigningKey`] to
//! the backup / archive manifest builders, and a
//! [`HybridVerifyingKey`] to the restore-side verifier.

use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as Ed25519Signer, SigningKey as Ed25519SigningKey,
    Verifier as Ed25519Verifier, VerifyingKey as Ed25519VerifyingKey, SIGNATURE_LENGTH,
};
use ml_dsa::{
    EncodedSignature, EncodedSigningKey, EncodedVerifyingKey, KeyGen, MlDsa65,
    Signature as MlDsaSignatureGeneric, SigningKey as MlDsaSigningKeyGeneric,
    VerifyingKey as MlDsaVerifyingKeyGeneric,
};
use rand::{CryptoRng, RngCore};

use super::{CryptoError, CryptoResult};

/// ML-DSA-65 signing key (FIPS 204 Category 3).
pub type MlDsaSigningKey = MlDsaSigningKeyGeneric<MlDsa65>;
/// ML-DSA-65 verifying key.
pub type MlDsaVerifyingKey = MlDsaVerifyingKeyGeneric<MlDsa65>;
/// ML-DSA-65 signature.
pub type MlDsaSignature = MlDsaSignatureGeneric<MlDsa65>;

/// Encoded length of an ML-DSA-65 verifying key (FIPS 204 §4 Table 1).
pub const ML_DSA_65_VERIFYING_KEY_LEN: usize = 1952;
/// Encoded length of an ML-DSA-65 signing key.
pub const ML_DSA_65_SIGNING_KEY_LEN: usize = 4032;
/// Encoded length of an ML-DSA-65 signature.
pub const ML_DSA_65_SIGNATURE_LEN: usize = 3309;

/// Hybrid signing key bundling an Ed25519 key with an ML-DSA-65
/// key. Produced by [`HybridSigningKey::generate`] (random) or
/// [`HybridSigningKey::from_parts`] (caller-supplied keys, e.g.
/// keys decoded out of the device keychain).
#[derive(Clone)]
pub struct HybridSigningKey {
    ed25519: Ed25519SigningKey,
    ml_dsa_signing: MlDsaSigningKey,
    ml_dsa_verifying: MlDsaVerifyingKey,
}

impl HybridSigningKey {
    /// Construct a hybrid key from already-existing component keys.
    /// The platform layer (Keychain / Keystore / DPAPI) is the
    /// canonical home for these — see `docs/DESIGN.md §2.1`.
    ///
    /// Both ML-DSA components must come from the same FIPS 204
    /// key-gen run; the verifying key is taken on faith here
    /// because reconstructing it from the signing key alone
    /// requires re-running the seeded expansion.
    pub fn from_parts(
        ed25519: Ed25519SigningKey,
        ml_dsa_signing: MlDsaSigningKey,
        ml_dsa_verifying: MlDsaVerifyingKey,
    ) -> Self {
        Self {
            ed25519,
            ml_dsa_signing,
            ml_dsa_verifying,
        }
    }

    /// Generate a fresh hybrid signing key from `rng`. Both
    /// underlying keys consume entropy from the same source.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let ed25519 = Ed25519SigningKey::generate(rng);
        let kp = MlDsa65::key_gen(rng);
        let ml_dsa_signing = kp.signing_key().clone();
        let ml_dsa_verifying = kp.verifying_key().clone();
        Self {
            ed25519,
            ml_dsa_signing,
            ml_dsa_verifying,
        }
    }

    /// Borrow the Ed25519 component.
    pub fn ed25519(&self) -> &Ed25519SigningKey {
        &self.ed25519
    }

    /// Borrow the ML-DSA-65 signing component.
    pub fn ml_dsa(&self) -> &MlDsaSigningKey {
        &self.ml_dsa_signing
    }

    /// Borrow the ML-DSA-65 verifying component cached at
    /// generation time.
    pub fn ml_dsa_verifying_key(&self) -> &MlDsaVerifyingKey {
        &self.ml_dsa_verifying
    }

    /// Derive the matching [`HybridVerifyingKey`] for this signing
    /// key.
    pub fn verifying_key(&self) -> HybridVerifyingKey {
        HybridVerifyingKey {
            ed25519: self.ed25519.verifying_key(),
            ml_dsa: self.ml_dsa_verifying.clone(),
        }
    }

    /// Sign `payload` with both component keys and return the two
    /// signatures. The Ed25519 signature is exactly
    /// [`SIGNATURE_LENGTH`] bytes; the ML-DSA-65 signature is
    /// [`ML_DSA_65_SIGNATURE_LEN`] bytes when serialized via
    /// [`encode_ml_dsa_signature`].
    ///
    /// The ML-DSA leg uses `sign_deterministic` with an empty
    /// context string so signatures are reproducible across
    /// runs — exercising the same FIPS 204 deterministic variant
    /// that the conformance vectors test suite uses.
    pub fn sign_payload(&self, payload: &[u8]) -> CryptoResult<(Ed25519Signature, MlDsaSignature)> {
        let ed = self.ed25519.sign(payload);
        let mldsa = self
            .ml_dsa_signing
            .sign_deterministic(payload, b"")
            .map_err(|_| CryptoError::Aead("ml-dsa-65 sign failed"))?;
        Ok((ed, mldsa))
    }
}

impl std::fmt::Debug for HybridSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't print key bytes.
        f.write_str("HybridSigningKey(<redacted>)")
    }
}

/// Hybrid verifying key bundling an Ed25519 verifying key with an
/// ML-DSA-65 verifying key.
#[derive(Clone)]
pub struct HybridVerifyingKey {
    ed25519: Ed25519VerifyingKey,
    ml_dsa: MlDsaVerifyingKey,
}

impl HybridVerifyingKey {
    /// Construct a hybrid verifying key from its component keys.
    pub fn from_parts(ed25519: Ed25519VerifyingKey, ml_dsa: MlDsaVerifyingKey) -> Self {
        Self { ed25519, ml_dsa }
    }

    /// Borrow the Ed25519 verifying-key component.
    pub fn ed25519(&self) -> &Ed25519VerifyingKey {
        &self.ed25519
    }

    /// Borrow the ML-DSA-65 verifying-key component.
    pub fn ml_dsa(&self) -> &MlDsaVerifyingKey {
        &self.ml_dsa
    }

    /// Verify the Ed25519 leg of a hybrid signature.
    pub fn verify_ed25519(&self, payload: &[u8], signature: &[u8]) -> CryptoResult<()> {
        let sig_bytes: [u8; SIGNATURE_LENGTH] = signature.try_into().map_err(|_| {
            CryptoError::Frame(format!(
                "manifest: ed25519 signature must be {SIGNATURE_LENGTH} bytes, got {}",
                signature.len()
            ))
        })?;
        let sig = Ed25519Signature::from_bytes(&sig_bytes);
        self.ed25519
            .verify(payload, &sig)
            .map_err(|_| CryptoError::Aead("manifest: ed25519 verify failed"))
    }

    /// Verify the ML-DSA-65 leg of a hybrid signature.
    pub fn verify_ml_dsa(&self, payload: &[u8], signature: &[u8]) -> CryptoResult<()> {
        let sig = decode_ml_dsa_signature(signature)?;
        self.ml_dsa
            .verify(payload, &sig)
            .map_err(|_| CryptoError::Aead("manifest: ml-dsa-65 verify failed"))
    }

    /// Verify **both** signatures over the same payload. Returns
    /// `Ok()` only if both verify; otherwise reports which leg
    /// failed via [`HybridSignatureFailure`].
    pub fn verify_payload(
        &self,
        payload: &[u8],
        ed_signature: &[u8],
        pqc_signature: &[u8],
    ) -> Result<(), HybridSignatureFailure> {
        if self.verify_ed25519(payload, ed_signature).is_err() {
            return Err(HybridSignatureFailure::Ed25519);
        }
        if self.verify_ml_dsa(payload, pqc_signature).is_err() {
            return Err(HybridSignatureFailure::MlDsa);
        }
        Ok(())
    }
}

impl std::fmt::Debug for HybridVerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridVerifyingKey")
            .field("ed25519", &self.ed25519)
            .finish()
    }
}

/// Diagnostic returned by [`HybridVerifyingKey::verify_payload`]
/// when one of the legs fails. Surfaced as a sub-field of the
/// chain-walker's `SignatureInvalid` variant so operators can tell
/// which leg of the hybrid scheme broke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HybridSignatureFailure {
    /// The classical Ed25519 leg failed verification.
    Ed25519,
    /// The post-quantum ML-DSA-65 leg failed verification.
    MlDsa,
}

impl std::fmt::Display for HybridSignatureFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HybridSignatureFailure::Ed25519 => f.write_str("ed25519"),
            HybridSignatureFailure::MlDsa => f.write_str("ml-dsa-65"),
        }
    }
}

// --- Encoding helpers -------------------------------------------------------

/// Encode an ML-DSA-65 signature to its fixed-size byte form.
pub fn encode_ml_dsa_signature(sig: &MlDsaSignature) -> Vec<u8> {
    sig.encode().as_slice().to_vec()
}

/// Decode an ML-DSA-65 signature from a fixed-size byte slice.
pub fn decode_ml_dsa_signature(bytes: &[u8]) -> CryptoResult<MlDsaSignature> {
    if bytes.len() != ML_DSA_65_SIGNATURE_LEN {
        return Err(CryptoError::Frame(format!(
            "manifest: ml-dsa-65 signature must be {ML_DSA_65_SIGNATURE_LEN} bytes, got {}",
            bytes.len()
        )));
    }
    let mut buf = EncodedSignature::<MlDsa65>::default();
    buf.as_mut_slice().copy_from_slice(bytes);
    MlDsaSignature::decode(&buf)
        .ok_or_else(|| CryptoError::Frame("manifest: ml-dsa-65 signature decode failed".into()))
}

/// Encode an ML-DSA-65 signing key to its fixed-size byte form.
pub fn encode_ml_dsa_signing_key(sk: &MlDsaSigningKey) -> Vec<u8> {
    sk.encode().as_slice().to_vec()
}

/// Decode an ML-DSA-65 signing key from its fixed-size byte form.
pub fn decode_ml_dsa_signing_key(bytes: &[u8]) -> CryptoResult<MlDsaSigningKey> {
    if bytes.len() != ML_DSA_65_SIGNING_KEY_LEN {
        return Err(CryptoError::Frame(format!(
            "ml-dsa-65 signing key must be {ML_DSA_65_SIGNING_KEY_LEN} bytes, got {}",
            bytes.len()
        )));
    }
    let mut buf = EncodedSigningKey::<MlDsa65>::default();
    buf.as_mut_slice().copy_from_slice(bytes);
    Ok(MlDsaSigningKey::decode(&buf))
}

/// Encode an ML-DSA-65 verifying key to its fixed-size byte form.
pub fn encode_ml_dsa_verifying_key(vk: &MlDsaVerifyingKey) -> Vec<u8> {
    vk.encode().as_slice().to_vec()
}

/// Decode an ML-DSA-65 verifying key from its fixed-size byte form.
pub fn decode_ml_dsa_verifying_key(bytes: &[u8]) -> CryptoResult<MlDsaVerifyingKey> {
    if bytes.len() != ML_DSA_65_VERIFYING_KEY_LEN {
        return Err(CryptoError::Frame(format!(
            "ml-dsa-65 verifying key must be {ML_DSA_65_VERIFYING_KEY_LEN} bytes, got {}",
            bytes.len()
        )));
    }
    let mut buf = EncodedVerifyingKey::<MlDsa65>::default();
    buf.as_mut_slice().copy_from_slice(bytes);
    Ok(MlDsaVerifyingKey::decode(&buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn fresh() -> HybridSigningKey {
        let mut rng = OsRng;
        HybridSigningKey::generate(&mut rng)
    }

    #[test]
    fn round_trip_signs_and_verifies_both_legs() {
        let sk = fresh();
        let vk = sk.verifying_key();
        let payload = b"hybrid-manifest-canonical-payload";
        let (ed, ml) = sk.sign_payload(payload).unwrap();
        let ed_bytes = ed.to_bytes().to_vec();
        let ml_bytes = encode_ml_dsa_signature(&ml);
        assert_eq!(ed_bytes.len(), SIGNATURE_LENGTH);
        assert_eq!(ml_bytes.len(), ML_DSA_65_SIGNATURE_LEN);
        vk.verify_payload(payload, &ed_bytes, &ml_bytes)
            .expect("hybrid verify");
    }

    #[test]
    fn rejects_wrong_ed25519_key() {
        let sk_a = fresh();
        let sk_b = fresh();
        let vk_mixed = HybridVerifyingKey {
            ed25519: sk_b.verifying_key().ed25519,
            ml_dsa: sk_a.verifying_key().ml_dsa,
        };
        let payload = b"x";
        let (ed, ml) = sk_a.sign_payload(payload).unwrap();
        let err = vk_mixed
            .verify_payload(payload, &ed.to_bytes(), &encode_ml_dsa_signature(&ml))
            .unwrap_err();
        assert_eq!(err, HybridSignatureFailure::Ed25519);
    }

    #[test]
    fn rejects_wrong_ml_dsa_key() {
        let sk_a = fresh();
        let sk_b = fresh();
        let vk_mixed = HybridVerifyingKey {
            ed25519: sk_a.verifying_key().ed25519,
            ml_dsa: sk_b.verifying_key().ml_dsa,
        };
        let payload = b"y";
        let (ed, ml) = sk_a.sign_payload(payload).unwrap();
        let err = vk_mixed
            .verify_payload(payload, &ed.to_bytes(), &encode_ml_dsa_signature(&ml))
            .unwrap_err();
        assert_eq!(err, HybridSignatureFailure::MlDsa);
    }

    #[test]
    fn ml_dsa_signing_key_round_trip_through_bytes() {
        let sk = fresh();
        let bytes = encode_ml_dsa_signing_key(sk.ml_dsa());
        assert_eq!(bytes.len(), ML_DSA_65_SIGNING_KEY_LEN);
        let decoded = decode_ml_dsa_signing_key(&bytes).unwrap();
        // Re-sign with the decoded key and verify under the
        // original verifying key.
        let payload = b"reload";
        let sig = decoded.sign_deterministic(payload, b"").unwrap();
        sk.verifying_key()
            .verify_ml_dsa(payload, &encode_ml_dsa_signature(&sig))
            .unwrap();
    }

    #[test]
    fn ml_dsa_verifying_key_round_trip_through_bytes() {
        let sk = fresh();
        let bytes = encode_ml_dsa_verifying_key(sk.ml_dsa_verifying_key());
        assert_eq!(bytes.len(), ML_DSA_65_VERIFYING_KEY_LEN);
        let decoded = decode_ml_dsa_verifying_key(&bytes).unwrap();
        let payload = b"reload";
        let (_, ml) = sk.sign_payload(payload).unwrap();
        decoded
            .verify(payload, &ml)
            .expect("decoded verifying key still verifies");
    }

    #[test]
    fn truncated_ml_dsa_signature_is_rejected() {
        let bytes = vec![0u8; ML_DSA_65_SIGNATURE_LEN - 1];
        let err = decode_ml_dsa_signature(&bytes).unwrap_err();
        match err {
            CryptoError::Frame(_) => {}
            other => panic!("expected Frame, got {other:?}"),
        }
    }
}
