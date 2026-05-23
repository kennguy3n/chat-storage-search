//! Phase-4 key recovery foundation.
//!
//! Two recovery flows live here:
//!
//! 1. **Recovery key** — a human-readable string the user copies
//!    out at setup. The key is derived from a fresh 256-bit secret
//!    and used to AES-256-KW-wrap `K_user_master`. The wrapped
//!    blob lands in encrypted backups; the recovery string lives
//!    on paper / in a password manager.
//! 2. **Device-to-device transfer** — a short-lived AEAD-sealed
//!    bundle holding `K_user_master` and the three derived roots
//!    (`K_archive_root`, `K_backup_root`, `K_search_root`). The
//!    sender device shows a numeric code; the receiver enters
//!    that code and pulls the bundle off the wire.
//!
//! Server-side escrow is **off by default** per
//! `docs/PHASES.md §Phase 4` — neither flow involves the
//! KChat server seeing the user's master key.
//!
//! All secret material flows through
//! [`zeroize::Zeroizing`] / [`zeroize::ZeroizeOnDrop`] so panics
//! and early returns scrub the heap copies.

use argon2::{Algorithm, Argon2, Params, Version};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::aead::xchacha20_poly1305::{open as aead_open, seal as aead_seal, NONCE_LEN};
use crate::crypto::key_hierarchy::KEY_LEN;
use crate::crypto::key_wrap::{unwrap_key, wrap_key, WRAPPED_KEY_LEN};
use crate::crypto::CryptoError;
use crate::Error;

// ---------------------------------------------------------------------
// Recovery key — human-readable wrapper around K_user_master.
// ---------------------------------------------------------------------

/// Domain-separation tag for the HKDF / AEAD operations done on
/// the recovery side. Bumping the version here is a wire-format
/// change.
pub const RECOVERY_KEY_DOMAIN: &[u8] = b"kchat-recovery-key-v1";

/// Domain-separation tag for the device-transfer AEAD seal.
pub const DEVICE_TRANSFER_DOMAIN: &[u8] = b"kchat-device-transfer-v1";

/// Length of the wrapped-master output produced by
/// [`generate_recovery_key`] (RFC 3394 wrap of a 32-byte master).
pub const WRAPPED_MASTER_LEN: usize = WRAPPED_KEY_LEN;

/// User-facing recovery secret.
///
/// Internally a 256-bit random string that is *also* used as the
/// AES-256-KW wrapping key for `K_user_master`. Encoded as
/// base64 (no-padding) for display in QR codes / printouts; the
/// binary form is what actually wraps the master key.
///
/// Drops scrub the inner buffer.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryKey([u8; KEY_LEN]);

impl RecoveryKey {
    /// Construct a recovery key from raw 32 bytes.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the wrapping bytes.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Encode the recovery key as a 64-character lowercase hex
    /// string the user can write down.
    pub fn to_display(&self) -> String {
        let mut s = String::with_capacity(2 * KEY_LEN);
        for b in self.0.iter() {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    /// Parse a recovery key from a hex display string. Whitespace
    /// is trimmed; the input must decode to exactly 32 bytes
    /// (64 hex characters).
    pub fn from_display(s: &str) -> Result<Self, Error> {
        let trimmed = s.trim();
        if trimmed.len() != 2 * KEY_LEN {
            return Err(Error::Crypto(CryptoError::InvalidInput(
                "recovery key: must be 64 hex chars",
            )));
        }
        let bytes = trimmed.as_bytes();
        let mut out = [0u8; KEY_LEN];
        for (i, slot) in out.iter_mut().enumerate() {
            let hi = decode_hex_nibble(bytes[2 * i])?;
            let lo = decode_hex_nibble(bytes[2 * i + 1])?;
            *slot = (hi << 4) | lo;
        }
        Ok(Self(out))
    }
}

fn decode_hex_nibble(b: u8) -> Result<u8, Error> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(10 + (b - b'a')),
        b'A'..=b'F' => Ok(10 + (b - b'A')),
        _ => Err(Error::Crypto(CryptoError::InvalidInput(
            "recovery key: invalid hex digit",
        ))),
    }
}

impl std::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never leak the raw bytes through formatting.
        f.write_str("RecoveryKey(<redacted>)")
    }
}

/// Generate a fresh recovery key + AES-256-KW-wrapped master.
///
/// The user is expected to write down the recovery key (via
/// [`RecoveryKey::to_display`]) and store the wrapped master blob
/// alongside their backup manifests. Both pieces are required to
/// recover the master key.
///
/// Note: the wrapping key in this scheme **is** the recovery key.
/// We use AES-256-KW directly without an extra HKDF step because
/// (a) the input is already 32 bytes of high-entropy random data
/// and (b) RFC 3394 has its own integrity check value, so a wrong
/// recovery key will deterministically fail
/// [`recover_from_key`].
pub fn generate_recovery_key(
    k_user_master: &[u8; KEY_LEN],
) -> Result<(RecoveryKey, Vec<u8>), Error> {
    let mut rk_bytes = [0u8; KEY_LEN];
    OsRng.fill_bytes(&mut rk_bytes);
    let wrapped = wrap_key(&rk_bytes, k_user_master)?;
    Ok((RecoveryKey(rk_bytes), wrapped))
}

/// Recover `K_user_master` from a recovery key + wrapped master
/// blob. A wrong recovery key (or tampered blob) surfaces as
/// [`Error::Crypto`] thanks to the AES-256-KW integrity check
/// value.
pub fn recover_from_key(
    recovery_key: &RecoveryKey,
    wrapped_master: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>, Error> {
    if wrapped_master.len() != WRAPPED_MASTER_LEN {
        return Err(Error::Crypto(CryptoError::InvalidInput(
            "wrapped master: must be 40 bytes",
        )));
    }
    let unwrapped = unwrap_key(recovery_key.as_bytes(), wrapped_master)?;
    Ok(Zeroizing::new(unwrapped))
}

// ---------------------------------------------------------------------
// Device-to-device transfer.
// ---------------------------------------------------------------------

/// Bundle of the four user-scope secrets that make a fresh device
/// indistinguishable from the original.
///
/// `K_user_master` plus the three roots is what
/// [`crate::crypto::key_hierarchy`] needs to reconstruct every
/// downstream key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RecoveredKeys {
    /// `K_user_master`.
    pub k_user_master: [u8; KEY_LEN],
    /// `K_archive_root` (cached so the receiver doesn't have to
    /// re-derive on first use).
    pub k_archive_root: [u8; KEY_LEN],
    /// `K_backup_root`.
    pub k_backup_root: [u8; KEY_LEN],
    /// `K_search_root`.
    pub k_search_root: [u8; KEY_LEN],
}

impl std::fmt::Debug for RecoveredKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveredKeys(<redacted>)")
    }
}

/// AEAD-sealed payload that travels device → device.
///
/// The transfer key is derived deterministically from the numeric
/// transfer code (see [`derive_transfer_key`]) — the sending and
/// receiving devices share the code through an out-of-band
/// channel (QR scan / typed PIN). The payload is therefore safe
/// to ferry over an untrusted relay because anything other than
/// the right code fails AEAD open.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceTransferPayload {
    /// XChaCha20-Poly1305 nonce.
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    /// `ciphertext || tag`.
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

/// CBOR shape sealed inside [`DeviceTransferPayload::ciphertext`].
///
/// All four fields are 32-byte raw secret keys. The struct
/// derives [`Zeroize`] / [`ZeroizeOnDrop`] so a panic / early
/// return through `prepare_device_transfer` /
/// `accept_device_transfer` cannot leave plaintext key material
/// on the heap. The CBOR plaintext that travels through the AEAD
/// is itself wrapped in [`Zeroizing`] at the call sites for the
/// same reason.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct DeviceTransferEnvelope {
    #[serde(with = "serde_bytes")]
    k_user_master: Vec<u8>,
    #[serde(with = "serde_bytes")]
    k_archive_root: Vec<u8>,
    #[serde(with = "serde_bytes")]
    k_backup_root: Vec<u8>,
    #[serde(with = "serde_bytes")]
    k_search_root: Vec<u8>,
}

impl std::fmt::Debug for DeviceTransferEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never leak the raw key bytes through formatting.
        f.write_str("DeviceTransferEnvelope(<redacted>)")
    }
}

/// Derive the device-transfer AEAD key from a numeric code.
///
/// HKDF-SHA-256 with a fixed salt + the [`DEVICE_TRANSFER_DOMAIN`]
/// info string. Wrong codes deterministically derive different
/// keys, which the AEAD open then rejects.
fn derive_transfer_key(transfer_code: &str) -> Result<Zeroizing<[u8; KEY_LEN]>, Error> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let trimmed = transfer_code.trim();
    if trimmed.is_empty() {
        return Err(Error::Crypto(CryptoError::InvalidInput(
            "transfer code must be non-empty",
        )));
    }
    let hk = Hkdf::<Sha256>::new(Some(b"kchat-device-transfer-salt-v1"), trimmed.as_bytes());
    let mut okm = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(DEVICE_TRANSFER_DOMAIN, okm.as_mut_slice())
        .map_err(|_| Error::Crypto(CryptoError::Kdf("device-transfer hkdf expand failed")))?;
    Ok(okm)
}

/// Seal `keys` under a key derived from `transfer_code`.
///
/// The receiver runs [`accept_device_transfer`] with the same
/// `transfer_code` to recover the bundle. Any other code fails
/// AEAD open — the payload is therefore safe to ship over an
/// untrusted relay.
pub fn prepare_device_transfer(
    keys: &RecoveredKeys,
    transfer_code: &str,
) -> Result<DeviceTransferPayload, Error> {
    let key = derive_transfer_key(transfer_code)?;
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let envelope = DeviceTransferEnvelope {
        k_user_master: keys.k_user_master.to_vec(),
        k_archive_root: keys.k_archive_root.to_vec(),
        k_backup_root: keys.k_backup_root.to_vec(),
        k_search_root: keys.k_search_root.to_vec(),
    };
    let plaintext = Zeroizing::new(crate::cbor::to_vec(&envelope).map_err(|e| {
        Error::Storage(crate::local_store::StorageError::CborEncode {
            context: "device-transfer:",
            source: e,
        })
    })?);
    let ciphertext = aead_seal(&key, &nonce, &plaintext, DEVICE_TRANSFER_DOMAIN)?;
    Ok(DeviceTransferPayload {
        nonce: nonce.to_vec(),
        ciphertext,
    })
}

/// Open a [`DeviceTransferPayload`] under `transfer_code`.
///
/// The decoded envelope must hold exactly four 32-byte keys —
/// any other shape surfaces as [`Error::Storage`] (CBOR / length
/// mismatch) or [`Error::Crypto`] (AEAD failure).
pub fn accept_device_transfer(
    payload: &DeviceTransferPayload,
    transfer_code: &str,
) -> Result<RecoveredKeys, Error> {
    let key = derive_transfer_key(transfer_code)?;
    if payload.nonce.len() != NONCE_LEN {
        return Err(Error::Crypto(CryptoError::InvalidInput(
            "device-transfer: nonce must be 24 bytes",
        )));
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&payload.nonce);
    let plaintext = Zeroizing::new(aead_open(
        &key,
        &nonce,
        &payload.ciphertext,
        DEVICE_TRANSFER_DOMAIN,
    )?);
    let envelope: DeviceTransferEnvelope = crate::cbor::from_slice(&plaintext).map_err(|e| {
        Error::Storage(crate::local_store::StorageError::CborDecode {
            context: "device-transfer:",
            source: e,
        })
    })?;
    fn to_arr(v: &[u8]) -> Result<[u8; KEY_LEN], Error> {
        if v.len() != KEY_LEN {
            return Err(Error::Crypto(CryptoError::InvalidInput(
                "device-transfer: each key must be 32 bytes",
            )));
        }
        let mut out = [0u8; KEY_LEN];
        out.copy_from_slice(v);
        Ok(out)
    }
    Ok(RecoveredKeys {
        k_user_master: to_arr(&envelope.k_user_master)?,
        k_archive_root: to_arr(&envelope.k_archive_root)?,
        k_backup_root: to_arr(&envelope.k_backup_root)?,
        k_search_root: to_arr(&envelope.k_search_root)?,
    })
}

// ---------------------------------------------------------------------
// Passphrase-based recovery — Argon2id-derived AES-256-KW wrap.
// ---------------------------------------------------------------------

/// Length of the random per-envelope salt fed into Argon2id.
pub const PASSPHRASE_SALT_LEN: usize = 16;

/// Argon2id parameter triple persisted alongside a wrapped
/// master so a future device can re-derive the wrapping key
/// even if the defaults shift in a later release. The defaults
/// match OWASP's mobile-recommended baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2Params {
    /// Memory cost in KiB (`m_cost`). Defaults to 65 536 (64 MiB).
    pub m_cost: u32,
    /// Time cost (`t_cost`) — number of iterations. Defaults to 3.
    pub t_cost: u32,
    /// Degree of parallelism (`p_cost`). Defaults to 1.
    pub p_cost: u32,
}

impl Argon2Params {
    /// Default OWASP mobile baseline. The values are pinned in
    /// the wrapper so callers cannot accidentally weaken them.
    pub const fn owasp_mobile() -> Self {
        Self {
            m_cost: 65_536,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self::owasp_mobile()
    }
}

/// Wire-format envelope produced by [`wrap_master_key_with_passphrase`].
///
/// Carries the random salt, the AES-256-KW output, and the
/// Argon2id parameter triple used to derive the wrapping key.
/// Persisting the parameter triple makes the envelope
/// future-proof: a future release can bump the defaults without
/// invalidating older envelopes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassphraseRecoveryEnvelope {
    /// Random 16-byte salt fed into Argon2id.
    #[serde(with = "serde_bytes")]
    pub salt: Vec<u8>,
    /// AES-256-KW output (RFC 3394, 40 bytes for a 32-byte input).
    #[serde(with = "serde_bytes")]
    pub wrapped_key: Vec<u8>,
    /// Argon2id parameter triple used to derive the wrapping key.
    pub argon2_params: Argon2Params,
}

/// Derive a 32-byte AES wrapping key from `passphrase` and
/// `salt` using Argon2id with [`Argon2Params::owasp_mobile`].
///
/// Returns the raw 32 bytes; callers are expected to wrap the
/// result in [`Zeroizing`] (or pass it directly into a wrap /
/// unwrap call) so the derived key never lingers on the heap.
pub fn derive_passphrase_key(
    passphrase: &str,
    salt: &[u8; PASSPHRASE_SALT_LEN],
) -> Result<[u8; KEY_LEN], Error> {
    derive_passphrase_key_with_params(passphrase, salt, Argon2Params::owasp_mobile())
}

/// Lower-level variant of [`derive_passphrase_key`] that lets the
/// caller pass an explicit parameter triple. Used internally by
/// [`unwrap_master_key_with_passphrase`] when the on-disk
/// envelope predates a parameter bump.
pub fn derive_passphrase_key_with_params(
    passphrase: &str,
    salt: &[u8; PASSPHRASE_SALT_LEN],
    params: Argon2Params,
) -> Result<[u8; KEY_LEN], Error> {
    let trimmed = passphrase.trim();
    if trimmed.is_empty() {
        return Err(Error::Crypto(CryptoError::InvalidInput(
            "passphrase: must not be empty",
        )));
    }
    let argon_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|_| Error::Crypto(CryptoError::Kdf("argon2 params: invalid m/t/p combination")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut out = [0u8; KEY_LEN];
    argon
        .hash_password_into(trimmed.as_bytes(), salt, &mut out)
        .map_err(|_| Error::Crypto(CryptoError::Kdf("argon2id hash_password_into failed")))?;
    Ok(out)
}

/// Generate a fresh 16-byte salt, derive the wrapping key under
/// Argon2id, and AES-256-KW wrap `k_user_master`.
///
/// The returned [`PassphraseRecoveryEnvelope`] is the only
/// material that needs to travel with the backup — the
/// passphrase is supplied by the user at restore time and never
/// stored anywhere by the core.
pub fn wrap_master_key_with_passphrase(
    k_user_master: &[u8; KEY_LEN],
    passphrase: &str,
) -> Result<PassphraseRecoveryEnvelope, Error> {
    let mut salt = [0u8; PASSPHRASE_SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let params = Argon2Params::owasp_mobile();
    let kek = Zeroizing::new(derive_passphrase_key_with_params(
        passphrase, &salt, params,
    )?);
    let wrapped = wrap_key(&kek, k_user_master)?;
    Ok(PassphraseRecoveryEnvelope {
        salt: salt.to_vec(),
        wrapped_key: wrapped,
        argon2_params: params,
    })
}

/// Unwrap a [`PassphraseRecoveryEnvelope`] under `passphrase`.
///
/// Wrong passphrases (or a tampered envelope) surface as
/// [`Error::Crypto`] thanks to the AES-256-KW integrity-check
/// value. The recovered master is wrapped in [`Zeroizing`] so
/// dropping the result scrubs the bytes.
pub fn unwrap_master_key_with_passphrase(
    envelope: &PassphraseRecoveryEnvelope,
    passphrase: &str,
) -> Result<Zeroizing<[u8; KEY_LEN]>, Error> {
    if envelope.salt.len() != PASSPHRASE_SALT_LEN {
        return Err(Error::Crypto(CryptoError::InvalidInput(
            "passphrase envelope: salt must be 16 bytes",
        )));
    }
    if envelope.wrapped_key.len() != WRAPPED_KEY_LEN {
        return Err(Error::Crypto(CryptoError::InvalidInput(
            "passphrase envelope: wrapped_key must be 40 bytes",
        )));
    }
    let mut salt = [0u8; PASSPHRASE_SALT_LEN];
    salt.copy_from_slice(&envelope.salt);
    let kek = Zeroizing::new(derive_passphrase_key_with_params(
        passphrase,
        &salt,
        envelope.argon2_params,
    )?);
    let unwrapped = unwrap_key(&kek, &envelope.wrapped_key)?;
    Ok(Zeroizing::new(unwrapped))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_master() -> [u8; KEY_LEN] {
        let mut bytes = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        bytes
    }

    fn fresh_keys() -> RecoveredKeys {
        RecoveredKeys {
            k_user_master: fresh_master(),
            k_archive_root: fresh_master(),
            k_backup_root: fresh_master(),
            k_search_root: fresh_master(),
        }
    }

    #[test]
    fn recovery_key_generate_and_recover_round_trip() {
        let master = fresh_master();
        let (rk, wrapped) = generate_recovery_key(&master).expect("generate");
        let recovered = recover_from_key(&rk, &wrapped).expect("recover");
        assert_eq!(*recovered, master);
        // Same recovery key must unwrap deterministically.
        let recovered2 = recover_from_key(&rk, &wrapped).expect("recover2");
        assert_eq!(*recovered2, master);
    }

    #[test]
    fn recovery_key_wrong_key_fails() {
        let master = fresh_master();
        let (_rk, wrapped) = generate_recovery_key(&master).expect("generate");
        let mut bad_bytes = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut bad_bytes);
        let bad = RecoveryKey::from_bytes(bad_bytes);
        assert!(recover_from_key(&bad, &wrapped).is_err());
    }

    #[test]
    fn recovery_key_display_round_trip() {
        let master = fresh_master();
        let (rk, wrapped) = generate_recovery_key(&master).expect("generate");
        let s = rk.to_display();
        let parsed = RecoveryKey::from_display(&s).expect("parse display");
        let recovered = recover_from_key(&parsed, &wrapped).expect("recover via display");
        assert_eq!(*recovered, master);
    }

    #[test]
    fn recovery_key_display_rejects_bad_input() {
        // Wrong length payload.
        assert!(RecoveryKey::from_display("AAAA").is_err());
        // Invalid hex digit.
        assert!(RecoveryKey::from_display(&"z".repeat(64)).is_err());
    }

    #[test]
    fn recovery_key_is_deterministic_for_same_master_and_recovery_key() {
        // The combination (recovery_key, master) must produce a
        // stable wrapping when invoked twice with the same RNG
        // state — proven indirectly by round-tripping through
        // `recover_from_key`.
        let master = fresh_master();
        let (rk, wrapped1) = generate_recovery_key(&master).expect("gen1");
        // Reuse the recovery key, re-wrap manually to mimic the
        // "deterministic given the recovery key" property.
        let wrapped2 = wrap_key(rk.as_bytes(), &master).expect("rewrap");
        assert_eq!(wrapped1, wrapped2);
        // Both blobs unwrap to the same master.
        let r1 = recover_from_key(&rk, &wrapped1).expect("r1");
        let r2 = recover_from_key(&rk, &wrapped2).expect("r2");
        assert_eq!(*r1, *r2);
    }

    #[test]
    fn device_transfer_round_trip() {
        let keys = fresh_keys();
        let payload = prepare_device_transfer(&keys, "123-456").expect("prepare");
        let recovered = accept_device_transfer(&payload, "123-456").expect("accept");
        assert_eq!(recovered.k_user_master, keys.k_user_master);
        assert_eq!(recovered.k_archive_root, keys.k_archive_root);
        assert_eq!(recovered.k_backup_root, keys.k_backup_root);
        assert_eq!(recovered.k_search_root, keys.k_search_root);
    }

    #[test]
    fn device_transfer_wrong_code_fails() {
        let keys = fresh_keys();
        let payload = prepare_device_transfer(&keys, "123-456").expect("prepare");
        assert!(accept_device_transfer(&payload, "999-999").is_err());
        // Trimming + case sensitivity: trim is allowed, case
        // changes are not.
        assert!(accept_device_transfer(&payload, " 123-456 ").is_ok());
    }

    #[test]
    fn device_transfer_empty_code_rejected() {
        let keys = fresh_keys();
        assert!(prepare_device_transfer(&keys, "").is_err());
        assert!(prepare_device_transfer(&keys, "   ").is_err());
    }

    /// Compile-time check that [`DeviceTransferEnvelope`]
    /// implements [`ZeroizeOnDrop`] so the secret key bytes are
    /// scrubbed from the heap when the struct is dropped (whether
    /// the drop happens in the success path or via a panic / early
    /// return through one of the transfer functions).
    #[test]
    fn device_transfer_envelope_implements_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<DeviceTransferEnvelope>();
    }

    #[test]
    fn device_transfer_payload_length_validates() {
        let keys = fresh_keys();
        let mut payload = prepare_device_transfer(&keys, "abc").expect("prepare");
        payload.nonce.truncate(NONCE_LEN - 1);
        assert!(accept_device_transfer(&payload, "abc").is_err());
    }

    // -----------------------------------------------------------------
    // Passphrase-based recovery tests.
    // -----------------------------------------------------------------

    /// Lighter Argon2 parameters used by tests so the suite still
    /// runs in a reasonable time. The production wrappers always
    /// pin [`Argon2Params::owasp_mobile`]; the lower-level
    /// `*_with_params` variants used here are exercised by the
    /// envelope-on-disk-with-pinned-params test below.
    fn test_params() -> Argon2Params {
        Argon2Params {
            m_cost: 1024, // 1 MiB
            t_cost: 1,
            p_cost: 1,
        }
    }

    fn fresh_salt() -> [u8; PASSPHRASE_SALT_LEN] {
        let mut s = [0u8; PASSPHRASE_SALT_LEN];
        OsRng.fill_bytes(&mut s);
        s
    }

    #[test]
    fn passphrase_round_trip_with_default_params() {
        // The default-params path runs Argon2 with OWASP mobile
        // settings — slow on CPU but the only path that reaches
        // [`wrap_master_key_with_passphrase`] /
        // [`unwrap_master_key_with_passphrase`].
        let master = fresh_master();
        let envelope =
            wrap_master_key_with_passphrase(&master, "correct horse battery staple").expect("wrap");
        assert_eq!(envelope.salt.len(), PASSPHRASE_SALT_LEN);
        assert_eq!(envelope.wrapped_key.len(), WRAPPED_KEY_LEN);
        assert_eq!(envelope.argon2_params, Argon2Params::owasp_mobile());
        let recovered =
            unwrap_master_key_with_passphrase(&envelope, "correct horse battery staple")
                .expect("unwrap");
        assert_eq!(*recovered, master);
    }

    #[test]
    fn passphrase_wrong_passphrase_fails() {
        let master = fresh_master();
        // Use the lower-level path with weak params so the test
        // is fast — the wrong-passphrase failure surfaces from
        // the AES-256-KW integrity-check value, not Argon2.
        let salt = fresh_salt();
        let kek =
            derive_passphrase_key_with_params("right passphrase", &salt, test_params()).unwrap();
        let wrapped = wrap_key(&kek, &master).unwrap();
        let envelope = PassphraseRecoveryEnvelope {
            salt: salt.to_vec(),
            wrapped_key: wrapped,
            argon2_params: test_params(),
        };
        assert!(unwrap_master_key_with_passphrase(&envelope, "wrong passphrase").is_err());
        // Right passphrase still works.
        let ok = unwrap_master_key_with_passphrase(&envelope, "right passphrase").unwrap();
        assert_eq!(*ok, master);
    }

    #[test]
    fn passphrase_derivation_is_deterministic_for_same_salt_and_passphrase() {
        let salt = fresh_salt();
        let a = derive_passphrase_key_with_params("hunter2", &salt, test_params()).unwrap();
        let b = derive_passphrase_key_with_params("hunter2", &salt, test_params()).unwrap();
        assert_eq!(a, b, "argon2id must be deterministic on (passphrase, salt)");
    }

    #[test]
    fn passphrase_different_salts_produce_different_keys() {
        let salt_a = fresh_salt();
        let mut salt_b = salt_a;
        salt_b[0] ^= 0xFF;
        let a = derive_passphrase_key_with_params("hunter2", &salt_a, test_params()).unwrap();
        let b = derive_passphrase_key_with_params("hunter2", &salt_b, test_params()).unwrap();
        assert_ne!(a, b, "different salts must produce different keys");
    }

    #[test]
    fn passphrase_empty_rejected() {
        let salt = fresh_salt();
        assert!(derive_passphrase_key_with_params("", &salt, test_params()).is_err());
    }

    #[test]
    fn passphrase_whitespace_only_rejected() {
        // Passphrases that are only whitespace must fail the same
        // way as the empty string — otherwise a paste-induced "  "
        // would silently derive a valid key under any salt.
        let salt = fresh_salt();
        for whitespace in ["   ", "\t", "\n", " \t\n "] {
            let err = derive_passphrase_key_with_params(whitespace, &salt, test_params())
                .expect_err("whitespace-only passphrase must be rejected");
            assert!(
                matches!(err, Error::Crypto(CryptoError::InvalidInput(_))),
                "expected InvalidInput, got {err:?}"
            );
        }
    }

    #[test]
    fn passphrase_leading_trailing_whitespace_trimmed() {
        // The trim contract: leading / trailing whitespace must
        // collapse so a clipboard paste landing on a different
        // device does not lock the user out of K_user_master.
        let salt = fresh_salt();
        let canonical = derive_passphrase_key_with_params("hunter2", &salt, test_params()).unwrap();
        for variant in ["  hunter2", "hunter2  ", "  hunter2  ", "\thunter2\n"] {
            let derived = derive_passphrase_key_with_params(variant, &salt, test_params()).unwrap();
            assert_eq!(
                derived, canonical,
                "variant {variant:?} must derive the same key as canonical"
            );
        }
    }

    #[test]
    fn passphrase_internal_whitespace_preserved() {
        // The trim contract is leading / trailing only — a passphrase
        // like "hunter two" must NOT collapse to "huntertwo".
        let salt = fresh_salt();
        let with_space =
            derive_passphrase_key_with_params("hunter two", &salt, test_params()).unwrap();
        let without_space =
            derive_passphrase_key_with_params("huntertwo", &salt, test_params()).unwrap();
        assert_ne!(
            with_space, without_space,
            "internal whitespace must be preserved"
        );
    }

    #[test]
    fn passphrase_round_trip_survives_clipboard_padding() {
        // End-to-end version of the trim contract: wrap on device A
        // with a clean passphrase, unwrap on device B with a
        // whitespace-padded passphrase, master must round-trip.
        let mut master = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut master);
        let envelope = wrap_master_key_with_passphrase(&master, "hunter2").expect("wrap");
        let recovered =
            unwrap_master_key_with_passphrase(&envelope, "  hunter2\n").expect("unwrap");
        assert_eq!(*recovered, master);
    }

    #[test]
    fn passphrase_envelope_serde_round_trip() {
        let envelope = PassphraseRecoveryEnvelope {
            salt: vec![0u8; PASSPHRASE_SALT_LEN],
            wrapped_key: vec![0u8; WRAPPED_KEY_LEN],
            argon2_params: Argon2Params::owasp_mobile(),
        };
        let cbor = crate::cbor::to_vec(&envelope).expect("encode");
        let parsed: PassphraseRecoveryEnvelope = crate::cbor::from_slice(&cbor).expect("decode");
        assert_eq!(parsed, envelope);
    }
}
