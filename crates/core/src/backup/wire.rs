//! On-wire CBOR-serializable bundles for the backup transport.
//!
//! [`crate::backup::sinks::BackupSink`] accepts opaque
//! ciphertext bytes (`&[u8]`) for both the manifest and the
//! per-segment upload, so the orchestration layer has to choose a
//! canonical serialisation for the *bundle* it hands to the sink:
//!
//! * A sealed manifest has more than just `ciphertext` — the
//!   verifier needs the cleartext [`BackupManifest`] (so it can
//!   re-encode for hash chain + signature verification) plus the
//!   XChaCha20-Poly1305 `nonce` that the manifest body was sealed
//!   under.
//! * A sealed segment carries `ciphertext + nonce + merkle_root`
//!   AND a wrapped per-segment key
//!   (`AES-256-KW(k_segment, K_backup_root)`). The wrapped key is
//!   the same construction as
//!   [`crate::formats::manifest::ManifestMediaRef::wrapped_k_asset`]
//!   the on-wire authority for "which key opens this thing" lives
//!   alongside the ciphertext, not in a separate side channel.
//!
//! Why this module exists at all:
//!
//! The in-process types
//! [`crate::backup::manifest_builder::SealedBackupManifest`] and
//! [`crate::backup::segment_builder::BuiltBackupSegment`] are
//! convenient for the orchestrator but the manifest variant
//! cannot be `Serialize`/`Deserialize` (its
//! [`crate::crypto::signing::HybridManifestSignature`] field
//! wraps an `ml-dsa-65` signature whose underlying type does not
//! implement serde). The segment variant *could* be serde-derived
//! today but does not carry the wrapped per-segment key — and
//! adding the wrapped key to [`BuiltBackupSegment`] would have
//! pulled `K_backup_root` into the builder, which has been
//! deliberately kept root-agnostic (the orchestrator already
//! derives `k_segment` from the root and passes it in).
//!
//! Both invariants ([`BackupManifest`] is serde, and the manifest
//! body carries its own signatures, so we can serialise
//! `manifest + nonce + ciphertext` directly) are exploited here.
//! The bundles are versioned by a leading `magic + version` pair
//! so a future on-wire change can be detected and rejected
//! deterministically rather than producing silent
//! mis-deserialisations.
//!
//! ## Encoding
//!
//! Each bundle uses the crate-wide CBOR codec
//! ([`crate::cbor`]) which pins canonical encoding rules across
//! the project. The bytes produced by [`SealedManifestBundle::encode`]
//! are what gets handed verbatim to
//! [`crate::backup::sinks::BackupSink::upload_backup_manifest`]; the
//! restore path round-trips them via
//! [`SealedManifestBundle::decode`]. Same pattern for the segment
//! bundle.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::backup::manifest_builder::SealedBackupManifest;
use crate::backup::segment_builder::BuiltBackupSegment;
use crate::crypto::aead::xchacha20_poly1305::NONCE_LEN;
use crate::crypto::key_hierarchy::{KeyMaterial, KEY_LEN};
use crate::crypto::key_wrap::{unwrap_k_asset, wrap_k_asset};
use crate::formats::manifest::BackupManifest;
use crate::formats::serde_bytes_array;
use crate::formats::SegmentType;
use crate::{Error, Result};

/// Magic bytes stamped on a [`SealedManifestBundle`]. Lets a
/// reader reject misrouted bytes (a segment bundle accidentally
/// uploaded under a manifest object key, or some other CBOR-shaped
/// blob from an unrelated subsystem) without paying for a full
/// decode.
pub const MANIFEST_BUNDLE_MAGIC: &[u8; 16] = b"KCHAT_BAK_M_V1\0\0";

/// Magic bytes stamped on a [`SealedSegmentBundle`].
pub const SEGMENT_BUNDLE_MAGIC: &[u8; 16] = b"KCHAT_BAK_S_V1\0\0";

/// Current bundle on-wire version. Bumped when the field layout
/// changes; readers reject bundles whose `version` does not match
/// the version they were compiled against.
pub const BUNDLE_VERSION: u16 = 1;

/// Hard cap on the byte length of a single [`SealedManifestBundle`]
/// before CBOR decoding. A manifest body is small in practice (a
/// list of segment refs + signatures + a short ciphertext over the
/// CBOR-encoded manifest), so 1 MiB is generous yet bounded — it
/// prevents a malicious or corrupted sink from forcing the decoder
/// to allocate gigabytes for `ciphertext` / `manifest` before the
/// magic / version check fires. Defence in depth: the SHA-256 +
/// signature verification downstream would also reject, but this
/// guard fails fast before allocation pressure builds up.
pub const MAX_MANIFEST_BUNDLE_BYTES: usize = 1 << 20;

/// Hard cap on the byte length of a single [`SealedSegmentBundle`]
/// before CBOR decoding. Segments hold zstd-compressed CBOR events
/// — production runs target a few thousand events per segment, so
/// 64 MiB is well above the realistic upper bound while still
/// preventing unbounded allocation from a crafted blob.
pub const MAX_SEGMENT_BUNDLE_BYTES: usize = 64 << 20;

/// CBOR-serializable on-wire bundle for a sealed backup manifest.
///
/// Carries the cleartext [`BackupManifest`] (signatures live
/// inside it), the AEAD nonce sealing the manifest body, and the
/// AEAD ciphertext itself. The `device_id` is included so the
/// restoring side can reconstruct the AAD passed to
/// [`crate::backup::manifest_builder::open_sealed_backup_manifest`]
/// without relying on caller-supplied side-band data — the AAD
/// binds the manifest_id, generation, merkle_root, AND device_id,
/// so all four must travel with the ciphertext.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealedManifestBundle {
    /// Always [`MANIFEST_BUNDLE_MAGIC`]. Rejected on mismatch.
    #[serde(with = "serde_bytes_array")]
    pub magic: [u8; 16],
    /// Always [`BUNDLE_VERSION`].
    pub version: u16,
    /// The signed manifest body. Both hybrid signature legs
    /// (Ed25519 + ML-DSA-65) are carried inside this struct's
    /// `manifest_signature` / `pqc_signature` fields.
    pub manifest: BackupManifest,
    /// 24-byte XChaCha20-Poly1305 nonce sealing `ciphertext`.
    #[serde(with = "serde_bytes_array")]
    pub nonce: [u8; NONCE_LEN],
    /// AEAD ciphertext over the canonical CBOR encoding of
    /// `manifest` under `K_backup_manifest`.
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
    /// Stable device id stamped into the AAD at seal time. The
    /// restoring side needs this to rebuild the AAD even on a
    /// fresh device whose local DB has not yet been hydrated.
    pub device_id: String,
}

impl SealedManifestBundle {
    /// Wrap a freshly-built [`SealedBackupManifest`] into the
    /// CBOR-serializable on-wire form. The `device_id` MUST match
    /// the one passed to
    /// [`crate::backup::manifest_builder::build_backup_manifest`]
    /// or the restore side will fail to open the AEAD.
    pub fn from_sealed(sealed: &SealedBackupManifest, device_id: String) -> Self {
        Self {
            magic: *MANIFEST_BUNDLE_MAGIC,
            version: BUNDLE_VERSION,
            manifest: sealed.manifest.clone(),
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext.clone(),
            device_id,
        }
    }

    /// CBOR-encode the bundle into bytes suitable for
    /// [`crate::backup::sinks::BackupSink::upload_backup_manifest`].
    pub fn encode(&self) -> Result<Vec<u8>> {
        crate::cbor::to_vec(self)
            .map_err(|e| Error::Storage(format!("manifest bundle CBOR encode: {e}").into()))
    }

    /// CBOR-decode a manifest bundle produced by
    /// [`Self::encode`]. Rejects on magic / version mismatch.
    ///
    /// Inputs longer than [`MAX_MANIFEST_BUNDLE_BYTES`] are
    /// rejected before any CBOR decoding so a malicious or
    /// corrupted sink cannot force the decoder to allocate
    /// unbounded memory for the `ciphertext` / `manifest` fields
    /// ahead of the magic / version checks.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_MANIFEST_BUNDLE_BYTES {
            return Err(Error::Storage(
                format!(
                    "manifest bundle: input {} bytes exceeds {}-byte cap",
                    bytes.len(),
                    MAX_MANIFEST_BUNDLE_BYTES,
                )
                .into(),
            ));
        }
        let bundle: Self = crate::cbor::from_slice(bytes)
            .map_err(|e| Error::Storage(format!("manifest bundle CBOR decode: {e}").into()))?;
        if bundle.magic != *MANIFEST_BUNDLE_MAGIC {
            return Err(Error::Storage(
                "manifest bundle: magic mismatch — refusing to decode misrouted bytes".into(),
            ));
        }
        if bundle.version != BUNDLE_VERSION {
            return Err(Error::Storage(
                format!(
                    "manifest bundle: unsupported on-wire version {} (this build expects {})",
                    bundle.version, BUNDLE_VERSION,
                )
                .into(),
            ));
        }
        Ok(bundle)
    }

    /// Reconstitute the in-process [`SealedBackupManifest`] from
    /// this bundle (without the
    /// [`crate::crypto::signing::HybridManifestSignature`] — the
    /// caller verifies signatures via
    /// [`crate::formats::manifest::verify_backup_manifest`]
    /// against `self.manifest` directly, since the signature
    /// fields live inside the manifest body).
    pub fn manifest(&self) -> &BackupManifest {
        &self.manifest
    }
}

/// CBOR-serializable on-wire bundle for a sealed backup segment.
///
/// Mirrors the in-process [`BuiltBackupSegment`] one-for-one with
/// the addition of the wrapped per-segment key. The
/// `K_backup_segment(segment_id)` derivation contract
/// ([`crate::crypto::key_hierarchy::derive_backup_segment`]) is
/// keyed on a `segment_id` chosen at seal time, but the existing
/// [`crate::backup::segment_builder::BackupSegmentBuilder`] does
/// not currently take `K_backup_root` as input — it accepts the
/// pre-derived per-segment key. Carrying the wrapped key on the
/// wire lets the restoring side recover the per-segment key from
/// `K_backup_root` alone, mirroring the
/// [`crate::formats::manifest::ManifestMediaRef::wrapped_k_asset`]
/// convention.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealedSegmentBundle {
    /// Always [`SEGMENT_BUNDLE_MAGIC`]. Rejected on mismatch.
    #[serde(with = "serde_bytes_array")]
    pub magic: [u8; 16],
    /// Always [`BUNDLE_VERSION`].
    pub version: u16,
    /// UUID v7 segment identifier.
    pub segment_id: Uuid,
    /// Mirror of [`BuiltBackupSegment::segment_type`].
    pub segment_type: SegmentType,
    /// 24-byte XChaCha20-Poly1305 nonce sealing `ciphertext`.
    #[serde(with = "serde_bytes_array")]
    pub nonce: [u8; NONCE_LEN],
    /// AEAD ciphertext (zstd-compressed CBOR).
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
    /// BLAKE3 over the plaintext payload — same value as
    /// [`BuiltBackupSegment::merkle_root`]. The AAD that bound the
    /// AEAD seal is `BACKUP_SEGMENT_AAD_MAGIC || segment_id ||
    /// merkle_root`, so the restoring side needs this byte-for-
    /// byte to open the ciphertext.
    #[serde(with = "serde_bytes_array")]
    pub merkle_root: [u8; 32],
    /// Number of events sealed in this segment. Informational —
    /// the canonical count is the length of the decoded payload's
    /// events vector.
    pub event_count: u32,
    /// AES-256-KW (RFC 3394) wrap of the 32-byte per-segment AEAD
    /// key under `K_backup_root`. Exactly 40 bytes (32 key + 8
    /// integrity check value, per
    /// [`crate::crypto::key_wrap::WRAPPED_KEY_LEN`]).
    #[serde(with = "serde_bytes")]
    pub wrapped_k_segment: Vec<u8>,
}

impl SealedSegmentBundle {
    /// Wrap a [`BuiltBackupSegment`] plus its per-segment key
    /// under `K_backup_root` into the CBOR-serializable on-wire
    /// form. Returns an error if the AES-256-KW wrap fails (the
    /// only realistic cause is an invalid wrapping key length,
    /// which the type system normally rules out).
    pub fn from_built(
        built: &BuiltBackupSegment,
        k_segment: &KeyMaterial,
        k_backup_root: &KeyMaterial,
    ) -> Result<Self> {
        // Mirror the codebase-wide key-hygiene idiom
        // (`crates/core/src/archive/epoch_keys.rs:55-71`,
        // `crypto/key_hierarchy.rs:75-78` etc.): the staging copy
        // of the per-segment key sits inside a `Zeroizing<[u8;
        // KEY_LEN]>` so the bytes scrub on drop *unconditionally*
        // — even on the `?` early-return from `wrap_k_asset`,
        // even on a panic, and even if a future contributor adds
        // another fallible operation between the copy and the
        // wrap. A bare `[u8; 32]` + manual `.fill(0)` would only
        // scrub on the happy path.
        let mut k_segment_bytes = Zeroizing::new([0u8; KEY_LEN]);
        k_segment_bytes.copy_from_slice(k_segment.as_bytes());
        let wrapped = wrap_k_asset(&k_segment_bytes, k_backup_root).map_err(Error::Crypto)?;
        // Cast event_count `usize -> u32` defensively. A backup
        // segment never holds more than a few thousand events in
        // practice (the segment builder bounds them by event-seq
        // window), but a malformed builder pumping more than
        // u32::MAX events would silently truncate without this
        // guard. We refuse rather than emit a wrong count.
        let event_count = u32::try_from(built.event_count).map_err(|_| {
            Error::Storage(
                format!(
                    "segment bundle: event_count {} exceeds u32::MAX",
                    built.event_count
                )
                .into(),
            )
        })?;
        Ok(Self {
            magic: *SEGMENT_BUNDLE_MAGIC,
            version: BUNDLE_VERSION,
            segment_id: built.segment_id,
            segment_type: built.segment_type,
            nonce: built.nonce,
            ciphertext: built.ciphertext.clone(),
            merkle_root: built.merkle_root,
            event_count,
            wrapped_k_segment: wrapped,
        })
    }

    /// CBOR-encode the bundle.
    pub fn encode(&self) -> Result<Vec<u8>> {
        crate::cbor::to_vec(self)
            .map_err(|e| Error::Storage(format!("segment bundle CBOR encode: {e}").into()))
    }

    /// CBOR-decode a segment bundle produced by
    /// [`Self::encode`]. Rejects on magic / version mismatch.
    ///
    /// Inputs longer than [`MAX_SEGMENT_BUNDLE_BYTES`] are
    /// rejected before any CBOR decoding so a malicious or
    /// corrupted sink cannot force the decoder to allocate
    /// unbounded memory for the `ciphertext` field ahead of the
    /// magic / version checks.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_SEGMENT_BUNDLE_BYTES {
            return Err(Error::Storage(
                format!(
                    "segment bundle: input {} bytes exceeds {}-byte cap",
                    bytes.len(),
                    MAX_SEGMENT_BUNDLE_BYTES,
                )
                .into(),
            ));
        }
        let bundle: Self = crate::cbor::from_slice(bytes)
            .map_err(|e| Error::Storage(format!("segment bundle CBOR decode: {e}").into()))?;
        if bundle.magic != *SEGMENT_BUNDLE_MAGIC {
            return Err(Error::Storage(
                "segment bundle: magic mismatch — refusing to decode misrouted bytes".into(),
            ));
        }
        if bundle.version != BUNDLE_VERSION {
            return Err(Error::Storage(
                format!(
                    "segment bundle: unsupported on-wire version {} (this build expects {})",
                    bundle.version, BUNDLE_VERSION,
                )
                .into(),
            ));
        }
        Ok(bundle)
    }

    /// Reconstitute the in-process [`BuiltBackupSegment`] from
    /// this bundle. Used by the restore pipeline as the input to
    /// [`crate::backup::segment_builder::decrypt_backup_segment`].
    pub fn to_built(&self) -> BuiltBackupSegment {
        BuiltBackupSegment {
            segment_id: self.segment_id,
            segment_type: self.segment_type,
            nonce: self.nonce,
            ciphertext: self.ciphertext.clone(),
            merkle_root: self.merkle_root,
            event_count: self.event_count as usize,
        }
    }

    /// Unwrap the per-segment AEAD key carried in
    /// [`Self::wrapped_k_segment`] under `K_backup_root`. Returns
    /// `Err(Error::Crypto)` if the wrap is invalid (wrong root key,
    /// tampered bytes).
    pub fn unwrap_segment_key(&self, k_backup_root: &KeyMaterial) -> Result<KeyMaterial> {
        let unwrapped =
            unwrap_k_asset(&self.wrapped_k_segment, k_backup_root).map_err(Error::Crypto)?;
        Ok(KeyMaterial::from_bytes(unwrapped))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::event_journal::{BackupEvent, BackupEventType};
    use crate::backup::manifest_builder::{build_backup_manifest, BackupManifestBuildRequest};
    use crate::backup::segment_builder::{BackupSegmentBuildRequest, BackupSegmentBuilder};
    use crate::crypto::key_hierarchy::{
        derive_backup_manifest, derive_backup_root, derive_backup_segment,
    };
    use crate::crypto::signing::HybridSigningKey;
    use rand::rngs::OsRng;

    /// Build a coherent producer-side fixture: a fresh
    /// `backup_root`, a `(segment_id, k_seg)` pair derived from it
    /// so `derive_backup_segment(root, segment_id) == k_seg`, plus
    /// a per-test `k_man`. Tests pair `segment_id` and `k_seg`
    /// together via [`sample_segment`] below so the seal honours
    /// the same id contract production code uses.
    fn fresh_keys() -> (KeyMaterial, Uuid, KeyMaterial, KeyMaterial) {
        let identity = KeyMaterial::from_bytes([0x11; 32]);
        let backup_root = derive_backup_root(&identity).expect("derive backup root");
        let segment_id = Uuid::now_v7();
        let k_seg = derive_backup_segment(&backup_root, &segment_id.into_bytes()).expect("seg key");
        let k_man = derive_backup_manifest(&backup_root, b"wire-test").expect("man key");
        (backup_root, segment_id, k_seg, k_man)
    }

    /// Seal a single-event segment under a caller-supplied id +
    /// key pair. The fixture mirrors the production contract: the
    /// id stamped into the on-wire bundle MUST be the same id the
    /// `k_seg` was derived from, otherwise a future contributor
    /// adding a `derive_backup_segment(root, segment_id) == k_seg`
    /// assertion would see the segment fail validation despite the
    /// wire round-trip working.
    fn sample_segment(segment_id: Uuid, k_seg: &KeyMaterial) -> BuiltBackupSegment {
        let event = BackupEvent {
            event_type: BackupEventType::MessageReceived,
            conversation_id: Some(Uuid::now_v7()),
            message_id: Some(Uuid::now_v7()),
            payload: b"hello".to_vec(),
            created_at_ms: 1_777_000_000_000,
        };
        BackupSegmentBuilder::new()
            .build_segment_with_id(
                BackupSegmentBuildRequest {
                    events: vec![event],
                    segment_type: SegmentType::Events,
                },
                segment_id,
                k_seg,
            )
            .expect("seal segment")
    }

    #[test]
    fn segment_bundle_round_trips_through_cbor() {
        let (backup_root, segment_id, k_seg, _) = fresh_keys();
        let built = sample_segment(segment_id, &k_seg);
        let bundle = SealedSegmentBundle::from_built(&built, &k_seg, &backup_root).unwrap();
        let bytes = bundle.encode().unwrap();
        let back = SealedSegmentBundle::decode(&bytes).unwrap();
        assert_eq!(back, bundle);
        assert_eq!(back.to_built(), built);
    }

    #[test]
    fn segment_bundle_rejects_wrong_magic() {
        let (backup_root, segment_id, k_seg, _) = fresh_keys();
        let built = sample_segment(segment_id, &k_seg);
        let mut bundle = SealedSegmentBundle::from_built(&built, &k_seg, &backup_root).unwrap();
        bundle.magic = *b"NOT_KCHAT_V1\0\0\0\0";
        let bytes = bundle.encode().unwrap();
        let err = SealedSegmentBundle::decode(&bytes).unwrap_err();
        assert!(format!("{err}").contains("magic mismatch"));
    }

    #[test]
    fn segment_bundle_rejects_wrong_version() {
        let (backup_root, segment_id, k_seg, _) = fresh_keys();
        let built = sample_segment(segment_id, &k_seg);
        let mut bundle = SealedSegmentBundle::from_built(&built, &k_seg, &backup_root).unwrap();
        bundle.version = BUNDLE_VERSION + 1;
        let bytes = bundle.encode().unwrap();
        let err = SealedSegmentBundle::decode(&bytes).unwrap_err();
        assert!(format!("{err}").contains("unsupported on-wire version"));
    }

    #[test]
    fn segment_bundle_wrap_unwrap_round_trip_recovers_key() {
        let (backup_root, segment_id, k_seg, _) = fresh_keys();
        let built = sample_segment(segment_id, &k_seg);
        let bundle = SealedSegmentBundle::from_built(&built, &k_seg, &backup_root).unwrap();
        let recovered = bundle.unwrap_segment_key(&backup_root).unwrap();
        assert_eq!(recovered.as_bytes(), k_seg.as_bytes());
    }

    #[test]
    fn segment_bundle_wrong_root_rejects_unwrap() {
        let (backup_root, segment_id, k_seg, _) = fresh_keys();
        let built = sample_segment(segment_id, &k_seg);
        let bundle = SealedSegmentBundle::from_built(&built, &k_seg, &backup_root).unwrap();
        let wrong_root = KeyMaterial::from_bytes([0x22; 32]);
        let err = bundle.unwrap_segment_key(&wrong_root).unwrap_err();
        assert!(matches!(err, Error::Crypto(_)));
    }

    #[test]
    fn manifest_bundle_round_trips_through_cbor() {
        let (_, segment_id, k_seg, k_man) = fresh_keys();
        let built = sample_segment(segment_id, &k_seg);
        let mut rng = OsRng;
        let signing = HybridSigningKey::generate(&mut rng);
        let sealed = build_backup_manifest(
            BackupManifestBuildRequest {
                segments: std::slice::from_ref(&built),
                search_index_shards: vec![],
                media_references: vec![],
                tombstones: vec![],
                previous: None,
                device_id: "device-wire-test".into(),
                manifest_id: None,
            },
            &signing,
            &k_man,
        )
        .unwrap();
        let bundle = SealedManifestBundle::from_sealed(&sealed, "device-wire-test".to_string());
        let bytes = bundle.encode().unwrap();
        let back = SealedManifestBundle::decode(&bytes).unwrap();
        assert_eq!(back.manifest, sealed.manifest);
        assert_eq!(back.nonce, sealed.nonce);
        assert_eq!(back.ciphertext, sealed.ciphertext);
        assert_eq!(back.device_id, "device-wire-test");
    }

    #[test]
    fn segment_bundle_end_to_end_recovers_payload() {
        // produce → encode → decode → unwrap key → decrypt:
        // exactly the path the restore orchestrator drives. Guards
        // against the regression where any wire-side bit twiddling
        // breaks the segment AAD (the AEAD AAD binds segment_id +
        // merkle_root, so any CBOR roundtrip that mangles them
        // would surface as an "xchacha20-poly1305 open failed"
        // even though the magic / version checks pass).
        let (backup_root, segment_id, k_seg, _) = fresh_keys();
        let built = sample_segment(segment_id, &k_seg);
        let bundle = SealedSegmentBundle::from_built(&built, &k_seg, &backup_root).unwrap();
        let bytes = bundle.encode().unwrap();
        let back = SealedSegmentBundle::decode(&bytes).unwrap();
        let recovered_key = back.unwrap_segment_key(&backup_root).unwrap();
        let reconstituted = back.to_built();
        let payload =
            crate::backup::segment_builder::decrypt_backup_segment(&reconstituted, &recovered_key)
                .expect("decrypt after wire round-trip");
        assert_eq!(payload.events.len(), 1);
    }

    #[test]
    fn manifest_bundle_end_to_end_opens_aead() {
        // Symmetric to the segment end-to-end test: round-trips a
        // sealed manifest through CBOR and verifies the on-wire
        // form still opens against the original `K_backup_manifest`
        // + `device_id`. Catches AAD bit-twiddling regressions on
        // the manifest path.
        //
        // The id binding contract requires that
        // `K_backup_manifest` be derived from the manifest_id that
        // ends up inside the sealed manifest. We allocate the id
        // up front, derive the key from it, and pass the id into
        // [`BackupManifestBuildRequest::manifest_id`] so the
        // builder seals under the same key the restoring side
        // will derive from `bundle.manifest.manifest_id`.
        let (backup_root, segment_id, k_seg, _) = fresh_keys();
        let built = sample_segment(segment_id, &k_seg);
        let mut rng = OsRng;
        let signing = HybridSigningKey::generate(&mut rng);
        let device_id = "device-e2e-test";
        let manifest_id = Uuid::now_v7();
        let k_man = derive_backup_manifest(&backup_root, manifest_id.as_bytes()).expect("k_man");
        let sealed = build_backup_manifest(
            BackupManifestBuildRequest {
                segments: std::slice::from_ref(&built),
                search_index_shards: vec![],
                media_references: vec![],
                tombstones: vec![],
                previous: None,
                device_id: device_id.into(),
                manifest_id: Some(manifest_id),
            },
            &signing,
            &k_man,
        )
        .unwrap();
        assert_eq!(sealed.manifest.manifest_id, manifest_id);
        let bundle = SealedManifestBundle::from_sealed(&sealed, device_id.to_string());
        let bytes = bundle.encode().unwrap();
        let back = SealedManifestBundle::decode(&bytes).unwrap();
        let k_man_at_open =
            derive_backup_manifest(&backup_root, back.manifest.manifest_id.as_bytes()).unwrap();
        // Reconstruct the AAD using *only* fields the restoring
        // side reads back from the on-wire bundle — `back.device_id`
        // rather than the local `device_id` variable. Mirrors the
        // production restore path (`core_impl.rs::fetch_and_decode_
        // manifest_bundle` consumes `bundle.device_id` when rebuilding
        // the AAD; it does not have access to a side-band original).
        // Catches a hypothetical future regression where
        // `device_id` round-tripping diverges from the seal-time
        // value: the AEAD open would fail here even though the
        // CBOR round-trip looked correct.
        assert_eq!(
            back.device_id, device_id,
            "device_id must survive the CBOR round-trip byte-for-byte",
        );
        let aad = crate::backup::manifest_builder::build_manifest_aad(
            &back.manifest.manifest_id,
            back.manifest.generation,
            &back.manifest.merkle_root,
            &back.device_id,
        );
        let opened = crate::crypto::aead::xchacha20_poly1305::open(
            k_man_at_open.as_bytes(),
            &back.nonce,
            &back.ciphertext,
            &aad,
        )
        .expect("open after wire round-trip");
        assert!(!opened.is_empty());
    }

    #[test]
    fn manifest_bundle_rejects_wrong_magic() {
        let (_, segment_id, k_seg, k_man) = fresh_keys();
        let built = sample_segment(segment_id, &k_seg);
        let mut rng = OsRng;
        let signing = HybridSigningKey::generate(&mut rng);
        let sealed = build_backup_manifest(
            BackupManifestBuildRequest {
                segments: std::slice::from_ref(&built),
                search_index_shards: vec![],
                media_references: vec![],
                tombstones: vec![],
                previous: None,
                device_id: "device-wire-test".into(),
                manifest_id: None,
            },
            &signing,
            &k_man,
        )
        .unwrap();
        let mut bundle = SealedManifestBundle::from_sealed(&sealed, "device-wire-test".to_string());
        bundle.magic = *b"NOT_KCHAT_V1\0\0\0\0";
        let bytes = bundle.encode().unwrap();
        let err = SealedManifestBundle::decode(&bytes).unwrap_err();
        assert!(format!("{err}").contains("magic mismatch"));
    }

    #[test]
    fn manifest_bundle_decode_rejects_oversized_input_before_cbor() {
        // Defence in depth against a malicious sink shipping a
        // multi-MiB CBOR blob: `decode` must reject the input on
        // length alone, before ciborium walks the bytes and tries
        // to allocate `ciphertext` / `manifest` from a tampered
        // length header. The body bytes here are intentionally
        // garbage — the cap check fires first.
        let oversized = vec![0u8; MAX_MANIFEST_BUNDLE_BYTES + 1];
        let err = SealedManifestBundle::decode(&oversized).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("exceeds") && msg.contains("byte cap"),
            "expected size-cap error, got: {msg}"
        );
    }

    #[test]
    fn segment_bundle_decode_rejects_oversized_input_before_cbor() {
        // Symmetric to the manifest size-cap guard. Uses a one-
        // page buffer rather than the full cap value to keep the
        // test fast, exploiting the fact that the check is
        // strictly `>`: a vector exactly `MAX + 1` bytes long is
        // rejected without touching the CBOR decoder.
        let oversized = vec![0u8; MAX_SEGMENT_BUNDLE_BYTES + 1];
        let err = SealedSegmentBundle::decode(&oversized).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("exceeds") && msg.contains("byte cap"),
            "expected size-cap error, got: {msg}"
        );
    }
}
