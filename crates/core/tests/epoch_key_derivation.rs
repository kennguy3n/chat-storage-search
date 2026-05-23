//! Integration test vectors for the archive epoch key
//! hierarchy.
//!
//! `docs/DESIGN.md §2.1` defines the per-epoch indirection
//! between `K_archive_root` and the per-segment / per-manifest
//! keys: each "epoch" gets its own subkey derived as
//!
//! ```text
//! K_archive_epoch(epoch_id) = HKDF(K_archive_root,
//! info = "kchat-archive-epoch-v1" || epoch_id)
//! ```
//!
//! These tests exercise the surface that the orchestration layer
//! relies on:
//!
//! 1. Determinism — same `(K_archive_root, epoch_id)` always
//!    yields the same `K_archive_epoch`.
//! 2. Domain separation — different `epoch_id`s produce different
//!    epoch keys.
//! 3. Wrap / unwrap round trip under AES-256-KW so prior-epoch
//!    keys can be persisted in the manifest chain.
//! 4. Cross-epoch decrypt — encrypt under epoch A's segment key,
//!    "rotate" by deriving a new epoch key, then unwrap epoch A's
//!    key from the persisted blob and recover the original
//!    plaintext.
//! 5. HKDF info-string layout — the DESIGN.md spec
//!    pins the prefix as `b"kchat-archive-epoch-v1"`.

use kchat_core::crypto::aead::xchacha20_poly1305::{open, seal, NONCE_LEN};
use kchat_core::crypto::key_hierarchy::{
    derive_archive_epoch_key, derive_archive_root, derive_archive_segment_key, info,
    unwrap_epoch_key, wrap_epoch_key, KeyMaterial,
};

/// Fixed master key fixture so the integration test is fully
/// deterministic against the DESIGN.md HKDF spec.
fn master() -> KeyMaterial {
    KeyMaterial::from_bytes([0xAB; 32])
}

#[test]
fn deterministic_epoch_derivation() {
    let root = derive_archive_root(&master()).unwrap();
    let a = derive_archive_epoch_key(&root, "2026-04").unwrap();
    let b = derive_archive_epoch_key(&root, "2026-04").unwrap();
    assert_eq!(
        a.as_bytes(),
        b.as_bytes(),
        "K_archive_epoch must be a pure function of (K_archive_root, epoch_id)",
    );
}

#[test]
fn different_epochs_produce_different_keys() {
    let root = derive_archive_root(&master()).unwrap();
    let april = derive_archive_epoch_key(&root, "2026-04").unwrap();
    let may = derive_archive_epoch_key(&root, "2026-05").unwrap();
    assert_ne!(
        april.as_bytes(),
        may.as_bytes(),
        "different epoch_ids must derive disjoint epoch keys",
    );
}

#[test]
fn epoch_key_wrap_unwrap_round_trip() {
    let root = derive_archive_root(&master()).unwrap();
    let epoch = derive_archive_epoch_key(&root, "2026-04").unwrap();
    let wrapped = wrap_epoch_key(&root, &epoch).unwrap();
    let unwrapped = unwrap_epoch_key(&root, &wrapped).unwrap();
    assert_eq!(
        unwrapped.as_bytes(),
        epoch.as_bytes(),
        "AES-256-KW under K_archive_root must round-trip",
    );
}

#[test]
fn cross_epoch_segment_decrypt() {
    // key-rotation flow: build a segment under epoch A's
    // key, persist `wrap_epoch_key(K_archive_root, epoch_A)`,
    // "rotate" to epoch B (i.e. derive a fresh epoch_B key for
    // future segments), then later unwrap epoch A's key from the
    // manifest and decrypt the segment.
    let root = derive_archive_root(&master()).unwrap();

    let epoch_a = derive_archive_epoch_key(&root, "2026-04").unwrap();
    let seg_key_a = derive_archive_segment_key(&epoch_a, "seg-A").unwrap();
    let plaintext = b"archive segment payload encrypted under epoch A";
    let aad = b"KCHAT_ARC_SEG_PAYLOAD_V1";
    let nonce = [0x11u8; NONCE_LEN];
    let ciphertext = seal(seg_key_a.as_bytes(), &nonce, plaintext, aad).unwrap();

    let wrapped_epoch_a = wrap_epoch_key(&root, &epoch_a).unwrap();

    // Rotate: drop epoch A and start using epoch B for new
    // material. The wrapped epoch-A blob is what survives the
    // rotation.
    drop(epoch_a);
    drop(seg_key_a);
    let _epoch_b = derive_archive_epoch_key(&root, "2026-05").unwrap();

    let recovered_epoch_a = unwrap_epoch_key(&root, &wrapped_epoch_a).unwrap();
    let recovered_seg_a = derive_archive_segment_key(&recovered_epoch_a, "seg-A").unwrap();
    let recovered_plaintext = open(recovered_seg_a.as_bytes(), &nonce, &ciphertext, aad).unwrap();
    assert_eq!(recovered_plaintext, plaintext);
}

#[test]
fn epoch_key_info_string_matches_spec() {
    // `docs/DESIGN.md §2.1` pins the HKDF info prefix as
    // `b"kchat-archive-epoch-v1"`. If a future change tries to
    // bump that label, every existing archive on disk would no
    // longer decrypt — so the constant is part of the wire format
    // and must be guarded by an integration test, not just a
    // module-private one.
    assert_eq!(info::ARCHIVE_EPOCH, b"kchat-archive-epoch-v1");
}
