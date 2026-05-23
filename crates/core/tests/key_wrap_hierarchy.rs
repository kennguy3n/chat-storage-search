//! Integration test for the [`crate::crypto::key_wrap`] module wired
//! against the real key hierarchy. must guarantee that:
//!
//! * `K_asset` survives a wrap-then-unwrap round trip under any
//!   hierarchy root,
//! * the same `K_asset` produces *different* wrapped bytes under
//!   `K_archive_root` vs `K_backup_root`,
//! * a wrapped key from one root cannot be unwrapped under another.

use kchat_core::crypto::key_hierarchy::{
    derive_archive_root, derive_backup_root, derive_search_root, KeyMaterial,
};
use kchat_core::crypto::key_wrap::{unwrap_k_asset, wrap_k_asset, WRAPPED_KEY_LEN};

fn k_asset_fixture() -> [u8; 32] {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(13).wrapping_add(7);
    }
    k
}

#[test]
fn wrap_unwrap_under_archive_root_round_trips() {
    let master = KeyMaterial::from_bytes([0x11; 32]);
    let archive_root = derive_archive_root(&master).unwrap();
    let k_asset = k_asset_fixture();

    let wrapped = wrap_k_asset(&k_asset, &archive_root).unwrap();
    assert_eq!(wrapped.len(), WRAPPED_KEY_LEN);
    let unwrapped = unwrap_k_asset(&wrapped, &archive_root).unwrap();
    assert_eq!(unwrapped, k_asset);
}

#[test]
fn wrap_unwrap_under_backup_root_round_trips() {
    let master = KeyMaterial::from_bytes([0x22; 32]);
    let backup_root = derive_backup_root(&master).unwrap();
    let k_asset = k_asset_fixture();

    let wrapped = wrap_k_asset(&k_asset, &backup_root).unwrap();
    let unwrapped = unwrap_k_asset(&wrapped, &backup_root).unwrap();
    assert_eq!(unwrapped, k_asset);
}

#[test]
fn archive_and_backup_wraps_are_distinct() {
    let master = KeyMaterial::from_bytes([0x33; 32]);
    let archive_root = derive_archive_root(&master).unwrap();
    let backup_root = derive_backup_root(&master).unwrap();
    let k_asset = k_asset_fixture();

    let wrapped_archive = wrap_k_asset(&k_asset, &archive_root).unwrap();
    let wrapped_backup = wrap_k_asset(&k_asset, &backup_root).unwrap();
    assert_ne!(wrapped_archive, wrapped_backup);
}

#[test]
fn cross_root_unwrap_is_rejected() {
    let master = KeyMaterial::from_bytes([0x44; 32]);
    let archive_root = derive_archive_root(&master).unwrap();
    let backup_root = derive_backup_root(&master).unwrap();
    let search_root = derive_search_root(&master).unwrap();
    let k_asset = k_asset_fixture();

    let wrapped = wrap_k_asset(&k_asset, &archive_root).unwrap();

    // Same K_asset, different roots — none of the wrong-root
    // unwraps should succeed.
    assert!(unwrap_k_asset(&wrapped, &backup_root).is_err());
    assert!(unwrap_k_asset(&wrapped, &search_root).is_err());
}
