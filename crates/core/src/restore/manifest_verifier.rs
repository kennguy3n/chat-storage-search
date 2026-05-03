//! Phase-4 backup-manifest chain verification.
//!
//! Walks an ordered slice of [`BackupManifest`] from generation 0
//! to the latest and verifies:
//!
//! * Every manifest's Ed25519 [`manifest_signature`] under the
//!   supplied verifying key.
//! * The chain link
//!   `manifest[n].previous_manifest_hash == compute_manifest_hash(manifest[n-1])`.
//! * Genesis (`generation == 0`) has
//!   [`GENESIS_PREVIOUS_HASH`].
//! * No gaps (consecutive `generation` values).
//! * No empty input.
//!
//! On any violation the walker stops and returns the corresponding
//! [`VerificationError`] variant.
//!
//! This module is read-only; it does not mutate the connection or
//! the input slice.
//!
//! [`manifest_signature`]: crate::formats::manifest::BackupManifest::manifest_signature

use ed25519_dalek::VerifyingKey;
use thiserror::Error;

use crate::formats::manifest::{
    compute_manifest_hash, verify_backup_manifest, BackupManifest, GENESIS_PREVIOUS_HASH,
};

/// Failure modes for [`verify_manifest_chain`]. Each variant
/// carries enough context for the orchestrator to surface a
/// useful message to the user / telemetry.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum VerificationError {
    /// `manifests` is empty.
    #[error("manifest chain is empty")]
    EmptyChain,

    /// `manifest[generation]` failed Ed25519 verification.
    #[error("manifest {generation}: signature failed verification")]
    SignatureInvalid {
        /// Generation of the failing manifest.
        generation: u64,
    },

    /// `previous_manifest_hash` did not match the previous
    /// manifest's CBOR hash.
    #[error(
        "manifest {generation}: chain break — \
         expected previous_manifest_hash = {expected:?}, got {actual:?}"
    )]
    ChainBreak {
        /// Generation of the offending manifest.
        generation: u64,
        /// Hash the verifier expected (computed from the prior
        /// manifest's CBOR).
        expected: [u8; 32],
        /// Hash actually stored in the manifest.
        actual: [u8; 32],
    },

    /// A generation is missing from the input slice.
    #[error("manifest chain has a gap: missing generation {missing_generation}")]
    GapDetected {
        /// First absent generation, in chain order.
        missing_generation: u64,
    },

    /// Genesis manifest's `previous_manifest_hash` was non-zero.
    #[error("genesis manifest: previous_manifest_hash must be all zeros, got {actual:?}")]
    GenesisHashNotZero {
        /// The non-zero hash supplied by the genesis manifest.
        actual: [u8; 32],
    },

    /// Could not CBOR-encode a manifest to compute its hash. The
    /// only realistic cause is corrupt input.
    #[error("manifest {generation}: could not compute hash for chain step")]
    HashComputationFailed {
        /// Generation of the manifest that could not be hashed.
        generation: u64,
    },
}

/// Walk the manifest chain from `manifests[0]` (genesis) to
/// `manifests.last()`. Returns `Ok(())` only if every check
/// passes.
pub fn verify_manifest_chain(
    manifests: &[BackupManifest],
    signing_public_key: &VerifyingKey,
) -> Result<(), VerificationError> {
    if manifests.is_empty() {
        return Err(VerificationError::EmptyChain);
    }

    // 1) Genesis discipline.
    let genesis = &manifests[0];
    if genesis.generation != 0 {
        return Err(VerificationError::GapDetected {
            missing_generation: 0,
        });
    }
    if genesis.previous_manifest_hash != GENESIS_PREVIOUS_HASH {
        return Err(VerificationError::GenesisHashNotZero {
            actual: genesis.previous_manifest_hash,
        });
    }

    // 2) Walk the chain.
    let mut prev: Option<&BackupManifest> = None;
    for manifest in manifests {
        // Verify signature first — a bad signature short-circuits
        // before any hash work.
        verify_backup_manifest(manifest, signing_public_key).map_err(|_| {
            VerificationError::SignatureInvalid {
                generation: manifest.generation,
            }
        })?;

        if let Some(prev_manifest) = prev {
            // 2a) No gaps.
            let expected_gen = prev_manifest.generation + 1;
            if manifest.generation != expected_gen {
                return Err(VerificationError::GapDetected {
                    missing_generation: expected_gen,
                });
            }
            // 2b) Chain link.
            let expected_hash = compute_manifest_hash(prev_manifest).map_err(|_| {
                VerificationError::HashComputationFailed {
                    generation: prev_manifest.generation,
                }
            })?;
            if manifest.previous_manifest_hash != expected_hash {
                return Err(VerificationError::ChainBreak {
                    generation: manifest.generation,
                    expected: expected_hash,
                    actual: manifest.previous_manifest_hash,
                });
            }
        }

        prev = Some(manifest);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::event_journal::{BackupEvent, BackupEventType};
    use crate::backup::manifest_builder::{build_backup_manifest, BackupManifestBuildRequest};
    use crate::backup::segment_builder::{
        BackupSegmentBuildRequest, BackupSegmentBuilder, BuiltBackupSegment,
    };
    use crate::crypto::key_hierarchy::{
        derive_backup_manifest, derive_backup_root, derive_backup_segment, KeyMaterial,
    };
    use crate::formats::SegmentType;
    use ed25519_dalek::SigningKey;
    use uuid::Uuid;

    fn fake_segment(k_seg: &KeyMaterial) -> BuiltBackupSegment {
        let event = BackupEvent {
            event_type: BackupEventType::MessageReceived,
            conversation_id: Some(Uuid::now_v7()),
            message_id: Some(Uuid::now_v7()),
            payload: vec![0xAB],
            created_at_ms: 1_777_000_000_000,
        };
        BackupSegmentBuilder::new()
            .build_segment(
                BackupSegmentBuildRequest {
                    events: vec![event],
                    segment_type: SegmentType::Events,
                },
                k_seg,
            )
            .unwrap()
    }

    fn build_chain(
        signing_key: &SigningKey,
        n: u64,
    ) -> (Vec<BackupManifest>, KeyMaterial, KeyMaterial) {
        let identity = KeyMaterial::from_bytes([0xDD; 32]);
        let backup_root = derive_backup_root(&identity).unwrap();
        let k_seg = derive_backup_segment(&backup_root, &Uuid::now_v7().into_bytes()).unwrap();
        let k_man = derive_backup_manifest(&backup_root, b"manifest-tests").unwrap();

        let mut manifests = Vec::with_capacity(n as usize);
        for i in 0..n {
            let prev = if i == 0 {
                None
            } else {
                Some(&manifests[(i - 1) as usize])
            };
            let sealed = build_backup_manifest(
                BackupManifestBuildRequest {
                    segments: &[fake_segment(&k_seg)],
                    search_index_shards: vec![],
                    media_references: vec![],
                    tombstones: vec![],
                    previous: prev,
                    device_id: "device-A".into(),
                },
                signing_key,
                &k_man,
            )
            .unwrap();
            manifests.push(sealed.manifest);
        }

        (manifests, k_seg, k_man)
    }

    #[test]
    fn empty_chain_errors() {
        let signing = SigningKey::from_bytes(&[0x99; 32]);
        let err = verify_manifest_chain(&[], &signing.verifying_key()).unwrap_err();
        assert_eq!(err, VerificationError::EmptyChain);
    }

    #[test]
    fn single_genesis_passes() {
        let signing = SigningKey::from_bytes(&[0x99; 32]);
        let (chain, _, _) = build_chain(&signing, 1);
        verify_manifest_chain(&chain, &signing.verifying_key()).unwrap();
    }

    #[test]
    fn three_generation_chain_passes() {
        let signing = SigningKey::from_bytes(&[0x99; 32]);
        let (chain, _, _) = build_chain(&signing, 3);
        verify_manifest_chain(&chain, &signing.verifying_key()).unwrap();
    }

    #[test]
    fn tampered_signature_is_detected() {
        let signing = SigningKey::from_bytes(&[0x99; 32]);
        let (mut chain, _, _) = build_chain(&signing, 2);
        // Flip a byte in the signature on generation 1.
        if !chain[1].manifest_signature.is_empty() {
            chain[1].manifest_signature[0] ^= 0xFF;
        }
        let err = verify_manifest_chain(&chain, &signing.verifying_key()).unwrap_err();
        assert_eq!(err, VerificationError::SignatureInvalid { generation: 1 });
    }

    #[test]
    fn chain_break_is_detected() {
        let signing = SigningKey::from_bytes(&[0x99; 32]);
        let (mut chain, k_seg, k_man) = build_chain(&signing, 2);
        // Forge a generation-1 manifest whose previous_manifest_hash is wrong.
        let bad = build_backup_manifest(
            BackupManifestBuildRequest {
                segments: &[fake_segment(&k_seg)],
                search_index_shards: vec![],
                media_references: vec![],
                tombstones: vec![],
                previous: None, // genesis-shape but with generation forced below
                device_id: "device-A".into(),
            },
            &signing,
            &k_man,
        )
        .unwrap();
        // Force generation = 1 with a previous_manifest_hash of zeros.
        let mut forged = bad.manifest.clone();
        forged.generation = 1;
        forged.previous_manifest_hash = [0u8; 32];
        // Re-sign with the modified payload so the signature itself
        // verifies — only the chain link is broken.
        crate::formats::manifest::sign_backup_manifest(&mut forged, &signing).unwrap();
        chain[1] = forged;

        let err = verify_manifest_chain(&chain, &signing.verifying_key()).unwrap_err();
        match err {
            VerificationError::ChainBreak { generation, .. } => assert_eq!(generation, 1),
            other => panic!("expected ChainBreak, got {other:?}"),
        }
    }

    #[test]
    fn gap_in_generations_is_detected() {
        let signing = SigningKey::from_bytes(&[0x99; 32]);
        let (chain, _, _) = build_chain(&signing, 3);
        // Drop the middle manifest.
        let chain_with_gap: Vec<_> = vec![chain[0].clone(), chain[2].clone()];
        let err = verify_manifest_chain(&chain_with_gap, &signing.verifying_key()).unwrap_err();
        assert_eq!(
            err,
            VerificationError::GapDetected {
                missing_generation: 1
            }
        );
    }

    #[test]
    fn missing_generation_zero_errors() {
        let signing = SigningKey::from_bytes(&[0x99; 32]);
        let (chain, _, _) = build_chain(&signing, 2);
        // Drop the genesis.
        let chain_without_genesis: Vec<_> = chain.into_iter().skip(1).collect();
        let err =
            verify_manifest_chain(&chain_without_genesis, &signing.verifying_key()).unwrap_err();
        assert_eq!(
            err,
            VerificationError::GapDetected {
                missing_generation: 0
            }
        );
    }

    #[test]
    fn nonzero_previous_hash_on_genesis_errors() {
        let signing = SigningKey::from_bytes(&[0x99; 32]);
        let (mut chain, _, _) = build_chain(&signing, 1);
        chain[0].previous_manifest_hash = [0xAA; 32];
        // Re-sign so the signature verifies but the genesis hash check fails.
        crate::formats::manifest::sign_backup_manifest(&mut chain[0], &signing).unwrap();
        let err = verify_manifest_chain(&chain, &signing.verifying_key()).unwrap_err();
        match err {
            VerificationError::GenesisHashNotZero { actual } => assert_eq!(actual, [0xAA; 32]),
            other => panic!("expected GenesisHashNotZero, got {other:?}"),
        }
    }

    #[test]
    fn wrong_public_key_fails() {
        let signing = SigningKey::from_bytes(&[0x99; 32]);
        let other_pub = SigningKey::from_bytes(&[0xAA; 32]).verifying_key();
        let (chain, _, _) = build_chain(&signing, 2);
        let err = verify_manifest_chain(&chain, &other_pub).unwrap_err();
        match err {
            VerificationError::SignatureInvalid { generation } => assert_eq!(generation, 0),
            other => panic!("expected SignatureInvalid, got {other:?}"),
        }
    }
}
