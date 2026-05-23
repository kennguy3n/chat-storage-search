//! Privacy / dummy-request padding for the archive prefetch path.
//!
//! `docs/DESIGN.md §5.6` proposes optional **dummy request
//! padding** to break the per-bucket access-pattern fingerprint
//! that an honest-but-curious backend could otherwise build. With
//! [`crate::config::PrivacyLevel::High`] the prefetch path mixes
//! freshly-generated dummy segment ids in with the real ones; the
//! transport will 404 on every dummy id and the caller silently
//! drops those entries.
//!
//! This module owns the **policy**:
//!
//! * [`should_pad`] — does the configuration want padding?
//! * [`compute_padding_count`] — how many dummies for `n` real ids?
//!   Default is `min(2 * n, MAX_PADDING_PER_BUCKET)`. The cap is
//!   intentionally generous (32) — the marginal cost of a few more
//!   404s is small and the marginal privacy gain shrinks fast as
//!   the dummy / real ratio grows.
//! * [`generate_dummy_segment_id`] — fresh UUIDv4 per dummy.
//! * [`pad_with_dummy_requests`] — interleave the two lists in a
//!   deterministically random order so the position of each real
//!   id is shuffled, not just appended.
//!
//! The output of [`pad_with_dummy_requests`] is **just a list of
//! ids** — wiring it into the transport-level fetch is the job of
//! `archive/prefetch.rs`.

use rand::seq::SliceRandom;
use rand::thread_rng;
use uuid::Uuid;

use crate::config::{KChatCoreConfig, PrivacyLevel};

/// Cap on the absolute number of dummy ids appended to one
/// [`pad_with_dummy_requests`] call. Bumped via PR if the
/// orchestration layer ever wants a larger bound.
pub const MAX_PADDING_PER_BUCKET: usize = 32;

/// Default ratio of dummy ids to real ids when
/// [`compute_padding_count`] is not overridden by the caller.
pub const DEFAULT_PADDING_MULTIPLIER: usize = 2;

/// Generate a fresh dummy segment id. UUIDv4 (random) so a backend
/// observer cannot tell dummies apart from real UUIDv7-derived
/// segment ids without checking the database.
pub fn generate_dummy_segment_id() -> String {
    Uuid::new_v4().to_string()
}

/// Whether the prefetch should pad given `config.privacy_level`.
pub fn should_pad(config: &KChatCoreConfig) -> bool {
    matches!(config.privacy_level, PrivacyLevel::High)
}

/// Number of dummies to emit for a batch of `real_count` real ids.
///
/// `0` real ids → `0` dummies. We don't manufacture chatter when
/// the user is otherwise idle; the threat model is *fingerprinting
/// real activity*, not *concealing the absence of activity*. If
/// the orchestration layer wants a heartbeat it can call
/// [`generate_dummy_segment_id`] directly.
pub fn compute_padding_count(real_count: usize) -> usize {
    if real_count == 0 {
        return 0;
    }
    real_count
        .saturating_mul(DEFAULT_PADDING_MULTIPLIER)
        .min(MAX_PADDING_PER_BUCKET)
}

/// Pad a list of real segment ids with `padding_count` dummy ids
/// and shuffle the result so the position of each real id is no
/// longer guessable from its index. The original list is not
/// mutated. Every dummy id is unique.
pub fn pad_with_dummy_requests(real_segment_ids: &[String], padding_count: usize) -> Vec<String> {
    let mut padded: Vec<String> = Vec::with_capacity(real_segment_ids.len() + padding_count);
    padded.extend_from_slice(real_segment_ids);
    for _ in 0..padding_count {
        padded.push(generate_dummy_segment_id());
    }
    let mut rng = thread_rng();
    padded.shuffle(&mut rng);
    padded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Platform;
    use std::path::PathBuf;

    fn fresh_config(level: PrivacyLevel) -> KChatCoreConfig {
        KChatCoreConfig::new(PathBuf::from("/tmp/dummy"), Platform::MacOs, "tenant")
            .with_privacy_level(level)
    }

    #[test]
    fn padding_disabled_by_default() {
        let config = KChatCoreConfig::new(PathBuf::from("/tmp/d"), Platform::MacOs, "t");
        assert_eq!(config.privacy_level, PrivacyLevel::Standard);
        assert!(!should_pad(&config));
    }

    #[test]
    fn padding_enabled_when_high() {
        let config = fresh_config(PrivacyLevel::High);
        assert!(should_pad(&config));
    }

    #[test]
    fn compute_padding_count_for_empty_real_list_is_zero() {
        assert_eq!(compute_padding_count(0), 0);
    }

    #[test]
    fn compute_padding_count_doubles_real_count_under_cap() {
        assert_eq!(compute_padding_count(1), 2);
        assert_eq!(compute_padding_count(5), 10);
        assert_eq!(compute_padding_count(15), 30);
    }

    #[test]
    fn compute_padding_count_caps_at_max() {
        assert_eq!(compute_padding_count(64), MAX_PADDING_PER_BUCKET);
        assert_eq!(compute_padding_count(usize::MAX), MAX_PADDING_PER_BUCKET);
    }

    #[test]
    fn dummy_segment_id_is_a_valid_uuid() {
        for _ in 0..16 {
            let id = generate_dummy_segment_id();
            let parsed = Uuid::parse_str(&id).expect("dummy id must be a valid UUID");
            // We chose UUIDv4 specifically — assert that.
            assert_eq!(parsed.get_version_num(), 4);
        }
    }

    #[test]
    fn pad_with_no_real_ids_emits_dummies_only() {
        let padded = pad_with_dummy_requests(&[], 4);
        assert_eq!(padded.len(), 4);
        for id in &padded {
            assert_eq!(Uuid::parse_str(id).unwrap().get_version_num(), 4);
        }
    }

    #[test]
    fn pad_preserves_every_real_id() {
        let real: Vec<String> = (0..5).map(|i| format!("real-segment-{i:02}")).collect();
        let padded = pad_with_dummy_requests(&real, 7);
        assert_eq!(padded.len(), 5 + 7);
        for r in &real {
            assert!(
                padded.contains(r),
                "padded list must preserve real id {r:?}"
            );
        }
    }

    #[test]
    fn pad_with_zero_padding_returns_real_ids_unchanged_in_count() {
        let real: Vec<String> = vec!["a".into(), "b".into(), "c".into()];
        let padded = pad_with_dummy_requests(&real, 0);
        assert_eq!(padded.len(), 3);
        let mut sorted = padded.clone();
        sorted.sort();
        let mut expected = real.clone();
        expected.sort();
        assert_eq!(sorted, expected);
    }

    #[test]
    fn pad_dummy_ids_are_unique() {
        let real: Vec<String> = vec!["only-real".into()];
        let padded = pad_with_dummy_requests(&real, 16);
        assert_eq!(padded.len(), 17);
        let mut deduped = padded.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(
            deduped.len(),
            padded.len(),
            "every padded id must be unique"
        );
    }

    #[test]
    fn pad_shuffles_so_real_ids_are_not_always_at_the_front() {
        // Generate 16 padded lists and verify *at least one* of
        // them places the real id off index 0. With 17 slots and a
        // uniform shuffle, P(real-at-0) = 1/17, so the chance all
        // 16 lists place it at index 0 is (1/17)^16 ≈ 1e-19 — well
        // below the threshold for a flaky test.
        let real: Vec<String> = vec!["only-real".into()];
        let mut moved_off_zero = false;
        for _ in 0..16 {
            let padded = pad_with_dummy_requests(&real, 16);
            if padded.first() != Some(&"only-real".to_string()) {
                moved_off_zero = true;
                break;
            }
        }
        assert!(moved_off_zero, "shuffle never moved the real id off 0");
    }
}
