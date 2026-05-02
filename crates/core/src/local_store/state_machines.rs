//! State-machine enums for the local store.
//!
//! `docs/PROPOSAL.md §4` and `docs/ARCHITECTURE.md §5` lock the four
//! per-message state machines (`body_state`, `media_state`,
//! `archive_state`, `backup_state`) and the global `restore_state`.
//! Each enum here matches the state diagrams in those documents
//! exactly:
//!
//! * The variants are **closed** — adding a state is a wire-format
//!   change.
//! * The legal transitions are encoded in `try_transition`. Any
//!   transition not listed in the state diagram is rejected with
//!   [`StateTransitionError::Illegal`].
//! * `Display` and `FromStr` produce / consume the canonical
//!   `snake_case` strings the schema columns use (see
//!   `local_store::schema`).
//! * `Serialize` / `Deserialize` produce the same `snake_case`
//!   strings — good for JSON debug dumps and for any wire-format we
//!   later put a state-machine value into.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Error returned by `try_transition` when a transition is not part
/// of the documented state diagram.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StateTransitionError {
    /// The `from → to` transition is not legal for this state machine.
    #[error("illegal state transition: {from} → {to}")]
    Illegal {
        /// Source state, in canonical snake_case form.
        from: String,
        /// Target state, in canonical snake_case form.
        to: String,
    },

    /// The string did not parse as a known state.
    #[error("unknown state: {0:?}")]
    Unknown(String),
}

// ---------------------------------------------------------------------------
// body_state — PROPOSAL.md §4 / ARCHITECTURE.md §5
// ---------------------------------------------------------------------------

/// Per-message body lifecycle.
///
/// `docs/PROPOSAL.md §4` / `docs/ARCHITECTURE.md §5`. The terminal
/// states ([`BodyState::DeletedForMe`], [`BodyState::DeletedForEveryone`],
/// [`BodyState::Unavailable`]) have no outgoing transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyState {
    /// Body present locally in plaintext (in the SQLCipher database).
    LocalPlainAvailable,
    /// Body present locally but the in-memory key required to read it
    /// is unavailable (lock screen, app suspended).
    LocalEncryptedAvailable,
    /// Body has been offloaded to the personal archive; rehydratable.
    RemoteArchiveOnly,
    /// MLS message has arrived in the delivery store but the local
    /// ingest has not run yet.
    DeliveryStoreOnly,
    /// User deleted the message locally.
    DeletedForMe,
    /// `delete_for_everyone` MLS message processed.
    DeletedForEveryone,
    /// Terminal: backend lost the body and we have no local copy.
    Unavailable,
}

impl BodyState {
    /// Whether `to` is reachable from `self` per the state diagram.
    pub fn try_transition(from: Self, to: Self) -> Result<Self, StateTransitionError> {
        use BodyState::*;
        let ok = matches!(
            (from, to),
            (LocalPlainAvailable, LocalEncryptedAvailable)
                | (LocalEncryptedAvailable, LocalPlainAvailable)
                | (LocalPlainAvailable, RemoteArchiveOnly)
                | (RemoteArchiveOnly, LocalPlainAvailable)
                | (LocalPlainAvailable, DeletedForMe)
                | (LocalPlainAvailable, DeletedForEveryone)
                | (DeliveryStoreOnly, LocalPlainAvailable)
                | (RemoteArchiveOnly, Unavailable)
        );
        if ok {
            Ok(to)
        } else {
            Err(StateTransitionError::Illegal {
                from: from.to_string(),
                to: to.to_string(),
            })
        }
    }
}

impl fmt::Display for BodyState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            BodyState::LocalPlainAvailable => "local_plain_available",
            BodyState::LocalEncryptedAvailable => "local_encrypted_available",
            BodyState::RemoteArchiveOnly => "remote_archive_only",
            BodyState::DeliveryStoreOnly => "delivery_store_only",
            BodyState::DeletedForMe => "deleted_for_me",
            BodyState::DeletedForEveryone => "deleted_for_everyone",
            BodyState::Unavailable => "unavailable",
        };
        f.write_str(s)
    }
}

impl FromStr for BodyState {
    type Err = StateTransitionError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "local_plain_available" => BodyState::LocalPlainAvailable,
            "local_encrypted_available" => BodyState::LocalEncryptedAvailable,
            "remote_archive_only" => BodyState::RemoteArchiveOnly,
            "delivery_store_only" => BodyState::DeliveryStoreOnly,
            "deleted_for_me" => BodyState::DeletedForMe,
            "deleted_for_everyone" => BodyState::DeletedForEveryone,
            "unavailable" => BodyState::Unavailable,
            _ => return Err(StateTransitionError::Unknown(s.to_string())),
        })
    }
}

// ---------------------------------------------------------------------------
// media_state — PROPOSAL.md §4 / ARCHITECTURE.md §5
// ---------------------------------------------------------------------------

/// Per-asset media lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaState {
    /// Thumbnail decrypted locally; original not yet downloaded.
    ThumbnailOnly,
    /// Original media file present locally (decrypted on demand).
    OriginalLocal,
    /// Original lives only on the backend; not yet pulled.
    RemoteOriginal,
    /// Active chunked download.
    DownloadInProgress,
    /// `enforceStorageBudget` evicted the original. Thumbnail may
    /// still be present.
    Evicted,
    /// Hard-deleted (delete-for-everyone or local delete cascading).
    Deleted,
}

impl MediaState {
    /// Whether `to` is reachable from `self` per the state diagram in
    /// `docs/ARCHITECTURE.md §5`.
    pub fn try_transition(from: Self, to: Self) -> Result<Self, StateTransitionError> {
        use MediaState::*;
        let ok = matches!(
            (from, to),
            (ThumbnailOnly, OriginalLocal)
                | (ThumbnailOnly, RemoteOriginal)
                | (OriginalLocal, Evicted)
                | (OriginalLocal, Deleted)
                | (Evicted, DownloadInProgress)
                | (RemoteOriginal, DownloadInProgress)
                | (DownloadInProgress, OriginalLocal)
        );
        if ok {
            Ok(to)
        } else {
            Err(StateTransitionError::Illegal {
                from: from.to_string(),
                to: to.to_string(),
            })
        }
    }
}

impl fmt::Display for MediaState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            MediaState::ThumbnailOnly => "thumbnail_only",
            MediaState::OriginalLocal => "original_local",
            MediaState::RemoteOriginal => "remote_original",
            MediaState::DownloadInProgress => "download_in_progress",
            MediaState::Evicted => "evicted",
            MediaState::Deleted => "deleted",
        };
        f.write_str(s)
    }
}

impl FromStr for MediaState {
    type Err = StateTransitionError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "thumbnail_only" => MediaState::ThumbnailOnly,
            "original_local" => MediaState::OriginalLocal,
            "remote_original" => MediaState::RemoteOriginal,
            "download_in_progress" => MediaState::DownloadInProgress,
            "evicted" => MediaState::Evicted,
            "deleted" => MediaState::Deleted,
            _ => return Err(StateTransitionError::Unknown(s.to_string())),
        })
    }
}

// ---------------------------------------------------------------------------
// archive_state — PROPOSAL.md §4 / ARCHITECTURE.md §5
// ---------------------------------------------------------------------------

/// Personal archive lifecycle for a message-skeleton row or an
/// archive segment.
///
/// Strictly linear: `not_archived → archive_pending → archive_uploaded
/// → archive_verified → archive_compacted`. Failures at any stage
/// leave the cursor un-advanced rather than rolling the state back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveState {
    /// Not yet considered for the personal archive.
    NotArchived,
    /// Scheduler picked the row up; segment build in progress.
    ArchivePending,
    /// Encrypted segment uploaded to the backend blob service.
    ArchiveUploaded,
    /// Server-returned Merkle root re-checked against the local
    /// computation.
    ArchiveVerified,
    /// Subsumed by a later checkpoint — safe to drop the underlying
    /// delta segments.
    ArchiveCompacted,
}

impl ArchiveState {
    /// Linear, forward-only transition. Any backwards or skip-ahead
    /// move is an error.
    pub fn try_transition(from: Self, to: Self) -> Result<Self, StateTransitionError> {
        use ArchiveState::*;
        let ok = matches!(
            (from, to),
            (NotArchived, ArchivePending)
                | (ArchivePending, ArchiveUploaded)
                | (ArchiveUploaded, ArchiveVerified)
                | (ArchiveVerified, ArchiveCompacted)
        );
        if ok {
            Ok(to)
        } else {
            Err(StateTransitionError::Illegal {
                from: from.to_string(),
                to: to.to_string(),
            })
        }
    }
}

impl fmt::Display for ArchiveState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ArchiveState::NotArchived => "not_archived",
            ArchiveState::ArchivePending => "archive_pending",
            ArchiveState::ArchiveUploaded => "archive_uploaded",
            ArchiveState::ArchiveVerified => "archive_verified",
            ArchiveState::ArchiveCompacted => "archive_compacted",
        };
        f.write_str(s)
    }
}

impl FromStr for ArchiveState {
    type Err = StateTransitionError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "not_archived" => ArchiveState::NotArchived,
            "archive_pending" => ArchiveState::ArchivePending,
            "archive_uploaded" => ArchiveState::ArchiveUploaded,
            "archive_verified" => ArchiveState::ArchiveVerified,
            "archive_compacted" => ArchiveState::ArchiveCompacted,
            _ => return Err(StateTransitionError::Unknown(s.to_string())),
        })
    }
}

// ---------------------------------------------------------------------------
// backup_state — PROPOSAL.md §4 / ARCHITECTURE.md §5
// ---------------------------------------------------------------------------

/// Backup lifecycle for a message-skeleton row or a backup segment.
///
/// Linear: `not_backed_up → backup_pending → backup_uploaded →
/// backup_manifest_committed → backup_expired`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupState {
    /// Not yet eligible / not yet journaled.
    NotBackedUp,
    /// Event journaled; awaiting segment build.
    BackupPending,
    /// Encrypted segment uploaded to the selected sink.
    BackupUploaded,
    /// Manifest signed + uploaded; segment is durable.
    BackupManifestCommitted,
    /// Compacted into a checkpoint and pruned from the active backup
    /// chain.
    BackupExpired,
}

impl BackupState {
    /// Linear, forward-only transition.
    pub fn try_transition(from: Self, to: Self) -> Result<Self, StateTransitionError> {
        use BackupState::*;
        let ok = matches!(
            (from, to),
            (NotBackedUp, BackupPending)
                | (BackupPending, BackupUploaded)
                | (BackupUploaded, BackupManifestCommitted)
                | (BackupManifestCommitted, BackupExpired)
        );
        if ok {
            Ok(to)
        } else {
            Err(StateTransitionError::Illegal {
                from: from.to_string(),
                to: to.to_string(),
            })
        }
    }
}

impl fmt::Display for BackupState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            BackupState::NotBackedUp => "not_backed_up",
            BackupState::BackupPending => "backup_pending",
            BackupState::BackupUploaded => "backup_uploaded",
            BackupState::BackupManifestCommitted => "backup_manifest_committed",
            BackupState::BackupExpired => "backup_expired",
        };
        f.write_str(s)
    }
}

impl FromStr for BackupState {
    type Err = StateTransitionError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "not_backed_up" => BackupState::NotBackedUp,
            "backup_pending" => BackupState::BackupPending,
            "backup_uploaded" => BackupState::BackupUploaded,
            "backup_manifest_committed" => BackupState::BackupManifestCommitted,
            "backup_expired" => BackupState::BackupExpired,
            _ => return Err(StateTransitionError::Unknown(s.to_string())),
        })
    }
}

// ---------------------------------------------------------------------------
// restore_state — global, single-row table
// ---------------------------------------------------------------------------

/// Disaster-recovery restore lifecycle.
///
/// Skeleton-first restore (`docs/PROPOSAL.md §11`): the restore
/// pipeline visits every state in declaration order. The terminal
/// state is [`RestoreState::FullRestoreComplete`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreState {
    /// Device identity (Ed25519 device key) recovered from the
    /// device-to-device, recovery-key, or passphrase path.
    IdentityRestored,
    /// `K_user_master` and the four sub-roots are unwrapped and
    /// resident in memory.
    RootKeysUnwrapped,
    /// Latest manifest's `previous_manifest_hash` chain has been
    /// walked and the Ed25519 signatures verified.
    ManifestVerified,
    /// Conversation list and `message_skeleton` rows have been
    /// reconstructed from the manifest's referenced segments.
    SkeletonRestored,
    /// Search index shards (FTS / fuzzy / vector / media) have been
    /// reattached.
    SearchRestored,
    /// Recent message bodies have been downloaded.
    RecentMessagesRestored,
    /// Media restore enabled; older media restores lazily on tap.
    MediaLazyRestoreEnabled,
    /// Terminal: full restore complete.
    FullRestoreComplete,
}

impl RestoreState {
    /// Linear, forward-only transition.
    pub fn try_transition(from: Self, to: Self) -> Result<Self, StateTransitionError> {
        use RestoreState::*;
        let ok = matches!(
            (from, to),
            (IdentityRestored, RootKeysUnwrapped)
                | (RootKeysUnwrapped, ManifestVerified)
                | (ManifestVerified, SkeletonRestored)
                | (SkeletonRestored, SearchRestored)
                | (SearchRestored, RecentMessagesRestored)
                | (RecentMessagesRestored, MediaLazyRestoreEnabled)
                | (MediaLazyRestoreEnabled, FullRestoreComplete)
        );
        if ok {
            Ok(to)
        } else {
            Err(StateTransitionError::Illegal {
                from: from.to_string(),
                to: to.to_string(),
            })
        }
    }
}

impl fmt::Display for RestoreState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            RestoreState::IdentityRestored => "identity_restored",
            RestoreState::RootKeysUnwrapped => "root_keys_unwrapped",
            RestoreState::ManifestVerified => "manifest_verified",
            RestoreState::SkeletonRestored => "skeleton_restored",
            RestoreState::SearchRestored => "search_restored",
            RestoreState::RecentMessagesRestored => "recent_messages_restored",
            RestoreState::MediaLazyRestoreEnabled => "media_lazy_restore_enabled",
            RestoreState::FullRestoreComplete => "full_restore_complete",
        };
        f.write_str(s)
    }
}

impl FromStr for RestoreState {
    type Err = StateTransitionError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "identity_restored" => RestoreState::IdentityRestored,
            "root_keys_unwrapped" => RestoreState::RootKeysUnwrapped,
            "manifest_verified" => RestoreState::ManifestVerified,
            "skeleton_restored" => RestoreState::SkeletonRestored,
            "search_restored" => RestoreState::SearchRestored,
            "recent_messages_restored" => RestoreState::RecentMessagesRestored,
            "media_lazy_restore_enabled" => RestoreState::MediaLazyRestoreEnabled,
            "full_restore_complete" => RestoreState::FullRestoreComplete,
            _ => return Err(StateTransitionError::Unknown(s.to_string())),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_round_trip_display_fromstr<T>(values: &[T])
    where
        T: fmt::Display + FromStr + PartialEq + fmt::Debug + Copy,
        <T as FromStr>::Err: fmt::Debug,
    {
        for v in values {
            let s = v.to_string();
            let parsed: T = s.parse().expect("parse");
            assert_eq!(*v, parsed, "round trip via {s:?}");
        }
    }

    fn assert_round_trip_serde<T>(values: &[T])
    where
        T: Serialize + serde::de::DeserializeOwned + PartialEq + fmt::Debug + Copy,
    {
        for v in values {
            let json = serde_json::to_string(v).expect("serialize");
            let back: T = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*v, back, "serde round trip via {json}");
        }
    }

    // --- BodyState ---------------------------------------------------------

    const ALL_BODY: &[BodyState] = &[
        BodyState::LocalPlainAvailable,
        BodyState::LocalEncryptedAvailable,
        BodyState::RemoteArchiveOnly,
        BodyState::DeliveryStoreOnly,
        BodyState::DeletedForMe,
        BodyState::DeletedForEveryone,
        BodyState::Unavailable,
    ];

    #[test]
    fn body_state_round_trip_display_fromstr() {
        assert_round_trip_display_fromstr(ALL_BODY);
    }

    #[test]
    fn body_state_round_trip_serde() {
        assert_round_trip_serde(ALL_BODY);
    }

    #[test]
    fn body_state_legal_transitions() {
        use BodyState::*;
        let legal = [
            (LocalPlainAvailable, LocalEncryptedAvailable),
            (LocalEncryptedAvailable, LocalPlainAvailable),
            (LocalPlainAvailable, RemoteArchiveOnly),
            (RemoteArchiveOnly, LocalPlainAvailable),
            (LocalPlainAvailable, DeletedForMe),
            (LocalPlainAvailable, DeletedForEveryone),
            (DeliveryStoreOnly, LocalPlainAvailable),
            (RemoteArchiveOnly, Unavailable),
        ];
        for (from, to) in legal {
            assert_eq!(BodyState::try_transition(from, to), Ok(to), "{from} → {to}");
        }
    }

    #[test]
    fn body_state_illegal_transitions_are_rejected() {
        use BodyState::*;
        // Spot-check: deleted is terminal; encrypted cannot jump
        // straight to remote_archive_only without a plaintext stop.
        let illegal = [
            (DeletedForMe, LocalPlainAvailable),
            (DeletedForEveryone, LocalPlainAvailable),
            (Unavailable, LocalPlainAvailable),
            (LocalEncryptedAvailable, RemoteArchiveOnly),
            (DeliveryStoreOnly, RemoteArchiveOnly),
            (RemoteArchiveOnly, DeletedForMe),
            (LocalPlainAvailable, Unavailable),
        ];
        for (from, to) in illegal {
            assert!(
                matches!(
                    BodyState::try_transition(from, to),
                    Err(StateTransitionError::Illegal { .. })
                ),
                "{from} → {to} should be illegal",
            );
        }
    }

    #[test]
    fn body_state_self_transition_is_illegal() {
        for s in ALL_BODY {
            assert!(matches!(
                BodyState::try_transition(*s, *s),
                Err(StateTransitionError::Illegal { .. })
            ));
        }
    }

    #[test]
    fn body_state_unknown_string_errors() {
        assert!(matches!(
            "garbage".parse::<BodyState>(),
            Err(StateTransitionError::Unknown(_))
        ));
    }

    // --- MediaState --------------------------------------------------------

    const ALL_MEDIA: &[MediaState] = &[
        MediaState::ThumbnailOnly,
        MediaState::OriginalLocal,
        MediaState::RemoteOriginal,
        MediaState::DownloadInProgress,
        MediaState::Evicted,
        MediaState::Deleted,
    ];

    #[test]
    fn media_state_round_trip() {
        assert_round_trip_display_fromstr(ALL_MEDIA);
        assert_round_trip_serde(ALL_MEDIA);
    }

    #[test]
    fn media_state_legal_transitions() {
        use MediaState::*;
        let legal = [
            (ThumbnailOnly, OriginalLocal),
            (ThumbnailOnly, RemoteOriginal),
            (OriginalLocal, Evicted),
            (OriginalLocal, Deleted),
            (Evicted, DownloadInProgress),
            (RemoteOriginal, DownloadInProgress),
            (DownloadInProgress, OriginalLocal),
        ];
        for (from, to) in legal {
            assert_eq!(MediaState::try_transition(from, to), Ok(to));
        }
    }

    #[test]
    fn media_state_illegal_transitions() {
        use MediaState::*;
        let illegal = [
            (Deleted, OriginalLocal),
            (Evicted, OriginalLocal), // must go through DownloadInProgress
            (RemoteOriginal, OriginalLocal),
            (ThumbnailOnly, Evicted),
            (DownloadInProgress, Deleted),
        ];
        for (from, to) in illegal {
            assert!(matches!(
                MediaState::try_transition(from, to),
                Err(StateTransitionError::Illegal { .. })
            ));
        }
    }

    // --- ArchiveState ------------------------------------------------------

    const ALL_ARCHIVE: &[ArchiveState] = &[
        ArchiveState::NotArchived,
        ArchiveState::ArchivePending,
        ArchiveState::ArchiveUploaded,
        ArchiveState::ArchiveVerified,
        ArchiveState::ArchiveCompacted,
    ];

    #[test]
    fn archive_state_round_trip() {
        assert_round_trip_display_fromstr(ALL_ARCHIVE);
        assert_round_trip_serde(ALL_ARCHIVE);
    }

    #[test]
    fn archive_state_full_linear_walk() {
        let mut s = ArchiveState::NotArchived;
        for next in [
            ArchiveState::ArchivePending,
            ArchiveState::ArchiveUploaded,
            ArchiveState::ArchiveVerified,
            ArchiveState::ArchiveCompacted,
        ] {
            s = ArchiveState::try_transition(s, next).expect("legal");
        }
        assert_eq!(s, ArchiveState::ArchiveCompacted);
    }

    #[test]
    fn archive_state_no_skipping() {
        // Cannot skip from not_archived straight to archive_uploaded.
        assert!(matches!(
            ArchiveState::try_transition(ArchiveState::NotArchived, ArchiveState::ArchiveUploaded),
            Err(StateTransitionError::Illegal { .. })
        ));
    }

    #[test]
    fn archive_state_no_rollback() {
        assert!(matches!(
            ArchiveState::try_transition(
                ArchiveState::ArchiveUploaded,
                ArchiveState::ArchivePending
            ),
            Err(StateTransitionError::Illegal { .. })
        ));
    }

    // --- BackupState -------------------------------------------------------

    const ALL_BACKUP: &[BackupState] = &[
        BackupState::NotBackedUp,
        BackupState::BackupPending,
        BackupState::BackupUploaded,
        BackupState::BackupManifestCommitted,
        BackupState::BackupExpired,
    ];

    #[test]
    fn backup_state_round_trip() {
        assert_round_trip_display_fromstr(ALL_BACKUP);
        assert_round_trip_serde(ALL_BACKUP);
    }

    #[test]
    fn backup_state_full_linear_walk() {
        let mut s = BackupState::NotBackedUp;
        for next in [
            BackupState::BackupPending,
            BackupState::BackupUploaded,
            BackupState::BackupManifestCommitted,
            BackupState::BackupExpired,
        ] {
            s = BackupState::try_transition(s, next).expect("legal");
        }
        assert_eq!(s, BackupState::BackupExpired);
    }

    #[test]
    fn backup_state_no_skipping() {
        assert!(matches!(
            BackupState::try_transition(BackupState::NotBackedUp, BackupState::BackupUploaded),
            Err(StateTransitionError::Illegal { .. })
        ));
    }

    // --- RestoreState ------------------------------------------------------

    const ALL_RESTORE: &[RestoreState] = &[
        RestoreState::IdentityRestored,
        RestoreState::RootKeysUnwrapped,
        RestoreState::ManifestVerified,
        RestoreState::SkeletonRestored,
        RestoreState::SearchRestored,
        RestoreState::RecentMessagesRestored,
        RestoreState::MediaLazyRestoreEnabled,
        RestoreState::FullRestoreComplete,
    ];

    #[test]
    fn restore_state_round_trip() {
        assert_round_trip_display_fromstr(ALL_RESTORE);
        assert_round_trip_serde(ALL_RESTORE);
    }

    #[test]
    fn restore_state_full_linear_walk() {
        let mut s = RestoreState::IdentityRestored;
        for next in &ALL_RESTORE[1..] {
            s = RestoreState::try_transition(s, *next).expect("legal");
        }
        assert_eq!(s, RestoreState::FullRestoreComplete);
    }

    #[test]
    fn restore_state_no_rollback() {
        assert!(matches!(
            RestoreState::try_transition(
                RestoreState::SkeletonRestored,
                RestoreState::ManifestVerified
            ),
            Err(StateTransitionError::Illegal { .. })
        ));
    }

    #[test]
    fn restore_state_no_skipping() {
        assert!(matches!(
            RestoreState::try_transition(
                RestoreState::IdentityRestored,
                RestoreState::SkeletonRestored
            ),
            Err(StateTransitionError::Illegal { .. })
        ));
    }

    // --- canonical Display strings match the schema column shape -----------

    #[test]
    fn display_strings_match_documented_snake_case() {
        // Spot-check a few that the docs mention literally so a typo
        // in either the doc or the code is caught.
        assert_eq!(
            BodyState::LocalPlainAvailable.to_string(),
            "local_plain_available"
        );
        assert_eq!(
            MediaState::DownloadInProgress.to_string(),
            "download_in_progress"
        );
        assert_eq!(
            ArchiveState::ArchiveVerified.to_string(),
            "archive_verified"
        );
        assert_eq!(
            BackupState::BackupManifestCommitted.to_string(),
            "backup_manifest_committed"
        );
        assert_eq!(
            RestoreState::FullRestoreComplete.to_string(),
            "full_restore_complete"
        );
    }
}
