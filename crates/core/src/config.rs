//! Configuration for [`crate::KChatCore`].
//!
//! Phase 0 captures only the platform identifier and the on-disk
//! root directory; later phases extend the struct (network policy,
//! ML model directory, search budget, etc.) without breaking the
//! existing fields.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Logical platform the core is running on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Ios,
    Android,
    MacOs,
    Windows,
}

/// Personal-archive storage backend.
///
/// `docs/PROPOSAL.md §10.1` documents the
/// `archive_backend = "kchat" | "zkof"` configuration. The KChat
/// backend (PostgreSQL blob service) is the default; ZK Object
/// Fabric (S3 API) is the optional alternative that lands in
/// Phase 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ArchiveBackend {
    /// KChat backend's `/v1/blobs/*` and `/v1/archive/*` endpoints.
    #[default]
    #[serde(rename = "kchat")]
    KChat,
    /// ZK Object Fabric (S3 API). See `docs/PROPOSAL.md §10.1`.
    #[serde(rename = "zkof")]
    Zkof,
}
/// Storage destination for media blobs.
///
/// `docs/PROPOSAL.md §5.7` (tiered media storage). Media originals
/// dominate per-user archive cost at scale; routing them to the
/// user's own cloud (iCloud, Google Drive, ZKOF) instead of the
/// KChat backend keeps backend storage to text deltas, indexes,
/// thumbnails, and key wraps. The variants are intentionally a
/// superset: `KChatBackend` is the Phase-1 default, the user-cloud
/// variants land in Phase 3 and may grow inner fields then.
///
/// The serialized variant tags (`"kchat_backend"`, `"icloud"`,
/// `"google_drive"`, `"zk_object_fabric"`) are pinned via explicit
/// `#[serde(rename = "...")]` attributes so they always match the
/// `media_asset.storage_sink` SQL column default and the
/// canonical-values doc on
/// [`crate::media::sinks::MediaBlobReference::storage_sink`]. Do
/// **not** rely on `rename_all = "snake_case"` here — `KChatBackend`
/// would split at the `K` / `C` boundary and serialize as
/// `"k_chat_backend"`, which would silently mismatch the SQL
/// default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageSink {
    /// Default: media uploads flow through `TransportClient` to the
    /// KChat backend's blob service.
    #[serde(rename = "kchat_backend")]
    KChatBackend,
    /// iCloud (CloudKit file storage). Implementation lands in Phase 3.
    #[serde(rename = "icloud")]
    ICloud {
        /// CloudKit container path (or platform-specific equivalent)
        /// where media blobs are stored.
        container_path: String,
    },
    /// Google Drive (Drive API via platform bridge). Implementation
    /// lands in Phase 3.
    #[serde(rename = "google_drive")]
    GoogleDrive {
        /// Drive folder ID where media blobs are stored.
        folder_id: String,
    },
    /// ZK Object Fabric (S3 API). Implementation lands in Phase 3.
    #[serde(rename = "zk_object_fabric")]
    ZkObjectFabric {
        /// S3 bucket name media blobs are uploaded to.
        bucket: String,
    },
}

/// Privacy posture toggle for the archive prefetch / orchestration
/// pipeline.
///
/// `docs/PROPOSAL.md §5.6` proposes optional **dummy request
/// padding** to break the per-bucket access-pattern fingerprint:
/// when [`PrivacyLevel::High`] is configured, the orchestration
/// layer mixes dummy segment-id fetches in with the real ones so an
/// observer at the transport / backend layer cannot distinguish
/// "user is reading bucket X" from "user is paginating bucket Y".
/// The default ([`PrivacyLevel::Standard`]) keeps the prefetch path
/// cost-optimal and is what every Phase-1 / Phase-2 deployment
/// already runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PrivacyLevel {
    /// Phase-1 default. The prefetch issues exactly one fetch per
    /// real segment id.
    #[default]
    #[serde(rename = "standard")]
    Standard,
    /// Phase-3 optional. The prefetch interleaves randomly
    /// generated dummy segment ids with the real ones; the dummy
    /// fetches return empty / 404 from the backend and are
    /// dropped on the receiving side. Trades transport bandwidth
    /// for traffic-analysis resistance.
    #[serde(rename = "high")]
    High,
}

/// Configuration for a [`crate::KChatCore`] instance.
#[derive(Debug, Clone)]
pub struct KChatCoreConfig {
    /// Root directory for the encrypted local store and chunk cache.
    pub data_dir: PathBuf,
    /// Platform the core is running on. Drives platform-specific
    /// keychain bindings and ML execution-provider selection.
    pub platform: Platform,
    /// Tenant identifier used for ZK Object Fabric Pattern C derivation.
    pub tenant_id: String,
    /// Personal-archive backend. Defaults to
    /// [`ArchiveBackend::KChat`]. See `docs/PROPOSAL.md §10.1`.
    pub archive_backend: ArchiveBackend,
    /// Optional storage sink for **media originals**. `None` means
    /// media blobs flow through the default `TransportClient` to
    /// the KChat backend (Tier 0). When set to a user-cloud variant
    /// (Tier 2), the media engine routes originals there; thumbnails
    /// and archive segments still go to Tier 0. See
    /// `docs/PROPOSAL.md §5.7`.
    pub media_blob_sink: Option<StorageSink>,
    /// Privacy posture for archive prefetch / orchestration. The
    /// default is [`PrivacyLevel::Standard`]; bumping it to
    /// [`PrivacyLevel::High`] enables dummy-request padding per
    /// `docs/PROPOSAL.md §5.6`.
    pub privacy_level: PrivacyLevel,
}

impl KChatCoreConfig {
    /// Construct a new configuration with the required fields.
    ///
    /// `archive_backend` defaults to [`ArchiveBackend::KChat`] and
    /// `media_blob_sink` defaults to `None` (route media blobs
    /// through `TransportClient` to the KChat backend). Use
    /// [`KChatCoreConfig::with_archive_backend`] /
    /// [`KChatCoreConfig::with_media_blob_sink`] to override.
    pub fn new(data_dir: PathBuf, platform: Platform, tenant_id: impl Into<String>) -> Self {
        Self {
            data_dir,
            platform,
            tenant_id: tenant_id.into(),
            archive_backend: ArchiveBackend::default(),
            media_blob_sink: None,
            privacy_level: PrivacyLevel::default(),
        }
    }

    /// Builder-style override for [`Self::archive_backend`].
    #[must_use]
    pub fn with_archive_backend(mut self, backend: ArchiveBackend) -> Self {
        self.archive_backend = backend;
        self
    }

    /// Builder-style override for [`Self::media_blob_sink`].
    #[must_use]
    pub fn with_media_blob_sink(mut self, sink: Option<StorageSink>) -> Self {
        self.media_blob_sink = sink;
        self
    }

    /// Builder-style override for [`Self::privacy_level`].
    #[must_use]
    pub fn with_privacy_level(mut self, level: PrivacyLevel) -> Self {
        self.privacy_level = level;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_backend_defaults_to_kchat() {
        assert_eq!(ArchiveBackend::default(), ArchiveBackend::KChat);
    }

    #[test]
    fn archive_backend_serde_round_trip() {
        for variant in [ArchiveBackend::KChat, ArchiveBackend::Zkof] {
            let json = serde_json::to_string(&variant).unwrap();
            let back: ArchiveBackend = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, back);
        }
    }

    #[test]
    fn archive_backend_canonical_strings() {
        // PROPOSAL.md §10.1 documents `archive_backend = "kchat" | "zkof"`.
        assert_eq!(
            serde_json::to_string(&ArchiveBackend::KChat).unwrap(),
            "\"kchat\""
        );
        assert_eq!(
            serde_json::to_string(&ArchiveBackend::Zkof).unwrap(),
            "\"zkof\""
        );
    }

    #[test]
    fn storage_sink_canonical_strings_match_storage_sink_column() {
        // The `storage_sink` tag has to match the `media_asset.storage_sink`
        // SQL default (`'kchat_backend'`) and the canonical values listed
        // in the `MediaBlobReference::storage_sink` doc — `kchat_backend`,
        // `icloud`, `google_drive`, `zk_object_fabric`. Pin all four so a
        // future re-introduction of `rename_all = "snake_case"` (which
        // would split `KChatBackend` at the K/C boundary and emit
        // `"k_chat_backend"`) is caught by CI.
        let pinned: &[(StorageSink, &str)] = &[
            (StorageSink::KChatBackend, "kchat_backend"),
            (
                StorageSink::ICloud {
                    container_path: "iCloud.com.kchat.media".to_string(),
                },
                "icloud",
            ),
            (
                StorageSink::GoogleDrive {
                    folder_id: "1A2B3C".to_string(),
                },
                "google_drive",
            ),
            (
                StorageSink::ZkObjectFabric {
                    bucket: "kchat-media".to_string(),
                },
                "zk_object_fabric",
            ),
        ];
        for (variant, tag) in pinned {
            // Use serde_cbor's diagnostic-shaped representation: the
            // top-level CBOR map for an externally-tagged variant is
            // `{ "<tag>": <inner> }` for variants with payload, and a
            // bare string for unit variants. We only need to confirm
            // the tag substring appears, which works for both shapes.
            let json = serde_json::to_string(variant).unwrap();
            assert!(
                json.contains(&format!("\"{tag}\"")),
                "expected serialized {variant:?} to contain tag {tag:?}, got {json}"
            );
            // And the round-trip must still reproduce the original.
            let back: StorageSink = serde_json::from_str(&json).unwrap();
            assert_eq!(*variant, back);
        }
    }

    #[test]
    fn storage_sink_serde_round_trip_for_every_variant() {
        let cases = [
            StorageSink::KChatBackend,
            StorageSink::ICloud {
                container_path: "iCloud.com.kchat.media".to_string(),
            },
            StorageSink::GoogleDrive {
                folder_id: "1A2B3C".to_string(),
            },
            StorageSink::ZkObjectFabric {
                bucket: "kchat-media".to_string(),
            },
        ];
        for sink in cases {
            let json = serde_json::to_string(&sink).unwrap();
            let back: StorageSink = serde_json::from_str(&json).unwrap();
            assert_eq!(sink, back);
        }
    }

    #[test]
    fn kchat_core_config_new_uses_defaults_for_new_fields() {
        let cfg = KChatCoreConfig::new(
            PathBuf::from("/tmp/kchat-cfg-test"),
            Platform::MacOs,
            "tenant-test",
        );
        assert_eq!(cfg.archive_backend, ArchiveBackend::KChat);
        assert!(cfg.media_blob_sink.is_none());
    }

    #[test]
    fn kchat_core_config_builders_apply_overrides() {
        let cfg = KChatCoreConfig::new(
            PathBuf::from("/tmp/kchat-cfg-test"),
            Platform::MacOs,
            "tenant-test",
        )
        .with_archive_backend(ArchiveBackend::Zkof)
        .with_media_blob_sink(Some(StorageSink::ZkObjectFabric {
            bucket: "kchat-media".to_string(),
        }));
        assert_eq!(cfg.archive_backend, ArchiveBackend::Zkof);
        assert!(matches!(
            cfg.media_blob_sink,
            Some(StorageSink::ZkObjectFabric { .. })
        ));
    }
}
