//! Configuration for [`crate::KChatCore`].
//!
//! Phase 0 captures only the platform identifier and the on-disk
//! root directory; later phases extend the struct (network policy,
//! ML model directory, search budget, etc.) without breaking the
//! existing fields.

use std::collections::HashMap;
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
    /// Phase 8 (2026-05-04 batch 6) — per-tenant search policy
    /// overrides keyed by `tenant_id`. The orchestration layer
    /// looks the active tenant up in this map and feeds the
    /// resulting [`TenantSearchPolicy`] into the cold fan-out;
    /// tenants without a registered override fall back to
    /// [`TenantSearchPolicy::default`] (which allows everything
    /// the legacy Phase-1..Phase-7 search engine allowed).
    pub tenant_search_policies: HashMap<String, TenantSearchPolicy>,
    /// Phase 8 (2026-05-04 batch 10) — maximum number of cold
    /// shard fetches the orchestration layer is allowed to
    /// issue **in parallel** for a single search. Defaults to
    /// `4`. Setting this to `1` collapses the parallel path
    /// back to a sequential loop. The parallel fan-out lives
    /// in
    /// [`crate::search::query_engine::QueryEngine::execute_search_with_cold_source_parallel`]
    /// and is gated on the [`crate::search::query_engine::ColdShardSource`]
    /// implementation being `Send + Sync` — the legacy entry
    /// point is preserved unchanged for sources that are not.
    pub max_cold_fetch_concurrency: usize,
    /// Phase 7 (2026-05-04 batch 10 — Task 9) — when set to
    /// `Some((source, target))`, the eviction path automatically
    /// queues a one-off [`crate::scheduler::OneOffTask::MediaMigration`]
    /// after a successful eviction pass. `None` (the default)
    /// disables auto-scheduling — callers can still drive
    /// migrations manually via
    /// [`crate::core_impl::CoreImpl::schedule_media_migration`].
    ///
    /// `(source, target)` are storage-sink tags as used by
    /// [`crate::media::migration::plan_media_migration`] (e.g.
    /// `("local", "user-cloud")`).
    pub auto_migrate_after_eviction: Option<(String, String)>,
}

/// Phase 5 (2026-05-04 batch 10) — per-platform p95 latency
/// budgets for cold-shard search.
///
/// `docs/PROPOSAL.md §7.5` pins the cold-shard decrypt + search
/// p95 budget at 1.5 s and gives a per-device target matrix:
/// flagship phones get a tighter budget, mid-range Android sees
/// a looser one, desktops are tighter still. The
/// [`DeviceMatrixConfig`] surface lets a caller pick the right
/// budget for the host device when running the on-device
/// latency gates added in Phase 5 batch 10.
///
/// Values are nanoseconds — same unit as
/// [`crate::perf::PerfTrace::duration_ns`] and
/// [`crate::perf::PerfBudget::p95_budget_ns`] — so a
/// [`DeviceMatrixConfig`] can be plugged directly into
/// [`crate::perf::check_budgets`] without conversion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceMatrixConfig {
    /// p95 budget for an iOS flagship (A15+ / M-class). Default:
    /// `1_000_000_000` (1.0 s).
    pub ios_flagship_p95_ns: u64,
    /// p95 budget for an older iOS device (≤A13). Default:
    /// `1_500_000_000` (1.5 s) — matches the headline PROPOSAL
    /// §7.5 budget.
    pub ios_older_p95_ns: u64,
    /// p95 budget for an Android flagship (Snapdragon 8 Gen-class).
    /// Default: `1_200_000_000` (1.2 s).
    pub android_flagship_p95_ns: u64,
    /// p95 budget for an Android mid-range device. Default:
    /// `2_000_000_000` (2.0 s).
    pub android_midrange_p95_ns: u64,
    /// p95 budget for a desktop host (macOS / Windows / Linux).
    /// Default: `800_000_000` (0.8 s).
    pub desktop_p95_ns: u64,
}

impl Default for DeviceMatrixConfig {
    fn default() -> Self {
        Self {
            ios_flagship_p95_ns: 1_000_000_000,
            ios_older_p95_ns: 1_500_000_000,
            android_flagship_p95_ns: 1_200_000_000,
            android_midrange_p95_ns: 2_000_000_000,
            desktop_p95_ns: 800_000_000,
        }
    }
}

/// Phase 8 (2026-05-04 batch 6) — per-tenant search policy.
///
/// `docs/PROPOSAL.md §7` introduces multi-scope search: a single
/// query can target a single conversation, a community, a
/// domain, an entire tenant, or the global B2C archive. Some
/// deployments need to **forbid** the wider scopes — a B2B
/// tenant typically wants `allow_global_search = false` so its
/// users can never accidentally fan out to other tenants' cold
/// shards, even if the UI somehow constructed a
/// [`crate::SearchTarget::Global`] query.
///
/// All limits are enforced inside the cold fan-out path of
/// [`crate::search::query_engine::QueryEngine::execute_search_with_cold_source`].
/// The local FTS / fuzzy path is unaffected — the policy only
/// shapes which **cold** buckets are eligible for fetch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantSearchPolicy {
    /// Whether the tenant is allowed to issue a
    /// [`crate::SearchTarget::Global`] query. Default: `true`.
    /// Set to `false` for B2B tenants that must never see
    /// results from outside their own tenant.
    pub allow_global_search: bool,
    /// Whether cold buckets that resolve to a *different*
    /// tenant than the query target are eligible for fetch.
    /// Default: `false` — most B2B deployments keep tenants
    /// disjoint at the bucket level. Setting this to `true`
    /// lets the cold fan-out cross tenant boundaries, which is
    /// the legacy Phase-5 behaviour.
    pub allow_cross_tenant_results: bool,
    /// Maximum number of cold `(conversation_id, time_bucket)`
    /// pairs the fan-out is allowed to fetch for a single
    /// query. Default: `50`. Used as a defense-in-depth budget
    /// against pathological queries (e.g. a Global search over
    /// a tenant with thousands of cold buckets).
    pub max_cold_buckets_per_search: usize,
    /// Whether the orchestration layer requires every cold
    /// bucket to ship a bloom shard before the full text /
    /// fuzzy shards may be fetched. Default: `false` (legacy
    /// behaviour: bloom is best-effort). Setting this to
    /// `true` skips any bucket whose bloom shard is missing or
    /// fails to decrypt.
    pub require_bloom_shards: bool,
}

impl Default for TenantSearchPolicy {
    fn default() -> Self {
        Self {
            allow_global_search: true,
            allow_cross_tenant_results: false,
            max_cold_buckets_per_search: 50,
            require_bloom_shards: false,
        }
    }
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
            tenant_search_policies: HashMap::new(),
            max_cold_fetch_concurrency: 4,
            auto_migrate_after_eviction: None,
        }
    }

    /// Override the cold-shard parallel fetch concurrency
    /// (Phase 8 batch 10). Builder-style mirror of
    /// [`KChatCoreConfig::with_tenant_search_policy`].
    #[must_use]
    pub fn with_max_cold_fetch_concurrency(mut self, n: usize) -> Self {
        self.max_cold_fetch_concurrency = n.max(1);
        self
    }

    /// Register / override the [`TenantSearchPolicy`] for a tenant.
    /// Builder-style for ergonomic configuration in tests.
    #[must_use]
    pub fn with_tenant_search_policy(
        mut self,
        tenant_id: impl Into<String>,
        policy: TenantSearchPolicy,
    ) -> Self {
        self.tenant_search_policies.insert(tenant_id.into(), policy);
        self
    }

    /// Look up the [`TenantSearchPolicy`] for a tenant. Falls back
    /// to [`TenantSearchPolicy::default`] when no override is
    /// registered.
    pub fn tenant_search_policy_for(&self, tenant_id: &str) -> TenantSearchPolicy {
        self.tenant_search_policies
            .get(tenant_id)
            .cloned()
            .unwrap_or_default()
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

    // -------------------------------------------------------------------
    // Phase 8 (2026-05-04 batch 6) — TenantSearchPolicy
    // -------------------------------------------------------------------

    #[test]
    fn tenant_policy_default_allows_everything() {
        let p = TenantSearchPolicy::default();
        assert!(p.allow_global_search);
        assert!(!p.allow_cross_tenant_results);
        assert_eq!(p.max_cold_buckets_per_search, 50);
        assert!(!p.require_bloom_shards);
    }

    #[test]
    fn tenant_policy_serde_round_trip() {
        let p = TenantSearchPolicy {
            allow_global_search: false,
            allow_cross_tenant_results: true,
            max_cold_buckets_per_search: 17,
            require_bloom_shards: true,
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: TenantSearchPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn tenant_policy_lookup_falls_back_to_default_for_unknown_tenant() {
        let cfg = KChatCoreConfig::new(
            PathBuf::from("/tmp/kchat-cfg-test"),
            Platform::MacOs,
            "tenant-test",
        );
        let p = cfg.tenant_search_policy_for("missing");
        assert_eq!(p, TenantSearchPolicy::default());
    }

    #[test]
    fn tenant_policy_lookup_returns_registered_override() {
        let cfg = KChatCoreConfig::new(
            PathBuf::from("/tmp/kchat-cfg-test"),
            Platform::MacOs,
            "tenant-test",
        )
        .with_tenant_search_policy(
            "tenant-acme",
            TenantSearchPolicy {
                allow_global_search: false,
                allow_cross_tenant_results: false,
                max_cold_buckets_per_search: 10,
                require_bloom_shards: true,
            },
        );
        let p = cfg.tenant_search_policy_for("tenant-acme");
        assert!(!p.allow_global_search);
        assert_eq!(p.max_cold_buckets_per_search, 10);
        assert!(p.require_bloom_shards);
    }

    // ---------------------------------------------------------------
    // Phase 5 (2026-05-04 batch 10) — DeviceMatrixConfig.
    // ---------------------------------------------------------------

    #[test]
    fn device_matrix_config_default_budgets() {
        let m = DeviceMatrixConfig::default();
        // Pinned to PROPOSAL.md §7.5 device matrix.
        assert_eq!(m.ios_flagship_p95_ns, 1_000_000_000);
        assert_eq!(m.ios_older_p95_ns, 1_500_000_000);
        assert_eq!(m.android_flagship_p95_ns, 1_200_000_000);
        assert_eq!(m.android_midrange_p95_ns, 2_000_000_000);
        assert_eq!(m.desktop_p95_ns, 800_000_000);
    }

    #[test]
    fn device_matrix_config_serde_round_trip() {
        let m = DeviceMatrixConfig {
            ios_flagship_p95_ns: 950_000_000,
            ios_older_p95_ns: 1_400_000_000,
            android_flagship_p95_ns: 1_100_000_000,
            android_midrange_p95_ns: 1_900_000_000,
            desktop_p95_ns: 700_000_000,
        };
        let json = serde_json::to_string(&m).unwrap();
        let back: DeviceMatrixConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }
}
