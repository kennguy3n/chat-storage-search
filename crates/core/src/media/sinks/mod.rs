//! Media blob sink trait surface — /
//!
//! `docs/DESIGN.md §5.7` (tiered media storage) introduces a
//! three-tier storage model:
//!
//! * **Tier 0 — KChat backend**: text deltas, skeletons, manifests,
//!   media key wraps, thumbnails, search index shards.
//! * **Tier 1 — KChat backend, movable**: older search index shards
//!   that can age to user cloud.
//! * **Tier 2 — User cloud**: media originals on iCloud, Google
//!   Drive, or ZK Object Fabric.
//!
//! The [`MediaBlobSink`] trait is the routing seam between the
//! media engine and the underlying storage backend for **media
//! originals only**. Thumbnails always go through the KChat
//! [`crate::transport::TransportClient`]; archive segments use the
//! `archive_backend` configuration on
//! [`crate::config::KChatCoreConfig`]; only media originals are
//! routed through this trait.
//!
//! Lands the trait surface and the `Noop` placeholder that
//! returns [`crate::Error::NotImplemented`] from every method.
//! Lands the iCloud, Google Drive, and ZK Object Fabric
//! implementations in the sibling modules of this directory.

use crate::crypto::aead::BlobClass;

pub mod google_drive;
pub mod icloud;
pub mod zk_fabric;

/// Identifier returned by a [`MediaBlobSink`] after a successful
/// upload, and required to fetch or delete the blob later.
///
/// Carries enough information for the local store to round-trip the
/// blob through `media_asset.blob_id` (UUID-shaped) and
/// `media_asset.storage_sink` (sink tag), with optional
/// sink-specific metadata blob for things that don't fit those
/// columns (CloudKit record names, Drive file IDs, S3 versioning
/// tokens, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaBlobReference {
    /// Backend blob identifier — same shape as
    /// [`crate::local_store::schema::MediaAsset::blob_id`].
    pub blob_id: String,
    /// Storage sink tag — same shape as
    /// [`crate::local_store::schema::MediaAsset::storage_sink`].
    /// Canonical values: `"kchat_backend"`, `"icloud"`,
    /// `"google_drive"`, `"zk_object_fabric"`.
    pub storage_sink: String,
    /// Optional sink-specific metadata blob. Opaque to the media
    /// engine; the sink that produced the reference is the only
    /// component that interprets it. Examples:
    ///
    /// * `iCloud`: serialized CloudKit record name + zone.
    /// * `Google Drive`: file ID + revision token.
    /// * `ZK Object Fabric`: S3 object key + (optional)
    ///   version-id.
    pub sink_metadata: Option<Vec<u8>>,
}

/// Routing seam for media-blob upload / download / delete.
///
/// Object-safe (no generic methods, no `Self`-returning methods),
/// `Send + Sync` so the media engine can hold a
/// `Arc<dyn MediaBlobSink>` and dispatch from any worker.
///
/// The trait operates on **already-encrypted** chunks: the media
/// engine seals each chunk with `K_asset` (per
/// `docs/DESIGN.md §8`) before handing them off. The sink is
/// responsible only for moving bytes to / from the configured
/// storage backend. It must not interpret, compress, or mutate the
/// chunks.
pub trait MediaBlobSink: Send + Sync + std::fmt::Debug {
    /// Upload the encrypted chunks of an asset and return a
    /// reference that the local store can persist alongside the
    /// asset row.
    ///
    /// `expected_merkle_root` is the BLAKE3 Merkle root over the
    /// per-chunk SHA-256 of the **ciphertext** chunks. The sink
    /// must round-trip it back through the returned reference
    /// (or its `sink_metadata`) so the rehydration path can
    /// re-verify it.
    fn upload_media_chunks(
        &self,
        asset_id: &str,
        blob_class: BlobClass,
        chunks: &[&[u8]],
        expected_merkle_root: [u8; 32],
    ) -> crate::Result<MediaBlobReference>;

    /// Fetch a single encrypted chunk of a previously uploaded
    /// blob.
    fn fetch_media_chunk(
        &self,
        blob_ref: &MediaBlobReference,
        chunk_idx: u32,
    ) -> crate::Result<Vec<u8>>;

    /// Delete every chunk of a previously uploaded blob. Idempotent:
    /// deleting an already-deleted blob must succeed (the eviction
    /// pipeline retries on transient failure).
    fn delete_media_blob(&self, blob_ref: &MediaBlobReference) -> crate::Result<()>;
}

/// `MediaBlobSink` placeholder used by callers
/// before any real sink lands. Every method returns
/// [`crate::Error::NotImplemented("media_blob_sink")`].
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopMediaBlobSink;

impl MediaBlobSink for NoopMediaBlobSink {
    fn upload_media_chunks(
        &self,
        _asset_id: &str,
        _blob_class: BlobClass,
        _chunks: &[&[u8]],
        _expected_merkle_root: [u8; 32],
    ) -> crate::Result<MediaBlobReference> {
        Err(crate::Error::NotImplemented("media_blob_sink"))
    }

    fn fetch_media_chunk(
        &self,
        _blob_ref: &MediaBlobReference,
        _chunk_idx: u32,
    ) -> crate::Result<Vec<u8>> {
        Err(crate::Error::NotImplemented("media_blob_sink"))
    }

    fn delete_media_blob(&self, _blob_ref: &MediaBlobReference) -> crate::Result<()> {
        Err(crate::Error::NotImplemented("media_blob_sink"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ref() -> MediaBlobReference {
        MediaBlobReference {
            blob_id: "blob-1".to_string(),
            storage_sink: "kchat_backend".to_string(),
            sink_metadata: None,
        }
    }

    #[test]
    fn media_blob_sink_is_object_safe() {
        // Compile-time check: erase to a trait object.
        let b: Box<dyn MediaBlobSink> = Box::new(NoopMediaBlobSink);
        // And `Arc` for sharing between worker threads.
        let _a: std::sync::Arc<dyn MediaBlobSink> = std::sync::Arc::new(NoopMediaBlobSink);
        // Use it once so the binding isn't dead code.
        assert!(b
            .delete_media_blob(&sample_ref())
            .is_err_and(|e| matches!(e, crate::Error::NotImplemented("media_blob_sink"))));
    }

    #[test]
    fn noop_upload_returns_not_implemented() {
        let sink = NoopMediaBlobSink;
        let res = sink.upload_media_chunks("asset-1", BlobClass::Media, &[b"x"], [0u8; 32]);
        assert!(matches!(
            res,
            Err(crate::Error::NotImplemented("media_blob_sink"))
        ));
    }

    #[test]
    fn noop_fetch_returns_not_implemented() {
        let sink = NoopMediaBlobSink;
        let res = sink.fetch_media_chunk(&sample_ref(), 0);
        assert!(matches!(
            res,
            Err(crate::Error::NotImplemented("media_blob_sink"))
        ));
    }

    #[test]
    fn noop_delete_returns_not_implemented() {
        let sink = NoopMediaBlobSink;
        let res = sink.delete_media_blob(&sample_ref());
        assert!(matches!(
            res,
            Err(crate::Error::NotImplemented("media_blob_sink"))
        ));
    }

    #[test]
    fn media_blob_reference_round_trips_through_clone() {
        let r = MediaBlobReference {
            blob_id: "blob-42".to_string(),
            storage_sink: "icloud".to_string(),
            sink_metadata: Some(b"opaque".to_vec()),
        };
        assert_eq!(r, r.clone());
    }
}
