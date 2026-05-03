//! Batch encrypted-shard prefetch (Phase 5, Task 8).
//!
//! `docs/PHASES.md` Phase 5 calls out that "when fetching
//! encrypted index shards, fetch all shard types for the target
//! `(conversation_hash, bucket)` in one batch to coarsen the
//! metadata signal". A naive implementation that fetches text /
//! fuzzy / vector / media shards in four separate transport
//! round-trips leaks four distinct event timestamps to the
//! backend; a backend correlator can then infer the user is
//! actively searching the same `(conversation, bucket)` and
//! recover the access-pattern fingerprint privacy goal of
//! `docs/PROPOSAL.md §5.6`.
//!
//! This module owns the **batching policy**:
//!
//! * [`batch_prefetch_shards`] — fetch every
//!   [`crate::formats::search_shard::IndexType`] for one
//!   `(conversation_hash, bucket)` in a single fan-out, returning
//!   all four ciphertext blobs in one `Vec<PrefetchedShard>`.
//! * [`batch_prefetch_shards_with_padding`] — privacy-aware
//!   variant that adds dummy `(conversation_hash, bucket)`
//!   prefetches via [`crate::archive::privacy`] when
//!   `privacy_level = High`, so the backend cannot tell the real
//!   target apart from the cover requests.
//!
//! The prefetched ciphertext is *not* decrypted here — the
//! caller threads the [`PrefetchedShard`] vec into
//! [`crate::restore::pipeline::RestorePipeline::restore_search_index_shards_with_replay`]
//! (or a follow-up live-query path). Decryption requires the
//! `K_*_index_shard(shard_id)` derivation, which only the
//! orchestration layer knows.

use crate::archive::privacy::{compute_padding_count, generate_dummy_segment_id, should_pad};
use crate::config::KChatCoreConfig;
use crate::formats::search_shard::IndexType;
use crate::transport::TransportClient;
use crate::Error;

/// Default ordering of shard types fetched by
/// [`batch_prefetch_shards`]. Stable so the test suite can pin
/// the expected wire ordering, and so any caller that wants to
/// drop into [`IndexType::all`] for a parallel join sees a
/// predictable layout.
const PREFETCH_ORDER: [IndexType; 4] = [
    IndexType::Text,
    IndexType::Fuzzy,
    IndexType::Vector,
    IndexType::Media,
];

/// Wire identifier the transport uses for a given shard type.
/// Matches the `shard_type` parameter of
/// [`crate::transport::TransportClient::fetch_index_shards`].
fn shard_type_str(it: IndexType) -> &'static str {
    match it {
        IndexType::Text => "text",
        IndexType::Fuzzy => "fuzzy",
        IndexType::Vector => "vector",
        IndexType::Media => "media",
    }
}

/// One prefetched ciphertext blob ready to feed into the shard
/// restore path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefetchedShard {
    /// Which kind of index this blob carries.
    pub shard_type: IndexType,
    /// `(conversation_hash, bucket)` the blob covers — copied
    /// from the call so the caller can correlate without holding
    /// the prefetch arguments.
    pub conversation_hash: String,
    /// Coarse time bucket this shard covers.
    pub bucket: String,
    /// Concatenated shard payload bytes — see
    /// [`crate::formats::search_shard::SearchIndexShard`].
    pub ciphertext: Vec<u8>,
}

/// Fetch every [`IndexType`] for the target
/// `(conversation_hash, bucket)` in one fan-out.
///
/// The transport call order is fixed
/// (text → fuzzy → vector → media — see [`PREFETCH_ORDER`]) so
/// timing observers see a single deterministic burst. An empty
/// transport response (no shards on the backend yet) returns an
/// empty `Vec`; the caller must not treat that as an error
/// because it is the legitimate "no shards uploaded yet"
/// signal.
pub fn batch_prefetch_shards(
    transport: &dyn TransportClient,
    conversation_hash: &str,
    bucket: &str,
) -> Result<Vec<PrefetchedShard>, Error> {
    let mut out = Vec::with_capacity(PREFETCH_ORDER.len());
    for shard_type in PREFETCH_ORDER {
        let bytes =
            transport.fetch_index_shards(conversation_hash, bucket, shard_type_str(shard_type))?;
        if bytes.is_empty() {
            continue;
        }
        out.push(PrefetchedShard {
            shard_type,
            conversation_hash: conversation_hash.into(),
            bucket: bucket.into(),
            ciphertext: bytes,
        });
    }
    Ok(out)
}

/// Privacy-aware variant. Mixes in dummy
/// `(conversation_hash, bucket)` prefetches when `config.privacy_level = High`
/// (see [`crate::archive::privacy::should_pad`]). Each dummy
/// fetches every shard type in the same order so a timing
/// observer cannot tell the real target apart from the dummies.
///
/// Dummy responses are silently dropped — the returned vec
/// contains only real-target shards. The number of dummy
/// `(conversation_hash, bucket)` pairs is governed by
/// [`compute_padding_count`].
pub fn batch_prefetch_shards_with_padding(
    transport: &dyn TransportClient,
    conversation_hash: &str,
    bucket: &str,
    config: &KChatCoreConfig,
) -> Result<Vec<PrefetchedShard>, Error> {
    let real = batch_prefetch_shards(transport, conversation_hash, bucket)?;
    if !should_pad(config) {
        return Ok(real);
    }
    let dummy_count = compute_padding_count(1);
    for _ in 0..dummy_count {
        let dummy_hash = generate_dummy_segment_id();
        for shard_type in PREFETCH_ORDER {
            // Best-effort dummy: ignore the response (and any
            // error — a 404 / NotImplemented on a dummy is the
            // expected case).
            let _ = transport.fetch_index_shards(&dummy_hash, bucket, shard_type_str(shard_type));
        }
    }
    Ok(real)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Platform, PrivacyLevel};
    use crate::crypto::aead::BlobClass;
    use crate::transport::{
        BlobUploadHandle, ChunkReceipt, CommitBlobResponse, EncryptedManifest,
        FetchMessagesResponse, TransportClient, TransportResult,
    };
    use std::collections::HashMap;
    use std::ops::Range;
    use std::path::PathBuf;
    use std::sync::Mutex;

    /// Mock transport recording every `fetch_index_shards` call
    /// and serving canned ciphertext from a `(hash, bucket,
    /// type)` map. Tests can both seed the map and assert on the
    /// recorded call sequence. All other [`TransportClient`]
    /// methods return `NotImplemented` because the prefetch path
    /// only exercises `fetch_index_shards`.
    #[derive(Debug, Default)]
    struct RecordingTransport {
        responses: Mutex<HashMap<(String, String, String), Vec<u8>>>,
        calls: Mutex<Vec<(String, String, String)>>,
    }

    impl RecordingTransport {
        fn seed(&self, hash: &str, bucket: &str, shard_type: &str, bytes: Vec<u8>) {
            self.responses
                .lock()
                .unwrap()
                .insert((hash.into(), bucket.into(), shard_type.into()), bytes);
        }

        fn calls(&self) -> Vec<(String, String, String)> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl TransportClient for RecordingTransport {
        fn fetch_messages(
            &self,
            _conversation_id: &str,
            _after_cursor: Option<&str>,
        ) -> TransportResult<FetchMessagesResponse> {
            Err(crate::Error::NotImplemented("transport"))
        }
        fn init_blob_upload(
            &self,
            _size: u64,
            _blob_class: BlobClass,
            _expected_merkle_root: [u8; 32],
        ) -> TransportResult<BlobUploadHandle> {
            Err(crate::Error::NotImplemented("transport"))
        }
        fn upload_chunk(
            &self,
            _blob_id: &str,
            _chunk_idx: u32,
            _ciphertext: &[u8],
            _sha256: [u8; 32],
        ) -> TransportResult<ChunkReceipt> {
            Err(crate::Error::NotImplemented("transport"))
        }
        fn commit_blob(&self, _blob_id: &str) -> TransportResult<CommitBlobResponse> {
            Err(crate::Error::NotImplemented("transport"))
        }
        fn fetch_blob_range(&self, _blob_id: &str, _range: Range<u64>) -> TransportResult<Vec<u8>> {
            Err(crate::Error::NotImplemented("transport"))
        }
        fn fetch_archive_manifests(
            &self,
            _after_generation: Option<u64>,
        ) -> TransportResult<Vec<EncryptedManifest>> {
            Err(crate::Error::NotImplemented("transport"))
        }
        fn fetch_archive_segment(&self, _segment_id: &str) -> TransportResult<Vec<u8>> {
            Err(crate::Error::NotImplemented("transport"))
        }
        fn fetch_index_shards(
            &self,
            conversation_hash: &str,
            bucket: &str,
            shard_type: &str,
        ) -> TransportResult<Vec<u8>> {
            self.calls.lock().unwrap().push((
                conversation_hash.into(),
                bucket.into(),
                shard_type.into(),
            ));
            Ok(self
                .responses
                .lock()
                .unwrap()
                .get(&(conversation_hash.into(), bucket.into(), shard_type.into()))
                .cloned()
                .unwrap_or_default())
        }
    }

    fn fresh_config(level: PrivacyLevel) -> KChatCoreConfig {
        KChatCoreConfig::new(PathBuf::from("/tmp/d"), Platform::MacOs, "t")
            .with_privacy_level(level)
    }

    #[test]
    fn batch_prefetch_returns_every_seeded_shard_type() {
        let t = RecordingTransport::default();
        t.seed("hash", "2026-04", "text", b"text-bytes".to_vec());
        t.seed("hash", "2026-04", "fuzzy", b"fuzzy-bytes".to_vec());
        t.seed("hash", "2026-04", "vector", b"vector-bytes".to_vec());
        t.seed("hash", "2026-04", "media", b"media-bytes".to_vec());

        let out = batch_prefetch_shards(&t, "hash", "2026-04").expect("prefetch");
        assert_eq!(out.len(), 4);
        assert_eq!(out[0].shard_type, IndexType::Text);
        assert_eq!(out[1].shard_type, IndexType::Fuzzy);
        assert_eq!(out[2].shard_type, IndexType::Vector);
        assert_eq!(out[3].shard_type, IndexType::Media);
        for shard in &out {
            assert_eq!(shard.conversation_hash, "hash");
            assert_eq!(shard.bucket, "2026-04");
        }
        // Exactly one transport call per shard type.
        assert_eq!(t.calls().len(), 4);
    }

    #[test]
    fn batch_prefetch_skips_empty_transport_responses() {
        let t = RecordingTransport::default();
        t.seed("hash", "2026-04", "text", b"text-bytes".to_vec());
        // fuzzy / vector / media are unseeded → empty Vec → skipped.
        let out = batch_prefetch_shards(&t, "hash", "2026-04").expect("prefetch");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].shard_type, IndexType::Text);
        // The transport is still called for every type — the
        // batch contract is "one fan-out per call", not "skip
        // unseeded types".
        assert_eq!(t.calls().len(), 4);
    }

    #[test]
    fn empty_bucket_returns_empty_vec() {
        let t = RecordingTransport::default();
        let out = batch_prefetch_shards(&t, "hash", "2099-01").expect("prefetch");
        assert!(out.is_empty());
    }

    #[test]
    fn padding_disabled_emits_only_real_calls() {
        let t = RecordingTransport::default();
        t.seed("hash", "2026-04", "text", b"text-bytes".to_vec());
        let cfg = fresh_config(PrivacyLevel::Standard);
        let out =
            batch_prefetch_shards_with_padding(&t, "hash", "2026-04", &cfg).expect("prefetch");
        assert_eq!(out.len(), 1);
        assert_eq!(t.calls().len(), 4, "no dummy calls when padding disabled");
    }

    #[test]
    fn padding_enabled_emits_dummy_calls_in_addition_to_real() {
        let t = RecordingTransport::default();
        t.seed("hash", "2026-04", "text", b"text-bytes".to_vec());
        let cfg = fresh_config(PrivacyLevel::High);
        let out =
            batch_prefetch_shards_with_padding(&t, "hash", "2026-04", &cfg).expect("prefetch");
        // Real shards returned exactly as if padding was off —
        // dummies are observable on the transport, not in the
        // returned Vec.
        assert_eq!(out.len(), 1);
        // 4 real-target calls + (compute_padding_count(1) * 4)
        // dummy calls.
        let expected = 4 + compute_padding_count(1) * 4;
        assert_eq!(t.calls().len(), expected);
    }

    #[test]
    fn dummy_calls_use_distinct_conversation_hashes() {
        let t = RecordingTransport::default();
        t.seed("hash", "2026-04", "text", b"text-bytes".to_vec());
        let cfg = fresh_config(PrivacyLevel::High);
        let _ = batch_prefetch_shards_with_padding(&t, "hash", "2026-04", &cfg).expect("prefetch");
        let dummy_hashes: std::collections::HashSet<String> = t
            .calls()
            .into_iter()
            .filter_map(|(h, _, _)| if h == "hash" { None } else { Some(h) })
            .collect();
        // Each dummy iteration uses a fresh UUIDv4, so the set
        // size must equal `compute_padding_count(1)` (one unique
        // hash per dummy bucket).
        assert_eq!(dummy_hashes.len(), compute_padding_count(1));
    }
}
