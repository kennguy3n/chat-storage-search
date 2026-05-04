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

use crate::archive::privacy::{compute_padding_count, pad_with_dummy_requests, should_pad};
use crate::config::KChatCoreConfig;
use crate::formats::search_shard::IndexType;
use crate::transport::TransportClient;
use crate::Error;

/// Default ordering of shard types fetched by
/// [`batch_prefetch_shards`]. Stable so the test suite can pin
/// the expected wire ordering, and so any caller that wants to
/// drop into [`IndexType::all`] for a parallel join sees a
/// predictable layout. Phase 8 prepends [`IndexType::Bloom`]:
/// the bloom filter shard is fetched first so the prefetcher
/// can short-circuit buckets whose filter rejects every query
/// token before paying for the larger Text / Fuzzy / Vector /
/// Media payloads.
const PREFETCH_ORDER: [IndexType; 5] = [
    IndexType::Bloom,
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
        IndexType::Bloom => "bloom",
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
/// Real and dummy `conversation_hash` values are **interleaved**
/// via [`pad_with_dummy_requests`] before any transport call
/// fires, so a network observer cannot recover the real target
/// from the position of the first burst of fetches. The
/// archive-segment counterpart in
/// [`crate::archive::prefetch::batch_prefetch_bucket_with_padding`]
/// uses the same shape.
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
    if !should_pad(config) {
        return batch_prefetch_shards(transport, conversation_hash, bucket);
    }
    let real_hashes = vec![conversation_hash.to_string()];
    let dummy_count = compute_padding_count(real_hashes.len());
    let interleaved = pad_with_dummy_requests(&real_hashes, dummy_count);
    let mut out: Vec<PrefetchedShard> = Vec::with_capacity(PREFETCH_ORDER.len());
    for hash in &interleaved {
        let is_real = hash == conversation_hash;
        for shard_type in PREFETCH_ORDER {
            let result = transport.fetch_index_shards(hash, bucket, shard_type_str(shard_type));
            if !is_real {
                // Best-effort dummy: ignore the response (and any
                // error — a 404 / NotImplemented on a dummy is the
                // expected case).
                continue;
            }
            let bytes = result?;
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
    }
    Ok(out)
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
        t.seed("hash", "2026-04", "bloom", b"bloom-bytes".to_vec());
        t.seed("hash", "2026-04", "text", b"text-bytes".to_vec());
        t.seed("hash", "2026-04", "fuzzy", b"fuzzy-bytes".to_vec());
        t.seed("hash", "2026-04", "vector", b"vector-bytes".to_vec());
        t.seed("hash", "2026-04", "media", b"media-bytes".to_vec());

        let out = batch_prefetch_shards(&t, "hash", "2026-04").expect("prefetch");
        assert_eq!(out.len(), 5);
        assert_eq!(out[0].shard_type, IndexType::Bloom);
        assert_eq!(out[1].shard_type, IndexType::Text);
        assert_eq!(out[2].shard_type, IndexType::Fuzzy);
        assert_eq!(out[3].shard_type, IndexType::Vector);
        assert_eq!(out[4].shard_type, IndexType::Media);
        for shard in &out {
            assert_eq!(shard.conversation_hash, "hash");
            assert_eq!(shard.bucket, "2026-04");
        }
        // Exactly one transport call per shard type.
        assert_eq!(t.calls().len(), 5);
    }

    #[test]
    fn batch_prefetch_skips_empty_transport_responses() {
        let t = RecordingTransport::default();
        t.seed("hash", "2026-04", "text", b"text-bytes".to_vec());
        // bloom / fuzzy / vector / media are unseeded → empty Vec → skipped.
        let out = batch_prefetch_shards(&t, "hash", "2026-04").expect("prefetch");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].shard_type, IndexType::Text);
        // The transport is still called for every type — the
        // batch contract is "one fan-out per call", not "skip
        // unseeded types".
        assert_eq!(t.calls().len(), 5);
    }

    #[test]
    fn shard_prefetch_order_includes_bloom_first() {
        let t = RecordingTransport::default();
        t.seed("hash", "2026-04", "bloom", b"bloom-bytes".to_vec());
        t.seed("hash", "2026-04", "text", b"text-bytes".to_vec());
        let _ = batch_prefetch_shards(&t, "hash", "2026-04").expect("prefetch");
        let calls = t.calls();
        assert_eq!(calls.len(), 5);
        // The transport is invoked in PREFETCH_ORDER. The first
        // call must be the bloom shard.
        assert_eq!(calls[0].2, "bloom");
        assert_eq!(calls[1].2, "text");
        assert_eq!(calls[2].2, "fuzzy");
        assert_eq!(calls[3].2, "vector");
        assert_eq!(calls[4].2, "media");
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
        assert_eq!(
            t.calls().len(),
            PREFETCH_ORDER.len(),
            "no dummy calls when padding disabled"
        );
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
        // PREFETCH_ORDER.len() real-target calls +
        // (compute_padding_count(1) * PREFETCH_ORDER.len())
        // dummy calls.
        let n = PREFETCH_ORDER.len();
        let expected = n + compute_padding_count(1) * n;
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

    #[test]
    fn padding_interleaves_real_and_dummy_calls() {
        // Regression test for the privacy bug: under the old
        // implementation the first 4 transport calls always
        // targeted the real `conversation_hash`, so a network
        // observer could read the real target straight off the
        // wire. The fix interleaves real + dummy hashes via
        // `pad_with_dummy_requests` before issuing any call, so
        // across many runs the real hash must NOT always appear
        // at position 0.
        let cfg = fresh_config(PrivacyLevel::High);
        let trials = 64;
        let mut real_first = 0usize;
        for _ in 0..trials {
            let t = RecordingTransport::default();
            t.seed("hash", "2026-04", "text", b"text-bytes".to_vec());
            let _ =
                batch_prefetch_shards_with_padding(&t, "hash", "2026-04", &cfg).expect("prefetch");
            let calls = t.calls();
            // The very first transport call's `conversation_hash`
            // tells us whether the real target was issued first.
            if calls.first().map(|(h, _, _)| h == "hash").unwrap_or(false) {
                real_first += 1;
            }
        }
        // With `compute_padding_count(1) == 2`, the interleaved
        // list has 3 hashes; under uniform shuffling the real
        // hash lands at position 0 ≈ 1/3 of the time. Allow a
        // very wide tail (≤ 60/64) so the test stays stable
        // across rand versions, but reject the broken
        // "real-always-first" case.
        assert!(
            real_first < trials,
            "real hash must not be issued first on every run (was {real_first}/{trials})"
        );
    }

    #[test]
    fn padding_returned_results_match_unpadded_results() {
        // Whichever interleaving the shuffle picks, the returned
        // `Vec<PrefetchedShard>` must be byte-identical to the
        // unpadded path — only the *transport call sequence*
        // changes when padding is on.
        let cfg = fresh_config(PrivacyLevel::High);
        let t_padded = RecordingTransport::default();
        let t_unpadded = RecordingTransport::default();
        for shard_type in ["text", "fuzzy", "vector", "media"] {
            let bytes = format!("{shard_type}-bytes").into_bytes();
            t_padded.seed("hash", "2026-04", shard_type, bytes.clone());
            t_unpadded.seed("hash", "2026-04", shard_type, bytes);
        }
        let padded =
            batch_prefetch_shards_with_padding(&t_padded, "hash", "2026-04", &cfg).expect("padded");
        let unpadded = batch_prefetch_shards(&t_unpadded, "hash", "2026-04").expect("unpadded");
        assert_eq!(padded, unpadded, "padding must not alter returned shards");
    }
}
