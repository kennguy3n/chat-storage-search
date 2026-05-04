//! Encrypted search-index shard build / restore (Phase 4, Task 6).
//!
//! `docs/PROPOSAL.md §7.8` describes the encrypted shard layer
//! that the cloud-backup / archive pipelines use to seal FTS and
//! fuzzy index rows. This module is the **runtime** counterpart
//! to [`crate::formats::search_shard::SearchIndexShard`] (the
//! wire format): it knows how to drain `search_fts` and
//! `search_fuzzy` rows for a `(conversation_id, time_bucket)`,
//! seal them into an [`SearchIndexShard`], and walk the inverse
//! path during restore.
//!
//! Sealing pipeline:
//!
//! 1. Read rows for the bucket from the local store.
//! 2. CBOR-encode the rows into an [`FtsShardPayload`] /
//!    [`FuzzyShardPayload`].
//! 3. zstd-compress the CBOR.
//! 4. AEAD-seal the compressed bytes with the appropriate
//!    `K_text_index_shard(shard_id)` /
//!    `K_fuzzy_index_shard(shard_id)` (Phase 4 reuses the
//!    text-index hierarchy for fuzzy shards until the per-fuzzy
//!    derivation lands in Phase 5).
//! 5. Wrap the ciphertext into a [`SearchIndexShard`] so the
//!    backup manifest can carry it.
//!
//! Restoration is the inverse: `K_*_index_shard(shard_id)` →
//! AEAD open → zstd decode → CBOR decode → row vector.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::aead::xchacha20_poly1305::{open, seal, KEY_LEN, NONCE_LEN};
use crate::crypto::content_hash::content_hash;
use crate::crypto::key_hierarchy::KeyMaterial;
use crate::formats::search_shard::{
    IndexType, SearchIndexShard, SHARD_COMPRESSION, SHARD_ENCRYPTION, SHARD_MAGIC, SHARD_VERSION,
};
use crate::Error;

/// zstd compression level used for the FTS and fuzzy shard
/// payloads. Mirrors
/// [`crate::backup::segment_builder::ZSTD_COMPRESSION_LEVEL`].
const SHARD_ZSTD_LEVEL: i32 = 3;

/// AAD magic prefix for FTS / fuzzy shard seals. Domain-separated
/// from the backup-segment AAD magic so a malicious sealer cannot
/// retag a backup segment as a search shard.
pub const SEARCH_SHARD_AAD_MAGIC: &[u8] = b"KCHAT_SEARCH_SHARD_AAD_V1";

// ---------------------------------------------------------------------------
// Row types
// ---------------------------------------------------------------------------

/// One row of `search_fts` ready to seal into a text shard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FtsRow {
    /// Message identifier (string form of the UUID v7).
    pub message_id: String,
    /// Conversation identifier (string form of the UUID v7).
    pub conversation_id: String,
    /// Sender identifier — same shape as
    /// [`crate::local_store::schema::MessageSkeleton::sender_id`].
    pub sender_id: String,
    /// Wall-clock timestamp the message was created (ms epoch).
    pub created_at_ms: i64,
    /// Plaintext text body.
    pub text_content: String,
}

/// One row of `search_fuzzy` ready to seal into a fuzzy shard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuzzyRow {
    /// N-gram token (already lowercased — see
    /// [`crate::search::fuzzy_search::FuzzyTokenizer`]).
    pub token: String,
    /// ISO-15924 script tag (text projection of
    /// [`crate::search::tokenizer::ScriptClass`]).
    pub script: String,
    /// Message identifier the token row belongs to.
    pub message_id: String,
}

// ---------------------------------------------------------------------------
// Payload shapes (CBOR-sealed inside the shard ciphertext)
// ---------------------------------------------------------------------------

/// Domain-separation magic for [`FtsShardPayload`].
pub const TEXT_SHARD_PAYLOAD_MAGIC: &[u8] = b"KCHAT_TEXT_SHARD_PAYLOAD_V1";

/// Domain-separation magic for [`FuzzyShardPayload`].
pub const FUZZY_SHARD_PAYLOAD_MAGIC: &[u8] = b"KCHAT_FUZZY_SHARD_PAYLOAD_V1";

/// CBOR-sealed plaintext of a text [`SearchIndexShard`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FtsShardPayload {
    /// Always [`TEXT_SHARD_PAYLOAD_MAGIC`].
    #[serde(with = "serde_bytes")]
    pub magic: Vec<u8>,
    /// FTS rows packed in this shard.
    pub rows: Vec<FtsRow>,
}

/// CBOR-sealed plaintext of a fuzzy [`SearchIndexShard`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuzzyShardPayload {
    /// Always [`FUZZY_SHARD_PAYLOAD_MAGIC`].
    #[serde(with = "serde_bytes")]
    pub magic: Vec<u8>,
    /// Fuzzy n-gram rows packed in this shard.
    pub rows: Vec<FuzzyRow>,
}

// ---------------------------------------------------------------------------
// Build / restore
// ---------------------------------------------------------------------------

/// Output of [`build_text_search_shard`] /
/// [`build_fuzzy_search_shard`].
#[derive(Debug, Clone)]
pub struct BuiltShard {
    /// Wire-format shard ready to attach to a backup manifest.
    pub shard: SearchIndexShard,
    /// `K_*_index_shard(shard_id)` the orchestrator just sealed
    /// the shard under. Phase 5 will move this into a
    /// `wrapped_k_shard` field on the manifest entry — until
    /// then the orchestrator keeps it in memory the same way the
    /// backup pipeline keeps `K_backup_segment` next to
    /// `BuiltBackupSegment` (Task 5).
    pub k_shard: KeyMaterial,
}

/// Compute the canonical AAD for a shard seal:
/// `SEARCH_SHARD_AAD_MAGIC || index_type_byte || shard_id(16) ||
/// conversation_id_hash || time_bucket`.
fn build_shard_aad(
    shard_id: &Uuid,
    index_type: IndexType,
    conversation_id_hash: &[u8],
    time_bucket: &str,
) -> Vec<u8> {
    let it_byte: u8 = match index_type {
        IndexType::Text => 1,
        IndexType::Fuzzy => 2,
        IndexType::Vector => 3,
        IndexType::Media => 4,
    };
    let mut aad = Vec::with_capacity(
        SEARCH_SHARD_AAD_MAGIC.len() + 1 + 16 + conversation_id_hash.len() + time_bucket.len(),
    );
    aad.extend_from_slice(SEARCH_SHARD_AAD_MAGIC);
    aad.push(it_byte);
    aad.extend_from_slice(shard_id.as_bytes());
    aad.extend_from_slice(conversation_id_hash);
    aad.extend_from_slice(time_bucket.as_bytes());
    aad
}

/// BLAKE3-keyed-hash of a conversation id under
/// `conversation_hash_key`.
///
/// Stable across runs given the same inputs — the cold-shard
/// transport pipeline uses this to translate a plaintext
/// `conversation_id` into the opaque
/// `conversation_id_hash` the backend stores its shards under
/// (`docs/PROPOSAL.md §7.8`).
pub fn keyed_conversation_id_hash(
    conversation_id: &str,
    conversation_hash_key: &KeyMaterial,
) -> Vec<u8> {
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(conversation_hash_key.as_bytes());
    blake3::keyed_hash(&key, conversation_id.as_bytes())
        .as_bytes()
        .to_vec()
}

fn random_nonce() -> [u8; NONCE_LEN] {
    use rand::RngCore;
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Seal `payload_cbor` into a [`SearchIndexShard`] under the
/// derived per-shard key.
fn seal_shard(
    rows_cbor: Vec<u8>,
    index_type: IndexType,
    conversation_id_hash: Vec<u8>,
    time_bucket: String,
    doc_count: u64,
    k_shard: &KeyMaterial,
) -> Result<SearchIndexShard, Error> {
    let compressed = zstd::stream::encode_all(&rows_cbor[..], SHARD_ZSTD_LEVEL)
        .map_err(|e| Error::Storage(format!("search shard zstd encode: {e}")))?;
    let shard_id = Uuid::now_v7();
    let nonce = random_nonce();
    let aad = build_shard_aad(&shard_id, index_type, &conversation_id_hash, &time_bucket);
    let aad_hash = content_hash(&aad);

    let ciphertext = seal(k_shard.as_bytes(), &nonce, &compressed, &aad).map_err(Error::Crypto)?;
    let ciphertext_sha256 = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&ciphertext);
        let out = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&out);
        arr
    };

    Ok(SearchIndexShard {
        magic: SHARD_MAGIC.to_string(),
        version: SHARD_VERSION,
        shard_id,
        index_type,
        conversation_id_hash,
        time_bucket,
        doc_count,
        compression: SHARD_COMPRESSION.to_string(),
        encryption: SHARD_ENCRYPTION.to_string(),
        nonce,
        aad_hash,
        ciphertext,
        ciphertext_sha256,
    })
}

/// Build an encrypted FTS shard from the supplied rows.
///
/// `k_text_index_shard` is the per-shard AEAD key — typically
/// `K_text_index_shard(shard_id)` from
/// [`crate::crypto::key_hierarchy::derive_text_index_shard`].
/// Because the shard generates its own `shard_id` internally
/// (mirroring [`crate::backup::segment_builder::BackupSegmentBuilder::build_segment`]),
/// the orchestrator stores `k_shard` alongside the shard so it
/// can re-open the seal without having to re-derive.
pub fn build_text_search_shard(
    rows: Vec<FtsRow>,
    conversation_id: &str,
    time_bucket: impl Into<String>,
    k_text_index_shard: &KeyMaterial,
    conversation_hash_key: &KeyMaterial,
) -> Result<BuiltShard, Error> {
    let payload = FtsShardPayload {
        magic: TEXT_SHARD_PAYLOAD_MAGIC.to_vec(),
        rows: rows.clone(),
    };
    let cbor = serde_cbor::to_vec(&payload)
        .map_err(|e| Error::Storage(format!("text shard cbor encode: {e}")))?;
    let conversation_id_hash = keyed_conversation_id_hash(conversation_id, conversation_hash_key);
    let shard = seal_shard(
        cbor,
        IndexType::Text,
        conversation_id_hash,
        time_bucket.into(),
        rows.len() as u64,
        k_text_index_shard,
    )?;
    Ok(BuiltShard {
        shard,
        k_shard: k_text_index_shard.clone(),
    })
}

/// Build an encrypted fuzzy-token shard from the supplied rows.
pub fn build_fuzzy_search_shard(
    rows: Vec<FuzzyRow>,
    conversation_id: &str,
    time_bucket: impl Into<String>,
    k_fuzzy_index_shard: &KeyMaterial,
    conversation_hash_key: &KeyMaterial,
) -> Result<BuiltShard, Error> {
    let payload = FuzzyShardPayload {
        magic: FUZZY_SHARD_PAYLOAD_MAGIC.to_vec(),
        rows: rows.clone(),
    };
    let cbor = serde_cbor::to_vec(&payload)
        .map_err(|e| Error::Storage(format!("fuzzy shard cbor encode: {e}")))?;
    let conversation_id_hash = keyed_conversation_id_hash(conversation_id, conversation_hash_key);
    let shard = seal_shard(
        cbor,
        IndexType::Fuzzy,
        conversation_id_hash,
        time_bucket.into(),
        rows.len() as u64,
        k_fuzzy_index_shard,
    )?;
    Ok(BuiltShard {
        shard,
        k_shard: k_fuzzy_index_shard.clone(),
    })
}

/// Decrypt + decompress + decode a text [`SearchIndexShard`]
/// previously built by [`build_text_search_shard`].
pub fn restore_text_search_shard(
    shard: &SearchIndexShard,
    k_text_index_shard: &KeyMaterial,
) -> Result<Vec<FtsRow>, Error> {
    if shard.index_type != IndexType::Text {
        return Err(Error::Storage(format!(
            "restore_text_search_shard: index_type {:?} != Text",
            shard.index_type
        )));
    }
    let cbor = open_shard(shard, k_text_index_shard)?;
    let payload: FtsShardPayload = serde_cbor::from_slice(&cbor)
        .map_err(|e| Error::Storage(format!("text shard cbor decode: {e}")))?;
    if payload.magic != TEXT_SHARD_PAYLOAD_MAGIC {
        return Err(Error::Storage("text shard payload magic mismatch".into()));
    }
    Ok(payload.rows)
}

/// Decrypt + decompress + decode a fuzzy [`SearchIndexShard`]
/// previously built by [`build_fuzzy_search_shard`].
pub fn restore_fuzzy_search_shard(
    shard: &SearchIndexShard,
    k_fuzzy_index_shard: &KeyMaterial,
) -> Result<Vec<FuzzyRow>, Error> {
    if shard.index_type != IndexType::Fuzzy {
        return Err(Error::Storage(format!(
            "restore_fuzzy_search_shard: index_type {:?} != Fuzzy",
            shard.index_type
        )));
    }
    let cbor = open_shard(shard, k_fuzzy_index_shard)?;
    let payload: FuzzyShardPayload = serde_cbor::from_slice(&cbor)
        .map_err(|e| Error::Storage(format!("fuzzy shard cbor decode: {e}")))?;
    if payload.magic != FUZZY_SHARD_PAYLOAD_MAGIC {
        return Err(Error::Storage("fuzzy shard payload magic mismatch".into()));
    }
    Ok(payload.rows)
}

fn open_shard(shard: &SearchIndexShard, k: &KeyMaterial) -> Result<Vec<u8>, Error> {
    if !shard.has_valid_header() {
        return Err(Error::Storage(
            "search shard header / version mismatch".into(),
        ));
    }
    let aad = build_shard_aad(
        &shard.shard_id,
        shard.index_type,
        &shard.conversation_id_hash,
        &shard.time_bucket,
    );
    let actual_aad_hash = content_hash(&aad);
    if actual_aad_hash != shard.aad_hash {
        return Err(Error::Storage("search shard aad_hash mismatch".into()));
    }
    let compressed =
        open(k.as_bytes(), &shard.nonce, &shard.ciphertext, &aad).map_err(Error::Crypto)?;
    let cbor = zstd::stream::decode_all(&compressed[..])
        .map_err(|e| Error::Storage(format!("search shard zstd decode: {e}")))?;
    Ok(cbor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::key_hierarchy::{derive_search_root, derive_text_index_shard};

    fn fresh_shard_key() -> KeyMaterial {
        let identity = KeyMaterial::from_bytes([0xAB; 32]);
        let search_root = derive_search_root(&identity).expect("derive search root");
        derive_text_index_shard(&search_root, &Uuid::now_v7().into_bytes())
            .expect("derive shard key")
    }

    fn fresh_conv_hash_key() -> KeyMaterial {
        KeyMaterial::from_bytes([0x77; 32])
    }

    fn sample_text_rows(n: usize) -> Vec<FtsRow> {
        (0..n)
            .map(|i| FtsRow {
                message_id: format!("msg-{i}"),
                conversation_id: "conv-A".to_string(),
                sender_id: format!("sender-{}", i % 3),
                created_at_ms: 1_777_000_000_000 + (i as i64) * 1_000,
                text_content: format!("hello world #{i} the quick brown fox"),
            })
            .collect()
    }

    fn sample_fuzzy_rows(n: usize) -> Vec<FuzzyRow> {
        (0..n)
            .map(|i| FuzzyRow {
                token: format!("tok{i:03}"),
                script: "Latn".to_string(),
                message_id: format!("msg-{i}"),
            })
            .collect()
    }

    #[test]
    fn text_shard_build_and_restore_round_trip() {
        let key = fresh_shard_key();
        let conv_key = fresh_conv_hash_key();
        let rows = sample_text_rows(8);
        let built = build_text_search_shard(rows.clone(), "conv-A", "2026-04", &key, &conv_key)
            .expect("build");
        assert!(built.shard.has_valid_header());
        assert_eq!(built.shard.index_type, IndexType::Text);
        assert_eq!(built.shard.doc_count, 8);
        let restored = restore_text_search_shard(&built.shard, &built.k_shard).expect("restore");
        assert_eq!(restored, rows);
    }

    #[test]
    fn fuzzy_shard_build_and_restore_round_trip() {
        let key = fresh_shard_key();
        let conv_key = fresh_conv_hash_key();
        let rows = sample_fuzzy_rows(12);
        let built = build_fuzzy_search_shard(rows.clone(), "conv-A", "2026-04", &key, &conv_key)
            .expect("build");
        assert!(built.shard.has_valid_header());
        assert_eq!(built.shard.index_type, IndexType::Fuzzy);
        let restored = restore_fuzzy_search_shard(&built.shard, &built.k_shard).expect("restore");
        assert_eq!(restored, rows);
    }

    #[test]
    fn wrong_key_fails_text_shard_decrypt() {
        let key = fresh_shard_key();
        let conv_key = fresh_conv_hash_key();
        let rows = sample_text_rows(4);
        let built =
            build_text_search_shard(rows, "conv-A", "2026-04", &key, &conv_key).expect("build");
        let bogus = KeyMaterial::from_bytes([0xFF; 32]);
        let err = restore_text_search_shard(&built.shard, &bogus).unwrap_err();
        assert!(matches!(err, Error::Crypto(_)), "got {err:?}");
    }

    #[test]
    fn wrong_key_fails_fuzzy_shard_decrypt() {
        let key = fresh_shard_key();
        let conv_key = fresh_conv_hash_key();
        let rows = sample_fuzzy_rows(4);
        let built =
            build_fuzzy_search_shard(rows, "conv-A", "2026-04", &key, &conv_key).expect("build");
        let bogus = KeyMaterial::from_bytes([0xFF; 32]);
        let err = restore_fuzzy_search_shard(&built.shard, &bogus).unwrap_err();
        assert!(matches!(err, Error::Crypto(_)), "got {err:?}");
    }

    #[test]
    fn restore_with_wrong_index_type_fails() {
        let key = fresh_shard_key();
        let conv_key = fresh_conv_hash_key();
        let rows = sample_text_rows(2);
        let built =
            build_text_search_shard(rows, "conv-A", "2026-04", &key, &conv_key).expect("build");
        // Pass to fuzzy restorer.
        let err = restore_fuzzy_search_shard(&built.shard, &built.k_shard).unwrap_err();
        assert!(
            matches!(&err, Error::Storage(msg) if msg.contains("Fuzzy")),
            "got {err:?}"
        );
    }

    #[test]
    fn multilingual_content_survives_text_shard_round_trip() {
        let key = fresh_shard_key();
        let conv_key = fresh_conv_hash_key();
        // Latin + Cyrillic + CJK + Arabic + Devanagari + mixed.
        let rows = vec![
            FtsRow {
                message_id: "m1".into(),
                conversation_id: "conv-A".into(),
                sender_id: "alice".into(),
                created_at_ms: 1_777_000_000_000,
                text_content: "hello world".into(),
            },
            FtsRow {
                message_id: "m2".into(),
                conversation_id: "conv-A".into(),
                sender_id: "bob".into(),
                created_at_ms: 1_777_000_001_000,
                text_content: "Привет, мир".into(),
            },
            FtsRow {
                message_id: "m3".into(),
                conversation_id: "conv-A".into(),
                sender_id: "carol".into(),
                created_at_ms: 1_777_000_002_000,
                text_content: "你好世界".into(),
            },
            FtsRow {
                message_id: "m4".into(),
                conversation_id: "conv-A".into(),
                sender_id: "dave".into(),
                created_at_ms: 1_777_000_003_000,
                text_content: "مرحبا بالعالم".into(),
            },
            FtsRow {
                message_id: "m5".into(),
                conversation_id: "conv-A".into(),
                sender_id: "eve".into(),
                created_at_ms: 1_777_000_004_000,
                text_content: "नमस्ते दुनिया".into(),
            },
            FtsRow {
                message_id: "m6".into(),
                conversation_id: "conv-A".into(),
                sender_id: "frank".into(),
                created_at_ms: 1_777_000_005_000,
                text_content: "Meeting at 3pm 会議室で".into(),
            },
        ];
        let built = build_text_search_shard(rows.clone(), "conv-A", "2026-04", &key, &conv_key)
            .expect("build");
        let restored = restore_text_search_shard(&built.shard, &built.k_shard).expect("restore");
        assert_eq!(restored, rows);
    }

    #[test]
    fn tampered_aad_hash_fails_open() {
        let key = fresh_shard_key();
        let conv_key = fresh_conv_hash_key();
        let rows = sample_text_rows(2);
        let mut built =
            build_text_search_shard(rows, "conv-A", "2026-04", &key, &conv_key).expect("build");
        built.shard.aad_hash[0] ^= 0xFF;
        let err = restore_text_search_shard(&built.shard, &built.k_shard).unwrap_err();
        assert!(
            matches!(&err, Error::Storage(msg) if msg.contains("aad_hash")),
            "got {err:?}"
        );
    }
}
