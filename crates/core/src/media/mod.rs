//! `media` module — Phase 2 chunked-media pipeline.
//!
//! Phase 0 / Phase 1 left this module as a placeholder. Phase 2 lands
//! the chunked-media pipeline that splits a plaintext blob into
//! AEAD-sealed chunks, persists the descriptor side of the asset,
//! and uploads the ciphertext to the configured backend:
//!
//! * [`chunker`] — split, AEAD-seal (`docs/PROPOSAL.md §8.3`),
//!   integrity-verify, and size-class pad (`§8.2`).
//! * [`processor`] — generate `K_asset`, run [`chunker::chunk_and_encrypt`],
//!   wrap `K_asset` under a hierarchy root, and assemble the
//!   [`crate::formats::media_descriptor::MediaDescriptor`] the rest
//!   of the system persists.
//! * [`upload`] — drive [`crate::transport::TransportClient`] through
//!   the `init → chunk(s) → commit` sequence with server-side Merkle
//!   verification and a resume path that skips already-uploaded
//!   chunks.
//! * [`download`] — inverse of [`upload`]: drive `fetch_blob_range`
//!   per chunk, verify per-chunk SHA-256, AEAD-open under the same
//!   per-chunk AAD, and re-verify the whole-object BLAKE3 root.
//! * [`cache`] — local LRU cache for decrypted media originals so
//!   the rehydration path doesn't re-pay AEAD work for hot assets.
//! * [`caption`] — Unicode-NFC normalization and filesystem-safe
//!   sanitization for multilingual filenames / captions
//!   (`docs/PROPOSAL.md §3.4`).
//! * [`routing`] — `route_media_upload` / `route_media_download`
//!   dispatch between the KChat [`crate::transport::TransportClient`]
//!   and an optional [`sinks::MediaBlobSink`] per
//!   `docs/PROPOSAL.md §5.7`.
//! * [`sinks`] — the [`sinks::MediaBlobSink`] routing seam for
//!   media-original uploads / downloads (KChat backend, iCloud,
//!   Google Drive, ZK Object Fabric). See `docs/PROPOSAL.md §5.7`.

pub mod cache;
pub mod caption;
pub mod chunker;
pub mod download;
pub mod processor;
pub mod routing;
pub mod sinks;
pub mod upload;
