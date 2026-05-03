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
//! * [`sinks`] — the [`sinks::MediaBlobSink`] routing seam for
//!   media-original uploads / downloads (KChat backend, iCloud,
//!   Google Drive, ZK Object Fabric). See `docs/PROPOSAL.md §5.7`.

pub mod chunker;
pub mod processor;
pub mod sinks;
pub mod upload;
