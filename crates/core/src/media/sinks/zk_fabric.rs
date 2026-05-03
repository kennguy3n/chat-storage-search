//! ZK Object Fabric media blob sink. Implementation lands in
//! Phase 3.
//!
//! See `docs/PROPOSAL.md §5.7` (tiered media storage) and
//! `docs/PROPOSAL.md §10.2` (media blob sink routing). The Phase 3
//! implementation will reuse the ZKOF S3 PutObject / GetObject
//! transport from the archive-backend wiring.
