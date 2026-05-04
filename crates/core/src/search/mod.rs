//! `search` module — search engine surface.
//!
//! Phase 0 lands the multilingual tokenization spec ([`tokenizer`]):
//! the FTS5 `tokenize = '...'` literal, the ISO-15924 [`ScriptClass`],
//! the trigram-vs-bigram [`FuzzyGranularity`] mapping, and the
//! mixed-script `segment_by_script` helper that the fuzzy indexer
//! uses to tag rows. The actual FTS5 / fuzzy / vector engines land in
//! Phases 1, 5, and 6 respectively — see `docs/PHASES.md`.
//!
//! [`ScriptClass`]: tokenizer::ScriptClass
//! [`FuzzyGranularity`]: tokenizer::FuzzyGranularity

pub mod cold_shard_source;
pub mod fuzzy_search;
pub mod query_engine;
pub mod search_target;
pub mod semantic_search;
pub mod shard_builder;
pub mod shard_cache;
pub mod shard_prefetch;
pub mod text_search;
pub mod tokenizer;
