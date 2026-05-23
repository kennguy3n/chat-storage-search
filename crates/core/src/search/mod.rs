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

/// Search-layer error type wrapped by [`crate::Error::Search`].
///
/// Search failures fall into two buckets: SQL-side failures (the
/// `search_fts` / `search_fuzzy` / `search_vector` virtual-table
/// queries) and pure-Rust failures (query parse, shard cache miss,
/// cold-source fetch). The SQL bucket bubbles up through
/// [`SearchError::Sqlite`] so the `?` operator works; the rest are
/// either structured variants ([`SearchError::QueryParse`]) or fall
/// through to [`SearchError::Custom`].
#[derive(Debug, thiserror::Error)]
pub enum SearchError {
    /// A SQL query against `search_fts` / `search_fuzzy` /
    /// `search_vector` failed. Includes the upstream
    /// [`rusqlite::Error`] verbatim.
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// Parsing the user-supplied [`crate::SearchQuery`] failed
    /// (malformed FTS5 expression, unbalanced quotes, …).
    #[error("query parse: {0}")]
    QueryParse(String),

    /// A cold-source fetch (downloading a remote shard, opening a
    /// search-index manifest) failed.
    #[error("cold source ({context}): {detail}")]
    ColdSource {
        /// Static label identifying the cold-source operation.
        context: &'static str,
        /// Free-form detail captured from the underlying failure.
        detail: String,
    },

    /// Free-form fallback. New failure modes should prefer a typed
    /// variant.
    #[error("{0}")]
    Custom(String),
}

impl SearchError {
    /// Construct a [`SearchError::Custom`] from anything convertible
    /// to [`String`]. Mirrors [`crate::local_store::StorageError::msg`].
    pub fn msg(msg: impl Into<String>) -> Self {
        SearchError::Custom(msg.into())
    }
}

/// Lift a [`crate::local_store::DbError`] into a [`SearchError`].
///
/// `DbError::Rusqlite` lowers to [`SearchError::Sqlite`] verbatim so
/// pattern-matches on raw `rusqlite::Error` codes (e.g. `SQLITE_BUSY`)
/// keep working through the search lane; the remaining `DbError`
/// variants are free-form and lower to [`SearchError::Custom`] with
/// their [`std::fmt::Display`] text preserved.
impl From<crate::local_store::db::DbError> for SearchError {
    fn from(e: crate::local_store::db::DbError) -> Self {
        match e {
            crate::local_store::db::DbError::Rusqlite(s) => SearchError::Sqlite(s),
            other => SearchError::Custom(other.to_string()),
        }
    }
}
