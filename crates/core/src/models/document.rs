//! On-device document text extraction seam — Phase 6, Task 2 of
//! the 2026-05-04 batch.
//!
//! `docs/PROPOSAL.md §7.6` mandates page-level multilingual text
//! extraction for PDF and DOCX attachments so document bodies
//! flow through the same media-search index as OCR captions and
//! Whisper transcripts. The extraction itself runs in the
//! platform layer (PDFKit on iOS / macOS, Apache POI on Android,
//! Adobe / Tesseract / Apache POI on Windows desktop, …); this
//! module is the object-safe Rust seam the platform glue plugs
//! into.
//!
//! The trait is intentionally stateless and synchronous so the
//! same instance can be shared across `send_media` calls without
//! a `&mut self` restriction. Implementations MUST be cheap to
//! call repeatedly — they will be invoked from inside the open
//! `SAVEPOINT send_media;` transaction in
//! [`crate::core_impl::CoreImpl::send_media`].
//!
//! The MIME hint is the courtesy contract: `"application/pdf"`
//! and `"application/vnd.openxmlformats-officedocument.wordprocessingml.document"`
//! are the two formats the orchestration layer dispatches to
//! the extractor. Implementations are free to support more
//! formats — the hint is the disambiguator, not a gate.

use crate::Result;

/// One extracted page from a [`DocumentExtractor::extract_text`]
/// call.
///
/// `page_number` is 1-indexed (matches the way users / readers
/// number pages); `language` is the BCP-47 / ISO-639 tag the
/// extractor reported (`"en"`, `"es"`, `"zh"`, …) when
/// available. Pages without a detected language MUST set
/// `language = None` rather than picking a default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentPage {
    /// 1-indexed page number.
    pub page_number: u32,
    /// Extracted plaintext for this page.
    pub text: String,
    /// Detected language tag (`None` when the extractor did
    /// not report one).
    pub language: Option<String>,
}

/// On-device document text-extraction seam used by media
/// ingest (`docs/PROPOSAL.md §7.6`, Phase 6).
///
/// Object-safe + `Send + Sync` so [`crate::core_impl::CoreImpl`]
/// can stash a real platform extractor inside
/// `Mutex<Option<Box<dyn DocumentExtractor>>>` and reuse the
/// same instance across `send_media` calls. Implementations
/// SHOULD reject unsupported MIME types with
/// [`crate::Error::Model`] rather than returning an empty
/// `Vec<DocumentPage>`.
pub trait DocumentExtractor: std::fmt::Debug + Send + Sync {
    /// Extract per-page text from `data`. `mime_type` is the
    /// source MIME hint
    /// (`"application/pdf"` for PDFs,
    /// `"application/vnd.openxmlformats-officedocument.wordprocessingml.document"`
    /// for DOCX).
    fn extract_text(&self, data: &[u8], mime_type: &str) -> Result<Vec<DocumentPage>>;
}

/// Alias matching the Phase 6 task-spec name. `PageText` and
/// [`DocumentPage`] are the same struct — the alias lets call
/// sites use either name interchangeably while the trait
/// signature continues to return `Vec<DocumentPage>`.
pub use DocumentPage as PageText;

/// Wrapper helper matching the Phase 6 task-spec
/// `DocumentExtractionResult { pages }` shape. Implementations
/// of [`DocumentExtractor`] return `Vec<DocumentPage>` directly,
/// but callers that prefer the wrapper can build one with
/// [`DocumentExtractionResult::from_pages`] without changing the
/// trait surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentExtractionResult {
    /// Extracted pages, ordered by [`PageText::page_number`].
    pub pages: Vec<PageText>,
}

impl DocumentExtractionResult {
    /// Build a result from a `Vec<DocumentPage>` returned by
    /// an extractor.
    pub fn from_pages(pages: Vec<DocumentPage>) -> Self {
        Self { pages }
    }
}

impl From<Vec<DocumentPage>> for DocumentExtractionResult {
    fn from(pages: Vec<DocumentPage>) -> Self {
        Self::from_pages(pages)
    }
}

/// Always-`NotImplemented` [`DocumentExtractor`] for builds
/// without a real platform extractor wired in.
///
/// `extract_text` returns
/// [`crate::Error::NotImplemented("document_extractor")`](crate::Error::NotImplemented).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopDocumentExtractor;

impl DocumentExtractor for NoopDocumentExtractor {
    fn extract_text(&self, _data: &[u8], _mime_type: &str) -> Result<Vec<DocumentPage>> {
        Err(crate::Error::NotImplemented("document_extractor"))
    }
}

/// Deterministic test [`DocumentExtractor`] that derives a
/// reproducible per-page extraction from a BLAKE3 hash of
/// `(mime_type, data)`.
///
/// Used by the Phase 6 unit / integration tests to stand in for
/// a real PDFKit / Apache-POI / Tesseract extractor. Same
/// construction as [`crate::models::embeddings::MockTextEmbedder`]:
/// the hash seeds the synthetic extraction so identical inputs
/// always yield identical pages and distinct inputs always
/// diverge.
#[derive(Debug, Clone, Copy)]
pub struct MockDocumentExtractor {
    /// Number of synthetic pages the mock returns. Defaults to
    /// 3 — enough for tests that need to assert the per-page
    /// fan-out into [`crate::local_store::db::LocalStoreDb::insert_media_search_index`].
    page_count: u32,
}

impl Default for MockDocumentExtractor {
    fn default() -> Self {
        Self { page_count: 3 }
    }
}

impl MockDocumentExtractor {
    /// Build a [`MockDocumentExtractor`] that emits `page_count`
    /// pages.
    pub fn with_page_count(page_count: u32) -> Self {
        assert!(
            page_count > 0,
            "MockDocumentExtractor page_count must be > 0"
        );
        Self { page_count }
    }

    /// Number of synthetic pages the mock will emit.
    pub fn page_count(&self) -> u32 {
        self.page_count
    }
}

const PDF_MIME: &str = "application/pdf";
const DOCX_MIME: &str = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";

/// Whether `mime_type` is one of the two document MIME types the
/// `send_media` document-extraction path dispatches to.
///
/// Lifted out into a free function so the
/// [`crate::core_impl::CoreImpl`] gate and the
/// [`MockDocumentExtractor`]'s validation share one source of
/// truth — adding a new format to the dispatch only requires
/// editing one branch.
pub fn is_supported_document_mime(mime_type: &str) -> bool {
    matches!(mime_type, PDF_MIME | DOCX_MIME)
}

impl DocumentExtractor for MockDocumentExtractor {
    fn extract_text(&self, data: &[u8], mime_type: &str) -> Result<Vec<DocumentPage>> {
        if !is_supported_document_mime(mime_type) {
            return Err(crate::Error::Model(
                crate::models::ModelError::MediaDecode {
                    op: "extract_text",
                    detail: format!(
                        "MockDocumentExtractor rejects unsupported mime_type: {mime_type}"
                    ),
                },
            ));
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(mime_type.as_bytes());
        hasher.update(&[0]);
        hasher.update(data);
        let hash = hasher.finalize();
        let prefix: String = hash.to_hex().as_str().chars().take(12).collect();
        let mut pages = Vec::with_capacity(self.page_count as usize);
        for i in 1..=self.page_count {
            pages.push(DocumentPage {
                page_number: i,
                text: format!("mock page {i} content [{prefix}]"),
                language: Some("en".to_string()),
            });
        }
        Ok(pages)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_document_extractor_returns_not_implemented() {
        let ex = NoopDocumentExtractor;
        let err = ex.extract_text(b"%PDF-1.4 ...", PDF_MIME).unwrap_err();
        assert!(matches!(
            err,
            crate::Error::NotImplemented("document_extractor")
        ));
    }

    #[test]
    fn mock_document_extractor_is_deterministic() {
        let ex = MockDocumentExtractor::default();
        let a = ex.extract_text(b"hello-doc", PDF_MIME).expect("a");
        let b = ex.extract_text(b"hello-doc", PDF_MIME).expect("b");
        assert_eq!(a, b, "deterministic pages for identical inputs");
        let c = ex.extract_text(b"another-doc", PDF_MIME).expect("c");
        assert_ne!(a, c, "distinct inputs produce distinct extractions");
        assert_eq!(a.len(), 3);
        assert_eq!(a[0].page_number, 1);
        assert_eq!(a[2].page_number, 3);
    }

    #[test]
    fn mock_document_extractor_handles_docx() {
        let ex = MockDocumentExtractor::with_page_count(2);
        let pages = ex
            .extract_text(b"PK\x03\x04...docx", DOCX_MIME)
            .expect("docx");
        assert_eq!(pages.len(), 2);
        assert_eq!(pages[0].page_number, 1);
        assert_eq!(pages[1].page_number, 2);
    }

    #[test]
    fn mock_document_extractor_rejects_non_document_mime() {
        let ex = MockDocumentExtractor::default();
        let err = ex.extract_text(b"unused", "image/png").unwrap_err();
        assert!(matches!(err, crate::Error::Model(_)));
    }

    #[test]
    fn document_extractor_trait_is_object_safe() {
        // Compile-time + runtime sanity: a `&dyn DocumentExtractor`
        // can be created and invoked. If the trait stops being
        // object-safe, this fails to compile.
        let mock = MockDocumentExtractor::default();
        let dynref: &dyn DocumentExtractor = &mock;
        let pages = dynref.extract_text(b"X", PDF_MIME).unwrap();
        assert!(!pages.is_empty());
    }

    #[test]
    fn supported_mime_helper_recognizes_pdf_and_docx() {
        assert!(is_supported_document_mime(PDF_MIME));
        assert!(is_supported_document_mime(DOCX_MIME));
        assert!(!is_supported_document_mime("application/xml"));
        assert!(!is_supported_document_mime("text/plain"));
        assert!(!is_supported_document_mime("image/png"));
    }
}
