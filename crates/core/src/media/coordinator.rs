//! Phase-B.9 media coordinator.
//!
//! Owns the on-device media-model bridge state previously held
//! directly on [`crate::core_impl::CoreImpl`]:
//!
//!   * `image_embedder` — Phase-6 on-device image-embedding
//!     seam ([`crate::models::clip::ImageEmbedder`], typically a
//!     MobileCLIP-S2 ONNX session). Read by
//!     [`crate::core_impl::CoreImpl::maybe_embed_image_message`]
//!     and the video-keyframe path inside
//!     [`crate::core_impl::CoreImpl::maybe_embed_video_keyframes`]
//!     to write image / keyframe embeddings into the
//!     `search_vector` table on media ingest.
//!   * `ocr_bridge` — Phase-6 platform OCR seam
//!     ([`crate::models::ocr::OcrBridge`]). Today only the
//!     install / `has_ocr_bridge` surface is wired so the bridge
//!     can be registered from the platform layer; production
//!     callers will be added when the media-caption pipeline
//!     (`docs/PROPOSAL.md §7.6`) lights up, at which point an
//!     `ocr_bridge()` lookup accessor can be added alongside its
//!     first caller — no scaffolded accessor is shipped here.
//!   * `whisper_transcriber` — Phase-6 on-device Whisper
//!     transcription seam
//!     ([`crate::models::whisper::WhisperTranscriber`]). Read by
//!     [`crate::core_impl::CoreImpl::maybe_transcribe_audio_message`]
//!     to write per-message transcripts into the
//!     `media_search_index`.
//!   * `document_extractor` — Phase-6 on-device document
//!     text-extraction seam
//!     ([`crate::models::document::DocumentExtractor`]). Read by
//!     [`crate::core_impl::CoreImpl::maybe_extract_document_pages`]
//!     to write per-page caption rows into the
//!     `media_search_index` for PDF / DOCX uploads.
//!   * `video_keyframe_sampler` — Phase-6 on-device video
//!     keyframe-sampling seam
//!     ([`crate::models::video::VideoKeyframeSampler`]). Read by
//!     [`crate::core_impl::CoreImpl::maybe_embed_video_keyframes`]
//!     together with `image_embedder` to drive the
//!     video-keyframe → MobileCLIP-S2 → `search_vector`
//!     pipeline.
//!
//! Each bridge is held in an [`OnceLock`]`<`[`Arc`]`<dyn T>>`
//! so hot-path reads on media ingest are **lock-free atomic
//! loads** with no mutex acquisition. The corresponding
//! per-process resource (the underlying ONNX session,
//! `Vision.framework` registration, AVFoundation / MediaCodec
//! decoder handle) cannot be replaced live without leaking GPU
//! / decoder allocations and racing in-flight inference, so
//! every accessor is **write-once**: a second `install_*` call
//! returns [`crate::Error::Storage`]`(`[`crate::local_store::StorageError::SubsystemAlreadyInstalled`]`)`
//! rather than silently overwriting the previous bridge.
//!
//! Unlike the archive and backup coordinators, the media
//! coordinator deliberately does **not** own the
//! media-orchestrator methods themselves
//! ([`crate::core_impl::CoreImpl::maybe_embed_image_message`],
//! [`crate::core_impl::CoreImpl::maybe_transcribe_audio_message`],
//! [`crate::core_impl::CoreImpl::maybe_extract_document_pages`],
//! [`crate::core_impl::CoreImpl::maybe_embed_video_keyframes`],
//! [`crate::core_impl::CoreImpl::plan_media_migration`],
//! [`crate::core_impl::CoreImpl::migrate_media_sink`],
//! [`crate::core_impl::CoreImpl::schedule_media_migration`],
//! [`crate::core_impl::CoreImpl::rehydrate_media_for_message`]).
//! Those need cross-domain access to the writer mutex
//! ([`crate::core_impl::CoreImpl::db_writer`]), the reader pool
//! ([`crate::core_impl::CoreImpl::db_readers`]), the local-store
//! embedding cache, the dedup analytics sink, the resource
//! probe, the offline detector, the conversation index, the
//! scheduler, and (for `rehydrate_media_for_message`) the
//! archive epoch-key manager — extracting them into the
//! coordinator would either require giving the coordinator
//! back-references to half of `CoreImpl`'s remaining state or
//! re-routing the calls through ad-hoc closure trampolines, in
//! direct conflict with the Phase-B.9 goal of reducing
//! cross-coordinator coupling. The coordinator therefore owns
//! state only; the orchestrator methods stay on
//! [`crate::core_impl::CoreImpl`] and call the coordinator
//! through the typed accessors below.

use std::sync::Arc;
use std::sync::OnceLock;

use crate::local_store::StorageError;
use crate::Error;
use crate::Result;

use crate::models::clip::ImageEmbedder;
use crate::models::document::DocumentExtractor;
use crate::models::ocr::OcrBridge;
use crate::models::video::VideoKeyframeSampler;
use crate::models::whisper::WhisperTranscriber;

/// Owner of the five on-device media-model bridge `OnceLock`
/// fields previously held directly on
/// [`crate::core_impl::CoreImpl`]. See the module doc for the
/// rationale; the per-method docs below explain the accessor
/// contract.
pub(crate) struct Coordinator {
    /// Phase-6 on-device image-embedding seam (MobileCLIP-S2).
    /// Write-once via [`Self::install_image_embedder`]. Reads on
    /// the media-ingest hot path are lock-free atomic loads via
    /// [`Self::image_embedder`].
    image_embedder: OnceLock<Arc<dyn ImageEmbedder>>,

    /// Phase-6 platform OCR bridge. Write-once via
    /// [`Self::install_ocr_bridge`]. Install / `has_*` only
    /// today — no production caller invokes
    /// [`OcrBridge::recognize_text`] yet, so no lookup accessor
    /// is shipped (it would be dead scaffolding).
    ocr_bridge: OnceLock<Arc<dyn OcrBridge>>,

    /// Phase-6 on-device Whisper transcription seam.
    /// Write-once via [`Self::install_whisper_transcriber`].
    /// Lock-free atomic-load reads via
    /// [`Self::whisper_transcriber`].
    whisper_transcriber: OnceLock<Arc<dyn WhisperTranscriber>>,

    /// Phase-6 on-device document text-extraction seam.
    /// Write-once via [`Self::install_document_extractor`].
    /// Lock-free atomic-load reads via
    /// [`Self::document_extractor`].
    document_extractor: OnceLock<Arc<dyn DocumentExtractor>>,

    /// Phase-6 on-device video keyframe-sampling seam.
    /// Write-once via [`Self::install_video_keyframe_sampler`].
    /// Lock-free atomic-load reads via
    /// [`Self::video_keyframe_sampler`].
    video_keyframe_sampler: OnceLock<Arc<dyn VideoKeyframeSampler>>,
}

impl Coordinator {
    /// Construct a coordinator with every bridge slot empty.
    /// The bridges are populated post-construction via
    /// `install_*`; the orchestrator methods treat "not
    /// installed" as "skip this ingest step", matching the
    /// `Self::*_lookup -> Option<Arc<dyn _>>` contract.
    pub(crate) fn new() -> Self {
        Self {
            image_embedder: OnceLock::new(),
            ocr_bridge: OnceLock::new(),
            whisper_transcriber: OnceLock::new(),
            document_extractor: OnceLock::new(),
            video_keyframe_sampler: OnceLock::new(),
        }
    }

    // ----------------------------------------------------------------
    // image_embedder
    // ----------------------------------------------------------------

    /// Install the on-device image-embedding bridge used by
    /// media ingest (`docs/PROPOSAL.md §7.6`, Phase 6, Task 9).
    /// When set, MobileCLIP-S2 embeddings are written to
    /// `search_vector` for image-typed media on ingest.
    /// Write-once: returns
    /// [`StorageError::SubsystemAlreadyInstalled`] if an image
    /// embedder has already been installed.
    pub(crate) fn install_image_embedder(&self, embedder: Arc<dyn ImageEmbedder>) -> Result<()> {
        self.image_embedder
            .set(embedder)
            .map_err(|_| Error::Storage(StorageError::SubsystemAlreadyInstalled("image_embedder")))
    }

    /// Whether [`Self::install_image_embedder`] has been called.
    pub(crate) fn has_image_embedder(&self) -> bool {
        self.image_embedder.get().is_some()
    }

    /// Lock-free atomic load of the installed image embedder.
    /// Returns `None` when no bridge has been installed yet —
    /// the caller treats that as "skip MobileCLIP-S2 embedding
    /// for this message" (the `maybe_*` orchestrator methods
    /// log at `debug!` and return early).
    pub(crate) fn image_embedder(&self) -> Option<Arc<dyn ImageEmbedder>> {
        self.image_embedder.get().map(Arc::clone)
    }

    // ----------------------------------------------------------------
    // ocr_bridge
    // ----------------------------------------------------------------

    /// Install the platform OCR bridge used by media ingest
    /// (`docs/PROPOSAL.md §7.6`, Phase 6, Task 4). Write-once.
    pub(crate) fn install_ocr_bridge(&self, bridge: Arc<dyn OcrBridge>) -> Result<()> {
        self.ocr_bridge
            .set(bridge)
            .map_err(|_| Error::Storage(StorageError::SubsystemAlreadyInstalled("ocr_bridge")))
    }

    /// Whether [`Self::install_ocr_bridge`] has been called.
    pub(crate) fn has_ocr_bridge(&self) -> bool {
        self.ocr_bridge.get().is_some()
    }

    // No lock-free lookup accessor is exposed for `ocr_bridge`
    // yet — see the field-level doc comment and the
    // module-level doc for the rationale. When the media-caption
    // pipeline lands, add an `ocr_bridge()` accessor here
    // alongside its first production caller.

    // ----------------------------------------------------------------
    // whisper_transcriber
    // ----------------------------------------------------------------

    /// Install the on-device Whisper transcriber used by media
    /// ingest. Write-once.
    pub(crate) fn install_whisper_transcriber(
        &self,
        transcriber: Arc<dyn WhisperTranscriber>,
    ) -> Result<()> {
        self.whisper_transcriber.set(transcriber).map_err(|_| {
            Error::Storage(StorageError::SubsystemAlreadyInstalled(
                "whisper_transcriber",
            ))
        })
    }

    /// Whether [`Self::install_whisper_transcriber`] has been
    /// called.
    pub(crate) fn has_whisper_transcriber(&self) -> bool {
        self.whisper_transcriber.get().is_some()
    }

    /// Lock-free atomic load of the installed Whisper
    /// transcriber. Returns `None` when no bridge has been
    /// installed yet — the caller treats that as "skip
    /// transcription for this audio message".
    pub(crate) fn whisper_transcriber(&self) -> Option<Arc<dyn WhisperTranscriber>> {
        self.whisper_transcriber.get().map(Arc::clone)
    }

    // ----------------------------------------------------------------
    // document_extractor
    // ----------------------------------------------------------------

    /// Install the on-device document text-extraction bridge
    /// used by media ingest. Write-once.
    pub(crate) fn install_document_extractor(
        &self,
        extractor: Arc<dyn DocumentExtractor>,
    ) -> Result<()> {
        self.document_extractor.set(extractor).map_err(|_| {
            Error::Storage(StorageError::SubsystemAlreadyInstalled(
                "document_extractor",
            ))
        })
    }

    /// Whether [`Self::install_document_extractor`] has been
    /// called.
    pub(crate) fn has_document_extractor(&self) -> bool {
        self.document_extractor.get().is_some()
    }

    /// Lock-free atomic load of the installed document
    /// extractor. Returns `None` when no bridge has been
    /// installed yet — the caller treats that as "skip per-page
    /// caption extraction for this document".
    pub(crate) fn document_extractor(&self) -> Option<Arc<dyn DocumentExtractor>> {
        self.document_extractor.get().map(Arc::clone)
    }

    // ----------------------------------------------------------------
    // video_keyframe_sampler
    // ----------------------------------------------------------------

    /// Install the on-device video keyframe sampler used by
    /// media ingest. Write-once.
    pub(crate) fn install_video_keyframe_sampler(
        &self,
        sampler: Arc<dyn VideoKeyframeSampler>,
    ) -> Result<()> {
        self.video_keyframe_sampler.set(sampler).map_err(|_| {
            Error::Storage(StorageError::SubsystemAlreadyInstalled(
                "video_keyframe_sampler",
            ))
        })
    }

    /// Whether [`Self::install_video_keyframe_sampler`] has
    /// been called.
    pub(crate) fn has_video_keyframe_sampler(&self) -> bool {
        self.video_keyframe_sampler.get().is_some()
    }

    /// Lock-free atomic load of the installed video keyframe
    /// sampler. Returns `None` when no bridge has been
    /// installed yet — the caller treats that as "skip
    /// keyframe sampling for this video".
    pub(crate) fn video_keyframe_sampler(&self) -> Option<Arc<dyn VideoKeyframeSampler>> {
        self.video_keyframe_sampler.get().map(Arc::clone)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal in-test fakes for each bridge trait. The bridges
    // are not exercised here — these tests cover the OnceLock
    // contract (install once, double-install rejects, lookup
    // returns Some-or-None) which is identical across the five
    // accessors.

    #[derive(Debug)]
    struct FakeImageEmbedder;
    impl ImageEmbedder for FakeImageEmbedder {
        fn embed_image(&self, _image_data: &[u8], _mime_type: &str) -> Result<Vec<f32>> {
            Ok(vec![0.0; 512])
        }
    }

    #[derive(Debug)]
    struct FakeOcrBridge;
    impl OcrBridge for FakeOcrBridge {
        fn recognize_text(
            &self,
            _image_data: &[u8],
            _mime_type: &str,
        ) -> Result<Vec<crate::models::ocr::OcrResult>> {
            Ok(Vec::new())
        }
    }

    #[derive(Debug)]
    struct FakeWhisper;
    impl WhisperTranscriber for FakeWhisper {
        fn transcribe(
            &self,
            _audio_data: &[u8],
            _mime_type: &str,
        ) -> Result<crate::models::whisper::TranscriptionResult> {
            Ok(crate::models::whisper::TranscriptionResult {
                text: String::new(),
                language: None,
                segments: Vec::new(),
            })
        }
    }

    #[derive(Debug)]
    struct FakeDocExtractor;
    impl DocumentExtractor for FakeDocExtractor {
        fn extract_text(
            &self,
            _data: &[u8],
            _mime_type: &str,
        ) -> Result<Vec<crate::models::document::DocumentPage>> {
            Ok(Vec::new())
        }
    }

    #[derive(Debug)]
    struct FakeVideoSampler;
    impl VideoKeyframeSampler for FakeVideoSampler {
        fn extract_keyframes(
            &self,
            _video_data: &[u8],
            _mime_type: &str,
            _max_frames: usize,
        ) -> Result<Vec<crate::models::video::Keyframe>> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn install_image_embedder_is_write_once() {
        let c = Coordinator::new();
        assert!(!c.has_image_embedder());
        c.install_image_embedder(Arc::new(FakeImageEmbedder))
            .expect("first install");
        assert!(c.has_image_embedder());
        // Second install must reject — the ONNX session is a
        // per-process resource that cannot be replaced live.
        let err = c
            .install_image_embedder(Arc::new(FakeImageEmbedder))
            .expect_err("second install must reject");
        match err {
            Error::Storage(StorageError::SubsystemAlreadyInstalled(name)) => {
                assert_eq!(name, "image_embedder");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn lookups_return_none_until_install() {
        let c = Coordinator::new();
        assert!(c.image_embedder().is_none());
        assert!(c.whisper_transcriber().is_none());
        assert!(c.document_extractor().is_none());
        assert!(c.video_keyframe_sampler().is_none());
        // OCR has no production lookup accessor yet (see the
        // field-level doc comment); test the install / has
        // pair instead.
        assert!(!c.has_ocr_bridge());
    }

    #[test]
    fn lookups_clone_arc_after_install() {
        let c = Coordinator::new();
        c.install_image_embedder(Arc::new(FakeImageEmbedder))
            .expect("install");
        let a = c.image_embedder().expect("installed");
        let b = c.image_embedder().expect("installed");
        assert!(Arc::ptr_eq(&a, &b), "lookups must clone the same Arc");
    }

    #[test]
    fn has_ocr_bridge_flips_after_install() {
        let c = Coordinator::new();
        assert!(!c.has_ocr_bridge());
        c.install_ocr_bridge(Arc::new(FakeOcrBridge))
            .expect("install");
        assert!(c.has_ocr_bridge());
        // Second install must reject — the platform OCR
        // registration is process-singleton.
        let err = c
            .install_ocr_bridge(Arc::new(FakeOcrBridge))
            .expect_err("second install must reject");
        match err {
            Error::Storage(StorageError::SubsystemAlreadyInstalled(name)) => {
                assert_eq!(name, "ocr_bridge");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn each_bridge_is_independent() {
        let c = Coordinator::new();
        c.install_whisper_transcriber(Arc::new(FakeWhisper))
            .expect("install whisper");
        assert!(c.has_whisper_transcriber());
        // Installing whisper does NOT mark the other 4 as
        // installed.
        assert!(!c.has_image_embedder());
        assert!(!c.has_ocr_bridge());
        assert!(!c.has_document_extractor());
        assert!(!c.has_video_keyframe_sampler());
        // And installing a sibling bridge does NOT reject —
        // the OnceLocks are per-bridge.
        c.install_document_extractor(Arc::new(FakeDocExtractor))
            .expect("install doc extractor");
        c.install_video_keyframe_sampler(Arc::new(FakeVideoSampler))
            .expect("install video sampler");
    }
}
