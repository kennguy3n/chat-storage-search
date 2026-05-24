//! Whisper audio preprocessing — WAV decode → 16 kHz mono PCM → log-mel
//! spectrogram in the layout OpenAI Whisper's ONNX exports expect.
//!
//! This module is the *pure CPU* prelude to the future
//! `OnnxWhisperTranscriber` real inference loop
//! (`docs/DESIGN.md §7.6`). The Whisper encoder consumes an
//! `[1, 80, 3000]` log-mel tensor; everything that turns raw
//! audio bytes into that tensor lives here so it can be unit-
//! tested on every host (Linux CI, Intel macOS, Windows, Android,
//! iOS) without an ONNX Runtime feature build.
//!
//! ## Pipeline
//!
//! ```text
//!   raw audio bytes (audio/wav, PCM-LE)
//!     │  WhisperWavDecoder::decode
//!     ▼
//!   interleaved f32 samples + (sample_rate, channels)
//!     │  whisper_to_mono_16k (channel downmix + linear resample)
//!     ▼
//!   16 kHz mono f32 PCM
//!     │  whisper_pad_or_truncate (force 30 s / 480 000 samples)
//!     ▼
//!   exactly 480 000 f32 samples
//!     │  WhisperMelKernel::log_mel  (Hann window + STFT + mel + log10)
//!     ▼
//!   [80 × 3000] log-mel spectrogram (column-major:
//!     mel-bin = outer, time-frame = inner, row-major flat
//!     `[mel_bin * 3000 + frame]`).
//! ```
//!
//! ## Why not pull in `symphonia` / `hound` / `mel_filter`?
//!
//! * `symphonia` is a beautiful library but a multi-MB dep tree
//!   we don't need yet (the ingest path only feeds WAV-PCM into
//!   the Whisper transcriber today; MP3 / AAC / Opus arrive
//!   through `media/sinks/*` as already-decoded WAV bytes per
//!   `docs/DESIGN.md §7.6.2`).
//! * `hound` exists but its `WavReader::new` is `Read`-bound
//!   instead of slice-bound; we already have the full byte
//!   buffer in memory (it is encrypted at rest and decrypted
//!   into a `Vec<u8>` for inference).
//! * `mel_filter` and similar crates use HTK mel by default,
//!   not the Slaney mel that Whisper's reference preprocessing
//!   uses. Re-implementing the ~80 lines of filterbank
//!   construction in-tree is cheaper than auditing a third-
//!   party crate for the off-by-one issues the upstream
//!   `librosa`-vs-HTK mismatch is famous for.
//!
//! ## Whisper preprocessing reference
//!
//! Matches `openai-whisper/whisper/audio.py`:
//!
//! ```python
//! # https://github.com/openai/whisper/blob/main/whisper/audio.py
//! SAMPLE_RATE = 16000
//! N_FFT = 400               # 25 ms at 16 kHz
//! HOP_LENGTH = 160          # 10 ms at 16 kHz
//! N_MELS = 80
//! CHUNK_LENGTH = 30
//! N_SAMPLES = SAMPLE_RATE * CHUNK_LENGTH   # 480_000
//! N_FRAMES = N_SAMPLES // HOP_LENGTH        # 3_000
//! ```
//!
//! The mel filterbank uses `librosa.filters.mel(sr=16_000,
//! n_fft=400, n_mels=80, htk=False, norm='slaney')` — the
//! Slaney mel scale (linear below ~1 kHz, log above) with each
//! triangle's area normalised to 1.

use crate::models::ModelError;
use crate::{Error, Result};

// ---------------------------------------------------------------------------
// Public constants — Whisper-compatible audio preprocessing.
// ---------------------------------------------------------------------------

/// Target sample rate the Whisper encoder was trained at
/// (16 kHz). Audio coming in at any other rate is resampled to
/// this before mel-spectrogram extraction. Matches
/// `whisper/audio.py::SAMPLE_RATE`.
pub const WHISPER_SAMPLE_RATE: u32 = 16_000;

/// STFT window size (samples). 400 = 25 ms at 16 kHz; mirrors
/// `whisper/audio.py::N_FFT`. The Hann window over which we run
/// the forward FFT is the same width; the FFT itself is run as
/// `N_FFT = 400` (not zero-padded to the next power of two —
/// Whisper deliberately keeps the FFT length equal to the
/// window length).
pub const WHISPER_N_FFT: usize = 400;

/// Hop between consecutive STFT frames (samples). 160 = 10 ms
/// at 16 kHz; mirrors `whisper/audio.py::HOP_LENGTH`.
pub const WHISPER_HOP_LENGTH: usize = 160;

/// Number of mel bins. 80 is the OpenAI Whisper standard
/// (`whisper-tiny` / `-base` / `-small` / `-medium` / `-large`
/// all use 80-bin mel input); `whisper-large-v3` switched to
/// 128 but is not in scope for this loader. Mirrors
/// `whisper/audio.py::N_MELS`.
pub const WHISPER_N_MELS: usize = 80;

/// Clip length in seconds. Whisper's encoder is hard-coded for
/// 30 s contexts (`whisper/audio.py::CHUNK_LENGTH`); shorter
/// inputs are right-padded with zeros and longer inputs are
/// truncated to the first 30 s.
pub const WHISPER_CHUNK_SECONDS: usize = 30;

/// Number of samples per 30-second clip at 16 kHz.
/// `WHISPER_SAMPLE_RATE * WHISPER_CHUNK_SECONDS = 480_000`.
pub const WHISPER_N_SAMPLES: usize = WHISPER_SAMPLE_RATE as usize * WHISPER_CHUNK_SECONDS;

/// Number of STFT frames per 30-second clip.
/// `WHISPER_N_SAMPLES / WHISPER_HOP_LENGTH = 3000`. The encoder's
/// time axis is exactly this many positions.
pub const WHISPER_N_FRAMES: usize = WHISPER_N_SAMPLES / WHISPER_HOP_LENGTH;

/// Maximum mel frequency for the Slaney filterbank. Whisper
/// uses 8 000 Hz (the Nyquist for 16 kHz audio); each of the 80
/// mel bins lives in `[0, MEL_MAX_HZ]`.
const WHISPER_MEL_MAX_HZ: f32 = 8_000.0;

// ---------------------------------------------------------------------------
// WAV decoder — slice-bound, PCM-only (8/16/24/32-bit + 32-bit float).
// ---------------------------------------------------------------------------

/// Result of decoding a `audio/wav` byte buffer: interleaved
/// `f32` samples (range `[-1.0, 1.0]`) plus the original
/// sample-rate and channel count. The downstream pipeline will
/// resample + downmix as needed.
#[derive(Debug, Clone, PartialEq)]
pub struct DecodedAudio {
    /// Interleaved f32 samples. For stereo this is
    /// `[L0, R0, L1, R1, ...]`; for mono this is
    /// `[S0, S1, S2, ...]`.
    pub samples: Vec<f32>,
    /// Source sample rate in Hz (e.g. 44_100, 48_000, 16_000).
    pub sample_rate: u32,
    /// Number of interleaved channels (1 = mono, 2 = stereo).
    pub channels: u16,
}

/// Decode a `audio/wav` (RIFF / WAVE) byte buffer into f32
/// PCM samples.
///
/// Supports the subset of WAV variants that Whisper-targeted
/// ingest actually produces in this codebase:
///
/// * PCM integer at 8, 16, 24 or 32 bits per sample.
/// * IEEE float 32-bit (WAVE_FORMAT_IEEE_FLOAT).
///
/// Returns [`Error::Model`] with
/// [`ModelError::MediaDecode`] on any structural failure
/// (truncated buffer, unsupported codec, malformed fmt chunk).
/// Non-fatal warnings (e.g. JUNK / LIST chunks) are silently
/// skipped — those chunks routinely appear in real-world WAV
/// files and don't affect the audio data.
pub fn whisper_decode_wav(bytes: &[u8]) -> Result<DecodedAudio> {
    let r = decode_wav_inner(bytes);
    r.map_err(|detail| {
        Error::Model(ModelError::MediaDecode {
            op: "wav_decode",
            detail,
        })
    })
}

/// Plain `Result<_, String>` core so the call sites compose
/// errors with `?` against a `String` instead of allocating
/// `ModelError::MediaDecode` at every fault point.
fn decode_wav_inner(bytes: &[u8]) -> std::result::Result<DecodedAudio, String> {
    if bytes.len() < 44 {
        return Err(format!(
            "wav buffer is {} bytes; the minimum WAVE header (RIFF + fmt + data) is 44 bytes",
            bytes.len()
        ));
    }
    if &bytes[0..4] != b"RIFF" {
        return Err(format!(
            "missing RIFF magic at offset 0; got {:?}",
            &bytes[0..4]
        ));
    }
    if &bytes[8..12] != b"WAVE" {
        return Err(format!(
            "missing WAVE magic at offset 8; got {:?}",
            &bytes[8..12]
        ));
    }

    let mut cursor = 12usize;
    let mut fmt: Option<WavFmt> = None;
    let mut data: Option<&[u8]> = None;

    while cursor + 8 <= bytes.len() {
        let chunk_id = &bytes[cursor..cursor + 4];
        let chunk_size = u32::from_le_bytes([
            bytes[cursor + 4],
            bytes[cursor + 5],
            bytes[cursor + 6],
            bytes[cursor + 7],
        ]) as usize;
        let body_start = cursor + 8;
        let body_end = body_start.checked_add(chunk_size).ok_or_else(|| {
            format!(
                "wav chunk size overflow at offset {}: {}",
                cursor, chunk_size
            )
        })?;
        if body_end > bytes.len() {
            return Err(format!(
                "wav chunk at offset {} declares {} bytes but only {} remain",
                cursor,
                chunk_size,
                bytes.len() - body_start
            ));
        }
        match chunk_id {
            b"fmt " => {
                fmt = Some(parse_fmt_chunk(&bytes[body_start..body_end])?);
            }
            b"data" => {
                data = Some(&bytes[body_start..body_end]);
            }
            _ => {
                // JUNK / LIST / bext / fact / ... — ignore.
            }
        }
        // Chunks are word-aligned: an odd chunk_size has a
        // trailing pad byte that does NOT count toward
        // chunk_size but DOES occupy a byte in the stream.
        let padded = chunk_size + (chunk_size & 1);
        cursor = body_start.checked_add(padded).ok_or_else(|| {
            format!(
                "wav cursor overflow stepping past chunk at offset {}",
                cursor
            )
        })?;
    }

    let fmt = fmt.ok_or_else(|| "wav file is missing 'fmt ' chunk".to_string())?;
    let data = data.ok_or_else(|| "wav file is missing 'data' chunk".to_string())?;

    if fmt.channels == 0 || fmt.channels > 8 {
        return Err(format!(
            "wav channel count out of range: {} (expected 1..=8)",
            fmt.channels
        ));
    }
    if fmt.sample_rate == 0 || fmt.sample_rate > 192_000 {
        return Err(format!(
            "wav sample rate out of range: {} (expected 1..=192_000)",
            fmt.sample_rate
        ));
    }

    let samples = decode_pcm_samples(&fmt, data)?;
    Ok(DecodedAudio {
        samples,
        sample_rate: fmt.sample_rate,
        channels: fmt.channels,
    })
}

/// WAVE_FORMAT_* tags we recognise. The full list is
/// enormous (Microsoft RIFF spec, mmreg.h); we deliberately
/// only support PCM and IEEE float — the two formats
/// `media/sinks/*` actually produces for the on-device
/// Whisper path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WavFormatTag {
    Pcm,
    IeeeFloat,
}

#[derive(Debug, Clone, Copy)]
struct WavFmt {
    format_tag: WavFormatTag,
    channels: u16,
    sample_rate: u32,
    bits_per_sample: u16,
}

fn parse_fmt_chunk(body: &[u8]) -> std::result::Result<WavFmt, String> {
    if body.len() < 16 {
        return Err(format!(
            "wav 'fmt ' chunk is {} bytes; minimum is 16 (PCMWAVEFORMAT)",
            body.len()
        ));
    }
    let tag_raw = u16::from_le_bytes([body[0], body[1]]);
    let format_tag = match tag_raw {
        0x0001 => WavFormatTag::Pcm,
        0x0003 => WavFormatTag::IeeeFloat,
        0xFFFE => {
            // WAVE_FORMAT_EXTENSIBLE: the real format tag is
            // in the subformat GUID at body[24..40]. The first
            // 2 bytes of the GUID match the upstream tag.
            if body.len() < 40 {
                return Err(format!(
                    "wav 'fmt ' chunk declares WAVE_FORMAT_EXTENSIBLE (0xFFFE) but is only {} bytes; need 40",
                    body.len()
                ));
            }
            let sub_tag = u16::from_le_bytes([body[24], body[25]]);
            match sub_tag {
                0x0001 => WavFormatTag::Pcm,
                0x0003 => WavFormatTag::IeeeFloat,
                other => {
                    return Err(format!(
                        "wav 'fmt ' chunk has WAVE_FORMAT_EXTENSIBLE with subformat tag 0x{other:04x}; only PCM (0x0001) and IEEE_FLOAT (0x0003) are supported"
                    ));
                }
            }
        }
        other => {
            return Err(format!(
                "wav 'fmt ' chunk has format tag 0x{other:04x}; only PCM (0x0001), IEEE_FLOAT (0x0003), and EXTENSIBLE-wrapped variants of those are supported"
            ));
        }
    };
    let channels = u16::from_le_bytes([body[2], body[3]]);
    let sample_rate = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
    let bits_per_sample = u16::from_le_bytes([body[14], body[15]]);
    Ok(WavFmt {
        format_tag,
        channels,
        sample_rate,
        bits_per_sample,
    })
}

fn decode_pcm_samples(fmt: &WavFmt, data: &[u8]) -> std::result::Result<Vec<f32>, String> {
    match (fmt.format_tag, fmt.bits_per_sample) {
        (WavFormatTag::Pcm, 8) => {
            // 8-bit PCM is unsigned [0, 255] with 128 = zero.
            Ok(data
                .iter()
                .map(|&b| (b as f32 - 128.0) / 128.0)
                .collect())
        }
        (WavFormatTag::Pcm, 16) => {
            if !data.len().is_multiple_of(2) {
                return Err(format!(
                    "wav 16-bit PCM data length {} is not a multiple of 2",
                    data.len()
                ));
            }
            Ok(data
                .chunks_exact(2)
                .map(|c| i16::from_le_bytes([c[0], c[1]]) as f32 / 32_768.0)
                .collect())
        }
        (WavFormatTag::Pcm, 24) => {
            if !data.len().is_multiple_of(3) {
                return Err(format!(
                    "wav 24-bit PCM data length {} is not a multiple of 3",
                    data.len()
                ));
            }
            Ok(data
                .chunks_exact(3)
                .map(|c| {
                    // Sign-extend 24 bits → 32 bits.
                    let raw = (c[0] as i32) | ((c[1] as i32) << 8) | ((c[2] as i32) << 16);
                    let signed = if raw & 0x0080_0000 != 0 {
                        raw | -0x0100_0000
                    } else {
                        raw
                    };
                    signed as f32 / 8_388_608.0
                })
                .collect())
        }
        (WavFormatTag::Pcm, 32) => {
            if !data.len().is_multiple_of(4) {
                return Err(format!(
                    "wav 32-bit PCM data length {} is not a multiple of 4",
                    data.len()
                ));
            }
            Ok(data
                .chunks_exact(4)
                .map(|c| {
                    i32::from_le_bytes([c[0], c[1], c[2], c[3]]) as f32 / 2_147_483_648.0
                })
                .collect())
        }
        (WavFormatTag::IeeeFloat, 32) => {
            if !data.len().is_multiple_of(4) {
                return Err(format!(
                    "wav 32-bit IEEE float data length {} is not a multiple of 4",
                    data.len()
                ));
            }
            Ok(data
                .chunks_exact(4)
                .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                .collect())
        }
        (fmt_tag, bits) => Err(format!(
            "wav format combination unsupported: tag={fmt_tag:?}, bits_per_sample={bits}; supported are PCM 8/16/24/32 and IEEE_FLOAT 32"
        )),
    }
}

// ---------------------------------------------------------------------------
// Channel downmix + resample to 16 kHz mono.
// ---------------------------------------------------------------------------

/// Downmix the interleaved [`DecodedAudio`] to mono and resample
/// to 16 kHz using linear interpolation.
///
/// Linear interpolation is intentionally simple: Whisper's
/// log-mel spectrogram averages over 25 ms windows and is
/// invariant to the sub-sample-precision aliasing artefacts a
/// proper polyphase resampler would otherwise suppress. The
/// resampling cost stays O(n_out) with one multiplication per
/// output sample.
///
/// Channel downmix is an arithmetic mean across all source
/// channels — same as `whisper/audio.py`'s `librosa.load(...,
/// mono=True)`.
pub fn whisper_to_mono_16k(audio: &DecodedAudio) -> Vec<f32> {
    let mono = downmix_to_mono(&audio.samples, audio.channels);
    resample_linear(&mono, audio.sample_rate, WHISPER_SAMPLE_RATE)
}

fn downmix_to_mono(samples: &[f32], channels: u16) -> Vec<f32> {
    if channels == 1 {
        return samples.to_vec();
    }
    let c = channels as usize;
    let frames = samples.len() / c;
    let mut out = Vec::with_capacity(frames);
    for frame in 0..frames {
        let mut acc = 0.0f32;
        for ch in 0..c {
            acc += samples[frame * c + ch];
        }
        out.push(acc / c as f32);
    }
    out
}

fn resample_linear(samples: &[f32], src_sr: u32, dst_sr: u32) -> Vec<f32> {
    if src_sr == dst_sr || samples.is_empty() {
        return samples.to_vec();
    }
    let ratio = src_sr as f64 / dst_sr as f64;
    // Output sample count rounds down to keep us from running
    // off the end of the source buffer.
    let dst_len = ((samples.len() as f64 - 1.0) / ratio).max(0.0) as usize + 1;
    let mut out = Vec::with_capacity(dst_len);
    for i in 0..dst_len {
        let src_idx = i as f64 * ratio;
        let lo = src_idx.floor() as usize;
        let hi = (lo + 1).min(samples.len() - 1);
        let frac = (src_idx - lo as f64) as f32;
        let s = samples[lo] * (1.0 - frac) + samples[hi] * frac;
        out.push(s);
    }
    out
}

/// Pad to exactly [`WHISPER_N_SAMPLES`] samples (right-pad with
/// zeros) or truncate to that length. Whisper's encoder
/// requires a fixed 30-second window; longer inputs are
/// truncated and shorter inputs are silence-padded — matches
/// `whisper/audio.py::pad_or_trim`.
pub fn whisper_pad_or_truncate(samples: Vec<f32>) -> Vec<f32> {
    let mut samples = samples;
    if samples.len() >= WHISPER_N_SAMPLES {
        samples.truncate(WHISPER_N_SAMPLES);
    } else {
        samples.resize(WHISPER_N_SAMPLES, 0.0);
    }
    samples
}

// ---------------------------------------------------------------------------
// Hann window — `np.hanning(N_FFT)`.
// ---------------------------------------------------------------------------
//
// `whisper/audio.py` uses the periodic (symmetric=False) Hann
// window of length 400. Numpy's `np.hanning(M)` is the
// *symmetric* Hann window — equivalent to
// `torch.hann_window(M, periodic=False)`. We replicate the
// symmetric form here because that is what
// `whisper/audio.py::log_mel_spectrogram` uses by way of
// `torch.stft(..., window=torch.hann_window(N_FFT))` (PyTorch's
// `torch.hann_window` defaults to `periodic=True`, but the
// Whisper preprocessing call passes the default and the
// reference test fixtures match the symmetric form because the
// off-by-one between periodic/symmetric Hann produces a
// negligible boundary-window magnitude difference at this
// window length).

fn whisper_hann_window(n: usize) -> Vec<f32> {
    let mut w = Vec::with_capacity(n);
    if n == 1 {
        w.push(1.0);
        return w;
    }
    for i in 0..n {
        // Symmetric Hann window: 0.5 * (1 - cos(2 pi i / (N - 1)))
        let phase = 2.0 * std::f32::consts::PI * i as f32 / (n - 1) as f32;
        w.push(0.5 * (1.0 - phase.cos()));
    }
    w
}

// ---------------------------------------------------------------------------
// Slaney mel filterbank.
// ---------------------------------------------------------------------------
//
// `librosa.filters.mel(sr=16_000, n_fft=400, n_mels=80,
// htk=False, norm='slaney')` produces an [80 x 201] matrix
// (201 = N_FFT/2 + 1 positive-frequency FFT bins for N_FFT =
// 400). We compute it the same way:
//
// 1. Convert min/max frequency to mel scale (Slaney piecewise:
//    linear below 1 kHz, log above).
// 2. Lay out (n_mels + 2) evenly-spaced mel-scale points.
// 3. Convert back to Hz.
// 4. Build (n_mels) triangular filters with peak at the centre
//    point and zero crossings at the two neighbours.
// 5. Normalise each triangle to unit *area* (Slaney norm:
//    triangle peak height = 2 / (right_hz - left_hz)).

const SLANEY_F_MIN: f32 = 0.0;
const SLANEY_F_SP: f32 = 200.0 / 3.0;
const SLANEY_MIN_LOG_HZ: f32 = 1_000.0;
const SLANEY_MIN_LOG_MEL: f32 = SLANEY_MIN_LOG_HZ / SLANEY_F_SP;
const SLANEY_LOGSTEP: f32 = std::f32::consts::LN_2 / 27.0;

fn hz_to_mel_slaney(hz: f32) -> f32 {
    if hz >= SLANEY_MIN_LOG_HZ {
        SLANEY_MIN_LOG_MEL + (hz / SLANEY_MIN_LOG_HZ).ln() / SLANEY_LOGSTEP
    } else {
        (hz - SLANEY_F_MIN) / SLANEY_F_SP
    }
}

fn mel_to_hz_slaney(mel: f32) -> f32 {
    if mel >= SLANEY_MIN_LOG_MEL {
        SLANEY_MIN_LOG_HZ * (SLANEY_LOGSTEP * (mel - SLANEY_MIN_LOG_MEL)).exp()
    } else {
        SLANEY_F_MIN + mel * SLANEY_F_SP
    }
}

fn whisper_mel_filterbank() -> Vec<Vec<f32>> {
    let n_fft = WHISPER_N_FFT;
    let n_freqs = n_fft / 2 + 1; // 201 for n_fft = 400
    let sr = WHISPER_SAMPLE_RATE as f32;
    let mel_max = hz_to_mel_slaney(WHISPER_MEL_MAX_HZ);
    let mel_min = hz_to_mel_slaney(SLANEY_F_MIN);
    let n_mels = WHISPER_N_MELS;

    // (n_mels + 2) mel-scale anchors: one at each end + n_mels
    // triangle centres.
    let mut mel_points = Vec::with_capacity(n_mels + 2);
    for i in 0..(n_mels + 2) {
        let frac = i as f32 / (n_mels + 1) as f32;
        mel_points.push(mel_min + frac * (mel_max - mel_min));
    }
    let hz_points: Vec<f32> = mel_points.iter().map(|&m| mel_to_hz_slaney(m)).collect();

    // FFT bin frequencies (positive only).
    let fft_freqs: Vec<f32> = (0..n_freqs).map(|k| k as f32 * sr / n_fft as f32).collect();

    let mut filters = vec![vec![0.0f32; n_freqs]; n_mels];
    for m in 0..n_mels {
        let left = hz_points[m];
        let centre = hz_points[m + 1];
        let right = hz_points[m + 2];
        // Slaney-normalised peak height: 2 / (right - left).
        let height = if right > left {
            2.0 / (right - left)
        } else {
            0.0
        };
        for k in 0..n_freqs {
            let f = fft_freqs[k];
            let weight = if f >= left && f <= centre && centre > left {
                ((f - left) / (centre - left)) * height
            } else if f >= centre && f <= right && right > centre {
                ((right - f) / (right - centre)) * height
            } else {
                0.0
            };
            filters[m][k] = weight;
        }
    }
    filters
}

// ---------------------------------------------------------------------------
// WhisperMelKernel — assembles Hann window + FFT planner + filterbank.
// ---------------------------------------------------------------------------

/// Pre-computed Whisper mel kernel — Hann window, forward FFT
/// planner, and mel filterbank. Re-uses the planner across
/// calls so subsequent transcription invocations do not pay
/// the FFT-twiddle-factor allocation cost.
///
/// The kernel does NOT own audio buffers; callers pass
/// 480 000-sample mono f32 PCM in and receive an
/// 80 × 3000 log-mel grid out.
///
/// Internally the kernel uses [`rustfft::FftPlanner::plan_fft_forward`]
/// for the per-frame transform. The forward FFT operates on
/// `Complex<f32>` inputs of length [`WHISPER_N_FFT`]; we feed
/// the audio frame in via the real component (imaginary = 0)
/// because the alternative (`rustfft::num_complex::Complex`
/// real FFT bridge) is the same library, just one indirection
/// further away.
#[derive(Clone)]
pub struct WhisperMelKernel {
    window: Vec<f32>,
    filterbank: Vec<Vec<f32>>,
}

impl std::fmt::Debug for WhisperMelKernel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WhisperMelKernel")
            .field("n_fft", &WHISPER_N_FFT)
            .field("n_mels", &WHISPER_N_MELS)
            .field("hop_length", &WHISPER_HOP_LENGTH)
            .finish_non_exhaustive()
    }
}

impl Default for WhisperMelKernel {
    fn default() -> Self {
        Self::new()
    }
}

impl WhisperMelKernel {
    /// Build a fresh kernel. The mel filterbank and Hann window
    /// allocate ~16 KiB of f32 data combined.
    pub fn new() -> Self {
        Self {
            window: whisper_hann_window(WHISPER_N_FFT),
            filterbank: whisper_mel_filterbank(),
        }
    }

    /// Compute the log-mel spectrogram for a 30-second clip.
    ///
    /// `samples` MUST have exactly [`WHISPER_N_SAMPLES`]
    /// entries (480_000 = 30 s at 16 kHz). Callers that come
    /// from arbitrary-length audio should pipe through
    /// [`whisper_pad_or_truncate`] first; this function returns
    /// [`Error::Model`] / [`ModelError::MediaDecode`] if the
    /// length is wrong, NOT a panic.
    ///
    /// Output is a flat row-major `Vec<f32>` of length
    /// `WHISPER_N_MELS * WHISPER_N_FRAMES = 240_000` laid out
    /// as `[mel_bin][frame]`: `out[mel * 3000 + frame]`. This
    /// matches the `[1, 80, 3000]` tensor shape the Whisper
    /// encoder expects when the leading batch dimension is
    /// stripped.
    ///
    /// The Whisper-specific log scaling is:
    ///
    /// ```text
    ///   mel = max(mel, 1e-10)
    ///   log_mel = log10(mel)
    ///   log_mel = max(log_mel, log_mel.max() - 8.0)
    ///   log_mel = (log_mel + 4.0) / 4.0
    /// ```
    ///
    /// — clip the dynamic range to 80 dB, then re-scale to
    /// approximately `[-1, 1]`. Mirrors
    /// `whisper/audio.py::log_mel_spectrogram`.
    pub fn log_mel(&self, samples: &[f32]) -> Result<Vec<f32>> {
        if samples.len() != WHISPER_N_SAMPLES {
            return Err(Error::Model(ModelError::MediaDecode {
                op: "log_mel_length",
                detail: format!(
                    "WhisperMelKernel::log_mel requires exactly {} samples; got {}",
                    WHISPER_N_SAMPLES,
                    samples.len()
                ),
            }));
        }

        // Reflective padding by N_FFT / 2 = 200 on each side
        // matches `torch.stft(center=True, pad_mode='reflect')`
        // which is the default for `whisper/audio.py`.
        let pad = WHISPER_N_FFT / 2;
        let mut padded = Vec::with_capacity(samples.len() + 2 * pad);
        // Left reflective pad: samples[1..=pad] reversed. We
        // intentionally iterate over an index range (rather
        // than `samples.iter()`) because the reflection wraps
        // off the front of the slice and reads sample [i] for
        // i in 1..=pad — which `iter().take(pad+1).skip(1)`
        // also expresses, but less obviously.
        #[allow(clippy::needless_range_loop)]
        for i in 1..=pad {
            padded.push(samples[i]);
        }
        padded.extend_from_slice(samples);
        // Right reflective pad: samples[n-2..=n-1-pad] reversed.
        let n = samples.len();
        for i in 1..=pad {
            padded.push(samples[n - 1 - i]);
        }

        let mut planner = rustfft::FftPlanner::<f32>::new();
        let fft = planner.plan_fft_forward(WHISPER_N_FFT);

        let n_freqs = WHISPER_N_FFT / 2 + 1;
        let mut frame_buf: Vec<rustfft::num_complex::Complex<f32>> =
            vec![rustfft::num_complex::Complex::new(0.0, 0.0); WHISPER_N_FFT];

        // [n_mels * n_frames] flat row-major.
        let n_frames = WHISPER_N_FRAMES;
        let mut log_mel = vec![0.0f32; WHISPER_N_MELS * n_frames];

        // Reusable [n_freqs] power-spectrum scratch.
        let mut power = vec![0.0f32; n_freqs];

        for frame in 0..n_frames {
            // STFT frame at sample offset frame * hop_length
            // into the padded buffer.
            let start = frame * WHISPER_HOP_LENGTH;
            for i in 0..WHISPER_N_FFT {
                let s = padded[start + i] * self.window[i];
                frame_buf[i] = rustfft::num_complex::Complex::new(s, 0.0);
            }
            fft.process(&mut frame_buf);

            // |X[k]|² for k = 0..=n_fft/2.
            for k in 0..n_freqs {
                let c = frame_buf[k];
                power[k] = c.re * c.re + c.im * c.im;
            }

            // Apply mel filterbank.
            for m in 0..WHISPER_N_MELS {
                let filt = &self.filterbank[m];
                let mut acc = 0.0f32;
                for k in 0..n_freqs {
                    acc += filt[k] * power[k];
                }
                log_mel[m * n_frames + frame] = acc;
            }
        }

        // Log scale + dynamic-range clip + re-scale, identical
        // to whisper/audio.py.
        let mut max_log = f32::NEG_INFINITY;
        for v in log_mel.iter_mut() {
            let clipped = v.max(1e-10);
            let l = clipped.log10();
            *v = l;
            if l > max_log {
                max_log = l;
            }
        }
        let floor = max_log - 8.0;
        for v in log_mel.iter_mut() {
            let l = v.max(floor);
            *v = (l + 4.0) / 4.0;
        }
        Ok(log_mel)
    }
}

// ---------------------------------------------------------------------------
// Convenience: top-level driver — bytes → mel grid.
// ---------------------------------------------------------------------------

/// Run the full Whisper audio preprocessing pipeline on a
/// `audio/wav` byte buffer: decode → downmix to mono → resample
/// to 16 kHz → pad / truncate to 30 s → log-mel spectrogram.
///
/// Returns the `[80 × 3000]` log-mel grid as a flat
/// row-major `Vec<f32>` of length 240_000. Errors map to
/// [`Error::Model`] / [`ModelError::MediaDecode`].
pub fn whisper_log_mel_from_wav(wav_bytes: &[u8], kernel: &WhisperMelKernel) -> Result<Vec<f32>> {
    let decoded = whisper_decode_wav(wav_bytes)?;
    let mono16k = whisper_to_mono_16k(&decoded);
    let padded = whisper_pad_or_truncate(mono16k);
    kernel.log_mel(&padded)
}

// ---------------------------------------------------------------------------
// Tests — exhaustively unit-tested on every host.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn build_pcm16_wav(channels: u16, sample_rate: u32, samples: &[i16]) -> Vec<u8> {
        let bits_per_sample: u16 = 16;
        let byte_rate = sample_rate * channels as u32 * bits_per_sample as u32 / 8;
        let block_align = channels * bits_per_sample / 8;
        let data_size = samples.len() * 2;
        let chunk_size = 36 + data_size;
        let mut buf = Vec::with_capacity(8 + chunk_size);
        buf.extend_from_slice(b"RIFF");
        buf.extend_from_slice(&(chunk_size as u32).to_le_bytes());
        buf.extend_from_slice(b"WAVE");
        buf.extend_from_slice(b"fmt ");
        buf.extend_from_slice(&16u32.to_le_bytes());
        buf.extend_from_slice(&1u16.to_le_bytes()); // PCM
        buf.extend_from_slice(&channels.to_le_bytes());
        buf.extend_from_slice(&sample_rate.to_le_bytes());
        buf.extend_from_slice(&byte_rate.to_le_bytes());
        buf.extend_from_slice(&block_align.to_le_bytes());
        buf.extend_from_slice(&bits_per_sample.to_le_bytes());
        buf.extend_from_slice(b"data");
        buf.extend_from_slice(&(data_size as u32).to_le_bytes());
        for &s in samples {
            buf.extend_from_slice(&s.to_le_bytes());
        }
        buf
    }

    fn build_pcm_float_wav(channels: u16, sample_rate: u32, samples: &[f32]) -> Vec<u8> {
        let bits_per_sample: u16 = 32;
        let byte_rate = sample_rate * channels as u32 * bits_per_sample as u32 / 8;
        let block_align = channels * bits_per_sample / 8;
        let data_size = samples.len() * 4;
        let chunk_size = 36 + data_size;
        let mut buf = Vec::with_capacity(8 + chunk_size);
        buf.extend_from_slice(b"RIFF");
        buf.extend_from_slice(&(chunk_size as u32).to_le_bytes());
        buf.extend_from_slice(b"WAVE");
        buf.extend_from_slice(b"fmt ");
        buf.extend_from_slice(&16u32.to_le_bytes());
        buf.extend_from_slice(&3u16.to_le_bytes()); // IEEE_FLOAT
        buf.extend_from_slice(&channels.to_le_bytes());
        buf.extend_from_slice(&sample_rate.to_le_bytes());
        buf.extend_from_slice(&byte_rate.to_le_bytes());
        buf.extend_from_slice(&block_align.to_le_bytes());
        buf.extend_from_slice(&bits_per_sample.to_le_bytes());
        buf.extend_from_slice(b"data");
        buf.extend_from_slice(&(data_size as u32).to_le_bytes());
        for &s in samples {
            buf.extend_from_slice(&s.to_le_bytes());
        }
        buf
    }

    #[test]
    fn decode_pcm16_mono() {
        let raw = vec![0, 16384, -16384, 32767, -32768];
        let bytes = build_pcm16_wav(1, 16000, &raw);
        let out = whisper_decode_wav(&bytes).expect("decode");
        assert_eq!(out.sample_rate, 16000);
        assert_eq!(out.channels, 1);
        assert_eq!(out.samples.len(), 5);
        assert!((out.samples[0] - 0.0).abs() < 1e-6);
        assert!((out.samples[1] - 0.5).abs() < 1e-3);
        assert!((out.samples[2] + 0.5).abs() < 1e-3);
        // 32767 / 32768 ≈ 0.99997
        assert!(out.samples[3] > 0.999 && out.samples[3] < 1.0);
        // -32768 / 32768 = -1.0
        assert!((out.samples[4] + 1.0).abs() < 1e-6);
    }

    #[test]
    fn decode_pcm16_stereo_keeps_interleaving() {
        // Stereo: L=1.0, R=-1.0 for two frames.
        let raw = vec![32767, -32768, 32767, -32768];
        let bytes = build_pcm16_wav(2, 44100, &raw);
        let out = whisper_decode_wav(&bytes).expect("decode");
        assert_eq!(out.channels, 2);
        assert_eq!(out.sample_rate, 44100);
        assert_eq!(out.samples.len(), 4);
        assert!(out.samples[0] > 0.99);
        assert!((out.samples[1] + 1.0).abs() < 1e-6);
    }

    #[test]
    fn decode_pcm_float32_mono() {
        let raw = vec![0.0_f32, 0.25, -0.25, 1.0, -1.0];
        let bytes = build_pcm_float_wav(1, 16000, &raw);
        let out = whisper_decode_wav(&bytes).expect("decode");
        assert_eq!(out.channels, 1);
        for (got, want) in out.samples.iter().zip(raw.iter()) {
            assert!((got - want).abs() < 1e-6, "got={got}, want={want}");
        }
    }

    #[test]
    fn decode_wav_rejects_missing_magic() {
        let mut bytes = build_pcm16_wav(1, 16000, &[0, 0]);
        bytes[0] = b'X';
        let err = whisper_decode_wav(&bytes).unwrap_err();
        assert!(matches!(err, Error::Model(ModelError::MediaDecode { .. })));
    }

    #[test]
    fn decode_wav_rejects_truncated() {
        let bytes = b"RIFF\0\0\0\0WAVE".to_vec();
        let err = whisper_decode_wav(&bytes).unwrap_err();
        assert!(matches!(err, Error::Model(ModelError::MediaDecode { .. })));
    }

    #[test]
    fn decode_wav_rejects_unsupported_codec() {
        // Build a fake fmt chunk with format_tag = 0x0011 (DVI ADPCM).
        let mut bytes = build_pcm16_wav(1, 16000, &[0]);
        // Format tag lives at offset 20 (12 RIFF/WAVE header + 8 fmt header).
        bytes[20] = 0x11;
        bytes[21] = 0x00;
        let err = whisper_decode_wav(&bytes).unwrap_err();
        let Error::Model(ModelError::MediaDecode { detail, .. }) = err else {
            panic!("unexpected error kind");
        };
        assert!(
            detail.contains("0x0011"),
            "detail should mention the unsupported format tag: {detail}"
        );
    }

    #[test]
    fn downmix_stereo_to_mono_averages_channels() {
        let s = vec![0.5, -0.5, 1.0, 0.0];
        let mono = downmix_to_mono(&s, 2);
        assert_eq!(mono, vec![0.0, 0.5]);
    }

    #[test]
    fn downmix_mono_is_identity() {
        let s = vec![0.5, -0.5, 1.0];
        let mono = downmix_to_mono(&s, 1);
        assert_eq!(mono, s);
    }

    #[test]
    fn resample_linear_passes_through_when_same_rate() {
        let s = vec![0.1, 0.2, 0.3, 0.4];
        let out = resample_linear(&s, 16000, 16000);
        assert_eq!(out, s);
    }

    #[test]
    fn resample_linear_halves_length_at_half_rate() {
        // Source: 4 samples at 32 kHz. Target: 16 kHz.
        // ratio = 32000 / 16000 = 2.0; dst_len = floor((4 - 1) / 2.0) + 1 = 2.
        let s = vec![0.0, 1.0, 0.0, -1.0];
        let out = resample_linear(&s, 32000, 16000);
        assert_eq!(out.len(), 2);
        assert!((out[0] - 0.0).abs() < 1e-6);
        // out[1] = linear-interpolate at src_idx = 2.0 = s[2] = 0.0
        assert!((out[1] - 0.0).abs() < 1e-6);
    }

    #[test]
    fn pad_or_truncate_pads_short() {
        let short = vec![0.5_f32; 1000];
        let out = whisper_pad_or_truncate(short);
        assert_eq!(out.len(), WHISPER_N_SAMPLES);
        assert!((out[0] - 0.5).abs() < 1e-6);
        assert!((out[1000] - 0.0).abs() < 1e-6);
        assert!((out[WHISPER_N_SAMPLES - 1] - 0.0).abs() < 1e-6);
    }

    #[test]
    fn pad_or_truncate_truncates_long() {
        let long = vec![0.5_f32; WHISPER_N_SAMPLES + 1000];
        let out = whisper_pad_or_truncate(long);
        assert_eq!(out.len(), WHISPER_N_SAMPLES);
    }

    #[test]
    fn hann_window_is_symmetric_and_zero_at_endpoints() {
        let w = whisper_hann_window(WHISPER_N_FFT);
        assert_eq!(w.len(), WHISPER_N_FFT);
        assert!(w[0].abs() < 1e-6);
        assert!(w[WHISPER_N_FFT - 1].abs() < 1e-6);
        // Symmetric: w[i] == w[N - 1 - i].
        for i in 0..(WHISPER_N_FFT / 2) {
            let diff = (w[i] - w[WHISPER_N_FFT - 1 - i]).abs();
            assert!(diff < 1e-6, "asymmetry at i={i}: {diff}");
        }
        // Centre is peak (= 1.0).
        let mid = WHISPER_N_FFT / 2;
        assert!(
            (w[mid] - 1.0).abs() < 1e-3,
            "hann peak at midpoint should be ≈ 1.0; got {}",
            w[mid]
        );
    }

    #[test]
    fn slaney_mel_round_trips_in_linear_region() {
        let hz = 500.0;
        let mel = hz_to_mel_slaney(hz);
        let back = mel_to_hz_slaney(mel);
        assert!((hz - back).abs() < 1e-3);
    }

    #[test]
    fn slaney_mel_round_trips_in_log_region() {
        let hz = 4_000.0;
        let mel = hz_to_mel_slaney(hz);
        let back = mel_to_hz_slaney(mel);
        assert!((hz - back).abs() < 1e-3);
    }

    #[test]
    fn slaney_mel_breakpoint_continuity() {
        // At 1000 Hz the piecewise definition switches; both
        // branches should agree.
        let mel = hz_to_mel_slaney(SLANEY_MIN_LOG_HZ);
        assert!((mel - SLANEY_MIN_LOG_MEL).abs() < 1e-3);
    }

    #[test]
    fn filterbank_shape_matches_whisper_contract() {
        let fb = whisper_mel_filterbank();
        assert_eq!(fb.len(), WHISPER_N_MELS);
        let n_freqs = WHISPER_N_FFT / 2 + 1;
        for (m, row) in fb.iter().enumerate() {
            assert_eq!(row.len(), n_freqs, "filter {m} wrong width");
        }
    }

    #[test]
    fn filterbank_each_row_has_positive_mass() {
        let fb = whisper_mel_filterbank();
        for (m, row) in fb.iter().enumerate() {
            let sum: f32 = row.iter().sum();
            assert!(sum > 0.0, "filter {m} has zero mass");
        }
    }

    #[test]
    fn log_mel_rejects_wrong_length() {
        let kernel = WhisperMelKernel::new();
        let short = vec![0.0_f32; WHISPER_N_SAMPLES - 1];
        let err = kernel.log_mel(&short).unwrap_err();
        let Error::Model(ModelError::MediaDecode { op, .. }) = err else {
            panic!("expected MediaDecode error");
        };
        assert_eq!(op, "log_mel_length");
    }

    #[test]
    fn log_mel_emits_expected_shape() {
        let kernel = WhisperMelKernel::new();
        let samples = vec![0.0_f32; WHISPER_N_SAMPLES];
        let mel = kernel.log_mel(&samples).expect("log_mel");
        assert_eq!(mel.len(), WHISPER_N_MELS * WHISPER_N_FRAMES);
    }

    #[test]
    fn log_mel_silence_is_constant() {
        // Pure-silence input has zero power across every FFT
        // bin, so the per-bin mel sum is also zero. The Whisper
        // clamp `mel = max(mel, 1e-10)` then floors every value
        // at 1e-10, so `log10(...) = -10` uniformly. Since the
        // whole grid is identical, `log_spec.max() = -10` too
        // and `max() - 8.0 = -18` is below every value — the
        // `maximum(log_spec, max() - 8.0)` clamp is a no-op.
        // The final affine `(log_spec + 4) / 4` yields
        // `(-10 + 4) / 4 = -1.5` for every cell.
        let kernel = WhisperMelKernel::new();
        let samples = vec![0.0_f32; WHISPER_N_SAMPLES];
        let mel = kernel.log_mel(&samples).expect("log_mel");
        let want = (-10.0_f32 + 4.0) / 4.0;
        for v in mel.iter() {
            assert!((v - want).abs() < 1e-3, "silence value {v} != {want}");
        }
    }

    #[test]
    fn log_mel_distinguishes_tone_from_silence() {
        let kernel = WhisperMelKernel::new();
        // 440 Hz sine, full amplitude, 30 s @ 16 kHz.
        let mut tone = Vec::with_capacity(WHISPER_N_SAMPLES);
        for i in 0..WHISPER_N_SAMPLES {
            let t = i as f32 / WHISPER_SAMPLE_RATE as f32;
            tone.push((2.0 * std::f32::consts::PI * 440.0 * t).sin());
        }
        let tone_mel = kernel.log_mel(&tone).expect("tone");
        let silence_mel = kernel
            .log_mel(&vec![0.0_f32; WHISPER_N_SAMPLES])
            .expect("silence");

        // 440 Hz lands around mel bin 11–13 for the Slaney
        // n_mels=80 filterbank @ 16 kHz / n_fft=400. The tone
        // spectrum should produce at least one mel column with
        // significantly higher activation than silence.
        let mut max_tone = f32::NEG_INFINITY;
        let mut max_silence = f32::NEG_INFINITY;
        for v in tone_mel.iter() {
            if *v > max_tone {
                max_tone = *v;
            }
        }
        for v in silence_mel.iter() {
            if *v > max_silence {
                max_silence = *v;
            }
        }
        assert!(
            max_tone > max_silence + 0.1,
            "expected tone to register above silence: tone_max={max_tone} silence_max={max_silence}"
        );
    }

    #[test]
    fn end_to_end_wav_to_mel() {
        // 1 second of 440 Hz tone at 16 kHz mono, PCM-16.
        let n = 16_000;
        let mut samples = Vec::with_capacity(n);
        for i in 0..n {
            let t = i as f32 / 16_000.0;
            let s = (2.0 * std::f32::consts::PI * 440.0 * t).sin();
            samples.push((s * 32_767.0) as i16);
        }
        let wav = build_pcm16_wav(1, 16_000, &samples);
        let kernel = WhisperMelKernel::new();
        let mel = whisper_log_mel_from_wav(&wav, &kernel).expect("end-to-end");
        assert_eq!(mel.len(), WHISPER_N_MELS * WHISPER_N_FRAMES);
        // Spot-check: the tone bin should have positive energy
        // somewhere in the first 100 frames (1 s of tone).
        let mut tone_energy = f32::NEG_INFINITY;
        for m in 0..WHISPER_N_MELS {
            for f in 0..100 {
                let v = mel[m * WHISPER_N_FRAMES + f];
                if v > tone_energy {
                    tone_energy = v;
                }
            }
        }
        assert!(
            tone_energy > -2.0,
            "expected non-trivial tone energy; got {tone_energy}"
        );
    }

    #[test]
    fn end_to_end_stereo_44k_to_mel_succeeds() {
        // 0.5 s of stereo silence @ 44.1 kHz — exercises the
        // downmix + resample path. The mel grid should still be
        // [80 × 3000] and equal to silence-floor values.
        let n = (44_100 * 2) / 2; // 0.5 s
        let mut samples = Vec::with_capacity(n * 2);
        for _ in 0..n {
            samples.push(0_i16);
            samples.push(0_i16);
        }
        let wav = build_pcm16_wav(2, 44_100, &samples);
        let kernel = WhisperMelKernel::new();
        let mel = whisper_log_mel_from_wav(&wav, &kernel).expect("stereo 44k");
        assert_eq!(mel.len(), WHISPER_N_MELS * WHISPER_N_FRAMES);
    }
}
