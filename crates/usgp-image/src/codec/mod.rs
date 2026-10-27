//! Chunk decompressors for WIM resources.
//!
//! M2 supports XPRESS only (decision 0014): [`xpress`] implements the
//! [MS-XCA] LZ77+Huffman decoder. LZX and LZMS are refused before any
//! decoder runs (WU-5, `UnsupportedCompression`).
//!
//! Every decoder here is told the exact expected output size of the chunk
//! by its caller (the output slice length) and never writes past it.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - compressed chunks
//   are untrusted input; every bound is checked and reported as an error.
// - NIST 800-53: SI-11 (Error Handling) - errors carry fixed text only,
//   never input bytes.
// - SPEC: specs/os-images.md#REQ-IMG-037, #REQ-IMG-038
// - SPEC: specs/standards/wim-compression.md §6

use std::fmt;

pub mod xpress;

pub use xpress::{XpressDecoder, decode_chunk as decode_xpress_chunk};

/// Why a compressed chunk could not be decoded.
///
/// Each variant is one bound from `specs/standards/wim-compression.md` §6.
/// Variants carry no input bytes or positions, so an error can be logged
/// or shown to an operator without echoing file content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CodecError {
    /// The Huffman code lengths would fill more than the whole code space
    /// (wim-compression.md §3.2).
    HuffmanTableOverfull,
    /// The Huffman code lengths do not fill the whole code space; this
    /// includes an all-zero table (wim-compression.md §3.2).
    HuffmanTableIncomplete,
    /// An extended match length stored as a 16-bit value is under 15
    /// (wim-compression.md §3.4).
    ExtendedLengthTooSmall,
    /// A match offset reaches before the start of the output
    /// (wim-compression.md §3.5).
    OffsetBeforeStart,
    /// A symbol, extra bits or an extra length byte would be read past the
    /// end of the input (wim-compression.md §3.6).
    InputExhausted,
    /// The data would write past the expected output size
    /// (wim-compression.md §6, derived from WIM framing).
    OutputOverrun,
    /// The input ended before the expected output size was produced
    /// (wim-compression.md §3.6 and §6).
    ShortOutput,
}

impl CodecError {
    /// Stable machine-readable reason, for audit records and operator
    /// messages.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::HuffmanTableOverfull => "huffman_table_overfull",
            Self::HuffmanTableIncomplete => "huffman_table_incomplete",
            Self::ExtendedLengthTooSmall => "extended_length_too_small",
            Self::OffsetBeforeStart => "offset_before_start",
            Self::InputExhausted => "input_exhausted",
            Self::OutputOverrun => "output_overrun",
            Self::ShortOutput => "short_output",
        }
    }
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::HuffmanTableOverfull => "Huffman code lengths overfill the code space",
            Self::HuffmanTableIncomplete => "Huffman code lengths do not fill the code space",
            Self::ExtendedLengthTooSmall => "extended match length below 15",
            Self::OffsetBeforeStart => "match offset before the start of the output",
            Self::InputExhausted => "compressed data ended unexpectedly",
            Self::OutputOverrun => "decoded data exceeds the expected size",
            Self::ShortOutput => "decoded data is shorter than the expected size",
        };
        f.write_str(text)
    }
}

impl std::error::Error for CodecError {}
