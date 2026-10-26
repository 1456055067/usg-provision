//! Parse errors for incoming TFTP packets.
//!
//! Variants carry lengths and codes only, never packet bytes, so they can
//! be counted and logged without echoing client-chosen content.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation)
// - SPEC: specs/boot-network.md#REQ-BOOT-030, #REQ-BOOT-031
// - RFC 1350 §5 - packet formats; RFC 2347 - option framing

use thiserror::Error;

/// Why a TFTP packet was rejected as malformed.
///
/// On port 69 a malformed packet is dropped silently; on a transfer socket
/// a malformed packet from the right TID is ignored (plan §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ParseError {
    /// Shorter than the smallest packet of its kind.
    #[error("packet too short ({len} octets)")]
    TooShort {
        /// Received length.
        len: usize,
    },
    /// Opcode outside 1..=6.
    #[error("unknown opcode {opcode}")]
    UnknownOpcode {
        /// Received opcode.
        opcode: u16,
    },
    /// RRQ, WRQ or OACK longer than 512 octets (RFC 2347).
    #[error("request too long ({len} octets)")]
    RequestTooLong {
        /// Received length.
        len: usize,
    },
    /// The filename has no terminating NUL.
    #[error("filename not terminated")]
    FilenameUnterminated,
    /// The filename is empty.
    #[error("empty filename")]
    EmptyFilename,
    /// The mode has no terminating NUL.
    #[error("mode not terminated")]
    ModeUnterminated,
    /// The mode is empty.
    #[error("empty mode")]
    EmptyMode,
    /// An option name has no terminating NUL.
    #[error("option name not terminated")]
    OptionUnterminated,
    /// An option name is empty.
    #[error("empty option name")]
    EmptyOptionName,
    /// An option name is not followed by a NUL-terminated value.
    #[error("option without a value")]
    OptionWithoutValue,
    /// The same option name (compared case-insensitively) appears twice.
    #[error("duplicate option")]
    DuplicateOption,
    /// An OACK with no options.
    #[error("empty OACK")]
    EmptyOack,
    /// An ACK whose length is not exactly 4.
    #[error("ACK length {len} is not 4")]
    BadAckLength {
        /// Received length.
        len: usize,
    },
    /// A DATA packet longer than 4 + 65464 octets.
    #[error("DATA packet too long ({len} octets)")]
    DataTooLong {
        /// Received length.
        len: usize,
    },
    /// An ERROR packet whose message is not NUL-terminated as its last
    /// octet.
    #[error("ERROR message not terminated")]
    ErrorUnterminated,
}

impl ParseError {
    /// Stable, low-cardinality label for drop counters.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::TooShort { .. } => "too_short",
            Self::UnknownOpcode { .. } => "unknown_opcode",
            Self::RequestTooLong { .. } => "request_too_long",
            Self::FilenameUnterminated => "filename_unterminated",
            Self::EmptyFilename => "empty_filename",
            Self::ModeUnterminated => "mode_unterminated",
            Self::EmptyMode => "empty_mode",
            Self::OptionUnterminated => "option_unterminated",
            Self::EmptyOptionName => "empty_option_name",
            Self::OptionWithoutValue => "option_without_value",
            Self::DuplicateOption => "duplicate_option",
            Self::EmptyOack => "empty_oack",
            Self::BadAckLength { .. } => "bad_ack_length",
            Self::DataTooLong { .. } => "data_too_long",
            Self::ErrorUnterminated => "error_unterminated",
        }
    }
}
