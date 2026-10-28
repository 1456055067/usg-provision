//! usgp-tftp: sans-IO TFTP read-only server state machine.
//!
//! [`parse`] decodes packets; [`admit_read_with`] decides whether to start
//! a read transfer (octet mode only, `blksize`/`tsize`/`windowsize`
//! negotiation, block-number wraparound or the 65535-block limit);
//! [`ReadTransfer`] is the windowed sender (lock-step with a window of 1).
//! [`admit_read`] keeps the M1 lock-step, no-wrap behaviour.
//! [`normalize_request_name`] turns a request name into the form matched
//! against published names. Time and file bytes are passed in on every
//! call, so nothing here performs I/O or reads the clock. There is no
//! write path: a WRQ parses as [`Packet::Wrq`] and the caller refuses it
//! with ERROR 2.
//!
//! Filled in: M1 (docs/ROADMAP.md section 3; plan WU-5). M3 (plan WU-6):
//! RFC 7440 windowsize, block-number wraparound, larger limits, request
//! name normalisation.

// Parses untrusted input: indexing and slicing that can panic are denied
// (CLAUDE.md, Engineering Rules: parsers never panic on input).
#![deny(clippy::indexing_slicing)]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation)
// - NIST 800-53: CM-7 (Least Functionality) - read-only, octet only
// - NIST 800-53: SC-5 (Denial-of-Service Protection)
// - SPEC: specs/boot-network.md#REQ-BOOT-030..035, #REQ-BOOT-040,
//   #REQ-BOOT-041, #REQ-BOOT-064

pub mod error;
pub mod names;
pub mod options;
pub mod packet;
pub mod rto;
pub mod transfer;

pub use error::ParseError;
pub use names::{
    MAX_REQUEST_NAME_LEN, NameRefusal, RequestName, case_insensitive_collision,
    normalize_request_name,
};
pub use options::{MAX_WINDOW_SIZE, Negotiated, OptionList, negotiate, negotiate_window};
pub use packet::{
    ErrorCode, Mode, Opcode, Packet, ReadRequest, Request, encode_ack, encode_data, encode_error,
    encode_oack, encode_request, parse,
};
pub use rto::Rto;
pub use transfer::{
    Admission, BlockWrap, FailReason, LARGE_FILE_MAX_DURATION, LARGE_FILE_MAX_SIZE, MAX_BLOCKS,
    MAX_DURATION_CEILING, MAX_FILE_SIZE_CEILING, Outcome, Phase, ReadTransfer, RefuseReason,
    ServerConfig, Step, WindowConfig, admit_read, admit_read_with, foreign_tid_error,
};
