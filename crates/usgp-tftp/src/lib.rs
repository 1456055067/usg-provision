//! usgp-tftp: sans-IO TFTP read-only server state machine.
//!
//! [`parse`] decodes packets; [`admit_read`] decides whether to start a
//! read transfer (octet mode only, `blksize`/`tsize` negotiation, the
//! 65535-block limit); [`ReadTransfer`] is the lock-step sender. Time and
//! file bytes are passed in on every call, so nothing here performs I/O or
//! reads the clock. There is no write path: a WRQ parses as
//! [`Packet::Wrq`] and the caller refuses it with ERROR 2.
//!
//! Filled in: M1 (docs/ROADMAP.md section 3; plan WU-5).

// Parses untrusted input: indexing and slicing that can panic are denied
// (CLAUDE.md, Engineering Rules: parsers never panic on input).
#![deny(clippy::indexing_slicing)]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation)
// - NIST 800-53: CM-7 (Least Functionality) - read-only, octet only
// - NIST 800-53: SC-5 (Denial-of-Service Protection)
// - SPEC: specs/boot-network.md#REQ-BOOT-030..035, #REQ-BOOT-040

pub mod error;
pub mod options;
pub mod packet;
pub mod rto;
pub mod transfer;

pub use error::ParseError;
pub use options::{Negotiated, OptionList, negotiate};
pub use packet::{
    ErrorCode, Mode, Opcode, Packet, ReadRequest, Request, encode_ack, encode_data, encode_error,
    encode_oack, encode_request, parse,
};
pub use rto::Rto;
pub use transfer::{
    Admission, FailReason, MAX_BLOCKS, Outcome, Phase, ReadTransfer, RefuseReason, ServerConfig,
    Step, admit_read, foreign_tid_error,
};
