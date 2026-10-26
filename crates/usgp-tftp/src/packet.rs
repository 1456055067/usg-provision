//! TFTP packet parser and encoders (RFC 1350 §5, RFC 2347).
//!
//! The parser borrows from the input and never panics: every read is a
//! bounds-checked `get`/`split_*`, and lengths are checked before any scan.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation)
// - NIST 800-53: SI-11 (Error Handling) - error messages we send are fixed
//   strings chosen by the caller, never paths or digests.
// - SPEC: specs/boot-network.md#REQ-BOOT-030, #REQ-BOOT-031
// - RFC 1350 §5 - packet formats; Appendix - error codes
// - RFC 2347 - OACK, option framing, 512-octet request limit

use crate::error::ParseError;
use crate::options::{OptionList, parse_option_list};

/// Longest RRQ/WRQ/OACK accepted (RFC 2347).
pub const MAX_REQUEST_LEN: usize = 512;
/// Default block size (RFC 1350 §2).
pub const DEFAULT_BLOCK_SIZE: u16 = 512;
/// Smallest negotiable block size (RFC 2348).
pub const MIN_BLOCK_SIZE: u16 = 8;
/// Largest negotiable block size (RFC 2348).
pub const MAX_BLOCK_SIZE: u16 = 65464;
/// Opcode and block number.
pub const HEADER_LEN: usize = 4;
/// Longest DATA packet (header plus the largest block).
pub const MAX_DATA_PACKET_LEN: usize = HEADER_LEN + 65464;

/// TFTP opcodes (RFC 1350 §5; RFC 2347 for OACK).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    /// Read request.
    Rrq,
    /// Write request.
    Wrq,
    /// Data.
    Data,
    /// Acknowledgement.
    Ack,
    /// Error.
    Error,
    /// Option acknowledgement.
    Oack,
}

impl Opcode {
    /// Wire value.
    #[must_use]
    pub fn code(self) -> u16 {
        match self {
            Self::Rrq => 1,
            Self::Wrq => 2,
            Self::Data => 3,
            Self::Ack => 4,
            Self::Error => 5,
            Self::Oack => 6,
        }
    }

    /// Decodes a wire value.
    #[must_use]
    pub fn from_code(v: u16) -> Option<Self> {
        Some(match v {
            1 => Self::Rrq,
            2 => Self::Wrq,
            3 => Self::Data,
            4 => Self::Ack,
            5 => Self::Error,
            6 => Self::Oack,
            _ => return None,
        })
    }
}

/// TFTP error codes (RFC 1350 Appendix; RFC 2347 for 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// 0: not defined, see message.
    NotDefined,
    /// 1: file not found.
    FileNotFound,
    /// 2: access violation.
    AccessViolation,
    /// 3: disk full or allocation exceeded.
    DiskFull,
    /// 4: illegal TFTP operation.
    IllegalOperation,
    /// 5: unknown transfer ID.
    UnknownTransferId,
    /// 6: file already exists.
    FileExists,
    /// 7: no such user.
    NoSuchUser,
    /// 8: option negotiation failed.
    OptionNegotiation,
}

impl ErrorCode {
    /// Wire value.
    #[must_use]
    pub fn code(self) -> u16 {
        match self {
            Self::NotDefined => 0,
            Self::FileNotFound => 1,
            Self::AccessViolation => 2,
            Self::DiskFull => 3,
            Self::IllegalOperation => 4,
            Self::UnknownTransferId => 5,
            Self::FileExists => 6,
            Self::NoSuchUser => 7,
            Self::OptionNegotiation => 8,
        }
    }

    /// Decodes a wire value.
    #[must_use]
    pub fn from_code(v: u16) -> Option<Self> {
        Some(match v {
            0 => Self::NotDefined,
            1 => Self::FileNotFound,
            2 => Self::AccessViolation,
            3 => Self::DiskFull,
            4 => Self::IllegalOperation,
            5 => Self::UnknownTransferId,
            6 => Self::FileExists,
            7 => Self::NoSuchUser,
            8 => Self::OptionNegotiation,
            _ => return None,
        })
    }
}

/// Transfer mode named in a request (RFC 1350 §1; matched
/// case-insensitively).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `octet`: the only mode this server serves.
    Octet,
    /// `netascii`: refused.
    Netascii,
    /// `mail`: obsolete (RFC 1123 §4.2.2.1); refused.
    Mail,
    /// Anything else; refused.
    Other,
}

impl Mode {
    /// Classifies raw mode bytes.
    #[must_use]
    pub fn classify(raw: &[u8]) -> Self {
        if raw.eq_ignore_ascii_case(b"octet") {
            Self::Octet
        } else if raw.eq_ignore_ascii_case(b"netascii") {
            Self::Netascii
        } else if raw.eq_ignore_ascii_case(b"mail") {
            Self::Mail
        } else {
            Self::Other
        }
    }
}

/// An RRQ or WRQ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request<'a> {
    /// Filename bytes exactly as sent (no decoding or normalisation). The
    /// caller matches it byte for byte against published names
    /// (REQ-BOOT-041) and never uses it as a path.
    pub filename: &'a [u8],
    /// Mode bytes exactly as sent.
    pub mode: &'a [u8],
    /// Options after the mode (RFC 2347).
    pub options: OptionList<'a>,
}

/// A read request (RRQ). Same layout as a WRQ.
pub type ReadRequest<'a> = Request<'a>;

impl Request<'_> {
    /// The classified mode.
    #[must_use]
    pub fn mode_kind(&self) -> Mode {
        Mode::classify(self.mode)
    }
}

/// A parsed TFTP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Packet<'a> {
    /// Read request.
    Rrq(Request<'a>),
    /// Write request (always refused by this server).
    Wrq(Request<'a>),
    /// Data block.
    Data {
        /// Block number.
        block: u16,
        /// Payload.
        data: &'a [u8],
    },
    /// Acknowledgement.
    Ack {
        /// Block number.
        block: u16,
    },
    /// Error.
    Error {
        /// Error code (may be outside the defined set).
        code: u16,
        /// Message bytes, without the terminating NUL.
        message: &'a [u8],
    },
    /// Option acknowledgement.
    Oack(OptionList<'a>),
}

/// Splits at the first NUL: `(before, after)`.
pub(crate) fn split_cstr(b: &[u8]) -> Option<(&[u8], &[u8])> {
    let pos = b.iter().position(|&c| c == 0)?;
    let (head, tail) = b.split_at_checked(pos)?;
    Some((head, tail.get(1..)?))
}

fn parse_request(body: &[u8]) -> Result<Request<'_>, ParseError> {
    let (filename, rest) = split_cstr(body).ok_or(ParseError::FilenameUnterminated)?;
    if filename.is_empty() {
        return Err(ParseError::EmptyFilename);
    }
    let (mode, rest) = split_cstr(rest).ok_or(ParseError::ModeUnterminated)?;
    if mode.is_empty() {
        return Err(ParseError::EmptyMode);
    }
    Ok(Request {
        filename,
        mode,
        options: parse_option_list(rest)?,
    })
}

/// Parses one TFTP packet.
///
/// Limits: RRQ, WRQ and OACK at most 512 octets; ACK exactly 4; DATA at
/// most 4 + 65464; ERROR message NUL-terminated as the last octet; opcodes
/// 1 to 6 only.
///
/// # Errors
///
/// A [`ParseError`] naming the first rule broken.
pub fn parse(buf: &[u8]) -> Result<Packet<'_>, ParseError> {
    let len = buf.len();
    let (op, body) = buf
        .split_first_chunk::<2>()
        .ok_or(ParseError::TooShort { len })?;
    let opcode = u16::from_be_bytes(*op);
    let op = Opcode::from_code(opcode).ok_or(ParseError::UnknownOpcode { opcode })?;
    match op {
        Opcode::Rrq | Opcode::Wrq | Opcode::Oack if len > MAX_REQUEST_LEN => {
            Err(ParseError::RequestTooLong { len })
        }
        Opcode::Rrq => parse_request(body).map(Packet::Rrq),
        Opcode::Wrq => parse_request(body).map(Packet::Wrq),
        Opcode::Oack => {
            let list = parse_option_list(body)?;
            if list.is_empty() {
                return Err(ParseError::EmptyOack);
            }
            Ok(Packet::Oack(list))
        }
        Opcode::Ack => match body {
            [hi, lo] => Ok(Packet::Ack {
                block: u16::from_be_bytes([*hi, *lo]),
            }),
            _ => Err(ParseError::BadAckLength { len }),
        },
        Opcode::Data => {
            if len > MAX_DATA_PACKET_LEN {
                return Err(ParseError::DataTooLong { len });
            }
            let (block, data) = body
                .split_first_chunk::<2>()
                .ok_or(ParseError::TooShort { len })?;
            Ok(Packet::Data {
                block: u16::from_be_bytes(*block),
                data,
            })
        }
        Opcode::Error => {
            let (code, rest) = body
                .split_first_chunk::<2>()
                .ok_or(ParseError::TooShort { len })?;
            let message = rest
                .strip_suffix(&[0])
                .ok_or(ParseError::ErrorUnterminated)?;
            if message.contains(&0) {
                return Err(ParseError::ErrorUnterminated);
            }
            Ok(Packet::Error {
                code: u16::from_be_bytes(*code),
                message,
            })
        }
    }
}

fn push_cstr(b: &mut Vec<u8>, s: &[u8]) {
    b.extend(s.iter().copied().filter(|&c| c != 0));
    b.push(0);
}

/// Encodes a DATA packet.
#[must_use]
pub fn encode_data(block: u16, data: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(HEADER_LEN + data.len());
    b.extend_from_slice(&Opcode::Data.code().to_be_bytes());
    b.extend_from_slice(&block.to_be_bytes());
    b.extend_from_slice(data);
    b
}

/// Encodes an ACK packet.
#[must_use]
pub fn encode_ack(block: u16) -> Vec<u8> {
    let mut b = Vec::with_capacity(HEADER_LEN);
    b.extend_from_slice(&Opcode::Ack.code().to_be_bytes());
    b.extend_from_slice(&block.to_be_bytes());
    b
}

/// Encodes an ERROR packet. NUL octets in `msg` are removed.
///
/// Callers pass fixed, generic messages only (SI-11): never a path, a
/// digest, or the requested name.
#[must_use]
pub fn encode_error(code: ErrorCode, msg: &str) -> Vec<u8> {
    encode_error_raw(code.code(), msg.as_bytes())
}

fn encode_error_raw(code: u16, msg: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(HEADER_LEN + msg.len() + 1);
    b.extend_from_slice(&Opcode::Error.code().to_be_bytes());
    b.extend_from_slice(&code.to_be_bytes());
    push_cstr(&mut b, msg);
    b
}

/// Encodes an OACK from `(name, value)` pairs.
#[must_use]
pub fn encode_oack(options: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut b = Vec::with_capacity(64);
    b.extend_from_slice(&Opcode::Oack.code().to_be_bytes());
    for (name, value) in options {
        push_cstr(&mut b, name);
        push_cstr(&mut b, value);
    }
    b
}

/// Encodes an RRQ or WRQ (for tests, fuzz seeds, and lab clients).
/// `opcode` other than RRQ/WRQ is encoded as given.
#[must_use]
pub fn encode_request(
    opcode: Opcode,
    filename: &[u8],
    mode: &[u8],
    options: &[(&[u8], &[u8])],
) -> Vec<u8> {
    let mut b = Vec::with_capacity(64);
    b.extend_from_slice(&opcode.code().to_be_bytes());
    push_cstr(&mut b, filename);
    push_cstr(&mut b, mode);
    for (name, value) in options {
        push_cstr(&mut b, name);
        push_cstr(&mut b, value);
    }
    b
}

impl Packet<'_> {
    /// Re-encodes the packet. For any `p` returned by [`parse`],
    /// `parse(&p.encode()) == Ok(p)`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Rrq(r) | Self::Wrq(r) => {
                let op = if matches!(self, Self::Rrq(_)) {
                    Opcode::Rrq
                } else {
                    Opcode::Wrq
                };
                let pairs: Vec<_> = r.options.iter().collect();
                encode_request(op, r.filename, r.mode, &pairs)
            }
            Self::Data { block, data } => encode_data(*block, data),
            Self::Ack { block } => encode_ack(*block),
            Self::Error { code, message } => encode_error_raw(*code, message),
            Self::Oack(list) => {
                let pairs: Vec<_> = list.iter().collect();
                encode_oack(&pairs)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rrq_parse() {
        let b = b"\x00\x01boot.efi\x00OcTeT\x00blksize\x001468\x00tsize\x000\x00";
        let Packet::Rrq(r) = parse(b).unwrap() else {
            panic!("not an RRQ")
        };
        assert_eq!(r.filename, b"boot.efi");
        assert_eq!(r.mode_kind(), Mode::Octet);
        assert_eq!(r.options.get(b"BLKSIZE"), Some(&b"1468"[..]));
        assert_eq!(r.options.len(), 2);
    }

    #[test]
    fn ack_data_error_parse() {
        assert_eq!(parse(&[0, 4, 1, 2]), Ok(Packet::Ack { block: 0x0102 }));
        assert_eq!(
            parse(&[0, 3, 0, 1, 9, 9]),
            Ok(Packet::Data {
                block: 1,
                data: &[9, 9]
            })
        );
        assert_eq!(
            parse(&[0, 3, 0, 1]),
            Ok(Packet::Data {
                block: 1,
                data: &[]
            })
        );
        assert_eq!(
            parse(b"\x00\x05\x00\x08no\x00"),
            Ok(Packet::Error {
                code: 8,
                message: b"no"
            })
        );
        assert_eq!(
            parse(b"\x00\x05\x00\x08\x00"),
            Ok(Packet::Error {
                code: 8,
                message: b""
            })
        );
        assert_eq!(
            parse(b"\x00\x05\x00\x08no"),
            Err(ParseError::ErrorUnterminated)
        );
        assert_eq!(
            parse(b"\x00\x05\x00\x08n\x00o\x00"),
            Err(ParseError::ErrorUnterminated)
        );
    }

    #[test]
    fn encoders_roundtrip() {
        for p in [
            encode_data(7, b"abc"),
            encode_ack(65535),
            encode_error(ErrorCode::FileNotFound, "file not found"),
            encode_oack(&[(b"blksize", b"1468"), (b"tsize", b"5632")]),
            encode_request(Opcode::Rrq, b"a/b", b"octet", &[(b"tsize", b"0")]),
            encode_request(Opcode::Wrq, b"x", b"netascii", &[]),
        ] {
            let parsed = parse(&p).unwrap();
            assert_eq!(parsed.encode(), p);
        }
    }

    #[test]
    fn error_message_nul_removed() {
        let b = encode_error(ErrorCode::NotDefined, "a\0b");
        assert_eq!(b, b"\x00\x05\x00\x00ab\x00");
    }

    #[test]
    fn data_length_limit() {
        let mut b = encode_data(1, &vec![0u8; usize::from(MAX_BLOCK_SIZE)]);
        assert!(parse(&b).is_ok());
        b.push(0);
        assert_eq!(
            parse(&b),
            Err(ParseError::DataTooLong {
                len: MAX_DATA_PACKET_LEN + 1
            })
        );
    }

    #[test]
    fn codes_roundtrip() {
        for v in 0..=8u16 {
            assert_eq!(ErrorCode::from_code(v).map(ErrorCode::code), Some(v));
        }
        assert_eq!(ErrorCode::from_code(9), None);
        for v in 1..=6u16 {
            assert_eq!(Opcode::from_code(v).map(Opcode::code), Some(v));
        }
        assert_eq!(Opcode::from_code(0), None);
        assert_eq!(Opcode::from_code(7), None);
    }

    #[test]
    fn mode_classify() {
        assert_eq!(Mode::classify(b"OCTET"), Mode::Octet);
        assert_eq!(Mode::classify(b"NetAscii"), Mode::Netascii);
        assert_eq!(Mode::classify(b"mail"), Mode::Mail);
        assert_eq!(Mode::classify(b"octet "), Mode::Other);
    }
}
