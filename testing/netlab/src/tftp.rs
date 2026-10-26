//! Minimal, independent TFTP client codec for the lab probe.
//!
//! Written from `specs/standards/tftp.md` (RFC 1350 §5, RFC 2347 §2,
//! RFC 2348, RFC 2349), not from `usgp-tftp` (plan section 1.2). It builds
//! requests and ACKs and decodes what a server sends back.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Testing and Evaluation), SI-10
//! - RFC 1350 §5 - packet formats; RFC 2347 §2 - options and OACK

use std::fmt;

/// Read request.
pub const OP_RRQ: u16 = 1;
/// Write request.
pub const OP_WRQ: u16 = 2;
/// Data.
pub const OP_DATA: u16 = 3;
/// Acknowledgment.
pub const OP_ACK: u16 = 4;
/// Error.
pub const OP_ERROR: u16 = 5;
/// Option acknowledgment (RFC 2347).
pub const OP_OACK: u16 = 6;

/// Largest datagram the probe accepts from a server: 65464-octet block plus
/// the 4-octet header (RFC 2348 block size range).
pub const MAX_DATAGRAM: usize = 65_468;

/// A packet received from a server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerPacket {
    /// DATA with block number and payload.
    Data {
        /// Block number.
        block: u16,
        /// Payload (0 to block size octets).
        data: Vec<u8>,
    },
    /// ERROR with code and message.
    Error {
        /// Error code (RFC 1350 appendix).
        code: u16,
        /// Message bytes, without the NUL.
        message: Vec<u8>,
    },
    /// OACK with name/value pairs.
    Oack(Vec<(String, String)>),
    /// Anything a server should not send to a reader (RRQ, WRQ, ACK).
    Unexpected(u16),
}

/// Why a server packet could not be decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TftpError {
    /// Fewer than 4 octets (2 for OACK).
    TooShort(usize),
    /// Longer than [`MAX_DATAGRAM`].
    TooLong(usize),
    /// Opcode outside 1 to 6.
    BadOpcode(u16),
    /// ERROR message or OACK field not NUL-terminated, or OACK name without value.
    BadFraming,
    /// OACK field not ASCII.
    NotAscii,
}

impl fmt::Display for TftpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort(n) => write!(f, "packet too short ({n} octets)"),
            Self::TooLong(n) => write!(f, "packet too long ({n} octets)"),
            Self::BadOpcode(op) => write!(f, "bad opcode {op}"),
            Self::BadFraming => write!(f, "bad NUL framing"),
            Self::NotAscii => write!(f, "OACK field is not ASCII"),
        }
    }
}

impl std::error::Error for TftpError {}

/// Builds an RRQ or WRQ: opcode, filename, NUL, mode, NUL, then option
/// name/value pairs, each NUL-terminated (RFC 1350 §5, RFC 2347 §2). The
/// filename is raw bytes so the probe can send hostile names.
pub fn request(opcode: u16, filename: &[u8], mode: &str, options: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(filename.len() + mode.len() + 16);
    out.extend_from_slice(&opcode.to_be_bytes());
    out.extend_from_slice(filename);
    out.push(0);
    out.extend_from_slice(mode.as_bytes());
    out.push(0);
    for (name, value) in options {
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        out.extend_from_slice(value.as_bytes());
        out.push(0);
    }
    out
}

/// Builds an ACK.
pub fn ack(block: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(4);
    out.extend_from_slice(&OP_ACK.to_be_bytes());
    out.extend_from_slice(&block.to_be_bytes());
    out
}

/// Builds an ERROR.
pub fn error(code: u16, message: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + message.len());
    out.extend_from_slice(&OP_ERROR.to_be_bytes());
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(message.as_bytes());
    out.push(0);
    out
}

/// Decodes a packet from a server, bounds-checked.
pub fn decode(buf: &[u8]) -> Result<ServerPacket, TftpError> {
    if buf.len() > MAX_DATAGRAM {
        return Err(TftpError::TooLong(buf.len()));
    }
    let Some((op, rest)) = buf.split_first_chunk::<2>() else {
        return Err(TftpError::TooShort(buf.len()));
    };
    let opcode = u16::from_be_bytes(*op);
    match opcode {
        OP_DATA | OP_ERROR => {
            let Some((num, body)) = rest.split_first_chunk::<2>() else {
                return Err(TftpError::TooShort(buf.len()));
            };
            let num = u16::from_be_bytes(*num);
            if opcode == OP_DATA {
                return Ok(ServerPacket::Data {
                    block: num,
                    data: body.to_vec(),
                });
            }
            let Some((&0, message)) = body.split_last() else {
                return Err(TftpError::BadFraming);
            };
            if message.contains(&0) {
                return Err(TftpError::BadFraming);
            }
            Ok(ServerPacket::Error {
                code: num,
                message: message.to_vec(),
            })
        }
        OP_OACK => {
            let mut pairs = Vec::new();
            let mut fields = Vec::new();
            if !rest.is_empty() {
                let Some((&0, body)) = rest.split_last() else {
                    return Err(TftpError::BadFraming);
                };
                for field in body.split(|&b| b == 0) {
                    if !field.is_ascii() {
                        return Err(TftpError::NotAscii);
                    }
                    fields.push(String::from_utf8_lossy(field).into_owned());
                }
            }
            let mut it = fields.into_iter();
            while let Some(name) = it.next() {
                let Some(value) = it.next() else {
                    return Err(TftpError::BadFraming);
                };
                pairs.push((name.to_ascii_lowercase(), value));
            }
            Ok(ServerPacket::Oack(pairs))
        }
        OP_RRQ | OP_WRQ | OP_ACK => Ok(ServerPacket::Unexpected(opcode)),
        other => Err(TftpError::BadOpcode(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_layout() {
        let r = request(
            OP_RRQ,
            b"boot.efi",
            "octet",
            &[("blksize", "1468"), ("tsize", "0")],
        );
        assert_eq!(
            r,
            b"\x00\x01boot.efi\x00octet\x00blksize\x001468\x00tsize\x000\x00".to_vec()
        );
        assert_eq!(
            request(OP_WRQ, b"x", "octet", &[]),
            b"\x00\x02x\x00octet\x00".to_vec()
        );
    }

    #[test]
    fn ack_and_error_layout() {
        assert_eq!(ack(0x0102), vec![0, 4, 1, 2]);
        assert_eq!(error(5, "tid"), b"\x00\x05\x00\x05tid\x00".to_vec());
    }

    #[test]
    fn decode_data_error_oack() {
        assert_eq!(
            decode(&[0, 3, 0, 1, 9, 8]),
            Ok(ServerPacket::Data {
                block: 1,
                data: vec![9, 8]
            })
        );
        assert_eq!(
            decode(&[0, 3, 0, 2]),
            Ok(ServerPacket::Data {
                block: 2,
                data: vec![]
            })
        );
        assert_eq!(
            decode(b"\x00\x05\x00\x01not found\x00"),
            Ok(ServerPacket::Error {
                code: 1,
                message: b"not found".to_vec()
            })
        );
        assert_eq!(
            decode(b"\x00\x06BLKSIZE\x001468\x00tsize\x003072\x00"),
            Ok(ServerPacket::Oack(vec![
                ("blksize".into(), "1468".into()),
                ("tsize".into(), "3072".into())
            ]))
        );
        assert_eq!(decode(&[0, 6]), Ok(ServerPacket::Oack(vec![])));
        assert_eq!(decode(&[0, 4, 0, 0]), Ok(ServerPacket::Unexpected(OP_ACK)));
    }

    #[test]
    fn decode_rejects_malformed() {
        assert_eq!(decode(&[]), Err(TftpError::TooShort(0)));
        assert_eq!(decode(&[0]), Err(TftpError::TooShort(1)));
        assert_eq!(decode(&[0, 3, 0]), Err(TftpError::TooShort(3)));
        assert_eq!(decode(&[0, 7, 0, 0]), Err(TftpError::BadOpcode(7)));
        assert_eq!(decode(&[0, 0, 0, 0]), Err(TftpError::BadOpcode(0)));
        assert_eq!(decode(b"\x00\x05\x00\x01abc"), Err(TftpError::BadFraming));
        assert_eq!(
            decode(b"\x00\x05\x00\x01a\x00b\x00"),
            Err(TftpError::BadFraming)
        );
        assert_eq!(decode(b"\x00\x06blksize\x00"), Err(TftpError::BadFraming));
        assert_eq!(decode(b"\x00\x06blksize"), Err(TftpError::BadFraming));
        assert_eq!(decode(b"\x00\x06b\xffk\x001\x00"), Err(TftpError::NotAscii));
        assert_eq!(
            decode(&vec![0; MAX_DATAGRAM + 1]),
            Err(TftpError::TooLong(MAX_DATAGRAM + 1))
        );
    }
}
