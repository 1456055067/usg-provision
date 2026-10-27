//! The optional integrity table (`wim.md` §8): SHA-1 hashes of fixed-size
//! chunks of the file, checked chunk by chunk.
//!
//! These hashes only detect damage; they are never proof that the file is
//! the one the operator intended (REQ-IMG-051). The product's own SHA-256
//! ([`crate::chunks`]) is the integrity control.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity) -
//   damaged files are refused before they become ready; SI-10 - table
//   size and count checked, entries streamed.
// - SPEC: specs/os-images.md#REQ-IMG-037 (every integrity hash matches),
//   #REQ-IMG-051 (format hashes detect damage only)
// - SPEC: specs/standards/wim.md §8
// - FIPS 180-4 §6.1 (SHA-1, through usgp-crypto's legacy hasher)

use std::io::{Read, Seek};

use usgp_crypto::CryptoProvider;

use super::header::HEADER_LEN_U64;
use super::reshdr::{ResourceHeader, le_u32};
use super::source::Source;
use crate::error::WimError;
use crate::limits::WimLimits;

/// Bytes before the first hash: table size, entry count, chunk size.
pub const TABLE_HEADER_LEN: u64 = 12;
/// Size of one entry (SHA-1).
pub const ENTRY_LEN: u64 = 20;

/// The 12-byte table header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntegrityTableHeader {
    /// Total table size in bytes.
    pub table_size: u32,
    /// Number of hashes.
    pub entry_count: u32,
    /// Chunk size in bytes.
    pub chunk_size: u32,
}

impl IntegrityTableHeader {
    /// Parses the first 12 bytes of the table.
    #[must_use]
    pub fn parse(b: &[u8]) -> Option<Self> {
        Some(Self {
            table_size: le_u32(b, 0)?,
            entry_count: le_u32(b, 4)?,
            chunk_size: le_u32(b, 8)?,
        })
    }
}

/// The hashed range: from the end of the header to the end of the lookup
/// table.
// FORMAT: OBS-015 - in S05 the single hash is SHA-1 of bytes 208 to the
// end of the lookup table; the XML is not hashed (wim.md §8 confirmed).
#[must_use]
pub fn hashed_range(lookup: &ResourceHeader) -> Option<(u64, u64)> {
    let end = lookup.offset.checked_add(lookup.stored_size)?;
    Some((HEADER_LEN_U64, end))
}

/// Checks the table header against the resource header and the hashed
/// range, returning the entry count.
///
/// # Errors
///
/// [`WimError::Malformed`] or [`WimError::LimitExceeded`].
pub fn check_table_header(
    rh: &ResourceHeader,
    t: &IntegrityTableHeader,
    range_len: u64,
    limits: &WimLimits,
) -> Result<u64, WimError> {
    let bad = |what| WimError::Malformed { what };
    if rh.stored_size > limits.max_integrity_bytes {
        return Err(WimError::LimitExceeded {
            what: "integrity table",
        });
    }
    if u64::from(t.table_size) != rh.stored_size {
        return Err(bad("integrity table size"));
    }
    let expected_size = u64::from(t.entry_count)
        .checked_mul(ENTRY_LEN)
        .and_then(|n| n.checked_add(TABLE_HEADER_LEN))
        .ok_or(bad("integrity table size"))?;
    if expected_size != rh.stored_size {
        return Err(bad("integrity table size"));
    }
    if t.chunk_size == 0 {
        return Err(bad("integrity chunk size"));
    }
    // FORMAT: derived, unconfirmed - OPEN-WIM-11. Entry count =
    // ceil(range / chunk size) (wim.md §8 [derived]); OBS-015 saw only a
    // one-entry table with chunk size 10485760.
    if range_len == 0 || range_len.div_ceil(u64::from(t.chunk_size)) != u64::from(t.entry_count) {
        return Err(bad("integrity entry count"));
    }
    Ok(u64::from(t.entry_count))
}

/// Verifies every integrity hash. `rh` is the header's integrity resource
/// (non-zero, already bounds-checked); `lookup` the lookup table's.
pub(crate) fn verify<R: Read + Seek>(
    src: &mut Source<'_, R>,
    rh: &ResourceHeader,
    lookup: &ResourceHeader,
    limits: &WimLimits,
    crypto: &dyn CryptoProvider,
) -> Result<(), WimError> {
    if rh.is_compressed() || rh.stored_size != rh.original_size {
        return Err(WimError::Malformed {
            what: "integrity table resource",
        });
    }
    if rh.stored_size < TABLE_HEADER_LEN {
        return Err(WimError::Malformed {
            what: "integrity table size",
        });
    }
    let mut head = [0u8; 12];
    src.read_at(rh.offset, &mut head)?;
    let t = IntegrityTableHeader::parse(&head).ok_or(WimError::TooShort)?;
    let (start, end) = hashed_range(lookup).ok_or(WimError::OutOfBounds {
        what: "integrity range",
    })?;
    let range_len = end.checked_sub(start).ok_or(WimError::OutOfBounds {
        what: "integrity range",
    })?;
    let count = check_table_header(rh, &t, range_len, limits)?;
    let chunk = u64::from(t.chunk_size);
    for i in 0..count {
        let entry_at = i
            .checked_mul(ENTRY_LEN)
            .and_then(|o| o.checked_add(TABLE_HEADER_LEN))
            .and_then(|o| o.checked_add(rh.offset))
            .ok_or(WimError::OutOfBounds {
                what: "integrity table",
            })?;
        let mut expected = [0u8; 20];
        src.read_at(entry_at, &mut expected)?;
        let chunk_start = i
            .checked_mul(chunk)
            .and_then(|o| o.checked_add(start))
            .ok_or(WimError::OutOfBounds {
                what: "integrity range",
            })?;
        // FORMAT: derived, unconfirmed - OPEN-WIM-11: the last chunk is
        // the remainder of the range (not observed; OBS-015 one entry).
        let len = end.saturating_sub(chunk_start).min(chunk);
        let mut h = crypto.legacy_sha1_hasher();
        src.stream(chunk_start, len, &mut |piece| {
            h.update(piece);
            Ok(())
        })?;
        if h.finish().0 != expected {
            return Err(WimError::IntegrityMismatch { chunk: i });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obs_015_header() {
        // S05: 20 00 00 00 01 00 00 00 00 00 a0 00.
        let t = IntegrityTableHeader::parse(&[0x20, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0xa0, 0]).unwrap();
        assert_eq!(t.table_size, 32);
        assert_eq!(t.entry_count, 1);
        assert_eq!(t.chunk_size, 10_485_760);
        let rh = ResourceHeader {
            stored_size: 32,
            flags: 0,
            offset: 644_888,
            original_size: 32,
        };
        let l = WimLimits::DEFAULT;
        assert_eq!(check_table_header(&rh, &t, 643_714, &l), Ok(1));
        assert!(check_table_header(&rh, &t, 10_485_761, &l).is_err());
        assert!(check_table_header(&rh, &t, 0, &l).is_err());
        let zero = IntegrityTableHeader { chunk_size: 0, ..t };
        assert!(check_table_header(&rh, &zero, 1, &l).is_err());
        let big = IntegrityTableHeader {
            entry_count: u32::MAX,
            ..t
        };
        assert!(check_table_header(&rh, &big, 1, &l).is_err());
    }
}
