//! The 24-byte resource header (`wim.md` §3) and little-endian field
//! readers shared by the WIM structures.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - fixed-size reads,
//   checked arithmetic on every offset and size.
// - SPEC: specs/os-images.md#REQ-IMG-037 (locations lie within the file)
// - SPEC: specs/standards/wim.md §3, §9
//
// FORMAT: OBS-002 - every multi-byte field is little-endian (OPEN-WIM-1).
// FORMAT: OBS-007 - layout 7-byte stored size, 1 flag byte, 8-byte offset,
// 8-byte original size; the 56-bit stored size reading holds.

use crate::error::WimError;

/// Size of a resource header in bytes (`wim.md` §3).
pub const RESHDR_LEN: usize = 24;

/// `RESHDR_FLAG_FREE` (`wim.md` §3).
pub const RESHDR_FLAG_FREE: u8 = 0x01;
/// `RESHDR_FLAG_METADATA` (`wim.md` §3).
pub const RESHDR_FLAG_METADATA: u8 = 0x02;
/// `RESHDR_FLAG_COMPRESSED` (`wim.md` §3).
pub const RESHDR_FLAG_COMPRESSED: u8 = 0x04;
/// `RESHDR_FLAG_SPANNED` (`wim.md` §3).
pub const RESHDR_FLAG_SPANNED: u8 = 0x08;

/// A resource location: where a resource is and how big it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResourceHeader {
    /// Stored (possibly compressed) size; 56 bits.
    pub stored_size: u64,
    /// Resource flags (`RESHDR_FLAG_*`).
    pub flags: u8,
    /// Offset from the start of the file.
    pub offset: u64,
    /// Original (uncompressed) size.
    pub original_size: u64,
}

impl ResourceHeader {
    /// Parses 24 bytes. Returns `None` if `b` is shorter than 24 bytes.
    #[must_use]
    pub fn parse(b: &[u8]) -> Option<Self> {
        let mut size = [0u8; 8];
        size.get_mut(..7)?.copy_from_slice(b.get(..7)?);
        Some(Self {
            stored_size: u64::from_le_bytes(size),
            flags: *b.get(7)?,
            offset: le_u64(b, 8)?,
            original_size: le_u64(b, 16)?,
        })
    }

    /// The 24-byte encoding (used by the test builder and fuzz seeds).
    /// The stored size is truncated to 56 bits.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; RESHDR_LEN] {
        let mut out = [0u8; RESHDR_LEN];
        let size = self.stored_size.to_le_bytes();
        for (o, s) in out.iter_mut().zip(size.iter().take(7)) {
            *o = *s;
        }
        if let Some(f) = out.get_mut(7) {
            *f = self.flags;
        }
        for (o, s) in out.iter_mut().skip(8).zip(
            self.offset
                .to_le_bytes()
                .iter()
                .chain(self.original_size.to_le_bytes().iter()),
        ) {
            *o = *s;
        }
        out
    }

    /// True if every field is zero (an absent optional resource).
    #[must_use]
    pub fn is_zero(&self) -> bool {
        *self == Self::default()
    }

    /// True if the compressed flag is set.
    #[must_use]
    pub fn is_compressed(&self) -> bool {
        self.flags & RESHDR_FLAG_COMPRESSED != 0
    }

    /// True if the metadata flag is set.
    #[must_use]
    pub fn is_metadata(&self) -> bool {
        self.flags & RESHDR_FLAG_METADATA != 0
    }

    /// Checks that `[offset, offset + stored_size)` lies after the header
    /// (`data_start`) and inside a file of `file_len` bytes, and returns
    /// the end offset.
    ///
    /// # Errors
    ///
    /// [`WimError::OutOfBounds`] naming `what`, including on u64 overflow.
    pub fn check_within(
        &self,
        data_start: u64,
        file_len: u64,
        what: &'static str,
    ) -> Result<u64, WimError> {
        let end = self
            .offset
            .checked_add(self.stored_size)
            .ok_or(WimError::OutOfBounds { what })?;
        if self.offset < data_start || end > file_len {
            return Err(WimError::OutOfBounds { what });
        }
        Ok(end)
    }
}

/// Little-endian u16 at `at`, or `None` past the end.
#[must_use]
pub fn le_u16(b: &[u8], at: usize) -> Option<u16> {
    let end = at.checked_add(2)?;
    let s: [u8; 2] = b.get(at..end)?.try_into().ok()?;
    Some(u16::from_le_bytes(s))
}

/// Little-endian u32 at `at`, or `None` past the end.
#[must_use]
pub fn le_u32(b: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    let s: [u8; 4] = b.get(at..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(s))
}

/// Little-endian u64 at `at`, or `None` past the end.
#[must_use]
pub fn le_u64(b: &[u8], at: usize) -> Option<u64> {
    let end = at.checked_add(8)?;
    let s: [u8; 8] = b.get(at..end)?.try_into().ok()?;
    Some(u64::from_le_bytes(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_56_bit_size() {
        // OBS-007 S01 lookup header bytes.
        let b = [
            0x84, 0x03, 0, 0, 0, 0, 0, 0x02, 0x4d, 0xd0, 0x0e, 0, 0, 0, 0, 0, 0x84, 0x03, 0, 0, 0,
            0, 0, 0,
        ];
        let h = ResourceHeader::parse(&b).unwrap_or_default();
        assert_eq!(h.stored_size, 900);
        assert_eq!(h.flags, 0x02);
        assert_eq!(h.offset, 970_829);
        assert_eq!(h.original_size, 900);
        assert_eq!(h.to_bytes(), b);
        assert!(ResourceHeader::parse(&b[..23]).is_none());
    }

    #[test]
    fn bounds() {
        let h = ResourceHeader {
            stored_size: 10,
            flags: 0,
            offset: 208,
            original_size: 10,
        };
        assert_eq!(h.check_within(208, 218, "x"), Ok(218));
        assert!(h.check_within(208, 217, "x").is_err());
        assert!(h.check_within(209, 1000, "x").is_err());
        let o = ResourceHeader {
            stored_size: 0x00ff_ffff_ffff_ffff,
            offset: u64::MAX,
            ..h
        };
        assert_eq!(
            o.check_within(208, u64::MAX, "x"),
            Err(WimError::OutOfBounds { what: "x" })
        );
    }
}
