//! GUIDs as GPT stores them (UEFI byte order).
//!
//! The 16 octets are held exactly as they sit on disk: TimeLow, TimeMid and
//! TimeHighAndVersion little-endian, the remaining eight octets in text
//! order (`specs/standards/uefi-guid-text.md` §1.2). The text form is the
//! 8-4-4-4-12 registry format (§1, §2).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation)
// - SPEC: specs/disk.md#REQ-DISK-009 (new random disk and partition GUIDs)
// - UEFI 2.10 Appendix A (specs/standards/uefi-guid-text.md §1.2)
// - RFC 9562 §5.4 - version 4 (random) UUID layout

use std::fmt;

/// A GUID in UEFI on-disk byte order.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Guid(pub [u8; 16]);

impl Guid {
    /// The nil GUID: all zero; marks an unused GPT entry (`gpt.md` §5, §9).
    pub const NIL: Self = Self([0; 16]);

    /// Builds a GUID from its text-form fields
    /// (`aabbccdd-eeff-gghh-iijj-kkllmmnnoopp` is
    /// `from_fields(0xaabbccdd, 0xeeff, 0xgghh, [ii, jj, kk, .., pp])`),
    /// stored in UEFI byte order (`uefi-guid-text.md` §1.2, Table A.2).
    #[must_use]
    pub const fn from_fields(time_low: u32, time_mid: u16, time_hi: u16, rest: [u8; 8]) -> Self {
        let a = time_low.to_le_bytes();
        let b = time_mid.to_le_bytes();
        let c = time_hi.to_le_bytes();
        Self([
            a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], rest[0], rest[1], rest[2], rest[3],
            rest[4], rest[5], rest[6], rest[7],
        ])
    }

    /// A new random GUID from `rng` (expected to be the FIPS DRBG through
    /// `usgp-crypto`), with the RFC 9562 version 4 and variant bits set.
    ///
    /// The version nibble is the high nibble of TimeHighAndVersion, which in
    /// UEFI byte order is octet 7 (`uefi-guid-text.md` §1.2); the variant is
    /// the top two bits of octet 8 (`uefi-guid-text.md` §1.1).
    pub fn random(rng: &mut dyn FnMut(&mut [u8])) -> Self {
        let mut b = [0u8; 16];
        rng(&mut b);
        // FORMAT: RFC 9562 §5.4 - version 4 in the high nibble of
        // time_hi_and_version (octet 7 in UEFI byte order).
        if let Some(v) = b.get_mut(7) {
            *v = (*v & 0x0F) | 0x40;
        }
        // FORMAT: RFC 9562 §4.1 - variant binary 10 in the top bits of
        // clock_seq_hi_and_reserved (octet 8).
        if let Some(v) = b.get_mut(8) {
            *v = (*v & 0x3F) | 0x80;
        }
        Self(b)
    }

    /// `true` for the nil GUID.
    #[must_use]
    pub fn is_nil(&self) -> bool {
        self.0 == [0; 16]
    }
}

impl fmt::Display for Guid {
    /// Registry text form, upper case (`uefi-guid-text.md` §1.2, §2: case is
    /// not significant).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [
            o0,
            o1,
            o2,
            o3,
            o4,
            o5,
            o6,
            o7,
            o8,
            o9,
            o10,
            o11,
            o12,
            o13,
            o14,
            o15,
        ] = self.0;
        write!(
            f,
            "{o3:02X}{o2:02X}{o1:02X}{o0:02X}-{o5:02X}{o4:02X}-{o7:02X}{o6:02X}-{o8:02X}{o9:02X}-\
             {o10:02X}{o11:02X}{o12:02X}{o13:02X}{o14:02X}{o15:02X}"
        )
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Guid({self})")
    }
}

/// Partition type GUIDs Windows uses (`specs/standards/gpt.md` §9).
pub mod types {
    use super::Guid;

    /// FORMAT: gpt.md §9 - EFI system partition
    /// `C12A7328-F81F-11D2-BA4B-00A0C93EC93B`.
    pub const ESP: Guid = Guid::from_fields(
        0xC12A_7328,
        0xF81F,
        0x11D2,
        [0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B],
    );
    /// FORMAT: gpt.md §9 - Microsoft reserved
    /// `E3C9E316-0B5C-4DB8-817D-F92DF00215AE`.
    pub const MSR: Guid = Guid::from_fields(
        0xE3C9_E316,
        0x0B5C,
        0x4DB8,
        [0x81, 0x7D, 0xF9, 0x2D, 0xF0, 0x02, 0x15, 0xAE],
    );
    /// FORMAT: gpt.md §9 - basic data
    /// `EBD0A0A2-B9E5-4433-87C0-68B6B72699C7`.
    pub const BASIC_DATA: Guid = Guid::from_fields(
        0xEBD0_A0A2,
        0xB9E5,
        0x4433,
        [0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7],
    );
    /// FORMAT: gpt.md §9 - Microsoft recovery
    /// `DE94BBA4-06D1-4D40-A16A-BFD50179D6AC`.
    pub const RECOVERY: Guid = Guid::from_fields(
        0xDE94_BBA4,
        0x06D1,
        0x4D40,
        [0xA1, 0x6A, 0xBF, 0xD5, 0x01, 0x79, 0xD6, 0xAC],
    );
}
