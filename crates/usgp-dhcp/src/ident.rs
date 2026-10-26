//! Device identifiers claimed in DHCP messages: hardware address, machine
//! GUID, and client architecture.
//!
//! These are labels the device claims. They are never authenticators
//! (REQ-BOOT-045): they are used only for suppression and audit labels.

// COMPLIANCE MAPPING:
// - NIST 800-53: IA-3 (Device Identification and Authentication) - not met
//   on TB-1 (PXE is unauthenticated by standard); identifiers are labels
//   only, never used as authorisation. Not implementation evidence for
//   IA-3; the gap and its compensating controls are tracked in
//   docs/compliance/POAM.md (IA-3 on TB-1: devices are not identified or
//   authenticated before network boot).
// - NIST 800-53: SI-10 (Information Input Validation)
// - SPEC: specs/boot-network.md#REQ-BOOT-007, #REQ-BOOT-045
// - RFC 2131 §2 (chaddr); RFC 4578 §2.1 (arch), §2.3 (machine identifier)
// - UEFI 2.10 Appendix A Tables A.1/A.2 - GUID text form and byte order
//   (specs/standards/uefi-guid-text.md §1-§3)

use core::fmt;
use core::str::FromStr;
use std::borrow::Cow;

use thiserror::Error;

/// Why an identifier string or value was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum IdentError {
    /// Not in the expected text form.
    #[error("identifier syntax invalid")]
    Syntax,
    /// A hardware address that is multicast (group bit set).
    #[error("hardware address is multicast")]
    Multicast,
    /// A hardware address of all zero octets.
    #[error("hardware address is all zero")]
    Zero,
}

/// A unicast, non-zero 48-bit Ethernet hardware address.
///
/// The constructor rejects multicast (least significant bit of the first
/// octet set) and all-zero addresses, so every `MacAddr` value is usable as
/// a device label.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    /// Validates and wraps six octets.
    ///
    /// # Errors
    ///
    /// [`IdentError::Multicast`] or [`IdentError::Zero`].
    pub fn new(octets: [u8; 6]) -> Result<Self, IdentError> {
        if octets == [0; 6] {
            return Err(IdentError::Zero);
        }
        let [first, ..] = octets;
        if first & 0x01 != 0 {
            return Err(IdentError::Multicast);
        }
        Ok(Self(octets))
    }

    /// The six octets in wire order.
    #[must_use]
    pub fn octets(&self) -> [u8; 6] {
        self.0
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacAddr({self})")
    }
}

impl FromStr for MacAddr {
    type Err = IdentError;

    /// Parses `aa:bb:cc:dd:ee:ff` (hex digits in either case, colon
    /// separators only).
    fn from_str(s: &str) -> Result<Self, IdentError> {
        let b = s.as_bytes();
        if b.len() != 17 {
            return Err(IdentError::Syntax);
        }
        let mut out = [0u8; 6];
        for (i, slot) in out.iter_mut().enumerate() {
            let at = i * 3;
            let hi = b.get(at).copied().and_then(hex_val);
            let lo = b.get(at + 1).copied().and_then(hex_val);
            let (Some(hi), Some(lo)) = (hi, lo) else {
                return Err(IdentError::Syntax);
            };
            if i < 5 && b.get(at + 2) != Some(&b':') {
                return Err(IdentError::Syntax);
            }
            *slot = (hi << 4) | lo;
        }
        Self::new(out)
    }
}

/// A 16-octet client machine identifier from option 97 (RFC 4578 §2.3).
///
/// Stored in wire order, which is read as the UEFI GUID buffer
/// (uefi-guid-text.md §3). The text form is the 8-4-4-4-12 registry form
/// (UEFI 2.10 Appendix A, Table A.2; uefi-guid-text.md §1.2): wire octets
/// 0-3, 4-5 and 6-7 are each reversed (TimeLow, TimeMid,
/// TimeHighAndVersion are little-endian), and octets 8-15 are kept in
/// order. Output is lowercase; input accepts either case (§2). Braces and
/// `urn:uuid:` prefixes are not accepted. Relay logs and the suppression
/// file both use this form, so an operator copying a GUID from a log always
/// gets a matching entry.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Guid([u8; 16]);

impl Guid {
    /// Wraps 16 octets in wire order (as carried after the type octet of
    /// option 97).
    #[must_use]
    pub fn from_wire(octets: [u8; 16]) -> Self {
        Self(octets)
    }

    /// The 16 octets in wire order.
    #[must_use]
    pub fn wire_octets(&self) -> [u8; 16] {
        self.0
    }

    /// Swaps between wire order and text (big-endian field) order. The
    /// permutation is its own inverse.
    fn swap_fields(o: [u8; 16]) -> [u8; 16] {
        let [
            a0,
            a1,
            a2,
            a3,
            b0,
            b1,
            c0,
            c1,
            d0,
            d1,
            d2,
            d3,
            d4,
            d5,
            d6,
            d7,
        ] = o;
        [
            a3, a2, a1, a0, b1, b0, c1, c0, d0, d1, d2, d3, d4, d5, d6, d7,
        ]
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, byte) in Self::swap_fields(self.0).iter().enumerate() {
            if matches!(i, 4 | 6 | 8 | 10) {
                f.write_str("-")?;
            }
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Guid({self})")
    }
}

impl FromStr for Guid {
    type Err = IdentError;

    /// Parses the 36-character text form (hex digits in either case).
    fn from_str(s: &str) -> Result<Self, IdentError> {
        let b = s.as_bytes();
        if b.len() != 36 {
            return Err(IdentError::Syntax);
        }
        let mut text = [0u8; 16];
        let mut nibbles = 0usize;
        for (pos, &c) in b.iter().enumerate() {
            if matches!(pos, 8 | 13 | 18 | 23) {
                if c != b'-' {
                    return Err(IdentError::Syntax);
                }
                continue;
            }
            let v = hex_val(c).ok_or(IdentError::Syntax)?;
            let slot = text.get_mut(nibbles / 2).ok_or(IdentError::Syntax)?;
            *slot = (*slot << 4) | v;
            nibbles += 1;
        }
        if nibbles != 32 {
            return Err(IdentError::Syntax);
        }
        Ok(Self(Self::swap_fields(text)))
    }
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// A client system architecture type from option 93 (RFC 4578 §2.1, IANA
/// Processor Architecture Types registry).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ClientArch(pub u16);

impl ClientArch {
    /// x64 (x86-64) UEFI: type 7 (RFC 4578 §2.1 as corrected by erratum
    /// 4624; IANA registry).
    pub const X64_UEFI: Self = Self(7);

    /// Architectures this release can serve (decision 0004: UEFI x86-64
    /// only in M1).
    pub const SUPPORTED: [Self; 1] = [Self::X64_UEFI];

    /// Whether this release can serve the architecture.
    #[must_use]
    pub fn is_supported(self) -> bool {
        Self::SUPPORTED.contains(&self)
    }

    /// The 16-bit value in network byte order.
    #[must_use]
    pub fn to_be_bytes(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

impl fmt::Display for ClientArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The architecture list from option 93: one or more 16-bit types.
///
/// Built only by the parser, which guarantees an even length. Holds the
/// reassembled value (RFC 3396), borrowed when the option was not split.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ArchList<'a>(Cow<'a, [u8]>);

impl<'a> ArchList<'a> {
    /// An empty list (option 93 absent).
    pub const EMPTY: ArchList<'static> = ArchList(Cow::Borrowed(&[]));

    /// Wraps option 93 data whose length the caller has checked is even.
    pub(crate) fn from_checked(data: impl Into<Cow<'a, [u8]>>) -> Self {
        Self(data.into())
    }

    /// Architectures in the order the client listed them.
    pub fn iter(&self) -> impl Iterator<Item = ClientArch> + '_ {
        let (pairs, _odd) = self.0.as_chunks::<2>();
        pairs
            .iter()
            .map(|&pair| ClientArch(u16::from_be_bytes(pair)))
    }

    /// Whether the client listed `arch`.
    #[must_use]
    pub fn contains(&self, arch: ClientArch) -> bool {
        self.iter().any(|a| a == arch)
    }

    /// Whether the list is empty (option 93 absent).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len() / 2
    }

    /// First listed architecture this release supports.
    #[must_use]
    pub fn first_supported(&self) -> Option<ClientArch> {
        self.iter().find(|a| a.is_supported())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_parse_display_roundtrip() {
        let m: MacAddr = "52:54:00:AB:cd:0f".parse().unwrap();
        assert_eq!(m.octets(), [0x52, 0x54, 0x00, 0xab, 0xcd, 0x0f]);
        assert_eq!(m.to_string(), "52:54:00:ab:cd:0f");
        assert_eq!(m.to_string().parse::<MacAddr>(), Ok(m));
    }

    #[test]
    fn mac_parse_rejects_multicast() {
        assert_eq!(
            "01:00:5e:00:00:01".parse::<MacAddr>(),
            Err(IdentError::Multicast)
        );
        assert_eq!(
            "ff:ff:ff:ff:ff:ff".parse::<MacAddr>(),
            Err(IdentError::Multicast)
        );
        assert_eq!(
            MacAddr::new([0x03, 0, 0, 0, 0, 1]),
            Err(IdentError::Multicast)
        );
    }

    #[test]
    fn mac_parse_rejects_zero_and_bad_syntax() {
        assert_eq!(
            "00:00:00:00:00:00".parse::<MacAddr>(),
            Err(IdentError::Zero)
        );
        for bad in [
            "",
            "52:54:00:12:34",
            "52:54:00:12:34:567",
            "52-54-00-12-34-56",
            "52:54:00:12:34:5g",
            "5254.0012.3456....",
            "52:54:00:12:34:56 ",
            "\u{e9}2:54:00:12:34:56",
        ] {
            assert_eq!(bad.parse::<MacAddr>(), Err(IdentError::Syntax), "{bad:?}");
        }
    }

    #[test]
    fn guid_parse_display_roundtrip() {
        // Wire order as carried in option 97 after the type octet.
        let wire = [
            0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let g = Guid::from_wire(wire);
        assert_eq!(g.to_string(), "00112233-4455-6677-8899-aabbccddeeff");
        let back: Guid = "00112233-4455-6677-8899-AABBCCDDEEFF".parse().unwrap();
        assert_eq!(back, g);
        assert_eq!(back.wire_octets(), wire);
    }

    #[test]
    fn guid_standards_worked_example() {
        // uefi-guid-text.md §1.3 / §3: UEFI byte order of the example text.
        let wire = [
            0x67, 0x45, 0x23, 0x01, 0xab, 0x89, 0xef, 0xcd, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let text = "01234567-89ab-cdef-fedc-ba9876543210";
        assert_eq!(Guid::from_wire(wire).to_string(), text);
        assert_eq!(text.parse::<Guid>().map(|g| g.wire_octets()), Ok(wire));
        assert_eq!(
            "01234567-89AB-CDEF-FEDC-BA9876543210".parse::<Guid>(),
            text.parse::<Guid>()
        );
    }

    #[test]
    fn guid_parse_rejects_bad_forms() {
        for bad in [
            "",
            "00112233-4455-6677-8899-aabbccddeef",
            "00112233-4455-6677-8899-aabbccddeeff0",
            "001122334455-6677-8899-aabbccddeeff-",
            "00112233_4455_6677_8899_aabbccddeeff",
            "0011223g-4455-6677-8899-aabbccddeeff",
            "{0112233-4455-6677-8899-aabbccddeef}",
            "{00112233-4455-6677-8899-aabbccddeeff}",
            "urn:uuid:00112233-4455-6677-8899-aabbccddeeff",
        ] {
            assert_eq!(bad.parse::<Guid>(), Err(IdentError::Syntax), "{bad:?}");
        }
    }

    #[test]
    fn arch_list_iteration() {
        let data = [0, 0, 0, 7, 0, 9];
        let l = ArchList::from_checked(&data[..]);
        assert_eq!(l.len(), 3);
        assert!(l.contains(ClientArch::X64_UEFI));
        assert_eq!(l.first_supported(), Some(ClientArch::X64_UEFI));
        assert!(ArchList::EMPTY.is_empty());
        assert_eq!(ArchList::EMPTY.first_supported(), None);
        assert!(!ArchList::from_checked(&[0u8, 0][..]).contains(ClientArch::X64_UEFI));
    }

    #[test]
    fn only_x64_uefi_supported_in_m1() {
        assert!(ClientArch(7).is_supported());
        for v in [0u16, 6, 9, 10, 11, 15, 16, 0xffff] {
            assert!(!ClientArch(v).is_supported());
        }
    }
}
