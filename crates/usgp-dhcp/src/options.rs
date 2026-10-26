//! DHCP option codes, the bounds-checked option walker, and the policy for
//! repeated options.
//!
//! Encoding (RFC 2132 §2): code octet, length octet, `length` data octets.
//! Pad (0) and End (255) are single octets.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation)
// - SPEC: specs/boot-network.md#REQ-BOOT-006
// - RFC 2132 §2 - option encoding; §3.1/§3.2 - Pad and End

use std::borrow::Cow;

use crate::error::ParseError;

/// Option codes used by this crate (RFC 2132, RFC 3046, RFC 4578).
pub mod code {
    /// Pad (RFC 2132 §3.1).
    pub const PAD: u8 = 0;
    /// Subnet mask (RFC 2132 §3.3). Never sent by this crate.
    pub const SUBNET_MASK: u8 = 1;
    /// Router (RFC 2132 §3.5). Never sent by this crate.
    pub const ROUTER: u8 = 3;
    /// Vendor-specific information (RFC 2132 §8.4).
    pub const VENDOR_SPECIFIC: u8 = 43;
    /// IP address lease time (RFC 2132 §9.2). Never sent by this crate.
    pub const LEASE_TIME: u8 = 51;
    /// Option overload (RFC 2132 §9.3).
    pub const OVERLOAD: u8 = 52;
    /// DHCP message type (RFC 2132 §9.6).
    pub const MESSAGE_TYPE: u8 = 53;
    /// Server identifier (RFC 2132 §9.7).
    pub const SERVER_ID: u8 = 54;
    /// Maximum DHCP message size (RFC 2132 §9.10).
    pub const MAX_MESSAGE_SIZE: u8 = 57;
    /// Renewal (T1) time. Lease timing; never sent by this crate.
    pub const RENEWAL_TIME: u8 = 58;
    /// Rebinding (T2) time. Lease timing; never sent by this crate.
    pub const REBINDING_TIME: u8 = 59;
    /// Vendor class identifier (RFC 2132 §9.13).
    pub const VENDOR_CLASS: u8 = 60;
    /// Client identifier (RFC 2132 §9.14).
    pub const CLIENT_ID: u8 = 61;
    /// Relay agent information (RFC 3046).
    pub const RELAY_AGENT_INFO: u8 = 82;
    /// Client system architecture (RFC 4578 §2.1).
    pub const CLIENT_ARCH: u8 = 93;
    /// Client network interface identifier (RFC 4578 §2.2).
    pub const CLIENT_NDI: u8 = 94;
    /// Client machine identifier (RFC 4578 §2.3).
    pub const CLIENT_MACHINE_ID: u8 = 97;
    /// End (RFC 2132 §3.2).
    pub const END: u8 = 255;

    /// PXE sub-option inside option 43: boot item (draft-henry §3.2.3).
    pub const PXE_BOOT_ITEM: u8 = 71;
}

/// Whether an options area must be closed by End.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EndRule {
    /// The main options field: End is required (RFC 2131 §2 framing; a
    /// field that just stops is treated as truncated).
    Required,
    /// A fixed-size area (`file`, `sname`, or the data of option 43): the
    /// area boundary also ends the walk.
    ///
    /// Project choice: the standards summaries do not say whether an
    /// overloaded `file`/`sname` field must carry End, so the field's fixed
    /// size is accepted as its end. Overruns are still malformed.
    Optional,
}

/// Walks one options area, calling `visit(code, data)` for every option
/// other than Pad, in order, until End or the end of the area.
///
/// Bytes after End are ignored (they are padding). Never panics: every
/// length is checked against the remaining area before use.
pub(crate) fn walk<'a>(
    mut area: &'a [u8],
    end_rule: EndRule,
    mut visit: impl FnMut(u8, &'a [u8]) -> Result<(), ParseError>,
) -> Result<(), ParseError> {
    loop {
        let Some((&code, rest)) = area.split_first() else {
            return match end_rule {
                EndRule::Required => Err(ParseError::MissingEnd),
                EndRule::Optional => Ok(()),
            };
        };
        match code {
            code::PAD => area = rest,
            code::END => return Ok(()),
            _ => {
                let Some((&len, rest)) = rest.split_first() else {
                    return Err(ParseError::OptionTruncated { code });
                };
                let Some((data, rest)) = rest.split_at_checked(usize::from(len)) else {
                    return Err(ParseError::OptionTruncated { code });
                };
                visit(code, data)?;
                area = rest;
            }
        }
    }
}

/// Option codes this crate interprets or echoes. Pieces of these codes are
/// kept for reassembly; every other option is skipped by length (RFC 2132
/// §2; dhcp-long-options.md §7).
pub const INTERPRETED_OPTIONS: [u8; 11] = [
    code::VENDOR_SPECIFIC,
    code::OVERLOAD,
    code::MESSAGE_TYPE,
    code::SERVER_ID,
    code::MAX_MESSAGE_SIZE,
    code::VENDOR_CLASS,
    code::CLIENT_ID,
    code::RELAY_AGENT_INFO,
    code::CLIENT_ARCH,
    code::CLIENT_NDI,
    code::CLIENT_MACHINE_ID,
];

/// Option pieces collected from the aggregate option buffer, in buffer
/// order: the `options` field, then `file`, then `sname` (RFC 3396 §5).
///
/// Only [`INTERPRETED_OPTIONS`] codes are kept. The number of pieces is
/// bounded by the message size (at most 1472 octets, two octets per
/// piece), so memory stays bounded.
#[derive(Debug, Default)]
pub(crate) struct Pieces<'a>(Vec<(u8, &'a [u8])>);

impl<'a> Pieces<'a> {
    /// Records one option instance if its code is interpreted.
    pub(crate) fn push(&mut self, code: u8, data: &'a [u8]) {
        if INTERPRETED_OPTIONS.contains(&code) {
            self.0.push((code, data));
        }
    }

    /// RFC 3396 POLICY POINT: the reassembled value of `code`.
    ///
    /// RFC 3396 §4/§7 (dhcp-long-options.md §3): every repeated code is a
    /// split option; the receiver joins the pieces' data in aggregate-buffer
    /// order and interprets only the joined value, whose length is the sum
    /// of the pieces and may exceed 255 octets. Split points carry no
    /// meaning. Per-option length rules are applied by the caller to the
    /// joined value. A single piece is borrowed, several are copied once.
    ///
    /// Returns `None` if the code did not occur.
    pub(crate) fn joined(&self, code: u8) -> Option<Cow<'a, [u8]>> {
        let mut it = self.0.iter().filter(|(c, _)| *c == code).map(|(_, d)| *d);
        let first = it.next()?;
        let Some(second) = it.next() else {
            return Some(Cow::Borrowed(first));
        };
        let mut v = Vec::with_capacity(first.len() + second.len());
        v.extend_from_slice(first);
        v.extend_from_slice(second);
        for piece in it {
            v.extend_from_slice(piece);
        }
        Some(Cow::Owned(v))
    }
}

/// Fixed-size set of option codes (one bit per code).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OptionSet([u64; 4]);

impl OptionSet {
    /// Adds `code`; returns `true` if it was already present.
    pub fn insert(&mut self, code: u8) -> bool {
        let (word, bit) = Self::locate(code);
        match self.0.get_mut(word) {
            Some(w) => {
                let was = *w & bit != 0;
                *w |= bit;
                was
            }
            None => false,
        }
    }

    /// Whether `code` is present.
    #[must_use]
    pub fn contains(&self, code: u8) -> bool {
        let (word, bit) = Self::locate(code);
        self.0.get(word).is_some_and(|w| w & bit != 0)
    }

    fn locate(code: u8) -> (usize, u64) {
        (usize::from(code >> 6), 1u64 << (code & 63))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect(area: &[u8], rule: EndRule) -> Result<Vec<(u8, Vec<u8>)>, ParseError> {
        let mut out = Vec::new();
        walk(area, rule, |c, d| {
            out.push((c, d.to_vec()));
            Ok(())
        })?;
        Ok(out)
    }

    #[test]
    fn walk_skips_pad_and_stops_at_end() {
        let area = [0, 0, 53, 1, 1, 0, 255, 99, 99];
        assert_eq!(collect(&area, EndRule::Required), Ok(vec![(53, vec![1])]));
    }

    #[test]
    fn walk_requires_end_in_main_area() {
        assert_eq!(
            collect(&[53, 1, 1], EndRule::Required),
            Err(ParseError::MissingEnd)
        );
        assert_eq!(
            collect(&[0, 0, 0], EndRule::Required),
            Err(ParseError::MissingEnd)
        );
        assert_eq!(
            collect(&[53, 1, 1], EndRule::Optional),
            Ok(vec![(53, vec![1])])
        );
    }

    #[test]
    fn walk_code_at_last_byte_is_truncated() {
        assert_eq!(
            collect(&[53], EndRule::Optional),
            Err(ParseError::OptionTruncated { code: 53 })
        );
    }

    #[test]
    fn walk_length_past_end_is_truncated() {
        assert_eq!(
            collect(&[60, 9, b'P', b'X'], EndRule::Optional),
            Err(ParseError::OptionTruncated { code: 60 })
        );
    }

    #[test]
    fn zero_length_option_is_visited() {
        assert_eq!(
            collect(&[60, 0, 255], EndRule::Required),
            Ok(vec![(60, vec![])])
        );
    }

    #[test]
    fn pieces_join_in_order() {
        let mut p = Pieces::default();
        p.push(60, b"PXE");
        p.push(55, b"\x01");
        p.push(60, b"");
        p.push(60, b"Client");
        assert_eq!(p.joined(60).as_deref(), Some(&b"PXEClient"[..]));
        assert_eq!(p.joined(55), None, "uninterpreted codes are not kept");
        assert_eq!(p.joined(93), None);
        p.push(93, &[0, 7]);
        assert!(matches!(p.joined(93), Some(Cow::Borrowed(_))));
    }

    #[test]
    fn joined_value_may_exceed_255() {
        let a = [1u8; 255];
        let b = [2u8; 100];
        let mut p = Pieces::default();
        p.push(82, &a);
        p.push(82, &b);
        assert_eq!(p.joined(82).map(|v| v.len()), Some(355));
    }

    #[test]
    fn option_set_insert_and_contains() {
        let mut s = OptionSet::default();
        for c in [0u8, 1, 63, 64, 127, 128, 200, 255] {
            assert!(!s.contains(c));
            assert!(!s.insert(c));
            assert!(s.insert(c));
            assert!(s.contains(c));
        }
        assert!(!s.contains(2));
    }
}
