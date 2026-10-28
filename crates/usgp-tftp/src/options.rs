//! RFC 2347 option lists and negotiation of `blksize` (RFC 2348), `tsize`
//! (RFC 2349) and `windowsize` (RFC 7440).
//!
//! Supported: `blksize`, `tsize`, and `windowsize` through
//! [`negotiate_window`] when the server's window limit is 2 or more.
//! Never acknowledged: `timeout` (keeps the adaptive RTO in control;
//! leaving it out is allowed by RFC 2349). [`negotiate`] is the M1
//! lock-step negotiation and never acknowledges `windowsize`. Unknown
//! options are ignored (RFC 2347).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation)
// - SPEC: specs/boot-network.md#REQ-BOOT-031, #REQ-BOOT-064
// - RFC 2347 - option framing, case-insensitive names, OACK content
// - RFC 2348 - blksize 8..=65464, server may answer with a smaller value
// - RFC 2349 - tsize 0 on read returns the file size
// - RFC 7440 §3 - windowsize 1..=65535, server may answer with a smaller
//   value

use crate::error::ParseError;
use crate::packet::{DEFAULT_BLOCK_SIZE, MAX_BLOCK_SIZE, MIN_BLOCK_SIZE, split_cstr};

/// A validated RFC 2347 option list: NUL-terminated name/value pairs with
/// non-empty, case-insensitively unique names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OptionList<'a>(&'a [u8]);

/// Parses the option area that follows the mode (or the OACK opcode).
///
/// The caller has already bounded the area to at most 512 octets, so the
/// quadratic duplicate check is bounded too.
///
/// # Errors
///
/// [`ParseError::OptionUnterminated`], [`ParseError::EmptyOptionName`],
/// [`ParseError::OptionWithoutValue`] or [`ParseError::DuplicateOption`].
pub(crate) fn parse_option_list(area: &[u8]) -> Result<OptionList<'_>, ParseError> {
    let mut rest = area;
    while !rest.is_empty() {
        let (name, r) = split_cstr(rest).ok_or(ParseError::OptionUnterminated)?;
        if name.is_empty() {
            return Err(ParseError::EmptyOptionName);
        }
        let (_value, r) = split_cstr(r).ok_or(ParseError::OptionWithoutValue)?;
        rest = r;
    }
    let list = OptionList(area);
    for (i, (name, _)) in list.iter().enumerate() {
        if list
            .iter()
            .skip(i + 1)
            .any(|(other, _)| other.eq_ignore_ascii_case(name))
        {
            return Err(ParseError::DuplicateOption);
        }
    }
    Ok(list)
}

impl<'a> OptionList<'a> {
    /// `(name, value)` pairs in request order.
    pub fn iter(&self) -> impl Iterator<Item = (&'a [u8], &'a [u8])> + 'a {
        let mut rest = self.0;
        core::iter::from_fn(move || {
            let (name, r) = split_cstr(rest)?;
            let (value, r) = split_cstr(r)?;
            rest = r;
            Some((name, value))
        })
    }

    /// Value of option `name` (case-insensitive).
    #[must_use]
    pub fn get(&self, name: &[u8]) -> Option<&'a [u8]> {
        self.iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    }

    /// Number of options.
    #[must_use]
    pub fn len(&self) -> usize {
        self.iter().count()
    }

    /// Whether there are no options.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Parses a non-empty ASCII decimal string into `u64`; `None` on any
/// non-digit or on overflow. Leading zeros are allowed.
#[must_use]
pub fn parse_decimal(v: &[u8]) -> Option<u64> {
    if v.is_empty() {
        return None;
    }
    v.iter().try_fold(0u64, |acc, &d| {
        if d.is_ascii_digit() {
            acc.checked_mul(10)?.checked_add(u64::from(d - b'0'))
        } else {
            None
        }
    })
}

/// Option names this server answers.
pub const BLKSIZE: &[u8] = b"blksize";
/// See [`BLKSIZE`].
pub const TSIZE: &[u8] = b"tsize";
/// See [`BLKSIZE`] (RFC 7440).
pub const WINDOWSIZE: &[u8] = b"windowsize";

/// Largest window this server ever grants. The window must stay far below
/// half of the 16-bit block-number space so that an ACK maps to exactly one
/// block of the window, even after the number wraps (plan §1, relay
/// changes). Project design, not product behaviour.
pub const MAX_WINDOW_SIZE: u16 = 64;

/// Largest `windowsize` value a client may ask for (RFC 7440 §3).
const MAX_WINDOWSIZE_OPTION: u64 = 65535;

/// The negotiated result of a read request's options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Negotiated {
    /// Block size in use (512 unless `blksize` was accepted).
    pub block_size: u16,
    /// Whether `blksize` goes in the OACK.
    pub blksize_acked: bool,
    /// File size to return in the OACK, if `tsize` was accepted.
    pub tsize: Option<u64>,
    /// Window size in use (1, lock-step, unless `windowsize` was
    /// accepted).
    pub window_size: u16,
    /// Whether `windowsize` goes in the OACK.
    pub windowsize_acked: bool,
}

impl Negotiated {
    /// Whether an OACK is needed (RFC 2347: none if no option accepted).
    #[must_use]
    pub fn needs_oack(&self) -> bool {
        self.blksize_acked || self.tsize.is_some() || self.windowsize_acked
    }

    /// The OACK `(name, value)` pairs: `blksize`, `tsize`, `windowsize`.
    #[must_use]
    pub fn oack_pairs(&self) -> Vec<(&'static [u8], Vec<u8>)> {
        let mut v = Vec::with_capacity(3);
        if self.blksize_acked {
            v.push((BLKSIZE, self.block_size.to_string().into_bytes()));
        }
        if let Some(t) = self.tsize {
            v.push((TSIZE, t.to_string().into_bytes()));
        }
        if self.windowsize_acked {
            v.push((WINDOWSIZE, self.window_size.to_string().into_bytes()));
        }
        v
    }
}

/// Negotiates `blksize` and `tsize` for a read of `file_len` octets.
///
/// - `blksize`: a decimal value in 8..=65464 is accepted and answered with
///   `min(value, max_block_size)`; anything else is ignored (RFC 2348).
/// - `tsize`: the value `0` is answered with `file_len`; any other value is
///   ignored (RFC 2349, read direction).
/// - every other option, including `timeout` and `windowsize`, is ignored.
///
/// This is the M1 lock-step negotiation; [`negotiate_window`] adds
/// `windowsize`.
#[must_use]
pub fn negotiate(opts: &OptionList<'_>, file_len: u64, max_block_size: u16) -> Negotiated {
    negotiate_window(opts, file_len, max_block_size, 1)
}

/// Negotiates `blksize`, `tsize` and `windowsize` for a read of `file_len`
/// octets.
///
/// `blksize` and `tsize` as in [`negotiate`]. `windowsize`: when
/// `max_window_size` is 2 or more, a decimal value in 1..=65535 is
/// accepted and answered with `min(value, max_window_size, 64)` (RFC 7440
/// §3: the server's value is never larger than the client's). A value of
/// 0, above 65535 or not decimal is ignored, so the transfer stays
/// lock-step. With `max_window_size` 0 or 1 the option is never
/// acknowledged (lock-step, as in M1).
#[must_use]
pub fn negotiate_window(
    opts: &OptionList<'_>,
    file_len: u64,
    max_block_size: u16,
    max_window_size: u16,
) -> Negotiated {
    let cap = max_block_size.clamp(MIN_BLOCK_SIZE, MAX_BLOCK_SIZE);
    let mut out = Negotiated {
        block_size: DEFAULT_BLOCK_SIZE,
        blksize_acked: false,
        tsize: None,
        window_size: 1,
        windowsize_acked: false,
    };
    if let Some(v) = opts.get(BLKSIZE).and_then(parse_decimal)
        && let Ok(v) = u16::try_from(v)
        && (MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&v)
    {
        out.block_size = v.min(cap);
        out.blksize_acked = true;
    }
    if opts.get(TSIZE).and_then(parse_decimal) == Some(0) {
        out.tsize = Some(file_len);
    }
    let window_cap = max_window_size.min(MAX_WINDOW_SIZE);
    if window_cap >= 2
        && let Some(v) = opts.get(WINDOWSIZE).and_then(parse_decimal)
        && (1..=MAX_WINDOWSIZE_OPTION).contains(&v)
        && let Ok(v) = u16::try_from(v)
    {
        out.window_size = v.min(window_cap);
        out.windowsize_acked = true;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(area: &[u8]) -> OptionList<'_> {
        parse_option_list(area).unwrap()
    }

    #[test]
    fn framing_rules() {
        assert_eq!(parse_option_list(b""), Ok(OptionList(b"")));
        assert_eq!(
            parse_option_list(b"blksize"),
            Err(ParseError::OptionUnterminated)
        );
        assert_eq!(
            parse_option_list(b"blksize\0"),
            Err(ParseError::OptionWithoutValue)
        );
        assert_eq!(
            parse_option_list(b"blksize\x00512"),
            Err(ParseError::OptionWithoutValue)
        );
        assert_eq!(
            parse_option_list(b"\x00512\x00"),
            Err(ParseError::EmptyOptionName)
        );
        assert_eq!(
            parse_option_list(b"blksize\x00512\x00BlkSize\x00512\x00"),
            Err(ParseError::DuplicateOption)
        );
        assert_eq!(list(b"x\x00\x00").get(b"x"), Some(&b""[..]));
    }

    #[test]
    fn decimal_parsing() {
        assert_eq!(parse_decimal(b"0"), Some(0));
        assert_eq!(parse_decimal(b"00512"), Some(512));
        assert_eq!(parse_decimal(b"18446744073709551615"), Some(u64::MAX));
        assert_eq!(parse_decimal(b"18446744073709551616"), None);
        assert_eq!(parse_decimal(b"99999999999999999999"), None);
        assert_eq!(parse_decimal(b""), None);
        assert_eq!(parse_decimal(b"12a"), None);
        assert_eq!(parse_decimal(b"-1"), None);
        assert_eq!(parse_decimal(b" 1"), None);
    }

    #[test]
    fn blksize_negotiation() {
        let n = negotiate(&list(b"blksize\x001428\x00"), 10, 1468);
        assert_eq!((n.block_size, n.blksize_acked), (1428, true));
        let n = negotiate(&list(b"BLKSIZE\x0065464\x00"), 10, 1468);
        assert_eq!((n.block_size, n.blksize_acked), (1468, true));
        let n = negotiate(&list(b"blksize\x008\x00"), 10, 1468);
        assert_eq!((n.block_size, n.blksize_acked), (8, true));
        for bad in [&b"7"[..], b"65465", b"abc", b"", b"99999999999999999999"] {
            let mut area = b"blksize\0".to_vec();
            area.extend_from_slice(bad);
            area.push(0);
            let n = negotiate(&list(&area), 10, 1468);
            assert_eq!((n.block_size, n.blksize_acked), (512, false), "{bad:?}");
        }
    }

    #[test]
    fn tsize_negotiation() {
        assert_eq!(
            negotiate(&list(b"tsize\x000\x00"), 5632, 1468).tsize,
            Some(5632)
        );
        assert_eq!(negotiate(&list(b"tsize\x005\x00"), 5632, 1468).tsize, None);
        assert_eq!(negotiate(&list(b"tsize\x00x\x00"), 5632, 1468).tsize, None);
    }

    #[test]
    fn timeout_and_unknown_not_acked() {
        let n = negotiate(
            &list(b"timeout\x005\x00windowsize\x004\x00foo\x00bar\x00"),
            1,
            1468,
        );
        assert!(!n.needs_oack());
        assert!(n.oack_pairs().is_empty());
    }

    #[test]
    fn windowsize_negotiation() {
        let n = negotiate_window(&list(b"windowsize\x004\x00"), 1, 1468, 8);
        assert_eq!((n.window_size, n.windowsize_acked), (4, true));
        assert!(n.needs_oack());
        let n = negotiate_window(&list(b"WindowSize\x0065535\x00"), 1, 1468, 8);
        assert_eq!((n.window_size, n.windowsize_acked), (8, true));
        let n = negotiate_window(&list(b"windowsize\x0065535\x00"), 1, 1468, 1000);
        assert_eq!((n.window_size, n.windowsize_acked), (MAX_WINDOW_SIZE, true));
        let n = negotiate_window(&list(b"windowsize\x001\x00"), 1, 1468, 8);
        assert_eq!((n.window_size, n.windowsize_acked), (1, true));
        for bad in [
            &b"0"[..],
            b"65536",
            b"x",
            b"",
            b"-1",
            b"99999999999999999999",
        ] {
            let mut area = b"windowsize\0".to_vec();
            area.extend_from_slice(bad);
            area.push(0);
            let n = negotiate_window(&list(&area), 1, 1468, 8);
            assert_eq!((n.window_size, n.windowsize_acked), (1, false), "{bad:?}");
            assert!(!n.needs_oack(), "{bad:?}");
        }
        // Lock-step limit: never acknowledged.
        for cap in [0, 1] {
            let n = negotiate_window(&list(b"windowsize\x004\x00"), 1, 1468, cap);
            assert_eq!((n.window_size, n.windowsize_acked), (1, false));
        }
    }

    #[test]
    fn oack_pairs_order() {
        let n = negotiate(&list(b"tsize\x000\x00blksize\x001468\x00"), 77, 1468);
        assert_eq!(
            n.oack_pairs(),
            vec![(BLKSIZE, b"1468".to_vec()), (TSIZE, b"77".to_vec())]
        );
        let n = negotiate_window(
            &list(b"windowsize\x004\x00tsize\x000\x00blksize\x001468\x00"),
            77,
            1468,
            8,
        );
        assert_eq!(
            n.oack_pairs(),
            vec![
                (BLKSIZE, b"1468".to_vec()),
                (TSIZE, b"77".to_vec()),
                (WINDOWSIZE, b"4".to_vec())
            ]
        );
    }
}
