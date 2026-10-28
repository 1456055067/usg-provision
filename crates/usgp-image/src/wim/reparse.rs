//! Reparse data of symbolic links and mount points (junctions): the
//! copy, re-base or refuse rule of decision 0022, and the typed apply root
//! it re-bases onto.
//!
//! Inputs (the rule's symbols): H, the header flags; T, the tag at entry
//! +88; M, the value at entry +92; B, the stored buffer (the reparse
//! `DataBuffer`, stored without the 8-byte header, OBS-036); A, the apply
//! root ([`ApplyRoot`]).
//!
//! 1. M = 0x00010000: B is copied unchanged, whatever H is, after the
//!    topic 24 §3 to §5 bounds and (symbolic links) Flags 0 or 1.
//! 2. M = 0: B is re-based onto A only if H has `RP_FIX`, T is a mount
//!    point or a symbolic link with Flags 0, B has the exact layout DISM
//!    writes, and both names are `\??\D:R` / `D:R` with the same upper-case
//!    D and a clean absolute R.
//! 3. Anything else is refused with a named [`ReparseError`].
//!
//! The output is always a whole `REPARSE_DATA_BUFFER` (topic 24 §2): the
//! 8-byte header rebuilt from T with `Reserved` 0, then the data.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - every offset and
//   length bounded; only observed combinations accepted.
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity) -
//   the product never writes a target that is not in the image, other
//   than the apply root substituted for the stored drive letter.
// - SPEC: specs/standards/reparse-and-security-descriptors.md §2 to §5
// - SPEC: specs/standards/wim.md §6.1, §13 (OPEN-WIM-12 [project rule])
// - DECISION: docs/decisions/0022-apply-rebases-rpfix-targets.md
// - FINDINGS: findings-boot-obs-r4.md "The re-base rule" (M-13)

use std::fmt;

use super::header::FLAG_RP_FIX;
use super::metadata::{REPARSE_FIELD_RELATIVE, tag};
use super::names::Component;

/// Largest reparse data, from the 16-bit `ReparseDataLength` (topic 24
/// §2, [derived]).
pub const MAX_REPARSE_DATA: usize = 65535;

/// Longest pathname in characters (topic 24 §5, [MS-FSCC] §2.1.5).
pub const MAX_PATH_CHARS: usize = 32760;

/// `SYMLINK_FLAG_RELATIVE` (topic 24 §4).
pub const SYMLINK_FLAG_RELATIVE: u32 = 1;

const BACKSLASH: u16 = 0x5C;
const COLON: u16 = 0x3A;
const DOT: u16 = 0x2E;
/// `\??\` (OBS-049: the full-path substitute name form).
const NT_PREFIX: [u16; 4] = [0x5C, 0x3F, 0x3F, 0x5C];

/// Why reparse data was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReparseError {
    /// The buffer breaks the topic 24 §3 to §5 bounds.
    Malformed {
        /// Which rule (fixed text).
        what: &'static str,
    },
    /// A symbolic link's Flags are neither 0 nor 1 (topic 24 §4).
    SymlinkFlags,
    /// A mount-point name holds a `.` or `..` component (topic 24 §5).
    MountPointDotName,
    /// M = 0 in a file without `RP_FIX` (never seen).
    RewrittenWithoutRpFix,
    /// M = 0 on a symbolic link with relative Flags (never seen).
    RebaseRelative,
    /// M = 0 with a layout other than DISM's (never seen).
    RebaseLayout,
    /// M = 0 with a target that is not `\??\D:R` / `D:R` as observed.
    RebaseTarget {
        /// Which rule (fixed text).
        what: &'static str,
    },
    /// The re-based buffer would exceed 65535 bytes or a name 32760
    /// characters.
    RebaseTooLong,
    /// A tag or +92 value outside the rule.
    Unsupported,
}

impl ReparseError {
    /// Every reason code.
    pub const REASON_CODES: &'static [&'static str] = &[
        "wim_reparse_malformed",
        "wim_reparse_symlink_flags",
        "wim_reparse_mount_point_dot_name",
        "wim_reparse_rewritten_without_rp_fix",
        "wim_reparse_rebase_relative",
        "wim_reparse_rebase_layout",
        "wim_reparse_rebase_target",
        "wim_reparse_rebase_too_long",
        "wim_reparse_unsupported",
    ];

    /// Stable machine-readable reason.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Malformed { .. } => "wim_reparse_malformed",
            Self::SymlinkFlags => "wim_reparse_symlink_flags",
            Self::MountPointDotName => "wim_reparse_mount_point_dot_name",
            Self::RewrittenWithoutRpFix => "wim_reparse_rewritten_without_rp_fix",
            Self::RebaseRelative => "wim_reparse_rebase_relative",
            Self::RebaseLayout => "wim_reparse_rebase_layout",
            Self::RebaseTarget { .. } => "wim_reparse_rebase_target",
            Self::RebaseTooLong => "wim_reparse_rebase_too_long",
            Self::Unsupported => "wim_reparse_unsupported",
        }
    }
}

impl fmt::Display for ReparseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed { what } => write!(f, "link or junction data is invalid ({what})"),
            Self::SymlinkFlags => f.write_str("symbolic link flags are not supported"),
            Self::MountPointDotName => f.write_str("junction target holds a dot component"),
            Self::RewrittenWithoutRpFix => f.write_str(
                "link or junction marked as rewritten in an image captured without the fix-up",
            ),
            Self::RebaseRelative => f.write_str("relative link marked as rewritten"),
            Self::RebaseLayout => {
                f.write_str("rewritten link or junction in an unsupported layout")
            }
            Self::RebaseTarget { what } => {
                write!(
                    f,
                    "rewritten link or junction target not supported ({what})"
                )
            }
            Self::RebaseTooLong => f.write_str("link or junction target too long after re-basing"),
            Self::Unsupported => f.write_str("link or junction form not supported"),
        }
    }
}

impl std::error::Error for ReparseError {}

/// Why an apply root was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplyRootError {
    /// Which rule (fixed text).
    pub what: &'static str,
}

impl ApplyRootError {
    /// Stable machine-readable reason.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        "apply_root_unsupported"
    }
}

impl fmt::Display for ApplyRootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "apply root not supported ({})", self.what)
    }
}

impl std::error::Error for ApplyRootError {}

/// The directory an image is applied to, as the Windows path that
/// re-based targets name: a drive-letter volume root (`L:`) or a
/// directory below one (`L:\c1\…\cn`).
///
/// UNC paths, `\\?\` paths and volume-GUID paths are refused by
/// [`ApplyRoot::parse`]. A root that is a mounted folder cannot be seen
/// from the text: the caller (the agent) must only pass a root on a
/// volume reached by its drive letter (findings R4, "Never seen").
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ApplyRoot {
    /// Upper-case drive letter.
    letter: u8,
    /// Components below the volume root.
    components: Vec<Component>,
}

impl fmt::Debug for ApplyRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ApplyRoot({:?})", self.to_text())
    }
}

impl ApplyRoot {
    /// Parses `L:`, `L:\` or `L:\c1\…\cn` (an optional trailing `\`),
    /// with `L` an upper-case `A`–`Z` and each component a valid name.
    ///
    /// # Errors
    ///
    /// [`ApplyRootError`] for UNC, `\\?\`, volume-GUID and any other form.
    // [project rule, findings R4]: normalise to `L:` or `L:\c1\…\cn`. A
    // lower-case letter is refused rather than folded (the rule refuses a
    // lower-case stored letter; folding is not specified).
    pub fn parse(text: &str) -> Result<Self, ApplyRootError> {
        let err = |what| ApplyRootError { what };
        if text.starts_with("\\\\") || text.starts_with("//") {
            return Err(err("UNC, \\\\?\\ or volume GUID path"));
        }
        let b = text.as_bytes();
        let (Some(&l), Some(&b':')) = (b.first(), b.get(1)) else {
            return Err(err("not a drive-letter path"));
        };
        if !l.is_ascii_uppercase() {
            return Err(err("drive letter must be A to Z"));
        }
        let rest = text.get(2..).unwrap_or("");
        let mut components = Vec::new();
        if !rest.is_empty() {
            let Some(body) = rest.strip_prefix('\\') else {
                return Err(err("drive-relative path"));
            };
            let body = body.strip_suffix('\\').unwrap_or(body);
            if !body.is_empty() {
                for c in body.split('\\') {
                    components.push(Component::new(c).map_err(|_| err("invalid component"))?);
                }
            }
        }
        Ok(Self {
            letter: l,
            components,
        })
    }

    /// The normalised text: `L:` or `L:\c1\…\cn`.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut s = String::new();
        s.push(char::from(self.letter));
        s.push(':');
        for c in &self.components {
            s.push('\\');
            s.push_str(c.as_str());
        }
        s
    }

    fn units(&self) -> Vec<u16> {
        self.to_text().encode_utf16().collect()
    }
}

/// A complete reparse buffer ready to set: header rebuilt from the tag,
/// then the data.
#[derive(Clone, PartialEq, Eq)]
pub struct ReparseBuffer {
    tag: u32,
    bytes: Vec<u8>,
    rebased: bool,
}

impl fmt::Debug for ReparseBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReparseBuffer")
            .field("tag", &format_args!("{:#010x}", self.tag))
            .field("len", &self.bytes.len())
            .field("rebased", &self.rebased)
            .finish()
    }
}

impl ReparseBuffer {
    /// The tag.
    #[must_use]
    pub fn tag(&self) -> u32 {
        self.tag
    }

    /// The whole `REPARSE_DATA_BUFFER` (topic 24 §2): tag, data length,
    /// zero `Reserved`, data. This is what `FSCTL_SET_REPARSE_POINT`
    /// takes (topic 24 §6).
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The data after the 8-byte header (what a WIM stores, OBS-036).
    #[must_use]
    pub fn data(&self) -> &[u8] {
        self.bytes.get(8..).unwrap_or(&[])
    }

    /// True if the targets were re-based onto the apply root.
    #[must_use]
    pub fn rebased(&self) -> bool {
        self.rebased
    }

    fn with_header(tag: u32, data: &[u8], rebased: bool) -> Result<Self, ReparseError> {
        let len = u16::try_from(data.len()).map_err(|_| ReparseError::RebaseTooLong)?;
        let mut bytes = Vec::with_capacity(data.len().saturating_add(8));
        bytes.extend_from_slice(&tag.to_le_bytes());
        bytes.extend_from_slice(&len.to_le_bytes());
        bytes.extend_from_slice(&[0, 0]);
        bytes.extend_from_slice(data);
        Ok(Self {
            tag,
            bytes,
            rebased,
        })
    }
}

/// The parsed fields of a stored buffer (topic 24 §3, §4, without the
/// 8-byte header).
struct Parsed {
    sub_off: usize,
    sub_len: usize,
    print_off: usize,
    print_len: usize,
    flags: Option<u32>,
    path: Vec<u16>,
}

fn u16_at(b: &[u8], at: usize) -> Option<usize> {
    let s: [u8; 2] = b.get(at..at.checked_add(2)?)?.try_into().ok()?;
    Some(usize::from(u16::from_le_bytes(s)))
}

fn malformed(what: &'static str) -> ReparseError {
    ReparseError::Malformed { what }
}

/// Checks `b` against topic 24 §3 to §5 for tag `t`.
fn parse(t: u32, b: &[u8]) -> Result<Parsed, ReparseError> {
    if b.len() > MAX_REPARSE_DATA {
        return Err(malformed("longer than 65535 bytes"));
    }
    let head = match t {
        tag::SYMLINK => 12,
        tag::JUNCTION => 8,
        _ => return Err(ReparseError::Unsupported),
    };
    if b.len() < head {
        return Err(malformed("shorter than its fixed part"));
    }
    let field = |at| u16_at(b, at).ok_or(malformed("shorter than its fixed part"));
    let (sub_off, sub_len, print_off, print_len) = (field(0)?, field(2)?, field(4)?, field(6)?);
    let flags = if t == tag::SYMLINK {
        let f: [u8; 4] = b
            .get(8..12)
            .and_then(|s| s.try_into().ok())
            .ok_or(malformed("shorter than its fixed part"))?;
        Some(u32::from_le_bytes(f))
    } else {
        None
    };
    let raw = b.get(head..).unwrap_or(&[]);
    if !raw.len().is_multiple_of(2) {
        return Err(malformed("odd path buffer"));
    }
    for v in [sub_off, sub_len, print_off, print_len] {
        if !v.is_multiple_of(2) {
            return Err(malformed("odd offset or length"));
        }
    }
    for (o, l) in [(sub_off, sub_len), (print_off, print_len)] {
        if o.checked_add(l).is_none_or(|e| e > raw.len()) {
            return Err(malformed("name outside the path buffer"));
        }
        if l / 2 > MAX_PATH_CHARS {
            return Err(malformed("name longer than 32760 characters"));
        }
    }
    let (units, _) = raw.as_chunks::<2>();
    let path = units.iter().map(|u| u16::from_le_bytes(*u)).collect();
    Ok(Parsed {
        sub_off,
        sub_len,
        print_off,
        print_len,
        flags,
        path,
    })
}

impl Parsed {
    fn name(&self, off: usize, len: usize) -> &[u16] {
        self.path.get(off / 2..(off + len) / 2).unwrap_or(&[])
    }
    fn sub(&self) -> &[u16] {
        self.name(self.sub_off, self.sub_len)
    }
    fn print(&self) -> &[u16] {
        self.name(self.print_off, self.print_len)
    }
}

fn has_dot_component(name: &[u16]) -> bool {
    name.split(|&u| u == BACKSLASH)
        .any(|c| c == [DOT] || c == [DOT, DOT])
}

/// Applies the decision 0022 rule to one entry's stored data.
///
/// `header_flags` is H, `t` the tag at +88, `m` the value at +92, `b` the
/// stored data, `root` the apply root.
///
/// # Errors
///
/// A named [`ReparseError`] for every combination outside the rule.
pub fn prepare(
    header_flags: u32,
    t: u32,
    m: u32,
    b: &[u8],
    root: &ApplyRoot,
) -> Result<ReparseBuffer, ReparseError> {
    let p = parse(t, b)?;
    if let Some(f) = p.flags
        && f != 0
        && f != SYMLINK_FLAG_RELATIVE
    {
        return Err(ReparseError::SymlinkFlags);
    }
    if t == tag::JUNCTION && (has_dot_component(p.sub()) || has_dot_component(p.print())) {
        return Err(ReparseError::MountPointDotName);
    }
    match m {
        // FORMAT: OBS-051, OBS-052 - M = 0x00010000 on every entry DISM
        // stored unchanged; its apply copied them byte for byte.
        REPARSE_FIELD_RELATIVE => ReparseBuffer::with_header(t, b, false),
        // FORMAT: OBS-049, OBS-050, OBS-052 - M = 0 exactly on in-tree
        // absolute targets rewritten with RP_FIX; DISM's apply re-based
        // both names onto the apply root (8 of 8 byte-exact).
        0 => rebase(header_flags, t, &p, root),
        _ => Err(ReparseError::Unsupported),
    }
}

/// Splits `\??\D:R` (substitute) or `D:R` (print) into (D, R).
fn drive_and_rest(name: &[u16], nt: bool) -> Result<(u16, &[u16]), ReparseError> {
    let target = |what| ReparseError::RebaseTarget { what };
    let body = if nt {
        name.strip_prefix(&NT_PREFIX[..])
            .ok_or(target("substitute name lacks the \\??\\ prefix"))?
    } else {
        name
    };
    let (d, rest) = match body {
        [d, c, rest @ ..] if *c == COLON => (*d, rest),
        _ => return Err(target("no drive letter")),
    };
    // (d) D is A to Z.
    if !(0x41..=0x5A).contains(&d) {
        return Err(target("drive letter not A to Z"));
    }
    Ok((d, rest))
}

fn rebase(h: u32, t: u32, p: &Parsed, root: &ApplyRoot) -> Result<ReparseBuffer, ReparseError> {
    // (a) RP_FIX set.
    if h & FLAG_RP_FIX == 0 {
        return Err(ReparseError::RewrittenWithoutRpFix);
    }
    // (b) a mount point, or a symbolic link with Flags 0.
    if p.flags.is_some_and(|f| f != 0) {
        return Err(ReparseError::RebaseRelative);
    }
    // (c) the exact layout: substitute at 0, print at SubLen + 2, a 2-byte
    // zero after each, nothing else.
    let end = p
        .sub_len
        .checked_add(2)
        .and_then(|v| v.checked_add(p.print_len))
        .and_then(|v| v.checked_add(2));
    let zero_after = |off: usize, len: usize| p.path.get((off + len) / 2) == Some(&0);
    if p.sub_off != 0
        || p.print_off != p.sub_len.saturating_add(2)
        || end != Some(p.path.len().saturating_mul(2))
        || !zero_after(p.sub_off, p.sub_len)
        || !zero_after(p.print_off, p.print_len)
    {
        return Err(ReparseError::RebaseLayout);
    }
    // (d) `\??\D:R` and `D:R`, same D and R.
    let (d1, r1) = drive_and_rest(p.sub(), true)?;
    let (d2, r2) = drive_and_rest(p.print(), false)?;
    let target = |what| ReparseError::RebaseTarget { what };
    if d1 != d2 || r1 != r2 {
        return Err(target("print name differs from the substitute"));
    }
    if r1.first() != Some(&BACKSLASH) || r1.len() < 2 {
        return Err(target("not an absolute path below the root"));
    }
    let comps = r1.get(1..).unwrap_or(&[]);
    if comps.contains(&0) {
        return Err(target("NUL in the path"));
    }
    for c in comps.split(|&u| u == BACKSLASH) {
        if c.is_empty() || c == [DOT] || c == [DOT, DOT] {
            return Err(target("empty or dot component"));
        }
    }

    // Output: A + R, the stored D discarded; layout (c); Flags 0.
    let mut print: Vec<u16> = root.units();
    print.extend_from_slice(r1);
    let mut sub: Vec<u16> = NT_PREFIX.to_vec();
    sub.extend_from_slice(&print);
    if sub.len() > MAX_PATH_CHARS || print.len() > MAX_PATH_CHARS {
        return Err(ReparseError::RebaseTooLong);
    }
    let sub_bytes = sub.len().saturating_mul(2);
    let print_bytes = print.len().saturating_mul(2);
    let too_long = |_| ReparseError::RebaseTooLong;
    let mut data = Vec::new();
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&u16::try_from(sub_bytes).map_err(too_long)?.to_le_bytes());
    data.extend_from_slice(
        &u16::try_from(sub_bytes.saturating_add(2))
            .map_err(too_long)?
            .to_le_bytes(),
    );
    data.extend_from_slice(&u16::try_from(print_bytes).map_err(too_long)?.to_le_bytes());
    if t == tag::SYMLINK {
        data.extend_from_slice(&0u32.to_le_bytes());
    }
    for u in sub
        .iter()
        .chain([0u16].iter())
        .chain(print.iter())
        .chain([0u16].iter())
    {
        data.extend_from_slice(&u.to_le_bytes());
    }
    if data.len() > MAX_REPARSE_DATA {
        return Err(ReparseError::RebaseTooLong);
    }
    ReparseBuffer::with_header(t, &data, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_roots() {
        for (t, n) in [
            ("S:", "S:"),
            ("S:\\", "S:"),
            ("U:\\deep\\apply-here", "U:\\deep\\apply-here"),
            ("U:\\deep\\apply-here\\", "U:\\deep\\apply-here"),
        ] {
            assert_eq!(
                ApplyRoot::parse(t).map(|r| r.to_text()).ok().as_deref(),
                Some(n)
            );
        }
        for bad in [
            "\\\\server\\share",
            "\\\\?\\C:\\x",
            "\\\\?\\Volume{01234567-89ab-cdef-0123-456789abcdef}\\",
            "s:\\",
            "S",
            "S:x",
            "S:\\a\\\\b",
            "S:\\..",
            "1:\\",
            "",
        ] {
            assert!(ApplyRoot::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn codes_are_one_to_one() {
        let all = [
            ReparseError::Malformed { what: "x" },
            ReparseError::SymlinkFlags,
            ReparseError::MountPointDotName,
            ReparseError::RewrittenWithoutRpFix,
            ReparseError::RebaseRelative,
            ReparseError::RebaseLayout,
            ReparseError::RebaseTarget { what: "x" },
            ReparseError::RebaseTooLong,
            ReparseError::Unsupported,
        ];
        let codes: Vec<_> = all.iter().map(ReparseError::reason_code).collect();
        assert_eq!(codes, ReparseError::REASON_CODES);
    }
}
