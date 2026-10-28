//! Request-name normalisation and case-insensitive matching (M3 plan §1,
//! relay changes, Request names).
//!
//! Microsoft's boot manager names files with backslashes and a leading
//! separator (`specs/standards/winpe-network-boot.md` §5), while published
//! names use `/` and no leading separator. So, in order:
//!
//! 1. every `\` becomes `/`;
//! 2. one leading `/` is dropped;
//! 3. the result must pass the same allow-list as a published boot file
//!    name: 1 to 127 bytes of ASCII `A-Z a-z 0-9 . _ -` and `/`, no
//!    leading `/`, no empty component, no `.` or `..` component;
//! 4. it is then compared with published names ASCII case-insensitively.
//!
//! A normalised name is only ever compared with published names; it is
//! never used to build a path (REQ-BOOT-041). Traversal forms (`..`, `.`,
//! absolute or drive-qualified names, `//`, percent-escapes, non-ASCII)
//! are refused by step 3 before any comparison. Published names that
//! collide case-insensitively make the comparison ambiguous; the caller
//! refuses such a manifest ([`case_insensitive_collision`]).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - allow-list of bytes
//   and components after normalisation.
// - NIST 800-53: AC-3 (Access Enforcement) - names are matched against the
//   published set only; traversal names cannot be represented.
// - SPEC: specs/boot-network.md#REQ-BOOT-041, #REQ-BOOT-063
// - SPEC: specs/standards/winpe-network-boot.md §5 (backslash paths)
// - RFC 1123 §4.2.3.4 - control over the paths that can be accessed

/// Longest normalised name in bytes (the published-name limit).
pub const MAX_REQUEST_NAME_LEN: usize = 127;

/// Why a request name cannot match any published name. Variants carry
/// positions and lengths only, never name bytes, so a client-chosen name
/// cannot reach a log through this error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NameRefusal {
    /// Nothing left after normalisation.
    #[error("request name is empty")]
    Empty,
    /// Longer than [`MAX_REQUEST_NAME_LEN`] after normalisation.
    #[error("request name is {len} bytes; the limit is 127")]
    TooLong {
        /// Length in bytes after normalisation.
        len: usize,
    },
    /// A byte outside the allow-list.
    #[error("request name has a disallowed byte at offset {offset}")]
    InvalidByte {
        /// Offset of the first disallowed byte after normalisation.
        offset: usize,
    },
    /// More than one leading separator.
    #[error("request name is absolute")]
    LeadingSlash,
    /// An empty component (`//` or a trailing separator).
    #[error("request name has an empty path component")]
    EmptyComponent,
    /// A `.` or `..` component.
    #[error("request name has a '.' or '..' component")]
    DotComponent,
}

impl NameRefusal {
    /// Stable, low-cardinality label for drop counters and audit events.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::TooLong { .. } => "too_long",
            Self::InvalidByte { .. } => "invalid_byte",
            Self::LeadingSlash => "leading_slash",
            Self::EmptyComponent => "empty_component",
            Self::DotComponent => "dot_component",
        }
    }
}

/// A normalised request name (case preserved). Only ever compared with
/// published names, never used as a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestName(String);

impl RequestName {
    /// The normalised name, case preserved.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The normalised name as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Whether `published` names the same file (ASCII case-insensitive,
    /// byte for byte otherwise).
    #[must_use]
    pub fn matches(&self, published: &[u8]) -> bool {
        self.0.as_bytes().eq_ignore_ascii_case(published)
    }
}

fn allowed(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/')
}

/// Normalises the filename of a read request (see the module docs).
///
/// # Errors
///
/// [`NameRefusal`] when the normalised name could never be a published
/// name; the caller answers as for any unpublished name.
pub fn normalize_request_name(raw: &[u8]) -> Result<RequestName, NameRefusal> {
    // RRQ names are at most 512 octets (RFC 2347), but check before
    // copying so the work is bounded whatever the caller passes.
    if raw.len() > MAX_REQUEST_NAME_LEN.saturating_add(1) {
        return Err(NameRefusal::TooLong { len: raw.len() });
    }
    let mut bytes: Vec<u8> = raw
        .iter()
        .map(|&b| if b == b'\\' { b'/' } else { b })
        .collect();
    if bytes.first() == Some(&b'/') {
        bytes.remove(0);
    }
    if bytes.is_empty() {
        return Err(NameRefusal::Empty);
    }
    if bytes.len() > MAX_REQUEST_NAME_LEN {
        return Err(NameRefusal::TooLong { len: bytes.len() });
    }
    if let Some(offset) = bytes.iter().position(|&b| !allowed(b)) {
        return Err(NameRefusal::InvalidByte { offset });
    }
    if bytes.first() == Some(&b'/') {
        return Err(NameRefusal::LeadingSlash);
    }
    for component in bytes.split(|&b| b == b'/') {
        match component {
            [] => return Err(NameRefusal::EmptyComponent),
            b"." | b".." => return Err(NameRefusal::DotComponent),
            _ => {}
        }
    }
    // Every byte is ASCII (allow-list above), so this cannot fail.
    String::from_utf8(bytes)
        .map(RequestName)
        .map_err(|_| NameRefusal::InvalidByte { offset: 0 })
}

/// Positions `(i, j)`, `i < j`, of two names in `names` that are equal
/// ASCII case-insensitively, if any. A manifest with such a pair is
/// refused, because a case-insensitive request could match either.
#[must_use]
pub fn case_insensitive_collision<'a, I>(names: I) -> Option<(usize, usize)>
where
    I: IntoIterator<Item = &'a [u8]>,
{
    let mut keys: Vec<(Vec<u8>, usize)> = names
        .into_iter()
        .enumerate()
        .map(|(i, n)| (n.to_ascii_lowercase(), i))
        .collect();
    keys.sort();
    keys.windows(2).find_map(|w| match w {
        [(a, i), (b, j)] if a == b => Some((*i.min(j), *i.max(j))),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(raw: &[u8]) -> String {
        normalize_request_name(raw).unwrap().as_str().to_owned()
    }

    #[test]
    fn backslash_and_one_leading_separator() {
        assert_eq!(ok(b"\\Boot\\BCD"), "Boot/BCD");
        assert_eq!(ok(b"/Boot/BCD"), "Boot/BCD");
        assert_eq!(
            ok(b"Boot\\Fonts\\wgl4_boot.ttf"),
            "Boot/Fonts/wgl4_boot.ttf"
        );
        assert_eq!(ok(b"bootmgfw.efi"), "bootmgfw.efi");
        assert_eq!(ok(b"\\sources/boot.wim"), "sources/boot.wim");
    }

    #[test]
    fn traversal_and_odd_forms_refused() {
        use NameRefusal as R;
        let cases: [(&[u8], NameRefusal); 18] = [
            (b"", R::Empty),
            (b"/", R::Empty),
            (b"\\", R::Empty),
            (b"//x", R::LeadingSlash),
            (b"\\\\x", R::LeadingSlash),
            (b"\\/x", R::LeadingSlash),
            (b"../x", R::DotComponent),
            (b"\\..\\x", R::DotComponent),
            (b"a\\..\\..\\b", R::DotComponent),
            (b"./x", R::DotComponent),
            (b"a/.", R::DotComponent),
            (b"a//b", R::EmptyComponent),
            (b"a\\", R::EmptyComponent),
            (b"C:\\x", R::InvalidByte { offset: 1 }),
            (b"%2e%2e/x", R::InvalidByte { offset: 0 }),
            (b"a b", R::InvalidByte { offset: 1 }),
            ("caf\u{e9}".as_bytes(), R::InvalidByte { offset: 3 }),
            (b"a\x00b", R::InvalidByte { offset: 1 }),
        ];
        for (raw, want) in cases {
            assert_eq!(normalize_request_name(raw), Err(want), "{raw:?}");
        }
    }

    #[test]
    fn length_limits() {
        let max = vec![b'a'; 127];
        assert_eq!(ok(&max).len(), 127);
        let mut lead = b"\\".to_vec();
        lead.extend_from_slice(&max);
        assert_eq!(ok(&lead).len(), 127);
        assert_eq!(
            normalize_request_name(&[b'a'; 128]),
            Err(NameRefusal::TooLong { len: 128 })
        );
        assert_eq!(
            normalize_request_name(&[b'a'; 600]),
            Err(NameRefusal::TooLong { len: 600 })
        );
    }

    #[test]
    fn case_insensitive_match() {
        let n = normalize_request_name(b"\\BOOT\\bcd").unwrap();
        assert!(n.matches(b"Boot/BCD"));
        assert!(n.matches(b"boot/bcd"));
        assert!(!n.matches(b"Boot/BCD.bak"));
        assert!(!n.matches(b"Boot\\BCD"));
        assert!(!n.matches(b"/Boot/BCD"));
    }

    #[test]
    fn collisions_found() {
        let names: [&[u8]; 3] = [b"Boot/BCD", b"sources/boot.wim", b"boot/bcd"];
        assert_eq!(case_insensitive_collision(names), Some((0, 2)));
        let names: [&[u8]; 3] = [b"Boot/BCD", b"Boot/boot.sdi", b"bootmgfw.efi"];
        assert_eq!(case_insensitive_collision(names), None);
        assert_eq!(case_insensitive_collision(Vec::<&[u8]>::new()), None);
    }

    #[test]
    fn refusal_labels_are_distinct() {
        let all = [
            NameRefusal::Empty,
            NameRefusal::TooLong { len: 0 },
            NameRefusal::InvalidByte { offset: 0 },
            NameRefusal::LeadingSlash,
            NameRefusal::EmptyComponent,
            NameRefusal::DotComponent,
        ];
        let mut labels: Vec<_> = all.iter().map(NameRefusal::label).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), all.len());
    }
}
