//! Text form of the canonical tree manifest (plan M-20, §10.2), following
//! the column contract in `scripts/wim-samples/README.md`: UTF-8, LF,
//! tab-separated, header first, rows sorted by path in UTF-16 code-unit
//! (ordinal) order, `-` for not applicable or not read, and
//! `error: <message>` for a value that could not be read.

// COMPLIANCE MAPPING:
// - NIST 800-53: SA-11 (Developer Testing and Evaluation)
// - SPEC: specs/preinstall-env.md REQ-PE-017 (apply fidelity oracle)

/// The header row.
pub const HEADER: &str = "path\ttype\tattributes\tcreation\tlast-access\tlast-write\tlength\tsha256\tstreams\tsddl\tlink-target\thard-links\treparse-tag";

/// A column value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Field {
    /// Not applicable or not read (`-`).
    None,
    /// A value. Tabs and line breaks become spaces; an empty value is `-`.
    Value(String),
    /// A value that could not be read.
    Error(String),
}

fn clean(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_break = false;
    for c in s.chars() {
        if matches!(c, '\t' | '\r' | '\n') {
            if !in_break {
                out.push(' ');
            }
            in_break = true;
        } else {
            out.push(c);
            in_break = false;
        }
    }
    out
}

impl Field {
    fn render(&self) -> String {
        match self {
            Self::None => "-".to_owned(),
            Self::Value(v) if v.is_empty() => "-".to_owned(),
            Self::Value(v) => clean(v),
            Self::Error(m) => format!("error: {}", clean(m)),
        }
    }
}

/// The kind of an item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A directory.
    Dir,
    /// A file.
    File,
    /// A reparse point, with its tag.
    Reparse(u32),
}

/// One manifest row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// Path relative to the root, `\`-separated; the root is `.`.
    pub path: String,
    /// Kind.
    pub kind: Kind,
    /// File attributes.
    pub attributes: u32,
    /// Creation time (FILETIME).
    pub creation: u64,
    /// Last access time (FILETIME).
    pub last_access: u64,
    /// Last write time (FILETIME).
    pub last_write: u64,
    /// Main-stream length (files only).
    pub length: Option<u64>,
    /// SHA-256 of the main stream.
    pub sha256: Field,
    /// Named streams, `name:length:sha256`, `;`-separated.
    pub streams: Field,
    /// Owner, group and DACL as SDDL.
    pub sddl: Field,
    /// Link target.
    pub link_target: Field,
    /// Hard-link names, `|`-separated.
    pub hard_links: Field,
}

impl Row {
    /// The row as one TSV line (without the newline).
    ///
    /// The `type` column of a reparse point is `reparse:0x<tag>`: the
    /// PowerShell manifest's `<link type>` names are not derived here
    /// (see the WU-5 notes).
    #[must_use]
    pub fn to_line(&self) -> String {
        let (kind, tag) = match self.kind {
            Kind::Dir => ("dir".to_owned(), "-".to_owned()),
            Kind::File => ("file".to_owned(), "-".to_owned()),
            Kind::Reparse(t) => (format!("reparse:0x{t:08x}"), format!("0x{t:08x}")),
        };
        let length = self
            .length
            .map_or_else(|| "-".to_owned(), |l| l.to_string());
        let path = Field::Value(self.path.clone()).render();
        format!(
            "{path}\t{kind}\t0x{:08x}\t{}\t{}\t{}\t{length}\t{}\t{}\t{}\t{}\t{}\t{tag}",
            self.attributes,
            self.creation,
            self.last_access,
            self.last_write,
            self.sha256.render(),
            self.streams.render(),
            self.sddl.render(),
            self.link_target.render(),
            self.hard_links.render(),
        )
    }
}

/// Sorts rows: `.` first, then by path in UTF-16 code-unit order.
pub fn sort_rows(rows: &mut [Row]) {
    rows.sort_by(|a, b| match (a.path == ".", b.path == ".") {
        (true, false) => core::cmp::Ordering::Less,
        (false, true) => core::cmp::Ordering::Greater,
        _ => a.path.encode_utf16().cmp(b.path.encode_utf16()),
    });
}

/// Renders the whole manifest, header first, LF line ends.
#[must_use]
pub fn render(rows: &[Row]) -> String {
    let mut out = String::from(HEADER);
    out.push('\n');
    for r in rows {
        out.push_str(&r.to_line());
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(path: &str) -> Row {
        Row {
            path: path.into(),
            kind: Kind::File,
            attributes: 0x20,
            creation: 1,
            last_access: 2,
            last_write: 3,
            length: Some(5),
            sha256: Field::Value("ab".into()),
            streams: Field::Value(String::new()),
            sddl: Field::Error("denied\tnow".into()),
            link_target: Field::None,
            hard_links: Field::None,
        }
    }

    #[test]
    fn line_format() {
        assert_eq!(
            row("a\\b").to_line(),
            "a\\b\tfile\t0x00000020\t1\t2\t3\t5\tab\t-\terror: denied now\t-\t-\t-"
        );
        let mut r = row(".");
        r.kind = Kind::Reparse(0xA000_000C);
        r.length = None;
        assert!(r.to_line().starts_with(".\treparse:0xa000000c\t"));
        assert!(r.to_line().ends_with("\t0xa000000c"));
        assert_eq!(HEADER.split('\t').count(), r.to_line().split('\t').count());
    }

    #[test]
    fn ordinal_utf16_sort_with_root_first() {
        // U+FF21 sorts before U+10000 in code-point (UTF-8) order, but
        // after it in UTF-16 code-unit order (surrogates are 0xD800..).
        let mut rows = vec![
            row("\u{10000}"),
            row("b"),
            row("."),
            row("\u{FF21}"),
            row("B"),
        ];
        sort_rows(&mut rows);
        let order: Vec<&str> = rows.iter().map(|r| r.path.as_str()).collect();
        assert_eq!(order, vec![".", "B", "b", "\u{10000}", "\u{FF21}"]);
        assert!(render(&rows).starts_with(HEADER));
        assert!(render(&rows).ends_with('\n'));
    }
}
