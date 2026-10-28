//! Test-only metadata writer (feature `testkit`): encodes a directory tree
//! the way our DISM samples lay it out (OBS-024 to OBS-036), so that apply
//! tests and fuzz seeds use synthetic images only (decision 0006 item 4).
//!
//! Layout written: the security block (OBS-024), the root entry at the
//! next multiple of 8, then each directory's list (breadth first), each
//! ending with an 8-byte zero (OBS-030). Entries use the 102-byte fixed
//! part (OBS-026), UTF-16LE names with terminators (OBS-027), short names
//! after the name (OBS-028), lengths rounded up to 8 (OBS-029), stream
//! entries after the entry (OBS-032), the hard-link value or reparse tag
//! at +88 (OBS-035, OBS-036). `tests/dism_samples.rs`
//! (`builder_metadata_matches_dism`) compares these facts with S13.

// COMPLIANCE MAPPING:
// - NIST 800-53: SA-11 (Developer Testing and Evaluation)
// - SPEC: specs/standards/wim.md §6, §6.1

use std::collections::VecDeque;

use usgp_crypto::digest::legacy_sha1;

use crate::wim::metadata::{REPARSE_FIELD_RELATIVE, attr, tag};

/// A synthetic, well-formed self-relative security descriptor `n`
/// (topic 24 §9): Control SR | DP, an owner and a group SID, and a DACL
/// with one access-allowed ACE; `n` varies the SIDs. 72 bytes.
#[must_use]
pub fn descriptor(n: u8) -> Vec<u8> {
    descriptor_with_control(n, 0x8004)
}

/// As [`descriptor`] with `control` written as given (for negative and
/// PS-bit tests; the offsets follow SR | DP).
#[must_use]
pub fn descriptor_with_control(n: u8, control: u16) -> Vec<u8> {
    let sid = |rid: u8| -> Vec<u8> {
        // Revision 1, one sub-authority, NT authority (0,0,0,0,0,5).
        let mut v = vec![1, 1, 0, 0, 0, 0, 0, 5];
        v.extend_from_slice(&[rid, n, 0, 0]);
        v
    };
    let mut d = vec![1, 0];
    d.extend_from_slice(&control.to_le_bytes());
    for off in [20u32, 32, 0, 44] {
        d.extend_from_slice(&off.to_le_bytes());
    }
    d.extend_from_slice(&sid(32));
    d.extend_from_slice(&sid(18));
    // ACL: revision 2, size 28, one ACE; ACE: allowed, size 20, mask.
    d.extend_from_slice(&[2, 0, 28, 0, 1, 0, 0, 0]);
    d.extend_from_slice(&[0, 0, 20, 0, 0xff, 0x01, 0x1f, 0x00]);
    d.extend_from_slice(&sid(32));
    d
}

/// What a node is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeKind {
    /// A directory and its children.
    Dir(Vec<NodeSpec>),
    /// A file and its main data.
    File(Vec<u8>),
    /// A symbolic link with reparse data; `field_92` is the value at +92.
    Symlink {
        /// A directory link.
        directory: bool,
        /// The value at +92 (0x00010000 on relative links, OBS-036).
        field_92: u32,
        /// The reparse data.
        data: Vec<u8>,
    },
    /// A junction (mount point) with reparse data; `field_92` is the
    /// value at +92 (0x00010000: copied; 0: rewritten, OBS-052).
    Junction {
        /// The value at +92.
        field_92: u32,
        /// The reparse data.
        data: Vec<u8>,
    },
}

/// One node of a [`TreeSpec`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeSpec {
    /// Name (empty for the root).
    pub name: String,
    /// Short name.
    pub short_name: Option<String>,
    /// Stored attribute value.
    pub attributes: u32,
    /// Security index (stored as given; `u32::MAX` is −1).
    pub security: u32,
    /// Creation, last access, last write.
    pub times: [u64; 3],
    /// Hard-link value at +88 (0 for none).
    pub link: u64,
    /// Named streams.
    pub streams: Vec<(String, Vec<u8>)>,
    /// Extra bytes appended inside the entry length (sparse files).
    pub sparse_extra: Vec<u8>,
    /// What it is.
    pub kind: NodeKind,
}

/// Default times: 2021, 2022 and 2023 (OBS-034's values).
pub const TIMES: [u64; 3] = [
    132_539_328_001_234_567,
    132_854_688_001_234_567,
    133_170_048_001_234_567,
];

impl NodeSpec {
    fn new(name: &str, attributes: u32, kind: NodeKind) -> Self {
        Self {
            name: name.to_owned(),
            short_name: None,
            attributes,
            security: 0,
            times: TIMES,
            link: 0,
            streams: Vec::new(),
            sparse_extra: Vec::new(),
            kind,
        }
    }

    /// A directory (attributes 0x10).
    #[must_use]
    pub fn dir(name: &str, children: Vec<NodeSpec>) -> Self {
        Self::new(name, attr::DIRECTORY, NodeKind::Dir(children))
    }

    /// A file (attributes 0x20).
    #[must_use]
    pub fn file(name: &str, data: &[u8]) -> Self {
        Self::new(name, attr::ARCHIVE, NodeKind::File(data.to_vec()))
    }

    /// A relative symbolic link (+92 = 0x00010000), as OBS-036 saw.
    #[must_use]
    pub fn symlink(name: &str, directory: bool, data: &[u8]) -> Self {
        let a = attr::REPARSE
            | if directory {
                attr::DIRECTORY
            } else {
                attr::ARCHIVE
            };
        Self::new(
            name,
            a,
            NodeKind::Symlink {
                directory,
                field_92: REPARSE_FIELD_RELATIVE,
                data: data.to_vec(),
            },
        )
    }

    /// A junction (attributes 0x410).
    #[must_use]
    pub fn junction(name: &str, data: &[u8]) -> Self {
        Self::new(
            name,
            attr::REPARSE | attr::DIRECTORY,
            NodeKind::Junction {
                field_92: REPARSE_FIELD_RELATIVE,
                data: data.to_vec(),
            },
        )
    }

    /// Sets the value at +92 of a symbolic link or junction (0 marks a
    /// target DISM rewrote at capture, OBS-052).
    #[must_use]
    pub fn field_92(mut self, m: u32) -> Self {
        match &mut self.kind {
            NodeKind::Symlink { field_92, .. } | NodeKind::Junction { field_92, .. } => {
                *field_92 = m;
            }
            _ => {}
        }
        self
    }

    /// Sets the attributes.
    #[must_use]
    pub fn attributes(mut self, a: u32) -> Self {
        self.attributes = a;
        self
    }

    /// Sets the short name.
    #[must_use]
    pub fn short(mut self, s: &str) -> Self {
        self.short_name = Some(s.to_owned());
        self
    }

    /// Sets the security index.
    #[must_use]
    pub fn security(mut self, i: u32) -> Self {
        self.security = i;
        self
    }

    /// Sets the times.
    #[must_use]
    pub fn times(mut self, t: [u64; 3]) -> Self {
        self.times = t;
        self
    }

    /// Sets the hard-link value.
    #[must_use]
    pub fn link(mut self, g: u64) -> Self {
        self.link = g;
        self
    }

    /// Adds a named stream.
    #[must_use]
    pub fn stream(mut self, name: &str, data: &[u8]) -> Self {
        self.streams.push((name.to_owned(), data.to_vec()));
        self
    }

    /// Sets the sparse block appended inside the entry.
    #[must_use]
    pub fn sparse_extra(mut self, b: &[u8]) -> Self {
        self.sparse_extra = b.to_vec();
        self
    }
}

/// A whole metadata resource to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeSpec {
    /// The descriptors.
    pub security: Vec<Vec<u8>>,
    /// The root (a directory with an empty name).
    pub root: NodeSpec,
}

/// An encoded metadata resource and where its entries went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedTree {
    /// The resource bytes.
    pub bytes: Vec<u8>,
    /// Each entry's `\`-joined path ("" for the root) and offset.
    pub offsets: Vec<(String, usize)>,
}

impl EncodedTree {
    /// The offset of the entry at `path`.
    #[must_use]
    pub fn offset(&self, path: &str) -> Option<usize> {
        self.offsets
            .iter()
            .find(|(p, _)| p == path)
            .map(|(_, o)| *o)
    }
}

fn hash_of(data: &[u8]) -> [u8; 20] {
    if data.is_empty() {
        [0u8; 20]
    } else {
        legacy_sha1(data).0
    }
}

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn pad8(b: &mut Vec<u8>) {
    while !b.len().is_multiple_of(8) {
        b.push(0);
    }
}

fn u16_len(n: usize) -> u16 {
    u16::try_from(n).unwrap_or(u16::MAX)
}

/// A stream entry to write: name ("" for unnamed) and hash.
type StreamOut = (String, [u8; 20]);

/// One stream entry (OBS-032).
fn stream_entry(name: &str, hash: [u8; 20]) -> Vec<u8> {
    let n = utf16(name);
    let mut e = vec![0u8; 8];
    e.extend_from_slice(&[0u8; 8]);
    e.extend_from_slice(&hash);
    e.extend_from_slice(&u16_len(n.len()).to_le_bytes());
    e.extend_from_slice(&n);
    e.extend_from_slice(&[0, 0]);
    pad8(&mut e);
    let len = u64::try_from(e.len()).unwrap_or(0);
    if let Some(h) = e.get_mut(..8) {
        h.copy_from_slice(&len.to_le_bytes());
    }
    e
}

/// The named streams of `n` (never written on a reparse point by DISM;
/// written here so negative tests can build that case).
fn named(n: &NodeSpec) -> Vec<StreamOut> {
    n.streams
        .iter()
        .map(|(s, d)| (s.clone(), hash_of(d)))
        .collect()
}

/// The entry for `n` (fixed part, names, padding, sparse block) and its
/// stream entries; the children offset is written as 0 and patched later.
fn entry(n: &NodeSpec) -> Vec<u8> {
    let (hash, union, streams): ([u8; 20], u64, Vec<StreamOut>) = match &n.kind {
        NodeKind::Dir(_) => (
            [0u8; 20],
            n.link,
            n.streams
                .iter()
                .map(|(s, d)| (s.clone(), hash_of(d)))
                .collect(),
        ),
        NodeKind::File(data) if n.streams.is_empty() => (hash_of(data), n.link, Vec::new()),
        NodeKind::File(data) => {
            let mut v = vec![(String::new(), hash_of(data))];
            v.extend(n.streams.iter().map(|(s, d)| (s.clone(), hash_of(d))));
            ([0u8; 20], n.link, v)
        }
        NodeKind::Symlink {
            directory,
            field_92,
            data,
        } => {
            let u = u64::from(tag::SYMLINK) | (u64::from(*field_92) << 32);
            if *directory {
                (hash_of(data), u, named(n))
            } else {
                let mut v = vec![(String::new(), hash_of(data)), (String::new(), [0u8; 20])];
                v.extend(named(n));
                ([0u8; 20], u, v)
            }
        }
        NodeKind::Junction { field_92, data } => (
            hash_of(data),
            u64::from(tag::JUNCTION) | (u64::from(*field_92) << 32),
            named(n),
        ),
    };
    let name = utf16(&n.name);
    let short = n.short_name.as_deref().map(utf16).unwrap_or_default();
    let mut e = vec![0u8; 102];
    let mut put = |at: usize, b: &[u8]| {
        if let Some(s) = e.get_mut(at..at.saturating_add(b.len())) {
            s.copy_from_slice(b);
        }
    };
    put(8, &n.attributes.to_le_bytes());
    put(12, &n.security.to_le_bytes());
    let [creation, last_access, last_write] = n.times;
    put(40, &creation.to_le_bytes());
    put(48, &last_access.to_le_bytes());
    put(56, &last_write.to_le_bytes());
    put(64, &hash);
    put(88, &union.to_le_bytes());
    put(96, &u16_len(streams.len()).to_le_bytes());
    put(98, &u16_len(short.len()).to_le_bytes());
    put(100, &u16_len(name.len()).to_le_bytes());
    e.extend_from_slice(&name);
    e.extend_from_slice(&[0, 0]);
    if !short.is_empty() {
        e.extend_from_slice(&short);
        e.extend_from_slice(&[0, 0]);
    }
    pad8(&mut e);
    e.extend_from_slice(&n.sparse_extra);
    pad8(&mut e);
    let len = u64::try_from(e.len()).unwrap_or(0);
    if let Some(h) = e.get_mut(..8) {
        h.copy_from_slice(&len.to_le_bytes());
    }
    for (s, h) in streams {
        e.extend_from_slice(&stream_entry(&s, h));
    }
    e
}

impl TreeSpec {
    /// A tree with `children` under the root and two descriptors.
    #[must_use]
    pub fn new(children: Vec<NodeSpec>) -> Self {
        Self {
            security: vec![descriptor(0), descriptor(1)],
            root: NodeSpec::dir("", children),
        }
    }

    /// Every non-empty content blob (data, streams, reparse data), for
    /// the builder's file resources.
    #[must_use]
    pub fn contents(&self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut stack = vec![&self.root];
        while let Some(n) = stack.pop() {
            match &n.kind {
                NodeKind::Dir(c) => stack.extend(c.iter()),
                NodeKind::File(d) | NodeKind::Junction { data: d, .. } => out.push(d.clone()),
                NodeKind::Symlink { data, .. } => out.push(data.clone()),
            }
            out.extend(n.streams.iter().map(|(_, d)| d.clone()));
        }
        out.retain(|d| !d.is_empty());
        out
    }

    /// Directories other than the root and reparse points, and all other
    /// non-root nodes (the OBS-048 counts).
    #[must_use]
    pub fn counts(&self) -> (u64, u64) {
        let (mut dirs, mut files) = (0u64, 0u64);
        let mut stack: Vec<&NodeSpec> = match &self.root.kind {
            NodeKind::Dir(c) => c.iter().collect(),
            _ => Vec::new(),
        };
        while let Some(n) = stack.pop() {
            if let NodeKind::Dir(c) = &n.kind {
                dirs += 1;
                stack.extend(c.iter());
            } else {
                files += 1;
            }
        }
        (dirs, files)
    }

    /// Encodes the metadata resource.
    #[must_use]
    pub fn encode(&self) -> EncodedTree {
        let mut b = Vec::new();
        let n = u32::try_from(self.security.len()).unwrap_or(u32::MAX);
        let total: usize =
            8 + 8 * self.security.len() + self.security.iter().map(Vec::len).sum::<usize>();
        b.extend_from_slice(&u32::try_from(total).unwrap_or(u32::MAX).to_le_bytes());
        b.extend_from_slice(&n.to_le_bytes());
        for d in &self.security {
            b.extend_from_slice(&u64::try_from(d.len()).unwrap_or(0).to_le_bytes());
        }
        for d in &self.security {
            b.extend_from_slice(d);
        }
        pad8(&mut b);
        let mut offsets = vec![(String::new(), b.len())];
        let root_at = b.len();
        b.extend_from_slice(&entry(&self.root));
        // (directory, its path, where to patch its children offset)
        let mut queue: VecDeque<(&NodeSpec, String, usize)> = VecDeque::new();
        queue.push_back((&self.root, String::new(), root_at + 16));
        while let Some((dir, path, patch)) = queue.pop_front() {
            let NodeKind::Dir(children) = &dir.kind else {
                continue;
            };
            let list = u64::try_from(b.len()).unwrap_or(0);
            if let Some(p) = b.get_mut(patch..patch + 8) {
                p.copy_from_slice(&list.to_le_bytes());
            }
            for c in children {
                let at = b.len();
                let child_path = if path.is_empty() {
                    c.name.clone()
                } else {
                    format!("{path}\\{}", c.name)
                };
                offsets.push((child_path.clone(), at));
                b.extend_from_slice(&entry(c));
                if matches!(c.kind, NodeKind::Dir(_)) {
                    queue.push_back((c, child_path, at + 16));
                }
            }
            b.extend_from_slice(&[0u8; 8]);
        }
        EncodedTree { bytes: b, offsets }
    }

    /// A tree with every feature the apply supports: nested and empty
    /// directories, empty and multi-chunk files, non-BMP names, short
    /// names, named streams on a file and a directory (one empty, one on a
    /// file with an empty main stream), a hard-link group of three, two
    /// relative symbolic links, a sparse file with its extra block,
    /// distinct descriptors, attributes and times, and a duplicate file
    /// that is not a link.
    #[must_use]
    pub fn sample() -> Self {
        let text: Vec<u8> = (0..70_000u32)
            .flat_map(|i| format!("line {i}\n").into_bytes())
            .take(70_000)
            .collect();
        let shared = b"same content in two places\n".repeat(10);
        let linked = b"three names, one file\n".to_vec();
        let mut t = Self::new(vec![
            NodeSpec::file("readme.txt", b"hello\n").short("README.TXT"),
            NodeSpec::file("empty.txt", b""),
            NodeSpec::file("big.txt", &text).times([1, 2, 3]),
            NodeSpec::file("ro.txt", b"read only\n").attributes(attr::READONLY),
            NodeSpec::file("hidden.txt", b"h").attributes(attr::HIDDEN | attr::SYSTEM),
            NodeSpec::file("\u{10400}-supplementary.txt", b"non-bmp\n").security(1),
            NodeSpec::file("streams.txt", b"main\n")
                .stream("usgp-one", b"first stream\n")
                .stream("usgp-zero", b""),
            NodeSpec::file("empty-main.txt", b"").stream("usgp-named", b"named only\n"),
            NodeSpec::dir("empty-dir", vec![]),
            NodeSpec::dir("dir-with-stream", vec![]).stream("usgp-dir-stream", b"on a dir\n"),
            NodeSpec::dir(
                "links",
                vec![
                    NodeSpec::file("hard-original.txt", &linked).link(0x0001_0000_0000_002A),
                    NodeSpec::file("hard-two.txt", &linked).link(0x0001_0000_0000_002A),
                    NodeSpec::dir(
                        "sub",
                        vec![NodeSpec::file("hard-three.txt", &linked).link(0x0001_0000_0000_002A)],
                    ),
                    NodeSpec::file("target-file.txt", b"target\n"),
                    NodeSpec::dir("target-dir", vec![NodeSpec::file("inside.txt", b"in\n")]),
                    NodeSpec::symlink("sym-file-rel.txt", false, &rel_link_data("target-file.txt")),
                    NodeSpec::symlink("sym-dir-rel", true, &rel_link_data("target-dir")),
                ],
            ),
            NodeSpec::dir(
                "special",
                vec![
                    NodeSpec::file("sparse.bin", &[0u8; 1000])
                        .attributes(attr::SPARSE | attr::ARCHIVE)
                        .sparse_extra(&[
                            3, 0, 0, 0, 16, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0,
                        ]),
                    NodeSpec::file("compressed.txt", b"compressible ".repeat(50).as_slice())
                        .attributes(attr::COMPRESSED | attr::ARCHIVE),
                    NodeSpec::file("copy-a.txt", &shared),
                    NodeSpec::file("copy-b.txt", &shared),
                ],
            )
            .attributes(attr::DIRECTORY | attr::HIDDEN | attr::SYSTEM),
        ]);
        t.security.push(descriptor(2));
        t
    }
}

/// Reparse data (without the 8-byte header, as a WIM stores it, OBS-036)
/// laid out as DISM writes it (OBS-049): substitute name at 0, a 2-byte
/// zero, the print name, a 2-byte zero; `flags` is `Some` for a symbolic
/// link (topic 24 §4) and `None` for a mount point (§3).
#[must_use]
pub fn link_data(sub: &str, print: &str, flags: Option<u32>) -> Vec<u8> {
    let s = utf16(sub);
    let p = utf16(print);
    let mut d = Vec::new();
    d.extend_from_slice(&0u16.to_le_bytes());
    d.extend_from_slice(&u16_len(s.len()).to_le_bytes());
    d.extend_from_slice(&u16_len(s.len().saturating_add(2)).to_le_bytes());
    d.extend_from_slice(&u16_len(p.len()).to_le_bytes());
    if let Some(f) = flags {
        d.extend_from_slice(&f.to_le_bytes());
    }
    d.extend_from_slice(&s);
    d.extend_from_slice(&[0, 0]);
    d.extend_from_slice(&p);
    d.extend_from_slice(&[0, 0]);
    d
}

/// Symbolic-link data for the relative target `target` (Flags 1).
#[must_use]
pub fn rel_link_data(target: &str) -> Vec<u8> {
    link_data(target, target, Some(1))
}

/// Data of an absolute target `D:R` as DISM stores a rewritten one
/// (OBS-049): `\??\D:R` and `D:R`; symbolic link (Flags 0) or mount point.
#[must_use]
pub fn abs_link_data(target: &str, junction: bool) -> Vec<u8> {
    link_data(&format!("\\??\\{target}"), target, (!junction).then_some(0))
}
