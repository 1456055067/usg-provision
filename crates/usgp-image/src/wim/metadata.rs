//! The metadata resource of one image (`wim.md` §6, §6.1): the security
//! block, then the directory tree, parsed into a bounded, validated
//! [`ImageTree`].
//!
//! Only layouts our own DISM samples show (OBS-024 to OBS-048, the
//! M-01 to M-23 contract of the M3 boot-protocol review) are accepted;
//! anything else is refused with a named [`MetadataError`] (decision
//! 0006). This module checks structure. Product rules that refuse valid
//! structures (EFS, junctions, absolute link targets) are applied when an
//! apply plan is built (`crate::apply`), so that the tree of every sample
//! can still be compared with its manifest.
//!
//! The parser never recurses: lists are walked with an explicit stack,
//! bounded by [`MetadataLimits`], and every list may be visited once and
//! may not overlap another, so a hostile resource cannot loop or repeat
//! work.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - every offset,
//   length and count checked; reserved fields and padding must be zero.
// - NIST 800-53: SC-5 (Denial of Service Protection) - entry, depth,
//   name, path, stream and descriptor limits; no recursion; no list
//   visited twice.
// - NIST 800-53: SI-11 (Error Handling) - one named reason per refusal;
//   no metadata bytes or names in the error.
// - SPEC: specs/standards/wim.md §6, §6.1 (AUDITED 2026-10-28)
// - SPEC: specs/preinstall-env.md#REQ-PE-017
// - DECISION: docs/decisions/0006-wim-format-by-black-box-test-files.md

use std::collections::{HashMap, HashSet};
use std::fmt;

use super::names::{
    Component, NameKind, ShortName, StreamName, check_component, decode_utf16le, fold_key,
};
use super::reshdr::{le_u16, le_u32, le_u64};

/// Size of an entry's fixed part.
// FORMAT: OBS-026 - 102 bytes in every entry of S01, S13 and S15 (33,
// 3057 and 3058 entries); the WIM paper's [derived] 98 is contradicted
// (wim.md §6.1).
pub const ENTRY_FIXED_LEN: usize = 102;

/// Size of a stream entry before its name.
// FORMAT: OBS-032 - length (8), zero (8), SHA-1 (20), name length (2).
pub const STREAM_FIXED_LEN: usize = 38;

/// Entry and stream-entry alignment.
// FORMAT: OBS-029 - every length is the used size rounded up to 8.
const ALIGN: usize = 8;

/// Field positions in the fixed part (OBS-026).
mod off {
    pub const LENGTH: usize = 0;
    pub const ATTRIBUTES: usize = 8;
    pub const SECURITY: usize = 12;
    pub const CHILDREN: usize = 16;
    pub const ZERO_24: usize = 24;
    pub const ZERO_32: usize = 32;
    pub const CREATION: usize = 40;
    pub const LAST_ACCESS: usize = 48;
    pub const LAST_WRITE: usize = 56;
    pub const HASH: usize = 64;
    pub const ZERO_84: usize = 84;
    pub const UNION: usize = 88;
    pub const UNION_HIGH: usize = 92;
    pub const STREAM_COUNT: usize = 96;
    pub const SHORT_LEN: usize = 98;
    pub const NAME_LEN: usize = 100;
    pub const NAME: usize = 102;
    // Stream entries (OBS-032).
    pub const S_LENGTH: usize = 0;
    pub const S_ZERO: usize = 8;
    pub const S_HASH: usize = 16;
    pub const S_NAME_LEN: usize = 36;
    pub const S_NAME: usize = 38;
}

/// File attribute bits seen at +8 (OBS-033).
pub mod attr {
    /// Read-only.
    pub const READONLY: u32 = 0x0001;
    /// Hidden.
    pub const HIDDEN: u32 = 0x0002;
    /// System.
    pub const SYSTEM: u32 = 0x0004;
    /// Directory.
    pub const DIRECTORY: u32 = 0x0010;
    /// Archive.
    pub const ARCHIVE: u32 = 0x0020;
    /// The value reported when no other bit is set.
    pub const NORMAL: u32 = 0x0080;
    /// Sparse file.
    pub const SPARSE: u32 = 0x0200;
    /// Reparse point.
    pub const REPARSE: u32 = 0x0400;
    /// NTFS-compressed.
    pub const COMPRESSED: u32 = 0x0800;
    /// Not content-indexed.
    pub const NOT_INDEXED: u32 = 0x2000;
    /// EFS-encrypted (parsed; refused when a plan is built, decision
    /// 0006, OBS-040).
    pub const ENCRYPTED: u32 = 0x4000;
    /// Every bit observed; any other bit is refused (M-10).
    // FORMAT: OBS-033 - values seen: 0x01, 0x02, 0x04, 0x10, 0x16, 0x20,
    // 0x30, 0x80, 0x220, 0x410, 0x420, 0x820, 0x2000, 0x4020.
    pub const KNOWN: u32 = READONLY
        | HIDDEN
        | SYSTEM
        | DIRECTORY
        | ARCHIVE
        | NORMAL
        | SPARSE
        | REPARSE
        | COMPRESSED
        | NOT_INDEXED
        | ENCRYPTED;
}

/// Reparse tags seen at +88 (OBS-036).
pub mod tag {
    /// Symbolic link (`fsutil` reported 0xA000000C).
    pub const SYMLINK: u32 = 0xA000_000C;
    /// Junction (mount point; `fsutil` reported 0xA0000003).
    pub const JUNCTION: u32 = 0xA000_0003;
}

/// The value at +92 seen on the two relative symbolic links (OBS-036).
// FORMAT: OBS-036 - `0000 0100` on relative links, 0 on absolute links
// and the junction; its meaning is open (wim.md §6.1). M-13: any other
// value is refused.
pub const REPARSE_FIELD_RELATIVE: u32 = 0x0001_0000;

/// `Control` bits of a self-relative descriptor (topic 24 §9).
mod sd {
    pub const SR: u16 = 0x8000;
    pub const RM: u16 = 0x4000;
    pub const SP: u16 = 0x0010;
    pub const DP: u16 = 0x0004;
    pub const GD: u16 = 0x0002;
    pub const OD: u16 = 0x0001;
    /// Fixed part of a self-relative descriptor ([derived], 20 bytes).
    pub const FIXED: usize = 20;
}

/// Checks a well-formed SID at `at` inside `d` (topic 24 §7).
fn check_sid(d: &[u8], at: usize) -> Result<(), &'static str> {
    let rev = d.get(at).ok_or("SID outside the descriptor")?;
    let count = usize::from(
        *d.get(at.saturating_add(1))
            .ok_or("SID outside the descriptor")?,
    );
    if *rev != 1 {
        return Err("SID revision");
    }
    if count > 15 {
        return Err("SID sub-authority count");
    }
    let end = at
        .checked_add(8 + 4 * count)
        .ok_or("SID outside the descriptor")?;
    if end > d.len() {
        return Err("SID outside the descriptor");
    }
    Ok(())
}

/// Checks a well-formed ACL at `at` inside `d` (topic 24 §8).
fn check_acl(d: &[u8], at: usize) -> Result<(), &'static str> {
    let rev = *d.get(at).ok_or("ACL outside the descriptor")?;
    let sbz1 = *d
        .get(at.saturating_add(1))
        .ok_or("ACL outside the descriptor")?;
    let size = le_u16(d, at.saturating_add(2)).ok_or("ACL outside the descriptor")?;
    let count = le_u16(d, at.saturating_add(4)).ok_or("ACL outside the descriptor")?;
    let sbz2 = le_u16(d, at.saturating_add(6)).ok_or("ACL outside the descriptor")?;
    if rev != 2 && rev != 4 {
        return Err("ACL revision");
    }
    if sbz1 != 0 || sbz2 != 0 {
        return Err("ACL reserved fields");
    }
    let size = usize::from(size);
    if size < 8 || !size.is_multiple_of(4) {
        return Err("ACL size");
    }
    let end = at.checked_add(size).ok_or("ACL outside the descriptor")?;
    if end > d.len() {
        return Err("ACL outside the descriptor");
    }
    let mut ace = at.saturating_add(8);
    for _ in 0..count {
        let ace_size = usize::from(le_u16(d, ace.saturating_add(2)).ok_or("ACE outside the ACL")?);
        if ace_size < 4 || !ace_size.is_multiple_of(4) {
            return Err("ACE size");
        }
        ace = ace.checked_add(ace_size).ok_or("ACE outside the ACL")?;
        if ace > end {
            return Err("ACE outside the ACL");
        }
    }
    Ok(())
}

/// Checks a stored descriptor against topic 24 §9 (M-01, M-14): at least
/// 20 bytes, Revision 1, SR set, `Sbz1` zero unless RM, owner and group
/// present unless defaulted, SACL and DACL offsets agreeing with SP and
/// DP, and every part a well-formed SID or ACL inside the block. PS
/// without SP is accepted (findings R4, M-14). Overlap of parts is not
/// checked (OPEN-RPSD-4).
// FORMAT: OBS-054 - every stored descriptor is self-relative: Revision 1,
// SR set, SACL offset 0, owner, group and DACL inside it.
fn check_descriptor(d: &[u8]) -> Result<(), &'static str> {
    if d.len() < sd::FIXED {
        return Err("shorter than 20 bytes");
    }
    let rev = *d.first().ok_or("shorter than 20 bytes")?;
    let sbz1 = *d.get(1).ok_or("shorter than 20 bytes")?;
    let control = le_u16(d, 2).ok_or("shorter than 20 bytes")?;
    let off = |at| {
        le_u32(d, at)
            .and_then(|v| usize::try_from(v).ok())
            .ok_or("shorter than 20 bytes")
    };
    let (owner, group, sacl, dacl) = (off(4)?, off(8)?, off(12)?, off(16)?);
    if rev != 1 {
        return Err("revision");
    }
    if control & sd::SR == 0 {
        return Err("not self-relative");
    }
    if sbz1 != 0 && control & sd::RM == 0 {
        return Err("Sbz1 without RM");
    }
    for o in [owner, group, sacl, dacl] {
        if o != 0 && o < sd::FIXED {
            return Err("offset inside the fixed part");
        }
    }
    if owner == 0 && control & sd::OD == 0 {
        return Err("no owner");
    }
    if group == 0 && control & sd::GD == 0 {
        return Err("no group");
    }
    if (sacl != 0) != (control & sd::SP != 0) {
        return Err("SACL offset disagrees with SP");
    }
    if (dacl != 0) != (control & sd::DP != 0) {
        return Err("DACL offset disagrees with DP");
    }
    if owner != 0 {
        check_sid(d, owner)?;
    }
    if group != 0 {
        check_sid(d, group)?;
    }
    if sacl != 0 {
        check_acl(d, sacl)?;
    }
    if dacl != 0 {
        check_acl(d, dacl)?;
    }
    Ok(())
}

/// Root-level names refused (M-19).
// FORMAT: OBS-044 - a volume-root capture left out `System Volume
// Information`; M-19 refuses it and any name starting with `$` at the
// root.
const ROOT_SYSTEM_FOLDER: &str = "System Volume Information";

/// Limits for [`parse_metadata`]. Our own bounds (SC-5), not format facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataLimits {
    /// Largest metadata resource, in bytes (it is held in memory).
    pub max_bytes: u64,
    /// Most entries, the root included.
    pub max_entries: u32,
    /// Deepest entry (the root's children are depth 1).
    pub max_depth: u16,
    /// Longest name or stream name, in UTF-16 units.
    pub max_name_units: u16,
    /// Longest full path below the root, in UTF-16 units including one
    /// separator per component (M-16).
    pub max_path_units: u16,
    /// Most stream entries on one entry.
    pub max_streams_per_entry: u16,
    /// Most security descriptors.
    pub max_security_descriptors: u32,
    /// Largest security descriptor, in bytes.
    pub max_sd_bytes: u32,
}

impl MetadataLimits {
    /// Plan §3.7 defaults: 512 MiB, 4 Mi entries, depth 64, 255-unit
    /// names, 32767-unit paths, 64 streams, 65536 descriptors of at most
    /// 64 KiB.
    pub const DEFAULT: Self = Self {
        max_bytes: 512 * 1024 * 1024,
        max_entries: 4 * 1024 * 1024,
        max_depth: 64,
        max_name_units: 255,
        max_path_units: 32767,
        max_streams_per_entry: 64,
        max_security_descriptors: 65536,
        max_sd_bytes: 64 * 1024,
    };
}

impl Default for MetadataLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Why a metadata resource was refused. Variants carry fixed text and
/// numbers only, never bytes or names from the resource (SI-11).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MetadataError {
    /// The security block is inconsistent (M-01).
    SecurityBlock {
        /// Which rule (fixed text).
        what: &'static str,
    },
    /// A security descriptor is not a well-formed self-relative
    /// descriptor (M-01, M-14; topic 24 §9).
    SecurityDescriptor {
        /// Which rule (fixed text).
        what: &'static str,
    },
    /// A security index is −1 or names no descriptor (M-14).
    SecurityIndex,
    /// A structure runs past the end of the resource.
    Truncated {
        /// Which structure (fixed text).
        what: &'static str,
    },
    /// An entry or stream entry length breaks the observed rule (M-06).
    EntryLength {
        /// Which rule (fixed text).
        what: &'static str,
    },
    /// Padding, a terminator gap or trailing bytes are not zero (M-06).
    Padding,
    /// A field that was zero in every observed entry is not (M-03).
    ReservedField {
        /// Entry offset of the field.
        offset: u8,
    },
    /// The root entry is not in the observed form (M-02).
    Root {
        /// Which rule (fixed text).
        what: &'static str,
    },
    /// An entry name is invalid (M-04).
    Name {
        /// Which rule (fixed text).
        what: &'static str,
    },
    /// A short name is invalid (M-05).
    ShortName {
        /// Which rule (fixed text).
        what: &'static str,
    },
    /// A stream name is invalid (M-04 rules).
    StreamName {
        /// Which rule (fixed text).
        what: &'static str,
    },
    /// A children offset is misplaced, out of bounds, or shared (M-07).
    Children {
        /// Which rule (fixed text).
        what: &'static str,
    },
    /// The stream entries of an entry are not in an observed form (M-09).
    Streams {
        /// Which rule (fixed text).
        what: &'static str,
    },
    /// The attributes hold a bit not observed (M-10).
    UnknownAttributes {
        /// The unknown bits.
        bits: u32,
    },
    /// A reparse tag other than symbolic link or junction (M-13).
    UnknownReparseTag {
        /// The tag.
        tag: u32,
    },
    /// A reparse entry is not in an observed form (M-13).
    Reparse {
        /// Which rule (fixed text).
        what: &'static str,
    },
    /// Names of one hard-linked file disagree (M-12).
    HardLink {
        /// Which rule (fixed text).
        what: &'static str,
    },
    /// Two siblings (or two streams of one entry) have names that collide
    /// without case.
    DuplicateName,
    /// A root-level name that is refused (M-19).
    ReservedRootName,
    /// A sparse entry's extra block is not in the observed form (M-15).
    SparseBlock {
        /// Which rule (fixed text).
        what: &'static str,
    },
    /// A count or size exceeds [`MetadataLimits`].
    LimitExceeded {
        /// Which limit (fixed text).
        what: &'static str,
    },
}

impl MetadataError {
    /// Every reason code, for tests and documentation.
    pub const REASON_CODES: &'static [&'static str] = &[
        "wim_meta_security_block",
        "wim_meta_security_descriptor",
        "wim_meta_security_index",
        "wim_meta_truncated",
        "wim_meta_entry_length",
        "wim_meta_padding",
        "wim_meta_reserved_field",
        "wim_meta_root",
        "wim_meta_name",
        "wim_meta_short_name",
        "wim_meta_stream_name",
        "wim_meta_children",
        "wim_meta_streams",
        "wim_meta_attributes",
        "wim_meta_reparse_tag",
        "wim_meta_reparse",
        "wim_meta_hard_link",
        "wim_meta_duplicate_name",
        "wim_meta_reserved_root_name",
        "wim_meta_sparse_block",
        "wim_meta_limit_exceeded",
    ];

    /// Stable machine-readable reason. One code per variant.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::SecurityBlock { .. } => "wim_meta_security_block",
            Self::SecurityDescriptor { .. } => "wim_meta_security_descriptor",
            Self::SecurityIndex => "wim_meta_security_index",
            Self::Truncated { .. } => "wim_meta_truncated",
            Self::EntryLength { .. } => "wim_meta_entry_length",
            Self::Padding => "wim_meta_padding",
            Self::ReservedField { .. } => "wim_meta_reserved_field",
            Self::Root { .. } => "wim_meta_root",
            Self::Name { .. } => "wim_meta_name",
            Self::ShortName { .. } => "wim_meta_short_name",
            Self::StreamName { .. } => "wim_meta_stream_name",
            Self::Children { .. } => "wim_meta_children",
            Self::Streams { .. } => "wim_meta_streams",
            Self::UnknownAttributes { .. } => "wim_meta_attributes",
            Self::UnknownReparseTag { .. } => "wim_meta_reparse_tag",
            Self::Reparse { .. } => "wim_meta_reparse",
            Self::HardLink { .. } => "wim_meta_hard_link",
            Self::DuplicateName => "wim_meta_duplicate_name",
            Self::ReservedRootName => "wim_meta_reserved_root_name",
            Self::SparseBlock { .. } => "wim_meta_sparse_block",
            Self::LimitExceeded { .. } => "wim_meta_limit_exceeded",
        }
    }

    /// Operator text: fixed words and computed numbers only.
    #[must_use]
    pub fn operator_message(&self) -> String {
        let damaged = "image metadata is damaged or in an unsupported layout";
        match self {
            Self::SecurityBlock { what } => format!("{damaged}: security block ({what})"),
            Self::SecurityDescriptor { what } => {
                format!("{damaged}: invalid security descriptor ({what})")
            }
            Self::SecurityIndex => format!("{damaged}: an entry names no security descriptor"),
            Self::Truncated { what } => format!("{damaged}: {what} runs past the end"),
            Self::EntryLength { what } => format!("{damaged}: entry length ({what})"),
            Self::Padding => format!("{damaged}: non-zero padding"),
            Self::ReservedField { offset } => {
                format!("{damaged}: unsupported value in the field at entry offset {offset}")
            }
            Self::Root { what } => format!("{damaged}: root entry ({what})"),
            Self::Name { what } => format!("{damaged}: invalid file name ({what})"),
            Self::ShortName { what } => format!("{damaged}: invalid short name ({what})"),
            Self::StreamName { what } => format!("{damaged}: invalid stream name ({what})"),
            Self::Children { what } => format!("{damaged}: directory list ({what})"),
            Self::Streams { what } => format!("{damaged}: stream entries ({what})"),
            Self::UnknownAttributes { bits } => {
                format!("unsupported file attributes 0x{bits:08x} in the image")
            }
            Self::UnknownReparseTag { tag } => {
                format!("unsupported reparse point type 0x{tag:08x} in the image")
            }
            Self::Reparse { what } => format!("{damaged}: reparse point ({what})"),
            Self::HardLink { what } => format!("{damaged}: hard links ({what})"),
            Self::DuplicateName => {
                "image holds two names in one directory that differ only in case".to_owned()
            }
            Self::ReservedRootName => {
                "image root holds a reserved system name (System Volume Information or $...)"
                    .to_owned()
            }
            Self::SparseBlock { what } => format!("{damaged}: sparse file ranges ({what})"),
            Self::LimitExceeded { what } => format!("image metadata exceeds the limit for {what}"),
        }
    }
}

impl fmt::Display for MetadataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.operator_message())
    }
}

impl std::error::Error for MetadataError {}

/// The three times of an entry, each a 64-bit count of 100-ns units since
/// 1601-01-01 UTC.
// FORMAT: OBS-034 - +40 creation, +48 last access, +56 last write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FileTimes {
    /// Creation time.
    pub creation: u64,
    /// Last access time.
    pub last_access: u64,
    /// Last write time.
    pub last_write: u64,
}

/// The stored attribute value, unchanged (OBS-033).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Attributes(pub u32);

impl Attributes {
    /// True if any of `bits` is set.
    #[must_use]
    pub fn has(self, bits: u32) -> bool {
        self.0 & bits != 0
    }
}

/// A 20-byte content hash naming a resource (OBS-008). Never all zero:
/// empty content is `None` wherever a hash is optional (OBS-031).
pub type Sha1 = [u8; 20];

/// What an entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A directory with a list of children.
    Directory,
    /// A file.
    File,
    /// A symbolic link; `directory` if the link is a directory.
    Symlink {
        /// The attributes carry the directory bit.
        directory: bool,
    },
    /// A junction (refused when a plan is built, OPEN-WIM-12).
    Junction,
}

/// A reparse point's tag and data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reparse {
    /// The reparse tag (OBS-036).
    pub tag: u32,
    /// The 4 bytes at +92: 0 or [`REPARSE_FIELD_RELATIVE`] (M-13).
    pub field_92: u32,
    /// Hash of the reparse data resource (the data without tag and
    /// length, OBS-036).
    pub data: Sha1,
}

/// One named stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedStream {
    /// The name.
    pub name: StreamName,
    /// The content hash; `None` for empty content (OBS-031).
    pub hash: Option<Sha1>,
}

/// One entry of the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Index of the parent in [`ImageTree::entries`]; `None` for the root.
    pub parent: Option<usize>,
    /// The name; `None` for the root.
    pub name: Option<Component>,
    /// The short name, if stored (OBS-028).
    pub short_name: Option<ShortName>,
    /// What the entry is.
    pub kind: EntryKind,
    /// The stored attributes (OBS-033).
    pub attributes: Attributes,
    /// Index into [`ImageTree::security`] (OBS-038; −1 is refused).
    pub security: u32,
    /// The three times (OBS-034).
    pub times: FileTimes,
    /// The main data's hash (files only); `None` for empty content.
    pub data: Option<Sha1>,
    /// Named streams, in stored order (which carries no meaning, M-09).
    pub streams: Vec<NamedStream>,
    /// The hard-link value at +88, if non-zero (OBS-035; opaque).
    pub link_group: Option<u64>,
    /// The reparse tag and data, for symbolic links and junctions.
    pub reparse: Option<Reparse>,
    /// Depth below the root (the root is 0).
    pub depth: u16,
    /// Deallocated (start, end) ranges from the sparse block, last first
    /// (M-15, OBS-055); empty if none. Data is always written in full;
    /// re-creating holes is a sink choice.
    pub sparse_ranges: Vec<(u64, u64)>,
}

/// A parsed, validated metadata resource. Entries are in walk order: every
/// parent comes before its children; index 0 is the root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageTree {
    /// The security descriptors, in stored order (M-14: stored once,
    /// referenced by index).
    pub security: Vec<Vec<u8>>,
    /// The entries, root first.
    pub entries: Vec<Entry>,
}

impl ImageTree {
    /// The root entry.
    #[must_use]
    pub fn root(&self) -> Option<&Entry> {
        self.entries.first()
    }

    /// Directories other than the root and reparse points, and every
    /// other non-root entry: the two numbers OBS-048 relates to the XML
    /// `DIRCOUNT` and `FILECOUNT`.
    #[must_use]
    pub fn dir_and_file_counts(&self) -> (u64, u64) {
        let mut dirs: u64 = 0;
        let mut files: u64 = 0;
        for e in self.entries.iter().skip(1) {
            if e.kind == EntryKind::Directory {
                dirs = dirs.saturating_add(1);
            } else {
                files = files.saturating_add(1);
            }
        }
        (dirs, files)
    }
}

fn trunc(what: &'static str) -> MetadataError {
    MetadataError::Truncated { what }
}

fn limit(what: &'static str) -> MetadataError {
    MetadataError::LimitExceeded { what }
}

/// `n` rounded up to a multiple of [`ALIGN`].
fn align8(n: usize) -> Option<usize> {
    n.checked_add(ALIGN - 1).map(|v| v / ALIGN * ALIGN)
}

fn all_zero(b: &[u8]) -> bool {
    b.iter().all(|&x| x == 0)
}

fn hash_at(b: &[u8], at: usize) -> Option<Sha1> {
    let end = at.checked_add(20)?;
    b.get(at..end)?.try_into().ok()
}

fn nonzero(h: Sha1) -> Option<Sha1> {
    (h != [0u8; 20]).then_some(h)
}

/// Parses the security block (M-01). Returns the descriptors and the root
/// entry's offset.
// FORMAT: OBS-024 - u32 total length including the 8-byte header, u32
// descriptor count, one u64 length per descriptor, the descriptors with no
// padding between them; the root entry at the next multiple of 8, the
// bytes between zero.
fn parse_security(b: &[u8], l: &MetadataLimits) -> Result<(Vec<Vec<u8>>, usize), MetadataError> {
    let sec = |what| MetadataError::SecurityBlock { what };
    let total = le_u32(b, 0).ok_or(trunc("security block"))?;
    let count = le_u32(b, 4).ok_or(trunc("security block"))?;
    let total = usize::try_from(total).map_err(|_| sec("length"))?;
    if total < 8 || total > b.len() {
        return Err(sec("length"));
    }
    if count > l.max_security_descriptors {
        return Err(limit("security descriptors"));
    }
    let n = usize::try_from(count).map_err(|_| limit("security descriptors"))?;
    let lengths_end = n
        .checked_mul(8)
        .and_then(|v| v.checked_add(8))
        .ok_or(sec("count"))?;
    if lengths_end > total {
        return Err(sec("count"));
    }
    let mut descriptors = Vec::new();
    descriptors
        .try_reserve_exact(n)
        .map_err(|_| limit("security descriptors"))?;
    let mut at = lengths_end;
    for k in 0..n {
        let len_at = k
            .checked_mul(8)
            .and_then(|v| v.checked_add(8))
            .ok_or(sec("count"))?;
        let len = le_u64(b, len_at).ok_or(trunc("security block"))?;
        if len > u64::from(l.max_sd_bytes) {
            return Err(limit("security descriptor size"));
        }
        let len = usize::try_from(len).map_err(|_| sec("descriptor length"))?;
        let end = at.checked_add(len).ok_or(sec("descriptor length"))?;
        if end > total {
            return Err(sec("descriptor lengths exceed the block"));
        }
        let d = b.get(at..end).ok_or(trunc("security descriptor"))?;
        // M-01, M-14: bounded (inside the block) and a well-formed
        // self-relative descriptor (topic 24 §9). The bytes are kept and
        // passed to the sink exactly as stored (PS is not normalised).
        check_descriptor(d).map_err(|what| MetadataError::SecurityDescriptor { what })?;
        descriptors.push(d.to_vec());
        at = end;
    }
    if at != total {
        return Err(sec("lengths do not sum to the total"));
    }
    let root = align8(total).ok_or(sec("length"))?;
    let pad = b.get(total..root).ok_or(trunc("security block padding"))?;
    if !all_zero(pad) {
        return Err(MetadataError::Padding);
    }
    Ok((descriptors, root))
}

/// One stream entry as stored.
struct RawStream {
    name: Option<StreamName>,
    hash: Option<Sha1>,
}

/// One entry as stored, before classification.
struct RawEntry {
    attributes: u32,
    security: u32,
    children: u64,
    times: FileTimes,
    hash: Option<Sha1>,
    union: u64,
    union_high: u32,
    name: String,
    short_name: Option<ShortName>,
    streams: Vec<RawStream>,
    /// The sparse block's (start, end) ranges (M-15).
    sparse: Vec<(u64, u64)>,
    /// Offset just past the entry and its stream entries.
    end: usize,
}

/// Reads the name and terminator at `at` (M-04, M-05). Returns the name
/// and the offset after its terminator.
fn read_name(
    b: &[u8],
    at: usize,
    len_bytes: usize,
    kind: NameKind,
) -> Result<(String, usize), MetadataError> {
    let end = at.checked_add(len_bytes).ok_or(trunc("name"))?;
    let raw = b.get(at..end).ok_or(trunc("name"))?;
    let name = decode_utf16le(raw, kind)?;
    // FORMAT: OBS-027, OBS-028 - a 2-byte zero terminator follows.
    let term_end = end.checked_add(2).ok_or(trunc("name"))?;
    let term = b.get(end..term_end).ok_or(trunc("name"))?;
    if !all_zero(term) {
        return Err(match kind {
            NameKind::Long => MetadataError::Name {
                what: "missing terminator",
            },
            NameKind::Short => MetadataError::ShortName {
                what: "missing terminator",
            },
            NameKind::Stream => MetadataError::StreamName {
                what: "missing terminator",
            },
        });
    }
    Ok((name, term_end))
}

/// Parses the entry at `at` and its stream entries (OBS-026 to OBS-032).
fn parse_entry(b: &[u8], at: usize, l: &MetadataLimits) -> Result<RawEntry, MetadataError> {
    let field = |o: usize| at.checked_add(o).ok_or(trunc("entry"));
    // FORMAT: OBS-029 - every entry starts at a multiple of 8.
    if !at.is_multiple_of(ALIGN) {
        return Err(MetadataError::EntryLength {
            what: "misaligned entry",
        });
    }
    let fixed_end = field(ENTRY_FIXED_LEN)?;
    if fixed_end > b.len() {
        return Err(trunc("entry"));
    }
    let len = le_u64(b, field(off::LENGTH)?).ok_or(trunc("entry"))?;
    let len = usize::try_from(len).map_err(|_| trunc("entry"))?;
    if !len.is_multiple_of(ALIGN) {
        return Err(MetadataError::EntryLength {
            what: "not a multiple of 8",
        });
    }
    let entry_end = at.checked_add(len).ok_or(trunc("entry"))?;
    if entry_end > b.len() {
        return Err(trunc("entry"));
    }
    // M-03: the fields at +24, +32 and +84 were zero in every entry.
    for (o, width) in [(off::ZERO_24, 8usize), (off::ZERO_32, 8), (off::ZERO_84, 4)] {
        let s = field(o)?;
        let e = s.checked_add(width).ok_or(trunc("entry"))?;
        if !all_zero(b.get(s..e).ok_or(trunc("entry"))?) {
            return Err(MetadataError::ReservedField {
                offset: u8::try_from(o).unwrap_or(u8::MAX),
            });
        }
    }
    let u32_at = |o: usize| field(o).and_then(|p| le_u32(b, p).ok_or(trunc("entry")));
    let u64_at = |o: usize| field(o).and_then(|p| le_u64(b, p).ok_or(trunc("entry")));
    let u16_at = |o: usize| field(o).and_then(|p| le_u16(b, p).ok_or(trunc("entry")));
    let attributes = u32_at(off::ATTRIBUTES)?;
    let security = u32_at(off::SECURITY)?;
    let children = u64_at(off::CHILDREN)?;
    let times = FileTimes {
        creation: u64_at(off::CREATION)?,
        last_access: u64_at(off::LAST_ACCESS)?,
        last_write: u64_at(off::LAST_WRITE)?,
    };
    let hash = nonzero(hash_at(b, field(off::HASH)?).ok_or(trunc("entry"))?);
    let union = u64_at(off::UNION)?;
    let union_high = u32_at(off::UNION_HIGH)?;
    let stream_count = u16_at(off::STREAM_COUNT)?;
    let short_len = usize::from(u16_at(off::SHORT_LEN)?);
    let name_len = usize::from(u16_at(off::NAME_LEN)?);

    if name_len / 2 > usize::from(l.max_name_units) {
        return Err(limit("name length"));
    }
    let (name, mut used) = read_name(b, field(off::NAME)?, name_len, NameKind::Long)?;
    let mut short_name = None;
    if short_len > 0 {
        // M-05: a short name longer than 12 characters is refused.
        if short_len / 2 > super::names::MAX_SHORT_NAME_UNITS {
            return Err(MetadataError::ShortName {
                what: "longer than 12 characters",
            });
        }
        let (s, end) = read_name(b, used, short_len, NameKind::Short)?;
        short_name = Some(ShortName::new(&s)?);
        used = end;
    }
    // FORMAT: OBS-029 - length = used size rounded up to 8, zero padding.
    // FORMAT: OBS-029, OBS-039 - the sparse exception: a sparse file's
    // entry carries a further block inside its length; M-06: skip it
    // without interpreting it.
    let padded = align8(used).ok_or(trunc("entry"))?;
    if padded > entry_end {
        return Err(MetadataError::EntryLength {
            what: "shorter than its contents",
        });
    }
    if !all_zero(b.get(used..padded).ok_or(trunc("entry"))?) {
        return Err(MetadataError::Padding);
    }
    let sparse = if padded == entry_end {
        // FORMAT: OBS-055 - a sparse file without holes has no block.
        Vec::new()
    } else if attributes & attr::SPARSE == 0 {
        return Err(MetadataError::SparseBlock {
            what: "block on a non-sparse entry",
        });
    } else {
        parse_sparse_block(b.get(padded..entry_end).ok_or(trunc("entry"))?)?
    };

    if stream_count > l.max_streams_per_entry {
        return Err(limit("streams per entry"));
    }
    let mut streams = Vec::with_capacity(usize::from(stream_count));
    let mut s = entry_end;
    for _ in 0..stream_count {
        let (st, next) = parse_stream(b, s, l)?;
        streams.push(st);
        s = next;
    }
    Ok(RawEntry {
        attributes,
        security,
        children,
        times,
        hash,
        union,
        union_high,
        name,
        short_name,
        streams,
        sparse,
        end: s,
    })
}

/// The sparse block (M-15): u32 3, u32 16 × n equal to the rest of the
/// block, then n (start, end) u64 pairs, strictly descending and not
/// overlapping, each with start < end. That end lies within the file is
/// checked when the plan knows the file length.
// FORMAT: OBS-055 - first word 3 in every block; second word 16, 32, 48
// for 1, 2, 3 pairs; merged ranges with exclusive ends, last first.
// FORMAT: OBS-039 - R3's one-pair block.
fn parse_sparse_block(blk: &[u8]) -> Result<Vec<(u64, u64)>, MetadataError> {
    let bad = |what| MetadataError::SparseBlock { what };
    let first = le_u32(blk, 0).ok_or(bad("inconsistent length"))?;
    let size = le_u32(blk, 4).ok_or(bad("inconsistent length"))?;
    if first != 3 {
        return Err(bad("first word is not 3"));
    }
    let size = usize::try_from(size).map_err(|_| bad("inconsistent length"))?;
    let pairs = blk.get(8..).unwrap_or(&[]);
    // No empty list was ever seen (a sparse file without holes has no
    // block), so n = 0 is refused as inconsistent too.
    if size == 0 || size != pairs.len() || !size.is_multiple_of(16) {
        return Err(bad("inconsistent length"));
    }
    let (chunks, _) = pairs.as_chunks::<16>();
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(chunks.len());
    for c in chunks {
        let start = le_u64(c, 0).ok_or(bad("inconsistent length"))?;
        let end = le_u64(c, 8).ok_or(bad("inconsistent length"))?;
        if start >= end {
            return Err(bad("start not below end"));
        }
        if let Some(&(prev_start, _)) = out.last()
            && end > prev_start
        {
            return Err(bad("ranges not strictly descending or overlapping"));
        }
        out.push((start, end));
    }
    Ok(out)
}

/// Parses one stream entry at `at` (OBS-032), returning it and the offset
/// after it.
fn parse_stream(
    b: &[u8],
    at: usize,
    l: &MetadataLimits,
) -> Result<(RawStream, usize), MetadataError> {
    let field = |o: usize| at.checked_add(o).ok_or(trunc("stream entry"));
    let fixed_end = field(STREAM_FIXED_LEN)?;
    if fixed_end > b.len() {
        return Err(trunc("stream entry"));
    }
    let len = le_u64(b, field(off::S_LENGTH)?).ok_or(trunc("stream entry"))?;
    let len = usize::try_from(len).map_err(|_| trunc("stream entry"))?;
    let end = at.checked_add(len).ok_or(trunc("stream entry"))?;
    if end > b.len() {
        return Err(trunc("stream entry"));
    }
    // FORMAT: OBS-032 - the 8 bytes at +8 were zero in every stream entry.
    let z = field(off::S_ZERO)?;
    if !all_zero(b.get(z..z.saturating_add(8)).ok_or(trunc("stream entry"))?) {
        return Err(MetadataError::ReservedField {
            offset: u8::try_from(off::S_ZERO).unwrap_or(u8::MAX),
        });
    }
    let hash = nonzero(hash_at(b, field(off::S_HASH)?).ok_or(trunc("stream entry"))?);
    let name_len = usize::from(le_u16(b, field(off::S_NAME_LEN)?).ok_or(trunc("stream entry"))?);
    if name_len / 2 > usize::from(l.max_name_units) {
        return Err(limit("name length"));
    }
    let (name, used) = read_name(b, field(off::S_NAME)?, name_len, NameKind::Stream)?;
    // FORMAT: OBS-029 - stream entries: length = (38 + name + 2) rounded
    // up to 8, exactly, with zero padding.
    let padded = align8(used).ok_or(trunc("stream entry"))?;
    if padded != end {
        return Err(MetadataError::EntryLength {
            what: "stream entry length",
        });
    }
    if !all_zero(b.get(used..padded).ok_or(trunc("stream entry"))?) {
        return Err(MetadataError::Padding);
    }
    let name = if name.is_empty() {
        None
    } else {
        Some(StreamName::new(&name)?)
    };
    Ok((RawStream { name, hash }, end))
}

/// Classifies a parsed entry: kind, data, streams, link group and reparse
/// data, enforcing M-07, M-09, M-10, M-12 (per entry) and M-13.
fn classify(
    raw: RawEntry,
    parent: Option<usize>,
    depth: u16,
    descriptors: usize,
) -> Result<(Entry, u64), MetadataError> {
    // M-10: unknown attribute bits are refused.
    let unknown = raw.attributes & !attr::KNOWN;
    if unknown != 0 {
        return Err(MetadataError::UnknownAttributes { bits: unknown });
    }
    // M-14: −1 and out-of-range indexes are refused.
    // FORMAT: OBS-038 - every entry held an index; −1 was never seen.
    let in_range = usize::try_from(raw.security).is_ok_and(|i| i < descriptors);
    if raw.security == u32::MAX || !in_range {
        return Err(MetadataError::SecurityIndex);
    }
    let is_dir = raw.attributes & attr::DIRECTORY != 0;
    let is_reparse = raw.attributes & attr::REPARSE != 0;
    // M-07: only a directory that is not a reparse point has a list, and
    // such a directory always has one (an empty one points at a zero).
    // FORMAT: OBS-030.
    if is_dir && !is_reparse {
        if raw.children == 0 {
            return Err(MetadataError::Children {
                what: "directory without a list",
            });
        }
    } else if raw.children != 0 {
        return Err(MetadataError::Children {
            what: "children on a file or reparse point",
        });
    }

    let name = if parent.is_some() {
        check_component(&raw.name, NameKind::Long)?;
        Some(Component::new(&raw.name)?)
    } else {
        None
    };

    // Streams: unnamed entries first (OBS-032), then named ones.
    let unnamed: Vec<Option<Sha1>> = raw
        .streams
        .iter()
        .filter(|s| s.name.is_none())
        .map(|s| s.hash)
        .collect();
    let first_named = raw.streams.iter().position(|s| s.name.is_some());
    let last_unnamed = raw.streams.iter().rposition(|s| s.name.is_none());
    if let (Some(n), Some(u)) = (first_named, last_unnamed)
        && u > n
    {
        return Err(MetadataError::Streams {
            what: "unnamed stream after a named one",
        });
    }
    let mut streams: Vec<NamedStream> = Vec::new();
    let mut seen = HashSet::new();
    for s in raw.streams {
        if let Some(name) = s.name {
            if !seen.insert(fold_key(name.as_str())) {
                return Err(MetadataError::DuplicateName);
            }
            streams.push(NamedStream { name, hash: s.hash });
        }
    }

    let mut data = None;
    let mut link_group = None;
    let mut reparse = None;
    let kind = if is_reparse {
        // M-13: tag at +88; +92 is 0 or 0x00010000 (OBS-036).
        let tag = u32::try_from(raw.union & 0xFFFF_FFFF).unwrap_or(0);
        if tag != tag::SYMLINK && tag != tag::JUNCTION {
            return Err(MetadataError::UnknownReparseTag { tag });
        }
        if raw.union_high != 0 && raw.union_high != REPARSE_FIELD_RELATIVE {
            return Err(MetadataError::Reparse {
                what: "unsupported value after the tag",
            });
        }
        // FORMAT: OBS-036 - no named streams on reparse points were seen.
        if !streams.is_empty() {
            return Err(MetadataError::Reparse {
                what: "named streams",
            });
        }
        let data_hash = if is_dir {
            // Directory reparse point: data named by the entry hash, no
            // stream entries.
            if !unnamed.is_empty() {
                return Err(MetadataError::Reparse {
                    what: "stream entries on a directory reparse point",
                });
            }
            raw.hash
        } else {
            // File reparse point: entry hash zero; two unnamed stream
            // entries, the first naming the data, the second empty.
            if raw.hash.is_some() || unnamed.len() != 2 {
                return Err(MetadataError::Reparse {
                    what: "file reparse point stream form",
                });
            }
            match (unnamed.first(), unnamed.get(1)) {
                (Some(Some(h)), Some(None)) => Some(*h),
                _ => None,
            }
        };
        let data_hash = data_hash.ok_or(MetadataError::Reparse {
            what: "no reparse data",
        })?;
        reparse = Some(Reparse {
            tag,
            field_92: raw.union_high,
            data: data_hash,
        });
        match tag {
            tag::JUNCTION if is_dir => EntryKind::Junction,
            tag::JUNCTION => {
                return Err(MetadataError::Reparse {
                    what: "junction on a file",
                });
            }
            _ => EntryKind::Symlink { directory: is_dir },
        }
    } else {
        // FORMAT: OBS-035 - +88 holds a non-zero shared value on hard-link
        // names and zero otherwise; it is opaque (M-12).
        link_group = (raw.union != 0).then_some(raw.union);
        if is_dir {
            // FORMAT: OBS-032 - a directory with a named stream has only the
            // named entry; no directory data or hard link was seen.
            if !unnamed.is_empty() {
                return Err(MetadataError::Streams {
                    what: "unnamed stream on a directory",
                });
            }
            if raw.hash.is_some() {
                return Err(MetadataError::Streams {
                    what: "data on a directory",
                });
            }
            if link_group.is_some() {
                return Err(MetadataError::HardLink {
                    what: "hard link on a directory",
                });
            }
            EntryKind::Directory
        } else {
            match (unnamed.len(), streams.is_empty()) {
                // No stream entries: the data hash is the entry's own.
                (0, true) => data = raw.hash,
                // FORMAT: OBS-032 - with named streams, the unnamed entry
                // comes first and carries the data; the entry hash is zero.
                (1, false) => {
                    if raw.hash.is_some() {
                        return Err(MetadataError::Streams {
                            what: "entry hash and an unnamed stream",
                        });
                    }
                    data = unnamed.first().copied().flatten();
                }
                (0, false) => {
                    return Err(MetadataError::Streams {
                        what: "named streams without an unnamed stream",
                    });
                }
                (1, true) => {
                    return Err(MetadataError::Streams {
                        what: "unnamed stream without named streams",
                    });
                }
                _ => {
                    return Err(MetadataError::Streams {
                        what: "more than one unnamed stream",
                    });
                }
            }
            EntryKind::File
        }
    };

    let short_name = raw.short_name;
    if parent.is_none() {
        // M-02: the root has no name, short name or streams (OBS-025).
        if !raw.name.is_empty() || short_name.is_some() || !streams.is_empty() {
            return Err(MetadataError::Root {
                what: "name or streams",
            });
        }
        if kind != EntryKind::Directory {
            return Err(MetadataError::Root {
                what: "not a directory",
            });
        }
    }
    let entry = Entry {
        parent,
        name,
        short_name,
        kind,
        attributes: Attributes(raw.attributes),
        security: raw.security,
        times: raw.times,
        data,
        streams,
        link_group,
        reparse,
        depth,
        sparse_ranges: raw.sparse,
    };
    Ok((entry, raw.children))
}

/// Parses a decoded metadata resource.
///
/// # Errors
///
/// The first [`MetadataError`] found.
pub fn parse_metadata(b: &[u8], l: &MetadataLimits) -> Result<ImageTree, MetadataError> {
    let len = u64::try_from(b.len()).map_err(|_| limit("metadata size"))?;
    if len > l.max_bytes {
        return Err(limit("metadata size"));
    }
    let (security, root_at) = parse_security(b, l)?;
    let descriptors = security.len();

    // FORMAT: OBS-025 - the root is a single entry, not part of a list.
    let root_raw = parse_entry(b, root_at, l)?;
    let root_end = root_raw.end;
    let (root, root_children) = classify(root_raw, None, 0, descriptors)?;
    let mut entries = vec![root];
    // Byte ranges taken by the root and by each list, to refuse overlaps.
    let mut ranges: Vec<(usize, usize)> = vec![(0, root_end)];
    let mut visited: HashSet<usize> = HashSet::new();
    let mut path_units: Vec<u32> = vec![0];
    // (list offset, parent index)
    let mut stack: Vec<(u64, usize)> = vec![(root_children, 0)];
    let max_entries = usize::try_from(l.max_entries).unwrap_or(usize::MAX);
    let mut links: HashMap<u64, usize> = HashMap::new();

    while let Some((list, parent)) = stack.pop() {
        let start = usize::try_from(list).map_err(|_| MetadataError::Children {
            what: "offset out of bounds",
        })?;
        // FORMAT: OBS-030 - a children offset counts from the start of the
        // resource and points at the first entry of the list.
        if start < root_end || start >= b.len() || !start.is_multiple_of(ALIGN) {
            return Err(MetadataError::Children {
                what: "offset out of bounds",
            });
        }
        if !visited.insert(start) {
            return Err(MetadataError::Children {
                what: "list shared or cyclic",
            });
        }
        let parent_depth = entries.get(parent).map_or(0, |e| e.depth);
        let depth = parent_depth.checked_add(1).ok_or(limit("depth"))?;
        if depth > l.max_depth {
            return Err(limit("depth"));
        }
        let parent_units = path_units.get(parent).copied().unwrap_or(0);
        let mut names: HashSet<String> = HashSet::new();
        let mut at = start;
        loop {
            // FORMAT: OBS-030 - each list ends with an 8-byte zero where the
            // next length would be.
            let next_len = le_u64(b, at).ok_or(trunc("directory list"))?;
            if next_len == 0 {
                at = at.checked_add(8).ok_or(trunc("directory list"))?;
                break;
            }
            if entries.len() >= max_entries {
                return Err(limit("entries"));
            }
            let raw = parse_entry(b, at, l)?;
            let next = raw.end;
            let (entry, children) = classify(raw, Some(parent), depth, descriptors)?;
            let name = entry.name.as_ref().map(Component::as_str).unwrap_or("");
            // M-19: refused names at the root.
            if parent == 0
                && (name.eq_ignore_ascii_case(ROOT_SYSTEM_FOLDER) || name.starts_with('$'))
            {
                return Err(MetadataError::ReservedRootName);
            }
            if !names.insert(fold_key(name)) {
                return Err(MetadataError::DuplicateName);
            }
            // M-16: our own path limit, components plus separators.
            let units = u32::try_from(name.encode_utf16().count()).unwrap_or(u32::MAX);
            let total = parent_units.saturating_add(1).saturating_add(units);
            if total > u32::from(l.max_path_units) {
                return Err(limit("path length"));
            }
            let index = entries.len();
            if let Some(g) = entry.link_group {
                links.entry(g).or_insert(index);
            }
            if children != 0 {
                stack.push((children, index));
            }
            entries.push(entry);
            path_units.push(total);
            at = next;
        }
        ranges.push((start, at));
    }

    // Lists may not overlap each other or the root (a shared or
    // overlapping list would repeat entries).
    ranges.sort_unstable();
    for w in ranges.windows(2) {
        if let [(_, a_end), (b_start, _)] = w
            && b_start < a_end
        {
            return Err(MetadataError::Children {
                what: "lists overlap",
            });
        }
    }

    check_link_groups(&entries, &links)?;
    Ok(ImageTree { security, entries })
}

/// M-12: names of one hard-linked file must agree in content hash and
/// streams. Attributes and descriptor must agree too, since they belong to
/// the one file (fail closed: a disagreement was never observed).
fn check_link_groups(entries: &[Entry], first: &HashMap<u64, usize>) -> Result<(), MetadataError> {
    let sorted = |e: &Entry| {
        let mut s: Vec<(String, Option<Sha1>)> = e
            .streams
            .iter()
            .map(|s| (fold_key(s.name.as_str()), s.hash))
            .collect();
        s.sort();
        s
    };
    for e in entries {
        let Some(g) = e.link_group else { continue };
        let Some(f) = first.get(&g).and_then(|&i| entries.get(i)) else {
            continue;
        };
        if e.data != f.data || sorted(e) != sorted(f) {
            return Err(MetadataError::HardLink {
                what: "names differ in content or streams",
            });
        }
        if e.attributes != f.attributes || e.security != f.security {
            return Err(MetadataError::HardLink {
                what: "names differ in attributes or descriptor",
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reason_codes_are_one_to_one() {
        let all = [
            MetadataError::SecurityBlock { what: "x" },
            MetadataError::SecurityDescriptor { what: "x" },
            MetadataError::SecurityIndex,
            MetadataError::Truncated { what: "x" },
            MetadataError::EntryLength { what: "x" },
            MetadataError::Padding,
            MetadataError::ReservedField { offset: 24 },
            MetadataError::Root { what: "x" },
            MetadataError::Name { what: "x" },
            MetadataError::ShortName { what: "x" },
            MetadataError::StreamName { what: "x" },
            MetadataError::Children { what: "x" },
            MetadataError::Streams { what: "x" },
            MetadataError::UnknownAttributes { bits: 1 },
            MetadataError::UnknownReparseTag { tag: 1 },
            MetadataError::Reparse { what: "x" },
            MetadataError::HardLink { what: "x" },
            MetadataError::DuplicateName,
            MetadataError::ReservedRootName,
            MetadataError::SparseBlock { what: "x" },
            MetadataError::LimitExceeded { what: "x" },
        ];
        let codes: Vec<_> = all.iter().map(MetadataError::reason_code).collect();
        assert_eq!(codes, MetadataError::REASON_CODES);
        let unique: HashSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), codes.len());
        for e in &all {
            assert!(!e.operator_message().is_empty());
        }
    }

    #[test]
    fn security_block_obs_024() {
        // S01's header (OBS-024): total 396, two descriptors 232 and 140.
        let mut b = Vec::new();
        b.extend_from_slice(&396u32.to_le_bytes());
        b.extend_from_slice(&2u32.to_le_bytes());
        b.extend_from_slice(&232u64.to_le_bytes());
        b.extend_from_slice(&140u64.to_le_bytes());
        let descriptor = |n: usize| {
            let mut d = crate::testkit::tree::descriptor(1);
            d.resize(n, 0);
            d
        };
        let (d1, d2) = (descriptor(232), descriptor(140));
        b.extend_from_slice(&d1);
        b.extend_from_slice(&d2);
        b.extend_from_slice(&[0u8; 4]);
        let (d, root) = parse_security(&b, &MetadataLimits::DEFAULT).unwrap();
        assert_eq!(d.len(), 2);
        assert_eq!(root, 400);
        // Non-zero padding before the root.
        let mut p = b.clone();
        if let Some(x) = p.get_mut(397) {
            *x = 1;
        }
        assert_eq!(
            parse_security(&p, &MetadataLimits::DEFAULT),
            Err(MetadataError::Padding)
        );
        // Lengths that do not sum to the total.
        let mut s = b.clone();
        if let Some(x) = s.get_mut(0) {
            *x = 0x8d;
        }
        assert!(parse_security(&s, &MetadataLimits::DEFAULT).is_err());
    }
}
