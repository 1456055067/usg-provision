//! Applying one image of a WIM file to a target (M3), and the verify pass
//! that runs before the disk is wiped.
//!
//! Both read the file through a [`ChunkSource`]: every 8 MiB content chunk
//! is checked against the signed manifest's SHA-256 before any of its
//! bytes are decoded or written (SI-7, decision 0011). Then:
//!
//! 1. the file's structure is checked as the upload check does (header,
//!    lookup table, XML, counts, boot index);
//! 2. **only** the chosen image's metadata resource is decoded, once, and
//!    its SHA-1 checked; two images naming one resource (OBS-018) cost the
//!    same, and no other image's metadata is read (SEC-002);
//! 3. the metadata is parsed into an [`ImageTree`] ([`parse_metadata`]),
//!    and the needed resources are found in the lookup table;
//! 4. [`ApplyPlan::build`] applies the product's refusals and limits;
//! 5. each needed resource is decoded **once**, in file-offset order, and
//!    every path that uses it is written from that one decode; its SHA-1
//!    is checked at its end;
//! 6. each link and junction buffer is copied, re-based onto the
//!    [`ApplyRoot`] or refused by the decision 0022 rule
//!    ([`crate::wim::reparse`]).
//!
//! [`verify_pass`] runs steps 1 to 5 without a sink, so every refusal and
//! every damaged resource is found before the wipe. [`apply`] repeats them
//! with a sink.
//!
//! # Apply order (plan §3.7)
//!
//! 1. directories top-down;
//! 2. files (empty) and named streams;
//! 3. data, by resource offset;
//! 4. hard links;
//! 5. reparse data;
//! 6. security descriptors;
//! 7. short names;
//! 8. attributes and times: files, then directories bottom-up, the root's
//!    times last (the root's attributes are not set, see below).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity) -
//   chunks verified before use; each resource's SHA-1 checked; the verify
//   pass finds damage before the wipe.
// - NIST 800-53: SI-10 (Information Input Validation) - only observed
//   layouts accepted; product refusals named.
// - NIST 800-53: SC-5 (Denial of Service Protection) - one metadata
//   decode, one decode per resource, total size checked against the
//   target before any write.
// - SPEC: specs/preinstall-env.md#REQ-PE-016, #REQ-PE-017
// - SPEC: specs/standards/wim.md §4, §5, §6, §6.1
// - DECISION: docs/decisions/0006, 0011, 0018 item 4, 0022

mod dir;
mod error;
mod memory;
mod sink;

use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek};

use usgp_crypto::CryptoProvider;

pub use dir::DirSink;
pub use error::ApplyError;
pub use memory::{MemoryNode, MemoryNodeKind, MemorySink};
pub use sink::{ApplySink, SinkError, SinkOp, SinkResult};

use crate::codec::XpressDecoder;
use crate::error::WimError;
use crate::limits::WimLimits;
use crate::wim::check::read_structure;
use crate::wim::header::Compression;
use crate::wim::header::FLAG_RP_FIX;
use crate::wim::lookup;
use crate::wim::metadata::{
    EntryKind, ImageTree, MetadataError, MetadataLimits, REPARSE_FIELD_RELATIVE, Sha1, attr,
    parse_metadata,
};
use crate::wim::names::ImagePath;
use crate::wim::remote::{ChunkReader, ChunkSource};
use crate::wim::reparse::prepare as prepare_reparse;
pub use crate::wim::reparse::{ApplyRoot, ApplyRootError, ReparseBuffer, ReparseError};
use crate::wim::reshdr::ResourceHeader;
use crate::wim::resource::{RawChunks, read_resource};
use crate::wim::source::{Progress, Source};

/// Largest reparse data accepted, in bytes. Our own bound (SC-5): the data
/// is held in memory from the data step to the reparse step.
pub const MAX_REPARSE_BYTES: u32 = 16 * 1024;

/// Limits for [`verify_pass`] and [`apply`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyLimits {
    /// Most bytes the image may expand to on the target (the Windows
    /// partition's size): every path's content counted in full, each
    /// hard-linked file once.
    pub max_total_bytes: u64,
    /// Largest reparse data.
    pub max_reparse_bytes: u32,
    /// Metadata limits.
    pub metadata: MetadataLimits,
    /// File-structure limits (as for the upload check).
    pub wim: WimLimits,
}

impl ApplyLimits {
    /// Default limits for a target of `max_total_bytes`.
    #[must_use]
    pub fn new(max_total_bytes: u64) -> Self {
        Self {
            max_total_bytes,
            max_reparse_bytes: MAX_REPARSE_BYTES,
            metadata: MetadataLimits::DEFAULT,
            wim: WimLimits::DEFAULT,
        }
    }
}

/// What the decision 0022 rule needs besides the tree: the file's header
/// flags (H) and the apply root (A).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyContext {
    /// Header flags of the WIM file (`@16`).
    pub header_flags: u32,
    /// The apply root that re-based targets name.
    pub root: ApplyRoot,
}

/// The resources of a file by content hash (non-metadata lookup entries).
pub type Resources = HashMap<Sha1, ResourceHeader>;

/// How the XML's `DIRCOUNT` and `FILECOUNT` relate to the tree (M-23: a
/// warning only, never a refusal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XmlCounts {
    /// Both equal the tree's counts (OBS-048 rule).
    Match,
    /// At least one differs.
    Mismatch {
        /// `DIRCOUNT`, if recorded and numeric.
        xml_dirs: Option<u64>,
        /// `FILECOUNT`, if recorded and numeric.
        xml_files: Option<u64>,
        /// Directories in the tree (root and reparse points excluded).
        tree_dirs: u64,
        /// Other entries in the tree (root excluded).
        tree_files: u64,
    },
}

/// What a verify pass found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyPreview {
    /// Entries in the image, the root included.
    pub entries: u64,
    /// Distinct resources the image needs.
    pub resources: u64,
    /// Bytes the image expands to on the target (as checked against
    /// [`ApplyLimits::max_total_bytes`]).
    pub total_bytes: u64,
    /// The M-23 cross-check.
    pub xml_counts: XmlCounts,
}

/// What an apply did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyReport {
    /// The verify-pass facts of the image applied.
    pub preview: ApplyPreview,
    /// Bytes written to the sink.
    pub bytes_written: u64,
}

/// One use of a resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    /// The unnamed stream of entry `.0`.
    Data(usize),
    /// Named stream `.1` of entry `.0`.
    Stream(usize, usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PlannedResource {
    sha1: Sha1,
    reshdr: ResourceHeader,
    targets: Vec<Target>,
    /// Also the reparse data of some entry.
    reparse: bool,
}

/// A checked plan for applying one [`ImageTree`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyPlan {
    tree: ImageTree,
    paths: Vec<ImagePath>,
    /// For each entry: the first name of its hard-link group, if it is a
    /// later name of that group.
    first_name: Vec<Option<usize>>,
    /// Needed resources, by file offset.
    resources: Vec<PlannedResource>,
    total_bytes: u64,
    root: ImagePath,
    ctx: ApplyContext,
}

impl ApplyPlan {
    /// Checks `tree` against the product's apply rules and `resources`,
    /// and plans the work.
    ///
    /// # Errors
    ///
    /// [`ApplyError::EncryptedNotSupported`],
    /// [`ApplyError::Reparse`] (M = 0 without `RP_FIX`),
    /// [`ApplyError::Metadata`] (a sparse range beyond its file),
    /// [`ApplyError::ResourceMissing`],
    /// [`ApplyError::ChunkTableWidthNotSupported`], or
    /// [`ApplyError::LimitExceeded`].
    pub fn build(
        tree: ImageTree,
        resources: &Resources,
        limits: &ApplyLimits,
        ctx: &ApplyContext,
    ) -> Result<Self, ApplyError> {
        // FORMAT: OBS-040 - an EFS file is stored in a form our sources do
        // not describe; [project rule, DEC-0006] refused (M-10, M-15).
        // Checked over the whole tree first, so the reason is the same
        // whatever the walk order.
        if tree
            .entries
            .iter()
            .any(|e| e.attributes.has(attr::ENCRYPTED))
        {
            return Err(ApplyError::EncryptedNotSupported);
        }
        for e in &tree.entries {
            // M-13, decision 0022: M is 0 or 0x00010000 (the parser
            // refused other values); M = 0 needs RP_FIX. The buffer
            // checks run when the data is decoded.
            if let Some(r) = e.reparse
                && r.field_92 != REPARSE_FIELD_RELATIVE
                && ctx.header_flags & FLAG_RP_FIX == 0
            {
                return Err(ApplyError::Reparse(ReparseError::RewrittenWithoutRpFix));
            }
        }

        // Paths: parents come before children in the tree.
        let mut paths: Vec<ImagePath> = Vec::with_capacity(tree.entries.len());
        for e in &tree.entries {
            let p = match (e.parent.and_then(|i| paths.get(i)), &e.name) {
                (Some(parent), Some(name)) => parent.join(name.clone()),
                _ => ImagePath::root(),
            };
            paths.push(p);
        }

        // Hard-link groups (M-12): the first name in walk order is
        // created and written; the others are linked to it.
        let mut group_first: HashMap<u64, usize> = HashMap::new();
        let mut first_name = Vec::with_capacity(tree.entries.len());
        for (i, e) in tree.entries.iter().enumerate() {
            let first = e.link_group.map(|g| *group_first.entry(g).or_insert(i));
            first_name.push(first.filter(|&f| f != i));
        }

        // Resource uses.
        let mut index: HashMap<Sha1, usize> = HashMap::new();
        let mut planned: Vec<PlannedResource> = Vec::new();
        let mut use_of = |sha1: Sha1, t: Option<Target>| -> Result<(), ApplyError> {
            let k = match index.get(&sha1) {
                Some(&k) => k,
                None => {
                    // M-08: a non-zero hash without a lookup entry.
                    let reshdr = *resources.get(&sha1).ok_or(ApplyError::ResourceMissing)?;
                    planned.push(PlannedResource {
                        sha1,
                        reshdr,
                        targets: Vec::new(),
                        reparse: false,
                    });
                    let k = planned.len().saturating_sub(1);
                    index.insert(sha1, k);
                    k
                }
            };
            if let Some(r) = planned.get_mut(k) {
                match t {
                    Some(t) => r.targets.push(t),
                    None => r.reparse = true,
                }
            }
            Ok(())
        };
        for (i, e) in tree.entries.iter().enumerate() {
            if first_name.get(i).copied().flatten().is_some() {
                continue;
            }
            if let Some(h) = e.data {
                use_of(h, Some(Target::Data(i)))?;
            }
            for (k, s) in e.streams.iter().enumerate() {
                if let Some(h) = s.hash {
                    use_of(h, Some(Target::Stream(i, k)))?;
                }
            }
            if let Some(r) = e.reparse {
                use_of(r.data, None)?;
            }
        }

        // M-15: every sparse range ends within the file (its data length).
        for e in &tree.entries {
            if let Some(&(_, end)) = e.sparse_ranges.iter().max_by_key(|r| r.1) {
                let len = e
                    .data
                    .and_then(|h| resources.get(&h))
                    .map_or(0, |r| r.original_size);
                if end > len {
                    return Err(ApplyError::Metadata(MetadataError::SparseBlock {
                        what: "range beyond the file length",
                    }));
                }
            }
        }

        let mut total: u64 = 0;
        for r in &planned {
            // M-22, OBS-058: 8-byte entries above 2^32; exactly 2^32 is
            // the open threshold (OPEN-WIM-10), refused.
            if r.reshdr.is_compressed() && r.reshdr.original_size == 1u64 << 32 {
                return Err(ApplyError::ChunkTableWidthNotSupported);
            }
            if r.reparse && r.reshdr.original_size > u64::from(limits.max_reparse_bytes) {
                return Err(ApplyError::LimitExceeded {
                    what: "reparse data",
                });
            }
            let uses = u64::try_from(r.targets.len()).unwrap_or(u64::MAX);
            total = r
                .reshdr
                .original_size
                .checked_mul(uses)
                .and_then(|n| total.checked_add(n))
                .ok_or(ApplyError::LimitExceeded { what: "image size" })?;
        }
        if total > limits.max_total_bytes {
            return Err(ApplyError::LimitExceeded { what: "image size" });
        }
        planned.sort_unstable_by_key(|r| r.reshdr.offset);
        Ok(Self {
            tree,
            paths,
            first_name,
            resources: planned,
            total_bytes: total,
            root: ImagePath::root(),
            ctx: ctx.clone(),
        })
    }

    /// The tree being applied.
    #[must_use]
    pub fn tree(&self) -> &ImageTree {
        &self.tree
    }

    /// The path of each entry, in [`ImageTree::entries`] order.
    #[must_use]
    pub fn paths(&self) -> &[ImagePath] {
        &self.paths
    }

    /// Bytes the image expands to on the target.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Distinct resources needed.
    #[must_use]
    pub fn resource_count(&self) -> u64 {
        u64::try_from(self.resources.len()).unwrap_or(u64::MAX)
    }

    fn path(&self, i: usize) -> &ImagePath {
        // `paths` has one path per entry, so the fallback is never used.
        self.paths.get(i).unwrap_or(&self.root)
    }

    fn is_later_name(&self, i: usize) -> bool {
        self.first_name.get(i).copied().flatten().is_some()
    }
}

/// The chosen image, read and checked.
struct Opened {
    compression: Compression,
    plan: ApplyPlan,
    xml_counts: XmlCounts,
}

fn xml_counts(xml: &crate::wim::xml::WimXml, index: u32, tree: &ImageTree) -> XmlCounts {
    let (tree_dirs, tree_files) = tree.dir_and_file_counts();
    let image = xml.images.iter().find(|i| i.index == index);
    let num = |k: &str| {
        image
            .and_then(|i| i.leaf(k))
            .and_then(|t| t.trim().parse().ok())
    };
    let (xml_dirs, xml_files) = (num("DIRCOUNT"), num("FILECOUNT"));
    // FORMAT: OBS-048 - DIRCOUNT counts directories other than the root
    // and reparse points; FILECOUNT every other entry. M-23: a mismatch is
    // a warning only; HARDLINKBYTES is never used.
    if xml_dirs == Some(tree_dirs) && xml_files == Some(tree_files) {
        XmlCounts::Match
    } else {
        XmlCounts::Mismatch {
            xml_dirs,
            xml_files,
            tree_dirs,
            tree_files,
        }
    }
}

/// Steps 1 to 4 of the module description.
fn open<R: Read + Seek>(
    src: &mut Source<'_, R>,
    file_len: u64,
    index: u32,
    limits: &ApplyLimits,
    root: &ApplyRoot,
    crypto: &dyn CryptoProvider,
) -> Result<Opened, ApplyError> {
    let st = read_structure(src, file_len, &limits.wim)?;
    let image_count = st.h.image_count;
    let k = index
        .checked_sub(1)
        .and_then(|k| usize::try_from(k).ok())
        .filter(|_| index <= image_count)
        .ok_or(ApplyError::ImageIndex { index, image_count })?;
    // SEC-002: only this image's metadata entry is read, and only once.
    // An entry repeating another (OBS-018) names the same bytes, so per
    // image the work is the same whether or not it is shared; no other
    // image's metadata is touched.
    let entry = *st
        .scan
        .image_metadata()
        .get(k)
        .ok_or(ApplyError::ImageIndex { index, image_count })?;
    let rh = entry.reshdr;
    if rh.original_size > limits.metadata.max_bytes {
        return Err(metadata_too_large());
    }
    if rh.is_compressed() && rh.original_size == 1u64 << 32 {
        return Err(ApplyError::ChunkTableWidthNotSupported);
    }
    let cap = usize::try_from(rh.original_size).map_err(|_| metadata_too_large())?;
    let mut bytes: Vec<u8> = Vec::new();
    bytes
        .try_reserve_exact(cap)
        .map_err(|_| metadata_too_large())?;
    let mut decoder = match st.compression {
        Compression::Xpress => Some(XpressDecoder::new()),
        Compression::None => None,
    };
    let mut hasher = crypto.legacy_sha1_hasher();
    // FORMAT: OBS-043 - XPRESS metadata decodes through the chunk table to
    // the uncompressed capture's bytes (M-18); OBS-046 - full-size raw
    // chunks at any position (M-21).
    read_resource(src, &rh, decoder.as_mut(), RawChunks::Apply, &mut |p| {
        hasher.update(p);
        bytes.extend_from_slice(p);
        Ok(())
    })?;
    if hasher.finish().0 != entry.sha1 {
        return Err(WimError::MetadataHashMismatch { index }.into());
    }
    let tree = parse_metadata(&bytes, &limits.metadata)?;
    drop(bytes);

    let mut needed: HashSet<Sha1> = HashSet::new();
    for e in &tree.entries {
        needed.extend(e.data);
        needed.extend(e.streams.iter().filter_map(|s| s.hash));
        needed.extend(e.reparse.map(|r| r.data));
    }
    let resources = lookup::resolve(src, &st.h.lookup, &needed)?;
    let counts = xml_counts(&st.xml, index, &tree);
    let ctx = ApplyContext {
        header_flags: st.h.flags,
        root: root.clone(),
    };
    let plan = ApplyPlan::build(tree, &resources, limits, &ctx)?;
    Ok(Opened {
        compression: st.compression,
        plan,
        xml_counts: counts,
    })
}

/// A metadata size refusal.
fn metadata_too_large() -> ApplyError {
    ApplyError::Metadata(MetadataError::LimitExceeded {
        what: "metadata size",
    })
}

/// Step 5, and with a sink the rest of the apply order.
fn run<R: Read + Seek>(
    src: &mut Source<'_, R>,
    opened: &Opened,
    mut sink: Option<&mut dyn ApplySink>,
    crypto: &dyn CryptoProvider,
) -> Result<u64, ApplyError> {
    let plan = &opened.plan;
    let entries = &plan.tree.entries;
    let is_dir = |k: EntryKind| {
        matches!(
            k,
            EntryKind::Directory | EntryKind::Symlink { directory: true } | EntryKind::Junction
        )
    };

    let mut decoder = match opened.compression {
        Compression::Xpress => Some(XpressDecoder::new()),
        Compression::None => None,
    };

    // 0. Reparse data first (small: at most `max_reparse_bytes` each), so
    // that every decision 0022 refusal comes before any sink operation,
    // in `apply` as well as in the verify pass.
    let mut reparse_data: HashMap<Sha1, Vec<u8>> = HashMap::new();
    for r in plan.resources.iter().filter(|r| r.reparse) {
        let mut hasher = crypto.legacy_sha1_hasher();
        let mut keep: Vec<u8> = Vec::new();
        read_resource(
            src,
            &r.reshdr,
            decoder.as_mut(),
            RawChunks::Apply,
            &mut |p| {
                hasher.update(p);
                keep.extend_from_slice(p);
                Ok(())
            },
        )?;
        if hasher.finish().0 != r.sha1 {
            return Err(ApplyError::ResourceHashMismatch);
        }
        reparse_data.insert(r.sha1, keep);
    }
    // Reparse buffers by the decision 0022 rule, in both passes, so that
    // every refusal is found by the verify pass before the wipe.
    let mut buffers: Vec<Option<ReparseBuffer>> = Vec::with_capacity(entries.len());
    for e in entries {
        let b = match e.reparse {
            Some(r) => {
                let data = reparse_data
                    .get(&r.data)
                    .ok_or(ApplyError::ResourceMissing)?;
                Some(
                    prepare_reparse(
                        plan.ctx.header_flags,
                        r.tag,
                        r.field_92,
                        data,
                        &plan.ctx.root,
                    )
                    .map_err(ApplyError::Reparse)?,
                )
            }
            None => None,
        };
        buffers.push(b);
    }

    if let Some(s) = sink.as_deref_mut() {
        // 1. Directories top-down (walk order puts parents first).
        for (i, e) in entries.iter().enumerate().skip(1) {
            if is_dir(e.kind) {
                s.create_dir(plan.path(i))?;
            }
        }
        // 2. Files (each hard-linked file once) and named streams.
        for (i, e) in entries.iter().enumerate().skip(1) {
            if !is_dir(e.kind) && !plan.is_later_name(i) {
                s.create_file(plan.path(i))?;
            }
        }
        for (i, e) in entries.iter().enumerate() {
            if plan.is_later_name(i) {
                continue;
            }
            for st in &e.streams {
                s.create_stream(plan.path(i), &st.name)?;
            }
        }
    }

    // 3. Data: each resource decoded once, in file-offset order; every
    // path using it is written from that decode. The chunks under it were
    // verified (SHA-256) before the decoder saw them; the SHA-1 at the end
    // detects damage in the WIM itself (never the SI-7 decision, plan §5).
    // Resources used only as reparse data were read in step 0.
    let mut written: u64 = 0;
    for r in plan.resources.iter().filter(|r| !r.targets.is_empty()) {
        let mut hasher = crypto.legacy_sha1_hasher();
        let mut at: u64 = 0;
        let mut failed: Option<SinkError> = None;
        let mut on_piece = |piece: &[u8]| -> Result<(), WimError> {
            hasher.update(piece);
            if let Some(s) = sink.as_deref_mut() {
                for t in &r.targets {
                    let res = match *t {
                        Target::Data(i) => s.write(plan.path(i), None, at, piece),
                        Target::Stream(i, k) => {
                            let name = entries
                                .get(i)
                                .and_then(|e| e.streams.get(k))
                                .map(|st| &st.name);
                            match name {
                                Some(n) => s.write(plan.path(i), Some(n), at, piece),
                                None => Ok(()),
                            }
                        }
                    };
                    if let Err(e) = res {
                        failed = Some(e);
                        // Any error stops the reader; the real one is kept.
                        return Err(WimError::Stalled);
                    }
                    written =
                        written.saturating_add(u64::try_from(piece.len()).unwrap_or(u64::MAX));
                }
            }
            at = at.saturating_add(u64::try_from(piece.len()).unwrap_or(u64::MAX));
            Ok(())
        };
        let res = read_resource(
            src,
            &r.reshdr,
            decoder.as_mut(),
            RawChunks::Apply,
            &mut on_piece,
        );
        if let Some(e) = failed {
            return Err(ApplyError::Sink(e));
        }
        res?;
        if hasher.finish().0 != r.sha1 {
            return Err(ApplyError::ResourceHashMismatch);
        }
    }

    let Some(s) = sink else {
        return Ok(0);
    };
    // 4. Hard links: later names of each group, to the first name.
    for i in 0..entries.len() {
        if let Some(f) = plan.first_name.get(i).copied().flatten() {
            s.hard_link(plan.path(f), plan.path(i))?;
        }
    }
    // 5. Reparse data, after every write (no path is ever opened through
    // a reparse point).
    for (i, b) in buffers.iter().enumerate() {
        if let Some(b) = b {
            s.set_reparse(plan.path(i), b)?;
        }
    }
    // 6. Security descriptors (M-14), the root's included (M-19).
    for (i, e) in entries.iter().enumerate() {
        if plan.is_later_name(i) {
            continue;
        }
        let sd = usize::try_from(e.security)
            .ok()
            .and_then(|k| plan.tree.security.get(k))
            .ok_or(ApplyError::Metadata(MetadataError::SecurityIndex))?;
        s.set_security(plan.path(i), sd)?;
    }
    // 7. Short names: one per name, so later link names too.
    for (i, e) in entries.iter().enumerate() {
        if let Some(n) = &e.short_name {
            s.set_short_name(plan.path(i), n)?;
        }
    }
    // 8. Attributes and times last: files, then directories bottom-up.
    for (i, e) in entries.iter().enumerate().skip(1) {
        if !is_dir(e.kind) && !plan.is_later_name(i) {
            s.set_attributes(plan.path(i), e.attributes)?;
            s.set_times(plan.path(i), &e.times)?;
        }
    }
    for (i, e) in entries.iter().enumerate().skip(1).rev() {
        if is_dir(e.kind) {
            s.set_attributes(plan.path(i), e.attributes)?;
            s.set_times(plan.path(i), &e.times)?;
        }
    }
    // The root (M-19): its times (and, above, its descriptor) go to the
    // target root. Its attributes are not set: whether the product applies
    // the captured root's attributes to a volume root is not specified
    // (OBS-045: DISM did not; M-20 excludes root attributes from the
    // oracle), so the target root's own attributes are left unchanged.
    if let Some(root) = entries.first() {
        s.set_times(plan.path(0), &root.times)?;
    }
    Ok(written)
}

fn preview(opened: &Opened) -> ApplyPreview {
    ApplyPreview {
        entries: u64::try_from(opened.plan.tree.entries.len()).unwrap_or(u64::MAX),
        resources: opened.plan.resource_count(),
        total_bytes: opened.plan.total_bytes,
        xml_counts: opened.xml_counts,
    }
}

/// Runs `f` over a [`ChunkReader`] of `img`, and turns a read failure
/// caused by a chunk (integrity, length, fetch) into its own reason.
fn over_chunks<T>(
    img: &mut dyn ChunkSource,
    crypto: &dyn CryptoProvider,
    progress: &mut dyn Progress,
    f: impl FnOnce(&mut Source<'_, ChunkReader<'_>>, u64) -> Result<T, ApplyError>,
) -> Result<T, ApplyError> {
    let mut reader = ChunkReader::new(img, crypto);
    let len = reader.len();
    let result = {
        let mut src = Source::new(&mut reader, progress);
        f(&mut src, len)
    };
    match (result, reader.error()) {
        (Err(_), Some(e)) => Err(ApplyError::from_chunk(e)),
        (r, _) => r,
    }
}

/// The verify pass (plan §0 item 4, step 1): reads the chosen image of the
/// WIM file in `img` as an apply would, without writing anything, so that
/// every refusal, every chunk mismatch and every damaged resource is found
/// before the target disk is wiped.
///
/// `progress` is called after every read; returning `Break` stops the pass
/// with [`WimError::Stalled`].
///
/// # Errors
///
/// The first [`ApplyError`] found.
pub fn verify_pass(
    img: &mut dyn ChunkSource,
    index: u32,
    root: &ApplyRoot,
    limits: &ApplyLimits,
    progress: &mut dyn Progress,
    crypto: &dyn CryptoProvider,
) -> Result<ApplyPreview, ApplyError> {
    over_chunks(img, crypto, progress, |src, len| {
        let opened = open(src, len, index, limits, root, crypto)?;
        run(src, &opened, None, crypto)?;
        Ok(preview(&opened))
    })
}

/// Applies image `index` of the WIM file in `img` to `sink`, in the order
/// of the module description. Run [`verify_pass`] first: a failure here
/// may leave a partly written target.
///
/// # Errors
///
/// The first [`ApplyError`] found.
pub fn apply(
    img: &mut dyn ChunkSource,
    index: u32,
    root: &ApplyRoot,
    sink: &mut dyn ApplySink,
    limits: &ApplyLimits,
    progress: &mut dyn Progress,
    crypto: &dyn CryptoProvider,
) -> Result<ApplyReport, ApplyError> {
    over_chunks(img, crypto, progress, |src, len| {
        let opened = open(src, len, index, limits, root, crypto)?;
        let bytes_written = run(src, &opened, Some(sink), crypto)?;
        Ok(ApplyReport {
            preview: preview(&opened),
            bytes_written,
        })
    })
}
