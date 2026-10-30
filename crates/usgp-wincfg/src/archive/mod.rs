//! Bounded reader for driver archives: ZIP and Microsoft cabinet (plan §1.5).
//!
//! One reader serves both sides: the server validates an upload with
//! [`validate_archive`] (full decode, INF list), and the pre-boot agent
//! extracts with [`extract_archive`] at step 4.
//!
//! Scope (decision 0025 item 3, OPEN-ARC-2): ZIP stored and Deflate with
//! Zip64; CAB uncompressed and MSZIP, single cabinet. Everything else is
//! refused with a named reason ([`ArchiveError::reason`]). The reader
//! refuses anything it does not fully understand.
//!
//! **Partial output.** Extraction is single-pass: CRC-32, CAB checksums and
//! decoded sizes are checked as data streams, so a sink may already hold
//! some files when an error is returned. Callers must extract into a fresh
//! folder and delete it on any error (plan §1.5); a refused archive is then
//! never partly applied.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), SI-7 (Software,
//   Firmware, and Information Integrity), CM-7 (Least Functionality)
// - SPEC: specs/drivers.md#REQ-DRV-001, #REQ-DRV-006, #REQ-DRV-009
// - PKWARE APPNOTE 6.3.10; Microsoft Cabinet Format; RFC 1951
//   (specs/standards/zip-cab.md)

mod cab;
pub mod inf;
pub mod inflate;
mod limits;
mod names;
#[cfg(any(test, feature = "testkit"))]
pub mod testkit;
mod zip;

use std::collections::BTreeSet;

pub use inflate::InflateError;
pub use limits::ArchiveLimits;
pub use names::RelPath;

use names::NameSet;

/// Positional reads from an archive file or buffer.
pub trait ReadAt {
    /// Fills `buf` from `offset`. A short read is an error.
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<()>;
}

impl ReadAt for &[u8] {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
        let start = usize::try_from(offset).map_err(|_| eof())?;
        let end = start.checked_add(buf.len()).ok_or_else(eof)?;
        buf.copy_from_slice(self.get(start..end).ok_or_else(eof)?);
        Ok(())
    }
}

impl ReadAt for Vec<u8> {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
        self.as_slice().read_exact_at(offset, buf)
    }
}

impl ReadAt for std::fs::File {
    #[cfg(unix)]
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
        std::os::unix::fs::FileExt::read_exact_at(self, buf, offset)
    }

    #[cfg(windows)]
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
        let mut done = 0usize;
        while let Some(rest) = buf.get_mut(done..) {
            if rest.is_empty() {
                break;
            }
            let at = offset
                .checked_add(u64::try_from(done).map_err(|_| eof())?)
                .ok_or_else(eof)?;
            let n = std::os::windows::fs::FileExt::seek_read(self, rest, at)?;
            if n == 0 {
                return Err(eof());
            }
            done = done.saturating_add(n);
        }
        Ok(())
    }
}

fn eof() -> std::io::Error {
    std::io::Error::from(std::io::ErrorKind::UnexpectedEof)
}

/// Archive format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveKind {
    /// PKWARE ZIP.
    Zip,
    /// Microsoft cabinet.
    Cab,
}

impl ArchiveKind {
    /// Stable lower-case name (`zip` or `cab`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Zip => "zip",
            Self::Cab => "cab",
        }
    }
}

/// Why an archive was refused. Messages carry no entry names or content.
#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    /// Reading the source failed.
    #[error("archive read failed: {0}")]
    Io(#[source] std::io::Error),
    /// The sink failed.
    #[error("extraction sink failed: {0}")]
    Sink(#[source] std::io::Error),
    /// Neither ZIP nor CAB.
    #[error("not a ZIP or cabinet archive")]
    UnknownFormat,
    /// A structure runs past the end of the file.
    #[error("archive is truncated")]
    Truncated,
    /// A structure is invalid.
    #[error("archive is malformed: {0}")]
    Malformed(&'static str),
    /// Encrypted entries or directory (ZIP flags 0, 6, 13; method 99).
    #[error("encrypted archives are not supported")]
    Encrypted,
    /// ZIP spanning or split archive.
    #[error("multi-disk archives are not supported")]
    MultiDisk,
    /// CAB with previous/next cabinet, or a continued folder.
    #[error("multi-cabinet sets are not supported")]
    MultiCabinet,
    /// ZIP patched-data flag (bit 5).
    #[error("patched data is not supported")]
    PatchedData,
    /// A ZIP method other than stored (0) and Deflate (8).
    #[error("ZIP compression method {method} ({name}) is not supported")]
    ZipMethodUnsupported {
        /// Method number from the header.
        method: u16,
        /// Method name, or `unknown`.
        name: &'static str,
    },
    /// A CAB folder compression type other than none (0) and MSZIP (1).
    /// This covers LZX and Quantum (OPEN-ARC-1: their numeric encoding is
    /// not specified, so every other value is refused).
    #[error("cabinet compression type {type_value:#06x} is not supported")]
    CabCompressionUnsupported {
        /// The raw folder compression field.
        type_value: u16,
    },
    /// CAB version other than 1.3.
    #[error("cabinet version is not supported")]
    CabVersionUnsupported,
    /// An entry name breaks the name rules.
    #[error("entry name refused: {reason}")]
    BadName {
        /// Which rule.
        reason: &'static str,
    },
    /// The same name twice, after case folding.
    #[error("duplicate entry name")]
    DuplicateName,
    /// A file name is also used as a folder.
    #[error("entry path conflicts with a file")]
    PathConflict,
    /// A symbolic link or other special entry.
    #[error("special entries (links, devices) are not supported")]
    SpecialEntry,
    /// Local header and central directory disagree.
    #[error("local header disagrees with central directory: {0}")]
    Mismatch(&'static str),
    /// Data ranges overlap or lie outside the data area.
    #[error("entry data ranges overlap")]
    Overlap,
    /// A configured bound was exceeded.
    #[error("archive limit exceeded: {0}")]
    LimitExceeded(&'static str),
    /// A DEFLATE stream is invalid.
    #[error("deflate stream invalid: {0}")]
    Inflate(InflateError),
    /// A ZIP CRC-32 does not match.
    #[error("CRC-32 mismatch")]
    Crc,
    /// A CAB data-block checksum does not match.
    #[error("cabinet data block checksum mismatch")]
    CabChecksum,
    /// Decoded size differs from the declared size.
    #[error("decoded size differs from declared size")]
    SizeMismatch,
    /// No INF driver package (REQ-DRV-006).
    #[error("archive holds no INF driver package")]
    NoInfPackages,
}

impl ArchiveError {
    /// Stable reason code for `refused{reason}` and
    /// `driver_extract_refused{archive,reason}` (plan §1.5, §3.4).
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Io(_) => "read_failed",
            Self::Sink(_) => "sink_failed",
            Self::UnknownFormat => "unknown_format",
            Self::Truncated => "truncated",
            Self::Malformed(_) => "malformed",
            Self::Encrypted => "encrypted",
            Self::MultiDisk => "multi_disk",
            Self::MultiCabinet => "multi_cabinet",
            Self::PatchedData => "patched_data",
            Self::ZipMethodUnsupported { .. } => "zip_method_unsupported",
            Self::CabCompressionUnsupported { .. } => "cab_compression_unsupported",
            Self::CabVersionUnsupported => "cab_version_unsupported",
            Self::BadName { .. } => "bad_name",
            Self::DuplicateName => "duplicate_name",
            Self::PathConflict => "path_conflict",
            Self::SpecialEntry => "special_entry",
            Self::Mismatch(_) => "header_mismatch",
            Self::Overlap => "overlap",
            Self::LimitExceeded(_) => "limit_exceeded",
            Self::Inflate(_) => "bad_deflate",
            Self::Crc => "crc_mismatch",
            Self::CabChecksum => "cab_checksum",
            Self::SizeMismatch => "size_mismatch",
            Self::NoInfPackages => "no_inf_packages",
        }
    }
}

/// Receives extracted content. Paths are validated and relative; the sink
/// joins them below its own fixed folder. Every parent folder is announced
/// with [`ExtractSink::create_dir`] before anything inside it.
pub trait ExtractSink {
    /// Creates a folder.
    fn create_dir(&mut self, path: &RelPath) -> std::io::Result<()>;
    /// Starts a file of `size` bytes (as declared; checked after writing).
    fn begin_file(&mut self, path: &RelPath, size: u64) -> std::io::Result<()>;
    /// Appends to the current file.
    fn write(&mut self, data: &[u8]) -> std::io::Result<()>;
    /// Ends the current file.
    fn end_file(&mut self) -> std::io::Result<()>;
}

/// A sink that discards everything (validation only).
#[derive(Debug, Default, Clone, Copy)]
pub struct NullSink;

impl ExtractSink for NullSink {
    fn create_dir(&mut self, _: &RelPath) -> std::io::Result<()> {
        Ok(())
    }
    fn begin_file(&mut self, _: &RelPath, _: u64) -> std::io::Result<()> {
        Ok(())
    }
    fn write(&mut self, _: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
    fn end_file(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Result of a successful read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveReport {
    /// Format.
    pub kind: ArchiveKind,
    /// Entries (files and explicit directories).
    pub entries: u32,
    /// Total uncompressed bytes of all files.
    pub expanded: u64,
    /// Driver-package INFs, sorted (REQ-DRV-006).
    pub infs: Vec<RelPath>,
    /// Files with an executable extension; never run (REQ-DRV-006).
    pub ignored_executables: u32,
}

/// What the archive must hold (M4 plan WU-7a item 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveMode {
    /// A driver archive: at least one INF driver package whose catalogs
    /// are present, or [`ArchiveError::NoInfPackages`] (REQ-DRV-006).
    DriverPackages,
    /// Any content (the agent package): the INF rule is skipped; every
    /// other bound and check applies unchanged. INFs found are still
    /// listed in the report.
    Plain,
}

/// Reads and fully decodes a driver archive, discarding content (server
/// upload). Same as [`validate_archive_mode`] with
/// [`ArchiveMode::DriverPackages`].
///
/// # Errors
///
/// Any [`ArchiveError`]; the archive must then be marked refused.
pub fn validate_archive(
    src: &dyn ReadAt,
    len: u64,
    lim: &ArchiveLimits,
) -> Result<ArchiveReport, ArchiveError> {
    validate_archive_mode(src, len, lim, ArchiveMode::DriverPackages)
}

/// Reads and fully decodes the archive in `mode`, discarding content (the
/// server's driver upload uses [`ArchiveMode::DriverPackages`], its agent
/// package upload [`ArchiveMode::Plain`]).
///
/// # Errors
///
/// Any [`ArchiveError`]; the archive must then be marked refused.
pub fn validate_archive_mode(
    src: &dyn ReadAt,
    len: u64,
    lim: &ArchiveLimits,
    mode: ArchiveMode,
) -> Result<ArchiveReport, ArchiveError> {
    extract_archive_mode(src, len, lim, mode, &mut NullSink)
}

/// Reads, decodes and passes every entry of a driver archive to `sink`
/// (agent step 4). Same as [`extract_archive_mode`] with
/// [`ArchiveMode::DriverPackages`].
///
/// # Errors
///
/// Any [`ArchiveError`]. On error the sink may hold partial output, which
/// the caller must delete (module documentation).
pub fn extract_archive(
    src: &dyn ReadAt,
    len: u64,
    lim: &ArchiveLimits,
    sink: &mut dyn ExtractSink,
) -> Result<ArchiveReport, ArchiveError> {
    extract_archive_mode(src, len, lim, ArchiveMode::DriverPackages, sink)
}

/// Reads, decodes and passes every entry to `sink`, in `mode`.
///
/// # Errors
///
/// Any [`ArchiveError`]. On error the sink may hold partial output, which
/// the caller must delete (module documentation).
pub fn extract_archive_mode(
    src: &dyn ReadAt,
    len: u64,
    lim: &ArchiveLimits,
    mode: ArchiveMode,
    sink: &mut dyn ExtractSink,
) -> Result<ArchiveReport, ArchiveError> {
    if len > lim.max_archive_bytes {
        return Err(ArchiveError::LimitExceeded("archive_bytes"));
    }
    let input = Input { r: src, len };
    let mut magic = [0u8; 4];
    input.read(0, &mut magic)?;
    match &magic {
        b"MSCF" => cab::extract(&input, lim, mode, sink),
        b"PK\x03\x04" | b"PK\x05\x06" => zip::extract(&input, lim, mode, sink),
        _ => Err(ArchiveError::UnknownFormat),
    }
}

/// Bounds-checked access to the source.
pub(crate) struct Input<'a> {
    r: &'a dyn ReadAt,
    len: u64,
}

impl Input<'_> {
    pub(crate) fn len(&self) -> u64 {
        self.len
    }

    pub(crate) fn read(&self, off: u64, buf: &mut [u8]) -> Result<(), ArchiveError> {
        let n = u64::try_from(buf.len()).map_err(|_| ArchiveError::Truncated)?;
        let end = off.checked_add(n).ok_or(ArchiveError::Truncated)?;
        if end > self.len {
            return Err(ArchiveError::Truncated);
        }
        self.r.read_exact_at(off, buf).map_err(ArchiveError::Io)
    }

    pub(crate) fn read_vec(&self, off: u64, n: usize) -> Result<Vec<u8>, ArchiveError> {
        let n64 = u64::try_from(n).map_err(|_| ArchiveError::Truncated)?;
        if off.checked_add(n64).is_none_or(|e| e > self.len) {
            return Err(ArchiveError::Truncated);
        }
        let mut v = vec![0u8; n];
        self.read(off, &mut v)?;
        Ok(v)
    }
}

/// Buffered sequential reader over `[pos, end)` of the input.
pub(crate) struct RangeReader<'a, 'b> {
    input: &'b Input<'a>,
    pos: u64,
    end: u64,
    buf: Vec<u8>,
    at: usize,
}

const RANGE_BUF: usize = 64 * 1024;

impl<'a, 'b> RangeReader<'a, 'b> {
    pub(crate) fn new(input: &'b Input<'a>, start: u64, end: u64) -> Self {
        Self {
            input,
            pos: start,
            end,
            buf: Vec::new(),
            at: 0,
        }
    }

    /// Bytes not yet returned.
    pub(crate) fn remaining(&self) -> u64 {
        let buffered = u64::try_from(self.buf.len().saturating_sub(self.at)).unwrap_or(0);
        self.end.saturating_sub(self.pos).saturating_add(buffered)
    }

    fn fill(&mut self) -> Result<bool, ArchiveError> {
        if self.at < self.buf.len() {
            return Ok(true);
        }
        let left = self.end.saturating_sub(self.pos);
        if left == 0 {
            return Ok(false);
        }
        let n = usize::try_from(left.min(RANGE_BUF as u64)).map_err(|_| ArchiveError::Truncated)?;
        self.buf = self.input.read_vec(self.pos, n)?;
        self.at = 0;
        self.pos = self.pos.saturating_add(u64::try_from(n).unwrap_or(0));
        Ok(true)
    }

    /// Next chunk of at most `max` bytes; empty at the end.
    pub(crate) fn chunk(&mut self, max: usize) -> Result<&[u8], ArchiveError> {
        if !self.fill()? {
            return Ok(&[]);
        }
        let take = max.min(self.buf.len().saturating_sub(self.at));
        let s = self.at;
        self.at = s.saturating_add(take);
        self.buf
            .get(s..s.saturating_add(take))
            .ok_or(ArchiveError::Truncated)
    }

    /// Exactly `out.len()` bytes.
    pub(crate) fn read_exact(&mut self, out: &mut [u8]) -> Result<(), ArchiveError> {
        let mut done = 0usize;
        while done < out.len() {
            let want = out.len() - done;
            let c = self.chunk(want)?;
            if c.is_empty() {
                return Err(ArchiveError::Truncated);
            }
            let n = c.len();
            out.get_mut(done..done + n)
                .ok_or(ArchiveError::Truncated)?
                .copy_from_slice(c);
            done += n;
        }
        Ok(())
    }
}

impl inflate::ByteSource for RangeReader<'_, '_> {
    fn next_byte(&mut self) -> Result<Option<u8>, ArchiveError> {
        Ok(self.chunk(1)?.first().copied())
    }
}

/// Little-endian field reader over a header buffer.
pub(crate) struct Le<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Le<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Self {
        Self { b, p: 0 }
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], ArchiveError> {
        let end = self.p.checked_add(n).ok_or(ArchiveError::Truncated)?;
        let s = self.b.get(self.p..end).ok_or(ArchiveError::Truncated)?;
        self.p = end;
        Ok(s)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, ArchiveError> {
        Ok(self.take(1)?.first().copied().unwrap_or(0))
    }

    pub(crate) fn u16(&mut self) -> Result<u16, ArchiveError> {
        let s = self.take(2)?;
        Ok(u16::from_le_bytes(
            s.try_into().map_err(|_| ArchiveError::Truncated)?,
        ))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, ArchiveError> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes(
            s.try_into().map_err(|_| ArchiveError::Truncated)?,
        ))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, ArchiveError> {
        let s = self.take(8)?;
        Ok(u64::from_le_bytes(
            s.try_into().map_err(|_| ArchiveError::Truncated)?,
        ))
    }

    pub(crate) fn rest(&self) -> &'a [u8] {
        self.b.get(self.p..).unwrap_or(&[])
    }
}

/// One listed entry, before decoding.
pub(crate) struct Listed {
    pub(crate) path: RelPath,
    pub(crate) is_dir: bool,
    pub(crate) size: u64,
}

/// Checks a full listing against the limits and name rules.
pub(crate) fn check_listing(
    entries: &[Listed],
    archive_len: u64,
    lim: &ArchiveLimits,
) -> Result<NameSet, ArchiveError> {
    if entries.len() > usize::try_from(lim.max_entries).unwrap_or(usize::MAX) {
        return Err(ArchiveError::LimitExceeded("entries"));
    }
    let mut set = NameSet::default();
    let mut total: u64 = 0;
    for e in entries {
        set.insert(&e.path, e.is_dir)?;
        if e.size > lim.max_entry_bytes {
            return Err(ArchiveError::LimitExceeded("entry_bytes"));
        }
        if !e.is_dir && is_inf(&e.path) && e.size > lim.max_inf_bytes {
            return Err(ArchiveError::LimitExceeded("inf_bytes"));
        }
        total = total
            .checked_add(e.size)
            .ok_or(ArchiveError::LimitExceeded("expanded_bytes"))?;
    }
    set.check_conflicts()?;
    if total > lim.max_expanded_bytes {
        return Err(ArchiveError::LimitExceeded("expanded_bytes"));
    }
    if total > archive_len.saturating_mul(lim.max_ratio_total) {
        return Err(ArchiveError::LimitExceeded("expansion_ratio"));
    }
    Ok(set)
}

fn has_ext(p: &RelPath, exts: &[&str]) -> bool {
    p.file_name()
        .rsplit_once('.')
        .is_some_and(|(_, e)| exts.iter().any(|x| e.eq_ignore_ascii_case(x)))
}

fn is_inf(p: &RelPath) -> bool {
    has_ext(p, &["inf"])
}

/// Extensions counted as executables (REQ-DRV-006: never run).
const EXEC_EXTS: &[&str] = &[
    "exe", "msi", "msp", "com", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "scr", "cpl",
];

/// Passes entries to the sink and gathers the report.
pub(crate) struct Collector<'s> {
    sink: &'s mut dyn ExtractSink,
    names: NameSet,
    mode: ArchiveMode,
    max_inf: u64,
    dirs: BTreeSet<String>,
    current: Option<Current>,
    infs: Vec<(RelPath, inf::InfPackage)>,
    entries: u32,
    expanded: u64,
    executables: u32,
}

struct Current {
    path: RelPath,
    size: u64,
    written: u64,
    inf: Option<Vec<u8>>,
}

impl<'s> Collector<'s> {
    pub(crate) fn new(
        sink: &'s mut dyn ExtractSink,
        names: NameSet,
        lim: &ArchiveLimits,
        mode: ArchiveMode,
    ) -> Self {
        Self {
            sink,
            names,
            mode,
            max_inf: lim.max_inf_bytes,
            dirs: BTreeSet::new(),
            current: None,
            infs: Vec::new(),
            entries: 0,
            expanded: 0,
            executables: 0,
        }
    }

    fn ensure_dir(&mut self, path: &RelPath) -> Result<(), ArchiveError> {
        if self.dirs.contains(&path.folded()) {
            return Ok(());
        }
        if let Some(parent) = path.parent() {
            self.ensure_dir(&parent)?;
        }
        self.sink.create_dir(path).map_err(ArchiveError::Sink)?;
        self.dirs.insert(path.folded());
        Ok(())
    }

    pub(crate) fn dir(&mut self, path: &RelPath) -> Result<(), ArchiveError> {
        self.entries = self.entries.saturating_add(1);
        self.ensure_dir(path)
    }

    pub(crate) fn begin(&mut self, path: &RelPath, size: u64) -> Result<(), ArchiveError> {
        if self.current.is_some() {
            return Err(ArchiveError::Malformed("nested file"));
        }
        if let Some(parent) = path.parent() {
            self.ensure_dir(&parent)?;
        }
        self.sink
            .begin_file(path, size)
            .map_err(ArchiveError::Sink)?;
        self.entries = self.entries.saturating_add(1);
        if has_ext(path, EXEC_EXTS) {
            self.executables = self.executables.saturating_add(1);
        }
        let inf = is_inf(path).then(Vec::new);
        self.current = Some(Current {
            path: path.clone(),
            size,
            written: 0,
            inf,
        });
        Ok(())
    }

    pub(crate) fn write(&mut self, data: &[u8]) -> Result<(), ArchiveError> {
        let cur = self
            .current
            .as_mut()
            .ok_or(ArchiveError::Malformed("data outside file"))?;
        let n = u64::try_from(data.len()).map_err(|_| ArchiveError::SizeMismatch)?;
        cur.written = cur
            .written
            .checked_add(n)
            .ok_or(ArchiveError::SizeMismatch)?;
        if cur.written > cur.size {
            return Err(ArchiveError::SizeMismatch);
        }
        if let Some(buf) = cur.inf.as_mut() {
            if cur.written > self.max_inf {
                return Err(ArchiveError::LimitExceeded("inf_bytes"));
            }
            buf.extend_from_slice(data);
        }
        self.sink.write(data).map_err(ArchiveError::Sink)
    }

    pub(crate) fn end(&mut self) -> Result<(), ArchiveError> {
        let cur = self
            .current
            .take()
            .ok_or(ArchiveError::Malformed("end outside file"))?;
        if cur.written != cur.size {
            return Err(ArchiveError::SizeMismatch);
        }
        self.sink.end_file().map_err(ArchiveError::Sink)?;
        self.expanded = self.expanded.saturating_add(cur.size);
        if let Some(bytes) = cur.inf
            && let Some(pkg) = inf::scan(&bytes)
        {
            self.infs.push((cur.path, pkg));
        }
        Ok(())
    }

    pub(crate) fn finish(self, kind: ArchiveKind) -> Result<ArchiveReport, ArchiveError> {
        if self.current.is_some() {
            return Err(ArchiveError::Malformed("unfinished file"));
        }
        let mut infs = Vec::new();
        for (path, pkg) in self.infs {
            let folder = path.parent().map(|p| format!("{}/", p.folded()));
            let all_present = pkg.catalogs.iter().all(|cat| {
                names::check_segment(cat).is_ok()
                    && self.names.has_file(&format!(
                        "{}{}",
                        folder.as_deref().unwrap_or(""),
                        names::fold(cat)
                    ))
            });
            if all_present {
                infs.push(path);
            }
        }
        if infs.is_empty() && self.mode == ArchiveMode::DriverPackages {
            return Err(ArchiveError::NoInfPackages);
        }
        infs.sort();
        Ok(ArchiveReport {
            kind,
            entries: self.entries,
            expanded: self.expanded,
            infs,
            ignored_executables: self.executables,
        })
    }
}

#[cfg(test)]
mod tests;
