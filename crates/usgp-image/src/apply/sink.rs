//! The apply sink: what the apply engine asks a target file system to do.
//!
//! The pre-boot agent implements [`ApplySink`] on Windows (`WinSink`,
//! WU-12 over `usgp-winapi`); this crate has [`super::MemorySink`] for
//! tests and fuzzing and [`super::DirSink`] for an OS-neutral directory.
//! Every path a sink receives is an [`ImagePath`] of validated components,
//! to be joined under the sink's own root and nowhere else.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - sinks receive only
//   validated components.
// - NIST 800-53: SI-11 (Error Handling) - sink errors carry an operation
//   and an I/O kind, never a path.
// - SPEC: specs/preinstall-env.md#REQ-PE-017

use std::fmt;
use std::io;

use crate::wim::metadata::{Attributes, FileTimes};
use crate::wim::names::{ImagePath, ShortName, StreamName};
use crate::wim::reparse::ReparseBuffer;

/// Which sink operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SinkOp {
    /// [`ApplySink::create_dir`].
    CreateDir,
    /// [`ApplySink::create_file`].
    CreateFile,
    /// [`ApplySink::create_stream`].
    CreateStream,
    /// [`ApplySink::write`].
    Write,
    /// [`ApplySink::hard_link`].
    HardLink,
    /// [`ApplySink::set_reparse`].
    SetReparse,
    /// [`ApplySink::set_security`].
    SetSecurity,
    /// [`ApplySink::set_short_name`].
    SetShortName,
    /// [`ApplySink::set_times`].
    SetTimes,
    /// [`ApplySink::set_attributes`].
    SetAttributes,
}

impl SinkOp {
    /// Fixed text naming the operation.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CreateDir => "create directory",
            Self::CreateFile => "create file",
            Self::CreateStream => "create stream",
            Self::Write => "write",
            Self::HardLink => "create hard link",
            Self::SetReparse => "set reparse data",
            Self::SetSecurity => "set security descriptor",
            Self::SetShortName => "set short name",
            Self::SetTimes => "set times",
            Self::SetAttributes => "set attributes",
        }
    }
}

/// A failed sink operation: which one and the I/O error kind. No path or
/// data is carried (SI-11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SinkError {
    /// The operation.
    pub op: SinkOp,
    /// The error kind.
    pub kind: io::ErrorKind,
}

impl SinkError {
    /// A failure of `op` with `kind`.
    #[must_use]
    pub fn new(op: SinkOp, kind: io::ErrorKind) -> Self {
        Self { op, kind }
    }
}

impl fmt::Display for SinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} failed ({})", self.op.as_str(), self.kind)
    }
}

impl std::error::Error for SinkError {}

/// Result of a sink operation.
pub type SinkResult = Result<(), SinkError>;

/// A target the image is applied into.
///
/// The engine calls these in the order of `crate::apply` ("Apply order"):
/// directories top-down, files and named streams, data, hard links,
/// reparse data, descriptors, short names, then attributes and times with
/// directories bottom-up. It never asks a sink to open a path through a
/// reparse point: reparse data is set only after every write.
pub trait ApplySink {
    /// Creates directory `p`; its parent exists. `p` is never the root.
    ///
    /// # Errors
    ///
    /// [`SinkError`] if it exists or cannot be created.
    fn create_dir(&mut self, p: &ImagePath) -> SinkResult;

    /// Creates the empty file `p`; its parent exists. Fails if `p` exists.
    ///
    /// # Errors
    ///
    /// [`SinkError`].
    fn create_file(&mut self, p: &ImagePath) -> SinkResult;

    /// Creates the empty named stream `s` on the existing file or
    /// directory `p`.
    ///
    /// # Errors
    ///
    /// [`SinkError`].
    fn create_stream(&mut self, p: &ImagePath, s: &StreamName) -> SinkResult;

    /// Writes `data` at `off` of the unnamed stream (`None`) or of named
    /// stream `stream` of `p`, which this apply created. Writes to one
    /// stream arrive in order with no gaps.
    ///
    /// # Errors
    ///
    /// [`SinkError`].
    fn write(
        &mut self,
        p: &ImagePath,
        stream: Option<&StreamName>,
        off: u64,
        data: &[u8],
    ) -> SinkResult;

    /// Makes `new` a further name of the file `existing`, which this
    /// apply created and wrote.
    ///
    /// # Errors
    ///
    /// [`SinkError`].
    fn hard_link(&mut self, existing: &ImagePath, new: &ImagePath) -> SinkResult;

    /// Sets reparse data on `p` (created by this apply as an empty file or
    /// directory). `buf` is a whole `REPARSE_DATA_BUFFER` (topic 24 §2:
    /// tag, data length, zero `Reserved`, data), already copied or
    /// re-based by the decision 0022 rule; a sink writes it as given
    /// (`FSCTL_SET_REPARSE_POINT`, topic 24 §6). Junctions (mount points)
    /// arrive here as well as symbolic links.
    ///
    /// # Errors
    ///
    /// [`SinkError`].
    fn set_reparse(&mut self, p: &ImagePath, buf: &ReparseBuffer) -> SinkResult;

    /// Sets the stored security descriptor `sd` on `p` (the root
    /// included). `sd` is passed byte for byte as stored: PS is not
    /// normalised (M-14). What the target keeps is the sink's: the Windows
    /// sink applies it with `SetSecurityInfo`, and an unprotected DACL or
    /// SACL also receives the parent's inheritable entries (topic 23 §20).
    /// On a reparse point it is set on the link itself, never through it.
    ///
    /// # Errors
    ///
    /// [`SinkError`].
    fn set_security(&mut self, p: &ImagePath, sd: &[u8]) -> SinkResult;

    /// Sets the short name of `p`.
    ///
    /// # Errors
    ///
    /// [`SinkError`].
    fn set_short_name(&mut self, p: &ImagePath, n: &ShortName) -> SinkResult;

    /// Sets the three times of `p` (the root included).
    ///
    /// # Errors
    ///
    /// [`SinkError`].
    fn set_times(&mut self, p: &ImagePath, t: &FileTimes) -> SinkResult;

    /// Sets the stored attribute value of `p` (never the root). The value
    /// is the one captured (OBS-033), including bits a file system sets
    /// only through other operations (directory, reparse, sparse,
    /// compressed); a sink applies the bits it can set and must not fail
    /// on the others.
    ///
    /// # Errors
    ///
    /// [`SinkError`].
    fn set_attributes(&mut self, p: &ImagePath, a: Attributes) -> SinkResult;
}
