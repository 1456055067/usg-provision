//! `WinSink`: the Windows [`ApplySink`] over [`crate::fs::TreeWriter`].
//!
//! Built with the `sink` feature (it brings `usgp-image`). The writer's
//! errors are mapped to [`SinkError`] (an operation and an I/O kind; no
//! path or data, SI-11).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10, SI-11 (Error Handling)
// - SPEC: specs/preinstall-env.md REQ-PE-016, REQ-PE-017
// - DECISION: docs/decisions/0019-windows-api-binding.md

use std::io::ErrorKind;
use std::path::Path;

use usgp_image::apply::{ApplySink, ReparseBuffer, SinkError, SinkOp, SinkResult};
use usgp_image::wim::metadata::{Attributes, FileTimes};
use usgp_image::wim::names::{ImagePath, ShortName, StreamName};

use crate::error::{Result, WinApiError};
use crate::fs::TreeWriter;

/// The Windows apply sink, rooted at a directory (normally the Windows
/// volume's root).
#[derive(Debug)]
pub struct WinSink {
    w: TreeWriter,
}

impl WinSink {
    /// A sink writing under `root` (see [`TreeWriter::new`]).
    pub fn new(root: &Path) -> Result<Self> {
        Ok(Self {
            w: TreeWriter::new(root)?,
        })
    }

    /// The underlying writer.
    #[must_use]
    pub fn writer(&self) -> &TreeWriter {
        &self.w
    }
}

fn parts(p: &ImagePath) -> Vec<&str> {
    p.components().iter().map(|c| c.as_str()).collect()
}

fn kind(e: &WinApiError) -> ErrorKind {
    match e {
        WinApiError::Os { source, .. } => source.kind(),
        WinApiError::Refused { .. } => ErrorKind::InvalidInput,
        WinApiError::Malformed { .. } => ErrorKind::InvalidData,
        WinApiError::PrivilegeNotHeld { .. } => ErrorKind::PermissionDenied,
        WinApiError::Reparse(crate::parse::ReparseRefusal::Malformed(_)) => ErrorKind::InvalidData,
        WinApiError::Reparse(_) | WinApiError::ShortNameNotSet { .. } => ErrorKind::Unsupported,
        _ => ErrorKind::Other,
    }
}

fn map(op: SinkOp) -> impl FnOnce(WinApiError) -> SinkError {
    move |e| SinkError::new(op, kind(&e))
}

impl ApplySink for WinSink {
    fn create_dir(&mut self, p: &ImagePath) -> SinkResult {
        self.w.create_dir(&parts(p)).map_err(map(SinkOp::CreateDir))
    }

    fn create_file(&mut self, p: &ImagePath) -> SinkResult {
        self.w
            .create_file(&parts(p))
            .map_err(map(SinkOp::CreateFile))
    }

    fn create_stream(&mut self, p: &ImagePath, s: &StreamName) -> SinkResult {
        self.w
            .create_stream(&parts(p), s.as_str())
            .map_err(map(SinkOp::CreateStream))
    }

    fn write(
        &mut self,
        p: &ImagePath,
        stream: Option<&StreamName>,
        off: u64,
        data: &[u8],
    ) -> SinkResult {
        self.w
            .write(&parts(p), stream.map(StreamName::as_str), off, data)
            .map_err(map(SinkOp::Write))
    }

    fn hard_link(&mut self, existing: &ImagePath, new: &ImagePath) -> SinkResult {
        self.w
            .hard_link(&parts(existing), &parts(new))
            .map_err(map(SinkOp::HardLink))
    }

    fn set_reparse(&mut self, p: &ImagePath, buf: &ReparseBuffer) -> SinkResult {
        self.w
            .set_reparse(&parts(p), buf.bytes())
            .map_err(map(SinkOp::SetReparse))
    }

    fn set_security(&mut self, p: &ImagePath, sd: &[u8]) -> SinkResult {
        self.w
            .set_security(&parts(p), sd)
            .map_err(map(SinkOp::SetSecurity))
    }

    fn set_short_name(&mut self, p: &ImagePath, n: &ShortName) -> SinkResult {
        self.w
            .set_short_name(&parts(p), n.as_str())
            .map_err(map(SinkOp::SetShortName))
    }

    fn set_times(&mut self, p: &ImagePath, t: &FileTimes) -> SinkResult {
        self.w
            .set_times(&parts(p), [t.creation, t.last_access, t.last_write])
            .map_err(map(SinkOp::SetTimes))
    }

    fn set_attributes(&mut self, p: &ImagePath, a: Attributes) -> SinkResult {
        self.w
            .set_attributes(&parts(p), a.0)
            .map_err(map(SinkOp::SetAttributes))
    }
}
