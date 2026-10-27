//! Bounded, progress-reporting reads from the file under check.
//!
//! Every read names an absolute offset that the caller has already checked
//! against the file length. Each read reports its byte count to the
//! caller's [`Progress`] hook, which can stop the check (watchdog or
//! shutdown, REQ-IMG-021).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), SC-5 (Denial of
//   Service Protection) - fixed-size buffers; no read sized by the file
//   beyond the checked limits.
// - SPEC: specs/os-images.md#REQ-IMG-021 (stoppable, observable check),
//   #REQ-IMG-032 (progress, not a total timeout)

use std::io::{Read, Seek, SeekFrom};
use std::ops::ControlFlow;

use crate::error::WimError;

/// Size of the streaming buffer used for hashing ranges.
pub const IO_BUF_LEN: usize = 64 * 1024;

/// Progress hook for [`crate::check_wim`].
///
/// Called after every read with the number of bytes just read. Return
/// [`ControlFlow::Break`] to stop the check; it then fails with
/// [`WimError::Stalled`].
pub trait Progress {
    /// `bytes` more bytes were read.
    fn advance(&mut self, bytes: u64) -> ControlFlow<()>;
}

/// A [`Progress`] that never stops the check.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoProgress;

impl Progress for NoProgress {
    fn advance(&mut self, _bytes: u64) -> ControlFlow<()> {
        ControlFlow::Continue(())
    }
}

impl<F: FnMut(u64) -> ControlFlow<()>> Progress for F {
    fn advance(&mut self, bytes: u64) -> ControlFlow<()> {
        self(bytes)
    }
}

/// The file under check.
pub(crate) struct Source<'a, R: Read + Seek> {
    r: &'a mut R,
    progress: &'a mut dyn Progress,
    /// Current stream position, if known (avoids redundant seeks).
    pos: Option<u64>,
}

impl<'a, R: Read + Seek> Source<'a, R> {
    pub(crate) fn new(r: &'a mut R, progress: &'a mut dyn Progress) -> Self {
        Self {
            r,
            progress,
            pos: None,
        }
    }

    /// Reads exactly `buf.len()` bytes at `offset`.
    pub(crate) fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), WimError> {
        if self.pos != Some(offset) {
            self.pos = None;
            self.r.seek(SeekFrom::Start(offset))?;
        }
        self.r.read_exact(buf)?;
        let n = u64::try_from(buf.len()).map_err(|_| WimError::Malformed { what: "read size" })?;
        self.pos = offset.checked_add(n);
        match self.progress.advance(n) {
            ControlFlow::Continue(()) => Ok(()),
            ControlFlow::Break(()) => Err(WimError::Stalled),
        }
    }

    /// Reads `len` bytes at `offset` in pieces of at most [`IO_BUF_LEN`]
    /// and hands each piece to `sink`.
    pub(crate) fn stream(
        &mut self,
        offset: u64,
        len: u64,
        sink: &mut dyn FnMut(&[u8]) -> Result<(), WimError>,
    ) -> Result<(), WimError> {
        let mut buf = vec![0u8; IO_BUF_LEN];
        let mut done: u64 = 0;
        while done < len {
            let left = len.saturating_sub(done);
            let n = usize::try_from(left).map_or(IO_BUF_LEN, |l| l.min(IO_BUF_LEN));
            let piece = buf
                .get_mut(..n)
                .ok_or(WimError::Malformed { what: "read size" })?;
            let at = offset
                .checked_add(done)
                .ok_or(WimError::OutOfBounds { what: "resource" })?;
            self.read_at(at, piece)?;
            sink(piece)?;
            done = done.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        }
        Ok(())
    }
}
