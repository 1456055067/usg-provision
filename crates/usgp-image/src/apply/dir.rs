//! An OS-neutral [`ApplySink`] on `std::fs`, for Linux CI and the agent's
//! simulated platform: directories, files, data, hard links and the last
//! write and access times are applied to a real directory; everything a
//! portable file system cannot hold (named streams, reparse data,
//! descriptors, short names, attributes, creation times) is recorded as
//! unsupported, never faked.
//!
//! The root must be an existing, empty directory. Paths are joined only
//! from validated components under it; files are created with
//! `create_new`, and no symbolic link is ever created, so nothing the sink
//! opens can lead outside the root.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - only validated
//   components joined under the root; existing paths never reused.
// - NIST 800-53: SA-11 (Developer Testing and Evaluation)
// - SPEC: specs/preinstall-env.md#REQ-PE-017 (simulated apply in CI)

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use super::sink::{ApplySink, SinkError, SinkOp, SinkResult};
use crate::wim::metadata::{Attributes, FileTimes};
use crate::wim::names::{ImagePath, ShortName, StreamName};
use crate::wim::reparse::ReparseBuffer;

/// 100-ns units between 1601-01-01 and 1970-01-01 (FILETIME epoch to the
/// Unix epoch): 11644473600 seconds.
const FILETIME_UNIX_OFFSET: u64 = 11_644_473_600 * 10_000_000;

/// A part of the image `DirSink` records instead of applying.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DirSinkGap {
    /// A named stream (creation and data).
    NamedStream,
    /// Reparse data (no link is ever created).
    Reparse,
    /// The security descriptor.
    Security,
    /// The short name.
    ShortName,
    /// The attributes.
    Attributes,
    /// The creation time (no portable setter; last access and last write
    /// are applied).
    CreationTime,
    /// All three times of a directory, on Windows only: opening a
    /// directory there needs the backup-semantics flag (topic 23 §21,
    /// §23), whose numeric value is not in our standards summaries, so
    /// this OS-neutral sink does not open directories on Windows. The
    /// Windows sink (`usgp-winapi`) applies them.
    DirectoryTimes,
    /// A time outside what the platform's clock type can hold.
    UnrepresentableTime,
}

/// A target directory.
#[derive(Debug)]
pub struct DirSink {
    root: PathBuf,
    open: Option<(ImagePath, File)>,
    unsupported: BTreeSet<(DirSinkGap, ImagePath)>,
}

fn sink_err(op: SinkOp) -> impl Fn(io::Error) -> SinkError {
    move |e| SinkError::new(op, e.kind())
}

/// A FILETIME value as a [`SystemTime`], if representable.
fn system_time(ft: u64) -> Option<SystemTime> {
    if ft >= FILETIME_UNIX_OFFSET {
        let d = ft.saturating_sub(FILETIME_UNIX_OFFSET);
        SystemTime::UNIX_EPOCH.checked_add(Duration::from_nanos(d.checked_mul(100)?))
    } else {
        let d = FILETIME_UNIX_OFFSET.saturating_sub(ft);
        SystemTime::UNIX_EPOCH.checked_sub(Duration::from_nanos(d.checked_mul(100)?))
    }
}

impl DirSink {
    /// A sink writing under `root`, which must be an existing, empty
    /// directory (not a symbolic link).
    ///
    /// # Errors
    ///
    /// `InvalidInput` if `root` is not a directory or not empty; any error
    /// reading it.
    pub fn new(root: &Path) -> io::Result<Self> {
        let meta = fs::symlink_metadata(root)?;
        if !meta.is_dir() {
            return Err(io::Error::from(ErrorKind::InvalidInput));
        }
        if fs::read_dir(root)?.next().is_some() {
            return Err(io::Error::from(ErrorKind::InvalidInput));
        }
        Ok(Self {
            root: root.to_path_buf(),
            open: None,
            unsupported: BTreeSet::new(),
        })
    }

    /// Operations that were recorded instead of applied, by path.
    #[must_use]
    pub fn unsupported(&self) -> &BTreeSet<(DirSinkGap, ImagePath)> {
        &self.unsupported
    }

    /// The target path of `p`: validated components under the root.
    fn join(&self, p: &ImagePath) -> PathBuf {
        let mut out = self.root.clone();
        for c in p.components() {
            out.push(c.as_str());
        }
        out
    }

    fn record(&mut self, gap: DirSinkGap, p: &ImagePath) {
        self.unsupported.insert((gap, p.clone()));
    }

    fn close(&mut self) {
        self.open = None;
    }
}

impl ApplySink for DirSink {
    fn create_dir(&mut self, p: &ImagePath) -> SinkResult {
        if p.is_root() {
            return Err(SinkError::new(SinkOp::CreateDir, ErrorKind::AlreadyExists));
        }
        fs::create_dir(self.join(p)).map_err(sink_err(SinkOp::CreateDir))
    }

    fn create_file(&mut self, p: &ImagePath) -> SinkResult {
        if p.is_root() {
            return Err(SinkError::new(SinkOp::CreateFile, ErrorKind::AlreadyExists));
        }
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.join(p))
            .map(drop)
            .map_err(sink_err(SinkOp::CreateFile))
    }

    fn create_stream(&mut self, p: &ImagePath, _s: &StreamName) -> SinkResult {
        self.record(DirSinkGap::NamedStream, p);
        Ok(())
    }

    fn write(
        &mut self,
        p: &ImagePath,
        stream: Option<&StreamName>,
        off: u64,
        data: &[u8],
    ) -> SinkResult {
        if stream.is_some() {
            self.record(DirSinkGap::NamedStream, p);
            return Ok(());
        }
        let e = sink_err(SinkOp::Write);
        if self.open.as_ref().is_none_or(|(q, _)| q != p) {
            // Only files this apply created are written (create_new above).
            let f = OpenOptions::new()
                .write(true)
                .open(self.join(p))
                .map_err(&e)?;
            self.open = Some((p.clone(), f));
        }
        let Some((_, f)) = self.open.as_mut() else {
            return Err(SinkError::new(SinkOp::Write, ErrorKind::NotFound));
        };
        f.seek(SeekFrom::Start(off)).map_err(&e)?;
        f.write_all(data).map_err(&e)
    }

    fn hard_link(&mut self, existing: &ImagePath, new: &ImagePath) -> SinkResult {
        self.close();
        fs::hard_link(self.join(existing), self.join(new)).map_err(sink_err(SinkOp::HardLink))
    }

    fn set_reparse(&mut self, p: &ImagePath, _buf: &ReparseBuffer) -> SinkResult {
        self.record(DirSinkGap::Reparse, p);
        Ok(())
    }

    fn set_security(&mut self, p: &ImagePath, _sd: &[u8]) -> SinkResult {
        self.record(DirSinkGap::Security, p);
        Ok(())
    }

    fn set_short_name(&mut self, p: &ImagePath, _n: &ShortName) -> SinkResult {
        self.record(DirSinkGap::ShortName, p);
        Ok(())
    }

    fn set_times(&mut self, p: &ImagePath, t: &FileTimes) -> SinkResult {
        self.close();
        let e = sink_err(SinkOp::SetTimes);
        let target = self.join(p);
        let is_dir = fs::symlink_metadata(&target).map_err(&e)?.is_dir();
        if is_dir && cfg!(windows) {
            self.record(DirSinkGap::DirectoryTimes, p);
            return Ok(());
        }
        let (Some(accessed), Some(modified)) =
            (system_time(t.last_access), system_time(t.last_write))
        else {
            self.record(DirSinkGap::UnrepresentableTime, p);
            return Ok(());
        };
        // Setting times needs write access to the file's attributes
        // (topic 23 §22: the handle must have the access the change
        // needs); a read-only open is refused on Windows. Directories are
        // opened read-only (Unix only, above), which suffices there.
        let f = if is_dir {
            File::open(&target)
        } else {
            OpenOptions::new().write(true).open(&target)
        }
        .map_err(&e)?;
        let times = fs::FileTimes::new()
            .set_accessed(accessed)
            .set_modified(modified);
        f.set_times(times).map_err(&e)?;
        self.record(DirSinkGap::CreationTime, p);
        Ok(())
    }

    fn set_attributes(&mut self, p: &ImagePath, _a: Attributes) -> SinkResult {
        self.record(DirSinkGap::Attributes, p);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_conversion() {
        // OBS-034: 132539328001234567 is 2021-01-01 00:00:00.1234567 UTC.
        let t = system_time(132_539_328_001_234_567).unwrap_or(SystemTime::UNIX_EPOCH);
        let d = t
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        assert_eq!(d.as_secs(), 1_609_459_200);
        assert_eq!(d.subsec_nanos(), 123_456_700);
        assert!(system_time(0).is_some());
    }
}
