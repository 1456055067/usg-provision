//! File operations below one fixed root, for M4 steps 4, 5 and 8 (M4 plan
//! WU-10; §1.2, §1.4, §1.7): the staging folders and staged archive files
//! of step 4, the closed set of files step 5 writes, and the extraction
//! folders of steps 4 and 8.
//!
//! Every path is built from the root and the `\`-separated relative text
//! of `usgp_deploy`'s closed path types ([`StagePath`], [`StagedArchive`],
//! [`TargetPath`]), which come only from fixed words and our own integer
//! indexes; archive entry names reach the file system only as
//! `usgp_wincfg` [`RelPath`]s, whose every segment already passed the
//! Windows name rules. Nothing here follows a name from the network.
//!
//! Files are created **create-new**: an existing file is refused with
//! `AlreadyExists` and left unchanged. A file that must be protected gets
//! its protection (the platform's hook; on Windows a protected
//! SYSTEM-only DACL) **before** any byte is written. On Windows, files are
//! opened without write or delete sharing, so nothing else can change a
//! staged archive between its verified write and its extraction.
//!
//! The removal of the staging root uses `std::fs::remove_dir_all`, which
//! does not follow symbolic links or junctions below the root (M4 plan
//! §6.2).
//!
//! OS-neutral: compiled on every target, tested on the CI hosts; the
//! Windows-only parts are the open options (access and share modes) and
//! positioned I/O.

// COMPLIANCE MAPPING:
// - NIST 800-53: AC-3, AC-6 - `job.key` protected (SYSTEM only) before
//   its bytes are written; create-new never replaces a file.
// - NIST 800-53: CM-7 - only the closed set of target paths can be
//   named; staging only below `$usgp-stage`.
// - NIST 800-53: SI-7 - a staged archive cannot be changed between its
//   verified write and its extraction (no write sharing).
// - NIST 800-53: SI-10 - archive names reach the file system only as
//   validated relative paths.
// - SPEC: specs/drivers.md#REQ-DRV-004, #REQ-DRV-009
// - SPEC: specs/agent-handoff.md#REQ-AGT-001
// - DECISION: docs/decisions/0024 items 2 and 4

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use usgp_deploy::platform::{
    FileProtection, FileWriter, STAGE_ROOT, StagePath, StagedArchive, TargetPath,
};
use usgp_wincfg::archive::{ExtractSink, ReadAt, RelPath};

/// Applies a file protection to a just-created, still empty file.
pub type ProtectFn = fn(&File) -> io::Result<()>;

/// The root a set of relative paths is joined below.
#[derive(Debug, Clone)]
pub struct TargetFs {
    root: PathBuf,
    protect: ProtectFn,
}

/// `rel`, `\`-separated, joined below `root`. Empty segments are skipped.
#[must_use]
pub fn join_backslashed(root: &Path, rel: &str) -> PathBuf {
    rel.split('\\')
        .filter(|s| !s.is_empty())
        .fold(root.to_path_buf(), |p, s| p.join(s))
}

impl TargetFs {
    /// Paths below `root` (for example `W:\`); `protect` applies
    /// [`FileProtection::SystemOnly`].
    #[must_use]
    pub fn new(root: &Path, protect: ProtectFn) -> Self {
        Self {
            root: root.to_path_buf(),
            protect,
        }
    }

    /// The root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The staging root, `<root>\$usgp-stage`.
    #[must_use]
    pub fn stage_root(&self) -> PathBuf {
        self.root.join(STAGE_ROOT)
    }

    /// The folder of one driver archive.
    #[must_use]
    pub fn stage_dir(&self, dir: &StagePath) -> PathBuf {
        join_backslashed(&self.root, &dir.relative())
    }

    /// A target file's path.
    #[must_use]
    pub fn target(&self, p: &TargetPath) -> PathBuf {
        join_backslashed(&self.root, &p.relative())
    }

    /// A sink that extracts into the folder `dir` names, which must not
    /// exist (the staging root and `drv` are created).
    ///
    /// # Errors
    ///
    /// The I/O error; `AlreadyExists` if the folder exists.
    pub fn stage_sink(&self, dir: &StagePath) -> io::Result<DirSink> {
        DirSink::create_fresh(&self.stage_dir(dir))
    }

    /// Removes the staging root and everything below it. Succeeds if it is
    /// absent. Does not follow links below the root (`remove_dir_all`).
    ///
    /// # Errors
    ///
    /// The I/O error.
    pub fn remove_staging(&self) -> io::Result<()> {
        match fs::remove_dir_all(self.stage_root()) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            r => r,
        }
    }

    /// `true` if anything (a file, folder or link) exists at the staging
    /// root's path.
    ///
    /// # Errors
    ///
    /// The I/O error, other than "not found".
    pub fn staging_exists(&self) -> io::Result<bool> {
        exists(&self.stage_root())
    }

    /// Creates `p` with `bytes` (create-new), its folders first, with its
    /// protection applied before the bytes are written.
    ///
    /// # Errors
    ///
    /// The I/O error; `AlreadyExists` if the file exists.
    pub fn write_new(&self, p: &TargetPath, bytes: &[u8]) -> io::Result<()> {
        let mut f = self.create_new(p)?;
        f.append(bytes)?;
        f.finish()
    }

    /// Creates `p` for writing in order (create-new), its folders first,
    /// with its protection applied before anything is written.
    ///
    /// # Errors
    ///
    /// The I/O error; `AlreadyExists` if the file exists.
    pub fn create_new(&self, p: &TargetPath) -> io::Result<NewFile> {
        let path = self.target(p);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let protect = p.protection() == FileProtection::SystemOnly;
        let file = open_new(&path, false, protect)?;
        if protect && let Err(e) = (self.protect)(&file) {
            drop(file);
            // Nothing was written; the unprotected empty file goes.
            let _ = fs::remove_file(&path);
            return Err(e);
        }
        Ok(NewFile { file, pos: 0 })
    }

    /// Creates the staged file of one driver archive (create-new; the
    /// staging root and `arc` are created), open for writing and reading.
    ///
    /// # Errors
    ///
    /// The I/O error; `AlreadyExists` if the file exists.
    pub fn stage_archive_file(&self, at: &StagedArchive) -> io::Result<NewFile> {
        let path = join_backslashed(&self.root, &at.relative());
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = open_new(&path, true, false)?;
        Ok(NewFile { file, pos: 0 })
    }
}

/// `true` if anything exists at `p` (links are not followed).
///
/// # Errors
///
/// The I/O error, other than "not found".
pub fn exists(p: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(p) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// Deletes the file at `p`; succeeds if it is absent.
///
/// # Errors
///
/// The I/O error.
pub fn delete_file(p: &Path) -> io::Result<()> {
    match fs::remove_file(p) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        r => r,
    }
}

// Windows access rights and share flags for `OpenOptionsExt` (the
// documented `ACCESS_MASK` bits and `FILE_SHARE_*` value; the agent has no
// direct `windows-sys` dependency, decision 0019).
#[cfg(windows)]
mod win {
    /// `GENERIC_READ`.
    pub const GENERIC_READ: u32 = 0x8000_0000;
    /// `GENERIC_WRITE`.
    pub const GENERIC_WRITE: u32 = 0x4000_0000;
    /// `READ_CONTROL`.
    pub const READ_CONTROL: u32 = 0x0002_0000;
    /// `WRITE_DAC`: needed to replace the file's DACL.
    pub const WRITE_DAC: u32 = 0x0004_0000;
    /// `FILE_SHARE_READ`: others may read, never write or delete.
    pub const FILE_SHARE_READ: u32 = 0x0000_0001;
}

/// Opens `path` create-new for writing (and reading when `read`), with
/// `WRITE_DAC` when it will be protected. On Windows others may only read
/// it while it is open.
fn open_new(path: &Path, read: bool, protect: bool) -> io::Result<File> {
    let mut o = OpenOptions::new();
    o.write(true).create_new(true).read(read);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        let mut access = win::GENERIC_WRITE;
        if read {
            access |= win::GENERIC_READ;
        }
        if protect {
            access |= win::WRITE_DAC | win::READ_CONTROL;
        }
        o.access_mode(access).share_mode(win::FILE_SHARE_READ);
    }
    #[cfg(not(windows))]
    let _ = protect;
    o.open(path)
}

/// Creates the file at `path` (create-new; its folder must exist) for
/// writing in order, applying `protect` before anything is written. A
/// protection failure removes the empty file.
///
/// # Errors
///
/// The I/O error; `AlreadyExists` if the file exists.
pub fn create_new_file(path: &Path, protect: Option<ProtectFn>) -> io::Result<NewFile> {
    let file = open_new(path, false, protect.is_some())?;
    if let Some(p) = protect
        && let Err(e) = p(&file)
    {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(e);
    }
    Ok(NewFile { file, pos: 0 })
}

/// Opens `path` for reading; on Windows nobody may write or delete it
/// while it is open.
///
/// # Errors
///
/// The I/O error.
pub fn open_read_only(path: &Path) -> io::Result<File> {
    let mut o = OpenOptions::new();
    o.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        o.share_mode(win::FILE_SHARE_READ);
    }
    o.open(path)
}

/// Reads exactly `buf.len()` bytes of `f` at `off` without using the
/// file's cursor.
///
/// # Errors
///
/// The I/O error; `UnexpectedEof` on a short file.
pub fn read_exact_at(f: &File, off: u64, buf: &mut [u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        FileExt::read_exact_at(f, buf, off)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let mut done = 0usize;
        while done < buf.len() {
            let at = off.saturating_add(u64::try_from(done).unwrap_or(u64::MAX));
            let rest = buf.get_mut(done..).unwrap_or_default();
            match f.seek_read(rest, at) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                Ok(n) => done = done.saturating_add(n),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// Writes all of `data` to `f` at `off` without using the file's cursor.
///
/// # Errors
///
/// The I/O error.
fn write_all_at(f: &File, off: u64, data: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        FileExt::write_all_at(f, data, off)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let mut done = 0usize;
        while done < data.len() {
            let at = off.saturating_add(u64::try_from(done).unwrap_or(u64::MAX));
            let rest = data.get(done..).unwrap_or_default();
            match f.seek_write(rest, at) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
                Ok(n) => done = done.saturating_add(n),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// A file created by [`TargetFs`]: written in order, readable by position
/// (staged archives).
#[derive(Debug)]
pub struct NewFile {
    file: File,
    pos: u64,
}

impl FileWriter for NewFile {
    fn append(&mut self, data: &[u8]) -> io::Result<()> {
        write_all_at(&self.file, self.pos, data)?;
        let n =
            u64::try_from(data.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        self.pos = self
            .pos
            .checked_add(n)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        Ok(())
    }

    fn finish(&mut self) -> io::Result<()> {
        self.file.sync_all()
    }
}

impl ReadAt for NewFile {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        read_exact_at(&self.file, offset, buf)
    }
}

/// A file opened read-only by position.
#[derive(Debug)]
pub struct FileReadAt(pub File);

impl ReadAt for FileReadAt {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        read_exact_at(&self.0, offset, buf)
    }
}

/// An extraction sink rooted at a folder this sink created. Archive paths
/// are joined segment by segment below it; every file is create-new.
#[derive(Debug)]
pub struct DirSink {
    root: PathBuf,
    current: Option<File>,
}

impl DirSink {
    /// Creates `dir` (its parents as needed); `dir` itself must not exist.
    ///
    /// # Errors
    ///
    /// The I/O error; `AlreadyExists` if `dir` exists.
    pub fn create_fresh(dir: &Path) -> io::Result<Self> {
        if let Some(parent) = dir.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::create_dir(dir)?;
        Ok(Self {
            root: dir.to_path_buf(),
            current: None,
        })
    }

    /// The folder.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn path(&self, p: &RelPath) -> PathBuf {
        p.segments().fold(self.root.clone(), |acc, s| acc.join(s))
    }
}

impl ExtractSink for DirSink {
    fn create_dir(&mut self, path: &RelPath) -> io::Result<()> {
        fs::create_dir_all(self.path(path))
    }

    fn begin_file(&mut self, path: &RelPath, _size: u64) -> io::Result<()> {
        if self.current.is_some() {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let p = self.path(path);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent)?;
        }
        self.current = Some(open_new(&p, false, false)?);
        Ok(())
    }

    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        self.current
            .as_mut()
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?
            .write_all(data)
    }

    fn end_file(&mut self) -> io::Result<()> {
        let f = self
            .current
            .take()
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        drop(f);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use usgp_deploy::platform::PostSetupFile;
    use usgp_wincfg::archive::testkit::{ZipBuilder, ZipEntrySpec};
    use usgp_wincfg::archive::{ArchiveLimits, ArchiveMode, extract_archive_mode};

    use super::*;

    static PROTECTED: AtomicUsize = AtomicUsize::new(0);

    fn count(_: &File) -> io::Result<()> {
        PROTECTED.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn refuse(_: &File) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    }

    fn temp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("usgp-tfs-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn target_files_are_create_new_and_protected_first() {
        let root = temp("target");
        let t = TargetFs::new(&root, count);
        let key = TargetPath::PostSetup(PostSetupFile::JobKey);
        let before = PROTECTED.load(Ordering::SeqCst);
        t.write_new(&key, b"k").unwrap();
        assert_eq!(PROTECTED.load(Ordering::SeqCst), before + 1);
        assert_eq!(
            fs::read(root.join("ProgramData/usgp/postsetup/job.key")).unwrap(),
            b"k"
        );
        let e = t.write_new(&key, b"other").unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            fs::read(root.join("ProgramData/usgp/postsetup/job.key")).unwrap(),
            b"k",
            "an existing file is left unchanged"
        );
        // An unprotected file does not call the hook.
        let before = PROTECTED.load(Ordering::SeqCst);
        t.write_new(&TargetPath::AnswerFile, b"<x/>").unwrap();
        assert_eq!(PROTECTED.load(Ordering::SeqCst), before);
        assert!(root.join("Windows/Panther/unattend.xml").is_file());
        // A protection failure leaves no file behind.
        let t = TargetFs::new(&temp("refuse"), refuse);
        assert!(t.write_new(&key, b"k").is_err());
        assert!(!exists(&t.target(&key)).unwrap());
    }

    #[test]
    fn staging_is_below_its_root_and_removed() {
        let root = temp("stage");
        let t = TargetFs::new(&root, count);
        let mut a = t.stage_archive_file(&StagedArchive::driver(2)).unwrap();
        a.append(b"hello ").unwrap();
        a.append(b"world").unwrap();
        a.finish().unwrap();
        let mut b = [0u8; 5];
        a.read_exact_at(6, &mut b).unwrap();
        assert_eq!(&b, b"world");
        assert!(a.read_exact_at(8, &mut b).is_err(), "short read refused");
        assert!(root.join("$usgp-stage/arc/2.bin").is_file());

        let mut s = t.stage_sink(&StagePath::driver(2)).unwrap();
        assert!(s.root().starts_with(t.stage_root()));
        let zip = ZipBuilder::default()
            .entry(ZipEntrySpec::stored("net/e1d.inf", b"inf"))
            .build();
        let len = u64::try_from(zip.len()).unwrap();
        extract_archive_mode(
            &zip.as_slice(),
            len,
            &ArchiveLimits::default(),
            ArchiveMode::Plain,
            &mut s,
        )
        .unwrap();
        assert_eq!(
            fs::read(root.join("$usgp-stage/drv/2/net/e1d.inf")).unwrap(),
            b"inf"
        );
        assert_eq!(
            t.stage_sink(&StagePath::driver(2)).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        drop(a);
        assert!(t.staging_exists().unwrap());
        t.remove_staging().unwrap();
        assert!(!t.staging_exists().unwrap());
        t.remove_staging().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn removal_does_not_follow_links() {
        let root = temp("links");
        let outside = temp("outside");
        fs::write(outside.join("keep"), b"x").unwrap();
        let t = TargetFs::new(&root, count);
        fs::create_dir_all(t.stage_root()).unwrap();
        std::os::unix::fs::symlink(&outside, t.stage_root().join("link")).unwrap();
        t.remove_staging().unwrap();
        assert!(outside.join("keep").is_file());
        assert!(!t.staging_exists().unwrap());
    }
}
