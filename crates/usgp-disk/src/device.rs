//! The block-device abstraction the writer and parser work through.
//!
//! The Windows backend (`usgp-winapi`/`usgp-deploy`) implements
//! [`BlockDevice`] for the chosen physical disk. This crate ships two
//! implementations for tests and simulation:
//!
//! - [`MemBlockDevice`]: sparse, in memory, any logical size;
//! - [`FileBlockDevice`]: a **regular file** used as a disk image. Opening
//!   anything that is not a regular file (a block or character device, a
//!   directory) is refused, so this type can never reach a real disk.
//!
//! All offsets and lengths must be whole logical sectors, as raw disk I/O
//! requires; a misaligned or out-of-range request is an error, never a
//! partial read or write.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - bounds on every I/O
// - NIST 800-53: CM-7 (Least Functionality) - test backend opens files only
// - SPEC: specs/disk.md#REQ-DISK-015 (only the chosen disk is written)

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

/// A disk addressed in bytes, in whole logical sectors.
pub trait BlockDevice {
    /// Device length in bytes.
    fn len(&self) -> u64;
    /// `true` if the device has no sectors.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Logical sector size in bytes.
    fn logical_sector(&self) -> u32;
    /// Reads exactly `buf.len()` bytes at `off`.
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> io::Result<()>;
    /// Writes all of `buf` at `off`.
    fn write_at(&mut self, off: u64, buf: &[u8]) -> io::Result<()>;
    /// Flushes written data to stable storage.
    fn flush(&mut self) -> io::Result<()>;
}

/// Checks that `[off, off + n)` is sector-aligned and inside `len`.
pub(crate) fn check_range(len: u64, sector: u32, off: u64, n: usize) -> io::Result<()> {
    let sector = u64::from(sector);
    let n = u64::try_from(n).map_err(|_| invalid("length out of range"))?;
    if sector == 0 || !off.is_multiple_of(sector) || !n.is_multiple_of(sector) {
        return Err(invalid("I/O not aligned to the logical sector"));
    }
    match off.checked_add(n) {
        Some(end) if end <= len => Ok(()),
        _ => Err(invalid("I/O past the end of the device")),
    }
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

/// Sparse in-memory disk: unwritten sectors read as zero. Holds only the
/// sectors written, so a 64 GB disk costs a few MiB in tests.
#[derive(Debug, Clone)]
pub struct MemBlockDevice {
    len: u64,
    sector: u32,
    /// Written sectors, keyed by LBA.
    blocks: BTreeMap<u64, Vec<u8>>,
    writes: u64,
}

impl MemBlockDevice {
    /// A zero-filled device of `len` bytes with `sector`-byte sectors.
    ///
    /// # Errors
    /// `InvalidInput` if `sector` is zero or `len` is not a multiple of it.
    pub fn new(len: u64, sector: u32) -> io::Result<Self> {
        if sector == 0 || !len.is_multiple_of(u64::from(sector)) {
            return Err(invalid("length not a multiple of the sector size"));
        }
        Ok(Self {
            len,
            sector,
            blocks: BTreeMap::new(),
            writes: 0,
        })
    }

    /// Number of `write_at` calls so far (tests use it to prove nothing was
    /// written).
    #[must_use]
    pub fn write_count(&self) -> u64 {
        self.writes
    }

    /// LBAs of every sector holding a non-zero byte.
    #[must_use]
    pub fn nonzero_lbas(&self) -> Vec<u64> {
        self.blocks
            .iter()
            .filter(|(_, b)| b.iter().any(|&x| x != 0))
            .map(|(&lba, _)| lba)
            .collect()
    }
}

impl BlockDevice for MemBlockDevice {
    fn len(&self) -> u64 {
        self.len
    }

    fn logical_sector(&self) -> u32 {
        self.sector
    }

    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> io::Result<()> {
        check_range(self.len, self.sector, off, buf.len())?;
        let sector = u64::from(self.sector);
        let mut lba = off / sector;
        let step = usize::try_from(self.sector).map_err(|_| invalid("sector size out of range"))?;
        for chunk in buf.chunks_mut(step) {
            match self.blocks.get(&lba) {
                Some(b) => chunk.copy_from_slice(b),
                None => chunk.fill(0),
            }
            lba = lba.saturating_add(1);
        }
        Ok(())
    }

    fn write_at(&mut self, off: u64, buf: &[u8]) -> io::Result<()> {
        check_range(self.len, self.sector, off, buf.len())?;
        self.writes = self.writes.saturating_add(1);
        let sector = u64::from(self.sector);
        let mut lba = off / sector;
        let step = usize::try_from(self.sector).map_err(|_| invalid("sector size out of range"))?;
        for chunk in buf.chunks(step) {
            if chunk.iter().all(|&b| b == 0) {
                self.blocks.remove(&lba);
            } else {
                self.blocks.insert(lba, chunk.to_vec());
            }
            lba = lba.saturating_add(1);
        }
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A disk image held in a regular file.
#[derive(Debug)]
pub struct FileBlockDevice {
    file: File,
    len: u64,
    sector: u32,
}

impl FileBlockDevice {
    /// Opens an existing regular file as a disk with `sector`-byte sectors.
    /// The device length is the file length.
    ///
    /// # Errors
    /// `InvalidInput` if the path is not a regular file (block and character
    /// devices are refused), or the length is not a multiple of `sector`.
    pub fn open(path: &Path, sector: u32, writable: bool) -> io::Result<Self> {
        // Check before opening, so a device node is never opened at all...
        if !std::fs::symlink_metadata(path)?.file_type().is_file() {
            return Err(invalid("not a regular file"));
        }
        let file = OpenOptions::new().read(true).write(writable).open(path)?;
        // ...and again on the handle, in case the path changed in between.
        let meta = file.metadata()?;
        if !meta.file_type().is_file() {
            return Err(invalid("not a regular file"));
        }
        let len = meta.len();
        if sector == 0 || !len.is_multiple_of(u64::from(sector)) {
            return Err(invalid("length not a multiple of the sector size"));
        }
        Ok(Self { file, len, sector })
    }

    /// Creates (or truncates) a sparse regular file of `len` bytes and opens
    /// it read-write.
    ///
    /// # Errors
    /// As [`FileBlockDevice::open`], plus file creation errors.
    pub fn create(path: &Path, len: u64, sector: u32) -> io::Result<Self> {
        if sector == 0 || !len.is_multiple_of(u64::from(sector)) {
            return Err(invalid("length not a multiple of the sector size"));
        }
        if let Ok(m) = std::fs::symlink_metadata(path)
            && !m.file_type().is_file()
        {
            return Err(invalid("not a regular file"));
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        file.set_len(len)?;
        drop(file);
        Self::open(path, sector, true)
    }
}

impl BlockDevice for FileBlockDevice {
    fn len(&self) -> u64 {
        self.len
    }

    fn logical_sector(&self) -> u32 {
        self.sector
    }

    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> io::Result<()> {
        check_range(self.len, self.sector, off, buf.len())?;
        self.file.seek(SeekFrom::Start(off))?;
        self.file.read_exact(buf)
    }

    fn write_at(&mut self, off: u64, buf: &[u8]) -> io::Result<()> {
        check_range(self.len, self.sector, off, buf.len())?;
        self.file.seek(SeekFrom::Start(off))?;
        self.file.write_all(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()?;
        self.file.sync_all()
    }
}
