//! The content store on disk: staging files for uploads and read-only,
//! SHA-256-addressed objects for Ready content, with a per-chunk verified
//! reader (plan M2 sections 1.1, 5.7 and 6).
//!
//! Layout under the configured root (0700):
//!
//! ```text
//! staging/<upload id>.part            0600, written once by an upload
//! objects/sha256/<2 hex>/<64 hex>     0440, renamed from staging at Ready
//! ```
//!
//! Every function here is blocking file I/O; callers run it on the
//! blocking pool. Nothing here trusts a file name it did not make: staging
//! names are checked against the upload-id form, object names are made
//! from digests.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7, SI-7(1) (Software, Firmware, and Information
//   Integrity) - every chunk verified against the signed manifest before
//   it is released; objects read-only once Ready.
// - NIST 800-53: AC-6 (Least Privilege), SC-28 basis - 0700 root, 0600
//   staging, 0440 objects.
// - NIST 800-53: SI-10 (Information Input Validation) - staging names
//   validated; sizes checked before reading.
// - SPEC: specs/os-images.md#REQ-IMG-035 (partial data removed),
//   #REQ-IMG-050 (verified before every use), #REQ-IMG-052 (Ready content
//   never changes in place)
// - SPEC: specs/preinstall-env.md#REQ-PE-008
// - Decision 0011 (integrity on every use)

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use usgp_common::Sha256Digest;
use usgp_crypto::CryptoProvider;
use usgp_proto::ContentManifestV1;

/// Directory mode of the root and its subdirectories.
const DIR_MODE: u32 = 0o700;
/// Mode of a staging file.
const STAGING_MODE: u32 = 0o600;
/// Mode of an object once Ready (read-only, REQ-IMG-052).
pub const OBJECT_MODE: u32 = 0o440;

/// Suffix of staging files.
const STAGING_SUFFIX: &str = ".part";

/// The content store.
#[derive(Debug, Clone)]
pub struct ContentStore {
    root: PathBuf,
}

/// True if `name` is `<36-char hyphenated lowercase uuid>.part`.
#[must_use]
pub fn is_staging_name(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(STAGING_SUFFIX) else {
        return false;
    };
    stem.len() == 36
        && stem.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
        })
}

/// The staging name of an upload.
#[must_use]
pub fn staging_name(upload_id: &impl std::fmt::Display) -> String {
    format!("{upload_id}{STAGING_SUFFIX}")
}

fn invalid(what: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, what)
}

fn mkdir(p: &Path) -> io::Result<()> {
    match fs::create_dir(p) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let meta = fs::symlink_metadata(p)?;
    if !meta.is_dir() {
        return Err(invalid("content store path is not a directory"));
    }
    fs::set_permissions(p, fs::Permissions::from_mode(DIR_MODE))
}

fn sync_dir(p: &Path) -> io::Result<()> {
    File::open(p)?.sync_all()
}

impl ContentStore {
    /// Opens (and creates if needed) the store at `root`.
    ///
    /// # Errors
    ///
    /// I/O errors creating or securing the directories.
    pub fn open(root: &Path) -> io::Result<Self> {
        mkdir(root)?;
        let s = Self {
            root: root.to_path_buf(),
        };
        mkdir(&s.staging_dir())?;
        mkdir(&root.join("objects"))?;
        mkdir(&s.objects_dir())?;
        Ok(s)
    }

    /// The root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn staging_dir(&self) -> PathBuf {
        self.root.join("staging")
    }

    fn objects_dir(&self) -> PathBuf {
        self.root.join("objects").join("sha256")
    }

    /// Path of a staging file.
    ///
    /// # Errors
    ///
    /// `InvalidInput` unless `name` is a staging name.
    pub fn staging_path(&self, name: &str) -> io::Result<PathBuf> {
        if !is_staging_name(name) {
            return Err(invalid("not a staging name"));
        }
        Ok(self.staging_dir().join(name))
    }

    /// Path of the object with this digest.
    #[must_use]
    pub fn object_path(&self, sha256: &Sha256Digest) -> PathBuf {
        let hex = sha256.to_hex();
        let prefix = hex.get(..2).unwrap_or("00").to_owned();
        self.objects_dir().join(prefix).join(hex)
    }

    /// Creates a new staging file (never an existing one; 0600, no
    /// symlink followed).
    ///
    /// # Errors
    ///
    /// I/O errors, including `AlreadyExists`.
    pub fn create_staging(&self, name: &str) -> io::Result<File> {
        let p = self.staging_path(name)?;
        // create_new is O_CREAT|O_EXCL: it fails on any existing path,
        // a symlink included (POSIX open(2)).
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(STAGING_MODE)
            .open(p)
    }

    /// Removes a staging file if it exists (REQ-IMG-035).
    ///
    /// # Errors
    ///
    /// I/O errors other than `NotFound`.
    pub fn remove_staging(&self, name: &str) -> io::Result<()> {
        match fs::remove_file(self.staging_path(name)?) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }

    /// Moves a checked staging file to its object path, makes it
    /// read-only (0440) and syncs both directories. The caller has
    /// checked the digest.
    ///
    /// # Errors
    ///
    /// I/O errors; the staging file is left in place on failure.
    pub fn finalise(&self, name: &str, sha256: &Sha256Digest) -> io::Result<PathBuf> {
        let from = self.staging_path(name)?;
        let to = self.object_path(sha256);
        let dir = to
            .parent()
            .ok_or_else(|| invalid("object path has no parent"))?
            .to_path_buf();
        mkdir(&dir)?;
        fs::set_permissions(&from, fs::Permissions::from_mode(OBJECT_MODE))?;
        fs::rename(&from, &to)?;
        sync_dir(&dir)?;
        sync_dir(&self.staging_dir())?;
        Ok(to)
    }

    /// Unlinks an object (after the deletion is committed).
    ///
    /// # Errors
    ///
    /// I/O errors other than `NotFound`.
    pub fn remove_object(&self, sha256: &Sha256Digest) -> io::Result<()> {
        match fs::remove_file(self.object_path(sha256)) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }

    /// Every file name in `staging/`.
    ///
    /// # Errors
    ///
    /// I/O errors reading the directory.
    pub fn list_staging(&self) -> io::Result<Vec<String>> {
        let mut out = Vec::new();
        for e in fs::read_dir(self.staging_dir())? {
            out.push(e?.file_name().to_string_lossy().into_owned());
        }
        Ok(out)
    }

    /// The digest of every object file (files whose names are not a
    /// digest in the right directory are reported as `None`).
    ///
    /// # Errors
    ///
    /// I/O errors reading the directories.
    pub fn list_objects(&self) -> io::Result<Vec<Result<Sha256Digest, PathBuf>>> {
        let mut out = Vec::new();
        for d in fs::read_dir(self.objects_dir())? {
            let d = d?;
            if !d.file_type()?.is_dir() {
                out.push(Err(d.path()));
                continue;
            }
            let prefix = d.file_name().to_string_lossy().into_owned();
            for f in fs::read_dir(d.path())? {
                let f = f?;
                let name = f.file_name().to_string_lossy().into_owned();
                match Sha256Digest::from_hex(&name) {
                    Ok(dg) if name.get(..2) == Some(prefix.as_str()) => out.push(Ok(dg)),
                    _ => out.push(Err(f.path())),
                }
            }
        }
        Ok(out)
    }

    /// Opens an object for a verified read against `manifest` (the
    /// manifest's signature has already been verified). Refuses if the
    /// file's length differs from the manifest's size.
    ///
    /// # Errors
    ///
    /// [`VerifyError`].
    pub fn open_verified(
        &self,
        manifest: &ContentManifestV1,
    ) -> Result<VerifiedReader, VerifyError> {
        let path = self.object_path(&manifest.sha256);
        // Never follow a symlink planted in the store: the link itself is
        // refused, and the opened handle must be a regular file.
        let link = fs::symlink_metadata(&path).map_err(VerifyError::Io)?;
        if !link.is_file() {
            // Something other than the object was put in its place: an
            // integrity failure, not a read error.
            return Err(VerifyError::NotRegularFile);
        }
        let file = File::open(&path).map_err(VerifyError::Io)?;
        let meta = file.metadata().map_err(VerifyError::Io)?;
        if !meta.is_file() || meta.len() != manifest.size {
            return Err(VerifyError::SizeMismatch {
                expected: manifest.size,
                found: meta.len(),
            });
        }
        Ok(VerifiedReader {
            file,
            chunks: manifest.chunk_sha256.clone(),
            size: manifest.size,
            next: 0,
            total: usgp_crypto::provider().sha256_hasher(),
            expected_total: manifest.sha256,
        })
    }
}

/// Why a verified read stopped.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// The object could not be read.
    #[error("content object could not be read")]
    Io(#[source] io::Error),
    /// The object's length differs from the signed size.
    #[error("content object is {found} bytes; the signed manifest says {expected}")]
    SizeMismatch {
        /// Signed size.
        expected: u64,
        /// Size on disk.
        found: u64,
    },
    /// A chunk's SHA-256 differs from the signed one.
    #[error("content chunk {index} does not match its signed digest")]
    ChunkMismatch {
        /// 0-based chunk index.
        index: u64,
    },
    /// Every chunk matched but the whole-file digest did not (only
    /// possible if the manifest itself is inconsistent).
    #[error("content does not match its signed total digest")]
    TotalMismatch,
    /// The object's path names a symbolic link or another non-file.
    #[error("content object is not a regular file")]
    NotRegularFile,
}

impl VerifyError {
    /// True if this is an integrity failure (as opposed to an I/O error).
    #[must_use]
    pub const fn is_integrity(&self) -> bool {
        !matches!(self, Self::Io(_))
    }
}

/// Reads an object one chunk at a time and releases each chunk only after
/// its SHA-256 matched the signed manifest (plan section 5.7).
pub struct VerifiedReader {
    file: File,
    chunks: Vec<Sha256Digest>,
    size: u64,
    next: u64,
    total: usgp_crypto::Sha256Hasher,
    expected_total: Sha256Digest,
}

impl std::fmt::Debug for VerifiedReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedReader")
            .field("size", &self.size)
            .field("next", &self.next)
            .finish_non_exhaustive()
    }
}

impl VerifiedReader {
    /// Total size.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// The next verified chunk, or `None` after the last one (when the
    /// whole-file digest has also been checked).
    ///
    /// # Errors
    ///
    /// [`VerifyError`]; nothing of a failing chunk is returned.
    pub fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, VerifyError> {
        let Some(len) = usgp_proto::content_manifest::chunk_len(self.size, self.next) else {
            // Past the end: the file must end here too.
            let mut probe = [0u8; 1];
            if self.file.read(&mut probe).map_err(VerifyError::Io)? != 0 {
                return Err(VerifyError::SizeMismatch {
                    expected: self.size,
                    found: self.size.saturating_add(1),
                });
            }
            let total = std::mem::replace(&mut self.total, usgp_crypto::provider().sha256_hasher())
                .finish();
            if total != self.expected_total {
                return Err(VerifyError::TotalMismatch);
            }
            return Ok(None);
        };
        let index = self.next;
        let want = usize::try_from(index)
            .ok()
            .and_then(|i| self.chunks.get(i))
            .copied()
            .ok_or(VerifyError::ChunkMismatch { index })?;
        let n = usize::try_from(len).map_err(|_| VerifyError::ChunkMismatch { index })?;
        let mut buf = vec![0u8; n];
        self.file.read_exact(&mut buf).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                VerifyError::SizeMismatch {
                    expected: self.size,
                    found: 0,
                }
            } else {
                VerifyError::Io(e)
            }
        })?;
        let got = usgp_crypto::provider().sha256(&buf);
        if got != want {
            return Err(VerifyError::ChunkMismatch { index });
        }
        self.total.update(&buf);
        self.next = self.next.saturating_add(1);
        Ok(Some(buf))
    }
}

/// Writes an upload body to a staging file while hashing it in one pass
/// (total and per-chunk SHA-256, REQ-IMG-050).
pub struct StagingWriter {
    file: io::BufWriter<File>,
    hasher: usgp_image::chunks::ContentHasher<'static>,
}

impl std::fmt::Debug for StagingWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StagingWriter")
            .field("hasher", &self.hasher)
            .finish_non_exhaustive()
    }
}

/// Buffer size of the staging writer.
const WRITE_BUF: usize = 1024 * 1024;

impl StagingWriter {
    /// A writer on a new staging file.
    #[must_use]
    pub fn new(file: File) -> Self {
        let crypto: &'static dyn CryptoProvider = usgp_crypto::provider();
        Self {
            file: io::BufWriter::with_capacity(WRITE_BUF, file),
            hasher: usgp_image::chunks::ContentHasher::new(crypto),
        }
    }

    /// Bytes written so far.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.hasher.size()
    }

    /// True before any byte is written.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Appends `data`.
    ///
    /// # Errors
    ///
    /// I/O errors.
    pub fn write(&mut self, data: &[u8]) -> io::Result<()> {
        self.file.write_all(data)?;
        self.hasher.update(data);
        Ok(())
    }

    /// Flushes and syncs the file, returning the digests.
    ///
    /// # Errors
    ///
    /// I/O errors.
    pub fn finish(self) -> io::Result<usgp_image::chunks::ContentDigests> {
        let file = self
            .file
            .into_inner()
            .map_err(io::IntoInnerError::into_error)?;
        file.sync_all()?;
        Ok(self.hasher.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staging_names() {
        assert!(is_staging_name("0b7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e6f.part"));
        for bad in [
            "0b7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e6f",
            "../b7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e6f.part",
            "0B7C2F4E-9A1D-4C3B-8E6F-1A2B3C4D5E6F.part",
            "0b7c2f4e09a1d-4c3b-8e6f-1a2b3c4d5e6f.part",
            "x.part",
            "",
        ] {
            assert!(!is_staging_name(bad), "{bad}");
        }
    }
}
