//! `usgp-cli boot-manifest create | verify` (plan WU-7, sections 3.3 and 5).
//!
//! `create` reads each named file under the boot root, hashes it with
//! SHA-256 through `usgp-crypto`, and writes a new version-1 manifest
//! (`usgp_proto::BootManifest`). It never overwrites an existing file.
//! `verify` reads a manifest and checks every listed file's size and
//! digest against the bytes on disk.
//!
//! Boot files are read the way the relay is required to read them (plan
//! section 5, step 3): regular files only, never through a symbolic link,
//! and size-bounded. This tool additionally refuses symbolic links in the
//! directory part of a name, so a manifest cannot describe a file outside
//! the boot root.
//!
//! M3 (plan WU-13): `create --pe-kit` also writes the `[pe_kit]` section
//! the relay reads (see [`crate::pe_kit`]). The kit files are hashed and
//! listed like any other published file; the boot program must be a UEFI
//! x64 application; the WIM's digest and size must equal a Ready x64 PE
//! on the server, read over the operator's mTLS connection before the
//! manifest is written; the memory the PE needs is printed (REQ-PE-018).
//! The BCD is never generated or edited (decision 0018 item 3). `verify`
//! reads either format and, for a kit, also checks completeness, the WIM
//! digest binding and the boot program's architecture.
//!
//! Every run that gets past argument parsing emits one audit event
//! (`boot_manifest.created` or `boot_manifest.verify`, plan section 7).
//! There is no operator authentication until M2. "Who" is recorded as the
//! process's effective uid and (on Linux) real uid, read from the kernel,
//! plus the user name claimed by the environment (`env_user_claimed`),
//! which any caller can set and is not evidence of identity.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity) -
//   produces and checks the reference digests the relay verifies before
//   serving.
// - NIST 800-53: SC-13 (Cryptographic Protection) - SHA-256 only through the
//   FIPS module (`usgp_crypto::sha256`, decision 0001).
// - NIST 800-53: SI-10 (Information Input Validation) - names validated by
//   `BootFileName`; regular files only; sizes bounded.
// - NIST 800-53: AU-2, AU-3, AU-12 - one audit event per create or verify.
// - SPEC: specs/boot-network.md#REQ-BOOT-041 (published files only),
//   #REQ-BOOT-052 (missing or tampered content is detected)
// - SPEC: specs/preinstall-env.md#REQ-PE-012 (kit complete, matches the
//   imported PE and its architecture, BCD never generated), #REQ-PE-018
//   (memory requirement shown before the kit is offered)
// - SPEC: specs/standards/winpe.md §10 (PE/COFF Machine field, SR-2)

// POAM: SI-7 - the manifest written here is not signed. The relay accepts
// it only if it is owned by root or the configured administrator uid, is
// not group- or world-writable, and every directory above it is owned by
// root or that uid and not group- or world-writable unless sticky
// (usgp_common::config::read_trusted; ACLs not inspected). This tool does
// not set ownership; the operator installs the file. M2 adds a
// server-signed manifest.
// POAM: AU-3 / IA-2 - "who" in cli audit events is the OS uid (effective;
// real uid on Linux) with no operator authentication; operator
// authentication arrives in M2.

use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use usgp_common::Sha256Digest;
use usgp_common::config::{ConfigError, read_bounded};
use usgp_common::event::{AuditEvent, Outcome, emit};
use usgp_proto::api::PeView;
use usgp_proto::boot_manifest::{MAX_FILE_SIZE, MAX_MANIFEST_BYTES};
use usgp_proto::facts::Architecture;
use usgp_proto::ids::ContentId;
use usgp_proto::status::ContentState;
use usgp_proto::{BootFileName, BootFileNameError, BootManifest, ManifestEntry, ManifestError};

use crate::args::{CreateArgs, KitCreateArgs, VerifyArgs};
use crate::display::esc;
use crate::pe_kit::{
    self, KitManifestError, KitShapeError, PeCoffError, PeKit, check_boot_program, memory_required,
};

/// Component name in audit events.
pub const COMPONENT: &str = "usgp-cli";

/// Longest claimed user name copied into an audit event.
const MAX_USER_CHARS: usize = 256;

/// Why one boot file could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FileError {
    /// The file (or a directory on its path) does not exist.
    #[error("does not exist")]
    Missing,
    /// The file is a symbolic link.
    #[error("is a symbolic link")]
    Symlink,
    /// A directory on the path is a symbolic link.
    #[error("has a symbolic link in its directory path")]
    SymlinkedDirectory,
    /// The file is not a regular file, or a path component is not a
    /// directory.
    #[error("is not a regular file")]
    NotRegular,
    /// The file is larger than the manifest allows.
    #[error("is larger than the {MAX_FILE_SIZE}-byte limit")]
    TooLarge,
    /// The file was replaced or changed size while it was being read.
    #[error("changed while it was being read")]
    Changed,
    /// Another I/O error (the OS message is omitted).
    #[error("cannot be read: {0}")]
    Io(io::ErrorKind),
}

/// A failed `create` or `verify`.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// The output manifest already exists.
    #[error("{} already exists; refusing to overwrite it", .0.display())]
    OutputExists(PathBuf),
    /// A requested name is not valid UTF-8.
    #[error("name #{index} is not valid UTF-8")]
    NameNotUtf8 {
        /// 1-based position among the names.
        index: usize,
    },
    /// A requested name breaks the `BootFileName` rules.
    #[error("name #{index} ({shown}) is not a valid boot file name: {source}")]
    InvalidName {
        /// 1-based position among the names.
        index: usize,
        /// The name, escaped for display.
        shown: String,
        /// The rule that failed.
        #[source]
        source: BootFileNameError,
    },
    /// The boot root is missing or not a directory.
    #[error("boot root {} is not a directory", .0.display())]
    RootNotDirectory(PathBuf),
    /// A boot file could not be read.
    #[error("{name} {reason}")]
    File {
        /// The file.
        name: BootFileName,
        /// Why.
        reason: FileError,
    },
    /// The manifest built or read breaks a manifest rule.
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    /// The manifest file could not be read.
    #[error(transparent)]
    Read(#[from] ConfigError),
    /// The manifest could not be written.
    #[error("cannot write {}: {kind}", path.display())]
    Write {
        /// The output file.
        path: PathBuf,
        /// The I/O error kind.
        kind: io::ErrorKind,
    },
    /// One or more files did not match the manifest.
    #[error("{failed} of {total} files do not match the manifest")]
    Mismatch {
        /// Files that failed.
        failed: usize,
        /// Files in the manifest.
        total: usize,
    },
    /// The `[pe_kit]` section breaks a shape rule.
    #[error(transparent)]
    KitShape(#[from] KitShapeError),
    /// A `--boot-program`, `--bcd`, `--sdi`, `--wim` or `--font` value is
    /// not a valid boot file name.
    #[error("--{role} ({shown}) is not a valid boot file name: {reason}")]
    InvalidKitName {
        /// The option, without dashes.
        role: &'static str,
        /// The value, escaped for display.
        shown: String,
        /// The rule that failed (or "not valid UTF-8").
        reason: String,
    },
    /// `--pe` is not an identifier.
    #[error("--pe {0} is not a PE kit identifier")]
    InvalidPeId(String),
    /// The boot program is not a UEFI x64 application.
    #[error("boot program {name} {reason}")]
    BootProgram {
        /// The file.
        name: BootFileName,
        /// The rule that failed.
        reason: PeCoffError,
    },
    /// The kit is incomplete or does not match the manifest (verify).
    #[error("the pe_kit section has {0} problem(s)")]
    KitMismatch(usize),
    /// The server could not be asked about the PE (connection, setup or
    /// refusal). The text is the client's, already escaped.
    #[error("cannot read PE kit from the server: {0}")]
    PeLookup(String),
    /// The server's PE is not the kit's WIM or not usable for x64.
    #[error("PE kit {id} on the server does not match: {reason}")]
    PeMismatch {
        /// The PE.
        id: ContentId,
        /// Why.
        reason: String,
    },
}

impl From<KitManifestError> for CliError {
    fn from(e: KitManifestError) -> Self {
        match e {
            KitManifestError::Manifest(m) => Self::Manifest(m),
            KitManifestError::Shape(s) => Self::KitShape(s),
        }
    }
}

impl CliError {
    /// Audit outcome: refusals by rule are `refused`, everything else is
    /// `failure`.
    #[must_use]
    pub const fn outcome(&self) -> Outcome {
        match self {
            Self::OutputExists(_)
            | Self::NameNotUtf8 { .. }
            | Self::InvalidName { .. }
            | Self::RootNotDirectory(_)
            | Self::File { .. }
            | Self::Manifest(_)
            | Self::KitShape(_)
            | Self::InvalidKitName { .. }
            | Self::InvalidPeId(_)
            | Self::BootProgram { .. }
            | Self::PeMismatch { .. } => Outcome::Refused,
            Self::Read(_)
            | Self::Write { .. }
            | Self::Mismatch { .. }
            | Self::KitMismatch(_)
            | Self::PeLookup(_) => Outcome::Failure,
        }
    }
}

/// Why one manifest entry failed verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryFailure {
    /// The file could not be read.
    File(FileError),
    /// The size differs from the manifest.
    Size {
        /// Size in the manifest.
        expected: u64,
        /// Size on disk.
        actual: u64,
    },
    /// The digest differs from the manifest.
    Digest {
        /// Digest in the manifest.
        expected: Sha256Digest,
        /// Digest of the bytes on disk.
        actual: Sha256Digest,
    },
}

impl fmt::Display for EntryFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File(e) => write!(f, "{e}"),
            Self::Size { expected, actual } => {
                write!(f, "size {actual} does not match manifest size {expected}")
            }
            Self::Digest { expected, actual } => {
                write!(
                    f,
                    "sha256 {actual} does not match manifest sha256 {expected}"
                )
            }
        }
    }
}

/// Result of a successful `create`.
#[derive(Debug)]
pub struct Created {
    /// The manifest written.
    pub manifest: BootManifest,
    /// SHA-256 of the manifest text written.
    pub manifest_sha256: Sha256Digest,
}

/// Result of reading a manifest and checking its files.
#[derive(Debug)]
pub struct Verified {
    /// SHA-256 of the manifest text read.
    pub manifest_sha256: Sha256Digest,
    /// Every entry with its result, in manifest order.
    pub entries: Vec<(BootFileName, Result<(), EntryFailure>)>,
    /// `Some` if the manifest has a `[pe_kit]` section: each problem
    /// found with the kit (empty when it is complete and matches).
    pub kit_problems: Option<Vec<String>>,
}

impl Verified {
    /// Number of failed entries.
    #[must_use]
    pub fn failed(&self) -> usize {
        self.entries.iter().filter(|(_, r)| r.is_err()).count()
    }
}

fn io_file_error(e: &io::Error) -> FileError {
    match e.kind() {
        io::ErrorKind::NotFound => FileError::Missing,
        k => FileError::Io(k),
    }
}

fn open_file_error(e: &io::Error) -> FileError {
    #[cfg(unix)]
    if e.raw_os_error() == Some(libc::ELOOP) {
        return FileError::Symlink;
    }
    io_file_error(e)
}

/// Opens `path` read-only without following a final symbolic link and
/// without blocking on a FIFO.
fn open_no_follow(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    options.open(path)
}

/// Reads boot file `name` under `root`: no symbolic link anywhere below
/// the root, regular file only, at most [`MAX_FILE_SIZE`] bytes, and the
/// opened file must be the one that was checked.
///
/// # Errors
///
/// [`FileError`] for the first rule that fails.
pub fn read_boot_file(root: &Path, name: &BootFileName) -> Result<Vec<u8>, FileError> {
    // Directory components: each must be a real directory, not a link.
    let mut dir = root.to_path_buf();
    let mut components = name.as_str().split('/').peekable();
    let mut file_component = "";
    while let Some(c) = components.next() {
        if components.peek().is_none() {
            file_component = c;
            break;
        }
        dir.push(c);
        let m = fs::symlink_metadata(&dir).map_err(|e| io_file_error(&e))?;
        if m.file_type().is_symlink() {
            return Err(FileError::SymlinkedDirectory);
        }
        if !m.is_dir() {
            return Err(FileError::NotRegular);
        }
    }
    let path = dir.join(file_component);

    let checked = fs::symlink_metadata(&path).map_err(|e| io_file_error(&e))?;
    if checked.file_type().is_symlink() {
        return Err(FileError::Symlink);
    }
    if !checked.is_file() {
        return Err(FileError::NotRegular);
    }
    if checked.len() > MAX_FILE_SIZE {
        return Err(FileError::TooLarge);
    }

    // O_NOFOLLOW / O_NONBLOCK: a file swapped for a link or a FIFO after
    // the check above is refused or not blocked on; the identity check
    // below catches any other replacement.
    let mut file = open_no_follow(&path).map_err(|e| open_file_error(&e))?;
    let opened = file.metadata().map_err(|e| io_file_error(&e))?;
    if !opened.is_file() {
        return Err(FileError::NotRegular);
    }
    if !same_file(&checked, &opened) {
        return Err(FileError::Changed);
    }
    if opened.len() > MAX_FILE_SIZE {
        return Err(FileError::TooLarge);
    }

    let capacity = usize::try_from(opened.len()).map_err(|_| FileError::TooLarge)?;
    let mut buf = Vec::with_capacity(capacity);
    (&mut file)
        .take(MAX_FILE_SIZE.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| io_file_error(&e))?;
    let read = u64::try_from(buf.len()).map_err(|_| FileError::TooLarge)?;
    if read > MAX_FILE_SIZE {
        return Err(FileError::TooLarge);
    }
    if read != opened.len() {
        return Err(FileError::Changed);
    }
    Ok(buf)
}

#[cfg(unix)]
fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}

#[cfg(not(unix))]
fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.len() == b.len()
}

fn ensure_root(root: &Path) -> Result<(), CliError> {
    match fs::metadata(root) {
        Ok(m) if m.is_dir() => Ok(()),
        _ => Err(CliError::RootNotDirectory(root.to_path_buf())),
    }
}

fn validate_names(names: &[OsString]) -> Result<Vec<BootFileName>, CliError> {
    names
        .iter()
        .enumerate()
        .map(|(i, raw)| {
            let index = i.saturating_add(1);
            let text = raw.to_str().ok_or(CliError::NameNotUtf8 { index })?;
            BootFileName::try_from(text).map_err(|source| CliError::InvalidName {
                index,
                shown: format!("{text:?}"),
                source,
            })
        })
        .collect()
}

/// `boot-manifest create`: hashes the named files and writes a new
/// manifest to `args.out`.
///
/// # Errors
///
/// [`CliError`] for the first failure; on any error no manifest is left
/// behind.
pub fn create(args: &CreateArgs) -> Result<Created, CliError> {
    let names = validate_names(&args.names)?;
    // Fail fast before hashing; `create_new` below is the real guarantee.
    if fs::symlink_metadata(&args.out).is_ok() {
        return Err(CliError::OutputExists(args.out.clone()));
    }
    ensure_root(&args.root)?;

    let mut files = Vec::with_capacity(names.len());
    for name in names {
        let bytes = read_boot_file(&args.root, &name).map_err(|reason| CliError::File {
            name: name.clone(),
            reason,
        })?;
        let size = u64::try_from(bytes.len()).map_err(|_| CliError::File {
            name: name.clone(),
            reason: FileError::TooLarge,
        })?;
        let sha256 = usgp_crypto::sha256(&bytes);
        files.push(ManifestEntry { name, size, sha256 });
    }
    let manifest = BootManifest::new(files)?;
    let text = manifest.to_toml();
    let manifest_sha256 = usgp_crypto::sha256(text.as_bytes());
    write_new(&args.out, text.as_bytes())?;
    Ok(Created {
        manifest,
        manifest_sha256,
    })
}

/// Result of a successful `create --pe-kit`.
#[derive(Debug)]
pub struct KitCreated {
    /// The manifest and its digest.
    pub created: Created,
    /// The kit section written.
    pub kit: PeKit,
    /// The WIM's size in bytes.
    pub wim_size: u64,
    /// Memory a device needs to start this PE (REQ-PE-018).
    pub memory_required: u64,
}

/// How `create --pe-kit` reads a PE kit's record from the server. The
/// error text is shown to the operator and recorded in the audit event.
pub type PeLookup<'a> = dyn FnMut(ContentId) -> Result<PeView, String> + 'a;

/// One kit name given on the command line.
fn kit_name(role: &'static str, raw: &OsString) -> Result<BootFileName, CliError> {
    let Some(text) = raw.to_str() else {
        return Err(CliError::InvalidKitName {
            role,
            shown: format!("{raw:?}"),
            reason: "not valid UTF-8".into(),
        });
    };
    BootFileName::try_from(text).map_err(|e| CliError::InvalidKitName {
        role,
        shown: format!("{text:?}"),
        reason: e.to_string(),
    })
}

/// Checks the server's record of the PE against the kit's WIM: the same
/// id, Ready, the same SHA-256 and size, and x64 (REQ-PE-012).
fn check_pe(
    id: ContentId,
    v: &PeView,
    wim_sha256: &Sha256Digest,
    wim_size: u64,
) -> Result<(), CliError> {
    let refuse = |reason: String| Err(CliError::PeMismatch { id, reason });
    if v.id != id {
        return refuse("the server returned a different PE kit".into());
    }
    if v.state != ContentState::Ready {
        return refuse(format!("it is {}, not ready", v.state));
    }
    match &v.sha256 {
        Some(d) if d == wim_sha256 => {}
        Some(d) => {
            return refuse(format!("its sha256 is {d}; the kit's WIM is {wim_sha256}"));
        }
        None => return refuse("the server has no verified sha256 for it".into()),
    }
    if v.size != wim_size {
        return refuse(format!(
            "its size is {} bytes; the kit's WIM is {wim_size} bytes",
            v.size
        ));
    }
    if v.architecture.value != Architecture::X64 {
        return refuse(format!(
            "its architecture is {}, not x64",
            v.architecture.value
        ));
    }
    Ok(())
}

/// `boot-manifest create --pe-kit`: hashes the named files and the kit
/// files, checks the boot program, binds the WIM to a Ready x64 PE on the
/// server through `lookup`, and writes a new manifest with `[pe_kit]` to
/// `args.create.out`. The BCD is hashed as an opaque file, never built.
///
/// # Errors
///
/// [`CliError`] for the first failure; on any error no manifest is left
/// behind and `lookup` is not called before every local check passed.
pub fn create_kit(args: &KitCreateArgs, lookup: &mut PeLookup<'_>) -> Result<KitCreated, CliError> {
    let c = &args.create;
    let mut names = validate_names(&c.names)?;
    let pe_id = ContentId::parse(&args.pe).map_err(|_| CliError::InvalidPeId(esc(&args.pe)))?;
    let mut kit = PeKit {
        boot_program: kit_name("boot-program", &args.boot_program)?,
        bcd: kit_name("bcd", &args.bcd)?,
        sdi: kit_name("sdi", &args.sdi)?,
        wim: kit_name("wim", &args.wim)?,
        fonts: args
            .fonts
            .iter()
            .map(|f| kit_name("font", f))
            .collect::<Result<_, _>>()?,
        // Replaced by the WIM's digest once it is hashed.
        pe_content_sha256: usgp_crypto::sha256(b""),
    };
    kit.check_shape()?;
    if fs::symlink_metadata(&c.out).is_ok() {
        return Err(CliError::OutputExists(c.out.clone()));
    }
    ensure_root(&c.root)?;

    // Every kit file is a published file; one listed as NAME too is
    // listed once.
    for (_, n) in kit.files() {
        if !names.contains(n) {
            names.push(n.clone());
        }
    }
    let mut files = Vec::with_capacity(names.len());
    let mut wim: Option<(Sha256Digest, u64)> = None;
    for name in names {
        let bytes = read_boot_file(&c.root, &name).map_err(|reason| CliError::File {
            name: name.clone(),
            reason,
        })?;
        let size = u64::try_from(bytes.len()).map_err(|_| CliError::File {
            name: name.clone(),
            reason: FileError::TooLarge,
        })?;
        if name == kit.boot_program {
            check_boot_program(&bytes).map_err(|reason| CliError::BootProgram {
                name: name.clone(),
                reason,
            })?;
        }
        let sha256 = usgp_crypto::sha256(&bytes);
        if name == kit.wim {
            wim = Some((sha256, size));
        }
        files.push(ManifestEntry { name, size, sha256 });
    }
    let (wim_sha256, wim_size) = wim.ok_or(CliError::KitMismatch(1))?;
    kit.pe_content_sha256 = wim_sha256;
    let manifest = BootManifest::new(files)?;
    let problems = pe_kit::assess(&kit, &manifest);
    if !problems.is_empty() {
        return Err(CliError::KitMismatch(problems.len()));
    }

    let view = lookup(pe_id).map_err(CliError::PeLookup)?;
    check_pe(pe_id, &view, &wim_sha256, wim_size)?;

    let text = pe_kit::to_toml(&manifest, &kit);
    // Self-check: the text reads back as exactly what was built, through
    // the same rules the relay applies.
    match pe_kit::parse_manifest(&text) {
        Ok((m, Some(k))) if m == manifest && k == kit => {}
        Ok(_) => return Err(CliError::KitMismatch(1)),
        Err(e) => return Err(e.into()),
    }
    let manifest_sha256 = usgp_crypto::sha256(text.as_bytes());
    write_new(&c.out, text.as_bytes())?;
    Ok(KitCreated {
        created: Created {
            manifest,
            manifest_sha256,
        },
        kit,
        wim_size,
        memory_required: memory_required(wim_size),
    })
}

/// Writes `bytes` to a file that must not exist yet (mode 0644 on Unix:
/// the relay refuses a world-writable manifest). Removes the file again if
/// writing fails.
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o644);
    }
    let mut file = opts.open(path).map_err(|e| match e.kind() {
        io::ErrorKind::AlreadyExists => CliError::OutputExists(path.to_path_buf()),
        kind => CliError::Write {
            path: path.to_path_buf(),
            kind,
        },
    })?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    if let Err(e) = written {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(CliError::Write {
            path: path.to_path_buf(),
            kind: e.kind(),
        });
    }
    Ok(())
}

/// `boot-manifest verify`: reads the manifest and checks every entry.
///
/// # Errors
///
/// [`CliError`] if the manifest cannot be read or is invalid, or the root
/// is not a directory. File mismatches are reported in [`Verified`], not
/// as an error.
pub fn verify(args: &VerifyArgs) -> Result<Verified, CliError> {
    let limit = u64::try_from(MAX_MANIFEST_BYTES).unwrap_or(u64::MAX);
    let text = read_bounded(&args.manifest, limit)?;
    let manifest_sha256 = usgp_crypto::sha256(text.as_bytes());
    let (manifest, kit) = pe_kit::parse_manifest(&text)?;
    ensure_root(&args.root)?;
    let entries: Vec<_> = manifest
        .files
        .iter()
        .map(|entry| (entry.name.clone(), check_entry(&args.root, entry)))
        .collect();
    let kit_problems = kit.map(|k| kit_problems(&args.root, &k, &manifest, &entries));
    Ok(Verified {
        manifest_sha256,
        entries,
        kit_problems,
    })
}

/// The kit checks of `verify`: completeness and the WIM binding
/// ([`pe_kit::assess`]), then the boot program's architecture if its file
/// matched the manifest (a file that did not is already a failure).
fn kit_problems(
    root: &Path,
    kit: &PeKit,
    manifest: &BootManifest,
    entries: &[(BootFileName, Result<(), EntryFailure>)],
) -> Vec<String> {
    let mut out: Vec<String> = pe_kit::assess(kit, manifest)
        .iter()
        .map(ToString::to_string)
        .collect();
    let program_ok = entries
        .iter()
        .any(|(n, r)| *n == kit.boot_program && r.is_ok());
    if program_ok {
        match read_boot_file(root, &kit.boot_program) {
            Ok(bytes) => {
                if let Err(e) = check_boot_program(&bytes) {
                    out.push(format!("pe_kit boot_program {} {e}", kit.boot_program));
                }
            }
            Err(e) => out.push(format!("pe_kit boot_program {} {e}", kit.boot_program)),
        }
    }
    out
}

fn check_entry(root: &Path, entry: &ManifestEntry) -> Result<(), EntryFailure> {
    let bytes = read_boot_file(root, &entry.name).map_err(EntryFailure::File)?;
    let actual = u64::try_from(bytes.len()).map_err(|_| EntryFailure::File(FileError::TooLarge))?;
    if actual != entry.size {
        return Err(EntryFailure::Size {
            expected: entry.size,
            actual,
        });
    }
    let digest = usgp_crypto::sha256(&bytes);
    if digest != entry.sha256 {
        return Err(EntryFailure::Digest {
            expected: entry.sha256,
            actual: digest,
        });
    }
    Ok(())
}

/// The user name claimed by the environment (`USER`, then `LOGNAME`), for
/// the audit record. Any caller can set it; the uids are the evidence.
fn env_user_claimed() -> String {
    let raw = std::env::var_os("USER")
        .or_else(|| std::env::var_os("LOGNAME"))
        .map(|v| v.to_string_lossy().into_owned())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    raw.chars().take(MAX_USER_CHARS).collect()
}

/// "Who" fields for a cli audit record: kernel uids plus the claimed
/// environment user name.
fn who() -> Vec<(&'static str, String)> {
    let uid = |v: Option<u32>| v.map_or_else(|| "unknown".to_owned(), |u| u.to_string());
    vec![
        (
            "effective_uid",
            uid(usgp_common::process::effective_uid().ok()),
        ),
        ("real_uid", uid(usgp_common::process::real_uid())),
        ("env_user_claimed", env_user_claimed()),
    ]
}

fn join_names<'a>(names: impl Iterator<Item = &'a str>) -> String {
    names.collect::<Vec<_>>().join(",")
}

fn audit(event: &str, outcome: Outcome, detail: &[(&str, String)]) {
    emit(&AuditEvent {
        detail,
        ..AuditEvent::new(event, outcome, COMPONENT)
    });
}

/// Runs `create`, reports on stderr, emits `boot_manifest.created`, and
/// returns the process exit status (0 or 1).
pub fn run_create(args: &CreateArgs) -> u8 {
    let result = create(args);
    let requested = join_names(
        args.names
            .iter()
            .map(|n| n.to_str().unwrap_or("<non-UTF-8>")),
    );
    let mut detail = who();
    detail.extend([
        ("root", args.root.display().to_string()),
        ("manifest", args.out.display().to_string()),
        ("files", requested),
        ("file_count", args.names.len().to_string()),
    ]);
    match result {
        Ok(created) => {
            detail.push(("manifest_sha256", created.manifest_sha256.to_hex()));
            audit("boot_manifest.created", Outcome::Success, &detail);
            for e in &created.manifest.files {
                eprintln!("usgp-cli: {} {} {}", e.sha256, e.size, e.name);
            }
            eprintln!(
                "usgp-cli: wrote {} ({} files, sha256 {})",
                args.out.display(),
                created.manifest.files.len(),
                created.manifest_sha256
            );
            0
        }
        Err(e) => {
            detail.push(("reason", e.to_string()));
            audit("boot_manifest.created", e.outcome(), &detail);
            eprintln!("usgp-cli: boot-manifest create: {e}");
            1
        }
    }
}

/// Runs `create --pe-kit`, reports on stderr, emits
/// `boot_manifest.created`, and returns the exit status (0 or 1).
/// `lookup` is `Err` when the connection could not be set up; that is
/// reported and audited before any file is read.
pub fn run_create_kit(args: &KitCreateArgs, lookup: Result<&mut PeLookup<'_>, String>) -> u8 {
    let c = &args.create;
    let mut detail = who();
    let kit_names = std::iter::once(&args.boot_program)
        .chain([&args.bcd, &args.sdi, &args.wim])
        .chain(args.fonts.iter())
        .map(|n| n.to_str().unwrap_or("<non-UTF-8>"));
    detail.extend([
        ("root", c.root.display().to_string()),
        ("manifest", c.out.display().to_string()),
        (
            "files",
            join_names(c.names.iter().map(|n| n.to_str().unwrap_or("<non-UTF-8>"))),
        ),
        ("pe_kit", "true".to_owned()),
        ("pe_kit_files", join_names(kit_names)),
        ("pe_id", args.pe.chars().take(64).collect()),
    ]);
    let result = match lookup {
        Ok(l) => create_kit(args, l),
        Err(e) => Err(CliError::PeLookup(e)),
    };
    match result {
        Ok(k) => {
            let m = &k.created;
            detail.extend([
                ("file_count", m.manifest.files.len().to_string()),
                ("manifest_sha256", m.manifest_sha256.to_hex()),
                ("pe_content_sha256", k.kit.pe_content_sha256.to_hex()),
                ("memory_required_bytes", k.memory_required.to_string()),
            ]);
            audit("boot_manifest.created", Outcome::Success, &detail);
            for e in &m.manifest.files {
                eprintln!("usgp-cli: {} {} {}", e.sha256, e.size, e.name);
            }
            eprintln!(
                "usgp-cli: wrote {} ({} files, sha256 {})",
                c.out.display(),
                m.manifest.files.len(),
                m.manifest_sha256
            );
            eprintln!(
                "usgp-cli: pe_kit: boot program {} is a UEFI x64 application; WIM {} \
                 matches Ready x64 PE {} (sha256 {})",
                k.kit.boot_program, k.kit.wim, args.pe, k.kit.pe_content_sha256
            );
            eprintln!(
                "usgp-cli: pe_kit: the relay's boot.uefi_x64_program must be {}",
                k.kit.boot_program
            );
            eprintln!(
                "usgp-cli: memory required to start this PE: {} bytes \
                 (512 MiB base + {} bytes WIM held in memory)",
                k.memory_required, k.wim_size
            );
            0
        }
        Err(e) => {
            detail.push(("reason", e.to_string()));
            audit("boot_manifest.created", e.outcome(), &detail);
            eprintln!("usgp-cli: boot-manifest create: {e}");
            1
        }
    }
}

/// Runs `verify`, reports on stderr, emits `boot_manifest.verify`, and
/// returns the process exit status (0 if every file matches, else 1).
pub fn run_verify(args: &VerifyArgs) -> u8 {
    let mut detail = who();
    detail.extend([
        ("root", args.root.display().to_string()),
        ("manifest", args.manifest.display().to_string()),
    ]);
    let verified = match verify(args) {
        Ok(v) => v,
        Err(e) => {
            detail.push(("reason", e.to_string()));
            audit("boot_manifest.verify", e.outcome(), &detail);
            eprintln!("usgp-cli: boot-manifest verify: {e}");
            return 1;
        }
    };
    for (name, r) in &verified.entries {
        match r {
            Ok(()) => eprintln!("usgp-cli: ok {name}"),
            Err(f) => eprintln!("usgp-cli: FAILED {name}: {f}"),
        }
    }
    let kit_failed = verified.kit_problems.as_ref().map_or(0, Vec::len);
    for p in verified.kit_problems.iter().flatten() {
        eprintln!("usgp-cli: FAILED {p}");
    }
    detail.push(("pe_kit", verified.kit_problems.is_some().to_string()));
    let total = verified.entries.len();
    let failed = verified.failed();
    detail.push(("manifest_sha256", verified.manifest_sha256.to_hex()));
    detail.push((
        "files",
        join_names(verified.entries.iter().map(|(n, _)| n.as_str())),
    ));
    detail.push(("file_count", total.to_string()));
    detail.push((
        "failed_files",
        join_names(
            verified
                .entries
                .iter()
                .filter(|(_, r)| r.is_err())
                .map(|(n, _)| n.as_str()),
        ),
    ));
    if failed == 0 && kit_failed == 0 {
        audit("boot_manifest.verify", Outcome::Success, &detail);
        eprintln!("usgp-cli: all {total} files match the manifest");
        if verified.kit_problems.is_some() {
            eprintln!("usgp-cli: pe_kit is complete and its boot program is UEFI x64");
        }
        0
    } else {
        let e = if failed == 0 {
            CliError::KitMismatch(kit_failed)
        } else {
            CliError::Mismatch { failed, total }
        };
        detail.push(("kit_problems", kit_failed.to_string()));
        detail.push(("reason", e.to_string()));
        audit("boot_manifest.verify", e.outcome(), &detail);
        eprintln!("usgp-cli: boot-manifest verify: {e}");
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A fresh directory under the system temp dir, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!("usgp-cli-unit-{}-{n}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(p.join("root")).unwrap();
            Self(p)
        }
        fn root(&self) -> PathBuf {
            self.0.join("root")
        }
        fn put(&self, name: &str, bytes: &[u8]) {
            let p = self.root().join(name);
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(p, bytes).unwrap();
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn name(s: &str) -> BootFileName {
        BootFileName::try_from(s).unwrap()
    }

    fn create_args(t: &TempDir, names: &[&str]) -> CreateArgs {
        CreateArgs {
            root: t.root(),
            out: t.0.join("manifest.toml"),
            names: names.iter().map(OsString::from).collect(),
        }
    }

    #[test]
    fn create_then_verify_ok() {
        let t = TempDir::new();
        t.put("a.efi", b"abc");
        t.put("x64/empty.bin", b"");
        let args = create_args(&t, &["a.efi", "x64/empty.bin"]);
        let c = create(&args).unwrap();
        let text = fs::read_to_string(&args.out).unwrap();
        assert_eq!(text, c.manifest.to_toml());
        assert_eq!(c.manifest_sha256, usgp_crypto::sha256(text.as_bytes()));
        // FIPS 180-4 "abc" and empty-message digests.
        assert!(text.contains("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
        assert!(text.contains("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
        let v = verify(&VerifyArgs {
            root: t.root(),
            manifest: args.out.clone(),
        })
        .unwrap();
        assert_eq!(v.failed(), 0);
        assert_eq!(v.manifest_sha256, c.manifest_sha256);
    }

    #[cfg(unix)]
    #[test]
    fn manifest_written_not_world_writable() {
        use std::os::unix::fs::PermissionsExt;
        let t = TempDir::new();
        t.put("a.efi", b"abc");
        let args = create_args(&t, &["a.efi"]);
        create(&args).unwrap();
        let mode = fs::metadata(&args.out).unwrap().permissions().mode();
        assert_eq!(mode & 0o002, 0);
        usgp_common::config::ensure_not_world_writable(&args.out).unwrap();
    }

    #[test]
    fn refuses_existing_output_and_leaves_it() {
        let t = TempDir::new();
        t.put("a.efi", b"abc");
        let args = create_args(&t, &["a.efi"]);
        fs::write(&args.out, b"keep").unwrap();
        assert!(matches!(create(&args), Err(CliError::OutputExists(_))));
        assert_eq!(fs::read(&args.out).unwrap(), b"keep");
    }

    #[test]
    fn refuses_invalid_names() {
        let t = TempDir::new();
        t.put("a.efi", b"abc");
        for bad in [
            "../x",
            "/etc/passwd",
            "a/../b",
            "\\x",
            "%2e%2e",
            "a\0b",
            "a//b",
            "./a",
            "",
        ] {
            let args = create_args(&t, &["a.efi", bad]);
            match create(&args) {
                Err(CliError::InvalidName { index: 2, .. }) => {}
                other => panic!("{bad:?}: {other:?}"),
            }
            assert!(!args.out.exists());
        }
        let long = "a".repeat(128);
        assert!(matches!(
            create(&create_args(&t, &[&long])),
            Err(CliError::InvalidName { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn refuses_non_utf8_name() {
        use std::os::unix::ffi::OsStringExt;
        let t = TempDir::new();
        let mut args = create_args(&t, &[]);
        args.names = vec![OsString::from_vec(vec![b'a', 0xff])];
        assert!(matches!(
            create(&args),
            Err(CliError::NameNotUtf8 { index: 1 })
        ));
    }

    #[test]
    fn refuses_duplicates_missing_and_directories() {
        let t = TempDir::new();
        t.put("a.efi", b"abc");
        fs::create_dir_all(t.root().join("dir")).unwrap();
        assert!(matches!(
            create(&create_args(&t, &["a.efi", "a.efi"])),
            Err(CliError::Manifest(ManifestError::DuplicateName(_)))
        ));
        assert!(matches!(
            create(&create_args(&t, &["nope.efi"])),
            Err(CliError::File {
                reason: FileError::Missing,
                ..
            })
        ));
        assert!(matches!(
            create(&create_args(&t, &["dir"])),
            Err(CliError::File {
                reason: FileError::NotRegular,
                ..
            })
        ));
        assert!(matches!(
            create(&create_args(&t, &["a.efi/x"])),
            Err(CliError::File {
                reason: FileError::NotRegular,
                ..
            })
        ));
    }

    #[test]
    fn refuses_missing_root() {
        let t = TempDir::new();
        let mut args = create_args(&t, &["a.efi"]);
        args.root = t.0.join("absent");
        assert!(matches!(create(&args), Err(CliError::RootNotDirectory(_))));
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinks() {
        use std::os::unix::fs::symlink;
        let t = TempDir::new();
        t.put("real/a.efi", b"abc");
        fs::write(t.0.join("outside.efi"), b"secret").unwrap();
        symlink(t.0.join("outside.efi"), t.root().join("link.efi")).unwrap();
        symlink(t.root().join("real"), t.root().join("linkdir")).unwrap();
        assert_eq!(
            read_boot_file(&t.root(), &name("link.efi")),
            Err(FileError::Symlink)
        );
        assert_eq!(
            read_boot_file(&t.root(), &name("linkdir/a.efi")),
            Err(FileError::SymlinkedDirectory)
        );
        assert_eq!(
            read_boot_file(&t.root(), &name("real/a.efi")).unwrap(),
            b"abc"
        );
    }

    #[cfg(unix)]
    #[test]
    fn refuses_fifo_without_blocking() {
        let t = TempDir::new();
        let fifo = t.root().join("pipe");
        let ok = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .is_ok_and(|s| s.success());
        if ok {
            assert_eq!(
                read_boot_file(&t.root(), &name("pipe")),
                Err(FileError::NotRegular)
            );
        }
    }

    #[test]
    fn verify_detects_tamper_size_and_missing() {
        let t = TempDir::new();
        t.put("a.efi", b"abc");
        t.put("b.efi", b"0123456789");
        t.put("c.efi", b"keep");
        let args = create_args(&t, &["a.efi", "b.efi", "c.efi"]);
        create(&args).unwrap();
        // One byte changed, same size.
        t.put("a.efi", b"abd");
        // One byte appended.
        t.put("b.efi", b"0123456789!");
        fs::remove_file(t.root().join("c.efi")).unwrap();
        let v = verify(&VerifyArgs {
            root: t.root(),
            manifest: args.out.clone(),
        })
        .unwrap();
        assert_eq!(v.failed(), 3);
        let [(_, a), (_, b), (_, c)] = v.entries.as_slice() else {
            panic!("expected three entries");
        };
        assert!(matches!(a, Err(EntryFailure::Digest { .. })));
        assert_eq!(
            *b,
            Err(EntryFailure::Size {
                expected: 10,
                actual: 11
            })
        );
        assert_eq!(*c, Err(EntryFailure::File(FileError::Missing)));
    }

    #[test]
    fn verify_refuses_bad_manifests() {
        let t = TempDir::new();
        let m = t.0.join("m.toml");
        let va = VerifyArgs {
            root: t.root(),
            manifest: m.clone(),
        };
        assert!(matches!(verify(&va), Err(CliError::Read(_))));
        fs::write(&m, "schema_version = 2\nalgorithm = \"sha256\"\n").unwrap();
        assert!(matches!(verify(&va), Err(CliError::Manifest(_))));
        fs::write(
            &m,
            "schema_version = 1\nalgorithm = \"sha256\"\nextra = 1\n",
        )
        .unwrap();
        assert!(matches!(verify(&va), Err(CliError::Manifest(_))));
        fs::write(&m, vec![b' '; MAX_MANIFEST_BYTES + 1]).unwrap();
        assert!(matches!(verify(&va), Err(CliError::Read(_))));
    }

    #[test]
    fn outcomes() {
        assert_eq!(
            CliError::OutputExists(PathBuf::new()).outcome(),
            Outcome::Refused
        );
        assert_eq!(
            CliError::Mismatch {
                failed: 1,
                total: 1
            }
            .outcome(),
            Outcome::Failure
        );
    }

    // -----------------------------------------------------------------
    // --pe-kit (M3 plan WU-13)
    // -----------------------------------------------------------------

    use crate::pe_kit::tests::{pe_header, x64_efi};
    use crate::pe_kit::{MACHINE_X64, MAGIC_PE32_PLUS};

    const PE_ID: &str = "0b7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e6f";
    const WIM: &[u8] = b"pretend boot.wim bytes";

    fn kit_tree(t: &TempDir) {
        t.put("bootmgfw.efi", &x64_efi());
        t.put("Boot/BCD", b"operator-built store");
        t.put("Boot/boot.sdi", b"sdi");
        t.put("Boot/boot.wim", WIM);
        t.put("Boot/Fonts/a.ttf", b"font");
    }

    fn kit_args(t: &TempDir, fonts: &[&str]) -> KitCreateArgs {
        KitCreateArgs {
            create: create_args(t, &[]),
            boot_program: "bootmgfw.efi".into(),
            bcd: "Boot/BCD".into(),
            sdi: "Boot/boot.sdi".into(),
            wim: "Boot/boot.wim".into(),
            fonts: fonts.iter().map(OsString::from).collect(),
            pe: PE_ID.into(),
            conn: crate::args::ConnArgs::default(),
        }
    }

    /// The server's record of the imported PE: Ready, x64, the WIM's
    /// digest and size.
    fn ready_pe() -> PeView {
        let mut v = crate::cmd_pe::tests::pe();
        v.sha256 = Some(usgp_crypto::sha256(WIM));
        v.size = u64::try_from(WIM.len()).unwrap();
        v
    }

    /// A lookup that returns `v` and counts calls.
    fn lookup_of(
        v: PeView,
        calls: &mut u32,
    ) -> impl FnMut(ContentId) -> Result<PeView, String> + '_ {
        move |id| {
            *calls += 1;
            assert_eq!(id.to_string(), PE_ID);
            Ok(v.clone())
        }
    }

    #[test]
    fn kit_create_then_verify_ok() {
        let t = TempDir::new();
        kit_tree(&t);
        let a = kit_args(&t, &["Boot/Fonts/a.ttf"]);
        let mut calls = 0;
        let k = create_kit(&a, &mut lookup_of(ready_pe(), &mut calls)).unwrap();
        assert_eq!(calls, 1);
        let text = fs::read_to_string(&a.create.out).unwrap();
        assert_eq!(
            k.created.manifest_sha256,
            usgp_crypto::sha256(text.as_bytes())
        );
        let (m, kit) = pe_kit::parse_manifest(&text).unwrap();
        let kit = kit.unwrap();
        assert_eq!(m.files.len(), 5);
        assert_eq!(kit.pe_content_sha256, usgp_crypto::sha256(WIM));
        assert_eq!(kit.fonts.len(), 1);
        assert_eq!(k.wim_size, 22);
        assert_eq!(k.memory_required, 512 * 1024 * 1024 + 22);
        // The BCD is listed with the digest of the operator's own bytes.
        let bcd = m.get(b"Boot/BCD").unwrap();
        assert_eq!(bcd.sha256, usgp_crypto::sha256(b"operator-built store"));
        let v = verify(&VerifyArgs {
            root: t.root(),
            manifest: a.create.out.clone(),
        })
        .unwrap();
        assert_eq!(v.failed(), 0);
        assert_eq!(v.kit_problems, Some(Vec::new()));
    }

    #[test]
    fn kit_names_also_given_as_names_listed_once() {
        let t = TempDir::new();
        kit_tree(&t);
        t.put("extra.bin", b"x");
        let mut a = kit_args(&t, &[]);
        a.create.names = vec!["extra.bin".into(), "Boot/boot.wim".into()];
        let mut calls = 0;
        let k = create_kit(&a, &mut lookup_of(ready_pe(), &mut calls)).unwrap();
        let names: Vec<&str> = k
            .created
            .manifest
            .files
            .iter()
            .map(|e| e.name.as_str())
            .collect();
        assert_eq!(
            names,
            [
                "extra.bin",
                "Boot/boot.wim",
                "bootmgfw.efi",
                "Boot/BCD",
                "Boot/boot.sdi"
            ]
        );
    }

    /// A refusal: the error, nothing written, and the server not asked
    /// unless every local check passed.
    fn refused(a: &KitCreateArgs, v: PeView, asked: u32) -> CliError {
        let mut calls = 0;
        let e = create_kit(a, &mut lookup_of(v, &mut calls)).unwrap_err();
        assert_eq!(calls, asked, "{e}");
        assert!(!a.create.out.exists(), "{e}");
        assert_eq!(
            e.outcome(),
            match e {
                CliError::PeLookup(_) => Outcome::Failure,
                _ => Outcome::Refused,
            }
        );
        e
    }

    #[test]
    fn kit_wrong_machine_refused_before_server() {
        for (m, want) in [
            (0x014Cu16, PeCoffError::WrongMachine(0x014C)),
            (0xAA64, PeCoffError::WrongMachine(0xAA64)),
        ] {
            let t = TempDir::new();
            kit_tree(&t);
            t.put("bootmgfw.efi", &pe_header(m, MAGIC_PE32_PLUS, 10));
            match refused(&kit_args(&t, &[]), ready_pe(), 0) {
                CliError::BootProgram { reason, .. } => assert_eq!(reason, want),
                other => panic!("{other}"),
            }
        }
        let t = TempDir::new();
        kit_tree(&t);
        t.put("bootmgfw.efi", &pe_header(MACHINE_X64, 0x10B, 10));
        let e = refused(&kit_args(&t, &[]), ready_pe(), 0);
        assert!(e.to_string().contains("not PE32+"), "{e}");
        let t = TempDir::new();
        kit_tree(&t);
        t.put("bootmgfw.efi", b"not an image");
        let e = refused(&kit_args(&t, &[]), ready_pe(), 0);
        assert!(matches!(e, CliError::BootProgram { .. }), "{e}");
    }

    #[test]
    fn kit_missing_file_refused_and_bcd_never_generated() {
        for missing in ["Boot/BCD", "Boot/boot.sdi", "Boot/boot.wim", "bootmgfw.efi"] {
            let t = TempDir::new();
            kit_tree(&t);
            fs::remove_file(t.root().join(missing)).unwrap();
            match refused(&kit_args(&t, &[]), ready_pe(), 0) {
                CliError::File { name, reason } => {
                    assert_eq!(name.as_str(), missing);
                    assert_eq!(reason, FileError::Missing);
                }
                other => panic!("{missing}: {other}"),
            }
            // Nothing was created in place of the missing file.
            assert!(!t.root().join(missing).exists());
        }
        // A font named but absent.
        let t = TempDir::new();
        kit_tree(&t);
        let e = refused(&kit_args(&t, &["Boot/Fonts/b.ttf"]), ready_pe(), 0);
        assert!(matches!(e, CliError::File { .. }), "{e}");
    }

    #[test]
    fn kit_server_mismatches_refused() {
        let other = usgp_crypto::sha256(b"another wim");
        let cases: Vec<(PeView, &str)> = vec![
            (
                {
                    let mut v = ready_pe();
                    v.sha256 = Some(other);
                    v
                },
                "sha256",
            ),
            (
                {
                    let mut v = ready_pe();
                    v.sha256 = None;
                    v
                },
                "no verified sha256",
            ),
            (
                {
                    let mut v = ready_pe();
                    v.size += 1;
                    v
                },
                "size",
            ),
            (
                {
                    let mut v = ready_pe();
                    v.state = ContentState::Failed;
                    v
                },
                "not ready",
            ),
            (
                {
                    let mut v = ready_pe();
                    v.architecture = usgp_proto::facts::Fact::declared(Architecture::Arm64);
                    v
                },
                "not x64",
            ),
            (
                {
                    let mut v = ready_pe();
                    v.id = ContentId::parse("1c9e8a70-2b3d-4e5f-9a0b-c1d2e3f40516").unwrap();
                    v
                },
                "different PE",
            ),
        ];
        for (v, want) in cases {
            let t = TempDir::new();
            kit_tree(&t);
            let e = refused(&kit_args(&t, &[]), v, 1);
            assert!(matches!(e, CliError::PeMismatch { .. }), "{e}");
            assert!(e.to_string().contains(want), "{want}: {e}");
        }
        // The server could not be asked.
        let t = TempDir::new();
        kit_tree(&t);
        let a = kit_args(&t, &[]);
        let e = create_kit(&a, &mut |_| Err("HTTP 403".to_owned())).unwrap_err();
        assert!(matches!(e, CliError::PeLookup(_)), "{e}");
        assert_eq!(e.outcome(), Outcome::Failure);
        assert!(!a.create.out.exists());
    }

    #[test]
    fn kit_shape_and_name_errors_refused_before_reading() {
        let t = TempDir::new();
        // No files at all: shape errors come first.
        let mut a = kit_args(&t, &["Boot/BCD"]);
        assert!(matches!(
            refused(&a, ready_pe(), 0),
            CliError::KitShape(KitShapeError::DuplicateRole)
        ));
        a.fonts = (0..=32)
            .map(|i| OsString::from(format!("f{i}.ttf")))
            .collect();
        assert!(matches!(
            refused(&a, ready_pe(), 0),
            CliError::KitShape(KitShapeError::TooManyFonts)
        ));
        let mut a = kit_args(&t, &[]);
        a.bcd = "../BCD".into();
        assert!(matches!(
            refused(&a, ready_pe(), 0),
            CliError::InvalidKitName { role: "bcd", .. }
        ));
        let mut a = kit_args(&t, &[]);
        a.pe = "not-an-id\x1b".into();
        let e = refused(&a, ready_pe(), 0);
        assert!(matches!(e, CliError::InvalidPeId(_)), "{e}");
        assert!(!e.to_string().contains('\x1b'));
    }

    #[test]
    fn kit_verify_detects_machine_and_binding_problems() {
        let t = TempDir::new();
        kit_tree(&t);
        t.put("bootmgfw.efi", &pe_header(0xAA64, MAGIC_PE32_PLUS, 10));
        let names = ["bootmgfw.efi", "Boot/BCD", "Boot/boot.sdi", "Boot/boot.wim"];
        let files = names
            .iter()
            .map(|n| {
                let name = BootFileName::try_from(*n).unwrap();
                let bytes = read_boot_file(&t.root(), &name).unwrap();
                ManifestEntry {
                    name,
                    size: u64::try_from(bytes.len()).unwrap(),
                    sha256: usgp_crypto::sha256(&bytes),
                }
            })
            .collect();
        let m = BootManifest::new(files).unwrap();
        let kit = PeKit {
            boot_program: BootFileName::try_from("bootmgfw.efi").unwrap(),
            bcd: BootFileName::try_from("Boot/BCD").unwrap(),
            sdi: BootFileName::try_from("Boot/boot.sdi").unwrap(),
            wim: BootFileName::try_from("Boot/boot.wim").unwrap(),
            fonts: vec![BootFileName::try_from("Boot/Fonts/a.ttf").unwrap()],
            pe_content_sha256: usgp_crypto::sha256(b"another wim"),
        };
        let path = t.0.join("kit.toml");
        fs::write(&path, pe_kit::to_toml(&m, &kit)).unwrap();
        let v = verify(&VerifyArgs {
            root: t.root(),
            manifest: path,
        })
        .unwrap();
        assert_eq!(v.failed(), 0);
        let problems = v.kit_problems.unwrap();
        assert_eq!(problems.len(), 3, "{problems:?}");
        assert!(problems.iter().any(|p| p.contains("font")), "{problems:?}");
        assert!(
            problems.iter().any(|p| p.contains("pe_content_sha256")),
            "{problems:?}"
        );
        assert!(
            problems.iter().any(|p| p.contains("0xaa64")),
            "{problems:?}"
        );
    }
}
