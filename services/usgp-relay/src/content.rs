//! Published boot content: the SHA-256 manifest and verify-on-open reads
//! (plan section 1.1, Integrity).
//!
//! Every TFTP read request makes the store read the file again (bounded,
//! `O_NOFOLLOW`, regular files only), hash it through `usgp-crypto`, and
//! compare size and digest with the manifest. Only bytes that matched are
//! ever returned, and the caller serves exactly those bytes, so there is no
//! gap between check and use. Concurrent transfers of the same file share
//! one verified buffer: a fresh read that matches replaces nothing and the
//! cached copy is handed out, so memory stays at one copy per file plus at
//! most `verify_concurrency` reads in flight.
//!
//! Request names are normalised (`\` to `/`, one leading separator
//! dropped, the published-name allow-list) and matched ASCII
//! case-insensitively against manifest names
//! ([`ContentStore::resolve`]; M3 plan section 1.2(e)); a manifest whose
//! names collide case-insensitively is refused at load. Request names are
//! never used to build a path: only the matched manifest name is. Manifest
//! names are validated [`BootFileName`]s (no `..`, no absolute paths, no
//! backslash, no NUL).
//! Every directory component of a name below the boot root must be a real
//! directory, not a symbolic link, and the final component is opened with
//! `O_NOFOLLOW`. After the open the directory components are checked again
//! and the path must still name the opened file (same device and inode),
//! so a component swapped for a link during the open is detected. Only
//! files below the boot root are served (REQ-BOOT-041).
//!
//! Checks of one file can run concurrently (requests and the periodic
//! re-check). Each takes a sequence number when its read starts, and a
//! result older than the one already recorded for that file is ignored
//! for the service state ([`RelayState::record_check`]).
//!
//! The manifest is read under the trusted-file rules
//! (`usgp_common::config::read_trusted`). Its optional `[pe_kit]` section
//! is checked by [`crate::pe_kit`]; an incomplete or mismatched kit is
//! tracked as missing content under [`crate::pe_kit::KIT_STATUS_NAME`].

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity) -
//   SHA-256 verified before serving, on every request.
// - NIST 800-53: SC-13 (Cryptographic Protection) - digest through the
//   FIPS module (usgp-crypto).
// - NIST 800-53: SI-10 - bounded reads, regular files only.
// - NIST 800-53: CM-7 - files are opened read-only; nothing is written.
// - NIST 800-53: SC-5 - verification concurrency is bounded.
// - SPEC: specs/boot-network.md#REQ-BOOT-033 (missing file), #REQ-BOOT-040
//   (read-only), #REQ-BOOT-041 (published files only), #REQ-BOOT-052
//   (missing content state), #REQ-BOOT-063 (Windows PE boot files)
// - SPEC: specs/preinstall-env.md#REQ-PE-012 (complete kit)

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;
use usgp_common::Sha256Digest;
use usgp_common::config::{ConfigError, TrustPolicy, read_trusted};
use usgp_proto::boot_manifest::MAX_MANIFEST_BYTES;
use usgp_proto::{BootFileName, BootManifest, ManifestEntry, ManifestError};
use usgp_tftp::{NameRefusal, case_insensitive_collision, normalize_request_name};

use crate::events::{self, Outcome};
use crate::lock;
use crate::pe_kit::{self, KIT_STATUS_NAME, PeKitV1};
use crate::state::{FileStatus, RelayState};

/// A request's verification of a published file did not finish within
/// the request's time bound, so the request was dropped. Rate-limited per
/// file ([`SLOW_REPORT_INTERVAL`]). Declared here rather than in
/// `events.rs` (outside the round-3 change scope); the name follows the
/// `boot.file.*` family.
pub const FILE_VERIFY_SLOW: &str = "boot.file.verify_slow";

/// At most one `boot.file.verify_slow` per file in this interval; the
/// timeouts in between are counted and reported with the next event.
pub const SLOW_REPORT_INTERVAL: Duration = Duration::from_secs(60);

/// Why the manifest could not be loaded. Every variant refuses start-up
/// (exit 78).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ContentLoadError {
    /// The manifest file could not be read.
    #[error(transparent)]
    File(#[from] ConfigError),
    /// The manifest is not a valid v1 manifest (including a `[pe_kit]`
    /// section with an invalid shape).
    #[error("invalid boot manifest: {0}")]
    Manifest(#[from] ManifestError),
    /// `boot.uefi_x64_program` is not listed in the manifest.
    #[error("boot.uefi_x64_program is not listed in the boot manifest")]
    ProgramNotPublished,
    /// A manifest entry is larger than `tftp.max_file_size_bytes`, so it
    /// could never be served.
    #[error("a manifest entry is larger than tftp.max_file_size_bytes")]
    EntryTooLarge,
    /// Two manifest names are equal ASCII case-insensitively, so a request
    /// could match either (names are operator-published, not secrets).
    #[error("boot manifest names {first} and {second} differ only in letter case")]
    NameCollision {
        /// The first name.
        first: String,
        /// The second name.
        second: String,
    },
}

/// Why a request name matched no published file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unresolved {
    /// The name can never be a published name (normalisation refused it).
    Refused(NameRefusal),
    /// A valid name that is not published.
    NotPublished,
}

/// Why a published file could not be served. The TFTP answer is ERROR 1 in
/// every case (no detail is disclosed to the device; SI-11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentError {
    /// The name is not in the manifest (no file access happened).
    NotPublished,
    /// The file is absent from the boot root.
    Missing,
    /// The file does not match the manifest (or is not a regular file).
    IntegrityFailed,
    /// The verification task could not run.
    Unavailable,
}

/// Why a file read did not produce matching bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    NotFound,
    Symlink,
    SymlinkedDirectory,
    Replaced,
    NotRegular,
    TooLarge {
        actual: u64,
    },
    SizeMismatch {
        actual: u64,
    },
    DigestMismatch {
        actual: Sha256Digest,
    },
    Io(std::io::ErrorKind),
    #[cfg(not(unix))]
    Unsupported,
}

impl Fault {
    fn label(&self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::Symlink => "symlink",
            Self::SymlinkedDirectory => "symlinked_directory",
            Self::Replaced => "replaced_during_open",
            Self::NotRegular => "not_regular_file",
            Self::TooLarge { .. } => "too_large",
            Self::SizeMismatch { .. } => "size_mismatch",
            Self::DigestMismatch { .. } => "digest_mismatch",
            Self::Io(_) => "io_error",
            #[cfg(not(unix))]
            Self::Unsupported => "unsupported_platform",
        }
    }

    fn status(&self) -> FileStatus {
        match self {
            Self::NotFound => FileStatus::Missing,
            _ => FileStatus::IntegrityFailed,
        }
    }
}

/// The published boot files and their verified bytes.
#[derive(Debug)]
pub struct ContentStore {
    root: PathBuf,
    manifest: BootManifest,
    manifest_sha256: Sha256Digest,
    program: BootFileName,
    max_file_size: u64,
    /// Read permits. Each permit is moved into the blocking read and is
    /// released only when that read returns, so a caller that gives up
    /// (the TFTP handshake deadline) does not free its slot early.
    verify: Arc<Semaphore>,
    cache: Mutex<HashMap<String, Arc<[u8]>>>,
    state: Arc<RelayState>,
    /// Per published file: when `boot.file.verify_slow` was last emitted
    /// and how many timeouts have not been reported since. Keys are
    /// manifest names only, so the map is bounded by the manifest.
    slow: Mutex<HashMap<String, (Instant, u64)>>,
    #[cfg(all(test, unix))]
    read_gate: Option<Arc<tests::Gate>>,
}

impl ContentStore {
    /// Loads and validates the manifest at `manifest_path` (trusted-file
    /// rules under `trust`) and emits `boot.manifest.loaded`. No boot file
    /// is read yet; call [`Self::recheck_all`] before serving.
    ///
    /// # Errors
    ///
    /// [`ContentLoadError`].
    pub fn load(
        manifest_path: &Path,
        root: &Path,
        program: &BootFileName,
        max_file_size: u64,
        verify_concurrency: usize,
        trust: &TrustPolicy,
    ) -> Result<Self, ContentLoadError> {
        let max = u64::try_from(MAX_MANIFEST_BYTES).unwrap_or(u64::MAX);
        let text = read_trusted(manifest_path, max, trust)?;
        let manifest_sha256 = usgp_crypto::sha256(text.as_bytes());
        let manifest = BootManifest::from_toml(&text)?;
        let kit = manifest.pe_kit.as_ref();
        if manifest.get(program.as_bytes()).is_none() {
            return Err(ContentLoadError::ProgramNotPublished);
        }
        if manifest.files.iter().any(|f| f.size > max_file_size) {
            return Err(ContentLoadError::EntryTooLarge);
        }
        // COMPLIANCE MAPPING:
        // - NIST 800-53: SI-10 / AC-3 - requests are matched
        //   case-insensitively, so names that differ only in case would
        //   make the match ambiguous: refuse the manifest.
        // - SPEC: specs/boot-network.md#REQ-BOOT-041, #REQ-BOOT-063
        if let Some((i, j)) =
            case_insensitive_collision(manifest.files.iter().map(|f| f.name.as_bytes()))
        {
            let name = |k: usize| {
                manifest
                    .files
                    .get(k)
                    .map_or_else(String::new, |f| f.name.as_str().to_owned())
            };
            return Err(ContentLoadError::NameCollision {
                first: name(i),
                second: name(j),
            });
        }
        let mut tracked: Vec<String> = manifest
            .files
            .iter()
            .map(|f| f.name.as_str().to_owned())
            .collect();
        if kit.is_some() {
            tracked.push(KIT_STATUS_NAME.to_owned());
        }
        let state = Arc::new(RelayState::new(tracked));
        let mut detail = vec![
            ("manifest_sha256", manifest_sha256.to_hex()),
            ("file_count", manifest.files.len().to_string()),
            ("uefi_x64_program", program.as_str().to_owned()),
            ("pe_kit", kit.is_some().to_string()),
        ];
        if let Some(k) = &kit {
            detail.push(("pe_content_sha256", k.pe_content_sha256.to_hex()));
        }
        events::emit_simple(events::MANIFEST_LOADED, Outcome::Success, &detail);
        if let Some(k) = kit {
            record_kit(&state, k, &manifest, program);
        }
        Ok(Self {
            root: root.to_path_buf(),
            manifest,
            manifest_sha256,
            program: program.clone(),
            max_file_size,
            verify: Arc::new(Semaphore::new(verify_concurrency.max(1))),
            cache: Mutex::new(HashMap::new()),
            state,
            slow: Mutex::new(HashMap::new()),
            #[cfg(all(test, unix))]
            read_gate: None,
        })
    }

    /// The shared service state derived from file status.
    #[must_use]
    pub fn state(&self) -> &Arc<RelayState> {
        &self.state
    }

    /// SHA-256 of the manifest text.
    #[must_use]
    pub fn manifest_sha256(&self) -> Sha256Digest {
        self.manifest_sha256
    }

    /// The manifest.
    #[must_use]
    pub fn manifest(&self) -> &BootManifest {
        &self.manifest
    }

    /// The boot program to name in offers, or `None` while content is
    /// missing (REQ-BOOT-052: never offer what cannot be delivered).
    #[must_use]
    pub fn offerable_program(&self) -> Option<&BootFileName> {
        self.state.content_available().then_some(&self.program)
    }

    /// The `[pe_kit]` section, if the manifest has one.
    #[must_use]
    pub fn pe_kit(&self) -> Option<&PeKitV1> {
        self.manifest.pe_kit.as_ref()
    }

    /// Whether `name` is a published name (byte-exact; no file access).
    #[must_use]
    pub fn is_published(&self, name: &[u8]) -> bool {
        self.manifest.get(name).is_some()
    }

    /// The published name a TFTP request name refers to: the request is
    /// normalised (`usgp_tftp::normalize_request_name`) and compared ASCII
    /// case-insensitively with every manifest name. No file access; the
    /// request bytes are never used as a path.
    ///
    /// # Errors
    ///
    /// [`Unresolved`]; the caller answers ERROR 1.
    // COMPLIANCE MAPPING:
    // - NIST 800-53: SI-10, AC-3 - allow-list after normalisation; only a
    //   manifest name ever leaves this function.
    // - SPEC: specs/boot-network.md#REQ-BOOT-041, #REQ-BOOT-063;
    //   specs/standards/winpe-network-boot.md §5 (backslash paths)
    pub fn resolve(&self, raw: &[u8]) -> Result<&BootFileName, Unresolved> {
        let name = normalize_request_name(raw).map_err(Unresolved::Refused)?;
        // At most one entry matches: case-insensitive collisions are
        // refused at load.
        self.manifest
            .files
            .iter()
            .find(|e| name.matches(e.name.as_bytes()))
            .map(|e| &e.name)
            .ok_or(Unresolved::NotPublished)
    }

    /// Reads and verifies the published file `name` for serving.
    ///
    /// On success returns exactly the bytes whose size and SHA-256 matched
    /// the manifest. On failure records the file status (which may move
    /// the service to `RunningMissingContent`) and emits
    /// `boot.file.integrity_failed` or `boot.file.missing`.
    ///
    /// # Errors
    ///
    /// [`ContentError`]; the caller answers ERROR 1.
    pub async fn get_verified(&self, name: &[u8]) -> Result<Arc<[u8]>, ContentError> {
        let entry = self
            .manifest
            .get(name)
            .ok_or(ContentError::NotPublished)?
            .clone();
        self.verify_entry(entry, "rrq").await
    }

    /// Records that a request's verification of `name` timed out after
    /// `elapsed` (limit `limit`) and was dropped. Emits
    /// [`FILE_VERIFY_SLOW`] naming the file, at most once per
    /// [`SLOW_REPORT_INTERVAL`] per file, with the number of timeouts
    /// since the last event. Returns whether an event was emitted.
    /// Unpublished names are ignored.
    // COMPLIANCE MAPPING:
    // - NIST 800-53: AU-2 / AU-12 - a file that cannot be verified in
    //   time is reported by name, not only as a shed count.
    // - NIST 800-53: SC-5 - the event itself is rate-limited per file.
    // - SPEC: specs/boot-network.md#REQ-BOOT-034, #REQ-BOOT-044
    pub fn report_verify_slow(
        &self,
        name: &[u8],
        elapsed: Duration,
        limit: Duration,
        now: Instant,
    ) -> bool {
        let Some(entry) = self.manifest.get(name) else {
            return false;
        };
        let file = entry.name.as_str();
        let suppressed = {
            let mut slow = lock(&self.slow);
            match slow.get_mut(file) {
                Some((last, pending))
                    if now.saturating_duration_since(*last) < SLOW_REPORT_INTERVAL =>
                {
                    *pending = pending.saturating_add(1);
                    return false;
                }
                Some((last, pending)) => {
                    let n = *pending;
                    *last = now;
                    *pending = 0;
                    n
                }
                None => {
                    slow.insert(file.to_owned(), (now, 0));
                    0
                }
            }
        };
        let detail = [
            ("file", file.to_owned()),
            ("size", entry.size.to_string()),
            ("elapsed_ms", millis(elapsed)),
            ("limit_ms", millis(limit)),
            ("suppressed_since_last", suppressed.to_string()),
        ];
        events::emit_simple(FILE_VERIFY_SLOW, Outcome::Dropped, &detail);
        true
    }

    /// Re-reads and verifies every published file (start-up and periodic
    /// re-check). Emits `boot.file.verified` for each match.
    pub async fn recheck_all(&self, cause: &str) {
        for entry in self.manifest.files.clone() {
            let _ = self.verify_entry(entry, cause).await;
        }
    }

    async fn verify_entry(
        &self,
        entry: ManifestEntry,
        cause: &str,
    ) -> Result<Arc<[u8]>, ContentError> {
        // COMPLIANCE MAPPING:
        // - NIST 800-53: SC-5 (Denial-of-Service Protection) - at most
        //   `verify_concurrency` reads (and their buffers) exist at once,
        //   including reads whose caller has been cancelled.
        // - SPEC: specs/boot-network.md#REQ-BOOT-044
        //
        // The permit is owned by the blocking task, not by this future. If
        // the caller drops this future (the TFTP handshake deadline), the
        // read already started keeps running on the blocking pool and keeps
        // its permit until it returns, so the next waiter cannot start
        // another read in its place. The cancelled read's result is then
        // discarded: it neither refreshes the shared copy nor records a
        // status. Its sequence number is simply never used, which cannot
        // make a later result look stale ([`RelayState::record_check`]
        // only rejects results older than the one recorded); the periodic
        // re-check is never cancelled and still reports faults.
        let Ok(permit) = Arc::clone(&self.verify).acquire_owned().await else {
            return Err(ContentError::Unavailable);
        };
        // Taken when the read starts (after the permit), so results are
        // ordered by when the bytes were read.
        let seq = self.state.begin_check();
        let root = self.root.clone();
        let max = self.max_file_size;
        let job_entry = entry.clone();
        #[cfg(all(test, unix))]
        let gate = self.read_gate.clone();
        let result = tokio::task::spawn_blocking(move || {
            #[cfg(all(test, unix))]
            if let Some(gate) = gate {
                gate.enter();
            }
            let result = read_and_verify(&root, &job_entry, max);
            drop(permit);
            result
        })
        .await;
        let Ok(result) = result else {
            return Err(ContentError::Unavailable);
        };
        let name = entry.name.as_str();
        match result {
            Ok(bytes) => {
                if cause != "rrq" {
                    let detail = [
                        ("file", name.to_owned()),
                        ("size", entry.size.to_string()),
                        ("sha256", entry.sha256.to_hex()),
                        ("cause", cause.to_owned()),
                    ];
                    events::emit_simple(events::FILE_VERIFIED, Outcome::Success, &detail);
                }
                let current = self
                    .state
                    .record_check(name, FileStatus::Verified, cause, seq)
                    .is_some();
                if !current {
                    // A newer check already recorded a result. These bytes
                    // matched the manifest, so this request may still use
                    // them, but they do not refresh the shared copy.
                    return Ok(Arc::from(bytes));
                }
                let shared = {
                    let mut cache = lock(&self.cache);
                    match cache.get(name) {
                        // Same manifest digest, so the cached copy holds
                        // the same bytes; drop the fresh read.
                        Some(existing) if existing.len() == bytes.len() => Arc::clone(existing),
                        _ => {
                            let fresh: Arc<[u8]> = Arc::from(bytes);
                            cache.insert(name.to_owned(), Arc::clone(&fresh));
                            fresh
                        }
                    }
                };
                Ok(shared)
            }
            Err(fault) => {
                self.report_fault(&entry, fault, cause);
                if self
                    .state
                    .record_check(name, fault.status(), cause, seq)
                    .is_some()
                {
                    lock(&self.cache).remove(name);
                }
                Err(match fault.status() {
                    FileStatus::Missing => ContentError::Missing,
                    _ => ContentError::IntegrityFailed,
                })
            }
        }
    }

    fn report_fault(&self, entry: &ManifestEntry, fault: Fault, cause: &str) {
        let mut detail = vec![
            ("file", entry.name.as_str().to_owned()),
            ("reason", fault.label().to_owned()),
            ("expected_size", entry.size.to_string()),
            ("expected_sha256", entry.sha256.to_hex()),
            ("cause", cause.to_owned()),
        ];
        match fault {
            Fault::TooLarge { actual } | Fault::SizeMismatch { actual } => {
                detail.push(("actual_size", actual.to_string()));
            }
            Fault::DigestMismatch { actual } => {
                detail.push(("actual_sha256", actual.to_hex()));
            }
            Fault::Io(kind) => detail.push(("io_error", format!("{kind:?}"))),
            _ => {}
        }
        let event = if fault == Fault::NotFound {
            events::FILE_MISSING
        } else {
            events::FILE_INTEGRITY_FAILED
        };
        events::emit_simple(event, Outcome::Failure, &detail);
    }
}

/// Records the kit's completeness under [`KIT_STATUS_NAME`] and emits
/// `boot.kit.incomplete` when it is not complete (REQ-PE-012).
fn record_kit(state: &RelayState, kit: &PeKitV1, manifest: &BootManifest, program: &BootFileName) {
    let problems = kit.assess(manifest, Some(program));
    let status = problems
        .iter()
        .map(pe_kit::problem_status)
        .find(|s| *s == FileStatus::IntegrityFailed)
        .or_else(|| problems.first().map(pe_kit::problem_status))
        .unwrap_or(FileStatus::Verified);
    if !problems.is_empty() {
        let reasons: Vec<String> = problems.iter().map(pe_kit::KitProblem::describe).collect();
        let detail = [
            ("reasons", reasons.join(",")),
            ("pe_content_sha256", kit.pe_content_sha256.to_hex()),
            ("action", "no boot program offered".to_owned()),
        ];
        events::emit_simple(events::KIT_INCOMPLETE, Outcome::Failure, &detail);
    }
    state.record(KIT_STATUS_NAME, status, "startup");
}

fn millis(d: Duration) -> String {
    d.as_millis().to_string()
}

/// Opens `root/name` without following a final symbolic link and without
/// blocking on a FIFO, read-only.
#[cfg(unix)]
fn open_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

#[cfg(unix)]
fn classify_open_error(e: &std::io::Error) -> Fault {
    match e.raw_os_error() {
        Some(code) if code == libc::ELOOP => Fault::Symlink,
        _ if e.kind() == std::io::ErrorKind::NotFound => Fault::NotFound,
        _ => Fault::Io(e.kind()),
    }
}

/// Checks that every directory component of `name` below `root` is a
/// real directory (not a symbolic link).
#[cfg(unix)]
fn check_directories(root: &Path, name: &str) -> Result<(), Fault> {
    let mut dir = root.to_path_buf();
    let mut parts = name.split('/').peekable();
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            break;
        }
        dir.push(part);
        let m = std::fs::symlink_metadata(&dir).map_err(|e| classify_open_error(&e))?;
        if m.file_type().is_symlink() {
            return Err(Fault::SymlinkedDirectory);
        }
        if !m.is_dir() {
            return Err(Fault::NotRegular);
        }
    }
    Ok(())
}

/// Reads the file for `entry` below `root` and checks it against the
/// manifest. Runs on the blocking pool.
#[cfg(unix)]
fn read_and_verify(root: &Path, entry: &ManifestEntry, max: u64) -> Result<Vec<u8>, Fault> {
    use std::os::unix::fs::MetadataExt;

    // The name is a validated relative path (no `..`, no leading `/`).
    let name = entry.name.as_str();
    let path = root.join(name);
    check_directories(root, name)?;
    let file = open_no_follow(&path).map_err(|e| classify_open_error(&e))?;
    let meta = file.metadata().map_err(|e| Fault::Io(e.kind()))?;
    if !meta.is_file() {
        return Err(Fault::NotRegular);
    }
    // A directory swapped for a link between the check and the open would
    // have led elsewhere: check again and require the path to name the
    // opened file now.
    check_directories(root, name)?;
    let now = std::fs::symlink_metadata(&path).map_err(|_| Fault::Replaced)?;
    if now.dev() != meta.dev() || now.ino() != meta.ino() {
        return Err(Fault::Replaced);
    }
    let len = meta.len();
    if len > max {
        return Err(Fault::TooLarge { actual: len });
    }
    if len != entry.size {
        return Err(Fault::SizeMismatch { actual: len });
    }
    let cap = usize::try_from(len).map_err(|_| Fault::TooLarge { actual: len })?;
    let mut buf = Vec::with_capacity(cap);
    file.take(entry.size.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| Fault::Io(e.kind()))?;
    let read_len = u64::try_from(buf.len()).unwrap_or(u64::MAX);
    if read_len != entry.size {
        return Err(Fault::SizeMismatch { actual: read_len });
    }
    let actual = usgp_crypto::sha256(&buf);
    if actual != entry.sha256 {
        return Err(Fault::DigestMismatch { actual });
    }
    Ok(buf)
}

#[cfg(not(unix))]
fn read_and_verify(_root: &Path, _entry: &ManifestEntry, _max: u64) -> Result<Vec<u8>, Fault> {
    Err(Fault::Unsupported)
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Condvar;
    use std::time::Duration;

    use usgp_common::config::TrustPolicy;

    use super::*;

    /// Holds blocking reads at their start until opened, and counts how
    /// many reads have started.
    #[derive(Debug, Default)]
    pub(super) struct Gate {
        inner: Mutex<(usize, bool)>,
        cv: Condvar,
    }

    impl Gate {
        /// Called on the blocking pool before the read.
        pub(super) fn enter(&self) {
            let mut g = lock(&self.inner);
            g.0 += 1;
            self.cv.notify_all();
            while !g.1 {
                g = self
                    .cv
                    .wait(g)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
        }

        fn started(&self) -> usize {
            lock(&self.inner).0
        }

        fn open(&self) {
            lock(&self.inner).1 = true;
            self.cv.notify_all();
        }
    }

    /// Opens the gate when dropped, so a failing assertion cannot leave
    /// blocking reads parked (the runtime would wait for them forever).
    struct OpenOnDrop(Arc<Gate>);

    impl Drop for OpenOnDrop {
        fn drop(&mut self) {
            self.0.open();
        }
    }

    struct Scratch(PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    type Fixture = (Scratch, Arc<ContentStore>, Arc<Gate>);

    fn set_mode(p: &Path, mode: u32) -> Result<(), String> {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode))
            .map_err(|e| e.to_string())
    }

    fn write(p: &Path, data: &[u8]) -> Result<(), String> {
        std::fs::write(p, data).map_err(|e| e.to_string())?;
        set_mode(p, 0o644)
    }

    /// A store with one published file, `verify_concurrency` permits and
    /// the gate installed (no start-up check, so no read has run yet).
    fn gated_store(tag: &str, concurrency: usize) -> Result<Fixture, String> {
        let dir =
            std::env::temp_dir().join(format!("usgp-relay-unit-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let scratch = Scratch(dir.clone());
        let root = dir.join("root");
        std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;
        set_mode(&dir, 0o755)?;
        set_mode(&root, 0o755)?;
        let data = vec![0x5a_u8; 4096];
        write(&root.join("prog.efi"), &data)?;
        let name = BootFileName::try_from("prog.efi").map_err(|e| e.to_string())?;
        let manifest = BootManifest::new(vec![ManifestEntry {
            name: name.clone(),
            size: u64::try_from(data.len()).map_err(|e| e.to_string())?,
            sha256: usgp_crypto::sha256(&data),
        }])
        .map_err(|e| e.to_string())?;
        let manifest_path = dir.join("boot-manifest.toml");
        write(&manifest_path, manifest.to_toml().as_bytes())?;
        let uid = usgp_common::process::effective_uid().map_err(|e| e.to_string())?;
        let trust = TrustPolicy::with_admin(uid);
        let mut store =
            ContentStore::load(&manifest_path, &root, &name, 1 << 20, concurrency, &trust)
                .map_err(|e| e.to_string())?;
        let gate = Arc::new(Gate::default());
        store.read_gate = Some(Arc::clone(&gate));
        Ok((scratch, Arc::new(store), gate))
    }

    /// Waits (real time, bounded) until `cond` holds; false on timeout.
    async fn wait_for(cond: impl Fn() -> bool) -> bool {
        for _ in 0..2000 {
            if cond() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        false
    }

    /// A verification cancelled mid-read (as the TFTP handshake deadline
    /// does) keeps its permit until the blocking read returns, so no
    /// further read starts beyond `verify_concurrency` (SC-5).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_verification_keeps_permit_until_read_ends() {
        const CONCURRENCY: usize = 2;
        let (_s, store, gate) = gated_store("cancel", CONCURRENCY).unwrap();
        let _open = OpenOnDrop(Arc::clone(&gate));

        // Fill every permit with a read held at its start.
        let first: Vec<_> = (0..CONCURRENCY)
            .map(|_| {
                let store = Arc::clone(&store);
                tokio::spawn(async move { store.get_verified(b"prog.efi").await })
            })
            .collect();
        assert!(
            wait_for(|| gate.started() == CONCURRENCY).await,
            "first reads did not start"
        );
        assert_eq!(store.verify.available_permits(), 0);

        // Cancel the waiters while their reads are still running.
        for task in first {
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        }
        assert_eq!(
            store.verify.available_permits(),
            0,
            "a cancelled verification released its permit while its read runs"
        );

        // A new request must wait for a running read to finish.
        let next = {
            let store = Arc::clone(&store);
            tokio::spawn(async move { store.get_verified(b"prog.efi").await })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            gate.started(),
            CONCURRENCY,
            "a read started beyond the bound"
        );
        assert_eq!(store.verify.available_permits(), 0);
        assert!(!next.is_finished());

        // Let the reads finish: the new request is served and every permit
        // comes back.
        gate.open();
        let served = next.await.unwrap().unwrap();
        assert_eq!(served.len(), 4096);
        assert_eq!(gate.started(), CONCURRENCY + 1);
        assert!(
            wait_for(|| store.verify.available_permits() == CONCURRENCY).await,
            "permits did not return"
        );
    }

    /// `boot.file.verify_slow` is emitted once per file per interval;
    /// timeouts in between are only counted. Unpublished names are
    /// ignored.
    #[test]
    fn verify_slow_report_rate_limited_per_file() {
        let (_s, store, _gate) = gated_store("slow", 1).unwrap();
        let t0 = Instant::now();
        let d = Duration::from_secs(2);
        assert!(store.report_verify_slow(b"prog.efi", d, d, t0));
        assert!(!store.report_verify_slow(b"prog.efi", d, d, t0 + Duration::from_secs(1)));
        assert!(!store.report_verify_slow(
            b"prog.efi",
            d,
            d,
            t0 + SLOW_REPORT_INTERVAL - Duration::from_millis(1)
        ));
        assert_eq!(lock(&store.slow).get("prog.efi").map(|e| e.1), Some(2));
        assert!(store.report_verify_slow(b"prog.efi", d, d, t0 + SLOW_REPORT_INTERVAL));
        assert_eq!(lock(&store.slow).get("prog.efi").map(|e| e.1), Some(0));
        assert!(!store.report_verify_slow(b"other.efi", d, d, t0));
        assert_eq!(lock(&store.slow).len(), 1);
    }
}
