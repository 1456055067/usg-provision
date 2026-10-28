//! Bounded, strict reading of operator-owned files (config, manifest,
//! suppression list).
//!
//! Every file is size-limited before it is parsed, must be a regular file,
//! must be UTF-8, and is parsed with unknown keys rejected by the caller's
//! serde types (`deny_unknown_fields`). Errors name the path and the rule
//! that failed. They do not echo file content, except that a TOML type
//! mismatch may quote the mismatched scalar (see [`ConfigError::Parse`]).
//!
//! Every file is opened once, with `O_NOFOLLOW | O_NONBLOCK`, and every
//! check is made on the opened handle (`fstat`), so a symbolic link or a
//! FIFO swapped in is refused rather than followed or blocked on.
//!
//! # Trusted files
//!
//! [`read_trusted`] adds the rules for files that decide what the relay
//! serves or how it behaves (configuration, boot manifest, suppression
//! list), under a [`TrustPolicy`]:
//!
//! 1. the file is owned by uid 0 or by the configured administrator uid;
//! 2. it is neither group- nor world-writable;
//! 3. every directory from its parent up to `/` (after resolving symbolic
//!    links in the directory part) is owned by uid 0 or the administrator
//!    uid and is not group- or world-writable unless the sticky bit is set;
//! 4. after the walk, the checked path still names the opened file (same
//!    device and inode), so a rename during the checks is detected.
//!
//! Rule 1 means a service that runs under its own uid can never write the
//! files it trusts. If the service itself runs as uid 0 or as the
//! administrator uid, that separation is lost; the rules still pass, and
//! [`TrustPolicy::service_is_trusted_owner`] lets the caller report it.
//!
//! Access control lists and other extended permission mechanisms are not
//! inspected (POAM below).

// COMPLIANCE MAPPING:
// - NIST 800-53: CM-6 (Configuration Settings) - strict validation; callers
//   refuse to start on any error.
// - NIST 800-53: SI-10 (Information Input Validation) - size bound before
//   parsing, regular files only, UTF-8 only, no link or FIFO followed.
// - NIST 800-53: CM-5 (Access Restrictions for Change) / SI-7 (Software,
//   Firmware, and Information Integrity) - trust files and every parent
//   directory must be owned by root or the administrator and not writable
//   by anyone else; checked on the opened handle.
// - SPEC: specs/boot-network.md#REQ-BOOT-053 (settings read, never rewritten)

// POAM: POSIX ACLs (Linux) and extended ACLs (macOS) on trust files and
// their directories are not inspected; on Linux a group ACL entry shows up
// in the group mode bits and is refused, but a named-user entry with write
// access does not. Deployment guidance: no ACLs on /etc/usgp-relay.

// POAM: off Unix, [`read_bounded`] has no equivalent of `O_NOFOLLOW`: a
// final symbolic link or junction is followed (the target must still be a
// regular file). No Windows caller reads operator files through it yet;
// the trust functions fail closed there.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;

/// Errors from reading or parsing an operator file.
///
/// No variant carries file content beyond what [`ConfigError::Parse`]
/// documents.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// The file could not be opened, inspected, or read.
    #[error("cannot read {}: {kind}", path.display())]
    Io {
        /// The file.
        path: PathBuf,
        /// The I/O error kind (the OS message is omitted on purpose).
        kind: std::io::ErrorKind,
    },
    /// The path is not a regular file (directory, device, FIFO, socket).
    #[error("{} is not a regular file", path.display())]
    NotRegularFile {
        /// The file.
        path: PathBuf,
    },
    /// The file is larger than the limit for its kind.
    #[error("{} is larger than the {max_bytes}-byte limit", path.display())]
    TooLarge {
        /// The file.
        path: PathBuf,
        /// The limit that was exceeded.
        max_bytes: u64,
    },
    /// The file is not valid UTF-8.
    #[error("{} is not valid UTF-8 (first bad byte at offset {offset})", path.display())]
    NotUtf8 {
        /// The file.
        path: PathBuf,
        /// Offset of the first invalid byte.
        offset: usize,
    },
    /// Other users can write to the file, so its content cannot be trusted.
    #[error("{} is world-writable", path.display())]
    WorldWritable {
        /// The file or directory.
        path: PathBuf,
    },
    /// The TOML text did not parse into the expected type.
    #[error("invalid TOML at line {line}, column {column}: {message}")]
    Parse {
        /// 1-based line of the error (0 if unknown).
        line: usize,
        /// 1-based column in bytes (0 if unknown).
        column: usize,
        /// Parser message. The source-line snippet is deliberately dropped.
        /// A serde type-mismatch message can still quote the offending
        /// scalar (for example `invalid type: string "x"`), so files that
        /// hold secrets must not be parsed through this function without
        /// redaction (none exist in M1; plan section 6, Secrets).
        message: String,
    },
    /// The permission check is not implemented for this platform, so it
    /// fails closed.
    #[error("file permission checks are not supported on this platform")]
    UnsupportedPlatform,
    /// The final path component is a symbolic link (never followed).
    #[error("{} is a symbolic link", path.display())]
    Symlink {
        /// The file.
        path: PathBuf,
    },
    /// A trust rule ([`read_trusted`]) failed for the file or one of its
    /// directories.
    #[error("{} is not trusted: {rule}", path.display())]
    Untrusted {
        /// The file or directory that failed.
        path: PathBuf,
        /// The rule that failed.
        rule: TrustRule,
    },
}

/// The trust rule that a file or directory failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TrustRule {
    /// The group may write it.
    #[error("group-writable")]
    GroupWritable,
    /// Every user may write it.
    #[error("world-writable")]
    WorldWritable,
    /// Owned by a uid other than 0 or the administrator uid.
    #[error("owner is neither root nor the administrator uid")]
    Owner,
    /// A directory on the path is group- or world-writable without the
    /// sticky bit.
    #[error("directory is writable by group or others without the sticky bit")]
    WritableDirectory,
    /// The path no longer names the file that was opened.
    #[error("file was replaced while it was being checked")]
    Replaced,
    /// The directory part of the path could not be resolved.
    #[error("directory path cannot be resolved")]
    Unresolvable,
}

/// Who may own trusted files (see the module documentation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TrustPolicy {
    /// A uid trusted in addition to uid 0, for deployments where an
    /// unprivileged administrator account owns the relay's files. `None`
    /// trusts uid 0 only.
    pub admin_uid: Option<u32>,
}

impl TrustPolicy {
    /// Trusts uid 0 only.
    #[must_use]
    pub const fn root_only() -> Self {
        Self { admin_uid: None }
    }

    /// Trusts uid 0 and `uid`.
    #[must_use]
    pub const fn with_admin(uid: u32) -> Self {
        Self {
            admin_uid: Some(uid),
        }
    }

    /// Whether `uid` may own trusted files and directories.
    #[must_use]
    pub fn is_trusted_owner(&self, uid: u32) -> bool {
        uid == 0 || self.admin_uid == Some(uid)
    }

    /// Whether a service running as `service_uid` could itself write the
    /// files it trusts (it runs as root or as the administrator uid).
    #[must_use]
    pub fn service_is_trusted_owner(&self, service_uid: u32) -> bool {
        self.is_trusted_owner(service_uid)
    }
}

fn io_err(path: &Path, e: &std::io::Error) -> ConfigError {
    ConfigError::Io {
        path: path.to_path_buf(),
        kind: e.kind(),
    }
}

/// Reads a whole UTF-8 file of at most `max_bytes` bytes.
///
/// The file is opened once without following a final symbolic link and
/// without blocking on a FIFO (`O_NOFOLLOW | O_NONBLOCK`), and the opened
/// handle must be a regular file. At most `max_bytes + 1` bytes are ever
/// read, so an oversized or growing file cannot exhaust memory.
///
/// # Errors
///
/// [`ConfigError::Io`], [`ConfigError::Symlink`],
/// [`ConfigError::NotRegularFile`], [`ConfigError::TooLarge`] or
/// [`ConfigError::NotUtf8`].
pub fn read_bounded(path: &Path, max_bytes: u64) -> Result<String, ConfigError> {
    let (file, meta) = open_regular(path)?;
    read_open(file, &meta, path, max_bytes)
}

/// Reads a trusted operator file: [`read_bounded`] plus every rule in the
/// module documentation, all checked against the one opened handle.
///
/// # Errors
///
/// As [`read_bounded`], plus [`ConfigError::Untrusted`] naming the file or
/// directory and the rule, or [`ConfigError::UnsupportedPlatform`] off
/// Unix.
pub fn read_trusted(
    path: &Path,
    max_bytes: u64,
    policy: &TrustPolicy,
) -> Result<String, ConfigError> {
    let (file, meta) = open_trusted(path, policy)?;
    read_open(file, &meta, path, max_bytes)
}

/// Checks a trusted operator file without reading it (same rules as
/// [`read_trusted`]).
///
/// # Errors
///
/// As [`read_trusted`].
pub fn ensure_trusted_file(path: &Path, policy: &TrustPolicy) -> Result<(), ConfigError> {
    open_trusted(path, policy).map(|_| ())
}

/// Checks a directory that holds trusted content (for example the boot
/// root): it and every directory above it, after resolving symbolic
/// links, follow rule 3 of the module documentation, and it is itself
/// neither group- nor world-writable, sticky bit or not.
///
/// # Errors
///
/// [`ConfigError::Io`] if it cannot be inspected,
/// [`ConfigError::Untrusted`], or [`ConfigError::UnsupportedPlatform`] off
/// Unix.
pub fn ensure_trusted_dir(path: &Path, policy: &TrustPolicy) -> Result<(), ConfigError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let canonical = std::fs::canonicalize(path).map_err(|e| io_err(path, &e))?;
        let meta = std::fs::metadata(&canonical).map_err(|e| io_err(&canonical, &e))?;
        check_mode_and_owner(&canonical, meta.mode(), meta.uid(), policy)?;
        check_directories(&canonical, policy)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, policy);
        Err(ConfigError::UnsupportedPlatform)
    }
}

/// Opens `path` read-only with `O_NOFOLLOW | O_NONBLOCK` and checks that
/// the handle is a regular file.
fn open_regular(path: &Path) -> Result<(File, std::fs::Metadata), ConfigError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|e| open_err(path, &e))?;
    let meta = file.metadata().map_err(|e| io_err(path, &e))?;
    if !meta.is_file() {
        return Err(ConfigError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    Ok((file, meta))
}

/// Maps an open failure to the error for the rule it shows was broken.
///
/// Unix: `O_NOFOLLOW` on a final symbolic link fails with `ELOOP`.
///
/// Windows: a directory cannot be opened as a file without
/// `FILE_FLAG_BACKUP_SEMANTICS` (deliberately not set: with the backup
/// privilege enabled it bypasses the file's access checks), so the open
/// fails with access denied before the handle can be inspected. The path is
/// then looked up, without following a link, to report a directory as
/// [`ConfigError::NotRegularFile`] as on Unix. This lookup only chooses
/// which refusal to report: nothing is opened or read after it, so a swap
/// between the open and the lookup cannot cause a file to be accepted.
fn open_err(path: &Path, e: &std::io::Error) -> ConfigError {
    #[cfg(unix)]
    if e.raw_os_error() == Some(libc::ELOOP) {
        return ConfigError::Symlink {
            path: path.to_path_buf(),
        };
    }
    #[cfg(not(unix))]
    if e.kind() == std::io::ErrorKind::PermissionDenied
        && std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir())
    {
        return ConfigError::NotRegularFile {
            path: path.to_path_buf(),
        };
    }
    io_err(path, e)
}

fn open_trusted(
    path: &Path,
    policy: &TrustPolicy,
) -> Result<(File, std::fs::Metadata), ConfigError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let (file, meta) = open_regular(path)?;
        check_mode_and_owner(path, meta.mode(), meta.uid(), policy)?;
        // Resolve the directory part (symbolic links there are allowed but
        // every directory they lead through is checked).
        let untrusted = |rule| ConfigError::Untrusted {
            path: path.to_path_buf(),
            rule,
        };
        let name = path
            .file_name()
            .ok_or_else(|| untrusted(TrustRule::Unresolvable))?;
        let parent = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        let parent = std::fs::canonicalize(parent).map_err(|e| io_err(parent, &e))?;
        check_directories(&parent, policy)?;
        // The checked name must still be the opened file.
        let now = std::fs::symlink_metadata(parent.join(name))
            .map_err(|_| untrusted(TrustRule::Replaced))?;
        if now.dev() != meta.dev() || now.ino() != meta.ino() {
            return Err(untrusted(TrustRule::Replaced));
        }
        Ok((file, meta))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, policy);
        Err(ConfigError::UnsupportedPlatform)
    }
}

/// Rules 1 and 2 for a file, or the target directory of
/// [`ensure_trusted_dir`].
#[cfg(unix)]
fn check_mode_and_owner(
    path: &Path,
    mode: u32,
    uid: u32,
    policy: &TrustPolicy,
) -> Result<(), ConfigError> {
    const GROUP_WRITE: u32 = 0o020;
    const OTHER_WRITE: u32 = 0o002;
    let rule = if mode & OTHER_WRITE != 0 {
        Some(TrustRule::WorldWritable)
    } else if mode & GROUP_WRITE != 0 {
        Some(TrustRule::GroupWritable)
    } else if !policy.is_trusted_owner(uid) {
        Some(TrustRule::Owner)
    } else {
        None
    };
    match rule {
        Some(rule) => Err(ConfigError::Untrusted {
            path: path.to_path_buf(),
            rule,
        }),
        None => Ok(()),
    }
}

/// Rule 3: `dir` (already canonical) and every ancestor up to `/`.
#[cfg(unix)]
fn check_directories(dir: &Path, policy: &TrustPolicy) -> Result<(), ConfigError> {
    use std::os::unix::fs::MetadataExt;

    const GROUP_OR_OTHER_WRITE: u32 = 0o022;
    const STICKY: u32 = 0o1000;
    for d in dir.ancestors() {
        let meta = std::fs::symlink_metadata(d).map_err(|e| io_err(d, &e))?;
        let untrusted = |rule| ConfigError::Untrusted {
            path: d.to_path_buf(),
            rule,
        };
        if !meta.is_dir() {
            // A canonical path has no links; anything else is a race.
            return Err(untrusted(TrustRule::Unresolvable));
        }
        if !policy.is_trusted_owner(meta.uid()) {
            return Err(untrusted(TrustRule::Owner));
        }
        let mode = meta.mode();
        if mode & GROUP_OR_OTHER_WRITE != 0 && mode & STICKY == 0 {
            return Err(untrusted(TrustRule::WritableDirectory));
        }
    }
    Ok(())
}

/// Reads at most `max_bytes` from an opened regular file.
fn read_open(
    file: File,
    meta: &std::fs::Metadata,
    path: &Path,
    max_bytes: u64,
) -> Result<String, ConfigError> {
    let too_large = || ConfigError::TooLarge {
        path: path.to_path_buf(),
        max_bytes,
    };
    if meta.len() > max_bytes {
        return Err(too_large());
    }
    let mut buf = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| io_err(path, &e))?;
    let read_len = u64::try_from(buf.len()).unwrap_or(u64::MAX);
    if read_len > max_bytes {
        return Err(too_large());
    }
    String::from_utf8(buf).map_err(|e| ConfigError::NotUtf8 {
        path: path.to_path_buf(),
        offset: e.utf8_error().valid_up_to(),
    })
}

/// Parses TOML text into `T`.
///
/// Strictness (unknown keys, ranges) comes from `T`'s serde attributes and
/// the caller's own validation.
///
/// # Errors
///
/// [`ConfigError::Parse`] with the line and column of the failure.
pub fn parse_toml<T: DeserializeOwned>(text: &str) -> Result<T, ConfigError> {
    toml::from_str(text).map_err(|e| {
        let (line, column) = e
            .span()
            .map_or((0, 0), |span| line_column(text, span.start));
        ConfigError::Parse {
            line,
            column,
            message: e.message().to_owned(),
        }
    })
}

/// 1-based line and byte column of `offset` in `text`.
fn line_column(text: &str, offset: usize) -> (usize, usize) {
    let before = text.as_bytes().get(..offset).unwrap_or(text.as_bytes());
    let line = before.iter().filter(|&&b| b == b'\n').count() + 1;
    let line_start = before
        .iter()
        .rposition(|&b| b == b'\n')
        .map_or(0, |p| p + 1);
    (line, before.len() - line_start + 1)
}

/// Refuses a file or directory that any user may write to.
///
/// This is the world-write bit only. Files that decide what is served or
/// how a service behaves must use [`read_trusted`] /
/// [`ensure_trusted_file`] instead.
///
/// The check is on the path's target (symbolic links are followed). On
/// non-Unix platforms it fails closed with
/// [`ConfigError::UnsupportedPlatform`].
///
/// # Errors
///
/// [`ConfigError::Io`] if the path cannot be inspected, or
/// [`ConfigError::WorldWritable`] if the "other" write bit is set.
pub fn ensure_not_world_writable(path: &Path) -> Result<(), ConfigError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        const OTHER_WRITE: u32 = 0o002;
        let meta = std::fs::metadata(path).map_err(|e| io_err(path, &e))?;
        if meta.permissions().mode() & OTHER_WRITE != 0 {
            return Err(ConfigError::WorldWritable {
                path: path.to_path_buf(),
            });
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(ConfigError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A uniquely named scratch directory under the system temp dir,
    /// removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let dir = std::env::temp_dir().join(format!(
                "usgp-common-test-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn file(&self, name: &str, content: &[u8]) -> PathBuf {
            let p = self.0.join(name);
            std::fs::write(&p, content).unwrap();
            p
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn reads_file_at_limit() {
        let s = Scratch::new();
        let p = s.file("ok.toml", b"a = 1\n");
        assert_eq!(read_bounded(&p, 6).unwrap(), "a = 1\n");
    }

    #[test]
    fn oversize_rejected() {
        let s = Scratch::new();
        let p = s.file("big.toml", b"a = 1\n");
        let e = read_bounded(&p, 5).unwrap_err();
        assert!(
            matches!(e, ConfigError::TooLarge { max_bytes: 5, .. }),
            "{e:?}"
        );
    }

    #[test]
    fn empty_file_reads_empty() {
        let s = Scratch::new();
        let p = s.file("empty.toml", b"");
        assert_eq!(read_bounded(&p, 0).unwrap(), "");
    }

    #[test]
    fn non_utf8_rejected_with_offset() {
        let s = Scratch::new();
        let p = s.file("bad.toml", b"ab\xff\xfe");
        let e = read_bounded(&p, 100).unwrap_err();
        assert!(matches!(e, ConfigError::NotUtf8 { offset: 2, .. }), "{e:?}");
    }

    #[test]
    fn directory_rejected() {
        let s = Scratch::new();
        let e = read_bounded(&s.0, 100).unwrap_err();
        assert!(matches!(e, ConfigError::NotRegularFile { .. }), "{e:?}");
    }

    #[test]
    fn missing_file_is_io_not_found() {
        let s = Scratch::new();
        let e = read_bounded(&s.0.join("nope"), 100).unwrap_err();
        assert!(
            matches!(
                e,
                ConfigError::Io {
                    kind: std::io::ErrorKind::NotFound,
                    ..
                }
            ),
            "{e:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn device_file_rejected() {
        let e = read_bounded(Path::new("/dev/null"), 100).unwrap_err();
        assert!(matches!(e, ConfigError::NotRegularFile { .. }), "{e:?}");
    }

    #[cfg(unix)]
    #[test]
    fn world_writable_rejected_and_private_accepted() {
        use std::os::unix::fs::PermissionsExt;
        let s = Scratch::new();
        let p = s.file("cfg.toml", b"a = 1\n");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        ensure_not_world_writable(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o646)).unwrap();
        let e = ensure_not_world_writable(&p).unwrap_err();
        assert!(matches!(e, ConfigError::WorldWritable { .. }), "{e:?}");
        // This check looks at the world bit only; trusted files go through
        // `read_trusted`, which refuses group-write as well.
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o664)).unwrap();
        ensure_not_world_writable(&p).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn world_writable_directory_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let s = Scratch::new();
        let d = s.0.join("root");
        std::fs::create_dir(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            ensure_not_world_writable(&d),
            Err(ConfigError::WorldWritable { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_never_followed() {
        let s = Scratch::new();
        let target = s.file("target.toml", b"a = 1\n");
        let link = s.0.join("link.toml");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let e = read_bounded(&link, 100).unwrap_err();
        assert!(matches!(e, ConfigError::Symlink { .. }), "{e:?}");
    }

    #[cfg(unix)]
    #[test]
    fn fifo_refused_without_blocking() {
        let s = Scratch::new();
        let fifo = s.0.join("fifo.toml");
        let ok = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success();
        assert!(ok);
        // O_NONBLOCK: the open returns at once and the handle is refused.
        let e = read_bounded(&fifo, 100).unwrap_err();
        assert!(matches!(e, ConfigError::NotRegularFile { .. }), "{e:?}");
    }

    // ----- trusted files -------------------------------------------------
    //
    // These run as an ordinary developer: the test's own uid is configured
    // as the administrator uid, which the policy trusts like uid 0.

    #[cfg(unix)]
    fn me() -> TrustPolicy {
        TrustPolicy::with_admin(crate::process::effective_uid().unwrap())
    }

    #[cfg(unix)]
    fn mode(p: &Path, m: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
    }

    #[cfg(unix)]
    fn rule_of(e: &ConfigError) -> Option<TrustRule> {
        match e {
            ConfigError::Untrusted { rule, .. } => Some(*rule),
            _ => None,
        }
    }

    #[cfg(unix)]
    #[test]
    fn trusted_file_accepted_when_owned_by_admin() {
        let s = Scratch::new();
        mode(&s.0, 0o755);
        let p = s.file("manifest.toml", b"a = 1\n");
        mode(&p, 0o644);
        assert_eq!(read_trusted(&p, 100, &me()).unwrap(), "a = 1\n");
        ensure_trusted_file(&p, &me()).unwrap();
        ensure_trusted_dir(&s.0, &me()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn trusted_file_refuses_group_and_world_writable() {
        let s = Scratch::new();
        mode(&s.0, 0o755);
        let p = s.file("manifest.toml", b"a = 1\n");
        mode(&p, 0o664);
        let e = read_trusted(&p, 100, &me()).unwrap_err();
        assert_eq!(rule_of(&e), Some(TrustRule::GroupWritable), "{e:?}");
        mode(&p, 0o646);
        let e = read_trusted(&p, 100, &me()).unwrap_err();
        assert_eq!(rule_of(&e), Some(TrustRule::WorldWritable), "{e:?}");
    }

    #[cfg(unix)]
    #[test]
    fn trusted_file_refuses_untrusted_owner() {
        let s = Scratch::new();
        mode(&s.0, 0o755);
        let p = s.file("manifest.toml", b"a = 1\n");
        mode(&p, 0o644);
        let uid = crate::process::effective_uid().unwrap();
        if uid == 0 {
            // Root owns the file: root is always trusted.
            return;
        }
        // Root only: a file owned by this (non-root) user is refused.
        let e = read_trusted(&p, 100, &TrustPolicy::root_only()).unwrap_err();
        assert!(matches!(e, ConfigError::Untrusted { .. }), "{e:?}");
        // Another administrator uid does not help either.
        let other = TrustPolicy::with_admin(uid.wrapping_add(1));
        assert!(read_trusted(&p, 100, &other).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn trusted_file_refuses_writable_parent_without_sticky() {
        let s = Scratch::new();
        let d = s.0.join("etc");
        std::fs::create_dir(&d).unwrap();
        let p = d.join("relay.toml");
        std::fs::write(&p, b"a = 1\n").unwrap();
        mode(&p, 0o644);
        for bad in [0o775, 0o777, 0o757] {
            mode(&d, bad);
            let e = read_trusted(&p, 100, &me()).unwrap_err();
            assert_eq!(
                rule_of(&e),
                Some(TrustRule::WritableDirectory),
                "{bad:o} {e:?}"
            );
        }
        // Sticky bit: others may not rename or remove this user's file.
        mode(&d, 0o1777);
        read_trusted(&p, 100, &me()).unwrap();
        mode(&d, 0o755);
        read_trusted(&p, 100, &me()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn trusted_file_checks_grandparents_and_resolved_links() {
        let s = Scratch::new();
        mode(&s.0, 0o755);
        let open = s.0.join("open");
        let inner = open.join("inner");
        std::fs::create_dir_all(&inner).unwrap();
        let p = inner.join("relay.toml");
        std::fs::write(&p, b"a = 1\n").unwrap();
        mode(&p, 0o644);
        mode(&inner, 0o755);
        mode(&open, 0o777);
        let e = read_trusted(&p, 100, &me()).unwrap_err();
        assert_eq!(rule_of(&e), Some(TrustRule::WritableDirectory), "{e:?}");
        // Reaching the same directory through a link is no way round it.
        let link = s.0.join("link");
        std::os::unix::fs::symlink(&inner, &link).unwrap();
        let e = read_trusted(&link.join("relay.toml"), 100, &me()).unwrap_err();
        assert_eq!(rule_of(&e), Some(TrustRule::WritableDirectory), "{e:?}");
        mode(&open, 0o755);
        read_trusted(&link.join("relay.toml"), 100, &me()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn trusted_dir_rules() {
        let s = Scratch::new();
        mode(&s.0, 0o755);
        let root = s.0.join("root");
        std::fs::create_dir(&root).unwrap();
        mode(&root, 0o755);
        ensure_trusted_dir(&root, &me()).unwrap();
        // The content directory itself: no group/other write, sticky or not.
        for bad in [0o775, 0o1777] {
            mode(&root, bad);
            assert!(ensure_trusted_dir(&root, &me()).is_err(), "{bad:o}");
        }
        mode(&root, 0o755);
        mode(&s.0, 0o777);
        let e = ensure_trusted_dir(&root, &me()).unwrap_err();
        assert_eq!(rule_of(&e), Some(TrustRule::WritableDirectory), "{e:?}");
        mode(&s.0, 0o755);
    }

    #[cfg(unix)]
    #[test]
    fn trusted_policy_owner_rules() {
        let p = TrustPolicy::root_only();
        assert!(p.is_trusted_owner(0));
        assert!(!p.is_trusted_owner(1000));
        let a = TrustPolicy::with_admin(1000);
        assert!(a.is_trusted_owner(0) && a.is_trusted_owner(1000));
        assert!(!a.is_trusted_owner(1001));
        assert!(a.service_is_trusted_owner(1000));
        assert!(!a.service_is_trusted_owner(999));
    }

    #[derive(Debug, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Sample {
        name: String,
    }

    #[test]
    fn parse_error_has_position_and_no_value() {
        let text = "name = \"x\"\nsecret_value_here = \"hunter2\"\n";
        let e = parse_toml::<Sample>(text).unwrap_err();
        match &e {
            ConfigError::Parse { line, .. } => assert_eq!(*line, 2),
            other => panic!("unexpected {other:?}"),
        }
        assert!(!e.to_string().contains("hunter2"), "{e}");
    }

    #[test]
    fn parse_ok() {
        let s: Sample = parse_toml("name = \"x\"").unwrap();
        assert_eq!(s.name, "x");
    }

    #[test]
    fn line_column_counts() {
        assert_eq!(line_column("abc", 0), (1, 1));
        assert_eq!(line_column("a\nbc", 3), (2, 2));
        assert_eq!(line_column("a\n", 99), (2, 1));
    }
}
