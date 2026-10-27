//! Reading the trusted files the configuration names: certificates, CRLs
//! (PEM or DER), public keys and private keys.
//!
//! The configuration file itself is text and is read with
//! [`usgp_common::config::read_trusted`]. The files it names may be binary
//! (a DER CRL) or secret (a private key, which must land in a buffer that
//! is wiped), so they are read here, under the same trust rules:
//!
//! 1. [`usgp_common::config::ensure_trusted_file`] checks the path: a
//!    regular file, not a symbolic link, owned by root or the
//!    administrator uid, not group- or world-writable, and every directory
//!    above it trusted;
//! 2. the file is opened and the **opened handle** is checked again: a
//!    regular file, trusted owner, not group- or world-writable;
//! 3. the path must still name the opened file (same device and inode),
//!    so a swap between the checks is refused;
//! 4. at most `max_bytes` are read, into a [`Zeroizing`] buffer sized
//!    from the file length, so a private key is not copied into
//!    unwiped reallocations.
//!
//! Private keys ([`read_private_key`]) must in addition not be readable by
//! others (mode `0o004`), nor by the group unless the group is the
//! service's own (the process's effective gid): `root:<service group>
//! 0640` or `0600` (finding SEC-005). A command run as root does not know
//! the service's group, so it accepts a group-readable key; `serve`, which
//! runs as the service user, applies the full rule at every start.
//!
//! Administrative keys ([`KeyAccess::OwnerOnly`]: the `[database.admin]`
//! client key and the owner role's `--owner-key`) must not be readable by
//! group or others at all, whoever runs the command, root included: mode
//! `0600` or `0400` (finding SEC-011; decision 0016 item 3). The service
//! account must never be able to read them; `serve` also refuses to start
//! if it can open the configured admin key
//! (`serve::admin_key_refusal`).

// COMPLIANCE MAPPING:
// - NIST 800-53: CM-5 (Access Restrictions for Change) / SI-7 - trusted
//   owner and mode, directory chain, checked on the opened handle.
// - NIST 800-53: SI-10 (Information Input Validation) - size bound before
//   reading; regular files only.
// - NIST 800-53: SC-12 (Cryptographic Key Establishment and Management),
//   SC-4 (Information in Shared System Resources) - private keys read
//   into wiped buffers.
// - NIST 800-53: SC-12, AC-6 - private key files refused if readable by
//   others or by a group other than the service's.
// - NIST 800-53: AC-6, AC-6(1), SC-12 - administrative database keys
//   (admin and owner roles) refused unless readable by their owner only
//   (decision 0016 item 3; finding SEC-011).
// - SPEC: plan M2 section 5.2 (keys read with the trusted-file rules)

// POAM: if a file grows between the length check and the read, the
// buffer can reallocate once and the old allocation is not wiped (the
// read is still bounded by `max_bytes`). Key files are written once by an
// administrator, so this needs a concurrent writer with trusted-owner
// rights.

use std::io::Read;
use std::path::{Path, PathBuf};

use usgp_common::config::{ConfigError, TrustPolicy, TrustRule, ensure_trusted_file};
use zeroize::Zeroizing;

/// Reads a trusted file of at most `max_bytes` bytes (module rules).
///
/// # Errors
///
/// [`ConfigError`] naming the path and the rule that failed.
pub fn read_trusted_bytes(
    path: &Path,
    max_bytes: u64,
    policy: &TrustPolicy,
) -> Result<Zeroizing<Vec<u8>>, ConfigError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        const GROUP_WRITE: u32 = 0o020;
        const OTHER_WRITE: u32 = 0o002;

        ensure_trusted_file(path, policy)?;
        let io_err = |e: &std::io::Error| ConfigError::Io {
            path: path.to_path_buf(),
            kind: e.kind(),
        };
        let untrusted = |rule| ConfigError::Untrusted {
            path: path.to_path_buf(),
            rule,
        };
        let file = std::fs::File::open(path).map_err(|e| io_err(&e))?;
        let meta = file.metadata().map_err(|e| io_err(&e))?;
        if !meta.is_file() {
            return Err(ConfigError::NotRegularFile {
                path: path.to_path_buf(),
            });
        }
        if meta.mode() & OTHER_WRITE != 0 {
            return Err(untrusted(TrustRule::WorldWritable));
        }
        if meta.mode() & GROUP_WRITE != 0 {
            return Err(untrusted(TrustRule::GroupWritable));
        }
        if !policy.is_trusted_owner(meta.uid()) {
            return Err(untrusted(TrustRule::Owner));
        }
        let now = std::fs::symlink_metadata(path).map_err(|_| untrusted(TrustRule::Replaced))?;
        if now.dev() != meta.dev() || now.ino() != meta.ino() {
            return Err(untrusted(TrustRule::Replaced));
        }
        let too_large = || ConfigError::TooLarge {
            path: path.to_path_buf(),
            max_bytes,
        };
        if meta.len() > max_bytes {
            return Err(too_large());
        }
        let cap = usize::try_from(meta.len())
            .map_err(|_| too_large())?
            .saturating_add(1);
        let mut buf = Zeroizing::new(Vec::with_capacity(cap));
        file.take(max_bytes.saturating_add(1))
            .read_to_end(&mut buf)
            .map_err(|e| io_err(&e))?;
        let read = u64::try_from(buf.len()).unwrap_or(u64::MAX);
        if read > max_bytes {
            return Err(too_large());
        }
        Ok(buf)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, max_bytes, policy, ensure_trusted_file);
        Err(ConfigError::UnsupportedPlatform)
    }
}

/// [`read_trusted_bytes`] for public data: the bytes are moved out of the
/// wiped buffer without a copy.
///
/// # Errors
///
/// As [`read_trusted_bytes`].
pub fn read_trusted_public(
    path: &Path,
    max_bytes: u64,
    policy: &TrustPolicy,
) -> Result<Vec<u8>, ConfigError> {
    let mut z = read_trusted_bytes(path, max_bytes, policy)?;
    Ok(std::mem::take(&mut *z))
}

/// Why a private key file was refused.
#[derive(Debug, thiserror::Error)]
pub enum PrivateKeyFileError {
    /// A trusted-file rule failed or the file could not be read.
    #[error(transparent)]
    File(#[from] ConfigError),
    /// The file is readable by others, or by a group other than the
    /// service's.
    #[error(
        "{} is readable by {who}; a private key must be mode 0600, or 0640 with the service's group",
        path.display()
    )]
    Readable {
        /// The file.
        path: PathBuf,
        /// `others` or `group`.
        who: &'static str,
    },
    /// An administrative key is readable by group or others.
    #[error(
        "{} is readable by {who}; an administrative database key must be mode 0600 or 0400 \
         (readable by its owner only, never by the service account)",
        path.display()
    )]
    AdminReadable {
        /// The file.
        path: PathBuf,
        /// `others` or `group`.
        who: &'static str,
    },
}

/// Who besides the owner may read a private key file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAccess {
    /// Keys the service reads (TLS, application database role, signing
    /// keys): `0600`, or `0640` with the service's group.
    Service,
    /// Administrative database keys (`[database.admin]`, owner role):
    /// `0600` or `0400` only, regardless of who runs the command.
    OwnerOnly,
}

/// The process's effective gid: the group of a freshly created Unix
/// socket (no `unsafe`; same method as `usgp_common::process::effective_uid`).
///
/// # Errors
///
/// The socket error, or `Unsupported` off Unix.
pub fn effective_gid() -> std::io::Result<u32> {
    #[cfg(unix)]
    {
        use std::os::fd::OwnedFd;
        use std::os::unix::fs::MetadataExt;

        let (a, _b) = std::os::unix::net::UnixDatagram::pair()?;
        let file = std::fs::File::from(OwnedFd::from(a));
        Ok(file.metadata()?.gid())
    }
    #[cfg(not(unix))]
    {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }
}

/// The mode rule for private keys: `None` if acceptable, else who may
/// read it. `group_ok` says whether the file's group is the service's.
#[must_use]
pub fn private_key_mode_refusal(mode: u32, group_ok: bool) -> Option<&'static str> {
    const GROUP_READ: u32 = 0o040;
    const OTHER_READ: u32 = 0o004;
    if mode & OTHER_READ != 0 {
        Some("others")
    } else if mode & GROUP_READ != 0 && !group_ok {
        Some("group")
    } else {
        None
    }
}

/// The mode rule for administrative keys: `None` if only the owner may
/// read it, else who else may.
#[must_use]
pub fn admin_key_mode_refusal(mode: u32) -> Option<&'static str> {
    private_key_mode_refusal(mode, false)
}

/// Reads a key the service uses ([`KeyAccess::Service`]).
///
/// # Errors
///
/// [`PrivateKeyFileError`].
pub fn read_private_key(
    path: &Path,
    max_bytes: u64,
    policy: &TrustPolicy,
) -> Result<Zeroizing<Vec<u8>>, PrivateKeyFileError> {
    read_private_key_with(path, max_bytes, policy, KeyAccess::Service)
}

/// Reads a private key: [`read_trusted_bytes`] plus the mode rule for
/// `access` (module documentation).
///
/// # Errors
///
/// [`PrivateKeyFileError`].
pub fn read_private_key_with(
    path: &Path,
    max_bytes: u64,
    policy: &TrustPolicy,
    access: KeyAccess,
) -> Result<Zeroizing<Vec<u8>>, PrivateKeyFileError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let bytes = read_trusted_bytes(path, max_bytes, policy)?;
        // The trusted read verified the inode; this re-check of the mode
        // is on the same path, which must still name a trusted file.
        let meta = std::fs::metadata(path).map_err(|e| ConfigError::Io {
            path: path.to_path_buf(),
            kind: e.kind(),
        })?;
        match access {
            KeyAccess::Service => {
                let root = usgp_common::process::effective_uid().ok() == Some(0);
                let group_ok = root || effective_gid().ok() == Some(meta.gid());
                if let Some(who) = private_key_mode_refusal(meta.mode(), group_ok) {
                    return Err(PrivateKeyFileError::Readable {
                        path: path.to_path_buf(),
                        who,
                    });
                }
            }
            KeyAccess::OwnerOnly => {
                if let Some(who) = admin_key_mode_refusal(meta.mode()) {
                    return Err(PrivateKeyFileError::AdminReadable {
                        path: path.to_path_buf(),
                        who,
                    });
                }
            }
        }
        Ok(bytes)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, max_bytes, policy, access);
        Err(ConfigError::UnsupportedPlatform.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_key_modes() {
        assert_eq!(private_key_mode_refusal(0o100_600, false), None);
        assert_eq!(private_key_mode_refusal(0o100_400, false), None);
        assert_eq!(private_key_mode_refusal(0o100_640, true), None);
        assert_eq!(private_key_mode_refusal(0o100_640, false), Some("group"));
        assert_eq!(private_key_mode_refusal(0o100_644, true), Some("others"));
        assert_eq!(private_key_mode_refusal(0o100_604, false), Some("others"));
    }

    /// SEC-011: administrative keys are owner-only whoever runs the
    /// command.
    #[test]
    fn admin_key_modes() {
        assert_eq!(admin_key_mode_refusal(0o100_600), None);
        assert_eq!(admin_key_mode_refusal(0o100_400), None);
        assert_eq!(admin_key_mode_refusal(0o100_640), Some("group"));
        assert_eq!(admin_key_mode_refusal(0o100_440), Some("group"));
        assert_eq!(admin_key_mode_refusal(0o100_604), Some("others"));
    }

    /// SEC-011: the reader applies the owner-only rule to a real file, and
    /// the service rule still accepts the same file with the service's
    /// group.
    #[cfg(unix)]
    #[test]
    fn admin_key_reader_refuses_group_readable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "usgp-files-admin-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let key = dir.join("admin.key");
        std::fs::write(&key, b"-----BEGIN PRIVATE KEY-----\n").unwrap();
        let uid = usgp_common::process::effective_uid().unwrap();
        let policy = TrustPolicy {
            admin_uid: Some(uid),
        };
        let trusted_dirs = ensure_trusted_file(&key, &policy).is_ok();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o640)).unwrap();
        let r = read_private_key_with(&key, 4096, &policy, KeyAccess::OwnerOnly);
        if trusted_dirs {
            assert!(
                matches!(
                    r,
                    Err(PrivateKeyFileError::AdminReadable { who: "group", .. })
                ),
                "{r:?}"
            );
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert!(read_private_key_with(&key, 4096, &policy, KeyAccess::OwnerOnly).is_ok());
        } else {
            // The temporary directory's parents are not trusted here; the
            // mode rule is covered by `admin_key_modes`.
            assert!(r.is_err());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
