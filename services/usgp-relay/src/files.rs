//! Reading the `[server_feed]` material: PEM trust anchors, the relay's
//! client certificate and private key, and the pinned boot-policy key
//! (plan WU-11, section 3.9).
//!
//! The configuration and manifest are text and are read with
//! [`usgp_common::config::read_trusted`]. The feed's private key must land
//! in a buffer that is wiped, so these files are read here, under the same
//! trusted-file rules:
//!
//! 1. [`usgp_common::config::ensure_trusted_file`] checks the path (regular
//!    file, not a symbolic link, owned by root or the administrator uid,
//!    not group- or world-writable, every directory above it trusted);
//! 2. the **opened handle** is checked again (regular file, trusted owner,
//!    not group- or world-writable) and the path must still name it (same
//!    device and inode);
//! 3. at most `max_bytes` are read, into a [`Zeroizing`] buffer sized from
//!    the file length.
//!
//! The private key must in addition not be readable by others, nor by the
//! group unless the group is the relay's own (`0600`, or `0640` with the
//! service's group).
//!
//! The same rules exist in `usgp-server` (`files.rs`); a shared helper in
//! `usgp-common` would remove the duplicate (reported in the WU-11 notes).

// COMPLIANCE MAPPING:
// - NIST 800-53: CM-5 (Access Restrictions for Change) / SI-7 - trusted
//   owner and mode, directory chain, checked on the opened handle.
// - NIST 800-53: SI-10 (Information Input Validation) - size bound before
//   reading; regular files only.
// - NIST 800-53: SC-12 (Cryptographic Key Establishment and Management),
//   SC-4 (Information in Shared System Resources) - the relay client key
//   is read into a wiped buffer and refused if others can read it.
// - SPEC: plan M3 section 5 ("relay side: the relay client key")

// POAM: SC-4 - if a key file grows between the length check and the read,
// the buffer can reallocate once and the old allocation is not wiped (the
// read is still bounded). Key files are written once by an administrator,
// so this needs a concurrent writer with trusted-owner rights.

use std::io::Read;
use std::path::{Path, PathBuf};

use usgp_common::config::{ConfigError, TrustPolicy, TrustRule, ensure_trusted_file};
use zeroize::Zeroizing;

/// Largest PEM certificate or trust-anchor file.
pub const MAX_CERT_PEM_BYTES: u64 = 256 * 1024;
/// Largest PEM private or public key file.
pub const MAX_KEY_PEM_BYTES: u64 = 16 * 1024;

/// Why a feed file was refused.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FileError {
    /// A trusted-file rule failed or the file could not be read.
    #[error(transparent)]
    File(#[from] ConfigError),
    /// The private key is readable by others, or by a group other than the
    /// relay's.
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
}

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
    read_checked(path, max_bytes, policy).map(|(bytes, _)| bytes)
}

/// [`read_trusted_bytes`] for public data.
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

/// The mode rule for the private key: `None` if acceptable, else who may
/// read it. `group_ok` says whether the file's group is the relay's.
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

/// Reads the relay's private key: [`read_trusted_bytes`] plus the mode
/// rule, checked on the opened handle.
///
/// # Errors
///
/// [`FileError`].
pub fn read_private_key(
    path: &Path,
    max_bytes: u64,
    policy: &TrustPolicy,
) -> Result<Zeroizing<Vec<u8>>, FileError> {
    let (bytes, meta) = read_checked(path, max_bytes, policy)?;
    let root = usgp_common::process::effective_uid().ok() == Some(0);
    let group_ok = root || effective_gid().ok() == Some(meta.gid);
    if let Some(who) = private_key_mode_refusal(meta.mode, group_ok) {
        return Err(FileError::Readable {
            path: path.to_path_buf(),
            who,
        });
    }
    Ok(bytes)
}

/// Mode and group of the opened handle.
#[derive(Debug, Clone, Copy)]
struct OpenedMeta {
    mode: u32,
    gid: u32,
}

fn read_checked(
    path: &Path,
    max_bytes: u64,
    policy: &TrustPolicy,
) -> Result<(Zeroizing<Vec<u8>>, OpenedMeta), ConfigError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

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
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|e| io_err(&e))?;
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
        Ok((
            buf,
            OpenedMeta {
                mode: meta.mode(),
                gid: meta.gid(),
            },
        ))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, max_bytes, policy, ensure_trusted_file);
        Err(ConfigError::UnsupportedPlatform)
    }
}

/// The process's effective gid: the group of a freshly created Unix
/// socket (no `unsafe`; same method as
/// `usgp_common::process::effective_uid`).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_mode_rule() {
        assert_eq!(private_key_mode_refusal(0o100600, false), None);
        assert_eq!(private_key_mode_refusal(0o100400, false), None);
        assert_eq!(private_key_mode_refusal(0o100640, true), None);
        assert_eq!(private_key_mode_refusal(0o100640, false), Some("group"));
        assert_eq!(private_key_mode_refusal(0o100604, true), Some("others"));
        assert_eq!(private_key_mode_refusal(0o100644, true), Some("others"));
    }
}
