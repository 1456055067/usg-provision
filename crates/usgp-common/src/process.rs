//! Facts about the running process for audit records and trust checks:
//! effective uid, real uid and host name.
//!
//! No `unsafe` is used (the workspace forbids it), so the values come from
//! the kernel through file descriptors and procfs rather than from libc
//! calls:
//!
//! - the effective uid is the owner of a freshly created Unix socket pair
//!   (the kernel stamps a new socket with the creator's effective, on
//!   Linux file-system, uid; the two differ only after `setfsuid`, which
//!   no usgp process calls);
//! - the real uid is the first `Uid:` field of `/proc/self/status`
//!   (Linux only);
//! - the host name is `/proc/sys/kernel/hostname` (Linux only).
//!
//! Every read is bounded. Where a value cannot be found the functions
//! return `None` or an error; callers decide whether that is fatal.

// COMPLIANCE MAPPING:
// - NIST 800-53: AU-3 (Content of Audit Records) - "who" (uid) and "where"
//   (host name) for audit records.
// - NIST 800-53: CM-5 / SI-7 - the service uid feeds the trusted-file
//   rules in `crate::config`.
// - NIST 800-53: SI-10 - procfs reads are size-bounded and parsed
//   strictly.

use std::io;

/// Longest procfs text read here. `/proc/self/status` is about 1.5 KiB;
/// the host name is at most 64 octets on Linux.
#[cfg(target_os = "linux")]
const MAX_PROC_BYTES: u64 = 16 * 1024;

/// Longest host name accepted (Linux `HOST_NAME_MAX`).
pub const MAX_HOSTNAME_LEN: usize = 64;

/// The process's effective uid.
///
/// # Errors
///
/// The socket error, or [`io::ErrorKind::Unsupported`] off Unix.
pub fn effective_uid() -> io::Result<u32> {
    #[cfg(unix)]
    {
        use std::os::fd::OwnedFd;
        use std::os::unix::fs::MetadataExt;

        let (a, _b) = std::os::unix::net::UnixDatagram::pair()?;
        let file = std::fs::File::from(OwnedFd::from(a));
        Ok(file.metadata()?.uid())
    }
    #[cfg(not(unix))]
    {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// The process's real uid, where the platform exposes it without `unsafe`
/// (Linux procfs). `None` elsewhere or if procfs is unavailable.
#[must_use]
pub fn real_uid() -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        let text = read_proc("/proc/self/status")?;
        parse_status_real_uid(&text)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// The system host name (Linux procfs), if it is 1 to
/// [`MAX_HOSTNAME_LEN`] printable ASCII characters. `None` elsewhere.
#[must_use]
pub fn hostname() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let text = read_proc("/proc/sys/kernel/hostname")?;
        valid_hostname(text.trim_end_matches('\n'))
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(target_os = "linux")]
fn read_proc(path: &str) -> Option<String> {
    use std::io::Read;
    let file = std::fs::File::open(path).ok()?;
    let mut buf = Vec::new();
    file.take(MAX_PROC_BYTES).read_to_end(&mut buf).ok()?;
    String::from_utf8(buf).ok()
}

/// The real uid from `/proc/self/status` text: the first number on the
/// `Uid:` line (real, effective, saved, file-system).
#[must_use]
pub fn parse_status_real_uid(text: &str) -> Option<u32> {
    let line = text.lines().find_map(|l| l.strip_prefix("Uid:"))?;
    line.split_whitespace().next()?.parse().ok()
}

/// `name` if it is 1 to [`MAX_HOSTNAME_LEN`] printable ASCII characters.
#[must_use]
pub fn valid_hostname(name: &str) -> Option<String> {
    let ok =
        (1..=MAX_HOSTNAME_LEN).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_graphic());
    ok.then(|| name.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn effective_uid_matches_owner_of_a_new_file() {
        use std::os::unix::fs::MetadataExt;
        let p = std::env::temp_dir().join(format!("usgp-common-euid-{}", std::process::id()));
        std::fs::write(&p, b"x").unwrap();
        let owner = std::fs::metadata(&p).unwrap().uid();
        let _ = std::fs::remove_file(&p);
        assert_eq!(effective_uid().unwrap(), owner);
    }

    #[test]
    fn status_parsing() {
        let text = "Name:\tx\nUmask:\t0022\nUid:\t1000\t0\t0\t0\nGid:\t5\t5\t5\t5\n";
        assert_eq!(parse_status_real_uid(text), Some(1000));
        assert_eq!(parse_status_real_uid("Name:\tx\n"), None);
        assert_eq!(parse_status_real_uid("Uid:\tabc\n"), None);
        assert_eq!(parse_status_real_uid("Uid:\n"), None);
    }

    #[test]
    fn hostname_rules() {
        assert_eq!(
            valid_hostname("relay-a.lab").as_deref(),
            Some("relay-a.lab")
        );
        assert_eq!(valid_hostname(""), None);
        assert_eq!(valid_hostname("a b"), None);
        assert_eq!(valid_hostname("a\u{1}"), None);
        assert_eq!(valid_hostname(&"a".repeat(65)), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_procfs_values() {
        assert!(real_uid().is_some());
        assert!(hostname().is_some());
    }
}
