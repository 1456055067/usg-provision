//! Read-only file metadata queries that `std` does not cover: named data
//! streams, hard-link names, the owner/group/DACL as SDDL, and the
//! attributes with the reparse tag. Used by the tree manifest
//! ([`crate::manifest`]); the file-system writer (`fs.rs`, `WinSink`)
//! comes later with WU-4's apply-sink trait.
//!
//! SR-3: none of `FindFirstStreamW`/`FindNextStreamW`,
//! `FindFirstFileNameW`/`FindNextFileNameW`, `GetFileSecurityW`,
//! `ConvertSecurityDescriptorToStringSecurityDescriptorW` or
//! `GetFileInformationByHandleEx` is summarised in topic 23 (spec request
//! in the WU-5 notes). Unexpected forms are errors, never skipped.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation); SA-11 (Developer
//   Testing and Evaluation) - apply-fidelity oracle input
// - SPEC: specs/preinstall-env.md REQ-PE-017 (through the tree manifest)
// - DECISION: docs/decisions/0019-windows-api-binding.md

use std::fs::OpenOptions;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
};

use crate::error::{Result, WinApiError};
use crate::ffi;
use crate::parse::{ParseError, from_wide, to_wide_nul};
use crate::paths::StreamEntry;

/// Most streams listed for one file.
pub const MAX_STREAMS: usize = 4096;
/// Most link names listed for one file.
pub const MAX_LINK_NAMES: usize = 1024;

fn malformed(op: &'static str) -> WinApiError {
    WinApiError::Malformed {
        op,
        source: ParseError::InvalidUtf16,
    }
}

/// The `\\?\` (verbatim) form of `path`, made absolute, so that paths
/// over 260 characters work. Only local drive-letter paths and paths
/// already in verbatim form are accepted.
pub fn verbatim(path: &Path) -> Result<PathBuf> {
    let abs = std::path::absolute(path).map_err(|e| WinApiError::os("make path absolute", e))?;
    let s = abs.to_str().ok_or_else(|| malformed("path"))?;
    if s.starts_with("\\\\?\\") {
        return Ok(abs);
    }
    let mut chars = s.chars();
    match (chars.next(), chars.next(), chars.next()) {
        (Some(c), Some(':'), Some('\\')) if c.is_ascii_alphabetic() => {
            Ok(PathBuf::from(format!("\\\\?\\{s}")))
        }
        _ => Err(WinApiError::Refused {
            reason: "only local drive-letter paths are accepted",
        }),
    }
}

fn wide_path(path: &Path) -> Result<Vec<u16>> {
    let s = path.to_str().ok_or_else(|| malformed("path"))?;
    to_wide_nul(s).ok_or(WinApiError::Refused {
        reason: "path contains NUL",
    })
}

/// A named stream and its size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedStream {
    /// Stream name (without colons or type).
    pub name: String,
    /// Size in bytes.
    pub size: u64,
}

/// The named data streams of `path` (the unnamed stream is left out),
/// sorted by name in UTF-16 code-unit order.
pub fn named_streams(path: &Path) -> Result<Vec<NamedStream>> {
    let raw = ffi::file_streams(&wide_path(path)?, MAX_STREAMS)
        .map_err(|e| WinApiError::os("list streams", e))?;
    let mut out = Vec::new();
    for r in raw {
        let name = from_wide(&r.name).map_err(|e| WinApiError::malformed("stream name", e))?;
        let size = u64::try_from(r.size)
            .map_err(|_| WinApiError::malformed("stream size", ParseError::Negative))?;
        match StreamEntry::parse(&name) {
            Some(StreamEntry::Unnamed) => {}
            Some(StreamEntry::Named(name)) => out.push(NamedStream { name, size }),
            None => return Err(malformed("stream name form")),
        }
    }
    out.sort_by(|a, b| a.name.encode_utf16().cmp(b.name.encode_utf16()));
    Ok(out)
}

/// The path of named stream `name` of `path` (`path:name`; `std` opens
/// streams by this name, decision 0019 item 3).
#[must_use]
pub fn stream_path(path: &Path, name: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(":");
    s.push(name);
    PathBuf::from(s)
}

/// The names (hard links) of the file at `path`, as Windows returns them.
pub fn link_names(path: &Path) -> Result<Vec<String>> {
    ffi::file_link_names(&wide_path(path)?, MAX_LINK_NAMES)
        .map_err(|e| WinApiError::os("list link names", e))?
        .iter()
        .map(|u| from_wide(u).map_err(|e| WinApiError::malformed("link name", e)))
        .collect()
}

/// The owner, group and DACL of `path` as the self-relative security
/// descriptor Windows returns (spec §19).
pub fn security_descriptor(path: &Path) -> Result<Vec<u8>> {
    ffi::file_security(&wide_path(path)?).map_err(|e| WinApiError::os("read security", e))
}

/// The owner, group and DACL of `path` as SDDL.
pub fn sddl(path: &Path) -> Result<String> {
    let units =
        ffi::file_sddl(&wide_path(path)?).map_err(|e| WinApiError::os("read security", e))?;
    from_wide(&units).map_err(|e| WinApiError::malformed("SDDL", e))
}

/// The attributes and reparse tag of `path` itself (a reparse point is not
/// followed). The tag is meaningful only when the reparse-point attribute
/// is set.
pub fn attributes_and_tag(path: &Path) -> Result<(u32, u32)> {
    let file = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|e| WinApiError::os("open for attributes", e))?;
    ffi::attribute_tag(&file).map_err(|e| WinApiError::os("read attributes and tag", e))
}

/// The complete reparse buffer of the reparse point at `path` (header and
/// data), read with `FSCTL_GET_REPARSE_POINT` on a handle that does not
/// follow it. Used to compare an applied link with the buffer that was set
/// (the check `fsutil reparsepoint query` makes).
///
/// SR request: `FSCTL_GET_REPARSE_POINT` is not summarised in topic 23 or
/// 24; this relies only on success and the returned bytes.
pub fn reparse_buffer(path: &Path) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|e| WinApiError::os("open reparse point", e))?;
    let max = crate::layout::REPARSE.data + usize::from(u16::MAX);
    ffi::device_io_control(
        &file,
        windows_sys::Win32::System::Ioctl::FSCTL_GET_REPARSE_POINT,
        ffi::IoctlInput::None,
        max,
    )
    .map_err(|f| WinApiError::os("read reparse point", f.error))
}
