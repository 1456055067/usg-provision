//! Writing an applied image's tree under a root directory on Windows: the
//! operations behind `WinSink` (`winsink.rs`), on plain types so they are
//! independent of `usgp-image`.
//!
//! Rules:
//!
//! - Paths are joined only from checked components under the root, in
//!   `\\?\` form (long paths).
//! - Every create is create-new; nothing that exists is reused.
//! - Nothing is opened through a reparse point: every metadata handle is
//!   opened with open-reparse-point, and any path below a reparse point
//!   this writer made is refused.
//! - Content is written in full. Sparse and NTFS-compressed state is not
//!   re-created (the attribute bits are recorded by the image only).
//! - Reparse points (symbolic links and mount points) are set from the
//!   complete buffer `usgp-image` built and gated (decision 0022), after a
//!   structural check (topic 24).
//! - A descriptor's SACL is applied when `SeSecurityPrivilege` is held,
//!   and refused by name otherwise; it is never dropped.
//! - Privileges (AC-6, NIST-001): restore and backup are enabled for the
//!   writer's life (the apply step) and disabled when it is dropped; the
//!   security privilege only around a descriptor set with a SACL, and the
//!   create-symbolic-link privilege only around a reparse-point set.
//!
//! Semantics: topic 23 §20 to §24 (SR-3c, DRAFT, audit pending) and
//! topic 24. Still open there: OPEN-WAPI-7 (protected and auto-inherited
//! bits after a set; checked by `tests/winsink.rs`), OPEN-WAPI-9 (short
//! names with 8.3 generation off: observed to succeed in CI; any failure
//! is still a named error here) and OPEN-WAPI-10 (reparse
//! set details; any unexpected error fails the apply).

// COMPLIANCE MAPPING:
// - SPEC: specs/standards/windows-storage-firmware-api.md §20-§24
// - SPEC: specs/standards/reparse-and-security-descriptors.md §2-§9
// - NIST 800-53: SI-10 (Information Input Validation) - checked
//   components under one root; SI-7 - only verified image content reaches
//   here; AC-3 - descriptors applied as stored; AC-6 - privileges enabled
//   only while used
// - SPEC: specs/preinstall-env.md REQ-PE-017; specs/standards/wim.md §6
// - DECISION: docs/decisions/0019-windows-api-binding.md

use std::collections::BTreeSet;
use std::fs::{File, FileTimes, OpenOptions};
use std::io;
use std::os::windows::fs::{FileExt, FileTimesExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::GENERIC_WRITE;
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    SACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, READ_CONTROL,
    WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::SystemServices::ACCESS_SYSTEM_SECURITY;

use crate::error::{Result, WinApiError};
use crate::ffi;
use crate::fsquery;
use crate::fsvalues::{self, attributes_to_send, filetime_to_system_time, is_safe_component};
use crate::parse::to_wide_nul;
use crate::privilege::{self, EnabledPrivilege, Privilege};

/// The attribute bits the writer sets (topic 23 §22; see
/// [`crate::fsvalues::SETTABLE`]); the rest are never set directly.
pub const SETTABLE_ATTRIBUTES: u32 = fsvalues::SETTABLE;

// The pure rules use plain numbers; they must equal the platform values.
const _: () = {
    use windows_sys::Win32::Storage::FileSystem as fs;
    assert!(fsvalues::ATTR_READONLY == fs::FILE_ATTRIBUTE_READONLY);
    assert!(fsvalues::ATTR_HIDDEN == fs::FILE_ATTRIBUTE_HIDDEN);
    assert!(fsvalues::ATTR_SYSTEM == fs::FILE_ATTRIBUTE_SYSTEM);
    assert!(fsvalues::ATTR_DIRECTORY == fs::FILE_ATTRIBUTE_DIRECTORY);
    assert!(fsvalues::ATTR_ARCHIVE == fs::FILE_ATTRIBUTE_ARCHIVE);
    assert!(fsvalues::ATTR_DEVICE == fs::FILE_ATTRIBUTE_DEVICE);
    assert!(fsvalues::ATTR_NORMAL == fs::FILE_ATTRIBUTE_NORMAL);
    assert!(fsvalues::ATTR_TEMPORARY == fs::FILE_ATTRIBUTE_TEMPORARY);
    assert!(fsvalues::ATTR_SPARSE == fs::FILE_ATTRIBUTE_SPARSE_FILE);
    assert!(fsvalues::ATTR_REPARSE_POINT == fs::FILE_ATTRIBUTE_REPARSE_POINT);
    assert!(fsvalues::ATTR_COMPRESSED == fs::FILE_ATTRIBUTE_COMPRESSED);
    assert!(fsvalues::ATTR_OFFLINE == fs::FILE_ATTRIBUTE_OFFLINE);
    assert!(fsvalues::ATTR_NOT_CONTENT_INDEXED == fs::FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
    assert!(fsvalues::ATTR_ENCRYPTED == fs::FILE_ATTRIBUTE_ENCRYPTED);
    assert!(fsvalues::ATTR_VIRTUAL == fs::FILE_ATTRIBUTE_VIRTUAL);
};

const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
/// Topic 23 §26: open-reparse-point opens a reparse point itself, never
/// its target; backup semantics is needed for a directory handle and marks
/// a backup or restore open (§23).
const META_FLAGS: u32 = FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;

fn os(op: &'static str) -> impl FnOnce(io::Error) -> WinApiError {
    move |e| WinApiError::os(op, e)
}

/// Writes a tree under one root directory.
#[derive(Debug)]
pub struct TreeWriter {
    root: PathBuf,
    open: Option<(PathBuf, File)>,
    reparse: BTreeSet<Vec<String>>,
    /// Restore and backup, enabled for the writer's life; disabled when it
    /// is dropped. Declared last so the open file is closed first.
    _privileges: [EnabledPrivilege; 2],
}

impl TreeWriter {
    /// A writer rooted at `root`, an existing directory that is not a
    /// reparse point (typically a volume root). Enables the restore and
    /// backup privileges until the writer is dropped; fails if the process
    /// token does not hold them.
    pub fn new(root: &Path) -> Result<Self> {
        let root = fsquery::verbatim(root)?;
        let md = std::fs::symlink_metadata(&root).map_err(os("read root"))?;
        if !md.is_dir() || md.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(WinApiError::Refused {
                reason: "root is not a plain directory",
            });
        }
        // Topic 23 §23: restore (owners, writes whatever the ACL) and
        // backup (reads whatever the ACL), with backup semantics on every
        // metadata open.
        let restore = privilege::scoped(Privilege::Restore)?;
        let backup = privilege::scoped(Privilege::Backup)?;
        Ok(Self {
            root,
            open: None,
            reparse: BTreeSet::new(),
            _privileges: [restore, backup],
        })
    }

    /// The root (verbatim form).
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The path of `components` under the root. Refuses unsafe components
    /// and any path strictly below a reparse point this writer made.
    fn path(&self, components: &[&str]) -> Result<PathBuf> {
        let mut out = self.root.clone();
        for (i, c) in components.iter().enumerate() {
            if !is_safe_component(c) {
                return Err(WinApiError::Refused {
                    reason: "unsafe path component",
                });
            }
            let prefix: Vec<String> = components.iter().take(i).map(|s| (*s).to_owned()).collect();
            if i > 0 && self.reparse.contains(&prefix) {
                return Err(WinApiError::Refused {
                    reason: "path lies below a reparse point",
                });
            }
            out.push(c);
        }
        Ok(out)
    }

    fn is_reparse(&self, components: &[&str]) -> bool {
        let key: Vec<String> = components.iter().map(|s| (*s).to_owned()).collect();
        self.reparse.contains(&key)
    }

    fn not_root(components: &[&str]) -> Result<()> {
        if components.is_empty() {
            return Err(WinApiError::Refused {
                reason: "the root is never created",
            });
        }
        Ok(())
    }

    fn stream_target(&self, components: &[&str], stream: Option<&str>) -> Result<PathBuf> {
        let p = self.path(components)?;
        match stream {
            None => Ok(p),
            Some(s) if is_safe_component(s) => Ok(fsquery::stream_path(&p, s)),
            Some(_) => Err(WinApiError::Refused {
                reason: "unsafe stream name",
            }),
        }
    }

    /// Opens `components` for a metadata change with `access`, never
    /// following a reparse point.
    fn open_meta(&mut self, components: &[&str], access: u32) -> Result<File> {
        self.open = None;
        let p = self.path(components)?;
        OpenOptions::new()
            .access_mode(access)
            .share_mode(SHARE_ALL)
            .custom_flags(META_FLAGS)
            .open(p)
            .map_err(os("open for metadata"))
    }

    /// Creates directory `components` (its parent exists).
    pub fn create_dir(&mut self, components: &[&str]) -> Result<()> {
        Self::not_root(components)?;
        self.open = None;
        std::fs::create_dir(self.path(components)?).map_err(os("create directory"))
    }

    /// Creates the empty file `components`.
    pub fn create_file(&mut self, components: &[&str]) -> Result<()> {
        Self::not_root(components)?;
        self.open = None;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(self.path(components)?)
            .map(drop)
            .map_err(os("create file"))
    }

    /// Creates the empty named stream `stream` on the existing file or
    /// directory `components` (std opens streams as `path:name`).
    pub fn create_stream(&mut self, components: &[&str], stream: &str) -> Result<()> {
        if self.is_reparse(components) {
            return Err(WinApiError::Refused {
                reason: "stream on a reparse point",
            });
        }
        self.open = None;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.stream_target(components, Some(stream))?)
            .map(drop)
            .map_err(os("create stream"))
    }

    /// Writes `data` at `off` of the unnamed or named stream.
    pub fn write(
        &mut self,
        components: &[&str],
        stream: Option<&str>,
        off: u64,
        data: &[u8],
    ) -> Result<()> {
        if self.is_reparse(components) {
            return Err(WinApiError::Refused {
                reason: "write to a reparse point",
            });
        }
        let target = self.stream_target(components, stream)?;
        if self.open.as_ref().is_none_or(|(p, _)| *p != target) {
            let f = OpenOptions::new()
                .write(true)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&target)
                .map_err(os("open for write"))?;
            self.open = Some((target, f));
        }
        let Some((_, f)) = self.open.as_mut() else {
            return Err(WinApiError::Refused {
                reason: "no open file",
            });
        };
        let mut done = 0usize;
        while let Some(rest) = data.get(done..).filter(|r| !r.is_empty()) {
            let pos = off
                .checked_add(u64::try_from(done).unwrap_or(u64::MAX))
                .ok_or(WinApiError::Refused {
                    reason: "write offset overflow",
                })?;
            let n = f.seek_write(rest, pos).map_err(os("write"))?;
            if n == 0 {
                return Err(WinApiError::os(
                    "write",
                    io::Error::from(io::ErrorKind::WriteZero),
                ));
            }
            done = done.saturating_add(n);
        }
        Ok(())
    }

    /// Makes `new` a further name of `existing`.
    pub fn hard_link(&mut self, existing: &[&str], new: &[&str]) -> Result<()> {
        Self::not_root(new)?;
        if self.is_reparse(existing) {
            return Err(WinApiError::Refused {
                reason: "hard link to a reparse point",
            });
        }
        self.open = None;
        std::fs::hard_link(self.path(existing)?, self.path(new)?).map_err(os("create hard link"))
    }

    /// Sets the complete reparse buffer `buffer` (as `usgp-image` built
    /// it, header included) on `components`, unchanged
    /// (`FSCTL_SET_REPARSE_POINT`, topic 24 §6, topic 23 §24).
    ///
    /// `usgp-image` is the gate for which links are applied (relative,
    /// and absolute targets re-based by decision 0022). This writer only
    /// checks structure before any pointer reaches Windows
    /// (`parse::check_reparse_buffer`: length, `Reserved`, the tag is a
    /// symbolic link or a mount point, names in bounds, link flags 0 or
    /// relative), and the target: a mount point must be an empty
    /// directory; a symbolic link an empty directory or a zero-length
    /// file; never already a reparse point.
    ///
    /// Privilege: topic 24 §6 and topic 23 §24 say the caller must hold
    /// `SeCreateSymbolicLinkPrivilege`, without limiting that to
    /// symbolic-link tags, so it is enabled for both kinds (fail closed;
    /// see the WU-5 notes), for this call only. Any error fails
    /// (OPEN-WAPI-10).
    pub fn set_reparse(&mut self, components: &[&str], buffer: &[u8]) -> Result<()> {
        Self::not_root(components)?;
        let kind = crate::parse::check_reparse_buffer(buffer, &crate::layout::REPARSE)
            .map_err(WinApiError::Reparse)?;
        let p = self.path(components)?;
        self.open = None;
        let md = std::fs::symlink_metadata(&p).map_err(os("read metadata"))?;
        if md.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(WinApiError::Refused {
                reason: "already a reparse point",
            });
        }
        let empty = if md.is_dir() {
            std::fs::read_dir(&p)
                .map_err(os("list directory"))?
                .next()
                .is_none()
        } else {
            md.len() == 0
        };
        if !empty {
            return Err(WinApiError::Refused {
                reason: "reparse target is not empty",
            });
        }
        if kind == crate::parse::ReparseKind::MountPoint && !md.is_dir() {
            return Err(WinApiError::Refused {
                reason: "mount point target is not a directory",
            });
        }
        let link_privilege = privilege::scoped(Privilege::CreateSymbolicLink)?;
        let f = self.open_meta(components, GENERIC_WRITE)?;
        ffi::set_reparse_point(&f, buffer).map_err(os("set reparse point"))?;
        drop(f);
        drop(link_privilege);
        self.reparse
            .insert(components.iter().map(|s| (*s).to_owned()).collect());
        Ok(())
    }

    /// Sets the stored self-relative descriptor `sd`: owner, group, DACL
    /// and SACL, each as present. A SACL needs `SeSecurityPrivilege`,
    /// enabled for this call only (topic 23 §23: enable, open with
    /// `ACCESS_SYSTEM_SECURITY`, set, disable); if the token does not hold
    /// it the call fails with [`WinApiError::PrivilegeNotHeld`]. A SACL is
    /// never dropped.
    pub fn set_security(&mut self, components: &[&str], sd: &[u8]) -> Result<()> {
        let info = ffi::descriptor_info(sd).map_err(os("check security descriptor"))?;
        // Topic 23 §20: owner and group need WRITE_OWNER, the DACL
        // WRITE_DAC, the SACL ACCESS_SYSTEM_SECURITY.
        let mut access = READ_CONTROL;
        if info & (OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION) != 0 {
            access |= WRITE_OWNER;
        }
        if info & DACL_SECURITY_INFORMATION != 0 {
            access |= WRITE_DAC;
        }
        let sacl_privilege = if info & SACL_SECURITY_INFORMATION != 0 {
            access |= ACCESS_SYSTEM_SECURITY;
            Some(privilege::scoped(Privilege::Security)?)
        } else {
            None
        };
        let f = self.open_meta(components, access)?;
        let set = ffi::set_file_security(&f, sd, info).map_err(os("set security descriptor"));
        drop(f);
        drop(sacl_privilege);
        set
    }

    /// Sets the short name.
    pub fn set_short_name(&mut self, components: &[&str], name: &str) -> Result<()> {
        Self::not_root(components)?;
        let wide = to_wide_nul(name).ok_or(WinApiError::Refused {
            reason: "short name contains NUL",
        })?;
        // Topic 23 §21: DELETE access and backup semantics.
        let f = self.open_meta(components, DELETE)?;
        ffi::set_short_name(&f, &wide).map_err(|e| WinApiError::ShortNameNotSet {
            os_code: e.raw_os_error(),
        })
    }

    /// Sets creation, last-access and last-write times (FILETIME values).
    pub fn set_times(&mut self, components: &[&str], times: [u64; 3]) -> Result<()> {
        let [c, a, w] = times.map(filetime_to_system_time);
        let (Some(c), Some(a), Some(w)) = (c, a, w) else {
            return Err(WinApiError::Refused {
                reason: "time not representable",
            });
        };
        let f = self.open_meta(components, FILE_WRITE_ATTRIBUTES)?;
        f.set_times(
            FileTimes::new()
                .set_created(c)
                .set_accessed(a)
                .set_modified(w),
        )
        .map_err(os("set times"))
    }

    /// Sets the settable bits of the stored attribute value
    /// ([`SETTABLE_ATTRIBUTES`], topic 23 §22, by the pure
    /// [`attributes_to_send`]). Structural bits (directory, reparse) and
    /// bits set by other means that are not implemented (sparse,
    /// compressed; POAM there) are never sent. System-reserved (device,
    /// virtual), encrypted and unnamed bits are refused. Zero is never
    /// sent (it means "unchanged"); a file with no settable bit gets
    /// `NORMAL`, a directory never does (OPEN-WAPI-12).
    // COMPLIANCE MAPPING:
    // - NIST 800-53: SI-7, SI-10
    // - SPEC: specs/standards/windows-storage-firmware-api.md §22
    //   (OPEN-WAPI-11: CI showed a basic-information set failing with
    //   InvalidInput on the WU-5 tree; only settable bits are sent)
    pub fn set_attributes(&mut self, components: &[&str], stored: u32) -> Result<()> {
        Self::not_root(components)?;
        let f = self.open_meta(
            components,
            FILE_WRITE_ATTRIBUTES | windows_sys::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES,
        )?;
        let md = f.metadata().map_err(os("read attributes"))?;
        let send = attributes_to_send(md.file_attributes(), stored, md.is_dir())
            .map_err(|reason| WinApiError::Refused { reason })?;
        match send {
            None => Ok(()),
            Some(v) => ffi::update_attributes(&f, |_| v).map_err(os("set attributes")),
        }
    }

    /// CI probe only (feature `sink-testkit`): sends `value` unmasked in a
    /// basic-information set on `components` and returns the raw OS
    /// result, so a test can record what Windows answers (e.g. `NORMAL`
    /// on a directory, OPEN-WAPI-12). Product code never calls this and
    /// never sends `NORMAL` to a directory.
    // COMPLIANCE MAPPING:
    // - NIST 800-53: SA-11 (Developer Testing and Evaluation)
    // - SPEC: specs/standards/windows-storage-firmware-api.md §22
    //   (OPEN-WAPI-12 probe)
    #[cfg(feature = "sink-testkit")]
    pub fn probe_set_attributes_raw(
        &mut self,
        components: &[&str],
        value: u32,
    ) -> Result<io::Result<()>> {
        Self::not_root(components)?;
        let f = self.open_meta(
            components,
            FILE_WRITE_ATTRIBUTES | windows_sys::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES,
        )?;
        Ok(ffi::update_attributes(&f, |_| value))
    }

    /// Closes any open data handle.
    pub fn finish(&mut self) {
        self.open = None;
    }
}
