//! The only module in the workspace allowed to hold `unsafe` code
//! (decision 0019 item 2).
//!
//! Every `unsafe` block here carries a `// SAFETY:` comment
//! (`clippy::undocumented_unsafe_blocks` is denied). Calls go through
//! `windows-sys` declarations only. Safe wrappers in the other modules
//! never use `unsafe` themselves.
//!
//! Rules kept by every function here:
//!
//! - Output buffers are owned, zero-initialised Rust allocations whose
//!   length is passed to Windows exactly; results are copied out as bytes
//!   or UTF-16 units and parsed by safe code (`crate::parse`).
//! - String inputs are checked to be NUL-terminated with no interior NUL
//!   before their pointer is passed ([`check_wide`]).
//! - Handles are wrapped so they are closed exactly once.
//! - `GetLastError` is read immediately after the failing call.
//! - The only firmware-variable write is [`set_boot_variable`], which takes
//!   a [`WritableBootVar`] and builds the name, namespace and attributes
//!   itself, so no caller can name a Secure Boot variable (0018 item 5).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-16 (Memory Protection), SA-15 (Development Process,
//   Standards, and Tools), SI-7 (Software, Firmware, and Information
//   Integrity) - Secure Boot variables never written
// - SPEC: specs/standards/windows-storage-firmware-api.md §1, §8, §9, §10
// - DECISION: docs/decisions/0019-windows-api-binding.md

#![allow(unsafe_code)]

use core::ffi::c_void;
use core::ptr;
use std::fs::File;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use windows_sys::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, ERROR_NO_MORE_FILES, ERROR_NOT_ALL_ASSIGNED,
    HANDLE, INVALID_HANDLE_VALUE, LUID, MAX_PATH,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
    SE_SYSTEM_ENVIRONMENT_NAME, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::Storage::FileSystem::{
    DeleteVolumeMountPointW, FindFirstVolumeW, FindNextVolumeW, FindVolumeClose,
    GetVolumeInformationW, GetVolumeNameForVolumeMountPointW, GetVolumePathNamesForVolumeNameW,
    SetVolumeMountPointW,
};
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::Ioctl::{
    PropertyStandardQuery, STORAGE_PROPERTY_ID, STORAGE_PROPERTY_QUERY,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::System::WindowsProgramming::{
    GetFirmwareEnvironmentVariableExW, SetFirmwareEnvironmentVariableExW,
};

use crate::parse::to_wide_nul;
use crate::vars::{BOOT_VAR_ATTRIBUTES, EFI_GLOBAL_VARIABLE, MAX_BOOT_VAR_WRITE, WritableBootVar};

/// UTF-16 units for one volume GUID path (49 characters plus NUL); a
/// generous fixed buffer.
const VOLUME_NAME_UNITS: usize = 1024;

fn is_os_error(e: &io::Error, code: u32) -> bool {
    i32::try_from(code).is_ok_and(|c| e.raw_os_error() == Some(c))
}

fn len_u32(len: usize) -> io::Result<u32> {
    u32::try_from(len).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "buffer too large"))
}

/// Checks that `s` is NUL-terminated and has no interior NUL, so that the
/// API reads exactly `s`.
fn check_wide(s: &[u16]) -> io::Result<()> {
    match s.split_last() {
        Some((0, body)) if !body.contains(&0) => Ok(()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "string is not a single NUL-terminated UTF-16 string",
        )),
    }
}

/// Copies `buf` up to its first NUL. A buffer with no NUL is malformed.
fn until_nul(buf: &[u16]) -> io::Result<Vec<u16>> {
    let n = buf.iter().position(|&u| u == 0).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "API returned an unterminated string",
        )
    })?;
    Ok(buf.iter().take(n).copied().collect())
}

// ---------------------------------------------------------------------------
// DeviceIoControl
// ---------------------------------------------------------------------------

/// Input to a control code.
#[derive(Debug, Clone, Copy)]
pub(crate) enum IoctlInput {
    /// No input buffer.
    None,
    /// `STORAGE_PROPERTY_QUERY` with `PropertyStandardQuery` for this
    /// property (spec §3).
    StandardPropertyQuery(STORAGE_PROPERTY_ID),
}

/// A failed control-code call: the error and the bytes the output buffer
/// held afterwards (some codes report the size needed in a partial
/// result, spec §8 `ERROR_MORE_DATA`).
#[derive(Debug)]
pub(crate) struct IoctlFailure {
    pub(crate) error: io::Error,
    pub(crate) partial: Vec<u8>,
}

impl IoctlFailure {
    fn input(msg: &'static str) -> Self {
        Self {
            error: io::Error::new(io::ErrorKind::InvalidInput, msg),
            partial: Vec::new(),
        }
    }
}

/// Sends `code` to the device behind `file` and returns the output bytes.
///
/// `file` must have been opened by this crate without overlapped I/O (all
/// opens here use `std::fs::OpenOptions` without `FILE_FLAG_OVERLAPPED`),
/// so the call is synchronous.
pub(crate) fn device_io_control(
    file: &File,
    code: u32,
    input: IoctlInput,
    out_len: usize,
) -> Result<Vec<u8>, IoctlFailure> {
    let out_len_u32 =
        u32::try_from(out_len).map_err(|_| IoctlFailure::input("output buffer too large"))?;
    // u64 words give the buffer 8-byte alignment, matching the largest
    // field alignment of the structures the codes return.
    let mut out = vec![0u64; out_len.div_ceil(8)];
    let out_ptr: *mut c_void = if out_len == 0 {
        ptr::null_mut()
    } else {
        out.as_mut_ptr().cast()
    };

    let query;
    let (in_ptr, in_len): (*const c_void, u32) = match input {
        IoctlInput::None => (ptr::null(), 0),
        IoctlInput::StandardPropertyQuery(id) => {
            query = STORAGE_PROPERTY_QUERY {
                PropertyId: id,
                QueryType: PropertyStandardQuery,
                AdditionalParameters: [0],
            };
            let len = u32::try_from(size_of::<STORAGE_PROPERTY_QUERY>())
                .map_err(|_| IoctlFailure::input("query too large"))?;
            (ptr::from_ref(&query).cast(), len)
        }
    };

    let mut returned: u32 = 0;
    // SAFETY: `file` is an open, synchronous handle that outlives the call.
    // `in_ptr` is null with length 0, or points to `query`, a live
    // `STORAGE_PROPERTY_QUERY` of exactly `in_len` bytes. `out_ptr` is null
    // with length 0, or points to `out`, a live allocation of at least
    // `out_len` bytes (`out_len.div_ceil(8)` u64 words) that Windows writes
    // at most `out_len_u32` bytes into. `returned` is a valid `u32` out
    // parameter. No OVERLAPPED is passed, so nothing refers to these
    // buffers after the call returns.
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            code,
            in_ptr,
            in_len,
            out_ptr,
            out_len_u32,
            &mut returned,
            ptr::null_mut(),
        )
    };
    let error = (ok == 0).then(io::Error::last_os_error);

    let mut bytes: Vec<u8> = out.iter().flat_map(|w| w.to_ne_bytes()).collect();
    match error {
        Some(error) => {
            bytes.truncate(out_len);
            Err(IoctlFailure {
                error,
                partial: bytes,
            })
        }
        None => {
            let n = usize::try_from(returned).unwrap_or(0).min(out_len);
            bytes.truncate(n);
            Ok(bytes)
        }
    }
}

// ---------------------------------------------------------------------------
// Volumes and mount points (spec §8)
// ---------------------------------------------------------------------------

/// Closes a volume scan exactly once.
struct VolumeScan(HANDLE);

impl Drop for VolumeScan {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a valid scan handle returned by a successful
        // `FindFirstVolumeW` (the only constructor), and `drop` runs once,
        // so the handle is closed exactly once. The result is ignored:
        // nothing can be done about a failed close in `drop`.
        let _ = unsafe { FindVolumeClose(self.0) };
    }
}

/// Lists volume GUID paths (UTF-16, without NUL), at most `limit`.
pub(crate) fn find_volumes(limit: usize) -> io::Result<Vec<Vec<u16>>> {
    let mut buf = vec![0u16; VOLUME_NAME_UNITS];
    let cap = len_u32(buf.len())?;
    // SAFETY: `buf` is a live, writable buffer of `cap` UTF-16 units; the
    // function writes at most `cap` units including the NUL.
    let h = unsafe { FindFirstVolumeW(buf.as_mut_ptr(), cap) };
    if h == INVALID_HANDLE_VALUE {
        let e = io::Error::last_os_error();
        return if is_os_error(&e, ERROR_NO_MORE_FILES) {
            Ok(Vec::new())
        } else {
            Err(e)
        };
    }
    let scan = VolumeScan(h);
    let mut out = vec![until_nul(&buf)?];
    loop {
        if out.len() >= limit {
            return Err(io::Error::other("more volumes than the limit"));
        }
        buf.fill(0);
        // SAFETY: `scan.0` is the open scan handle; `buf` is a live,
        // writable buffer of `cap` units.
        let ok = unsafe { FindNextVolumeW(scan.0, buf.as_mut_ptr(), cap) };
        if ok == 0 {
            let e = io::Error::last_os_error();
            if is_os_error(&e, ERROR_NO_MORE_FILES) {
                return Ok(out);
            }
            return Err(e);
        }
        out.push(until_nul(&buf)?);
    }
}

/// The double-NUL-terminated list of mount points of `volume` (a
/// NUL-terminated volume GUID path), at most `max_units` long.
pub(crate) fn volume_path_names(volume: &[u16], max_units: usize) -> io::Result<Vec<u16>> {
    check_wide(volume)?;
    let mut cap = 512usize;
    for _ in 0..3 {
        let mut buf = vec![0u16; cap];
        let cap_u32 = len_u32(cap)?;
        let mut needed: u32 = 0;
        // SAFETY: `volume` is NUL-terminated (checked above) and live;
        // `buf` is a live, writable buffer of `cap_u32` units; `needed` is
        // a valid out parameter.
        let ok = unsafe {
            GetVolumePathNamesForVolumeNameW(
                volume.as_ptr(),
                buf.as_mut_ptr(),
                cap_u32,
                &mut needed,
            )
        };
        if ok != 0 {
            // The buffer is zero-initialised, so the list is followed by
            // NULs if it did not fill the buffer; the parser checks it.
            return Ok(buf);
        }
        let e = io::Error::last_os_error();
        let want = usize::try_from(needed).unwrap_or(usize::MAX);
        if is_os_error(&e, ERROR_MORE_DATA) && want > cap && want <= max_units {
            cap = want;
            continue;
        }
        return Err(e);
    }
    Err(io::Error::other("mount-point list kept growing"))
}

/// `SetVolumeMountPointW(mount_point, volume)`; both NUL-terminated.
pub(crate) fn set_volume_mount_point(mount_point: &[u16], volume: &[u16]) -> io::Result<()> {
    check_wide(mount_point)?;
    check_wide(volume)?;
    // SAFETY: both strings are live and NUL-terminated (checked above).
    let ok = unsafe { SetVolumeMountPointW(mount_point.as_ptr(), volume.as_ptr()) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `DeleteVolumeMountPointW(mount_point)`; NUL-terminated.
pub(crate) fn delete_volume_mount_point(mount_point: &[u16]) -> io::Result<()> {
    check_wide(mount_point)?;
    // SAFETY: the string is live and NUL-terminated (checked above).
    let ok = unsafe { DeleteVolumeMountPointW(mount_point.as_ptr()) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The volume GUID path mounted at `mount_point` (UTF-16, without NUL).
pub(crate) fn volume_name_for_mount_point(mount_point: &[u16]) -> io::Result<Vec<u16>> {
    check_wide(mount_point)?;
    let mut buf = vec![0u16; VOLUME_NAME_UNITS];
    let cap = len_u32(buf.len())?;
    // SAFETY: `mount_point` is live and NUL-terminated (checked above);
    // `buf` is a live, writable buffer of `cap` units.
    let ok =
        unsafe { GetVolumeNameForVolumeMountPointW(mount_point.as_ptr(), buf.as_mut_ptr(), cap) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    until_nul(&buf)
}

/// The file-system name of the volume whose root is `root` (UTF-16,
/// without NUL).
pub(crate) fn volume_file_system_name(root: &[u16]) -> io::Result<Vec<u16>> {
    check_wide(root)?;
    let units = usize::try_from(MAX_PATH).unwrap_or(260) + 1;
    let mut fs_name = vec![0u16; units];
    let cap = len_u32(units)?;
    // SAFETY: `root` is live and NUL-terminated (checked above). The
    // volume-name buffer is null with size 0 and the serial, component and
    // flags out parameters are null, all of which the function accepts as
    // "not requested". `fs_name` is a live, writable buffer of `cap` units.
    let ok = unsafe {
        GetVolumeInformationW(
            root.as_ptr(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            fs_name.as_mut_ptr(),
            cap,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    until_nul(&fs_name)
}

/// The label of the volume whose root is `root` (UTF-16, without NUL;
/// empty if the volume has none). Topic 23 §15.
pub(crate) fn volume_label(root: &[u16]) -> io::Result<Vec<u16>> {
    check_wide(root)?;
    let units = usize::try_from(MAX_PATH).unwrap_or(260) + 1;
    let mut label = vec![0u16; units];
    let cap = len_u32(units)?;
    // SAFETY: `root` is live and NUL-terminated (checked above). `label`
    // is a live, writable buffer of `cap` units (MAX_PATH + 1, the most
    // the function writes, §15). The serial, component and flags out
    // parameters are null and the file-system name buffer is null with
    // size 0, all of which the function accepts as "not requested".
    let ok = unsafe {
        GetVolumeInformationW(
            root.as_ptr(),
            label.as_mut_ptr(),
            cap,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    until_nul(&label)
}

// ---------------------------------------------------------------------------
// Privileges (spec §10)
// ---------------------------------------------------------------------------

/// Result of asking to enable a privilege.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrivilegeOutcome {
    /// Enabled or disabled as asked (`ERROR_SUCCESS` after a nonzero
    /// return).
    Adjusted,
    /// The token does not hold it (`ERROR_NOT_ALL_ASSIGNED`, spec §10:
    /// success of the call does not mean the privilege was enabled).
    NotHeld,
}

/// A privilege [`adjust_privilege`] may enable or disable. The name constants come
/// from windows-sys, so no pointer crosses into this module from callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrivilegeName {
    /// `SeSystemEnvironmentPrivilege` (spec §9, §10: firmware variables).
    SystemEnvironment,
    /// `SeRestorePrivilege` (the apply sink: owners, short names, writes
    /// past a just-applied DACL with backup semantics).
    Restore,
    /// `SeSecurityPrivilege` (setting a SACL).
    Security,
    /// `SeBackupPrivilege` (topic 23 §23: backup semantics on open).
    Backup,
    /// `SeCreateSymbolicLinkPrivilege` (topic 24 §6: setting a symbolic
    /// link reparse point).
    CreateSymbolicLink,
}

/// Enables (`enable`) or disables `p` in the process token (spec §10:
/// `AdjustTokenPrivileges` enables or disables a privilege the token
/// already holds; attribute `SE_PRIVILEGE_ENABLED` to enable, no
/// attribute to disable).
///
/// The token is opened as topic 23 §26 ("Getting the token for
/// `AdjustTokenPrivileges`", SR-7) describes: `GetCurrentProcess` gives a
/// pseudo handle that need not be closed, and `OpenProcessToken` asks for
/// `TOKEN_ADJUST_PRIVILEGES` (to adjust) and `TOKEN_QUERY`; the returned
/// token handle must be closed (`OwnedHandle` below). The access-right
/// values come from windows-sys (OPEN-WAPI-1).
pub(crate) fn adjust_privilege(p: PrivilegeName, enable: bool) -> io::Result<PrivilegeOutcome> {
    let name = match p {
        PrivilegeName::SystemEnvironment => SE_SYSTEM_ENVIRONMENT_NAME,
        PrivilegeName::Restore => windows_sys::Win32::Security::SE_RESTORE_NAME,
        PrivilegeName::Security => windows_sys::Win32::Security::SE_SECURITY_NAME,
        PrivilegeName::Backup => windows_sys::Win32::Security::SE_BACKUP_NAME,
        PrivilegeName::CreateSymbolicLink => {
            windows_sys::Win32::Security::SE_CREATE_SYMBOLIC_LINK_NAME
        }
    };
    let mut raw_token: HANDLE = ptr::null_mut();
    // SAFETY: `GetCurrentProcess` takes no argument and returns a pseudo
    // handle for this process that needs no close (topic 23 §26).
    // `raw_token` is a valid, writable out parameter; on success it
    // receives a new token handle, which is taken over just below.
    let ok = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut raw_token,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw_token` is a valid handle just returned by a successful
    // `OpenProcessToken`, owned by nothing else; `OwnedHandle` closes it
    // exactly once when dropped (topic 23 §26: it must be closed).
    let token = unsafe { OwnedHandle::from_raw_handle(raw_token) };

    let mut luid = LUID::default();
    // SAFETY: a null system name means the local system; `name` is one of
    // the static NUL-terminated wide-string constants from windows-sys
    // chosen above; `luid` is a valid out parameter.
    let ok = unsafe { LookupPrivilegeValueW(ptr::null(), name, &mut luid) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }

    let new_state = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: if enable { SE_PRIVILEGE_ENABLED } else { 0 },
        }],
    };
    // SAFETY: `token` is an open token handle with TOKEN_ADJUST_PRIVILEGES
    // access and outlives the call. `new_state` is a live TOKEN_PRIVILEGES
    // whose count (1) matches its one-element array. The previous state is
    // not requested: its buffer is null with length 0 and the return
    // length pointer is null, which the function accepts.
    let ok = unsafe {
        AdjustTokenPrivileges(
            token.as_raw_handle(),
            0,
            &new_state,
            0,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    // Read immediately: on a nonzero return the outcome is in the last
    // error (spec §10).
    let last = io::Error::last_os_error();
    if ok == 0 {
        return Err(last);
    }
    if is_os_error(&last, ERROR_NOT_ALL_ASSIGNED) {
        return Ok(PrivilegeOutcome::NotHeld);
    }
    Ok(PrivilegeOutcome::Adjusted)
}

// ---------------------------------------------------------------------------
// Firmware variables (spec §9)
// ---------------------------------------------------------------------------

/// Reads firmware variable `name` in namespace `guid` (both NUL-terminated
/// wide strings; `guid` in braced form). Returns the value (at most
/// `max_len` bytes) and its attributes.
pub(crate) fn get_firmware_variable(
    name: &[u16],
    guid: &[u16],
    max_len: usize,
) -> io::Result<(Vec<u8>, u32)> {
    check_wide(name)?;
    check_wide(guid)?;
    let mut cap = 256usize.min(max_len.max(1));
    loop {
        let mut buf = vec![0u8; cap];
        let cap_u32 = len_u32(cap)?;
        let mut attributes: u32 = 0;
        // SAFETY: `name` and `guid` are live and NUL-terminated (checked
        // above); `buf` is a live, writable buffer of `cap_u32` bytes;
        // `attributes` is a valid out parameter.
        let n = unsafe {
            GetFirmwareEnvironmentVariableExW(
                name.as_ptr(),
                guid.as_ptr(),
                buf.as_mut_ptr().cast(),
                cap_u32,
                &mut attributes,
            )
        };
        if n == 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(0) {
                // Zero bytes stored and no error: an empty value.
                return Ok((Vec::new(), attributes));
            }
            if is_os_error(&e, ERROR_INSUFFICIENT_BUFFER) && cap < max_len {
                cap = cap.saturating_mul(2).min(max_len);
                continue;
            }
            return Err(e);
        }
        let len = usize::try_from(n).unwrap_or(usize::MAX);
        if len > cap {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "firmware reported more bytes than the buffer holds",
            ));
        }
        buf.truncate(len);
        return Ok((buf, attributes));
    }
}

/// Writes a boot-option variable: `BootOrder` or `Boot####` in the EFI
/// global namespace with NV + BS + RT (`uefi-boot-manager.md` §10.3). This
/// is the only firmware-variable write in the crate. An empty value is
/// refused, because a zero size deletes the variable (spec §9).
pub(crate) fn set_boot_variable(var: WritableBootVar, data: &[u8]) -> io::Result<()> {
    if data.is_empty() || data.len() > MAX_BOOT_VAR_WRITE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "boot variable value is empty or too large",
        ));
    }
    let bad = || io::Error::new(io::ErrorKind::InvalidInput, "variable name");
    let name = to_wide_nul(&var.name()).ok_or_else(bad)?;
    let guid = to_wide_nul(&EFI_GLOBAL_VARIABLE.to_braced_upper()).ok_or_else(bad)?;
    let len = len_u32(data.len())?;
    // SAFETY: `name` and `guid` are live NUL-terminated wide strings built
    // just above; `data` is a live buffer of exactly `len` bytes that the
    // function only reads.
    let ok = unsafe {
        SetFirmwareEnvironmentVariableExW(
            name.as_ptr(),
            guid.as_ptr(),
            data.as_ptr().cast(),
            len,
            BOOT_VAR_ATTRIBUTES,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Shared helpers for the sections below
// ---------------------------------------------------------------------------

use windows_sys::Win32::Foundation::{
    ERROR_BUFFER_OVERFLOW, ERROR_HANDLE_EOF, ERROR_NO_MORE_ITEMS, HLOCAL, LocalFree,
};

/// Closes a `Find*` search handle (`FindFirstStreamW`, `FindFirstFileNameW`)
/// exactly once.
struct FindHandle(HANDLE);

impl Drop for FindHandle {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a valid search handle returned by a successful
        // `FindFirstStreamW` or `FindFirstFileNameW` (the only constructors),
        // and `drop` runs once. A failed close cannot be acted on here.
        let _ = unsafe { windows_sys::Win32::Storage::FileSystem::FindClose(self.0) };
    }
}

/// An owned, zeroed, 8-byte-aligned byte buffer for structures Windows
/// writes. Returned bytes are copied out with [`AlignedBuf::to_bytes`].
struct AlignedBuf {
    words: Vec<u64>,
    len: usize,
}

impl AlignedBuf {
    fn new(len: usize) -> Self {
        Self {
            words: vec![0u64; len.div_ceil(8).max(1)],
            len,
        }
    }

    fn as_mut_ptr(&mut self) -> *mut c_void {
        self.words.as_mut_ptr().cast()
    }

    fn as_ptr(&self) -> *const u8 {
        self.words.as_ptr().cast()
    }

    /// A buffer holding a copy of `src`.
    fn from_bytes(src: &[u8]) -> Self {
        let mut buf = Self::new(src.len());
        for (w, c) in buf.words.iter_mut().zip(src.chunks(8)) {
            let mut b = [0u8; 8];
            for (d, v) in b.iter_mut().zip(c) {
                *d = *v;
            }
            *w = u64::from_ne_bytes(b);
        }
        buf
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut b: Vec<u8> = self.words.iter().flat_map(|w| w.to_ne_bytes()).collect();
        b.truncate(self.len);
        b
    }

    /// A pointer to a `T` at address `addr`, if `addr` lies inside this
    /// buffer with room for a whole, aligned `T`. The pointer carries the
    /// buffer's provenance, so it is valid to read when this returns
    /// `Some`.
    fn element<T>(&self, addr: usize) -> Option<*const T> {
        let base = self.as_ptr();
        let start = base.addr();
        let end = start.checked_add(self.len)?;
        let last = addr.checked_add(size_of::<T>())?;
        (addr >= start && last <= end && addr.is_multiple_of(align_of::<T>()))
            .then(|| base.with_addr(addr).cast::<T>())
    }
}

/// Copies UTF-16 units from `bytes` starting at `offset`, up to the first
/// NUL.
fn utf16_from_bytes(bytes: &[u8], offset: usize) -> io::Result<Vec<u16>> {
    let units: Vec<u16> = bytes
        .get(offset..)
        .unwrap_or(&[])
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&p| u16::from_ne_bytes(p))
        .collect();
    until_nul(&units)
}

// ---------------------------------------------------------------------------
// Disk interfaces through SetupAPI (spec §2)
// ---------------------------------------------------------------------------

use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    DIGCF_DEVICEINTERFACE, DIGCF_PRESENT, HDEVINFO, SP_DEVICE_INTERFACE_DATA,
    SP_DEVICE_INTERFACE_DETAIL_DATA_W, SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInterfaces,
    SetupDiGetClassDevsW, SetupDiGetDeviceInterfaceDetailW,
};
use windows_sys::Win32::System::Ioctl::GUID_DEVINTERFACE_DISK;

/// Largest interface-detail structure accepted (bytes).
const MAX_INTERFACE_DETAIL: u32 = 64 * 1024;

/// Releases a device information set exactly once (spec §2: the set must
/// be released with `SetupDiDestroyDeviceInfoList`).
struct DevInfoSet(HDEVINFO);

impl Drop for DevInfoSet {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a valid set returned by a successful
        // `SetupDiGetClassDevsW` (the only constructor), and `drop` runs
        // once.
        let _ = unsafe { SetupDiDestroyDeviceInfoList(self.0) };
    }
}

/// The device paths of every present disk interface
/// (`GUID_DEVINTERFACE_DISK`, spec §2), as UTF-16 without NUL, at most
/// `limit`. The paths are opaque: they are only passed to `CreateFile`.
pub(crate) fn disk_interface_paths(limit: usize) -> io::Result<Vec<Vec<u16>>> {
    // SAFETY: `GUID_DEVINTERFACE_DISK` is a static GUID from windows-sys;
    // a null enumerator and a null parent window are accepted.
    let set = unsafe {
        SetupDiGetClassDevsW(
            &GUID_DEVINTERFACE_DISK,
            ptr::null(),
            ptr::null_mut(),
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
        )
    };
    // INVALID_HANDLE_VALUE (-1) is the documented failure value; HDEVINFO
    // is an integer type in windows-sys.
    if set == INVALID_HANDLE_VALUE as HDEVINFO {
        return Err(io::Error::last_os_error());
    }
    let set = DevInfoSet(set);
    let data_size = len_u32(size_of::<SP_DEVICE_INTERFACE_DATA>())?;
    let detail_fixed = len_u32(size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>())?;
    let path_offset = core::mem::offset_of!(SP_DEVICE_INTERFACE_DETAIL_DATA_W, DevicePath);

    let mut out = Vec::new();
    for index in 0u32.. {
        let mut data = SP_DEVICE_INTERFACE_DATA {
            cbSize: data_size,
            ..Default::default()
        };
        // SAFETY: `set.0` is the open set; a null device-info filter is
        // accepted; the GUID is static; `data` is a live structure whose
        // `cbSize` is set as the function requires.
        let ok = unsafe {
            SetupDiEnumDeviceInterfaces(
                set.0,
                ptr::null(),
                &GUID_DEVINTERFACE_DISK,
                index,
                &mut data,
            )
        };
        if ok == 0 {
            let e = io::Error::last_os_error();
            if is_os_error(&e, ERROR_NO_MORE_ITEMS) {
                return Ok(out);
            }
            return Err(e);
        }
        if out.len() >= limit {
            return Err(io::Error::other("more disk interfaces than the limit"));
        }

        // Step 1: ask for the size (spec §2: fails with
        // ERROR_INSUFFICIENT_BUFFER and reports the size).
        let mut required: u32 = 0;
        // SAFETY: as above for `set.0` and `data`; no output buffer (null,
        // size 0) and no device-info output (null); `required` is a valid
        // out parameter.
        let ok = unsafe {
            SetupDiGetDeviceInterfaceDetailW(
                set.0,
                &data,
                ptr::null_mut(),
                0,
                &mut required,
                ptr::null_mut(),
            )
        };
        let e = io::Error::last_os_error();
        if ok != 0 || !is_os_error(&e, ERROR_INSUFFICIENT_BUFFER) {
            return Err(if ok != 0 {
                io::Error::other("interface detail size query did not fail as documented")
            } else {
                e
            });
        }
        if required < detail_fixed || required > MAX_INTERFACE_DETAIL {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "interface detail size out of range",
            ));
        }

        // Step 2: fetch it, with cbSize set to the fixed part only.
        let len = usize::try_from(required)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "size"))?;
        let mut buf = AlignedBuf::new(len);
        let detail = buf.as_mut_ptr().cast::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>();
        // SAFETY: `detail` points to the start of `buf`, a live, writable,
        // 8-byte-aligned allocation of at least `required` bytes, which is at
        // least the size of the fixed part (checked above), so the `cbSize`
        // field lies inside it.
        unsafe { (*detail).cbSize = detail_fixed };
        // SAFETY: `detail` points to `buf` of exactly `required` bytes, the
        // size passed; other arguments as in step 1.
        let ok = unsafe {
            SetupDiGetDeviceInterfaceDetailW(
                set.0,
                &data,
                detail,
                required,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        out.push(utf16_from_bytes(&buf.to_bytes(), path_offset)?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// File queries for the tree manifest (read-only)
// ---------------------------------------------------------------------------

use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, GetFileSecurityW,
    OWNER_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_TAG_INFO, FileAttributeTagInfo, FindFirstFileNameW, FindFirstStreamW,
    FindNextFileNameW, FindNextStreamW, FindStreamInfoStandard, GetFileInformationByHandleEx,
    WIN32_FIND_STREAM_DATA,
};

/// Largest security descriptor read (bytes).
const MAX_SECURITY_DESCRIPTOR: u32 = 64 * 1024;
/// Longest SDDL string accepted (UTF-16 units).
const MAX_SDDL_UNITS: u32 = 64 * 1024;
/// Longest hard-link name accepted (UTF-16 units, the long-path maximum).
const MAX_LINK_NAME_UNITS: u32 = 32_768;

/// One named or unnamed stream as `FindFirstStreamW` lists it: the raw
/// name (for example `:name:$DATA`) and the size.
pub(crate) struct RawStream {
    pub(crate) name: Vec<u16>,
    pub(crate) size: i64,
}

/// Lists the data streams of the file at `path` (NUL-terminated), at most
/// `limit`. A file with no streams gives an empty list.
pub(crate) fn file_streams(path: &[u16], limit: usize) -> io::Result<Vec<RawStream>> {
    check_wide(path)?;
    let mut data = WIN32_FIND_STREAM_DATA::default();
    // SAFETY: `path` is live and NUL-terminated (checked above); `data` is
    // a live WIN32_FIND_STREAM_DATA, the structure the standard info level
    // writes; flags must be 0.
    let h = unsafe {
        FindFirstStreamW(
            path.as_ptr(),
            FindStreamInfoStandard,
            ptr::from_mut(&mut data).cast(),
            0,
        )
    };
    if h == INVALID_HANDLE_VALUE {
        let e = io::Error::last_os_error();
        return if is_os_error(&e, ERROR_HANDLE_EOF) {
            Ok(Vec::new())
        } else {
            Err(e)
        };
    }
    let find = FindHandle(h);
    let mut out = Vec::new();
    loop {
        out.push(RawStream {
            name: until_nul(&data.cStreamName)?,
            size: data.StreamSize,
        });
        if out.len() > limit {
            return Err(io::Error::other("more streams than the limit"));
        }
        // SAFETY: `find.0` is the open search handle; `data` is a live
        // WIN32_FIND_STREAM_DATA.
        let ok = unsafe { FindNextStreamW(find.0, ptr::from_mut(&mut data).cast()) };
        if ok == 0 {
            let e = io::Error::last_os_error();
            if is_os_error(&e, ERROR_HANDLE_EOF) {
                return Ok(out);
            }
            return Err(e);
        }
    }
}

/// Lists the names (hard links) of the file at `path`, at most `limit`,
/// as UTF-16 without NUL.
pub(crate) fn file_link_names(path: &[u16], limit: usize) -> io::Result<Vec<Vec<u16>>> {
    check_wide(path)?;
    let mut cap: u32 = 1024;
    let (find, first) = loop {
        let mut buf = vec![0u16; usize::try_from(cap).unwrap_or(1024)];
        let mut len = cap;
        // SAFETY: `path` is live and NUL-terminated; flags must be 0; `len`
        // holds the size of `buf` in units, and `buf` is a live, writable
        // buffer of that many units.
        let h = unsafe { FindFirstFileNameW(path.as_ptr(), 0, &mut len, buf.as_mut_ptr()) };
        if h != INVALID_HANDLE_VALUE {
            break (FindHandle(h), until_nul(&buf)?);
        }
        let e = io::Error::last_os_error();
        if is_os_error(&e, ERROR_MORE_DATA) && len > cap && len <= MAX_LINK_NAME_UNITS {
            cap = len;
            continue;
        }
        return Err(e);
    };
    let mut out = vec![first];
    loop {
        if out.len() > limit {
            return Err(io::Error::other("more link names than the limit"));
        }
        let mut buf = vec![0u16; usize::try_from(cap).unwrap_or(1024)];
        let mut len = cap;
        // SAFETY: `find.0` is the open search handle; `buf` is a live,
        // writable buffer of `len` units.
        let ok = unsafe { FindNextFileNameW(find.0, &mut len, buf.as_mut_ptr()) };
        if ok != 0 {
            out.push(until_nul(&buf)?);
            continue;
        }
        let e = io::Error::last_os_error();
        if is_os_error(&e, ERROR_HANDLE_EOF) {
            return Ok(out);
        }
        if is_os_error(&e, ERROR_MORE_DATA) && len > cap && len <= MAX_LINK_NAME_UNITS {
            // The name did not fit: the search did not advance, so retry
            // the same call with a larger buffer.
            cap = len;
            continue;
        }
        return Err(e);
    }
}

/// Attributes and reparse tag of the open file (`FILE_ATTRIBUTE_TAG_INFO`).
pub(crate) fn attribute_tag(file: &File) -> io::Result<(u32, u32)> {
    let mut info = FILE_ATTRIBUTE_TAG_INFO::default();
    let size = len_u32(size_of::<FILE_ATTRIBUTE_TAG_INFO>())?;
    // SAFETY: `file` is an open handle that outlives the call; `info` is a
    // live FILE_ATTRIBUTE_TAG_INFO of exactly `size` bytes, the structure
    // this information class writes.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileAttributeTagInfo,
            ptr::from_mut(&mut info).cast(),
            size,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((info.FileAttributes, info.ReparseTag))
}

/// Frees a `LocalAlloc` block exactly once.
struct LocalBox(HLOCAL);

impl Drop for LocalBox {
    fn drop(&mut self) {
        // SAFETY: `self.0` was returned by a successful
        // `ConvertSecurityDescriptorToStringSecurityDescriptorW` (the only
        // constructor), which documents `LocalFree` as its release, and
        // `drop` runs once.
        let _ = unsafe { LocalFree(self.0) };
    }
}

/// The owner, group and DACL of the file at `path`, as the self-relative
/// security descriptor `GetFileSecurityW` returns (spec §19).
pub(crate) fn file_security(path: &[u16]) -> io::Result<Vec<u8>> {
    check_wide(path)?;
    let info = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut needed: u32 = 0;
    // SAFETY: `path` is live and NUL-terminated; no buffer (null, 0) is
    // passed to learn the size; `needed` is a valid out parameter.
    let ok = unsafe { GetFileSecurityW(path.as_ptr(), info, ptr::null_mut(), 0, &mut needed) };
    let e = io::Error::last_os_error();
    if ok != 0 || !is_os_error(&e, ERROR_INSUFFICIENT_BUFFER) {
        return Err(if ok != 0 {
            io::Error::other("security size query did not fail as expected")
        } else {
            e
        });
    }
    if needed == 0 || needed > MAX_SECURITY_DESCRIPTOR {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "security descriptor size out of range",
        ));
    }
    let mut sd = AlignedBuf::new(usize::try_from(needed).unwrap_or(0));
    let mut again: u32 = 0;
    // SAFETY: `sd` is a live, writable, aligned buffer of `needed` bytes,
    // the length passed; `again` is a valid out parameter.
    let ok = unsafe { GetFileSecurityW(path.as_ptr(), info, sd.as_mut_ptr(), needed, &mut again) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(sd.to_bytes())
}

/// The owner, group and DACL of the file at `path` as an SDDL string
/// (UTF-16 without NUL).
pub(crate) fn file_sddl(path: &[u16]) -> io::Result<Vec<u16>> {
    let info = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut sd = AlignedBuf::from_bytes(&file_security(path)?);
    let mut text: *mut u16 = ptr::null_mut();
    let mut units: u32 = 0;
    // SAFETY: `sd` holds a copy of the self-relative descriptor
    // `GetFileSecurityW` just returned and stays live; `text` and `units` are valid out
    // parameters; on success `text` receives a block this function owns and
    // frees with `LocalFree` (through `LocalBox`).
    let ok = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd.as_mut_ptr(),
            SDDL_REVISION_1,
            info,
            &mut text,
            &mut units,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let owned = LocalBox(text.cast());
    if text.is_null() || units > MAX_SDDL_UNITS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SDDL string missing or too long",
        ));
    }
    let n = usize::try_from(units).unwrap_or(0);
    // SAFETY: `text` is non-null and points to the string block of `units`
    // UTF-16 units the call returned; it is live until `owned` is dropped,
    // which happens after the copy below.
    let s = unsafe { core::slice::from_raw_parts(text, n) };
    let end = s.iter().position(|&u| u == 0).unwrap_or(s.len());
    let copy = s.iter().take(end).copied().collect();
    drop(owned);
    Ok(copy)
}

// ---------------------------------------------------------------------------
// System information
// ---------------------------------------------------------------------------

use windows_sys::Win32::System::SystemInformation::{
    GetNativeSystemInfo, GetSystemDirectoryW, GlobalMemoryStatusEx, MEMORYSTATUSEX, SYSTEM_INFO,
};

/// Longest path accepted from the path functions (UTF-16 units).
const MAX_PATH_UNITS: u32 = 32_768;

/// The native processor architecture (`wProcessorArchitecture`).
pub(crate) fn native_processor_architecture() -> u16 {
    let mut si = SYSTEM_INFO::default();
    // SAFETY: `si` is a live SYSTEM_INFO the function fills; it cannot fail.
    unsafe { GetNativeSystemInfo(&mut si) };
    // SAFETY: the union's two members overlay the same 32 bits; reading the
    // struct member is reading initialised plain integers (the structure
    // was zeroed and then written by the call).
    unsafe { si.Anonymous.Anonymous.wProcessorArchitecture }
}

/// Total physical memory in bytes (`ullTotalPhys`).
pub(crate) fn total_physical_memory() -> io::Result<u64> {
    let mut ms = MEMORYSTATUSEX {
        dwLength: len_u32(size_of::<MEMORYSTATUSEX>())?,
        ..Default::default()
    };
    // SAFETY: `ms` is a live MEMORYSTATUSEX with `dwLength` set to its size.
    let ok = unsafe { GlobalMemoryStatusEx(&mut ms) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ms.ullTotalPhys)
}

/// The system directory (UTF-16 without NUL).
pub(crate) fn system_directory() -> io::Result<Vec<u16>> {
    let mut cap: u32 = 512;
    for _ in 0..3 {
        let mut buf = vec![0u16; usize::try_from(cap).unwrap_or(512)];
        // SAFETY: `buf` is a live, writable buffer of `cap` units.
        let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), cap) };
        if n == 0 {
            return Err(io::Error::last_os_error());
        }
        if n < cap {
            return until_nul(&buf);
        }
        // `n` is the size needed, including the NUL.
        if n > MAX_PATH_UNITS {
            break;
        }
        cap = n;
    }
    Err(io::Error::other("system directory path too long"))
}

// ---------------------------------------------------------------------------
// Network adapters (GetAdaptersAddresses); the only linked-list walk
// ---------------------------------------------------------------------------

use windows_sys::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses,
    IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_DHCP_ENABLED, IP_ADAPTER_UNICAST_ADDRESS_LH,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR, SOCKADDR_IN};

/// Largest adapter buffer accepted (bytes).
const MAX_ADAPTER_BUFFER: u32 = 1024 * 1024;

/// One adapter's facts, copied out of the list.
pub(crate) struct RawAdapter {
    pub(crate) mac: Vec<u8>,
    pub(crate) if_type: u32,
    pub(crate) oper_up: bool,
    pub(crate) dhcp_enabled: bool,
    pub(crate) ipv4: Vec<[u8; 4]>,
}

/// Lists IPv4 adapters: at most `max_adapters`, each with at most
/// `max_addresses` unicast addresses. Every pointer in the returned list
/// is checked to lie inside the buffer before it is followed.
pub(crate) fn ipv4_adapters(
    max_adapters: usize,
    max_addresses: usize,
) -> io::Result<Vec<RawAdapter>> {
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size: u32 = 16 * 1024;
    let mut buf = AlignedBuf::new(usize::try_from(size).unwrap_or(0));
    let mut tries = 0;
    loop {
        let mut want = size;
        // SAFETY: `buf` is a live, writable, 8-byte-aligned buffer of `size`
        // bytes, the size passed in `want`; the reserved argument is null as
        // required.
        let rc = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_INET),
                flags,
                ptr::null(),
                buf.as_mut_ptr().cast(),
                &mut want,
            )
        };
        if rc == 0 {
            break;
        }
        tries += 1;
        if rc == ERROR_BUFFER_OVERFLOW && want > size && want <= MAX_ADAPTER_BUFFER && tries < 4 {
            size = want;
            buf = AlignedBuf::new(usize::try_from(size).unwrap_or(0));
            continue;
        }
        return Err(io::Error::from_raw_os_error(
            i32::try_from(rc).unwrap_or(i32::MAX),
        ));
    }

    let bad = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "adapter list pointer outside buffer",
        )
    };
    let mut out = Vec::new();
    let mut next = buf.as_ptr().addr();
    while next != 0 {
        if out.len() >= max_adapters {
            return Err(io::Error::other("more adapters than the limit"));
        }
        let p = buf
            .element::<IP_ADAPTER_ADDRESSES_LH>(next)
            .ok_or_else(bad)?;
        // SAFETY: `p` lies inside `buf`, is aligned and has room for a whole
        // IP_ADAPTER_ADDRESSES_LH (checked by `element`); the bytes were
        // written by the call above, and every field read is a plain
        // integer, array or pointer value (pointers are only used after the
        // same check).
        let a = unsafe { p.read() };
        let mac_len = usize::try_from(a.PhysicalAddressLength)
            .unwrap_or(usize::MAX)
            .min(a.PhysicalAddress.len());
        let mac = a.PhysicalAddress.iter().take(mac_len).copied().collect();
        // SAFETY: both union members overlay the same 32-bit integer;
        // `Flags` is the plain-integer view.
        let adapter_flags = unsafe { a.Anonymous2.Flags };

        let mut ipv4 = Vec::new();
        let mut u = a.FirstUnicastAddress.addr();
        while u != 0 {
            if ipv4.len() >= max_addresses {
                return Err(io::Error::other("more addresses than the limit"));
            }
            let up = buf
                .element::<IP_ADAPTER_UNICAST_ADDRESS_LH>(u)
                .ok_or_else(bad)?;
            // SAFETY: `up` lies inside `buf`, aligned, whole (checked by
            // `element`); fields are plain values.
            let ua = unsafe { up.read() };
            let sa_addr = ua.Address.lpSockaddr.addr();
            let sa_len = usize::try_from(ua.Address.iSockaddrLength).unwrap_or(0);
            if let Some(sp) = buf.element::<SOCKADDR>(sa_addr) {
                // SAFETY: `sp` lies inside `buf`, aligned, whole.
                let family = unsafe { sp.read() }.sa_family;
                if family == AF_INET && sa_len >= size_of::<SOCKADDR_IN>() {
                    let ip = buf.element::<SOCKADDR_IN>(sa_addr).ok_or_else(bad)?;
                    // SAFETY: `ip` lies inside `buf`, aligned, whole; the
                    // address union's members all overlay the same 32 bits,
                    // and `S_addr` is the plain-integer view in network
                    // byte order.
                    let raw = unsafe { ip.read().sin_addr.S_un.S_addr };
                    ipv4.push(raw.to_ne_bytes());
                }
            } else if sa_addr != 0 {
                return Err(bad());
            }
            u = ua.Next.addr();
        }

        out.push(RawAdapter {
            mac,
            if_type: a.IfType,
            oper_up: a.OperStatus == IfOperStatusUp,
            dhcp_enabled: adapter_flags & IP_ADAPTER_DHCP_ENABLED != 0,
            ipv4,
        });
        next = a.Next.addr();
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Console input mode
// ---------------------------------------------------------------------------

use windows_sys::Win32::System::Console::{
    GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, SetConsoleMode,
};

fn stdin_handle() -> io::Result<HANDLE> {
    // SAFETY: `GetStdHandle` takes a constant selector and returns the
    // process's standard handle (not owned by the caller; never closed
    // here).
    let h = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    if h == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    if h.is_null() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "no standard input"));
    }
    Ok(h)
}

/// The console mode of standard input. Fails if standard input is not a
/// console.
pub(crate) fn stdin_console_mode() -> io::Result<u32> {
    let h = stdin_handle()?;
    let mut mode: u32 = 0;
    // SAFETY: `h` is the process's standard input handle; `mode` is a valid
    // out parameter.
    let ok = unsafe { GetConsoleMode(h, &mut mode) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(mode)
}

/// Sets the console mode of standard input.
pub(crate) fn set_stdin_console_mode(mode: u32) -> io::Result<()> {
    let h = stdin_handle()?;
    // SAFETY: `h` is the process's standard input handle; `mode` is a plain
    // value.
    let ok = unsafe { SetConsoleMode(h, mode) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Volume classification (spec §13)
// ---------------------------------------------------------------------------

use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;

/// `GetDriveTypeW(root)`; `root` is NUL-terminated and ends in a
/// backslash (spec §13).
pub(crate) fn drive_type(root: &[u16]) -> io::Result<u32> {
    check_wide(root)?;
    // SAFETY: `root` is live and NUL-terminated (checked above).
    Ok(unsafe { GetDriveTypeW(root.as_ptr()) })
}

// ---------------------------------------------------------------------------
// Apply-sink writes (WinSink)
// ---------------------------------------------------------------------------

use windows_sys::Win32::Security::{GetSecurityDescriptorLength, IsValidSecurityDescriptor};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_BASIC_INFO, FileBasicInfo, SetFileInformationByHandle, SetFileShortNameW,
};

/// Checks the stored self-relative descriptor `sd` and reports which
/// parts it holds, as `OBJECT_SECURITY_INFORMATION` flags (owner, group,
/// DACL, SACL; no protection flags).
///
/// Before any pointer to `sd` is passed, the bytes are checked by
/// `crate::parse::check_security_descriptor` (topic 24 §7 to §9, layouts
/// from windows-sys). What that check establishes, and no more: the fixed
/// header is present, revision 1 and self-relative; the owner and group
/// SIDs (revision, sub-authority count and length) lie inside the buffer;
/// each ACL's header and its `AclSize` lie inside the buffer; and each
/// ACE's header and its `AceSize` extent lie inside its ACL. It does not
/// look inside an ACE body (its access mask, or the SID an ACE carries).
/// A null DACL is refused (topic 23 §20: fail securely). Then
/// `IsValidSecurityDescriptor` must accept it, and only after that is its
/// length read and required to fit (§20: the length is undefined for an
/// invalid descriptor).
pub(crate) fn descriptor_info(sd: &[u8]) -> io::Result<u32> {
    checked_descriptor(sd).map(|(_, parts)| parts_info(&parts))
}

fn parts_info(parts: &crate::parse::DescriptorParts) -> u32 {
    let mut info = 0;
    if parts.owner {
        info |= OWNER_SECURITY_INFORMATION;
    }
    if parts.group {
        info |= GROUP_SECURITY_INFORMATION;
    }
    if parts.dacl {
        info |= DACL_SECURITY_INFORMATION;
    }
    if parts.sacl {
        info |= windows_sys::Win32::Security::SACL_SECURITY_INFORMATION;
    }
    info
}

/// The checks of [`descriptor_info`]; returns the aligned copy and parts.
fn checked_descriptor(sd: &[u8]) -> io::Result<(AlignedBuf, crate::parse::DescriptorParts)> {
    let parts = crate::parse::check_security_descriptor(sd, &crate::layout::SECURITY_DESCRIPTOR)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if parts.null_dacl {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "null DACL (would allow all access)",
        ));
    }
    let len = len_u32(sd.len())?;
    let mut buf = AlignedBuf::from_bytes(sd);
    let p = buf.as_mut_ptr();
    // SAFETY: `p` points to `buf`, a live, 8-byte-aligned copy of `sd`,
    // valid for reads of `len` bytes. The check above bounds the header,
    // the owner and group SIDs, each ACL's extent (`AclSize`) and each ACE
    // header and extent (`AceSize`, inside its ACL). Topic 23 §20: this
    // function checks the parts that are present and does not check the
    // contents of individual ACLs or ACEs, so the parts it reads are ones
    // the check bounded.
    if unsafe { IsValidSecurityDescriptor(p) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "security descriptor is not valid",
        ));
    }
    // SAFETY: `p` as above (live, aligned, `len` bytes, every offset and
    // size field bounded by the check); the descriptor was just found
    // valid, so the length is defined (topic 23 §20) and is compared with
    // `len` below.
    let reported = unsafe { GetSecurityDescriptorLength(p) };
    if reported == 0 || reported > len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "security descriptor length exceeds the stored bytes",
        ));
    }
    Ok((buf, parts))
}

/// Sets the parts `info` of the stored descriptor `sd` on the open file
/// with `SetSecurityInfo` (topic 23 §20; `SetKernelObjectSecurity` is not
/// for file-system objects). `sd` is checked again exactly as
/// [`descriptor_info`] does before any pointer is passed. The stored
/// "protected" bits are passed on as the protected or unprotected flags
/// for the DACL and SACL (OPEN-WAPI-7: whether the result keeps them is
/// checked on the Windows runner). The handle must carry the access each
/// part needs (§20).
pub(crate) fn set_file_security(file: &File, sd: &[u8], info: u32) -> io::Result<()> {
    use windows_sys::Win32::Security::Authorization::{SE_FILE_OBJECT, SetSecurityInfo};
    use windows_sys::Win32::Security::{
        ACL, GetSecurityDescriptorDacl, GetSecurityDescriptorGroup, GetSecurityDescriptorOwner,
        GetSecurityDescriptorSacl, PROTECTED_DACL_SECURITY_INFORMATION,
        PROTECTED_SACL_SECURITY_INFORMATION, PSID, SACL_SECURITY_INFORMATION, SE_DACL_PROTECTED,
        SE_SACL_PROTECTED, UNPROTECTED_DACL_SECURITY_INFORMATION,
        UNPROTECTED_SACL_SECURITY_INFORMATION,
    };

    let (mut buf, parts) = checked_descriptor(sd)?;
    if info & !parts_info(&parts) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "requested parts not in the descriptor",
        ));
    }
    if info == 0 {
        return Ok(());
    }
    let p = buf.as_mut_ptr();
    let mut owner: PSID = ptr::null_mut();
    let mut group: PSID = ptr::null_mut();
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut sacl: *mut ACL = ptr::null_mut();
    let mut present: windows_sys::core::BOOL = 0;
    let mut defaulted: windows_sys::core::BOOL = 0;
    // SAFETY: `p` is the descriptor in `buf`, checked and found valid by
    // `checked_descriptor`; every other argument is a valid out parameter.
    // The returned pointers point into `buf` (topic 23 §20), which stays
    // live until after `SetSecurityInfo` returns.
    let ok = unsafe {
        GetSecurityDescriptorOwner(p, &mut owner, &mut defaulted) != 0
            && GetSecurityDescriptorGroup(p, &mut group, &mut defaulted) != 0
            && GetSecurityDescriptorDacl(p, &mut present, &mut dacl, &mut defaulted) != 0
            && GetSecurityDescriptorSacl(p, &mut present, &mut sacl, &mut defaulted) != 0
    };
    if !ok {
        return Err(io::Error::last_os_error());
    }
    if info & DACL_SECURITY_INFORMATION != 0 && dacl.is_null() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "null DACL"));
    }
    let mut flags = info;
    if info & DACL_SECURITY_INFORMATION != 0 {
        flags |= if parts.control & SE_DACL_PROTECTED != 0 {
            PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_DACL_SECURITY_INFORMATION
        };
    }
    if info & SACL_SECURITY_INFORMATION != 0 {
        flags |= if parts.control & SE_SACL_PROTECTED != 0 {
            PROTECTED_SACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_SACL_SECURITY_INFORMATION
        };
    }
    let pick = |want: u32, v: PSID| if info & want != 0 { v } else { ptr::null_mut() };
    // SAFETY: `file` is an open handle that outlives the call; the SID and
    // ACL pointers are null or point into `buf`, which stays live and is
    // only read; parts not named in `flags` are passed as null. Each SID
    // and each ACL's `AclSize` extent lies inside `buf` (checked above),
    // as does each ACE's `AceSize` extent. ACE bodies (an ACE's mask and
    // SID) are not parsed by this crate (their layouts are not in topic
    // 24, §12); their validity is left to Windows' own check of the ACL
    // it is given.
    // POAM: SEC-004 residual - ACE bodies are not bounded by this crate
    // before SetSecurityInfo; needs the ACE body layouts summarised (spec
    // request) and a per-type check in parse.rs.
    let rc = unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            flags,
            pick(OWNER_SECURITY_INFORMATION, owner),
            pick(GROUP_SECURITY_INFORMATION, group),
            if info & DACL_SECURITY_INFORMATION != 0 {
                dacl
            } else {
                ptr::null_mut()
            },
            if info & SACL_SECURITY_INFORMATION != 0 {
                sacl
            } else {
                ptr::null_mut()
            },
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(
            i32::try_from(rc).unwrap_or(i32::MAX),
        ));
    }
    Ok(())
}

/// Sets a reparse point on the open file or directory with
/// `FSCTL_SET_REPARSE_POINT`, from a buffer built by
/// `usgp-image` and checked by `crate::parse::check_reparse_buffer`
/// (topic 24 §2 to §6). The buffer is passed unchanged.
pub(crate) fn set_reparse_point(file: &File, buffer: &[u8]) -> io::Result<()> {
    let len = len_u32(buffer.len())?;
    let mut buf = AlignedBuf::from_bytes(buffer);
    let mut returned: u32 = 0;
    // SAFETY: `file` is an open, synchronous handle (opened by this crate
    // without overlapped I/O) that outlives the call; `buf` is a live,
    // 8-byte-aligned copy of `buffer` of exactly `len` bytes, read only;
    // there is no output buffer (null, 0); `returned` is a valid out
    // parameter; no OVERLAPPED is passed.
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            windows_sys::Win32::System::Ioctl::FSCTL_SET_REPARSE_POINT,
            buf.as_mut_ptr(),
            len,
            ptr::null_mut(),
            0,
            &mut returned,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Sets the short name of the open file (`name` NUL-terminated).
pub(crate) fn set_short_name(file: &File, name: &[u16]) -> io::Result<()> {
    check_wide(name)?;
    // SAFETY: `file` is an open handle that outlives the call; `name` is
    // live and NUL-terminated (checked above).
    let ok = unsafe { SetFileShortNameW(file.as_raw_handle(), name.as_ptr()) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Replaces the attributes of the open file, keeping its times: the basic
/// information is read, its attribute field changed by `f`, and the same
/// structure written back.
pub(crate) fn update_attributes(file: &File, f: impl FnOnce(u32) -> u32) -> io::Result<()> {
    let mut info = FILE_BASIC_INFO::default();
    let size = len_u32(size_of::<FILE_BASIC_INFO>())?;
    // SAFETY: `file` is an open handle; `info` is a live FILE_BASIC_INFO of
    // exactly `size` bytes, the structure this class reads and writes.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileBasicInfo,
            ptr::from_mut(&mut info).cast(),
            size,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    info.FileAttributes = f(info.FileAttributes);
    // SAFETY: as above; `info` is read by the call only.
    let ok = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileBasicInfo,
            ptr::from_ref(&info).cast(),
            size,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_sys_links_and_agrees_with_std() {
        // SAFETY: `GetCurrentProcessId` takes no arguments, has no
        // preconditions, cannot fail, and only returns the caller's
        // process id.
        let id = unsafe { windows_sys::Win32::System::Threading::GetCurrentProcessId() };
        assert_eq!(id, std::process::id());
    }

    #[test]
    fn wide_inputs_must_be_single_terminated_strings() {
        assert!(check_wide(&[67, 58, 92, 0]).is_ok());
        assert!(check_wide(&[]).is_err());
        assert!(check_wide(&[67]).is_err());
        assert!(check_wide(&[67, 0, 68, 0]).is_err());
        assert!(set_volume_mount_point(&[67], &[0]).is_err());
        assert!(get_firmware_variable(&[66], &[0], 16).is_err());
    }

    #[test]
    fn empty_or_oversized_boot_writes_are_refused_before_the_call() {
        let e = set_boot_variable(WritableBootVar::BootOrder, &[]);
        assert!(e.is_err_and(|e| e.kind() == io::ErrorKind::InvalidInput));
        let big = vec![0u8; MAX_BOOT_VAR_WRITE + 1];
        let e = set_boot_variable(WritableBootVar::Boot(1), &big);
        assert!(e.is_err_and(|e| e.kind() == io::ErrorKind::InvalidInput));
    }
}
