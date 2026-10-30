//! A page of locked memory for one short secret held as UTF-16 (the
//! administrator password, plan section 1.2).
//!
//! `VirtualLock` keeps the pages of a range in physical memory so they are
//! never written to the pagefile (topic 23 §31). It acts on whole pages, so
//! locking a small buffer would also lock, and unlocking would unlock,
//! whatever shares its pages (§31 [reading]). [`LockedWide`] therefore owns
//! a whole page-aligned allocation of its own, locks exactly that, wipes it
//! before unlocking, and unlocks it on drop.
//!
//! Locking prevents pagefile writes only; it says nothing about
//! hibernation or crash dumps (§31 [reading]).
//!
//! If the lock fails, the working-set minimum is raised once as §31
//! describes (`SetProcessWorkingSetSize`) and the lock is retried. If that
//! also fails, [`WinApiError::MemoryNotLocked`] is returned and the caller
//! must not place the secret anywhere else (fail closed, OPEN-WAPI-24).

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-28 (Protection of Information at Rest) - secret never
//   paged to disk; SC-4 (Information in Shared System Resources) and
//   MP-6 - wiped before release; SI-16 (Memory Protection)
// - SPEC: specs/standards/windows-storage-firmware-api.md §31
//   (OPEN-WAPI-24)

use core::fmt;

use zeroize::Zeroize;

use crate::error::{Result, WinApiError};
use crate::ffi;

/// Bytes in the locked allocation. A page-sized, page-aligned block when
/// the system page size divides it (checked at run time).
const BLOCK_BYTES: usize = 4096;

/// UTF-16 units in the block.
const UNITS: usize = BLOCK_BYTES / 2;

/// §31: the default minimum working set is 50 pages and the default
/// maximum 345 pages. When a lock fails, the minimum is raised to this
/// many pages and the maximum set to the default maximum.
const RAISED_MIN_PAGES: usize = 50 + 16;
const DEFAULT_MAX_PAGES: usize = 345;

#[repr(C, align(4096))]
struct Block([u16; UNITS]);

const _: () = assert!(size_of::<Block>() == BLOCK_BYTES && align_of::<Block>() == BLOCK_BYTES);

/// One locked, page-aligned block holding a NUL-terminated UTF-16 string.
///
/// The contents are wiped and the block unlocked when it is dropped or
/// [`LockedWide::close`]d. `Debug` never shows the contents.
pub struct LockedWide {
    block: Box<Block>,
    /// Units in use, NUL included (at least 1).
    len: usize,
    locked: bool,
}

impl fmt::Debug for LockedWide {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LockedWide { .. }")
    }
}

impl LockedWide {
    /// Allocates and locks an empty block.
    pub fn new() -> Result<Self> {
        let page = usize::try_from(ffi::page_size()).unwrap_or(0);
        // The block is the only thing in its pages only if the page size
        // divides the block size.
        if page == 0 || page > BLOCK_BYTES || !BLOCK_BYTES.is_multiple_of(page) {
            return Err(WinApiError::Refused {
                reason: "page size does not divide the locked block",
            });
        }
        let mut s = Self {
            block: Box::new(Block([0; UNITS])),
            len: 1,
            locked: false,
        };
        lock_with_raise(&s.block.0, page)?;
        s.locked = true;
        Ok(s)
    }

    /// Largest string accepted (UTF-16 units, NUL excluded).
    #[must_use]
    pub const fn capacity() -> usize {
        UNITS - 1
    }

    /// Replaces the contents with `s` as UTF-16 plus NUL, encoded directly
    /// into the block. Refused if `s` holds a NUL or is too long; the
    /// block is then left empty. Wiping `s` itself is the caller's job.
    pub fn set(&mut self, s: &str) -> Result<()> {
        self.wipe();
        let mut n = 0usize;
        for u in s.encode_utf16() {
            match self.block.0.get_mut(n) {
                Some(slot) if u != 0 && n < Self::capacity() => *slot = u,
                _ => {
                    self.wipe();
                    return Err(WinApiError::Refused {
                        reason: "secret too long or holds a NUL",
                    });
                }
            }
            n += 1;
        }
        self.len = n + 1;
        Ok(())
    }

    /// The string with its NUL terminator.
    #[must_use]
    pub fn as_wide_nul(&self) -> &[u16] {
        self.block.0.get(..self.len).unwrap_or(&[0])
    }

    /// Wipes the block and unlocks it. An `ERROR_NOT_LOCKED` from the
    /// unlock means the lock had silently failed or been undone (§31
    /// [reading]) and is returned as [`WinApiError::LockLost`].
    pub fn close(mut self) -> Result<()> {
        self.wipe();
        self.locked = false;
        ffi::virtual_unlock(&self.block.0).map_err(|e| {
            let not_locked = windows_sys::Win32::Foundation::ERROR_NOT_LOCKED;
            if i32::try_from(not_locked).is_ok_and(|c| e.raw_os_error() == Some(c)) {
                WinApiError::LockLost
            } else {
                WinApiError::os("unlock memory", e)
            }
        })
    }

    fn wipe(&mut self) {
        self.block.0.zeroize();
        self.len = 1;
    }
}

impl Drop for LockedWide {
    fn drop(&mut self) {
        self.wipe();
        if self.locked {
            // Nothing can be reported from drop; `close` reports.
            let _ = ffi::virtual_unlock(&self.block.0);
        }
    }
}

/// Locks `region`; on failure raises the working set once (§31) and
/// retries. Fails closed with [`WinApiError::MemoryNotLocked`].
fn lock_with_raise(region: &[u16], page: usize) -> Result<()> {
    if ffi::virtual_lock(region).is_ok() {
        return Ok(());
    }
    // §31: the lockable pages are bounded by the minimum working set; to
    // lock more, raise it first. Minimum above zero and not above the
    // maximum.
    let fail = |e: std::io::Error| WinApiError::MemoryNotLocked {
        os_code: e.raw_os_error(),
    };
    let min = RAISED_MIN_PAGES.checked_mul(page);
    let max = DEFAULT_MAX_PAGES.max(RAISED_MIN_PAGES).checked_mul(page);
    let (Some(min), Some(max)) = (min, max) else {
        return Err(WinApiError::MemoryNotLocked { os_code: None });
    };
    // POAM: the current working-set sizes are not read first (no read
    // call is summarised in topic 23 §31), so a process whose working set
    // was already set above these values would have it lowered; the agent
    // sets it nowhere else.
    ffi::set_working_set(min, max).map_err(fail)?;
    ffi::virtual_lock(region).map_err(fail)
}
