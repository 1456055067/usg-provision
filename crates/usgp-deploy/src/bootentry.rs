//! The installed Windows boot option, first in `BootOrder`
//! (REQ-BOOT-065; DEC-0018 item 9; `uefi-boot-manager.md` §9 and §10).
//!
//! [`make_windows_first`]:
//!
//! 1. reads and parses `BootOrder` (absent = empty); an unparseable value
//!    stops the step rather than being overwritten;
//! 2. reuses an option already in `BootOrder` that points at our ESP's
//!    Windows Boot Manager ([`LoadOption::points_to`]); options that do
//!    not parse are left untouched;
//! 3. otherwise picks the lowest option number that is neither in
//!    `BootOrder` nor present as a variable (probing `Boot0000` upwards, at
//!    most [`MAX_OPTION_PROBES`] reads) and writes our option there;
//! 4. reads the option back and compares the bytes;
//! 5. writes `BootOrder` with that number first and the rest in their
//!    order ([`put_first`]), and reads it back.
//!
//! Only `BootOrder` and `Boot####` can be named ([`BootVarName`]); nothing
//! here can touch a Secure Boot variable, and `BootNext` (one-shot) is not
//! used.

// COMPLIANCE MAPPING:
// - NIST 800-53: CM-7 (Least Functionality) - only boot-order variables.
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity) -
//   Secure Boot never weakened; written values read back.
// - NIST 800-53: SI-10 (Information Input Validation) - firmware values
//   parsed with bounds (usgp-disk uefi.rs).
// - SPEC: specs/boot-network.md#REQ-BOOT-065, #REQ-BOOT-066
// - SPEC: specs/standards/uefi-boot-manager.md §2, §9.2, §10.2, §10.3
// - DECISION: docs/decisions/0018 items 5 and 9

use usgp_disk::UefiError;
use usgp_disk::layout::Part;
use usgp_disk::uefi::{
    BootVarName, LoadOption, UefiLimits, encode_boot_order, parse_boot_order, parse_load_option,
    put_first,
};

use crate::platform::{FirmwareVars, FwError};

/// Design bound: the most `Boot####` reads made to find a free number.
pub const MAX_OPTION_PROBES: u16 = 4096;

/// What [`make_windows_first`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootEntry {
    /// The option number now first in `BootOrder`.
    pub option: u16,
    /// `true` if an existing option was reused rather than written.
    pub reused: bool,
    /// `BootOrder` as written and read back.
    pub order: Vec<u16>,
}

/// Why the boot entry could not be made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BootEntryError {
    /// The firmware refused or failed.
    #[error("firmware variable access failed: {0}")]
    Firmware(#[from] FwError),
    /// `BootOrder` is not a valid value; it is not overwritten.
    #[error("BootOrder is malformed: {0}")]
    BadBootOrder(#[source] UefiError),
    /// Our option could not be encoded.
    #[error("boot option could not be encoded: {0}")]
    Encode(#[source] UefiError),
    /// No free option number within the probe bound.
    #[error("no free boot option number")]
    NoFreeNumber,
    /// A value read back differs from what was written.
    #[error("read-back differs: {0}")]
    ReadBack(&'static str),
}

/// Makes the Windows Boot Manager on `esp` the first firmware boot option.
///
/// # Errors
///
/// [`BootEntryError`].
pub fn make_windows_first(
    fw: &mut dyn FirmwareVars,
    esp: &Part,
    limits: &UefiLimits,
) -> Result<BootEntry, BootEntryError> {
    let order_name = BootVarName::boot_order();
    let order = match fw.get(&order_name)? {
        Some(b) => parse_boot_order(&b, limits).map_err(BootEntryError::BadBootOrder)?,
        None => Vec::new(),
    };

    // 2. An option in BootOrder that already points at our ESP.
    let mut reuse = None;
    for &n in &order {
        let Some(bytes) = fw.get(&BootVarName::boot_option(n))? else {
            continue;
        };
        // Options that do not parse are someone else's; leave them.
        if parse_load_option(&bytes, limits).is_ok_and(|o| o.points_to(esp)) {
            reuse = Some(n);
            break;
        }
    }

    let (option, reused) = match reuse {
        Some(n) => (n, true),
        None => {
            let n = free_number(fw, &order)?;
            let ours = LoadOption::windows_boot_manager(esp)
                .encode()
                .map_err(BootEntryError::Encode)?;
            let name = BootVarName::boot_option(n);
            fw.set(&name, &ours)?;
            // 4. Read back.
            if fw.get(&name)?.as_deref() != Some(ours.as_slice()) {
                return Err(BootEntryError::ReadBack("boot option"));
            }
            (n, false)
        }
    };

    // 5. Windows first, the rest kept in order.
    let new_order = put_first(&order, option);
    let bytes = encode_boot_order(&new_order);
    fw.set(&order_name, &bytes)?;
    let back = fw
        .get(&order_name)?
        .ok_or(BootEntryError::ReadBack("BootOrder missing"))?;
    if back != bytes {
        return Err(BootEntryError::ReadBack("BootOrder"));
    }
    Ok(BootEntry {
        option,
        reused,
        order: new_order,
    })
}

/// The lowest number not in `order` and with no `Boot####` variable.
fn free_number(fw: &mut dyn FirmwareVars, order: &[u16]) -> Result<u16, BootEntryError> {
    for n in 0..MAX_OPTION_PROBES {
        if order.contains(&n) {
            continue;
        }
        if fw.get(&BootVarName::boot_option(n))?.is_none() {
            return Ok(n);
        }
    }
    Err(BootEntryError::NoFreeNumber)
}
