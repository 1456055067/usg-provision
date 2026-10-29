//! Fuzz target `pe_coff`: arbitrary bytes as a boot program's file head
//! for `usgp_proto::pe_coff::check_uefi_x64_application`.
//!
//! The whole input is the file head.
//!
//! Invariants (`specs/standards/winpe.md` §10; impl-notes-integration
//! item 7):
//!
//! - no panic;
//! - the answer equals a reference model written from the field list in
//!   the module documentation, with its own bounds arithmetic in `u64`:
//!   the u32 at `0x3C` names `PE\0\0`; the COFF header follows it, with
//!   `Machine` at +0 and `SizeOfOptionalHeader` at +16; the optional
//!   header follows the 20-byte COFF header, with `Magic` at +0 and
//!   `Subsystem` at +68, and must be long enough to hold `Subsystem`;
//!   checked in that order, each with its own refusal;
//! - the answer depends only on those bytes: changing a byte outside
//!   them (here: the first byte, the stub's `MZ`, when the signature is
//!   not at 0) does not change it. Like the module, the model does not
//!   check `MZ`: the module documentation lists only the fields above.

#![no_main]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), SI-7, SA-11
// - SPEC: specs/preinstall-env.md#REQ-PE-012
// - SPEC: specs/standards/winpe.md §10 (PE/COFF Machine field, SR-2)

use libfuzzer_sys::fuzz_target;
use usgp_proto::pe_coff::{
    MACHINE_X64, MAGIC_PE32_PLUS, PeCoffError, SUBSYSTEM_EFI_APPLICATION,
    check_uefi_x64_application,
};

fn le(b: &[u8], at: u64, n: u64) -> Option<u64> {
    let end = at.checked_add(n)?;
    if end > u64::try_from(b.len()).ok()? {
        return None;
    }
    let mut v = 0u64;
    for k in (0..n).rev() {
        let i = usize::try_from(at + k).ok()?;
        v = (v << 8) | u64::from(*b.get(i)?);
    }
    Some(v)
}

fn u16v(v: u64) -> u16 {
    u16::try_from(v).unwrap_or(u16::MAX)
}

fn model(b: &[u8]) -> Result<(), PeCoffError> {
    use PeCoffError::{NoSignature, NotPe32Plus, NotUefiApplication, Truncated, WrongMachine};
    let sig = le(b, 0x3C, 4).ok_or(Truncated)?;
    if le(b, sig, 4).is_none() {
        return Err(Truncated);
    }
    if le(b, sig, 4) != Some(u64::from(u32::from_le_bytes(*b"PE\0\0"))) {
        return Err(NoSignature);
    }
    let coff = sig + 4;
    let machine = le(b, coff, 2).ok_or(Truncated)?;
    if machine != u64::from(MACHINE_X64) {
        return Err(WrongMachine(u16v(machine)));
    }
    let opt_len = le(b, coff + 16, 2).ok_or(Truncated)?;
    let opt = coff + 20;
    let magic = le(b, opt, 2).ok_or(Truncated)?;
    if magic != u64::from(MAGIC_PE32_PLUS) {
        return Err(NotPe32Plus(u16v(magic)));
    }
    if opt_len < 70 {
        return Err(Truncated);
    }
    let subsystem = le(b, opt + 68, 2).ok_or(Truncated)?;
    if subsystem != u64::from(SUBSYSTEM_EFI_APPLICATION) {
        return Err(NotUefiApplication(u16v(subsystem)));
    }
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    let got = check_uefi_x64_application(data);
    assert_eq!(got, model(data), "check differs from the reference model");
    if got.is_err() {
        assert!(
            !got.err()
                .map(|e| e.to_string())
                .unwrap_or_default()
                .is_empty()
        );
    }
    // Byte 0 (the stub's `MZ`) is read only if the signature pointer
    // names offset 0.
    if le(data, 0x3C, 4).is_some_and(|sig| sig >= 1) {
        let mut other = data.to_vec();
        other[0] ^= 0xFF;
        assert_eq!(
            check_uefi_x64_application(&other),
            got,
            "answer depends on a byte outside the header fields"
        );
    }
});
