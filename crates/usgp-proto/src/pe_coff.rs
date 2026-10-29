//! PE/COFF header check for a boot program: is it a UEFI x64 application?
//! (`specs/standards/winpe.md` §10, SR-2; M3 plan WU-13.)
//!
//! Only the fields needed for the answer are read: the stub's pointer at
//! `0x3C`, the `PE\0\0` signature it points to, the COFF `Machine` and
//! `SizeOfOptionalHeader`, and the optional header's `Magic` and
//! `Subsystem`. All little-endian (UEFI §1.9.1). The input is untrusted
//! file bytes (a fuzz entry point): every offset is checked, nothing in
//! the file can make this read out of bounds or overflow, and nothing is
//! allocated.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - header read with
//   checked offsets only, never trusting a length or offset from the file.
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity) -
//   the boot program published in a kit must match the target
//   architecture.
// - SPEC: specs/preinstall-env.md#REQ-PE-012 (matching architecture)
// - SPEC: specs/standards/winpe.md §10 (PE/COFF Machine field, SR-2)

/// `IMAGE_FILE_MACHINE_AMD64` (`winpe.md` §10).
pub const MACHINE_X64: u16 = 0x8664;

/// Optional header `Magic` of a PE32+ image (`winpe.md` §10).
pub const MAGIC_PE32_PLUS: u16 = 0x20B;

/// `IMAGE_SUBSYSTEM_EFI_APPLICATION` (`winpe.md` §10).
pub const SUBSYSTEM_EFI_APPLICATION: u16 = 10;

/// File offset of the stub's pointer to the PE signature.
pub const PE_POINTER_OFFSET: usize = 0x3C;
/// Size of the COFF file header.
pub const COFF_HEADER_LEN: usize = 20;
/// Offset of `SizeOfOptionalHeader` in the COFF file header.
pub const COFF_SIZE_OF_OPTIONAL_HEADER: usize = 16;
/// Offset of `Subsystem` in the optional header (PE32 and PE32+).
pub const OPTIONAL_SUBSYSTEM: usize = 68;

/// Why a boot program is not a UEFI x64 application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PeCoffError {
    /// The file ends before a header field it must hold.
    #[error("is too short to hold a PE/COFF header")]
    Truncated,
    /// No `PE\0\0` signature at the offset the stub names.
    #[error("has no PE signature at the offset its MS-DOS stub names")]
    NoSignature,
    /// `Machine` is not x64.
    #[error("is built for machine type 0x{0:04x}, not x64 (0x8664)")]
    WrongMachine(u16),
    /// Optional header `Magic` is not PE32+.
    #[error("optional header magic is 0x{0:04x}, not PE32+ (0x020b)")]
    NotPe32Plus(u16),
    /// `Subsystem` is not a UEFI application.
    #[error("subsystem is {0}, not a UEFI application (10)")]
    NotUefiApplication(u16),
}

fn u16_at(b: &[u8], off: usize) -> Result<u16, PeCoffError> {
    let end = off.checked_add(2).ok_or(PeCoffError::Truncated)?;
    let s = b.get(off..end).ok_or(PeCoffError::Truncated)?;
    let mut a = [0u8; 2];
    a.copy_from_slice(s);
    Ok(u16::from_le_bytes(a))
}

fn u32_at(b: &[u8], off: usize) -> Result<u32, PeCoffError> {
    let end = off.checked_add(4).ok_or(PeCoffError::Truncated)?;
    let s = b.get(off..end).ok_or(PeCoffError::Truncated)?;
    let mut a = [0u8; 4];
    a.copy_from_slice(s);
    Ok(u32::from_le_bytes(a))
}

/// Checks that `bytes` is a UEFI x64 application: the stub's pointer at
/// `0x3C` leads to `PE\0\0`; the COFF `Machine` is `0x8664`; the optional
/// header is PE32+, long enough to hold `Subsystem`, and `Subsystem` is
/// 10. The MS-DOS `MZ` magic is not checked (the spec does not state it).
///
/// # Errors
///
/// [`PeCoffError`] for the first rule that fails, in that order.
pub fn check_uefi_x64_application(bytes: &[u8]) -> Result<(), PeCoffError> {
    let sig =
        usize::try_from(u32_at(bytes, PE_POINTER_OFFSET)?).map_err(|_| PeCoffError::Truncated)?;
    let sig_end = sig.checked_add(4).ok_or(PeCoffError::Truncated)?;
    match bytes.get(sig..sig_end) {
        Some(b"PE\0\0") => {}
        Some(_) => return Err(PeCoffError::NoSignature),
        None => return Err(PeCoffError::Truncated),
    }
    let coff = sig_end;
    let machine = u16_at(bytes, coff)?;
    if machine != MACHINE_X64 {
        return Err(PeCoffError::WrongMachine(machine));
    }
    let opt_len = usize::from(u16_at(
        bytes,
        coff.checked_add(COFF_SIZE_OF_OPTIONAL_HEADER)
            .ok_or(PeCoffError::Truncated)?,
    )?);
    let opt = coff
        .checked_add(COFF_HEADER_LEN)
        .ok_or(PeCoffError::Truncated)?;
    let magic = u16_at(bytes, opt)?;
    if magic != MAGIC_PE32_PLUS {
        return Err(PeCoffError::NotPe32Plus(magic));
    }
    // The subsystem field must lie inside the declared optional header.
    if opt_len < OPTIONAL_SUBSYSTEM.saturating_add(2) {
        return Err(PeCoffError::Truncated);
    }
    let subsystem = u16_at(
        bytes,
        opt.checked_add(OPTIONAL_SUBSYSTEM)
            .ok_or(PeCoffError::Truncated)?,
    )?;
    if subsystem != SUBSYSTEM_EFI_APPLICATION {
        return Err(PeCoffError::NotUefiApplication(subsystem));
    }
    Ok(())
}

/// Test helpers shared with dependent crates' tests (`testkit`-free: plain
/// byte building, no I/O).
pub mod sample {
    use super::{COFF_HEADER_LEN, OPTIONAL_SUBSYSTEM, PE_POINTER_OFFSET};

    /// Where [`header`] puts the `PE\0\0` signature.
    pub const SIGNATURE_OFFSET: usize = 0x80;

    /// A minimal image header: stub pointer, signature, COFF header and an
    /// optional header of 0xF0 bytes. Not a runnable program; only the
    /// fields [`super::check_uefi_x64_application`] reads are set.
    #[must_use]
    pub fn header(machine: u16, magic: u16, subsystem: u16) -> Vec<u8> {
        let sig = SIGNATURE_OFFSET;
        let coff = sig + 4;
        let opt = coff + COFF_HEADER_LEN;
        let mut b = vec![0u8; opt + 0xF0];
        let mut put = |off: usize, bytes: &[u8]| {
            if let Some(dst) = b.get_mut(off..off + bytes.len()) {
                dst.copy_from_slice(bytes);
            }
        };
        put(0, b"MZ");
        put(PE_POINTER_OFFSET, &0x80u32.to_le_bytes());
        put(sig, b"PE\0\0");
        put(coff, &machine.to_le_bytes());
        put(coff + 16, &0xF0u16.to_le_bytes());
        put(opt, &magic.to_le_bytes());
        put(opt + OPTIONAL_SUBSYSTEM, &subsystem.to_le_bytes());
        b
    }

    /// A header [`super::check_uefi_x64_application`] accepts.
    #[must_use]
    pub fn uefi_x64() -> Vec<u8> {
        header(
            super::MACHINE_X64,
            super::MAGIC_PE32_PLUS,
            super::SUBSYSTEM_EFI_APPLICATION,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::sample::{SIGNATURE_OFFSET, header, uefi_x64};
    use super::*;

    #[test]
    fn x64_uefi_application_accepted() {
        assert_eq!(check_uefi_x64_application(&uefi_x64()), Ok(()));
    }

    #[test]
    fn wrong_machine_magic_subsystem_refused() {
        for (m, want) in [
            (0x014C, PeCoffError::WrongMachine(0x014C)),
            (0xAA64, PeCoffError::WrongMachine(0xAA64)),
            (0x0000, PeCoffError::WrongMachine(0)),
            // Big-endian x64 bytes (86 64) read as 0x6486.
            (0x6486, PeCoffError::WrongMachine(0x6486)),
        ] {
            assert_eq!(
                check_uefi_x64_application(&header(m, MAGIC_PE32_PLUS, 10)),
                Err(want)
            );
        }
        assert_eq!(
            check_uefi_x64_application(&header(MACHINE_X64, 0x10B, 10)),
            Err(PeCoffError::NotPe32Plus(0x10B))
        );
        assert_eq!(
            check_uefi_x64_application(&header(MACHINE_X64, MAGIC_PE32_PLUS, 11)),
            Err(PeCoffError::NotUefiApplication(11))
        );
    }

    #[test]
    fn malformed_headers_never_panic() {
        assert_eq!(check_uefi_x64_application(b""), Err(PeCoffError::Truncated));
        assert_eq!(
            check_uefi_x64_application(&[0u8; 0x3F]),
            Err(PeCoffError::Truncated)
        );
        // Pointer far past the end, and the largest pointers.
        for ptr in [0x1000u32, u32::MAX, u32::MAX - 3] {
            let mut b = uefi_x64();
            b.get_mut(0x3C..0x40)
                .unwrap()
                .copy_from_slice(&ptr.to_le_bytes());
            assert_eq!(check_uefi_x64_application(&b), Err(PeCoffError::Truncated));
        }
        let sig = SIGNATURE_OFFSET;
        let mut b = uefi_x64();
        b.get_mut(sig..sig + 4)
            .unwrap()
            .copy_from_slice(b"PE\0\x01");
        assert_eq!(
            check_uefi_x64_application(&b),
            Err(PeCoffError::NoSignature)
        );
        // Optional header declared too short for Subsystem.
        let mut b = uefi_x64();
        b.get_mut(sig + 4 + 16..sig + 4 + 18)
            .unwrap()
            .copy_from_slice(&69u16.to_le_bytes());
        assert_eq!(check_uefi_x64_application(&b), Err(PeCoffError::Truncated));
        // Every prefix that ends before the last field read (Subsystem)
        // is refused without a panic; the first long enough one passes.
        let good = uefi_x64();
        let last = sig + 4 + COFF_HEADER_LEN + OPTIONAL_SUBSYSTEM + 2;
        for n in 0..last {
            assert!(
                check_uefi_x64_application(good.get(..n).unwrap()).is_err(),
                "{n}"
            );
        }
        assert_eq!(
            check_uefi_x64_application(good.get(..last).unwrap()),
            Ok(())
        );
    }
}
