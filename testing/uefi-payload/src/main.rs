//! usgp-test-payload: test-only UEFI x86-64 application (plan WU-9).
//!
//! Prints the build's marker line through the console's Simple Text Output
//! protocol (which the firmware also mirrors to the serial console), waits
//! one second, then asks the firmware to shut the machine down. If shutdown
//! returns, control goes back to the boot manager.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Testing and Evaluation)
//! - SPEC: specs/boot-network.md#REQ-BOOT-003 (UEFI x86-64 boot program)
//! - SPEC: specs/boot-network.md#REQ-BOOT-043 (no secrets in boot content)
//! - UEFI 2.10 §4.3 (EFI System Table), §7.5 (Stall), §8.5.1 (ResetSystem),
//!   §12.4 (OutputString)
//!
//! `unsafe` is required here: the firmware hands us raw pointers and every
//! UEFI service is an `extern "efiapi"` function pointer. Each block below
//! carries its own SAFETY argument.

#![no_std]
#![no_main]

use core::ptr;

use r_efi::efi;
use usgp_test_payload::{MARKER_LINE, STALL_MICROSECONDS};

/// No unwinding on UEFI (`panic = "abort"`). Nothing in this payload is
/// expected to panic; if it does, it halts without printing the marker, and
/// the harness deadline reports the boot as failed.
#[panic_handler]
fn panic_handler(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// UEFI image entry point (UEFI 2.10 §4.1, EFI_IMAGE_ENTRY_POINT).
///
/// # Safety
///
/// Only the firmware calls this, with `system_table` null or pointing to a
/// valid EFI System Table whose boot services are still active.
#[unsafe(export_name = "efi_main")]
pub unsafe extern "efiapi" fn efi_main(
    _image: efi::Handle,
    system_table: *mut efi::SystemTable,
) -> efi::Status {
    // SAFETY: the firmware passes either null or a pointer to a valid EFI
    // System Table that stays valid while boot services are active (UEFI
    // 2.10 §4.1). `as_ref` handles the null case.
    let Some(st) = (unsafe { system_table.as_ref() }) else {
        return efi::Status::INVALID_PARAMETER;
    };

    // The compile-time assertion in the library guarantees `Some`.
    let Some(mut line) = MARKER_LINE else {
        return efi::Status::LOAD_ERROR;
    };

    if st.con_out.is_null() {
        return efi::Status::UNSUPPORTED;
    }
    // SAFETY: `con_out` is non-null and points to the firmware's Simple Text
    // Output protocol instance for the console (UEFI 2.10 §4.3). `line` is a
    // live, NUL-terminated UCS-2 buffer on our stack; OutputString only
    // reads it (UEFI 2.10 §12.4).
    let status = unsafe { ((*st.con_out).output_string)(st.con_out, line.as_mut_ptr()) };
    if status.is_error() {
        return status;
    }

    // SAFETY: `boot_services` is either null (checked by `as_ref`) or the
    // firmware's Boot Services table, valid until ExitBootServices, which
    // this payload never calls (UEFI 2.10 §4.4).
    if let Some(bs) = unsafe { st.boot_services.as_ref() } {
        // SAFETY: Stall takes a microsecond count and no pointers (UEFI 2.10
        // §7.5). Its status is ignored: a short or failed wait only risks a
        // truncated serial line, which the harness reports as a failure.
        let _ = unsafe { (bs.stall)(STALL_MICROSECONDS) };
    }

    // SAFETY: `runtime_services` is either null (checked by `as_ref`) or the
    // firmware's Runtime Services table (UEFI 2.10 §4.5).
    if let Some(rt) = unsafe { st.runtime_services.as_ref() } {
        // SAFETY: ResetSystem with EfiResetShutdown, a success status, and no
        // reset data (size 0, null pointer) is a valid call (UEFI 2.10
        // §8.5.1). It does not return when it succeeds.
        unsafe {
            (rt.reset_system)(
                efi::RESET_SHUTDOWN,
                efi::Status::SUCCESS,
                0,
                ptr::null_mut(),
            );
        }
    }

    // Shutdown was unavailable or returned: hand control back to the boot
    // manager (UEFI 2.10 §3.1.2).
    efi::Status::SUCCESS
}
