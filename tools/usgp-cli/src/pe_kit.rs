//! The relay boot manifest's optional `[pe_kit]` section, as the CLI
//! writes and checks it (M3 plan WU-13).
//!
//! The section's type, parser and checks are shared with the relay, which
//! reads it: [`usgp_proto::pe_kit`] (the format is documented there), as
//! the `pe_kit` field of [`usgp_proto::BootManifest`]. The boot program's
//! PE/COFF header check is [`usgp_proto::pe_coff`]. Both are library code
//! so they can be fuzzed. This module adds only the memory requirement the
//! CLI prints (REQ-PE-018).
//!
//! The boot configuration (BCD) is an opaque operator file. Nothing here
//! generates or edits one; it is hashed and listed like any other
//! published file (decision 0018 item 3, REQ-PE-012).

// COMPLIANCE MAPPING:
// - SPEC: specs/preinstall-env.md#REQ-PE-018 (memory requirement)
// - SPEC: specs/standards/winpe.md §6, §9 (512 MB base plus the WIM)

pub use usgp_proto::pe_coff::{PeCoffError, check_uefi_x64_application as check_boot_program};
pub use usgp_proto::pe_kit::{PeKitError, PeKitV1 as PeKit};

/// Base memory Windows PE needs before its image is loaded: 512 MiB
/// (`winpe.md` §6 "512 MB"; plan section 3.5 reads it as MiB, the larger
/// value).
pub const PE_BASE_MEMORY_BYTES: u64 = 512 * 1024 * 1024;

/// Memory a device needs to start the PE: the base plus the WIM, which is
/// held in memory (REQ-PE-018). Saturates rather than wrapping.
#[must_use]
pub const fn memory_required(wim_size: u64) -> u64 {
    PE_BASE_MEMORY_BYTES.saturating_add(wim_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_requirement() {
        assert_eq!(memory_required(0), 536_870_912);
        assert_eq!(memory_required(300_000_000), 836_870_912);
        assert_eq!(memory_required(u64::MAX), u64::MAX);
    }
}
