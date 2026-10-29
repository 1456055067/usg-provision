//! OS-neutral pieces of the Windows backend, kept apart so they are tested
//! on every host: drive letter choice, the BCDBoot and `wpeutil` commands
//! and the partition kind from a GPT type. Bounded child processes, the
//! DiskPart script and volume matching moved to `usgp_winapi::diskpart`
//! (fix round 2, BOOT-004) so the Windows VHD tests run the same code.
//!
//! Compiled on Windows (used by `platform_win`) and in tests.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 - tool arguments built only from fixed words and
//   letters we chose, never from disk or network text.
// - SPEC: specs/disk.md#REQ-DISK-008
// - SPEC: specs/boot-network.md#REQ-BOOT-066 (BCDBoot from the applied
//   image, naming the ESP; uefi-boot-manager.md §9.1, §9.4)
// - SPEC: specs/standards/winpe.md §5.2 (wpeutil Reboot, Shutdown), §11
//   (letters)

use std::path::{Path, PathBuf};

use usgp_disk::Guid;
use usgp_disk::guid::types;
use usgp_proto::disk::PartitionKind;

use crate::host::PowerAction;

/// Letters tried for new volumes, most preferred first. `A`, `B`, `C`
/// and `X` (the Windows PE system letter) are never used.
///
/// [project rule] (plan section 1.2(c); CR-002): the order is this
/// project's choice. Microsoft's UEFI/GPT deployment sample happens to use
/// the same temporary letters, W for Windows, S for the system partition
/// and R for recovery (`specs/standards/winpe.md` §11, SRC-087), and says
/// they are temporary; that is not a Microsoft requirement.
const LETTER_ORDER: &str = "WSRTUVQPONMLKJIHGFED";

/// The first free letter, given the letters in use.
#[must_use]
pub fn pick_letter(used: &[char]) -> Option<char> {
    LETTER_ORDER
        .chars()
        .find(|c| !used.iter().any(|u| u.eq_ignore_ascii_case(c)))
}

/// The BCDBoot command for the applied Windows on `windows` with the ESP
/// at `esp` (`uefi-boot-manager.md` §9.1: BCDBoot from the applied image,
/// against the applied Windows directory, naming the system partition
/// with `/s`; plan section 1.2(c)). Returns the program and its arguments.
///
/// SPEC: `uefi-boot-manager.md` §9.4 (SR-7):
///
/// - form `bcdboot <source> /s <volume letter>`: `<source>` first, as
///   `<drive>:\Windows` of the applied image; `/s` with the system
///   partition's letter written with a colon (`S:`);
/// - which bcdboot.exe: the copy in the applied image,
///   `\Windows\System32\bcdboot.exe` on the Windows partition, as
///   Microsoft's apply flow and UEFI sample do;
/// - no `/f`: allowed only with `/s`, and when omitted the default is
///   `UEFI` on a UEFI system, which WinPE booted in UEFI mode is (the
///   agent refuses BIOS mode first, REQ-PE-020);
/// - no `/l`: the default locale.
///
/// §9.4 also says that with `/s` BCDBoot creates no firmware (NVRAM)
/// entry; the engine writes the boot option itself (step 4,
/// REQ-BOOT-066; OPEN-UBM-1).
#[must_use]
pub fn bcdboot_command(windows: char, esp: char) -> (PathBuf, Vec<String>) {
    let program = Path::new(&format!("{windows}:\\"))
        .join("Windows")
        .join("System32")
        .join("bcdboot.exe");
    (
        program,
        vec![
            format!("{windows}:\\Windows"),
            "/s".to_owned(),
            format!("{esp}:"),
        ],
    )
}

/// The `wpeutil` command for `action`: `Reboot` or `Shutdown`, one per
/// invocation, no argument, spelt as documented
/// (`specs/standards/winpe.md` §5.2, SR-7; CR-SR7-001). Whether `wpeutil`
/// command names are case-insensitive is not stated, so the documented
/// capitalisation is used.
#[must_use]
pub fn wpeutil_command(action: PowerAction) -> &'static str {
    match action {
        PowerAction::Restart => "Reboot",
        PowerAction::Shutdown => "Shutdown",
    }
}

/// The partition kind of a GPT type (`gpt.md` §9).
#[must_use]
pub fn gpt_kind(t: &Guid) -> PartitionKind {
    if *t == types::ESP {
        PartitionKind::Esp
    } else if *t == types::MSR {
        PartitionKind::Msr
    } else if *t == types::BASIC_DATA {
        PartitionKind::Basic
    } else if *t == types::RECOVERY {
        PartitionKind::Recovery
    } else {
        PartitionKind::Other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn letters_skip_used_and_reserved() {
        assert_eq!(pick_letter(&[]), Some('W'));
        assert_eq!(pick_letter(&['w', 'S']), Some('R'));
        let all: Vec<char> = LETTER_ORDER.chars().collect();
        assert_eq!(pick_letter(&all), None);
        assert!(!LETTER_ORDER.contains(['A', 'B', 'C', 'X', 'Y', 'Z']));
    }

    #[test]
    fn bcdboot_names_the_applied_windows_and_the_esp() {
        let (p, a) = bcdboot_command('W', 'S');
        assert!(p.to_string_lossy().contains("bcdboot.exe"));
        assert_eq!(a, vec!["W:\\Windows", "/s", "S:"]);
    }

    #[test]
    fn wpeutil_words_are_the_documented_ones() {
        assert_eq!(wpeutil_command(PowerAction::Restart), "Reboot");
        assert_eq!(wpeutil_command(PowerAction::Shutdown), "Shutdown");
    }

    #[test]
    fn kinds() {
        assert_eq!(gpt_kind(&types::ESP), PartitionKind::Esp);
        assert_eq!(gpt_kind(&types::RECOVERY), PartitionKind::Recovery);
        assert_eq!(gpt_kind(&Guid::NIL), PartitionKind::Other);
    }
}
