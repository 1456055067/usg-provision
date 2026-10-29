//! OS-neutral pieces of the Windows backend, kept apart so they are tested
//! on every host: bounded child processes, the DiskPart script and its
//! file, drive letter choice, volume matching by extents, the BCDBoot and
//! `wpeutil` commands and the partition kind from a GPT type.
//!
//! Compiled on Windows (used by `platform_win`) and in tests.

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-5, SI-10 - every child process bounded in time; tool
//   input built only from fixed words and values we chose (letters,
//   labels, file-system names), never from disk or network text.
// - NIST 800-53: AC-3 - a volume is used only if exactly one volume has
//   exactly the planned extent on the chosen disk.
// - SPEC: specs/disk.md#REQ-DISK-008, #REQ-DISK-015
// - SPEC: specs/boot-network.md#REQ-BOOT-066 (BCDBoot from the applied
//   image, naming the ESP; uefi-boot-manager.md §9.1, §9.4)
// - SPEC: specs/standards/winpe.md §5.2 (wpeutil Reboot, Shutdown), §11
//   (DiskPart select volume, format; OPEN-WINPE-2, -3)

use std::fs::OpenOptions;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use usgp_disk::Guid;
use usgp_disk::guid::types;
use usgp_proto::disk::{FileSystem, PartitionKind};

use crate::host::PowerAction;

/// How often a running tool is checked.
const POLL: Duration = Duration::from_millis(200);

/// Why a bounded tool run failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolError {
    /// It could not be started.
    Start(io::ErrorKind),
    /// It ran past its limit and was stopped.
    Timeout,
    /// It ended with a failure status.
    Failed(Option<i32>),
}

/// Runs `cmd` with no input or output, and waits at most `limit`. A tool
/// still running at the limit is killed (WU-8 POAM: no wait may outlast
/// the engine's limits).
///
/// # Errors
///
/// [`ToolError`].
pub fn run_bounded(mut cmd: Command, limit: Duration) -> Result<(), ToolError> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| ToolError::Start(e.kind()))?;
    let start = Instant::now();
    let status: ExitStatus = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) => {}
            Err(_) => {
                // Cannot observe it: stop it and fail.
                let _ = child.kill();
                let _ = child.wait();
                return Err(ToolError::Failed(None));
            }
        }
        if start.elapsed() >= limit {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ToolError::Timeout);
        }
        std::thread::sleep(POLL.min(limit.saturating_sub(start.elapsed())));
    };
    if status.success() {
        Ok(())
    } else {
        Err(ToolError::Failed(status.code()))
    }
}

/// The DiskPart script that formats the volume at `letter` (plan section
/// 1.2(c) step 4): it selects the volume by the letter we assigned, never
/// a disk by number. `label` is one of our fixed labels.
///
/// SPEC: `specs/standards/winpe.md` §11 (SR-7). `select volume=<d>` gives
/// focus to the volume with drive letter `<d>` (the page's `=` form);
/// `format fs=<ntfs|fat32> quick label=<label>` formats the volume with
/// focus. No `noerr`: without it an error makes DiskPart exit with an
/// error code. The labels contain no space, so they are not quoted.
///
/// [project rule] (plan section 1.2(c); CR-002): the labels (`System`,
/// `Windows`, `Recovery`; `usgp-deploy` `LABEL_*`) are this project's
/// choice. Microsoft's UEFI/GPT deployment sample uses the same labels
/// (`winpe.md` §11, SRC-087); that is not a Microsoft requirement.
#[must_use]
pub fn diskpart_script(letter: char, fs: FileSystem, label: &str) -> String {
    let fs = match fs {
        FileSystem::Fat32 => "fat32",
        _ => "ntfs",
    };
    format!("select volume={letter}\r\nformat fs={fs} quick label={label}\r\n")
}

/// The file-system name Windows reports for `fs`.
#[must_use]
pub fn fs_name(fs: FileSystem) -> &'static str {
    match fs {
        FileSystem::Fat32 => "FAT32",
        _ => "NTFS",
    }
}

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

/// One volume's extents: (disk number, start, length).
pub type Extent = (u32, u64, u64);

/// The result of looking for a volume by its extent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeMatch {
    /// No volume has that extent (yet).
    None,
    /// Exactly one volume, at this index.
    One(usize),
    /// More than one: never guess between volumes.
    Ambiguous,
}

/// Finds the volume whose extents are exactly one extent on `disk` at
/// `start` with `len` bytes.
#[must_use]
pub fn match_volume(volumes: &[Vec<Extent>], disk: u32, start: u64, len: u64) -> VolumeMatch {
    let mut hits = volumes
        .iter()
        .enumerate()
        .filter(|(_, e)| e.as_slice() == [(disk, start, len)])
        .map(|(i, _)| i);
    match (hits.next(), hits.next()) {
        (None, _) => VolumeMatch::None,
        (Some(i), None) => VolumeMatch::One(i),
        (Some(_), Some(_)) => VolumeMatch::Ambiguous,
    }
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

/// Writes the DiskPart script `text` to a new file in `dir` with a name
/// made from `random` (16 bytes from the DRBG), created with create-new
/// so an existing file of that name is never reused or followed
/// (SEC-008). Returns its path. On a write error the file is removed.
///
/// # Errors
///
/// The I/O error, including `AlreadyExists`.
pub fn write_script_new(dir: &Path, random: [u8; 16], text: &str) -> io::Result<PathBuf> {
    let name: String = random.iter().map(|b| format!("{b:02x}")).collect();
    let path = dir.join(format!("usgp-format-{name}.txt"));
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    if let Err(e) = f.write_all(text.as_bytes()).and_then(|()| f.sync_all()) {
        drop(f);
        let _ = std::fs::remove_file(&path);
        return Err(e);
    }
    Ok(path)
}

/// `true` if the drive letter still names the volume we resolved, right
/// before DiskPart runs (BOOT-001, REQ-DISK-015): the volume at the
/// letter is `expected` (same volume GUID path, compared ignoring ASCII
/// case), and that volume's extents are still exactly the planned one.
#[must_use]
pub fn letter_still_names(
    at_letter: Option<&str>,
    expected: &str,
    extents: &[Extent],
    want: Extent,
) -> bool {
    at_letter.is_some_and(|v| v.eq_ignore_ascii_case(expected)) && extents == [want]
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
    fn script_is_fixed_text() {
        assert_eq!(
            diskpart_script('S', FileSystem::Fat32, "System"),
            "select volume=S\r\nformat fs=fat32 quick label=System\r\n"
        );
        assert_eq!(
            diskpart_script('W', FileSystem::Ntfs, "Windows"),
            "select volume=W\r\nformat fs=ntfs quick label=Windows\r\n"
        );
    }

    #[test]
    fn letters_skip_used_and_reserved() {
        assert_eq!(pick_letter(&[]), Some('W'));
        assert_eq!(pick_letter(&['w', 'S']), Some('R'));
        let all: Vec<char> = LETTER_ORDER.chars().collect();
        assert_eq!(pick_letter(&all), None);
        assert!(!LETTER_ORDER.contains(['A', 'B', 'C', 'X', 'Y', 'Z']));
    }

    #[test]
    fn volumes_match_exactly_once() {
        let v = vec![
            vec![(1, 1 << 20, 100)],
            vec![(2, 1 << 20, 100)],
            vec![(1, 1 << 20, 100), (1, 1 << 30, 100)],
            vec![(1, 2 << 20, 100)],
        ];
        assert_eq!(match_volume(&v, 1, 1 << 20, 100), VolumeMatch::One(0));
        assert_eq!(match_volume(&v, 2, 1 << 20, 100), VolumeMatch::One(1));
        assert_eq!(match_volume(&v, 1, 1 << 20, 99), VolumeMatch::None);
        assert_eq!(match_volume(&v, 3, 1 << 20, 100), VolumeMatch::None);
        let dup = vec![vec![(1, 0, 5)], vec![(1, 0, 5)]];
        assert_eq!(match_volume(&dup, 1, 0, 5), VolumeMatch::Ambiguous);
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
    fn script_files_are_new_and_random_named() {
        let dir = std::env::temp_dir().join(format!("usgp-wintools-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let r = [0xABu8; 16];
        let p = write_script_new(&dir, r, "select volume=W\r\n").unwrap();
        assert_eq!(
            p.file_name().unwrap().to_str().unwrap(),
            "usgp-format-abababababababababababababababab.txt"
        );
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "select volume=W\r\n");
        // The same name again is refused, never overwritten.
        let e = write_script_new(&dir, r, "other").unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "select volume=W\r\n");
        // A different random value gives a different file.
        let q = write_script_new(&dir, [1u8; 16], "x").unwrap();
        assert_ne!(p, q);
        #[cfg(unix)]
        {
            // A planted link at the name is not followed.
            let target = dir.join("target");
            std::fs::write(&target, "keep").unwrap();
            let r2 = [2u8; 16];
            let planted = dir.join("usgp-format-02020202020202020202020202020202.txt");
            std::os::unix::fs::symlink(&target, &planted).unwrap();
            assert!(write_script_new(&dir, r2, "x").is_err());
            assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn letter_must_still_name_the_resolved_volume() {
        let v = "\\\\?\\Volume{1}\\";
        let want = (3, 1 << 20, 100);
        assert!(letter_still_names(Some(v), v, &[want], want));
        assert!(letter_still_names(
            Some(&v.to_ascii_lowercase()),
            v,
            &[want],
            want
        ));
        assert!(!letter_still_names(None, v, &[want], want), "letter gone");
        assert!(
            !letter_still_names(Some("\\\\?\\Volume{2}\\"), v, &[want], want),
            "letter moved to another volume"
        );
        assert!(
            !letter_still_names(Some(v), v, &[(4, 1 << 20, 100)], want),
            "volume on another disk"
        );
        assert!(!letter_still_names(Some(v), v, &[], want));
        assert!(!letter_still_names(Some(v), v, &[want, want], want));
    }

    #[test]
    fn kinds() {
        assert_eq!(gpt_kind(&types::ESP), PartitionKind::Esp);
        assert_eq!(gpt_kind(&types::RECOVERY), PartitionKind::Recovery);
        assert_eq!(gpt_kind(&Guid::NIL), PartitionKind::Other);
    }

    #[cfg(unix)]
    #[test]
    fn tools_are_bounded() {
        let mut ok = Command::new("sh");
        ok.args(["-c", "exit 0"]);
        assert_eq!(run_bounded(ok, Duration::from_secs(10)), Ok(()));
        let mut fail = Command::new("sh");
        fail.args(["-c", "exit 3"]);
        assert_eq!(
            run_bounded(fail, Duration::from_secs(10)),
            Err(ToolError::Failed(Some(3)))
        );
        let mut slow = Command::new("sh");
        slow.args(["-c", "sleep 30"]);
        let t = Instant::now();
        assert_eq!(
            run_bounded(slow, Duration::from_millis(300)),
            Err(ToolError::Timeout)
        );
        assert!(t.elapsed() < Duration::from_secs(10));
        assert!(matches!(
            run_bounded(Command::new("/nonexistent/tool"), Duration::from_secs(1)),
            Err(ToolError::Start(_))
        ));
    }
}
