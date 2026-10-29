//! DiskPart and bounded child processes: the OS-neutral parts of formatting
//! a volume (`crate::format`), kept apart so they are tested on every host.
//! Shared by the pre-boot agent and the Windows VHD tests, so the tests run
//! the agent's own sequence (BOOT-004).
//!
//! Moved from the agent's `wintools.rs` (fix round 2) unchanged in
//! behaviour; the file-system choice is this crate's own [`FsKind`]
//! (the crate has no `usgp-proto` dependency).

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-5, SI-10 - every child process bounded in time; tool
//   input built only from fixed words and values we chose (letters,
//   labels, file-system names), never from disk or network text.
// - NIST 800-53: AC-3 - a volume is used only if exactly one volume has
//   exactly the planned extent on the chosen disk.
// - SPEC: specs/disk.md#REQ-DISK-008, #REQ-DISK-015
// - SPEC: specs/standards/winpe.md §11 (DiskPart select volume, format;
//   OPEN-WINPE-2, -3)

use std::fs::OpenOptions;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// The file system DiskPart is asked to create.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsKind {
    /// NTFS (Windows and recovery volumes).
    Ntfs,
    /// FAT32 (the EFI system partition).
    Fat32,
}

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
pub fn diskpart_script(letter: char, fs: FsKind, label: &str) -> String {
    let fs = match fs {
        FsKind::Fat32 => "fat32",
        FsKind::Ntfs => "ntfs",
    };
    format!("select volume={letter}\r\nformat fs={fs} quick label={label}\r\n")
}

/// The file-system name Windows reports for `fs`.
#[must_use]
pub fn fs_name(fs: FsKind) -> &'static str {
    match fs {
        FsKind::Fat32 => "FAT32",
        FsKind::Ntfs => "NTFS",
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_is_fixed_text() {
        assert_eq!(
            diskpart_script('S', FsKind::Fat32, "System"),
            "select volume=S\r\nformat fs=fat32 quick label=System\r\n"
        );
        assert_eq!(
            diskpart_script('W', FsKind::Ntfs, "Windows"),
            "select volume=W\r\nformat fs=ntfs quick label=Windows\r\n"
        );
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
