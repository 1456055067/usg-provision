//! Formatting one new volume with DiskPart, as the pre-boot agent does it
//! (plan section 1.2(c) step 4): find the volume by its exact extent, and,
//! once the caller has given it a drive letter, write the script, check
//! the letter still names that volume, run DiskPart bounded in time, and
//! read the result back (file system, label, extent, letter).
//!
//! The agent's `platform_win` and the Windows VHD tests
//! (`tests/vhd_disk.rs`, BOOT-004) both call this module, so the tests run
//! the agent's own format sequence. Which letter a volume gets is the
//! caller's policy and stays with the caller.

// COMPLIANCE MAPPING:
// - NIST 800-53: AC-3 (Access Enforcement) - only the one volume at
//   exactly the planned extent on the chosen disk is formatted, selected
//   by a letter re-checked just before DiskPart runs.
// - NIST 800-53: SC-5 - DiskPart and every wait bounded in time.
// - NIST 800-53: SI-10 - the script holds only fixed words, our letter
//   and our label.
// - SPEC: specs/disk.md#REQ-DISK-008, #REQ-DISK-015
// - SPEC: specs/standards/winpe.md §11 (DiskPart; OPEN-WINPE-2, -3)
// - SPEC: specs/standards/windows-storage-firmware-api.md §8, §15

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use crate::WinApiError;
use crate::diskpart::{self, Extent, FsKind, ToolError, VolumeMatch};
use crate::paths::{DriveLetter, VolumeGuidPath};
use crate::volume;

/// How often a new volume is looked for.
pub const VOLUME_POLL: Duration = Duration::from_millis(500);

/// Why a volume could not be found or formatted. No path or data.
#[derive(Debug)]
#[non_exhaustive]
pub enum FormatError {
    /// No volume at the extent arrived in time.
    NotFound,
    /// The volume or its letter is not the one planned (more than one
    /// volume at the extent, the letter moved, or the read-back differs);
    /// the text names which check.
    Mismatch(&'static str),
    /// DiskPart could not be started, ran too long, or failed.
    Tool(ToolError),
    /// The script file could not be written.
    Script(std::io::ErrorKind),
    /// A Windows query failed.
    Os(WinApiError),
}

impl core::fmt::Display for FormatError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotFound => f.write_str("no volume appeared at the planned extent"),
            Self::Mismatch(what) => write!(f, "volume check failed: {what}"),
            Self::Tool(e) => write!(f, "DiskPart: {e:?}"),
            Self::Script(k) => write!(f, "cannot write the DiskPart script: {k:?}"),
            Self::Os(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for FormatError {}

/// One volume to format: exactly one extent on `disk`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatTarget<'a> {
    /// Disk number (now; spec §7).
    pub disk: u32,
    /// Byte offset of the partition.
    pub start: u64,
    /// Length in bytes.
    pub len: u64,
    /// File system to create.
    pub fs: FsKind,
    /// Volume label (fixed ASCII words, no spaces).
    pub label: &'a str,
}

impl FormatTarget<'_> {
    fn extent(&self) -> Extent {
        (self.disk, self.start, self.len)
    }
}

/// Where the script goes and how DiskPart is run.
#[derive(Debug, Clone, Copy)]
pub struct FormatEnv<'a> {
    /// The system directory holding `diskpart.exe`.
    pub system_dir: &'a Path,
    /// Directory for the script file (created new, removed after).
    pub script_dir: &'a Path,
    /// Most time DiskPart may run.
    pub tool_limit: Duration,
}

fn extents_of(v: &VolumeGuidPath) -> Vec<Extent> {
    volume::disk_extents(v)
        .map(|e| {
            e.iter()
                .map(|x| (x.disk_number, x.starting_offset, x.length))
                .collect()
        })
        .unwrap_or_default()
}

/// The one volume whose extents are exactly `t`'s extent, waited for up
/// to `limit`. Volumes whose extents cannot be read cannot match. More
/// than one match is refused, never guessed between.
///
/// # Errors
///
/// [`FormatError::NotFound`] or [`FormatError::Mismatch`].
pub fn wait_for_volume(
    t: &FormatTarget<'_>,
    limit: Duration,
) -> Result<VolumeGuidPath, FormatError> {
    let t0 = Instant::now();
    loop {
        if let Ok(vols) = volume::volumes() {
            let ext: Vec<Vec<Extent>> = vols.iter().map(extents_of).collect();
            match diskpart::match_volume(&ext, t.disk, t.start, t.len) {
                VolumeMatch::One(i) => return vols.get(i).cloned().ok_or(FormatError::NotFound),
                VolumeMatch::None => {}
                VolumeMatch::Ambiguous => {
                    return Err(FormatError::Mismatch("more than one volume at the extent"));
                }
            }
        }
        if t0.elapsed() >= limit {
            return Err(FormatError::NotFound);
        }
        std::thread::sleep(VOLUME_POLL);
    }
}

/// Formats `vol`, which the caller has given drive letter `letter`, as
/// `t` says, and reads the result back.
///
/// 1. The script (`select volume=<letter>`, `format fs= quick label=`) is
///    written create-new under a name made from `random` (16 bytes from
///    the caller's DRBG; SEC-008).
/// 2. Immediately before DiskPart starts, the letter must still name
///    `vol` and `vol` must still have exactly `t`'s extent (BOOT-001).
/// 3. DiskPart runs the script with `/s`, bounded by `env.tool_limit`.
///    `winpe.md` §11: `/s` is used by Microsoft's samples but not
///    described on the "diskpart" page (OPEN-WINPE-2), and the exit-code
///    values are not documented (OPEN-WINPE-3), so the exit status is only
///    a first filter; the read-back below is the real check.
/// 4. Read-back: the file-system name, the label (ignoring ASCII case:
///    whether FAT32 keeps a label's case is not in the summaries), the
///    extent, and that `letter` is still one of `vol`'s letters.
///
/// # Errors
///
/// [`FormatError`]; the script file is removed in every case (best
/// effort).
pub fn format_at_letter(
    t: &FormatTarget<'_>,
    vol: &VolumeGuidPath,
    letter: DriveLetter,
    env: &FormatEnv<'_>,
    random: [u8; 16],
) -> Result<(), FormatError> {
    let script = diskpart::write_script_new(
        env.script_dir,
        random,
        &diskpart::diskpart_script(letter.letter(), t.fs, t.label),
    )
    .map_err(|e| FormatError::Script(e.kind()))?;
    // POAM: BOOT-001 residual - DiskPart opens the volume itself, so a
    // lock cannot be held across its start; a change in the moments
    // between this check and DiskPart's `select volume` is caught only by
    // the read-back after the format.
    let at_letter = volume::volume_at(letter).ok();
    if !diskpart::letter_still_names(
        at_letter.as_ref().map(VolumeGuidPath::as_str),
        vol.as_str(),
        &extents_of(vol),
        t.extent(),
    ) {
        let _ = std::fs::remove_file(&script);
        return Err(FormatError::Mismatch(
            "volume at the drive letter before formatting",
        ));
    }
    let mut cmd = Command::new(env.system_dir.join("diskpart.exe"));
    cmd.arg("/s").arg(&script);
    let ran = diskpart::run_bounded(cmd, env.tool_limit);
    // Best effort: the script holds only our letter, fs and label.
    let _ = std::fs::remove_file(&script);
    ran.map_err(FormatError::Tool)?;

    let fs = volume::file_system_name(vol).map_err(FormatError::Os)?;
    if !fs.eq_ignore_ascii_case(diskpart::fs_name(t.fs)) {
        return Err(FormatError::Mismatch("formatted file system"));
    }
    let label = volume::label(vol).map_err(FormatError::Os)?;
    if !label.eq_ignore_ascii_case(t.label) {
        return Err(FormatError::Mismatch("formatted volume label"));
    }
    if extents_of(vol) != [t.extent()] {
        return Err(FormatError::Mismatch("formatted volume extents"));
    }
    let now = volume::drive_letters(vol).map_err(FormatError::Os)?;
    if !now.contains(&letter) {
        return Err(FormatError::Mismatch("volume drive letter"));
    }
    Ok(())
}
