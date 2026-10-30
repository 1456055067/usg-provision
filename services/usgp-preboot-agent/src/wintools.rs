//! OS-neutral pieces of the Windows backend, kept apart so they are tested
//! on every host: drive letter choice, the BCDBoot and `wpeutil` commands
//! and the partition kind from a GPT type. Bounded child processes, the
//! DiskPart script and volume matching moved to `usgp_winapi::diskpart`
//! (fix round 2, BOOT-004) so the Windows VHD tests run the same code.
//!
//! M4 (WU-10): the DISM argument vectors for steps 4 (`offline-drivers.md`
//! §7; M4 plan §1.4), a bounded child-process runner that captures at most
//! a fixed number of output bytes and kills the child at its limit, and the
//! redacted tail of a tool log.
//!
//! Compiled on every target: `platform_win` uses it on Windows, the
//! post-setup runner uses the bounded runner for the agent installer, and
//! the tests run it on the CI hosts.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 - tool arguments built only from fixed words and
//   letters we chose, never from disk or network text.
// - SPEC: specs/disk.md#REQ-DISK-008
// - SPEC: specs/boot-network.md#REQ-BOOT-066 (BCDBoot from the applied
//   image, naming the ESP; uefi-boot-manager.md §9.1, §9.4)
// - SPEC: specs/standards/winpe.md §5.2 (wpeutil Reboot, Shutdown), §11
//   (letters)
// - NIST 800-53: CM-7 (Least Functionality) - DISM is given only our own
//   staging folder, never `/ForceUnsigned` and never an answer file
//   (REQ-DRV-007).
// - NIST 800-53: SC-5 - every child process bounded in time and output.
// - SPEC: specs/drivers.md#REQ-DRV-004, #REQ-DRV-007
// - SPEC: specs/standards/offline-drivers.md §7.1, §7.3, §7.4, §7.5
// - DECISION: docs/decisions/0024 item 4

use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

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

/// The letters tried for new volumes, most preferred first. The caller
/// skips letters in use (`usgp_winapi::volume::free_letter`).
pub fn letter_order() -> impl Iterator<Item = char> {
    LETTER_ORDER.chars()
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

// ---------------------------------------------------------------------------
// M4: DISM (M4 plan §1.4; `offline-drivers.md` §7)
// ---------------------------------------------------------------------------

/// Largest DISM console output kept, in bytes (M4 plan §1.4: 4 MiB, the
/// listing parser's own limit).
pub const MAX_TOOL_OUTPUT: usize = 4 * 1024 * 1024;

/// Longest log tail kept for a failure detail, in bytes (M4 plan §1.4).
pub const LOG_TAIL_BYTES: u64 = 2048;

/// The folder below the Windows PE system drive that holds the DISM logs
/// (`X:\usgp\`; M4 plan §1.4). The logs stay in Windows PE and are lost
/// at the restart: nothing is left on the target.
pub const LOG_DIR: &str = "usgp";

/// The DISM log level for adding drivers (M4 plan §1.4: 3, errors,
/// warnings and information; `offline-drivers.md` §7.5).
const ADD_LOG_LEVEL: &str = "3";

/// The arguments that list the drivers of the offline Windows on
/// `windows` (M4 plan §1.4, WU-7a item 7): English output (§7.4), the
/// image root, the listing in list form (the form `usgp_wincfg::dism`
/// parses, §7.3) and a log path on Windows PE's own drive (§7.5).
///
/// [plan] The option spellings are the M4 plan's (§1.4); the spec names
/// the options but not their text (`offline-drivers.md` §7).
#[must_use]
pub fn dism_list_args(windows: char, log: &Path) -> Vec<String> {
    vec![
        "/English".to_owned(),
        format!("/Image:{windows}:\\"),
        "/Get-Drivers".to_owned(),
        "/Format:List".to_owned(),
        format!("/LogPath:{}", log.display()),
    ]
}

/// The arguments that add every driver package below `stage` (a path
/// relative to the Windows volume root, from
/// `usgp_deploy::platform::StagePath::relative`) to the offline Windows on
/// `windows`, recursively (`offline-drivers.md` §7.1; M4 plan §1.4).
///
/// Never `/ForceUnsigned` (REQ-DRV-007, §2) and never an answer file.
#[must_use]
pub fn dism_add_args(windows: char, stage: &str, log: &Path) -> Vec<String> {
    vec![
        "/English".to_owned(),
        format!("/Image:{windows}:\\"),
        "/Add-Driver".to_owned(),
        format!("/Driver:{windows}:\\{stage}\\"),
        "/Recurse".to_owned(),
        format!("/LogPath:{}", log.display()),
        format!("/LogLevel:{ADD_LOG_LEVEL}"),
    ]
}

/// The log file name for the listing or for archive `index`.
#[must_use]
pub fn dism_log_name(add_index: Option<u16>) -> String {
    match add_index {
        Some(i) => format!("dism-add-{i}.log"),
        None => "dism-list.log".to_owned(),
    }
}

/// The last [`LOG_TAIL_BYTES`] of `bytes` as printable ASCII: every other
/// byte becomes `.` and line breaks become spaces, so the text is safe for
/// a report and a screen (M4 plan §1.4: the logs hold no secret, because
/// there is none, and are redacted anyway).
#[must_use]
pub fn redacted_tail(bytes: &[u8]) -> String {
    let keep = usize::try_from(LOG_TAIL_BYTES).unwrap_or(usize::MAX);
    let start = bytes.len().saturating_sub(keep);
    bytes
        .get(start..)
        .unwrap_or_default()
        .iter()
        .map(|&b| match b {
            b'\r' | b'\n' | b'\t' => ' ',
            0x20..=0x7e => char::from(b),
            _ => '.',
        })
        .collect()
}

/// The redacted tail of the file at `path`, or an empty string if it
/// cannot be read (a missing log never hides the tool's own result).
#[must_use]
pub fn log_tail(path: &Path) -> String {
    use std::io::{Seek, SeekFrom};
    let Ok(mut f) = std::fs::File::open(path) else {
        return String::new();
    };
    let len = f.metadata().map_or(0, |m| m.len());
    let start = len.saturating_sub(LOG_TAIL_BYTES);
    if f.seek(SeekFrom::Start(start)).is_err() {
        return String::new();
    }
    let mut buf = Vec::new();
    if f.take(LOG_TAIL_BYTES).read_to_end(&mut buf).is_err() {
        return String::new();
    }
    redacted_tail(&buf)
}

/// What a bounded child process did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Captured {
    /// The exit code; `None` if the system gave none.
    pub exit_code: Option<i32>,
    /// Standard output, at most the limit given; anything beyond it was
    /// read and discarded.
    pub stdout: Vec<u8>,
    /// `true` if standard output was longer than the limit.
    pub truncated: bool,
}

/// Why a bounded child process gave no result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RunError {
    /// It could not be started.
    #[error("the tool could not be started ({0})")]
    Start(io::ErrorKind),
    /// It ran past its limit and was killed.
    #[error("the tool ran past its time limit")]
    Timeout,
    /// Its state could not be observed; it was killed.
    #[error("the tool could not be observed")]
    Lost,
}

/// How often a running child is checked.
const POLL: Duration = Duration::from_millis(100);

/// Runs `cmd` (an argument vector; no shell) with no input and standard
/// error discarded, keeps at most `max_out` bytes of standard output and
/// waits at most `limit`; a child still running at the limit is killed
/// (WU-8 POAM: no wait outlasts the engine's limits).
///
/// # Errors
///
/// [`RunError`].
pub fn run_captured(
    mut cmd: Command,
    limit: Duration,
    max_out: usize,
) -> Result<Captured, RunError> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| RunError::Start(e.kind()))?;
    let reader = child.stdout.take().map(|out| {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(read_capped(out, max_out));
        });
        rx
    });
    let status = wait_bounded(&mut child, limit)?;
    // The pipe closes when the child ends; a grandchild that kept it open
    // is not waited for longer than one poll interval past the limit.
    let (stdout, truncated) = match reader {
        Some(rx) => rx
            .recv_timeout(POLL.max(Duration::from_secs(1)))
            .unwrap_or_default(),
        None => (Vec::new(), false),
    };
    Ok(Captured {
        exit_code: status.code(),
        stdout,
        truncated,
    })
}

/// Waits for `child` at most `limit`, killing it at the limit.
///
/// # Errors
///
/// [`RunError::Timeout`] or [`RunError::Lost`].
pub fn wait_bounded(child: &mut Child, limit: Duration) -> Result<ExitStatus, RunError> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(s)) => return Ok(s),
            Ok(None) => {}
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(RunError::Lost);
            }
        }
        if start.elapsed() >= limit {
            let _ = child.kill();
            let _ = child.wait();
            return Err(RunError::Timeout);
        }
        std::thread::sleep(POLL.min(limit.saturating_sub(start.elapsed())));
    }
}

/// Reads `r` to its end, keeping at most `max` bytes.
fn read_capped(mut r: impl Read, max: usize) -> (Vec<u8>, bool) {
    let mut kept = Vec::new();
    let mut truncated = false;
    let mut buf = [0u8; 8192];
    loop {
        match r.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let chunk = buf.get(..n).unwrap_or_default();
                let room = max.saturating_sub(kept.len());
                if chunk.len() > room {
                    truncated = true;
                }
                kept.extend_from_slice(chunk.get(..room.min(chunk.len())).unwrap_or_default());
            }
        }
    }
    (kept, truncated)
}

/// A Windows exit code as the unsigned value Windows defines (installers
/// report 3010 and HRESULT-style values; M4 plan §1.7). Bit-for-bit, no
/// truncation.
#[must_use]
pub fn exit_code_u32(code: i32) -> u32 {
    u32::from_ne_bytes(code.to_ne_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn letter_order_prefers_w_s_r_and_skips_reserved() {
        let order: Vec<char> = letter_order().collect();
        assert_eq!(order.get(..3), Some(&['W', 'S', 'R'][..]));
        assert!(
            !order
                .iter()
                .any(|c| ['A', 'B', 'C', 'X', 'Y', 'Z'].contains(c))
        );
        let mut sorted = order.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), order.len(), "no letter twice");
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

    #[test]
    fn dism_arguments_stay_in_the_staging_root_and_never_force() {
        let log = Path::new("X:\\usgp\\dism-add-3.log");
        let a = dism_add_args('W', "$usgp-stage\\drv\\3", log);
        assert_eq!(
            a,
            vec![
                "/English",
                "/Image:W:\\",
                "/Add-Driver",
                "/Driver:W:\\$usgp-stage\\drv\\3\\",
                "/Recurse",
                "/LogPath:X:\\usgp\\dism-add-3.log",
                "/LogLevel:3",
            ]
        );
        let l = dism_list_args('W', Path::new("X:\\usgp\\dism-list.log"));
        assert!(l.contains(&"/Get-Drivers".to_owned()));
        assert!(l.contains(&"/Format:List".to_owned()));
        for arg in a.iter().chain(&l) {
            let low = arg.to_ascii_lowercase();
            assert!(!low.contains("forceunsigned"), "{arg}");
            assert!(!low.contains("unattend"), "{arg}");
            if let Some(d) = arg.strip_prefix("/Driver:") {
                assert!(d.starts_with("W:\\$usgp-stage\\"), "{d}");
            }
        }
        assert_eq!(dism_log_name(Some(7)), "dism-add-7.log");
        assert_eq!(dism_log_name(None), "dism-list.log");
    }

    #[test]
    fn log_tail_is_bounded_and_printable() {
        let mut b = vec![b'a'; 5000];
        b.extend_from_slice(b"\r\nend\x00\xff");
        let t = redacted_tail(&b);
        assert_eq!(t.len(), 2048);
        assert!(t.ends_with("  end.."), "{t}");
        assert!(t.chars().all(|c| (' '..='~').contains(&c)));
        assert_eq!(log_tail(Path::new("/nonexistent/usgp/log")), "");
    }

    #[test]
    fn exit_codes_keep_their_bits() {
        assert_eq!(exit_code_u32(3010), 3010);
        assert_eq!(exit_code_u32(-1), u32::MAX);
    }

    #[cfg(unix)]
    #[test]
    fn captured_output_is_capped_and_timeouts_kill() {
        let mut c = Command::new("/bin/sh");
        c.args(["-c", "printf 0123456789; exit 3"]);
        let r = run_captured(c, Duration::from_secs(20), 4).unwrap();
        assert_eq!(r.exit_code, Some(3));
        assert_eq!(r.stdout, b"0123");
        assert!(r.truncated);

        let mut c = Command::new("/bin/sh");
        c.args(["-c", "sleep 30"]);
        let start = Instant::now();
        assert_eq!(
            run_captured(c, Duration::from_millis(300), 16),
            Err(RunError::Timeout)
        );
        assert!(start.elapsed() < Duration::from_secs(10));

        let c = Command::new("/nonexistent/usgp-tool");
        assert!(matches!(
            run_captured(c, Duration::from_secs(1), 16),
            Err(RunError::Start(_))
        ));
    }
}
