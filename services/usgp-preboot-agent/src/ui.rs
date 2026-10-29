//! The device's screens and input (REQ-TGT-004..010, REQ-DISK-001..006,
//! REQ-JOB-002..005).
//!
//! Screens are pure functions from state to text, so tests check exactly
//! what the person sees. Input is one line at a time through [`Console`],
//! read on a separate thread so the session can poll the server while the
//! person types. The operator code is read with echo off (Windows:
//! `usgp_winapi::console::hide_input`; a code is never prompted for with
//! echo on there) and is never shown.
//!
//! The text is single-language (REQ-JOB-015 is a MAY).

// COMPLIANCE MAPPING:
// - NIST 800-53: IA-6 (Authentication Feedback) - the code is entered with
//   echo off and never displayed.
// - NIST 800-53: SI-10 - console lines bounded; codes parsed strictly.
// - NIST 800-53: SI-11 (Error Handling) - persistent named errors; no
//   secrets on screen (REQ-JOB-014).
// - SPEC: specs/targeting.md#REQ-TGT-004, -006, -008, -009, -010, -014
// - SPEC: specs/disk.md#REQ-DISK-001..006
// - SPEC: specs/progress.md#REQ-JOB-002..005, #REQ-JOB-014

use std::fmt::Write as _;
use std::io::{self, BufRead};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::Duration;

use usgp_deploy::{JobFailure, JobView, ViewEvent};
use usgp_proto::device::DevicePackageV1;
use usgp_proto::progress::{FailureCategory, Step};
use usgp_proto::{DisplayCode, JobId};
use zeroize::Zeroizing;

use crate::disks::{DiskEntry, Inventory, gb};
use crate::host::PowerAction;

/// Longest console line accepted; longer lines are refused whole.
pub const MAX_LINE_BYTES: usize = 256;

/// The console closed (no more input will come).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the console input closed")]
pub struct ConsoleClosed;

/// The device's console.
pub trait Console {
    /// Replaces the screen with `text`.
    fn show(&mut self, text: &str);

    /// Waits up to `wait` for one line. `Ok(None)` if none came in time.
    /// The line is held in a zeroizing buffer (it may be a code).
    ///
    /// # Errors
    ///
    /// [`ConsoleClosed`].
    fn line(&mut self, wait: Duration) -> Result<Option<Zeroizing<String>>, ConsoleClosed>;

    /// Turns echo of typed input off (`false`) or back on (`true`).
    ///
    /// # Errors
    ///
    /// A fixed reason if echo cannot be turned off; the caller must then
    /// not ask for a code.
    fn set_echo(&mut self, on: bool) -> Result<(), &'static str>;
}

/// The longest the agent waits for the person at any screen, including
/// the authorisation wait and every persistent error screen. When it runs
/// out, or the console input ends (EOF), the agent takes the safe choice:
/// before the wipe confirmation it cancels; at a persistent screen it ends
/// with no restart or shutdown. It never wipes and never restarts on its
/// own. (Design value.)
pub const MAX_IDLE_WAIT: Duration = Duration::from_secs(2 * 3600);

/// Waits for the person's `R` (restart) or `S` (shut down) at a persistent
/// screen, at most `limit` in all (REQ-JOB-005 item 4: the screen stays
/// until the person acts). `None` on EOF or when the limit runs out: no
/// power action.
pub fn wait_for_choice(console: &mut dyn Console, limit: Duration) -> Option<PowerAction> {
    let t0 = std::time::Instant::now();
    loop {
        let left = limit.saturating_sub(t0.elapsed());
        if left.is_zero() {
            return None;
        }
        match console.line(left) {
            Ok(Some(l)) => match Input::parse(&l) {
                Input::Restart => return Some(PowerAction::Restart),
                Input::Shutdown => return Some(PowerAction::Shutdown),
                _ => {}
            },
            Ok(None) | Err(ConsoleClosed) => return None,
        }
    }
}

/// What a line means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Input {
    /// A number from the list (1-based).
    Number(usize),
    /// `b` or `back`.
    Back,
    /// `c` or `cancel`.
    Cancel,
    /// `wipe` (the separate wipe confirmation).
    Wipe,
    /// `r` or `restart`.
    Restart,
    /// `s` or `shutdown`.
    Shutdown,
    /// Empty line.
    Empty,
    /// Anything else.
    Other,
}

impl Input {
    /// Parses one line (case-insensitive; surrounding spaces ignored).
    #[must_use]
    pub fn parse(line: &str) -> Self {
        let t = line.trim();
        if t.is_empty() {
            return Self::Empty;
        }
        if t.len() <= 4 && t.bytes().all(|b| b.is_ascii_digit()) {
            return t.parse().map_or(Self::Other, Self::Number);
        }
        match t.to_ascii_lowercase().as_str() {
            "b" | "back" => Self::Back,
            "c" | "cancel" => Self::Cancel,
            "wipe" => Self::Wipe,
            "r" | "restart" => Self::Restart,
            "s" | "shutdown" => Self::Shutdown,
            _ => Self::Other,
        }
    }
}

const RULE: &str = "------------------------------------------------------------------------";

fn header(title: &str) -> String {
    format!(
        "usg-provision pre-boot agent {}\n{RULE}\n{title}\n{RULE}\n",
        crate::AGENT_VERSION
    )
}

/// A plain status screen (start-up, network wait, connecting).
#[must_use]
pub fn status_screen(title: &str, lines: &[&str]) -> String {
    let mut s = header(title);
    for l in lines {
        let _ = writeln!(s, "{l}");
    }
    s
}

/// A screen that stays until the person restarts or shuts down
/// (REQ-JOB-005 item 4; REQ-TGT-008, -009, -010).
#[must_use]
pub fn stop_screen(title: &str, lines: &[String]) -> String {
    let mut s = header(title);
    for l in lines {
        let _ = writeln!(s, "{l}");
    }
    let _ = write!(
        s,
        "\nNothing more will happen until you act.\nType R and Enter to restart, or S and Enter to shut down.\n"
    );
    s
}

/// The authorisation screen (REQ-TGT-013, REQ-TGT-014).
#[must_use]
pub fn authorise_screen(
    display: &DisplayCode,
    attempts_left: u32,
    boot_service: Option<&str>,
    note: Option<&str>,
) -> String {
    let mut s = header("Authorise this device");
    let _ = writeln!(s, "Display code:   {display}");
    if let Some(b) = boot_service {
        let _ = writeln!(s, "Boot service:   {b}");
    }
    let _ = write!(
        s,
        "\nThis device is waiting to be authorised. Either:\n\
         - type the code an operator issued and press Enter (what you type is not shown), or\n\
         - ask an operator to approve this device in the console, using the display code above.\n\n\
         Code attempts left: {attempts_left}\nType C and Enter to cancel.\n"
    );
    if let Some(n) = note {
        let _ = write!(s, "\n{n}\n");
    }
    s
}

/// The package list (REQ-TGT-004).
#[must_use]
pub fn packages_screen(packages: &[DevicePackageV1], note: Option<&str>) -> String {
    let mut s = header("Choose what to install");
    for (i, p) in packages.iter().enumerate() {
        let _ = writeln!(s, "{:>3}) {}", i.saturating_add(1), p.name.as_str());
        if let Some(d) = &p.description {
            let _ = writeln!(s, "     {}", d.as_str());
        }
        let _ = writeln!(
            s,
            "     {} {} {} ({}); image {}; needs a disk of at least {}",
            p.os.release.as_str(),
            p.os.edition.as_str(),
            p.os.architecture.as_str(),
            p.os.source.as_str(),
            gb(p.image_bytes),
            gb(p.required_disk_bytes),
        );
    }
    let _ = write!(
        s,
        "\nType the number of a package and press Enter. Type C to cancel.\n"
    );
    if let Some(n) = note {
        let _ = write!(s, "\n{n}\n");
    }
    s
}

fn disk_line(e: &DiskEntry) -> String {
    let f = &e.found.facts;
    let parts = match f.partitions.len() {
        0 => "no partitions".to_owned(),
        1 => "1 existing partition".to_owned(),
        n => format!("{n} existing partitions"),
    };
    format!(
        "{} - {} - {} - {}",
        gb(f.size_bytes),
        usgp_proto::DiskText::sanitized(&f.identity.model).as_str(),
        f.bus,
        parts
    )
}

/// The disk list: eligible disks numbered, refused disks with every
/// reason (REQ-DISK-001, REQ-DISK-002, REQ-DISK-005).
#[must_use]
pub fn disks_screen(package: &str, inv: &Inventory, note: Option<&str>) -> String {
    let mut s = header("Choose the disk to install to");
    let _ = writeln!(s, "Package: {package}\n");
    for (i, e) in inv.eligible().enumerate() {
        let _ = writeln!(s, "{:>3}) {}", i.saturating_add(1), disk_line(e));
    }
    let refused: Vec<_> = inv.refused().collect();
    if !refused.is_empty() {
        let _ = writeln!(s, "\nDisks that cannot be used:");
        for e in refused {
            let _ = writeln!(s, "  -  {}", disk_line(e));
            for r in &e.refusals {
                let _ = writeln!(s, "       because: {r}");
            }
        }
    }
    let _ = write!(
        s,
        "\nType the number of a disk and press Enter. Type B to go back, C to cancel.\n"
    );
    if let Some(n) = note {
        let _ = write!(s, "\n{n}\n");
    }
    s
}

/// The separate wipe confirmation (REQ-DISK-006, REQ-TGT-006).
#[must_use]
pub fn wipe_screen(p: &DevicePackageV1, e: &DiskEntry) -> String {
    let mut s = header("Confirm: erase the disk and install");
    let f = &e.found.facts;
    let _ = writeln!(s, "Package:  {}", p.name.as_str());
    let _ = writeln!(
        s,
        "Installs: {} {} {}",
        p.os.release.as_str(),
        p.os.edition.as_str(),
        p.os.architecture.as_str()
    );
    let _ = writeln!(s, "Disk:     {}", disk_line(e));
    let serial = f.identity.serial.as_deref().unwrap_or("");
    if !serial.is_empty() {
        let _ = writeln!(
            s,
            "Serial:   {}",
            usgp_proto::DiskText::sanitized(serial).as_str()
        );
    }
    let _ = writeln!(
        s,
        "\nEVERY PARTITION AND ALL DATA ON THIS DISK WILL BE DESTROYED."
    );
    if f.partitions.is_empty() {
        let _ = writeln!(s, "The disk has no partitions.");
    } else {
        let _ = writeln!(s, "Existing partitions:");
        for (i, part) in f.partitions.iter().enumerate() {
            let kind = e.found.kinds.get(i).map_or("other", |k| k.as_str());
            let label = part
                .label
                .as_deref()
                .and_then(usgp_proto::PartitionLabel::sanitized)
                .map(|l| format!(" \"{}\"", l.as_str()))
                .unwrap_or_default();
            let _ = writeln!(
                s,
                "  {:>3}. {kind:<9} {:>12}{label}",
                i.saturating_add(1),
                gb(part.size_bytes)
            );
        }
    }
    let _ = write!(
        s,
        "\nType WIPE and press Enter to erase this disk and install.\n\
         Type B to choose another disk, or C to cancel.\n\
         After WIPE the install cannot be cancelled.\n"
    );
    s
}

fn step_name(s: Step) -> &'static str {
    match s.get() {
        1 => "Download and verify the content",
        2 => "Partition and format the disk",
        3 => "Apply the image",
        4 => "Make the disk bootable",
        _ => "Report success and restart",
    }
}

fn category_text(c: FailureCategory) -> &'static str {
    match c {
        FailureCategory::Network => "a network problem",
        FailureCategory::Integrity => "an integrity-check failure",
        FailureCategory::Refused => "a refusal",
        FailureCategory::Timeout => "a time limit",
        _ => "a local problem (disk, memory or the device)",
    }
}

/// The text of a job failure (REQ-JOB-005 items 1 to 3).
#[must_use]
pub fn failure_lines(f: &JobFailure) -> Vec<String> {
    let mut v = vec![
        format!("Failed step: {} - {}", f.step.get(), step_name(f.step)),
        format!("Cause:       {}", category_text(f.category)),
        format!("Reason:      {} ({})", f.message, f.code.as_str()),
    ];
    if !f.files.is_empty() || f.count > 0 {
        v.push(format!("Files that failed: {}", f.count));
        for i in &f.files {
            v.push(format!("  - {} ({})", i.name.as_str(), i.role.as_str()));
        }
    }
    if f.attempts > 1 {
        v.push(format!("Attempts:    {}", f.attempts));
    }
    v.push(if f.disk_written {
        "The disk was changed; it will not start Windows until it is installed again.".to_owned()
    } else {
        "Nothing was written to any disk.".to_owned()
    });
    v
}

/// Where each step is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mark {
    Pending,
    Running,
    Done,
    Failed,
}

/// The job screen state (REQ-JOB-002 to REQ-JOB-005).
#[derive(Debug, Clone)]
pub struct JobScreen {
    job: Option<JobId>,
    package: String,
    edition: String,
    marks: [Mark; 5],
    bytes: Option<(u64, u64)>,
    item: Option<String>,
    failure: Option<Vec<String>>,
    succeeded: bool,
}

impl Default for JobScreen {
    fn default() -> Self {
        Self {
            job: None,
            package: String::new(),
            edition: String::new(),
            marks: [Mark::Pending; 5],
            bytes: None,
            item: None,
            failure: None,
            succeeded: false,
        }
    }
}

impl JobScreen {
    fn mark(&mut self, s: Step, m: Mark) {
        if let Some(x) = usize::from(s.get())
            .checked_sub(1)
            .and_then(|i| self.marks.get_mut(i))
        {
            *x = m;
        }
    }

    /// Applies an engine event.
    pub fn apply(&mut self, e: &ViewEvent<'_>) {
        match e {
            ViewEvent::Started {
                job_id,
                package,
                edition,
                ..
            } => {
                self.job = Some(*job_id);
                self.package = (*package).to_owned();
                self.edition = (*edition).to_owned();
            }
            ViewEvent::StepStarted(s) => {
                self.mark(*s, Mark::Running);
                self.bytes = None;
                self.item = None;
            }
            ViewEvent::Progress {
                bytes_done,
                bytes_total,
                item,
                ..
            } => {
                self.bytes = Some((*bytes_done, *bytes_total));
                self.item = item.map(|i| format!("{} ({})", i.name.as_str(), i.role.as_str()));
            }
            ViewEvent::StepCompleted(s) => {
                self.mark(*s, Mark::Done);
                self.bytes = None;
                self.item = None;
            }
            ViewEvent::Failed(f) => {
                self.mark(f.step, Mark::Failed);
                self.failure = Some(failure_lines(f));
            }
            // The engine sends this only after every step succeeded and the
            // server acknowledged the report (step 5 has no separate
            // completion event).
            ViewEvent::Succeeded if self.failure.is_none() => {
                self.succeeded = true;
                self.marks = [Mark::Done; 5];
            }
            _ => {}
        }
    }

    /// The screen. Completion is shown only when every step is done and
    /// nothing failed (REQ-JOB-004).
    #[must_use]
    pub fn render(&self) -> String {
        let title = if self.failure.is_some() {
            "INSTALL FAILED"
        } else if self.succeeded && self.marks.iter().all(|m| *m == Mark::Done) {
            "Install complete"
        } else {
            "Installing"
        };
        let mut s = header(title);
        if let Some(j) = self.job {
            let _ = writeln!(s, "Job:     {j}");
        }
        let _ = writeln!(s, "Package: {}", self.package);
        let _ = writeln!(s, "Edition: {}\n", self.edition);
        for (i, step) in Step::ALL.iter().enumerate() {
            let m = match self.marks.get(i) {
                Some(Mark::Done) => "[done]   ",
                Some(Mark::Running) => "[running]",
                Some(Mark::Failed) => "[FAILED] ",
                _ => "[ ]      ",
            };
            let _ = writeln!(s, "  {m} {}. {}", step.get(), step_name(*step));
        }
        if let Some((done, total)) = self.bytes {
            let pct = done
                .saturating_mul(100)
                .checked_div(total)
                .unwrap_or(0)
                .min(100);
            let _ = writeln!(s, "\n  {} of {} ({pct}%)", gb(done), gb(total));
            if let Some(i) = &self.item {
                let _ = writeln!(s, "  File: {i}");
            }
        }
        if let Some(f) = &self.failure {
            let _ = writeln!(s);
            for l in f {
                let _ = writeln!(s, "{l}");
            }
            let _ = write!(
                s,
                "\nNothing more will happen until you act.\nType R and Enter to restart, or S and Enter to shut down.\n"
            );
        }
        s
    }
}

/// The engine's [`JobView`] on a [`Console`].
pub struct ConsoleView<'a> {
    console: &'a mut dyn Console,
    screen: JobScreen,
}

impl std::fmt::Debug for ConsoleView<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsoleView")
            .field("screen", &self.screen)
            .finish_non_exhaustive()
    }
}

impl<'a> ConsoleView<'a> {
    /// A view on `console`.
    pub fn new(console: &'a mut dyn Console) -> Self {
        Self {
            console,
            screen: JobScreen::default(),
        }
    }

    /// The current screen.
    #[must_use]
    pub fn screen(&self) -> &JobScreen {
        &self.screen
    }
}

impl JobView for ConsoleView<'_> {
    fn show(&mut self, event: &ViewEvent<'_>) {
        // A failure stays: later events never replace it (REQ-JOB-005).
        if self.screen.failure.is_some() {
            return;
        }
        self.screen.apply(event);
        let text = self.screen.render();
        self.console.show(&text);
    }
}

/// Reads one line of at most [`MAX_LINE_BYTES`] bytes. `Ok(None)` at end
/// of input. An overlong or non-UTF-8 line is consumed whole and returned
/// as an empty line, which no prompt accepts.
fn read_bounded_line(r: &mut dyn BufRead) -> io::Result<Option<Zeroizing<String>>> {
    let mut line = Zeroizing::new(Vec::with_capacity(64));
    let mut overlong = false;
    loop {
        let (consumed, done) = {
            let buf = r.fill_buf()?;
            if buf.is_empty() {
                if line.is_empty() && !overlong {
                    return Ok(None);
                }
                (0, true)
            } else {
                match buf.iter().position(|&b| b == b'\n') {
                    Some(i) => {
                        let part = buf.get(..i).unwrap_or_default();
                        if line.len().saturating_add(part.len()) <= MAX_LINE_BYTES {
                            line.extend_from_slice(part);
                        } else {
                            overlong = true;
                        }
                        (i.saturating_add(1), true)
                    }
                    None => {
                        if line.len().saturating_add(buf.len()) <= MAX_LINE_BYTES {
                            line.extend_from_slice(buf);
                        } else {
                            overlong = true;
                        }
                        (buf.len(), false)
                    }
                }
            }
        };
        r.consume(consumed);
        if done {
            break;
        }
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    if overlong {
        return Ok(Some(Zeroizing::new(String::new())));
    }
    let text = std::str::from_utf8(&line).map_or_else(|_| String::new(), str::to_owned);
    Ok(Some(Zeroizing::new(text)))
}

/// Line reader over any input, on its own thread.
pub struct LineReader {
    rx: Receiver<Zeroizing<String>>,
}

impl std::fmt::Debug for LineReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LineReader").finish_non_exhaustive()
    }
}

impl LineReader {
    /// Starts reading `input` line by line.
    ///
    /// # Errors
    ///
    /// If the thread cannot be started.
    pub fn spawn(input: Box<dyn BufRead + Send>) -> io::Result<Self> {
        let (tx, rx) = mpsc::channel();
        std::thread::Builder::new()
            .name("console-input".to_owned())
            .spawn(move || {
                let mut input = input;
                // Ends at end of input, on a read error, or when the
                // receiver is gone.
                while let Ok(Some(l)) = read_bounded_line(&mut *input) {
                    if tx.send(l).is_err() {
                        break;
                    }
                }
            })?;
        Ok(Self { rx })
    }

    /// Waits up to `wait` for one line.
    ///
    /// # Errors
    ///
    /// [`ConsoleClosed`] at end of input.
    pub fn line(&mut self, wait: Duration) -> Result<Option<Zeroizing<String>>, ConsoleClosed> {
        match self.rx.recv_timeout(wait) {
            Ok(l) => Ok(Some(l)),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => Err(ConsoleClosed),
        }
    }
}

/// The process console: standard output for screens, standard input for
/// lines.
pub struct StdConsole {
    reader: LineReader,
    #[cfg(windows)]
    echo_off: Option<usgp_winapi::console::EchoOff>,
}

impl std::fmt::Debug for StdConsole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StdConsole").finish_non_exhaustive()
    }
}

impl StdConsole {
    /// Starts reading standard input.
    ///
    /// # Errors
    ///
    /// If the reader thread cannot be started.
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            reader: LineReader::spawn(Box::new(io::BufReader::new(io::stdin())))?,
            #[cfg(windows)]
            echo_off: None,
        })
    }
}

impl Console for StdConsole {
    fn show(&mut self, text: &str) {
        use io::Write as _;
        let mut out = io::stdout().lock();
        // Form feed and a blank line separate screens on a plain console.
        let _ = write!(out, "\n\n{text}");
        let _ = out.flush();
    }

    fn line(&mut self, wait: Duration) -> Result<Option<Zeroizing<String>>, ConsoleClosed> {
        self.reader.line(wait)
    }

    #[cfg(windows)]
    fn set_echo(&mut self, on: bool) -> Result<(), &'static str> {
        if on {
            self.echo_off = None;
            return Ok(());
        }
        if self.echo_off.is_none() {
            self.echo_off = Some(
                usgp_winapi::console::hide_input()
                    .map_err(|_| "input echo could not be turned off")?,
            );
        }
        Ok(())
    }

    // Off Windows the binary runs only the simulation, whose input is a
    // script, not a person at a terminal.
    #[cfg(not(windows))]
    fn set_echo(&mut self, _on: bool) -> Result<(), &'static str> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inputs() {
        assert_eq!(Input::parse(" 2 "), Input::Number(2));
        assert_eq!(Input::parse("WIPE"), Input::Wipe);
        assert_eq!(Input::parse("wipe-disk"), Input::Other);
        assert_eq!(Input::parse("c"), Input::Cancel);
        assert_eq!(Input::parse("Back"), Input::Back);
        assert_eq!(Input::parse("s"), Input::Shutdown);
        assert_eq!(Input::parse("R"), Input::Restart);
        assert_eq!(Input::parse(""), Input::Empty);
        assert_eq!(Input::parse("12345"), Input::Other);
        assert_eq!(Input::parse("x"), Input::Other);
    }

    #[test]
    fn bounded_lines() {
        let long = "a".repeat(MAX_LINE_BYTES + 1);
        let mut text = format!("one\r\n{long}\n").into_bytes();
        // The third line is invalid UTF-8.
        text.extend_from_slice(b"\xff\ntwo");
        let mut r = io::Cursor::new(text);
        let read =
            |r: &mut io::Cursor<Vec<u8>>| read_bounded_line(r).unwrap().map(|s| s.to_string());
        assert_eq!(read(&mut r).as_deref(), Some("one"));
        assert_eq!(read(&mut r).as_deref(), Some(""));
        assert_eq!(read(&mut r).as_deref(), Some(""));
        assert_eq!(read(&mut r).as_deref(), Some("two"));
        assert_eq!(read(&mut r), None);
    }
}
