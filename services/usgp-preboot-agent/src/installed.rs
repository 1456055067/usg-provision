//! The post-setup runner's platform in the installed Windows (M4 plan
//! WU-10; §1.2, §1.6, §1.7): `usgp_deploy::PostSetupPlatform` over the
//! post-setup folder, the Windows folder and the account operations.
//!
//! The file work is OS-neutral and tested on the CI hosts. The account
//! and memory-lock operations come from an [`AccountOps`] implementation:
//! on Windows `postsetup_win::WinAccount` (on `usgp-winapi`, decision
//! 0019); in tests a double.
//!
//! - Every path is one of a closed set ([`RunnerFile`], `tags.json`,
//!   `postsetup-error.txt`, the `agent` folder) below folders fixed at
//!   start-up; none comes from the network or the package.
//! - Files the runner reads are opened without write or delete sharing
//!   on Windows, so the agent package cannot change between its digest
//!   check and its extraction.
//! - `tags.json` is written to a new file, protected (SYSTEM only) before
//!   any byte is written, then renamed over the old one.
//! - The installer runs from an argument vector (no shell), with a
//!   cleared environment plus `SystemRoot`, `Path`, `TEMP` and
//!   `USGP_TAGS`, its working folder the extracted package, and is killed
//!   at its time limit (M4 plan §1.7).

// COMPLIANCE MAPPING:
// - NIST 800-53: AC-3, AC-6 - tags.json writable only by SYSTEM; the
//   runner's inputs cannot be changed while open.
// - NIST 800-53: CM-7 (Least Functionality) - installer by argument
//   vector, no shell, cleared environment, bounded time.
// - NIST 800-53: SI-7 - the package is hashed and extracted from one open
//   file.
// - NIST 800-53: SI-11 - the device-side error file holds fixed text and
//   codes only.
// - SPEC: specs/configuration.md#REQ-CFG-009
// - SPEC: specs/agent-handoff.md#REQ-AGT-001, #REQ-AGT-005
// - SPEC: specs/workflow.md#REQ-SEQ-005
// - DECISION: docs/decisions/0024, 0025

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use usgp_deploy::platform::{FileWriter, PostSetupFile};
use usgp_deploy::postsetup::{AccountError, InstallOutcome, InstallerCommand, RunnerFile};
use usgp_deploy::{OpenedFile, PlatformError, PlatformErrorKind, PostSetupPlatform};
use usgp_proto::agent_package::InstallerKind;
use usgp_wincfg::archive::ExtractSink;
use zeroize::Zeroizing;

use crate::targetfs::{self, DirSink, FileReadAt, ProtectFn};
use crate::wintools::{self, RunError};

/// The tags file name in `%ProgramData%\usgp\` (M4 plan §1.6).
pub const TAGS_FILE: &str = "tags.json";
/// The device-side error file in `%ProgramData%\usgp\` (M4 plan §1.2).
pub const ERROR_FILE: &str = "postsetup-error.txt";
/// The folder the agent package is extracted to, in the post-setup folder.
pub const AGENT_DIR: &str = "agent";
/// Longest text written to the error file.
const MAX_ERROR_TEXT: usize = 4096;

/// The account and memory operations of step 7 (M4 plan §1.3).
pub trait AccountOps {
    /// Prepares locked memory for the password; fails if the memory
    /// cannot be locked (SI-16, fail closed).
    ///
    /// # Errors
    ///
    /// [`PlatformError`].
    fn lock(&mut self) -> Result<(), PlatformError>;

    /// Wipes and releases what [`AccountOps::lock`] prepared.
    fn unlock(&mut self);

    /// Sets the built-in Administrator's password, then enables it.
    ///
    /// # Errors
    ///
    /// [`AccountError`] with the status code.
    fn set_admin_password(&mut self, password: &Zeroizing<String>) -> Result<(), AccountError>;
}

/// The folders the runner works in, fixed at start-up.
#[derive(Debug, Clone)]
pub struct InstalledPaths {
    /// `%ProgramData%\usgp\postsetup`, the folder holding the runner.
    pub postsetup: PathBuf,
    /// `%ProgramData%\usgp`.
    pub usgp: PathBuf,
    /// `%WINDIR%`.
    pub windows: PathBuf,
    /// `%WINDIR%\System32`.
    pub system: PathBuf,
}

impl InstalledPaths {
    /// The path of `f`.
    #[must_use]
    pub fn runner_file(&self, f: RunnerFile) -> PathBuf {
        match f {
            RunnerFile::JobJson => self.postsetup.join(PostSetupFile::JobJson.file_name()),
            RunnerFile::JobKey => self.postsetup.join(PostSetupFile::JobKey.file_name()),
            RunnerFile::AgentPackage => {
                self.postsetup.join(PostSetupFile::AgentPackage.file_name())
            }
            RunnerFile::AnswerFile => self.windows.join("Panther").join("unattend.xml"),
            RunnerFile::SetupComplete => self
                .windows
                .join("Setup")
                .join("Scripts")
                .join("SetupComplete.cmd"),
        }
    }

    /// The paths for a runner at `exe`: `exe` must be
    /// `…\usgp\postsetup\<file>` (as `SetupComplete.cmd` starts it), so the
    /// folders follow from where the runner is, never from the
    /// environment. `None` otherwise.
    #[must_use]
    pub fn for_runner(exe: &Path, windows: &Path, system: &Path) -> Option<Self> {
        let postsetup = exe.parent()?;
        let usgp = postsetup.parent()?;
        let named = |p: &Path, n: &str| {
            p.file_name()
                .and_then(|f| f.to_str())
                .is_some_and(|f| f.eq_ignore_ascii_case(n))
        };
        (named(postsetup, "postsetup") && named(usgp, "usgp")).then(|| Self {
            postsetup: postsetup.to_path_buf(),
            usgp: usgp.to_path_buf(),
            windows: windows.to_path_buf(),
            system: system.to_path_buf(),
        })
    }
}

/// [`PostSetupPlatform`] over [`InstalledPaths`] and an [`AccountOps`].
pub struct InstalledPlatform<A: AccountOps> {
    paths: InstalledPaths,
    protect: ProtectFn,
    account: A,
}

impl<A: AccountOps> std::fmt::Debug for InstalledPlatform<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstalledPlatform")
            .field("paths", &self.paths)
            .finish_non_exhaustive()
    }
}

fn perr(kind: PlatformErrorKind, what: &'static str) -> PlatformError {
    PlatformError::new(kind, what)
}

fn io_perr(what: &'static str) -> impl Fn(io::Error) -> PlatformError {
    move |e| perr(PlatformErrorKind::Io(e.kind()), what)
}

/// Printable characters only (line breaks kept), at most
/// [`MAX_ERROR_TEXT`] bytes.
fn error_text(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars() {
        let c = if c == '\n' || !c.is_control() { c } else { ' ' };
        if out.len().saturating_add(c.len_utf8()) > MAX_ERROR_TEXT {
            break;
        }
        out.push(c);
    }
    out
}

impl<A: AccountOps> InstalledPlatform<A> {
    /// A platform over `paths`; `protect` applies the SYSTEM-only DACL.
    #[must_use]
    pub fn new(paths: InstalledPaths, protect: ProtectFn, account: A) -> Self {
        Self {
            paths,
            protect,
            account,
        }
    }

    /// The folders.
    #[must_use]
    pub fn paths(&self) -> &InstalledPaths {
        &self.paths
    }

    /// The account operations (tests).
    #[must_use]
    pub fn account(&self) -> &A {
        &self.account
    }

    fn installer_command(&self, cmd: &InstallerCommand<'_>) -> Command {
        let agent = self.paths.postsetup.join(AGENT_DIR);
        let installer = cmd
            .installer
            .as_str()
            .split('/')
            .fold(agent.clone(), |p, s| p.join(s));
        let mut c = match cmd.kind {
            InstallerKind::Msi => {
                let mut c = Command::new(self.paths.system.join("msiexec.exe"));
                c.arg("/i").arg(&installer).args(["/qn", "/norestart"]);
                c
            }
            InstallerKind::Exe => Command::new(&installer),
        };
        c.args(cmd.args.iter().map(|a| a.as_str()));
        let path =
            std::env::join_paths([&self.paths.system, &self.paths.windows]).unwrap_or_default();
        c.env_clear()
            .env("SystemRoot", &self.paths.windows)
            .env("Path", path)
            .env("TEMP", self.paths.windows.join("Temp"))
            .env("USGP_TAGS", cmd.tags_json)
            .current_dir(&agent)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        c
    }
}

impl<A: AccountOps> PostSetupPlatform for InstalledPlatform<A> {
    fn read_file(&mut self, f: RunnerFile, max: u64) -> Result<Zeroizing<Vec<u8>>, PlatformError> {
        const WHAT: &str = "read a post-setup file";
        let file = targetfs::open_read_only(&self.paths.runner_file(f)).map_err(io_perr(WHAT))?;
        let len = file.metadata().map_err(io_perr(WHAT))?.len();
        if len > max {
            return Err(perr(
                PlatformErrorKind::Refused,
                "post-setup file too large",
            ));
        }
        let mut out = Zeroizing::new(Vec::new());
        file.take(max.saturating_add(1))
            .read_to_end(&mut out)
            .map_err(io_perr(WHAT))?;
        if u64::try_from(out.len()).unwrap_or(u64::MAX) > max {
            return Err(perr(
                PlatformErrorKind::Refused,
                "post-setup file too large",
            ));
        }
        Ok(out)
    }

    fn open_file(&mut self, f: RunnerFile) -> Result<OpenedFile, PlatformError> {
        const WHAT: &str = "open a post-setup file";
        let file = targetfs::open_read_only(&self.paths.runner_file(f)).map_err(io_perr(WHAT))?;
        let len = file.metadata().map_err(io_perr(WHAT))?.len();
        Ok(OpenedFile {
            reader: Box::new(FileReadAt(file)),
            len,
        })
    }

    fn delete_file(&mut self, f: RunnerFile) -> Result<(), PlatformError> {
        targetfs::delete_file(&self.paths.runner_file(f)).map_err(io_perr("delete a file"))
    }

    fn file_exists(&mut self, f: RunnerFile) -> Result<bool, PlatformError> {
        targetfs::exists(&self.paths.runner_file(f)).map_err(io_perr("check a file"))
    }

    // COMPLIANCE MAPPING:
    // - NIST 800-53: AC-3, AC-6 - SYSTEM-only DACL applied before the
    //   bytes are written; replaced by rename, never edited in place.
    // - SPEC: specs/configuration.md#REQ-CFG-009
    fn write_tags(&mut self, json: &[u8]) -> Result<(), PlatformError> {
        const WHAT: &str = "write tags.json";
        let fresh = self.paths.usgp.join(format!("{TAGS_FILE}.new"));
        // A file left by an earlier, interrupted run is not reused.
        targetfs::delete_file(&fresh).map_err(io_perr(WHAT))?;
        let mut f = targetfs::create_new_file(&fresh, Some(self.protect)).map_err(io_perr(WHAT))?;
        let written = f.append(json).and_then(|()| f.finish());
        drop(f);
        if let Err(e) = written {
            let _ = targetfs::delete_file(&fresh);
            return Err(io_perr(WHAT)(e));
        }
        fs::rename(&fresh, self.paths.usgp.join(TAGS_FILE)).map_err(|e| {
            let _ = targetfs::delete_file(&fresh);
            io_perr(WHAT)(e)
        })
    }

    fn lock_memory(&mut self, _region: &[u8]) -> Result<(), PlatformError> {
        // POAM: SI-16 - the runner's password buffer (a `Zeroizing<String>`
        // from `usgp_crypto::random_password`) is not itself in locked
        // pages: `usgp-winapi` locks only its own page-aligned block
        // (`memlock::LockedWide`, by design: locking a shared page would
        // also unlock its neighbours). The copy handed to the account
        // call is in that locked block; the lock is still required, so a
        // system that cannot lock fails step 7 before any secret exists
        // beyond the generated buffer. Fix: generate the password
        // directly into the locked block (usgp-deploy and usgp-winapi
        // follow-up).
        self.account.lock()
    }

    fn unlock_memory(&mut self, _region: &[u8]) {
        self.account.unlock();
    }

    fn set_admin_password(&mut self, password: &Zeroizing<String>) -> Result<(), AccountError> {
        self.account.set_admin_password(password)
    }

    fn agent_sink(&mut self) -> Result<Box<dyn ExtractSink + '_>, PlatformError> {
        let sink = DirSink::create_fresh(&self.paths.postsetup.join(AGENT_DIR))
            .map_err(io_perr("create the agent folder"))?;
        Ok(Box::new(sink))
    }

    fn run_installer(
        &mut self,
        cmd: &InstallerCommand<'_>,
    ) -> Result<InstallOutcome, PlatformError> {
        let mut c = self.installer_command(cmd);
        let mut child = c.spawn().map_err(io_perr("start the agent installer"))?;
        // POAM: SC-5 - at the time limit only the installer process is
        // killed; processes it started are not (no job-object call in
        // usgp-winapi). The step fails either way.
        match wintools::wait_bounded(&mut child, cmd.timeout) {
            Ok(status) => Ok(InstallOutcome::Exited(
                status.code().map_or(u32::MAX, wintools::exit_code_u32),
            )),
            Err(RunError::Timeout) => Ok(InstallOutcome::TimedOut),
            Err(_) => Err(perr(
                PlatformErrorKind::Refused,
                "watch the agent installer",
            )),
        }
    }

    fn record_failure(&mut self, text: &str) {
        let text = error_text(text);
        // POAM: SI-11 / AU-12 - the Windows event log entry of M4 plan §1.2
        // is not written: usgp-winapi has no event-log call yet. The error
        // file and standard error carry the same fixed text.
        eprintln!("usgp-agent postsetup: {text}");
        let path = self.paths.usgp.join(ERROR_FILE);
        let r = fs::File::create(&path).and_then(|mut f| {
            f.write_all(text.as_bytes())?;
            f.write_all(b"\r\n")?;
            f.sync_all()
        });
        if let Err(e) = r {
            eprintln!(
                "usgp-agent postsetup: the error file could not be written ({})",
                e.kind()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use usgp_proto::{InstallerArg, RelPath};

    use super::*;

    #[derive(Default)]
    struct FakeAccount {
        locked: bool,
        set: Vec<String>,
    }

    impl AccountOps for FakeAccount {
        fn lock(&mut self) -> Result<(), PlatformError> {
            self.locked = true;
            Ok(())
        }
        fn unlock(&mut self) {
            self.locked = false;
        }
        fn set_admin_password(&mut self, pw: &Zeroizing<String>) -> Result<(), AccountError> {
            assert!(self.locked, "set only while locked");
            self.set.push(pw.as_str().to_owned());
            Ok(())
        }
    }

    fn none(_: &fs::File) -> io::Result<()> {
        Ok(())
    }

    fn tree(tag: &str) -> InstalledPlatform<FakeAccount> {
        let root = std::env::temp_dir().join(format!("usgp-inst-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let usgp = root.join("ProgramData").join("usgp");
        let postsetup = usgp.join("postsetup");
        let windows = root.join("Windows");
        fs::create_dir_all(&postsetup).unwrap();
        fs::create_dir_all(windows.join("Panther")).unwrap();
        let paths = InstalledPaths::for_runner(
            &postsetup.join("usgp-agent.exe"),
            &windows,
            &windows.join("System32"),
        )
        .unwrap();
        InstalledPlatform::new(paths, none, FakeAccount::default())
    }

    #[test]
    fn paths_follow_the_runner_only_from_its_folder() {
        let w = Path::new("/w");
        assert!(InstalledPaths::for_runner(Path::new("/p/USGP/PostSetup/a.exe"), w, w).is_some());
        assert!(InstalledPaths::for_runner(Path::new("/p/usgp/other/a.exe"), w, w).is_none());
        assert!(InstalledPaths::for_runner(Path::new("/p/x/postsetup/a.exe"), w, w).is_none());
    }

    #[test]
    fn files_are_bounded_tags_replace_and_errors_are_recorded() {
        let mut p = tree("files");
        let job = p.paths().runner_file(RunnerFile::JobJson);
        fs::write(&job, b"0123456789").unwrap();
        assert_eq!(
            &*p.read_file(RunnerFile::JobJson, 10).unwrap(),
            b"0123456789"
        );
        assert_eq!(
            p.read_file(RunnerFile::JobJson, 9).unwrap_err().kind,
            PlatformErrorKind::Refused
        );
        let o = p.open_file(RunnerFile::JobJson).unwrap();
        assert_eq!(o.len, 10);
        let mut b = [0u8; 3];
        o.reader.read_exact_at(7, &mut b).unwrap();
        assert_eq!(&b, b"789");
        drop(o);

        p.write_tags(b"[\"a\"]").unwrap();
        p.write_tags(b"[\"b\"]").unwrap();
        let tags = p.paths().usgp.join(TAGS_FILE);
        assert_eq!(fs::read(&tags).unwrap(), b"[\"b\"]");
        assert!(!p.paths().usgp.join("tags.json.new").exists());

        assert!(p.file_exists(RunnerFile::JobJson).unwrap());
        p.delete_file(RunnerFile::JobJson).unwrap();
        p.delete_file(RunnerFile::JobJson).unwrap();
        assert!(!p.file_exists(RunnerFile::JobJson).unwrap());

        p.record_failure("step 7 failed\u{7}: code x");
        let t = fs::read_to_string(p.paths().usgp.join(ERROR_FILE)).unwrap();
        assert_eq!(t, "step 7 failed : code x\r\n");

        p.lock_memory(b"").unwrap();
        p.set_admin_password(&Zeroizing::new("pw".to_owned()))
            .unwrap();
        p.unlock_memory(b"");
        assert_eq!(p.account().set, ["pw"]);
        assert!(!p.account().locked);

        let mut sink = p.agent_sink().unwrap();
        sink.end_file().unwrap_err();
        drop(sink);
        assert!(p.agent_sink().is_err(), "the agent folder must not exist");
    }

    #[cfg(unix)]
    #[test]
    fn the_installer_runs_with_a_cleared_environment_and_a_limit() {
        use std::os::unix::fs::PermissionsExt;
        let mut p = tree("installer");
        let agent = p.paths().postsetup.join(AGENT_DIR);
        fs::create_dir_all(&agent).unwrap();
        let script = agent.join("setup.exe");
        fs::write(
            &script,
            "#!/bin/sh\nenv > env.txt\necho \"$@\" > args.txt\nexit 7\n",
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let installer = RelPath::new("setup.exe").unwrap();
        let args = [InstallerArg::new("/quiet").unwrap()];
        let cmd = InstallerCommand {
            kind: InstallerKind::Exe,
            installer: &installer,
            args: &args,
            timeout: Duration::from_secs(30),
            tags_json: "[\"t\"]",
        };
        assert_eq!(p.run_installer(&cmd).unwrap(), InstallOutcome::Exited(7));
        let env = fs::read_to_string(agent.join("env.txt")).unwrap();
        assert!(env.contains("USGP_TAGS=[\"t\"]"), "{env}");
        assert!(env.contains("SystemRoot="), "{env}");
        assert!(!env.contains("HOME="), "the environment is cleared: {env}");
        assert_eq!(
            fs::read_to_string(agent.join("args.txt")).unwrap(),
            "/quiet\n"
        );

        fs::write(&script, "#!/bin/sh\nsleep 30\n").unwrap();
        let cmd = InstallerCommand {
            timeout: Duration::from_millis(300),
            ..cmd
        };
        assert_eq!(p.run_installer(&cmd).unwrap(), InstallOutcome::TimedOut);
    }
}
