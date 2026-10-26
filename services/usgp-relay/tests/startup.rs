//! Process contract of the `usgp-relay` binary (plan section 3.6).
//!
//! Runs the built artifact as a child process. Every invocation runs the
//! fail-closed FIPS check first (docs/decisions/0001, NIST 800-53 SC-13):
//! a non-FIPS build prints "refusing to start" and exits 1, failing these
//! tests.
//!
//! | Invocation | Expected |
//! |------------|----------|
//! | `--self-check` | exit 0, no output |
//! | no arguments | usage on stderr, exit 2 |
//! | `--help` | usage on stdout, exit 0 |
//! | unknown argument | usage on stderr, exit 2 |
//! | `--check-config` with valid config and content | exit 0, state `running` |
//! | `--check-config` with tampered or missing content | exit 3 |
//! | `--check-config` / `--config` with an unusable file | exit 78 |
//!
//! The tests run as an ordinary user, so every invocation with a
//! configuration names the test's uid with `--admin-uid` (the relay trusts
//! files owned by uid 0 or that uid).

#[cfg(test)]
pub mod common;

#[cfg(test)]
mod startup {
    use std::process::{Command, Output};

    use crate::common::{PROGRAM, Scratch, admin_uid, bytes, set_mode, write_config_toml};

    fn relay(args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_usgp-relay"))
            .args(args)
            .output()
            .expect("spawn usgp-relay")
    }

    fn text(b: &[u8]) -> String {
        String::from_utf8_lossy(b).into_owned()
    }

    #[test]
    fn self_check_in_fips_mode_exits_zero() {
        let out = relay(&["--self-check"]);
        let stderr = text(&out.stderr);
        assert_eq!(out.status.code(), Some(0), "stderr: {stderr}");
        assert!(stderr.is_empty(), "unexpected stderr output: {stderr}");
        assert!(out.stdout.is_empty());
    }

    #[test]
    fn no_arguments_prints_usage_and_exits_2() {
        let out = relay(&[]);
        let stderr = text(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "stderr: {stderr}");
        assert!(stderr.contains("usage: usgp-relay"), "{stderr}");
        assert!(!stderr.contains("refusing to start"), "{stderr}");
        assert!(out.stdout.is_empty());
    }

    #[test]
    fn help_prints_usage_on_stdout() {
        let out = relay(&["--help"]);
        assert_eq!(out.status.code(), Some(0));
        assert!(text(&out.stdout).contains("usage: usgp-relay"));
    }

    #[test]
    fn unknown_argument_exits_2() {
        for args in [&["--bogus"][..], &["--config"], &["--self-check", "x"]] {
            let out = relay(args);
            assert_eq!(out.status.code(), Some(2), "{args:?}");
            assert!(text(&out.stderr).contains("usage:"), "{args:?}");
        }
    }

    #[test]
    fn check_config_missing_file_exits_78() {
        let out = relay(&["--check-config", "/nonexistent/usgp-relay/relay.toml"]);
        assert_eq!(out.status.code(), Some(78), "stderr: {}", text(&out.stderr));
    }

    #[test]
    fn run_with_missing_config_exits_78_and_audits() {
        let out = relay(&["--config", "/nonexistent/usgp-relay/relay.toml"]);
        assert_eq!(out.status.code(), Some(78), "stderr: {}", text(&out.stderr));
        let stdout = text(&out.stdout);
        let line = stdout
            .lines()
            .find(|l| l.contains("relay.config.rejected"))
            .unwrap_or_else(|| panic!("no relay.config.rejected event in {stdout}"));
        assert!(line.starts_with('{') && line.ends_with('}'), "{line}");
        assert!(line.contains("\"outcome\":\"refused\""), "{line}");
        assert!(line.contains("\"component\":\"usgp-relay\""), "{line}");
    }

    /// Runs `args PATH --admin-uid <test uid>`. The test's uid is also
    /// the relay's uid, so `--config` additionally passes
    /// `--allow-shared-admin-uid` (SEC-009).
    fn relay_path(args: &[&str], path: &std::path::Path) -> Output {
        let mut all: Vec<&str> = args.to_vec();
        let p = path.to_str().unwrap();
        all.push(p);
        let uid = admin_uid().to_string();
        all.push("--admin-uid");
        all.push(&uid);
        if args.contains(&"--config") {
            all.push("--allow-shared-admin-uid");
        }
        relay(&all)
    }

    /// SEC-009: with `--config`, an effective uid equal to a non-zero
    /// `--admin-uid` refuses start-up (78) and is audited, unless
    /// `--allow-shared-admin-uid` is given; the flag is then recorded in
    /// `relay.start`. NIST-014: the refusal carries a node name where one
    /// is available (Linux host name; `log.node_name` here).
    #[test]
    fn run_as_admin_uid_refused_unless_allowed() {
        if admin_uid() == 0 {
            return;
        }
        let s = Scratch::new("run-shared-uid");
        s.publish(&[(PROGRAM, &bytes(10, 1))]);
        let p = write_config_toml(&s, "[log]\nnode_name = \"relay-test\"\n");
        let uid = admin_uid().to_string();
        let out = relay(&["--config", p.to_str().unwrap(), "--admin-uid", &uid]);
        assert_eq!(out.status.code(), Some(78), "{}", text(&out.stderr));
        assert!(
            text(&out.stderr).contains("--allow-shared-admin-uid"),
            "{}",
            text(&out.stderr)
        );
        let stdout = text(&out.stdout);
        let line = stdout
            .lines()
            .find(|l| l.contains("relay.config.rejected"))
            .unwrap_or_else(|| panic!("no relay.config.rejected in {stdout}"));
        assert!(line.contains("\"outcome\":\"refused\""), "{line}");
        assert!(line.contains("--admin-uid"), "{line}");
        assert!(line.contains("service_uid_is_admin_uid"), "{line}");
        assert!(line.contains("relay-test"), "{line}");
        assert!(!stdout.contains("relay.start"), "{stdout}");

        // --check-config is not affected and does not take the flag.
        let out = relay(&["--check-config", p.to_str().unwrap(), "--admin-uid", &uid]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        let out = relay(&[
            "--check-config",
            p.to_str().unwrap(),
            "--admin-uid",
            &uid,
            "--allow-shared-admin-uid",
        ]);
        assert_eq!(out.status.code(), Some(2));

        // With the flag the relay goes on; relay.start records it.
        let out = relay(&[
            "--config",
            p.to_str().unwrap(),
            "--allow-shared-admin-uid",
            "--admin-uid",
            &uid,
        ]);
        let stdout = text(&out.stdout);
        assert!(!stdout.contains("relay.config.rejected"), "{stdout}");
        let start = stdout
            .lines()
            .find(|l| l.contains("relay.start"))
            .unwrap_or_else(|| panic!("no relay.start in {stdout}"));
        assert!(start.contains("allow_shared_admin_uid"), "{start}");
        assert!(start.contains("true"), "{start}");
    }

    /// NIST-014: a configuration refused at load is audited with the host
    /// name as node name where the host name is available (Linux).
    #[cfg(target_os = "linux")]
    #[test]
    fn config_rejected_carries_host_node_name() {
        let out = relay(&["--config", "/nonexistent/usgp-relay/relay.toml"]);
        assert_eq!(out.status.code(), Some(78));
        let stdout = text(&out.stdout);
        let line = stdout
            .lines()
            .find(|l| l.contains("relay.config.rejected"))
            .unwrap_or_else(|| panic!("no relay.config.rejected in {stdout}"));
        assert!(line.contains("node_name"), "{line}");
    }

    /// NIST-002: without `--admin-uid`, files owned by an ordinary user
    /// are not trusted (only root is).
    #[test]
    fn check_config_without_admin_uid_refuses_user_owned_files() {
        if admin_uid() == 0 {
            return;
        }
        let s = Scratch::new("cc-noadmin");
        s.publish(&[(PROGRAM, &bytes(10, 1))]);
        let p = write_config_toml(&s, "");
        let out = relay(&["--check-config", p.to_str().unwrap()]);
        assert_eq!(out.status.code(), Some(78), "{}", text(&out.stderr));
        assert!(
            text(&out.stderr).contains("not trusted"),
            "{}",
            text(&out.stderr)
        );
        // NIST-003: the refusal is audited by --check-config too.
        assert!(text(&out.stdout).contains("relay.config.rejected"));
    }

    /// NIST-002: a group-writable manifest refuses start-up.
    #[test]
    fn check_config_refuses_group_writable_manifest() {
        let s = Scratch::new("cc-gw");
        s.publish(&[(PROGRAM, &bytes(10, 1))]);
        let p = write_config_toml(&s, "");
        set_mode(&s.manifest_path(), 0o664);
        let out = relay_path(&["--check-config"], &p);
        assert_eq!(out.status.code(), Some(78), "{}", text(&out.stderr));
        assert!(text(&out.stderr).contains("group-writable"));
    }

    #[test]
    fn check_config_running_exits_0() {
        let s = Scratch::new("cc-ok");
        s.publish(&[(PROGRAM, &bytes(3000, 1))]);
        let p = write_config_toml(&s, "");
        let out = relay_path(&["--check-config"], &p);
        let stdout = text(&out.stdout);
        assert_eq!(out.status.code(), Some(0), "{stdout} {}", text(&out.stderr));
        assert!(stdout.contains("state: running"), "{stdout}");
        assert!(
            stdout.contains(&format!("file {PROGRAM}: verified")),
            "{stdout}"
        );
        // NIST-003: --check-config writes its audit events too.
        assert!(stdout.contains("boot.file.verified"), "{stdout}");
    }

    #[test]
    fn check_config_missing_content_exits_3() {
        let s = Scratch::new("cc-tamper");
        let data = bytes(3000, 1);
        s.publish(&[(PROGRAM, &data)]);
        let p = write_config_toml(&s, "");
        let mut bad = data.clone();
        bad[1500] ^= 1;
        s.write_boot_file(PROGRAM, &bad);
        let out = relay_path(&["--check-config"], &p);
        let stdout = text(&out.stdout);
        assert_eq!(out.status.code(), Some(3), "{stdout} {}", text(&out.stderr));
        assert!(
            stdout.contains("state: running_missing_content"),
            "{stdout}"
        );
        assert!(stdout.contains("integrity_failed"), "{stdout}");
        assert!(stdout.contains("boot.file.integrity_failed"), "{stdout}");

        std::fs::remove_file(s.root().join(PROGRAM)).unwrap();
        let out = relay_path(&["--check-config"], &p);
        assert_eq!(out.status.code(), Some(3));
        assert!(text(&out.stdout).contains(&format!("file {PROGRAM}: missing")));
    }

    #[test]
    fn check_config_invalid_exits_78() {
        let s = Scratch::new("cc-invalid");
        s.publish(&[(PROGRAM, &bytes(10, 1))]);
        for extra in [
            "[limits]\nno_such_key = 1\n",
            "[tftp]\nmax_block_size = 7\n",
            "[suppression]\nfile = \"/nonexistent/usgp-relay/suppress.toml\"\n",
        ] {
            let p = write_config_toml(&s, extra);
            let out = relay_path(&["--check-config"], &p);
            assert_eq!(
                out.status.code(),
                Some(78),
                "{extra}: {}",
                text(&out.stderr)
            );
        }
        // World-writable configuration file.
        let p = write_config_toml(&s, "");
        set_mode(&p, 0o666);
        assert_eq!(relay_path(&["--check-config"], &p).status.code(), Some(78));
    }

    #[test]
    fn check_config_reports_suppression_entries() {
        let s = Scratch::new("cc-supp");
        s.publish(&[(PROGRAM, &bytes(10, 1))]);
        let supp = s.dir.join("suppress.toml");
        std::fs::write(
            &supp,
            "schema_version = 1\n[[device]]\nmac = \"52:54:00:12:34:56\"\n",
        )
        .unwrap();
        set_mode(&supp, 0o644);
        let p = write_config_toml(
            &s,
            &format!("[suppression]\nfile = \"{}\"\n", supp.display()),
        );
        let out = relay_path(&["--check-config"], &p);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        assert!(text(&out.stdout).contains("suppression entries: 1"));
    }

    #[test]
    fn run_with_invalid_config_audits_field() {
        let s = Scratch::new("run-invalid");
        s.publish(&[(PROGRAM, &bytes(10, 1))]);
        let p = write_config_toml(&s, "[tftp]\nmax_retries = 0\n");
        let out = relay_path(&["--config"], &p);
        assert_eq!(out.status.code(), Some(78));
        let stdout = text(&out.stdout);
        let line = stdout
            .lines()
            .find(|l| l.contains("relay.config.rejected"))
            .unwrap_or_else(|| panic!("no event in {stdout}"));
        assert!(line.contains("tftp.max_retries"), "{line}");
    }

    /// Off Linux the relay validates everything, then refuses to bind
    /// (exit 1), after recording the content check as events.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn run_off_linux_refuses_at_bind() {
        let s = Scratch::new("run-darwin");
        s.publish(&[(PROGRAM, &bytes(10, 1))]);
        let p = write_config_toml(&s, "");
        let out = relay_path(&["--config"], &p);
        assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
        assert!(text(&out.stderr).contains("only supported on Linux"));
        let stdout = text(&out.stdout);
        for event in [
            "boot.manifest.loaded",
            "boot.file.verified",
            "relay.state.changed",
        ] {
            assert!(stdout.contains(event), "{event} missing in {stdout}");
        }
        // NIST-003: the failed start is audited.
        let start = stdout
            .lines()
            .find(|l| l.contains("relay.start"))
            .unwrap_or_else(|| panic!("no relay.start in {stdout}"));
        assert!(start.contains("\"outcome\":\"failure\""), "{start}");
        assert!(start.contains("reason"), "{start}");
    }
}
