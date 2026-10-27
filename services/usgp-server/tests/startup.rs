//! Process contract of the `usgp-server` binary (plan M2 WU-7; exit codes
//! as for the relay).
//!
//! Runs the built artifact as a child process. Every invocation runs the
//! fail-closed FIPS check first (docs/decisions/0001, NIST 800-53 SC-13):
//! a non-FIPS build prints "refusing to start" and exits 1, failing these
//! tests.
//!
//! | Invocation | Expected |
//! |------------|----------|
//! | `--self-check` | exit 0, no output |
//! | no arguments, unknown argument | usage on stderr, exit 2 |
//! | `--help` | usage on stdout, exit 0 |
//! | `--check-config` valid | exit 0, `configuration: valid` |
//! | `--check-config` with a password key, missing file, untrusted file | exit 78 |
//! | `serve` with the database unreachable | exit 1, `server.start.refused` mirrored |
//! | `serve` as the `--admin-uid` without `--allow-shared-admin-uid` | exit 78 |
//! | `serve` able to read the `[database.admin]` key | exit 78 (SEC-011) |
//! | `keygen` | 0600 private key, SPKI public key; never overwrites (exit 1) |
//! | `audit verify` with the database unreachable | exit 69 |
//! | `migrate` / `operator enrol` with the database unreachable | exit 78 or 1 |
//!
//! The tests run as an ordinary user, so every invocation with a
//! configuration names the test's uid with `--admin-uid`.

#[cfg(test)]
pub mod common;

#[cfg(test)]
mod startup {
    use std::process::{Command, Output};

    use crate::common::{Fixture, Scratch, admin_uid};

    fn server(args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_usgp-server"))
            .args(args)
            .output()
            .expect("spawn usgp-server")
    }

    fn text(b: &[u8]) -> String {
        String::from_utf8_lossy(b).into_owned()
    }

    #[test]
    fn self_check_exits_zero_silently() {
        let out = server(&["--self-check"]);
        assert!(
            out.status.success(),
            "exit {:?}: {}",
            out.status.code(),
            text(&out.stderr)
        );
        assert!(out.stdout.is_empty());
        assert!(out.stderr.is_empty(), "{}", text(&out.stderr));
    }

    #[test]
    fn usage_contract() {
        let out = server(&[]);
        assert_eq!(out.status.code(), Some(2));
        assert!(text(&out.stderr).contains("usage: usgp-server serve"));
        let out = server(&["--help"]);
        assert_eq!(out.status.code(), Some(0));
        assert!(text(&out.stdout).contains("audit verify"));
        for bad in [
            &["--bogus"][..],
            &["serve"],
            &["serve", "--config"],
            &["audit", "verify", "--config", "x"],
            &[
                "keygen",
                "--purpose",
                "tls",
                "--out-key",
                "a",
                "--out-pub",
                "b",
            ],
        ] {
            let out = server(bad);
            assert_eq!(out.status.code(), Some(2), "{bad:?}");
        }
    }

    fn uid() -> String {
        admin_uid().to_string()
    }

    #[test]
    fn check_config_valid_and_invalid() {
        let f = Fixture::new("check");
        let p = f.write_config(&f.config_text(&f.unreachable_db()));
        let path = p.to_str().unwrap();
        let out = server(&["--check-config", path, "--admin-uid", &uid()]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        let stdout = text(&out.stdout);
        assert!(stdout.contains("configuration: valid"), "{stdout}");
        assert!(stdout.contains(&f.audit_pub.key_id().to_hex()), "{stdout}");
        assert!(stdout.contains("(certificate login)"), "{stdout}");
        // Nothing secret is printed.
        assert!(!stdout.contains("PRIVATE KEY"));

        // Without --admin-uid the user's files are not trusted.
        if admin_uid() != 0 {
            let out = server(&["--check-config", path]);
            assert_eq!(out.status.code(), Some(78), "{}", text(&out.stderr));
        }
        // A password key in [database] (decision 0012).
        let pw = f
            .config_text(&f.unreachable_db())
            .replace("pool_size = 2", "pool_size = 2\npassword = \"hunter2\"");
        let p = f.write_config(&pw);
        let out = server(&["--check-config", p.to_str().unwrap(), "--admin-uid", &uid()]);
        assert_eq!(out.status.code(), Some(78));
        assert!(
            text(&out.stderr).contains("password"),
            "{}",
            text(&out.stderr)
        );
        assert!(!text(&out.stderr).contains("hunter2"));
        // Missing file.
        let out = server(&["--check-config", "/nonexistent/server.toml"]);
        assert_eq!(out.status.code(), Some(78));
    }

    #[test]
    fn serve_refuses_without_database() {
        let f = Fixture::new("serve-nodb");
        let p = f.write_config(&f.config_text(&f.unreachable_db()));
        // SEC-011: the service must not be able to read the admin key.
        let admin_key = f.scratch.path("db-admin.key");
        set_mode(&admin_key, 0o000);
        let out = server(&[
            "serve",
            "--config",
            p.to_str().unwrap(),
            "--admin-uid",
            &uid(),
            "--allow-shared-admin-uid",
        ]);
        set_mode(&admin_key, 0o600);
        if usgp_common::process::effective_uid().ok() == Some(0) {
            // Root can open any file: the admin-key rule refuses first.
            assert_eq!(out.status.code(), Some(78), "{}", text(&out.stderr));
            return;
        }
        assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
        let stdout = text(&out.stdout);
        let line = stdout
            .lines()
            .find(|l| l.contains("server.start.refused"))
            .unwrap_or_else(|| panic!("no refusal record: {stdout}"));
        assert!(line.contains("database_unavailable"), "{line}");
        assert!(line.contains(r#"\"persisted\":\"false\""#), "{line}");
        assert!(line.contains("test-node"), "{line}");
    }

    #[test]
    fn serve_as_admin_uid_refused_unless_allowed() {
        if admin_uid() == 0 {
            return; // root is outside the rule (as for the relay)
        }
        let f = Fixture::new("serve-shared");
        let p = f.write_config(&f.config_text(&f.unreachable_db()));
        let out = server(&[
            "serve",
            "--config",
            p.to_str().unwrap(),
            "--admin-uid",
            &uid(),
        ]);
        assert_eq!(out.status.code(), Some(78), "{}", text(&out.stderr));
        assert!(text(&out.stderr).contains("--allow-shared-admin-uid"));
        assert!(text(&out.stdout).contains("service_uid_is_admin_uid"));
    }

    fn set_mode(p: &std::path::Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// SEC-011 (decision 0016 item 3): `serve` refuses to start (78) if it
    /// can read the `[database.admin]` client key, and mirrors the
    /// refusal; admin commands refuse a group-readable admin key even
    /// though the service-key rule would accept 0640.
    #[test]
    fn serve_refuses_a_readable_admin_key() {
        let f = Fixture::new("serve-admin-key");
        let p = f.write_config(&f.config_text(&f.unreachable_db()));
        let out = server(&[
            "serve",
            "--config",
            p.to_str().unwrap(),
            "--admin-uid",
            &uid(),
            "--allow-shared-admin-uid",
        ]);
        assert_eq!(out.status.code(), Some(78), "{}", text(&out.stderr));
        assert!(
            text(&out.stderr).contains("database.admin"),
            "{}",
            text(&out.stderr)
        );
        let stdout = text(&out.stdout);
        let line = stdout
            .lines()
            .find(|l| l.contains("server.start.refused"))
            .unwrap_or_else(|| panic!("no refusal record: {stdout}"));
        assert!(line.contains("admin_key_readable_by_service"), "{line}");
        assert!(line.contains("database.admin.client_key"), "{line}");

        // A group-readable admin key: refused by an admin command (78)
        // before any database connection.
        let admin_key = f.scratch.path("db-admin.key");
        set_mode(&admin_key, 0o640);
        let out = server(&[
            "audit",
            "verify",
            "--config",
            p.to_str().unwrap(),
            "--trusted-key",
            f.scratch.path("audit.pub").to_str().unwrap(),
            "--admin-uid",
            &uid(),
        ]);
        assert_eq!(out.status.code(), Some(78), "{}", text(&out.stderr));
        assert!(
            text(&out.stderr).contains("administrative database key"),
            "{}",
            text(&out.stderr)
        );
        // The application key may still be 0640 with the service group;
        // the admin key at 0600 passes this rule (and the command then
        // fails at the unreachable database, 69).
        set_mode(&admin_key, 0o600);
        let out = server(&[
            "audit",
            "verify",
            "--config",
            p.to_str().unwrap(),
            "--trusted-key",
            f.scratch.path("audit.pub").to_str().unwrap(),
            "--admin-uid",
            &uid(),
        ]);
        assert_eq!(out.status.code(), Some(69), "{}", text(&out.stderr));
    }

    #[test]
    fn keygen_writes_new_files_only() {
        use std::os::unix::fs::PermissionsExt;
        let s = Scratch::new("keygen");
        let k = s.path("content.p8");
        let pubk = s.path("content.pub");
        let args = [
            "keygen",
            "--purpose",
            "content",
            "--out-key",
            k.to_str().unwrap(),
            "--out-pub",
            pubk.to_str().unwrap(),
        ];
        let out = server(&args);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        let mode = std::fs::metadata(&k).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let key_text = std::fs::read_to_string(&k).unwrap();
        assert!(key_text.starts_with("-----BEGIN PRIVATE KEY-----"));
        // The private key never appears on stdout or stderr.
        assert!(!text(&out.stdout).contains("PRIVATE KEY"));
        let public =
            usgp_crypto::VerifyingKey::from_spki_pem(&std::fs::read(&pubk).unwrap()).unwrap();
        assert!(
            text(&out.stdout).contains(&public.key_id().to_hex()),
            "{}",
            text(&out.stdout)
        );
        // Never overwrites; the failure is mirrored (NIST-016).
        let out = server(&args);
        assert_eq!(out.status.code(), Some(1));
        assert_eq!(std::fs::read_to_string(&k).unwrap(), key_text);
        let stdout = text(&out.stdout);
        let line = stdout
            .lines()
            .find(|l| l.contains("key.generation.failed"))
            .unwrap_or_else(|| panic!("no failure record: {stdout}"));
        assert!(line.contains("write_failed"), "{line}");
        assert!(!line.contains("PRIVATE KEY"), "{line}");
        // An existing public-key file: the private key is not left behind.
        let k2 = s.path("audit.p8");
        let out = server(&[
            "keygen",
            "--purpose",
            "audit",
            "--out-key",
            k2.to_str().unwrap(),
            "--out-pub",
            pubk.to_str().unwrap(),
        ]);
        assert_eq!(out.status.code(), Some(1));
        assert!(!k2.exists());
        // A symbolic link at the output path is not followed.
        let target = s.path("target");
        std::os::unix::fs::symlink(&target, s.path("link.p8")).unwrap();
        let out = server(&[
            "keygen",
            "--purpose",
            "audit",
            "--out-key",
            s.path("link.p8").to_str().unwrap(),
            "--out-pub",
            s.path("x.pub").to_str().unwrap(),
        ]);
        assert_eq!(out.status.code(), Some(1));
        assert!(!target.exists());
    }

    #[test]
    fn local_commands_without_database() {
        let f = Fixture::new("local-nodb");
        let audit_pub = f.scratch.path("audit.pub");
        // Decision 0016: without `[database.admin]` local commands refuse
        // to run (exit 78) instead of using the application role.
        let mut no_admin = f.unreachable_db();
        no_admin.admin = None;
        let p = f.write_config(&f.config_text(&no_admin));
        let out = server(&[
            "audit",
            "verify",
            "--config",
            p.to_str().unwrap(),
            "--trusted-key",
            audit_pub.to_str().unwrap(),
            "--admin-uid",
            &uid(),
        ]);
        assert_eq!(out.status.code(), Some(78), "{}", text(&out.stderr));
        assert!(text(&out.stderr).contains("database.admin"));
        // A bad --max-unsigned-records value is a usage error.
        let p = f.write_config(&f.config_text(&f.unreachable_db()));
        let cfg = p.to_str().unwrap();
        let out = server(&[
            "audit",
            "verify",
            "--config",
            cfg,
            "--trusted-key",
            audit_pub.to_str().unwrap(),
            "--max-unsigned-records",
            "0",
            "--admin-uid",
            &uid(),
        ]);
        assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
        let out = server(&[
            "audit",
            "verify",
            "--config",
            cfg,
            "--trusted-key",
            audit_pub.to_str().unwrap(),
            "--admin-uid",
            &uid(),
        ]);
        assert_eq!(out.status.code(), Some(69), "{}", text(&out.stderr));

        let cert = f.scratch.path("operator.pem");
        let out = server(&[
            "operator",
            "enrol",
            "--config",
            cfg,
            "--cert",
            cert.to_str().unwrap(),
            "--name",
            "Operator One",
            "--role",
            "administrator",
            "--admin-uid",
            &uid(),
        ]);
        assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
        let out = server(&[
            "operator",
            "disable",
            "--config",
            cfg,
            "--id",
            "not-a-uuid",
            "--admin-uid",
            &uid(),
        ]);
        assert_eq!(out.status.code(), Some(2));

        let owner_cert = f.scratch.path("db-client.pem");
        let owner_key = f.scratch.path("db-client.key");
        let out = server(&[
            "migrate",
            "--config",
            cfg,
            "--owner-user",
            "usgp_owner",
            "--owner-cert",
            owner_cert.to_str().unwrap(),
            "--owner-key",
            owner_key.to_str().unwrap(),
            "--admin-uid",
            &uid(),
        ]);
        assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
        // The failed migration is mirrored as an unpersisted record.
        assert!(text(&out.stdout).contains("server.migrate"));
    }
}
