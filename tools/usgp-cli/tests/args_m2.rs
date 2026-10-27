//! Process-level tests for the M2 command line (plan WU-8): exit codes,
//! usage, and the fail-closed setup checks that run before any network
//! access (settings missing, untrusted or private-key permission rules,
//! content key required for verification).
//!
//! `delete_prompts_unless_yes` runs the binary against the stub server
//! over real mutual TLS (`tests/common`); the other API exchanges are in
//! `tests/download_verify.rs` and the unit tests in `src/cmd_*.rs`.

#[cfg(test)]
mod common;

#[cfg(test)]
mod tls {
    use usgp_proto::api::{PackageImageView, PackagePeView, PackageView, SupportView};
    use usgp_proto::facts::{Architecture, Fact, KitVersion, SupportState};
    use usgp_proto::ids::{ContentId, OperatorId, PackageId, UnixMicros};
    use usgp_proto::names::{DisplayName, EditionIndex, WimText};
    use usgp_proto::status::PackageStatus;

    use crate::common::{Env, route, stderr, stdout};

    const PKG: &str = "1c9e8a70-2b3d-4e5f-9a0b-c1d2e3f40516";

    fn package() -> Vec<u8> {
        let v = PackageView {
            id: PackageId::parse(PKG).unwrap(),
            name: DisplayName::new("Field laptops").unwrap(),
            description: None,
            revision: 3,
            status: PackageStatus::NotUsable,
            status_reason: None,
            image: PackageImageView {
                image_id: ContentId::parse("0b7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e6f").unwrap(),
                display_name: DisplayName::new("Win 11").unwrap(),
                edition_index: EditionIndex::new(1).unwrap(),
                edition_name: WimText::new("E").unwrap(),
                facts: None,
                support: SupportView {
                    status: SupportState::Unknown,
                    reason: None,
                },
            },
            pe: PackagePeView {
                pe_id: ContentId::parse("3a7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e70").unwrap(),
                display_name: DisplayName::new("PE").unwrap(),
                architecture: Fact::declared(Architecture::X64),
                kit_version: Fact::declared(KitVersion::parse("10.1.26100.1").unwrap()),
                kit_warning: None,
            },
            created_by: OperatorId::parse("2c9e8a70-2b3d-4e5f-9a0b-c1d2e3f40516").unwrap(),
            created_at: UnixMicros::new(0).unwrap(),
            updated_at: UnixMicros::new(0).unwrap(),
        };
        serde_json::to_vec(&v).unwrap()
    }

    fn env() -> Env {
        let path = format!("/v1/packages/{PKG}");
        Env::new(
            vec![
                route("GET", &path, 200, package()).with_header("etag", "\"r3\""),
                route("DELETE", &path, 204, Vec::new()),
            ],
            None,
        )
    }

    /// REQ-IMG-014: the CLI warns and asks; only `yes` deletes; `--yes`
    /// skips the prompt. The DELETE carries `If-Match` with the revision
    /// read.
    #[test]
    fn delete_prompts_unless_yes() {
        // Declined.
        let e = env();
        let o = e.run(&["package", "delete", PKG], b"no\n");
        assert_eq!(o.status.code(), Some(1));
        let err = stderr(&o);
        assert!(err.contains("permanently deletes package"), "{err}");
        assert!(err.contains("Field laptops"), "{err}");
        assert!(err.contains("not confirmed"), "{err}");
        let seen = e.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen.first().unwrap().method, "GET");

        // No answer at all (end of input) is a refusal.
        let e = env();
        let o = e.run(&["package", "delete", PKG], b"");
        assert_eq!(o.status.code(), Some(1));
        assert_eq!(e.seen().len(), 1);

        // Confirmed.
        let e = env();
        let o = e.run(&["package", "delete", PKG], b"yes\n");
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        assert!(stdout(&o).contains(&format!("deleted package {PKG}")));
        let seen = e.seen();
        let del = seen.get(1).unwrap();
        assert_eq!(del.method, "DELETE");
        assert_eq!(del.path, format!("/v1/packages/{PKG}"));
        assert!(del.body.is_empty());
        assert_eq!(del.header("if-match"), Some("\"r3\""));
        assert_eq!(
            del.client_cert_sha256.as_deref(),
            Some(e.operator_sha256().as_str())
        );

        // --yes: no prompt.
        let e = env();
        let o = e.run(&["package", "delete", PKG, "--yes"], b"");
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        assert!(!stderr(&o).contains("Type 'yes'"));
        assert_eq!(e.seen().len(), 2);
    }
}

#[cfg(test)]
mod cli {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};
    use std::sync::atomic::{AtomicU32, Ordering};

    const ID: &str = "0b7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e6f";

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!("usgp-cli-m2-{}-{n}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
            Self(p)
        }

        fn put(&self, name: &str, bytes: &[u8], mode: u32) -> PathBuf {
            let p = self.0.join(name);
            fs::write(&p, bytes).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
            p
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Runs the CLI with `HOME` pointing at `home` (no default config).
    fn cli(home: &Path, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_usgp-cli"))
            .args(args)
            .env("HOME", home)
            .output()
            .expect("spawn usgp-cli")
    }

    fn stderr(o: &Output) -> String {
        String::from_utf8_lossy(&o.stderr).into_owned()
    }

    fn s(p: &Path) -> &str {
        p.to_str().unwrap()
    }

    #[test]
    fn usage_errors_exit_2_with_usage() {
        let t = TempDir::new();
        for args in [
            &["image"][..],
            &["image", "frob"],
            &["image", "view"],
            &["image", "declare", ID, "--index", "one"],
            &["pe", "import", "f.wim", "--name", "PE"],
            &["package", "create", "--name", "x"],
            &["package", "list", "--unknown"],
        ] {
            let o = cli(&t.0, args);
            assert_eq!(o.status.code(), Some(2), "{args:?}: {}", stderr(&o));
            assert!(stderr(&o).contains("usage: usgp-cli"), "{args:?}");
            assert!(o.stdout.is_empty(), "{args:?}");
        }
    }

    #[test]
    fn help_lists_m2_commands() {
        let t = TempDir::new();
        let o = cli(&t.0, &["package", "--help"]);
        assert_eq!(o.status.code(), Some(0));
        let out = String::from_utf8(o.stdout).unwrap();
        for want in [
            "image upload FILE --name NAME",
            "image declare ID --index N --release R --edition E --arch A",
            "pe import FILE --name NAME --arch A --kit-version V",
            "package manifest ID --out FILE",
            "--client-key FILE",
        ] {
            assert!(out.contains(want), "missing {want:?} in {out}");
        }
    }

    #[test]
    fn missing_settings_fail_before_any_connection() {
        let t = TempDir::new();
        let o = cli(&t.0, &["image", "list"]);
        assert_eq!(o.status.code(), Some(1));
        assert!(
            stderr(&o).contains("server (--server) is not set"),
            "{}",
            stderr(&o)
        );
    }

    #[test]
    fn plain_http_server_refused() {
        let t = TempDir::new();
        let o = cli(
            &t.0,
            &[
                "limits",
                "--server",
                "http://ctl:8080",
                "--server-ca",
                "/ca",
                "--client-cert",
                "/c",
                "--client-key",
                "/k",
            ],
        );
        assert_eq!(o.status.code(), Some(1));
        assert!(
            stderr(&o).contains("must start with https://"),
            "{}",
            stderr(&o)
        );
    }

    #[test]
    fn untrusted_config_file_refused() {
        let t = TempDir::new();
        let cfg = t.put("cli.toml", b"server = \"https://ctl:8443\"\n", 0o666);
        let o = cli(&t.0, &["limits", "--config", s(&cfg)]);
        assert_eq!(o.status.code(), Some(1));
        assert!(stderr(&o).contains("not trusted"), "{}", stderr(&o));
    }

    #[test]
    fn group_readable_client_key_refused() {
        let t = TempDir::new();
        let ca = t.put("ca.pem", b"not a certificate\n", 0o644);
        let cert = t.put("op.pem", b"not a certificate\n", 0o644);
        let key = t.put("op.key", b"-----BEGIN PRIVATE KEY-----\n", 0o640);
        let o = cli(
            &t.0,
            &[
                "limits",
                "--server",
                "https://ctl:8443",
                "--server-ca",
                s(&ca),
                "--client-cert",
                s(&cert),
                "--client-key",
                s(&key),
            ],
        );
        assert_eq!(o.status.code(), Some(1));
        let e = stderr(&o);
        assert!(e.contains("group or others"), "{e}");
        assert!(!e.contains("BEGIN PRIVATE KEY"), "key content echoed: {e}");
    }

    #[test]
    fn download_requires_pinned_content_key() {
        let t = TempDir::new();
        let out = t.0.join("x.wim");
        let o = cli(
            &t.0,
            &[
                "image",
                "download",
                ID,
                "--out",
                s(&out),
                "--server",
                "https://ctl:8443",
                "--server-ca",
                "/ca",
                "--client-cert",
                "/c",
                "--client-key",
                "/k",
            ],
        );
        assert_eq!(o.status.code(), Some(1));
        assert!(
            stderr(&o).contains("content public key (--content-key-pub) is not set"),
            "{}",
            stderr(&o)
        );
        assert!(!out.exists());
    }
}
