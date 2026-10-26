//! Process-level tests for `usgp-cli boot-manifest create | verify`
//! (plan WU-7, section 3.6 exit codes, section 7 audit events).
//!
//! Every test works in its own directory under the system temp dir.

// Helpers live in a `cfg(test)` module so the workspace clippy test
// allowances (clippy.toml) cover their unwraps.
#[cfg(test)]
mod cli {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};
    use std::sync::atomic::{AtomicU32, Ordering};

    const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!("usgp-cli-it-{}-{n}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(p.join("root")).unwrap();
            Self(p)
        }
        fn root(&self) -> PathBuf {
            self.0.join("root")
        }
        fn manifest(&self) -> PathBuf {
            self.0.join("boot-manifest.toml")
        }
        fn put(&self, name: &str, bytes: &[u8]) {
            let p = self.root().join(name);
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(p, bytes).unwrap();
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn cli(args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_usgp-cli"))
            .args(args)
            .env("USER", "it-operator")
            .output()
            .expect("spawn usgp-cli")
    }

    fn s(p: &Path) -> &str {
        p.to_str().unwrap()
    }

    fn create(t: &TempDir, names: &[&str]) -> Output {
        let (root, out) = (t.root(), t.manifest());
        let mut a = vec![
            "boot-manifest",
            "create",
            "--root",
            s(&root),
            "--out",
            s(&out),
        ];
        a.extend_from_slice(names);
        cli(&a)
    }

    fn verify(t: &TempDir) -> Output {
        cli(&[
            "boot-manifest",
            "verify",
            "--root",
            s(&t.root()),
            "--manifest",
            s(&t.manifest()),
        ])
    }

    /// The single audit line on stdout.
    fn audit_line(out: &Output) -> String {
        let stdout = String::from_utf8(out.stdout.clone()).unwrap();
        let lines: Vec<&str> = stdout
            .lines()
            .filter(|l| l.contains(r#""target":"audit""#))
            .collect();
        assert_eq!(lines.len(), 1, "stdout: {stdout}");
        lines.first().unwrap().to_string()
    }

    fn code(out: &Output) -> Option<i32> {
        out.status.code()
    }

    #[test]
    fn create_verify_round_trip() {
        let t = TempDir::new();
        t.put("usgp-test-payload.efi", b"abc");
        t.put("x64/second.bin", b"0123");
        let out = create(&t, &["usgp-test-payload.efi", "x64/second.bin"]);
        assert_eq!(code(&out), Some(0), "{out:?}");
        let text = fs::read_to_string(t.manifest()).unwrap();
        assert!(text.starts_with("schema_version = 1\nalgorithm = \"sha256\"\n"));
        assert!(text.contains("name = \"usgp-test-payload.efi\"\nsize = 3\n"));
        assert!(text.contains(ABC_SHA256));

        let line = audit_line(&out);
        assert!(
            line.contains(r#""event":"boot_manifest.created""#),
            "{line}"
        );
        assert!(line.contains(r#""outcome":"success""#), "{line}");
        assert!(line.contains(r#""component":"usgp-cli""#), "{line}");
        assert!(line.contains("env_user_claimed"), "{line}");
        assert!(line.contains("effective_uid"), "{line}");
        assert!(line.contains("it-operator"), "{line}");
        assert!(line.contains("manifest_sha256"), "{line}");
        assert!(line.contains("timestamp"), "{line}");

        let out = verify(&t);
        assert_eq!(code(&out), Some(0), "{out:?}");
        let line = audit_line(&out);
        assert!(line.contains(r#""event":"boot_manifest.verify""#), "{line}");
        assert!(line.contains(r#""outcome":"success""#), "{line}");
    }

    #[test]
    fn verify_detects_one_byte_change() {
        let t = TempDir::new();
        t.put("a.efi", b"abc");
        assert_eq!(code(&create(&t, &["a.efi"])), Some(0));
        t.put("a.efi", b"abd");
        let out = verify(&t);
        assert_eq!(code(&out), Some(1), "{out:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("FAILED a.efi"), "{stderr}");
        assert!(stderr.contains(ABC_SHA256), "{stderr}");
        let line = audit_line(&out);
        assert!(line.contains(r#""outcome":"failure""#), "{line}");
        assert!(line.contains("failed_files"), "{line}");
    }

    #[test]
    fn verify_detects_missing_file() {
        let t = TempDir::new();
        t.put("a.efi", b"abc");
        assert_eq!(code(&create(&t, &["a.efi"])), Some(0));
        fs::remove_file(t.root().join("a.efi")).unwrap();
        assert_eq!(code(&verify(&t)), Some(1));
    }

    #[test]
    fn create_refuses_to_overwrite() {
        let t = TempDir::new();
        t.put("a.efi", b"abc");
        fs::write(t.manifest(), b"operator data").unwrap();
        let out = create(&t, &["a.efi"]);
        assert_eq!(code(&out), Some(1), "{out:?}");
        assert_eq!(fs::read(t.manifest()).unwrap(), b"operator data");
        let line = audit_line(&out);
        assert!(line.contains(r#""outcome":"refused""#), "{line}");
    }

    #[test]
    fn create_refuses_invalid_name_and_writes_nothing() {
        let t = TempDir::new();
        t.put("a.efi", b"abc");
        for bad in ["../a.efi", "/etc/passwd", "a\\b", "%2e%2e"] {
            let out = create(&t, &["a.efi", bad]);
            assert_eq!(code(&out), Some(1), "{bad}: {out:?}");
            assert!(!t.manifest().exists(), "{bad}");
            assert!(audit_line(&out).contains(r#""outcome":"refused""#));
        }
    }

    #[test]
    fn create_refuses_non_regular_file() {
        let t = TempDir::new();
        fs::create_dir_all(t.root().join("dir")).unwrap();
        let out = create(&t, &["dir"]);
        assert_eq!(code(&out), Some(1), "{out:?}");
        assert!(!t.manifest().exists());
    }

    #[cfg(unix)]
    #[test]
    fn create_refuses_symlink() {
        let t = TempDir::new();
        fs::write(t.0.join("outside"), b"x").unwrap();
        std::os::unix::fs::symlink(t.0.join("outside"), t.root().join("a.efi")).unwrap();
        let out = create(&t, &["a.efi"]);
        assert_eq!(code(&out), Some(1), "{out:?}");
        assert!(!t.manifest().exists());
    }

    #[test]
    fn verify_refuses_invalid_manifest() {
        let t = TempDir::new();
        fs::write(t.manifest(), "schema_version = 1\nalgorithm = \"md5\"\n").unwrap();
        let out = verify(&t);
        assert_eq!(code(&out), Some(1), "{out:?}");
        assert!(audit_line(&out).contains(r#""outcome":"refused""#));
    }

    #[test]
    fn usage_errors_exit_2_without_audit() {
        for args in [
            &["boot-manifest"][..],
            &["nope"],
            &["boot-manifest", "create", "--root", "/r"],
            &["boot-manifest", "verify", "--root", "/r"],
        ] {
            let out = cli(args);
            assert_eq!(code(&out), Some(2), "{args:?}");
            assert!(out.stdout.is_empty(), "{args:?}");
            assert!(String::from_utf8_lossy(&out.stderr).contains("usage:"));
        }
    }

    #[test]
    fn help_on_stdout_exit_0() {
        let out = cli(&["--help"]);
        assert_eq!(code(&out), Some(0));
        assert!(String::from_utf8_lossy(&out.stdout).contains("boot-manifest create"));
        assert!(out.stderr.is_empty());
    }
}
