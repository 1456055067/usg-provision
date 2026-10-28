//! Process-level tests for `usgp-cli boot-manifest create --pe-kit` and
//! `verify` of a kit manifest (M3 plan WU-13; REQ-PE-012, REQ-PE-018;
//! `winpe.md` §10; decision 0018 item 3), run against the in-process
//! stub API over real mutual TLS (`tests/common`).
//!
//! Negatives: a boot program for another machine, a missing kit file (the
//! BCD is never generated in its place), a WIM whose digest is not the
//! Ready PE's, and a server that cannot be reached. Each exits 1, writes
//! no manifest, and emits one audit event.

#[cfg(test)]
mod common;

#[cfg(test)]
mod kit {
    use std::fs;
    use std::path::PathBuf;
    use std::process::Output;

    use usgp_proto::api::PeView;
    use usgp_proto::facts::{Architecture, Fact, KitVersion};
    use usgp_proto::ids::{ContentId, OperatorId, UnixMicros};
    use usgp_proto::names::{DisplayName, EditionIndex, FileName};
    use usgp_proto::status::ContentState;

    use crate::common::{Env, Route, route, stderr, stdout};

    const PE: &str = "0b7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e6f";
    const WIM: &[u8] = b"pretend boot.wim bytes for the kit test";

    /// The header fields `winpe.md` §10 names, little-endian; the rest is
    /// zero. Not a runnable program.
    fn pe_image(machine: u16) -> Vec<u8> {
        let mut b = vec![0u8; 0x200];
        b.get_mut(0..2).unwrap().copy_from_slice(b"MZ");
        b.get_mut(0x3C..0x40)
            .unwrap()
            .copy_from_slice(&0x80u32.to_le_bytes());
        b.get_mut(0x80..0x84).unwrap().copy_from_slice(b"PE\0\0");
        b.get_mut(0x84..0x86)
            .unwrap()
            .copy_from_slice(&machine.to_le_bytes());
        b.get_mut(0x94..0x96)
            .unwrap()
            .copy_from_slice(&0xF0u16.to_le_bytes());
        b.get_mut(0x98..0x9A)
            .unwrap()
            .copy_from_slice(&0x20Bu16.to_le_bytes());
        b.get_mut(0x98 + 68..0x98 + 70)
            .unwrap()
            .copy_from_slice(&10u16.to_le_bytes());
        b
    }

    fn pe_view(sha256_of: &[u8]) -> Vec<u8> {
        let v = PeView {
            id: ContentId::parse(PE).unwrap(),
            display_name: DisplayName::new("PE x64").unwrap(),
            file_name: FileName::new("boot.wim").unwrap(),
            size: u64::try_from(WIM.len()).unwrap(),
            sha256: Some(usgp_crypto::sha256(sha256_of)),
            state: ContentState::Ready,
            reason: None,
            imported_by: OperatorId::parse("2c9e8a70-2b3d-4e5f-9a0b-c1d2e3f40516").unwrap(),
            imported_at: UnixMicros::new(0).unwrap(),
            updated_at: UnixMicros::new(0).unwrap(),
            usable_index: Some(EditionIndex::new(1).unwrap()),
            architecture: Fact::declared(Architecture::X64),
            kit_version: Fact::declared(KitVersion::parse("10.1.26100.1").unwrap()),
            kit_warning: None,
            used_by: Vec::new(),
        };
        serde_json::to_vec(&v).unwrap()
    }

    fn pe_route(sha256_of: &[u8]) -> Route {
        route("GET", &format!("/v1/pe/{PE}"), 200, pe_view(sha256_of))
            .with_header("etag", "\"pe-1\"")
    }

    /// `verify` (no connection options).
    fn verify(e: &Env, root: &std::path::Path) -> Output {
        std::process::Command::new(env!("CARGO_BIN_EXE_usgp-cli"))
            .args([
                "boot-manifest",
                "verify",
                "--root",
                root.to_str().unwrap(),
                "--manifest",
                manifest(e).to_str().unwrap(),
            ])
            .output()
            .unwrap()
    }

    /// A kit tree under the environment's directory.
    fn tree(e: &Env, machine: u16) -> PathBuf {
        let root = e.dir.join("tftp");
        let put = |name: &str, bytes: &[u8]| {
            let p = root.join(name);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, bytes).unwrap();
        };
        put("bootmgfw.efi", &pe_image(machine));
        put("Boot/BCD", b"operator-built store");
        put("Boot/boot.sdi", b"sdi");
        put("Boot/boot.wim", WIM);
        put("Boot/Fonts/wgl4_boot.ttf", b"font");
        root
    }

    fn create(e: &Env, root: &std::path::Path) -> Output {
        let out = e.dir.join("boot-manifest.toml");
        e.run(
            &[
                "boot-manifest",
                "create",
                "--pe-kit",
                "--root",
                root.to_str().unwrap(),
                "--out",
                out.to_str().unwrap(),
                "--pe",
                PE,
                "--boot-program",
                "bootmgfw.efi",
                "--bcd",
                "Boot/BCD",
                "--sdi",
                "Boot/boot.sdi",
                "--wim",
                "Boot/boot.wim",
                "--font",
                "Boot/Fonts/wgl4_boot.ttf",
            ],
            b"",
        )
    }

    fn manifest(e: &Env) -> PathBuf {
        e.dir.join("boot-manifest.toml")
    }

    /// The single audit line on stdout.
    fn audit_line(o: &Output) -> String {
        let out = stdout(o);
        let lines: Vec<&str> = out
            .lines()
            .filter(|l| l.contains(r#""target":"audit""#))
            .collect();
        assert_eq!(lines.len(), 1, "stdout: {out}");
        lines.first().unwrap().to_string()
    }

    #[test]
    fn kit_manifest_written_bound_and_verified() {
        let e = Env::new(vec![pe_route(WIM)], None);
        let root = tree(&e, 0x8664);
        let o = create(&e, &root);
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        let text = fs::read_to_string(manifest(&e)).unwrap();
        let wim = usgp_crypto::sha256(WIM).to_hex();
        for want in [
            "[pe_kit]\n",
            "boot_program = \"bootmgfw.efi\"\n",
            "bcd = \"Boot/BCD\"\n",
            "sdi = \"Boot/boot.sdi\"\n",
            "wim = \"Boot/boot.wim\"\n",
            "fonts = [\"Boot/Fonts/wgl4_boot.ttf\"]\n",
            &format!("pe_content_sha256 = \"{wim}\"\n"),
            "name = \"Boot/BCD\"\n",
        ] {
            assert!(text.contains(want), "missing {want:?} in {text}");
        }
        // REQ-PE-018: memory requirement printed (512 MiB + WIM).
        let mem = 512 * 1024 * 1024 + WIM.len();
        assert!(
            stderr(&o).contains(&format!("memory required to start this PE: {mem} bytes")),
            "{}",
            stderr(&o)
        );
        let line = audit_line(&o);
        assert!(
            line.contains(r#""event":"boot_manifest.created""#),
            "{line}"
        );
        assert!(line.contains(r#""outcome":"success""#), "{line}");
        assert!(line.contains(&wim), "{line}");
        // The PE was read once over mTLS with the operator certificate.
        let seen = e.seen();
        assert_eq!(seen.len(), 1);
        let get = seen.first().unwrap();
        assert_eq!(get.method, "GET");
        assert_eq!(get.path, format!("/v1/pe/{PE}"));
        assert_eq!(get.query, None);
        assert!(get.body.is_empty());
        assert_eq!(get.header("accept"), Some("application/json"));
        assert_eq!(
            get.client_cert_sha256.as_deref(),
            Some(e.operator_sha256().as_str())
        );

        // `verify` reads the kit manifest and checks the kit.
        let v = verify(&e, &root);
        assert_eq!(v.status.code(), Some(0), "{}", stderr(&v));
        assert!(stderr(&v).contains("pe_kit is complete"), "{}", stderr(&v));

        // A kit file altered after the manifest was written fails verify.
        fs::write(root.join("Boot/BCD"), b"another store").unwrap();
        let v = verify(&e, &root);
        assert_eq!(v.status.code(), Some(1));
        assert!(stderr(&v).contains("FAILED Boot/BCD"), "{}", stderr(&v));
    }

    #[test]
    fn wrong_machine_refused_before_server() {
        for machine in [0x014Cu16, 0xAA64] {
            let e = Env::new(vec![pe_route(WIM)], None);
            let root = tree(&e, machine);
            let o = create(&e, &root);
            assert_eq!(o.status.code(), Some(1));
            let err = stderr(&o);
            assert!(err.contains(&format!("0x{machine:04x}, not x64")), "{err}");
            assert!(!manifest(&e).exists());
            assert!(e.seen().is_empty(), "the server was asked");
            assert!(audit_line(&o).contains(r#""outcome":"refused""#));
        }
    }

    #[test]
    fn missing_bcd_refused_and_never_generated() {
        let e = Env::new(vec![pe_route(WIM)], None);
        let root = tree(&e, 0x8664);
        fs::remove_file(root.join("Boot/BCD")).unwrap();
        let o = create(&e, &root);
        assert_eq!(o.status.code(), Some(1));
        assert!(
            stderr(&o).contains("Boot/BCD does not exist"),
            "{}",
            stderr(&o)
        );
        assert!(!root.join("Boot/BCD").exists());
        assert!(!manifest(&e).exists());
        assert!(e.seen().is_empty());
    }

    #[test]
    fn wim_digest_mismatch_refused() {
        let e = Env::new(vec![pe_route(b"a different imported PE")], None);
        let root = tree(&e, 0x8664);
        let o = create(&e, &root);
        assert_eq!(o.status.code(), Some(1));
        let err = stderr(&o);
        assert!(err.contains("does not match"), "{err}");
        assert!(err.contains("the kit's WIM is"), "{err}");
        assert!(!manifest(&e).exists());
        assert_eq!(e.seen().len(), 1);
        assert!(audit_line(&o).contains(r#""outcome":"refused""#));
    }

    #[test]
    fn unknown_pe_refused() {
        // The stub answers 404 for any route it does not know.
        let e = Env::new(Vec::new(), None);
        let root = tree(&e, 0x8664);
        let o = create(&e, &root);
        assert_eq!(o.status.code(), Some(1));
        assert!(stderr(&o).contains("cannot read PE kit"), "{}", stderr(&o));
        assert!(!manifest(&e).exists());
        assert!(audit_line(&o).contains(r#""outcome":"failure""#));
    }
}
