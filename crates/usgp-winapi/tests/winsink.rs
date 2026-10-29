//! `WinSink` on a temporary VHD volume (plan WU-5, §10.2): a synthetic
//! WIM built by `usgp-image`'s testkit is applied through the verified
//! chunk reader, and the result is checked with the tree manifest.
//!
//! Needs administrator rights (restore privilege, DiskPart) and
//! `USGP_WIN_VHD=1`; ignored by default. The windows-agent CI job runs:
//! `USGP_WIN_VHD=1 cargo test -p usgp-winapi --features sink-testkit
//! --test winsink -- --ignored`. Run with `--ignored` but without the
//! variable, it fails rather than passing silently.
//!
//! The descriptors in the tree are real ones read from the new volume
//! (the testkit's synthetic descriptors are not valid Windows
//! descriptors). A relative link, a re-based absolute link and a
//! re-based junction are read back and compared byte for byte; a volume
//! with 8.3 names disabled fails by name.
//!
//! The VHD is made with a DiskPart script run by `diskpart /s`: `create
//! vdisk file= maximum= type=expandable`, `attach vdisk`, `convert gpt`,
//! `create partition primary`, `format fs=ntfs quick label=`, `assign
//! letter=` and `detach vdisk`, as `specs/standards/winpe.md` §11 (SR-7)
//! describes them. `/s` is OPEN-WINPE-2 and the exit codes OPEN-WINPE-3,
//! so the exit status is only a first filter; the test relies on what it
//! reads back (the volume at the letter, its file system, the applied
//! tree). `select vdisk file=` is not itself summarised in §11 (a reading
//! there: a VHD must be selected before it is attached); test harness
//! only. The letter is any free one from P to W (a test choice).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Testing and Evaluation), SI-7
//! - SPEC: specs/preinstall-env.md REQ-PE-016, REQ-PE-017
//! - SPEC: specs/standards/winpe.md §11 (DiskPart; OPEN-WINPE-2, -3)

#![cfg(windows)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use usgp_image::apply::{ApplyError, ApplyLimits, ApplyRoot, SinkOp, apply};
use usgp_image::testkit::tree::{abs_link_data, link_data, rel_link_data};
use usgp_image::testkit::{MemoryChunks, NodeSpec, TreeSpec, WimBuilder};
use usgp_image::wim::metadata::attr;
use usgp_image::{Compression, NoProgress};
use usgp_winapi::fs::SETTABLE_ATTRIBUTES;
use usgp_winapi::fsquery;
use usgp_winapi::manifest::{ManifestOptions, tree_rows};
use usgp_winapi::manifest_text::{Field, Kind, Row};
use usgp_winapi::paths::DriveLetter;
use usgp_winapi::volume;
use usgp_winapi::winsink::WinSink;

fn diskpart(lines: &[String]) -> Result<String, String> {
    let script = std::env::temp_dir().join(format!("usgp-wu5-sink-{}.txt", std::process::id()));
    std::fs::write(&script, lines.join("\r\n")).map_err(|e| e.to_string())?;
    let out = Command::new("diskpart").arg("/s").arg(&script).output();
    let _ = std::fs::remove_file(&script);
    let out = out.map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    if out.status.success() {
        Ok(text)
    } else {
        Err(text)
    }
}

/// A formatted, lettered VHD volume; detached and deleted on drop.
struct VhdVolume {
    file: PathBuf,
    letter: DriveLetter,
}

impl VhdVolume {
    fn create(tag: &str) -> Result<Self, String> {
        let file = std::env::temp_dir().join(format!("usgp-wu5-{tag}-{}.vhdx", std::process::id()));
        let _ = std::fs::remove_file(&file);
        let letter = ('P'..='W')
            .filter_map(DriveLetter::new)
            .find(|l| volume::volume_at(*l).is_err())
            .ok_or("no free letter")?;
        let v = Self { file, letter };
        diskpart(&[
            format!(
                "create vdisk file=\"{}\" maximum=512 type=expandable",
                v.file.display()
            ),
            format!("select vdisk file=\"{}\"", v.file.display()),
            "attach vdisk".to_owned(),
            "convert gpt".to_owned(),
            "create partition primary".to_owned(),
            "format fs=ntfs quick label=USGPSINK".to_owned(),
            format!("assign letter={}", letter.letter()),
        ])?;
        Ok(v)
    }

    fn root(&self) -> PathBuf {
        PathBuf::from(self.letter.root())
    }

    /// The apply root as `usgp-image` takes it (`L:`).
    fn apply_root(&self) -> ApplyRoot {
        ApplyRoot::parse(&format!("{}:", self.letter.letter())).expect("apply root")
    }
}

impl Drop for VhdVolume {
    fn drop(&mut self) {
        let _ = diskpart(&[
            format!("select vdisk file=\"{}\"", self.file.display()),
            "detach vdisk".to_owned(),
        ]);
        let _ = std::fs::remove_file(&self.file);
    }
}

fn sha256_hex(p: &Path) -> std::io::Result<String> {
    Ok(usgp_crypto::sha256(&std::fs::read(p)?).to_hex())
}

fn sha(b: &[u8]) -> String {
    usgp_crypto::sha256(b).to_hex()
}

fn require_env() {
    assert_eq!(
        std::env::var("USGP_WIN_VHD").as_deref(),
        Ok("1"),
        "set USGP_WIN_VHD=1 to run this test (NOT RUN is never PASS)"
    );
}

/// Descriptors read from Windows: index 0 from a directory, 1 from a
/// file, 2 from a file whose DACL was made protected (`icacls
/// /inheritance:r` keeps no inherited entries). Returns them with the SDDL
/// of the first two.
fn real_descriptors(root: &Path) -> (Vec<Vec<u8>>, String, String) {
    let d = root.join("sd-probe-dir");
    let f = root.join("sd-probe.txt");
    let g = root.join("sd-probe-protected.txt");
    std::fs::create_dir(&d).expect("probe dir");
    std::fs::write(&f, b"p").expect("probe file");
    std::fs::write(&g, b"p").expect("probe file");
    // Keep explicit access for Administrators and SYSTEM, then drop
    // inheritance so the DACL is protected.
    let st = Command::new("icacls")
        .arg(&g)
        .args([
            "/grant:r",
            "*S-1-5-32-544:F",
            "/grant:r",
            "*S-1-5-18:F",
            "/inheritance:r",
        ])
        .status()
        .expect("icacls");
    assert!(st.success(), "icacls");
    let sds = vec![
        fsquery::security_descriptor(&d).expect("dir descriptor"),
        fsquery::security_descriptor(&f).expect("file descriptor"),
        fsquery::security_descriptor(&g).expect("protected descriptor"),
    ];
    assert_ne!(
        control(&sds[2]) & DACL_PROTECTED,
        0,
        "probe DACL is protected"
    );
    let sddl = (
        fsquery::sddl(&d).expect("dir sddl"),
        fsquery::sddl(&f).expect("file sddl"),
    );
    for p in [&f, &g] {
        std::fs::remove_file(p).expect("remove probe");
    }
    std::fs::remove_dir(&d).expect("remove probe dir");
    (sds, sddl.0, sddl.1)
}

/// MS-DTYP control bits compared (topic 24 §9): DACL protected and DACL
/// auto-inherited.
const DACL_PROTECTED: u16 = 0x1000;
const DACL_AUTO_INHERITED: u16 = 0x0400;

/// The `Control` word of a self-relative descriptor (topic 24 §9, offset 2).
fn control(sd: &[u8]) -> u16 {
    match sd.get(2..4) {
        Some([a, b]) => u16::from_le_bytes([*a, *b]),
        _ => panic!("descriptor too short"),
    }
}

const T1: [u64; 3] = [
    132_539_328_001_234_567,
    132_854_688_001_234_567,
    133_170_048_001_234_567,
];
const T2: [u64; 3] = [
    130_000_000_000_000_001,
    130_000_000_000_000_002,
    130_000_000_000_000_003,
];

#[test]
#[ignore = "needs administrator rights and USGP_WIN_VHD=1; run by the windows-agent CI job with --ignored"]
fn synthetic_wim_applies_to_a_vhd_volume() {
    require_env();
    let vol = VhdVolume::create("sink").expect("VHD volume");
    let root = vol.root();
    // Short names need 8dot3 creation enabled on the volume.
    let st = Command::new("fsutil")
        .args([
            "8dot3name",
            "set",
            &format!("{}:", vol.letter.letter()),
            "0",
        ])
        .status()
        .expect("fsutil");
    assert!(st.success(), "enable 8dot3 names on the test volume");
    let (sds, dir_sddl, file_sddl) = real_descriptors(&root);

    let linked = b"three names, one file\n".to_vec();
    let comp = b"compressible ".repeat(50);
    let big: Vec<u8> = (0..200_000u32).flat_map(|i| i.to_le_bytes()).collect();
    let mut spec = TreeSpec::new(vec![
        NodeSpec::file("readme-long-name.txt", b"hello\n")
            .short("README~1.TXT")
            .security(1),
        NodeSpec::file("empty.txt", b"").security(1),
        NodeSpec::file("big.bin", &big).times(T2).security(1),
        NodeSpec::file("ro.txt", b"read only\n")
            .attributes(attr::READONLY)
            .security(2),
        NodeSpec::file("hs.txt", b"h")
            .attributes(attr::HIDDEN | attr::SYSTEM | attr::ARCHIVE)
            .security(1),
        NodeSpec::file("\u{10400}-supplementary.txt", b"non-bmp\n").security(1),
        NodeSpec::file("streams.txt", b"main\n")
            .stream("usgp-one", b"first stream\n")
            .stream("usgp-zero", b"")
            .security(1),
        NodeSpec::file("sparse.bin", &[0u8; 4096])
            .attributes(attr::SPARSE | attr::ARCHIVE)
            .security(1),
        NodeSpec::file("compressed.txt", &comp)
            .attributes(attr::COMPRESSED | attr::ARCHIVE)
            .security(1),
        NodeSpec::dir("empty-dir", vec![]),
        NodeSpec::dir("dir-with-stream", vec![]).stream("usgp-dir-stream", b"on a dir\n"),
        NodeSpec::dir(
            "links",
            vec![
                NodeSpec::file("hard-original.txt", &linked)
                    .link(0x0001_0000_0000_002A)
                    .security(1),
                NodeSpec::file("hard-two.txt", &linked)
                    .link(0x0001_0000_0000_002A)
                    .security(1),
                NodeSpec::dir(
                    "sub",
                    vec![
                        NodeSpec::file("hard-three.txt", &linked)
                            .link(0x0001_0000_0000_002A)
                            .security(1),
                    ],
                ),
            ],
        )
        .attributes(attr::DIRECTORY | attr::HIDDEN)
        .times(T1),
    ]);
    spec.security = sds.clone();
    let (wim, _) = WimBuilder::new(Compression::Xpress)
        .tree_image("img", "desc", spec)
        .build()
        .expect("build WIM");

    let mut sink = WinSink::new(&root).expect("sink");
    let report = apply(
        &mut MemoryChunks::new(wim),
        1,
        &vol.apply_root(),
        &mut sink,
        &ApplyLimits::new(1 << 28),
        &mut NoProgress,
        usgp_crypto::provider(),
    )
    .expect("apply");
    println!("{report:?}");
    drop(sink);

    let opts = ManifestOptions {
        no_descend: vec!["System Volume Information".to_owned()],
        ..ManifestOptions::default()
    };
    let rows = tree_rows(&root, &opts, &sha256_hex).expect("manifest");
    println!("{}", usgp_winapi::manifest_text::render(&rows));
    let by_path: BTreeMap<&str, &Row> = rows.iter().map(|r| (r.path.as_str(), r)).collect();
    let row = |p: &str| *by_path.get(p).unwrap_or_else(|| panic!("row {p}"));
    let value = |f: &Field| match f {
        Field::Value(v) => v.clone(),
        other => panic!("{other:?}"),
    };

    // Files: kind, settable attributes, times, content, descriptor.
    let files: [(&str, &[u8], u32, [u64; 3]); 9] = [
        ("readme-long-name.txt", b"hello\n", attr::ARCHIVE, T1),
        ("empty.txt", b"", attr::ARCHIVE, T1),
        ("big.bin", &big, attr::ARCHIVE, T2),
        ("ro.txt", b"read only\n", attr::READONLY, T1),
        (
            "hs.txt",
            b"h",
            attr::HIDDEN | attr::SYSTEM | attr::ARCHIVE,
            T1,
        ),
        (
            "\u{10400}-supplementary.txt",
            b"non-bmp\n",
            attr::ARCHIVE,
            T1,
        ),
        ("streams.txt", b"main\n", attr::ARCHIVE, T1),
        ("sparse.bin", &[0u8; 4096], attr::ARCHIVE, T1),
        ("compressed.txt", &comp, attr::ARCHIVE, T1),
    ];
    for (p, data, attrs, t) in files {
        let r = row(p);
        assert_eq!(r.kind, Kind::File, "{p}");
        assert_eq!(
            r.attributes & SETTABLE_ATTRIBUTES,
            attrs & SETTABLE_ATTRIBUTES,
            "{p}"
        );
        assert_eq!([r.creation, r.last_access, r.last_write], t, "{p}");
        assert_eq!(
            r.length,
            Some(u64::try_from(data.len()).expect("len")),
            "{p}"
        );
        assert_eq!(value(&r.sha256), sha(data), "{p}");
        if p != "ro.txt" {
            assert_eq!(value(&r.sddl), file_sddl, "{p}");
        }
    }
    // OPEN-WAPI-7: the stored "protected" and "auto-inherited" DACL bits
    // after SetSecurityInfo, compared explicitly and printed for the
    // report.
    let mask = DACL_PROTECTED | DACL_AUTO_INHERITED;
    let mut mismatches = Vec::new();
    for (p, idx) in [
        (".", 0usize),
        ("empty-dir", 0),
        ("links", 0),
        ("readme-long-name.txt", 1),
        ("big.bin", 1),
        ("ro.txt", 2),
    ] {
        let applied = fsquery::security_descriptor(&root.join(p)).expect("applied descriptor");
        let want = control(sds.get(idx).expect("sd")) & mask;
        let got = control(&applied) & mask;
        println!("OPEN-WAPI-7 {p}: stored control bits {want:#06x}, applied {got:#06x}");
        if want != got {
            mismatches.push((p, want, got));
        }
    }
    assert!(mismatches.is_empty(), "control bits differ: {mismatches:?}");
    assert_eq!(
        value(&row("streams.txt").streams),
        format!(
            "usgp-one:13:{};usgp-zero:0:{}",
            sha(b"first stream\n"),
            sha(b"")
        )
    );
    assert_eq!(
        value(&row("dir-with-stream").streams),
        format!("usgp-dir-stream:9:{}", sha(b"on a dir\n"))
    );
    // Directories, including the root's descriptor and times.
    for p in [".", "empty-dir", "dir-with-stream", "links", "links\\sub"] {
        let r = row(p);
        assert_eq!(r.kind, Kind::Dir, "{p}");
        assert_eq!(value(&r.sddl), dir_sddl, "{p}");
    }
    assert_eq!(row("links").attributes & SETTABLE_ATTRIBUTES, attr::HIDDEN);
    let l = row("links");
    assert_eq!([l.creation, l.last_access, l.last_write], T1);
    // One hard-link group of three names.
    let links = value(&row("links\\hard-two.txt").hard_links);
    for n in ["hard-original.txt", "hard-two.txt", "hard-three.txt"] {
        assert!(links.contains(n), "{links}");
    }
    assert_eq!(links.matches('|').count(), 2, "{links}");
}

fn apply_tree(vol: &VhdVolume, spec: TreeSpec) -> Result<(), ApplyError> {
    // The testkit's default header for an uncompressed WIM carries
    // `FLAG_HEADER_RP_FIX` (0x80, OBS-005), so stored absolute targets
    // are re-based (decision 0022).
    let (wim, _) = WimBuilder::new(Compression::None)
        .tree_image("img", "desc", spec)
        .build()
        .expect("build WIM");
    let mut sink = WinSink::new(&vol.root()).expect("sink");
    apply(
        &mut MemoryChunks::new(wim),
        1,
        &vol.apply_root(),
        &mut sink,
        &ApplyLimits::new(1 << 24),
        &mut NoProgress,
        usgp_crypto::provider(),
    )
    .map(drop)
}

/// The complete buffer `usgp-image` sets for stored `data` under `tag`:
/// the 8-byte header (tag, data length, Reserved 0) then the data
/// (topic 24 §2).
fn with_header(tag: u32, data: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(tag.to_le_bytes());
    b.extend(u16::try_from(data.len()).expect("short").to_le_bytes());
    b.extend([0u8, 0]);
    b.extend(data);
    b
}

const SYMLINK_TAG: u32 = 0xA000_000C;
const MOUNT_POINT_TAG: u32 = 0xA000_0003;

#[test]
#[ignore = "needs administrator rights and USGP_WIN_VHD=1; run by the windows-agent CI job with --ignored"]
fn links_and_junctions_are_applied_byte_for_byte() {
    require_env();
    let vol = VhdVolume::create("link").expect("VHD volume");
    let root = vol.root();
    let l = vol.letter.letter();
    let (sds, _, _) = real_descriptors(&root);
    // Stored as captured from C: with RP_FIX: `\??\C:\target-dir` and
    // `C:\target.txt`, marked 0 at +92 (re-base); the relative link is
    // copied.
    let mut spec = TreeSpec::new(vec![
        NodeSpec::file("target.txt", b"t\n").security(1),
        NodeSpec::dir(
            "target-dir",
            vec![NodeSpec::file("in.txt", b"in\n").security(1)],
        ),
        NodeSpec::symlink("rel.txt", false, &rel_link_data("target.txt")).security(1),
        NodeSpec::symlink("abs.txt", false, &abs_link_data("C:\\target.txt", false))
            .field_92(0)
            .security(1),
        NodeSpec::junction("junction", &abs_link_data("C:\\target-dir", true)).field_92(0),
    ]);
    spec.security = sds;
    apply_tree(&vol, spec).expect("apply");

    // Read each back (as `fsutil reparsepoint query` does) and compare the
    // bytes with the buffer the rules give.
    let expected = [
        (
            "rel.txt",
            with_header(SYMLINK_TAG, &rel_link_data("target.txt")),
        ),
        (
            "abs.txt",
            with_header(
                SYMLINK_TAG,
                &link_data(
                    &format!("\\??\\{l}:\\target.txt"),
                    &format!("{l}:\\target.txt"),
                    Some(0),
                ),
            ),
        ),
        (
            "junction",
            with_header(
                MOUNT_POINT_TAG,
                &link_data(
                    &format!("\\??\\{l}:\\target-dir"),
                    &format!("{l}:\\target-dir"),
                    None,
                ),
            ),
        ),
    ];
    for (p, want) in &expected {
        let got = fsquery::reparse_buffer(&root.join(p)).expect("read reparse point");
        assert_eq!(&got, want, "{p}");
    }
    // Following the links reaches the targets.
    assert_eq!(std::fs::read(root.join("rel.txt")).expect("rel"), b"t\n");
    assert_eq!(std::fs::read(root.join("abs.txt")).expect("abs"), b"t\n");
    assert_eq!(
        std::fs::read(root.join("junction").join("in.txt")).expect("through junction"),
        b"in\n"
    );
    // Descriptors were set on the links themselves: the targets keep
    // theirs, and the manifest lists the links without entering them.
    let opts = ManifestOptions {
        no_descend: vec!["System Volume Information".to_owned()],
        ..ManifestOptions::default()
    };
    let rows = tree_rows(&root, &opts, &sha256_hex).expect("manifest");
    for (p, tag) in [
        ("rel.txt", SYMLINK_TAG),
        ("abs.txt", SYMLINK_TAG),
        ("junction", MOUNT_POINT_TAG),
    ] {
        let r = rows.iter().find(|r| r.path == p).expect("row");
        assert_eq!(r.kind, Kind::Reparse(tag), "{p}");
    }
    assert!(!rows.iter().any(|r| r.path.starts_with("junction\\")));
    let link_sd = fsquery::security_descriptor(&root.join("abs.txt"));
    println!(
        "descriptor read on the link itself: {:?}",
        link_sd.map(|d| d.len())
    );
}

#[test]
#[ignore = "needs administrator rights and USGP_WIN_VHD=1; run by the windows-agent CI job with --ignored"]
fn short_names_disabled_fail_by_name() {
    require_env();
    let vol = VhdVolume::create("8dot3").expect("VHD volume");
    let root = vol.root();
    let st = Command::new("fsutil")
        .args([
            "8dot3name",
            "set",
            &format!("{}:", vol.letter.letter()),
            "1",
        ])
        .status()
        .expect("fsutil");
    assert!(st.success(), "disable 8dot3 names on the test volume");
    let (sds, _, _) = real_descriptors(&root);
    let mut spec = TreeSpec::new(vec![
        NodeSpec::file("readme-long-name.txt", b"x")
            .short("README~1.TXT")
            .security(1),
    ]);
    spec.security = sds;
    match apply_tree(&vol, spec) {
        Err(ApplyError::Sink(e)) => {
            assert_eq!(e.op, SinkOp::SetShortName);
            assert_eq!(e.kind, std::io::ErrorKind::Unsupported);
        }
        other => panic!("expected a named short-name failure, got {other:?}"),
    }
}
