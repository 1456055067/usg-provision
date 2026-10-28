//! Disk write path on an attached VHD (plan WU-5, §10.2): raw sector I/O,
//! property update, layout read-back, volume resolution by extents, drive
//! letters and the file-system name.
//!
//! Needs administrator rights. It creates a 1 GiB expandable VHDX in the
//! temp directory with DiskPart, writes only to the one disk that appeared
//! when it was attached, and detaches and deletes it afterwards. It never
//! touches any other disk.
//!
//! Ignored by default; the windows-agent CI job runs it with
//! `USGP_WIN_VHD=1 cargo test -p usgp-winapi --test vhd_disk -- --ignored`.
//! Run with `--ignored` but without `USGP_WIN_VHD=1`, it fails rather than
//! passing silently.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Testing and Evaluation)
//! - SPEC: specs/standards/windows-storage-firmware-api.md §5, §7, §8
//! - SPEC: specs/disk.md (DISK-1) - disk tests on image files only

#![cfg(windows)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use usgp_winapi::WinApiError;
use usgp_winapi::disk::{self, DiskQuery, PartitionStyle, RawDisk, Writability};
use usgp_winapi::paths::DriveLetter;
use usgp_winapi::volume;

const VHD_MIB: u64 = 1024;

fn diskpart(lines: &[String]) -> Result<String, String> {
    let dir = std::env::temp_dir();
    let script = dir.join(format!("usgp-wu5-dp-{}.txt", std::process::id()));
    std::fs::write(&script, lines.join("\r\n")).map_err(|e| format!("write script: {e}"))?;
    let out = Command::new("diskpart")
        .arg("/s")
        .arg(&script)
        .output()
        .map_err(|e| format!("run diskpart: {e}"));
    let _ = std::fs::remove_file(&script);
    let out = out?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    if out.status.success() {
        Ok(text)
    } else {
        Err(format!("diskpart failed:\n{text}"))
    }
}

struct Vhd {
    path: PathBuf,
}

impl Vhd {
    fn create(path: &Path) -> Result<Self, String> {
        let _ = std::fs::remove_file(path);
        let vhd = Self {
            path: path.to_owned(),
        };
        diskpart(&[
            format!(
                "create vdisk file=\"{}\" maximum={VHD_MIB} type=expandable",
                path.display()
            ),
            vhd.select(),
            "attach vdisk".to_owned(),
        ])?;
        Ok(vhd)
    }

    fn select(&self) -> String {
        format!("select vdisk file=\"{}\"", self.path.display())
    }
}

impl Drop for Vhd {
    fn drop(&mut self) {
        let script = [self.select(), "detach vdisk".to_owned()].join("\r\n");
        let f = std::env::temp_dir().join("usgp-wu5-dp-detach.txt");
        if std::fs::write(&f, script).is_ok() {
            let _ = Command::new("diskpart").arg("/s").arg(&f).output();
            let _ = std::fs::remove_file(&f);
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

fn wait_for<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    let start = Instant::now();
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "timed out waiting for {what}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

#[test]
#[ignore = "needs administrator rights and USGP_WIN_VHD=1; run by the windows-agent CI job with --ignored"]
fn vhd_raw_io_update_and_volume_letters() {
    assert_eq!(
        std::env::var("USGP_WIN_VHD").as_deref(),
        Ok("1"),
        "set USGP_WIN_VHD=1 to run this test (NOT RUN is never PASS)"
    );
    let size = VHD_MIB * 1024 * 1024;
    let before: BTreeSet<u32> = disk::enumerate().expect("enumerate").into_iter().collect();
    let path = std::env::temp_dir().join(format!("usgp-wu5-{}.vhdx", std::process::id()));
    let vhd = Vhd::create(&path).expect("create and attach the VHD");

    // The disk under test is the single disk that appeared on attach.
    let n = wait_for("the attached VHD", || {
        let after: BTreeSet<u32> = disk::enumerate().ok()?.into_iter().collect();
        let new: Vec<u32> = after.difference(&before).copied().collect();
        match new.as_slice() {
            [one] => Some(*one),
            [] => None,
            more => panic!("more than one new disk appeared: {more:?}"),
        }
    });
    let info = DiskQuery::open(n)
        .expect("open")
        .inspect()
        .expect("inspect");
    println!("VHD disk {n}: {info:?}");
    assert_eq!(info.geometry.size_bytes, size);
    assert_eq!(info.layout.style, PartitionStyle::Raw);
    assert_eq!(info.writability, Writability::Writable);

    // Opening for write re-checks the size the job recorded.
    assert!(matches!(
        RawDisk::open_for_write(n, size + 512),
        Err(WinApiError::DeviceMismatch { .. })
    ));
    let mut raw = RawDisk::open_for_write(n, size).expect("open for write");
    let sector = u64::from(raw.logical_sector());
    let sector_len = usize::try_from(sector).expect("sector fits");
    assert_eq!(raw.len(), size);

    // Unaligned and out-of-range I/O is refused before any write.
    assert!(matches!(
        raw.write_at(1, &vec![0u8; sector_len]),
        Err(WinApiError::Refused { .. })
    ));
    assert!(matches!(
        raw.write_at(0, &vec![0u8; sector_len + 1]),
        Err(WinApiError::Refused { .. })
    ));
    assert!(matches!(
        raw.write_at(size, &vec![0u8; sector_len]),
        Err(WinApiError::Refused { .. })
    ));

    let pattern: Vec<u8> = (0..sector_len * 8)
        .map(|i| u8::try_from(i % 251).expect("fits"))
        .collect();
    let off = 1024 * 1024;
    raw.write_at(off, &pattern).expect("write");
    raw.flush().expect("flush");
    let mut back = vec![0u8; pattern.len()];
    raw.read_at(off, &mut back).expect("read");
    assert_eq!(back, pattern);
    let mut last = vec![0u8; sector_len];
    raw.read_at(size - sector, &mut last)
        .expect("read last sector");
    raw.update_properties().expect("update properties");
    assert_eq!(raw.layout().expect("layout").style, PartitionStyle::Raw);
    drop(raw);

    // Let DiskPart lay out and format one volume, then resolve it by
    // disk number and starting offset, as the plan does (§1.2(c)).
    diskpart(&[
        vhd.select(),
        "convert gpt".to_owned(),
        "create partition primary".to_owned(),
        "format fs=ntfs quick label=USGPWU5".to_owned(),
    ])
    .expect("diskpart layout and format");
    let layout = DiskQuery::open(n).expect("open").layout().expect("layout");
    assert_eq!(layout.style, PartitionStyle::Gpt);
    let data = layout
        .partitions
        .iter()
        .max_by_key(|p| p.length)
        .expect("a partition")
        .clone();
    let vol = wait_for("the formatted volume", || {
        volume::volumes_with_extents()
            .ok()?
            .into_iter()
            .find_map(|(v, e)| {
                let e = e.ok()?;
                (e.len() == 1
                    && e.iter()
                        .all(|x| x.disk_number == n && x.starting_offset == data.starting_offset))
                .then_some(v)
            })
    });
    assert_eq!(volume::file_system_name(&vol).expect("fs name"), "NTFS");

    let letter = ('P'..='W')
        .filter_map(DriveLetter::new)
        .find(|l| volume::volume_at(*l).is_err())
        .expect("a free letter");
    volume::assign_letter(letter, &vol).expect("assign letter");
    assert_eq!(volume::volume_at(letter).expect("volume at letter"), vol);
    assert!(
        volume::drive_letters(&vol)
            .expect("letters")
            .contains(&letter)
    );
    // Tree manifest on the new volume: a file with a second hard link and
    // a named stream, and a directory. The content "hash" here is a test
    // stand-in (the example uses usgp-crypto's SHA-256).
    let root = std::path::PathBuf::from(letter.root());
    std::fs::write(root.join("a.txt"), b"abc").expect("write a.txt");
    std::fs::hard_link(root.join("a.txt"), root.join("b.txt")).expect("hard link");
    std::fs::write(root.join("a.txt:s1"), b"xyz").expect("write stream");
    std::fs::create_dir(root.join("d")).expect("mkdir");
    let fake_hash = |p: &Path| std::fs::metadata(p).map(|m| format!("len{}", m.len()));
    let rows = usgp_winapi::manifest::tree_rows(
        &root,
        &usgp_winapi::manifest::ManifestOptions {
            no_descend: vec!["System Volume Information".to_owned()],
            ..usgp_winapi::manifest::ManifestOptions::default()
        },
        &fake_hash,
    )
    .expect("manifest");
    let text = usgp_winapi::manifest_text::render(&rows);
    println!("{text}");
    let line = |p: &str| {
        text.lines()
            .find(|l| l.split('\t').next() == Some(p))
            .unwrap_or_else(|| panic!("row {p}"))
            .to_owned()
    };
    assert!(line(".").contains("\tdir\t"));
    let a_row = line("a.txt");
    assert!(a_row.contains("\tfile\t"), "{a_row}");
    assert!(a_row.contains("s1:3:"), "{a_row}");
    // Both names in the hard-links column.
    assert!(a_row.contains('|') && a_row.contains("b.txt"), "{a_row}");
    assert!(line("d").contains("\tdir\t"));

    volume::remove_letter(letter).expect("remove letter");

    // Lock and dismount before a wipe: fails closed while another lock is
    // held, and works again once it is released.
    let locks = volume::lock_volumes_on_disk(n).expect("lock volumes on the VHD");
    assert_eq!(locks.len(), 1);
    assert_eq!(locks.first().map(|l| l.volume()), Some(&vol));
    assert!(volume::lock_and_dismount(&vol).is_err());
    drop(locks);
    drop(volume::lock_and_dismount(&vol).expect("lock again after release"));
    assert!(
        !volume::drive_letters(&vol)
            .expect("letters")
            .contains(&letter)
    );
    drop(vhd);
}
