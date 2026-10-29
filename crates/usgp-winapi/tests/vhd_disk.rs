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
//! It also records GPT-OBS-001 (REL-M3-WU15-001): the GPT DiskPart wrote is
//! read back through `RawDisk` with `usgp_disk::parse_gpt` and the default
//! limits, and one line `GPT-OBS-001 accepted: ...` or `GPT-OBS-001
//! refused: ...` is printed for the CI summary. A refusal fails the test:
//! relaxing the reader's strictness (impl-notes-wu3 U-6) needs a decision.
//!
//! DiskPart script commands (`create vdisk file= maximum= type=`, `attach
//! vdisk`, `detach vdisk`, `convert gpt`, `create partition primary`,
//! `format fs= quick label=`): `specs/standards/winpe.md` §11 (SR-7).
//! `select vdisk file=` is not itself summarised there; §11 says only, as
//! a reading, that a VHD must be selected before it is attached (spec gap
//! noted in the fix notes; test harness only). The
//! script is run with `diskpart /s`, which the deployment samples use but
//! the "diskpart" page does not describe (OPEN-WINPE-2), and the exit-code
//! values are not documented (OPEN-WINPE-3). So DiskPart's exit status is
//! only a first filter: what this test relies on is the read-back (the
//! disk that appeared, the layout, the GPT, the volume's extents and file
//! system).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Testing and Evaluation)
//! - SPEC: specs/standards/windows-storage-firmware-api.md §2, §5, §7, §8
//! - SPEC: specs/standards/winpe.md §11 (DiskPart commands; OPEN-WINPE-2,
//!   OPEN-WINPE-3)
//! - SPEC: specs/disk.md (DISK-1) - disk tests on image files only;
//!   REQ-DISK-009 (GPT read-back), OPEN-GPT-1

#![cfg(windows)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use usgp_disk::layout::PartRole;
use usgp_disk::{
    BlockDevice, Bus, DiskFacts, DiskIdentity, GptLimits, WindowsUefiLayout, parse_gpt,
};
use usgp_winapi::WinApiError;
use usgp_winapi::disk::{
    self, DiskInterface, DiskQuery, PartitionStyle, RawDisk, TableId, Writability,
};
use usgp_winapi::diskpart::FsKind;
use usgp_winapi::format::{self, FormatEnv, FormatTarget};
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
        Self::create_mib(path, VHD_MIB)
    }

    fn create_mib(path: &Path, mib: u64) -> Result<Self, String> {
        let _ = std::fs::remove_file(path);
        let vhd = Self {
            path: path.to_owned(),
        };
        diskpart(&[
            format!(
                "create vdisk file=\"{}\" maximum={mib} type=expandable",
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

/// `RawDisk` as a read-only `usgp-disk` block device: GPT-OBS-001 reads
/// through the same handle type the agent writes with. Writes are refused.
struct ReadOnly(RawDisk);

impl BlockDevice for ReadOnly {
    fn len(&self) -> u64 {
        self.0.len()
    }

    fn logical_sector(&self) -> u32 {
        self.0.logical_sector()
    }

    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> std::io::Result<()> {
        self.0
            .read_at(off, buf)
            .map_err(|e| std::io::Error::other(e.to_string()))
    }

    fn write_at(&mut self, _off: u64, _buf: &[u8]) -> std::io::Result<()> {
        Err(std::io::Error::other("GPT-OBS-001 reads only"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A freshly attached VHD has no partitions: Windows reports it either as
/// RAW (no table) or as an empty MBR (observed on the CI runner). Any
/// other style, or any partition, fails.
fn assert_new_disk_is_empty(layout: &disk::DriveLayout) {
    assert!(
        matches!(layout.style, PartitionStyle::Raw | PartitionStyle::Mbr),
        "new disk style {:?}",
        layout.style
    );
    assert!(
        layout.partitions.is_empty(),
        "new disk has partitions: {:?}",
        layout.partitions
    );
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
    // A new VHD is "like an uninitialised disk" (`winpe.md` §11), but the
    // runner has reported it as MBR-style (CI run 40876728637), so the
    // style is an observation; what matters is that it has no partitions.
    println!("VHD-OBS new disk style: {:?}", info.layout.style);
    assert_new_disk_is_empty(&info.layout);
    let first_table = info.layout.table_id();
    assert_eq!(info.writability, Writability::Writable);
    assert_eq!(info.interface_path, None, "opened by number");

    // BOOT-002: the disk's interface path (spec §2) opens the same device,
    // for queries and for write, and the identity read on the write handle
    // is the one read on the query handle.
    let iface = disk::interfaces()
        .expect("interfaces")
        .into_iter()
        .find(|i| i.number == n)
        .expect("the VHD's interface");
    let by_path = DiskQuery::open_interface(&iface)
        .expect("open by interface path")
        .inspect()
        .expect("inspect by path");
    assert_eq!(by_path.interface_path.as_deref(), Some(iface.path.as_str()));
    assert_eq!(by_path.descriptor, info.descriptor);
    assert_eq!(by_path.layout.table_id(), first_table);
    let w = RawDisk::open_interface_for_write(&iface, size).expect("open by path for write");
    assert_eq!(w.number(), n);
    assert_eq!(
        w.descriptor().expect("descriptor on the write handle"),
        info.descriptor
    );
    assert_eq!(
        w.layout().expect("layout on the write handle").table_id(),
        first_table
    );
    drop(w);
    assert!(matches!(
        RawDisk::open_interface_for_write(&iface, size + 512),
        Err(WinApiError::DeviceMismatch { .. })
    ));
    // A path whose disk now has another number is refused.
    let moved = DiskInterface {
        number: n.wrapping_add(1000),
        path: iface.path.clone(),
    };
    assert!(matches!(
        RawDisk::open_interface_for_write(&moved, size),
        Err(WinApiError::DeviceMismatch { .. })
    ));

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
    // Only sectors past LBA 0 were written: the table is as it was.
    let after = raw.layout().expect("layout");
    assert_eq!(after.style, info.layout.style);
    assert_new_disk_is_empty(&after);
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

    // GPT-OBS-001 (REL-M3-WU15-001): usgp-disk's reader accepts the GPT
    // DiskPart wrote, read through the agent's own write-handle type.
    let mut dev = ReadOnly(RawDisk::open_interface_for_write(&iface, size).expect("open"));
    let table = dev
        .0
        .layout()
        .expect("layout on the write handle")
        .table_id();
    match parse_gpt(&mut dev, &GptLimits::default()) {
        Ok(v) => {
            println!(
                "GPT-OBS-001 accepted: entries {} used {} of {} bytes, first/last usable \
                 {}/{}, array LBA {} (backup {}), block {}",
                v.entry_count,
                v.entries.len(),
                v.entry_size,
                v.first_usable,
                v.last_usable,
                v.primary_array_lba,
                v.backup_array_lba,
                v.block
            );
            let g = match table {
                TableId::Gpt(g) => g,
                other => panic!("Windows reports {other:?} for a GPT disk"),
            };
            assert_eq!(
                v.disk_guid,
                usgp_disk::Guid::from_fields(g.data1, g.data2, g.data3, g.data4),
                "the disk GUID usgp-disk reads is the one Windows reports"
            );
            assert_eq!(v.entries.len(), layout.partitions.len());
        }
        Err(e) => {
            println!("GPT-OBS-001 refused: {e}");
            panic!("GPT-OBS-001 refused: {e} (relaxing U-6 needs a decision)");
        }
    }
    drop(dev);
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

/// The single disk that appeared after `before` was taken.
fn new_disk(before: &BTreeSet<u32>) -> u32 {
    wait_for("the attached VHD", || {
        let after: BTreeSet<u32> = disk::enumerate().ok()?.into_iter().collect();
        let new: Vec<u32> = after.difference(before).copied().collect();
        assert!(new.len() <= 1, "more than one new disk appeared: {new:?}");
        new.first().copied()
    })
}

/// BOOT-004: our full four-partition layout, with the recovery partition
/// already carrying its type and attributes `0x8000000000000001`
/// (`gpt.md` §10, REQ-DISK-008), is written to a VHD exactly as the
/// engine writes it (the `usgp-disk` plan through `RawDisk`, then the
/// property update). Each volume is then formatted with the agent's own
/// code, `usgp_winapi::format` (wait for the volume by extent, assign a
/// letter, write the script, re-check the letter, DiskPart, read back).
/// Only the letter choice differs: any free letter from P to W, where the
/// agent prefers W, S and R and reserves the Windows letter.
///
/// Prints `BOOT-004 recovery-format accepted: ...` or `BOOT-004
/// recovery-format refused: ...` for the CI summary. A refusal fails the
/// test: the agent then needs the format-as-basic-data fallback (POAM in
/// `platform_win.rs`).
///
/// The VHD is 66 000 MiB expandable (above the 64 GB layout minimum);
/// quick formats write little, so the file stays small.
#[test]
#[ignore = "needs administrator rights and USGP_WIN_VHD=1; run by the windows-agent CI job with --ignored"]
fn boot004_recovery_typed_partition_formats() {
    assert_eq!(
        std::env::var("USGP_WIN_VHD").as_deref(),
        Ok("1"),
        "set USGP_WIN_VHD=1 to run this test (NOT RUN is never PASS)"
    );
    let before: BTreeSet<u32> = disk::enumerate().expect("enumerate").into_iter().collect();
    let path = std::env::temp_dir().join(format!("usgp-boot004-{}.vhdx", std::process::id()));
    let vhd = Vhd::create_mib(&path, 66_000).expect("create and attach the VHD");
    let n = new_disk(&before);
    let iface = disk::interfaces()
        .expect("interfaces")
        .into_iter()
        .find(|i| i.number == n)
        .expect("the VHD's interface");
    let info = DiskQuery::open_interface(&iface)
        .expect("open")
        .inspect()
        .expect("inspect");
    println!("VHD-OBS new disk style: {:?}", info.layout.style);
    assert_new_disk_is_empty(&info.layout);
    let (logical, physical) = info.sector_sizes.map_or(
        (
            info.geometry.bytes_per_sector,
            info.geometry.bytes_per_sector,
        ),
        |s| (s.logical, s.physical),
    );
    let facts = DiskFacts {
        identity: DiskIdentity {
            device_number: n,
            model: String::new(),
            serial: None,
        },
        bus: Bus::FileBackedVirtual,
        removable: false,
        read_only: false,
        logical_sector: logical,
        physical_sector: physical,
        size_bytes: info.geometry.size_bytes,
        hosts_boot_environment: false,
        partitions: Vec::new(),
    };
    // Distinct, non-nil GUID bytes (test data; the agent uses the DRBG).
    let mut counter = 0u8;
    let mut rng = |buf: &mut [u8]| {
        for b in buf {
            counter = counter.wrapping_add(1);
            *b = counter;
        }
    };
    let layout = WindowsUefiLayout::compute(&facts, 500 * 1024 * 1024, &mut rng).expect("layout");
    assert_eq!(layout.recovery.attributes, 0x8000_0000_0000_0001);
    let plan = layout.gpt_plan().expect("GPT plan");

    // Write the table as the engine does (backup first; usgp-disk's
    // order), then make Windows re-read it.
    let mut raw = RawDisk::open_interface_for_write(&iface, info.geometry.size_bytes)
        .expect("open for write");
    for (off, bytes) in plan.writes().expect("encode") {
        raw.write_at(off, &bytes).expect("write table");
    }
    raw.flush().expect("flush");
    raw.update_properties().expect("update properties");
    drop(raw);

    let system_dir = usgp_winapi::system::system_directory().expect("system directory");
    let script_dir = std::env::temp_dir();
    let env = FormatEnv {
        system_dir: &system_dir,
        script_dir: &script_dir,
        tool_limit: Duration::from_secs(600),
    };
    let block = u64::from(layout.block);
    let roles = [
        (&layout.esp, FsKind::Fat32, "System"),
        (&layout.windows, FsKind::Ntfs, "Windows"),
        (&layout.recovery, FsKind::Ntfs, "Recovery"),
    ];
    let mut letters = Vec::new();
    let mut recovery = None;
    for (i, (part, fs, label)) in roles.iter().enumerate() {
        let t = FormatTarget {
            disk: n,
            start: part.first_lba * block,
            len: part.len_lbas() * block,
            fs: *fs,
            label,
        };
        let outcome = format::wait_for_volume(&t, Duration::from_secs(60)).and_then(|vol| {
            let letter = ('P'..='W')
                .filter_map(DriveLetter::new)
                .find(|l| volume::volume_at(*l).is_err())
                .expect("a free letter");
            volume::assign_letter(letter, &vol).map_err(format::FormatError::Os)?;
            letters.push(letter);
            let random = [u8::try_from(i).unwrap_or(0).wrapping_add(0xB0); 16];
            format::format_at_letter(&t, &vol, letter, &env, random)?;
            Ok((vol, letter))
        });
        println!("BOOT-004 {:?} ({label}): {outcome:?}", part.role);
        match part.role {
            PartRole::Recovery => recovery = Some((t, outcome)),
            _ => {
                let (vol, _) = outcome.unwrap_or_else(|e| panic!("{label}: {e}"));
                let want = if *fs == FsKind::Fat32 {
                    "FAT32"
                } else {
                    "NTFS"
                };
                assert_eq!(volume::file_system_name(&vol).expect("fs"), want);
            }
        }
    }
    let (t, outcome) = recovery.expect("recovery formatted or refused");
    match outcome {
        Ok((vol, _)) => {
            let fs = volume::file_system_name(&vol).expect("fs");
            let ext = volume::disk_extents(&vol).expect("extents");
            println!(
                "BOOT-004 recovery-format accepted: {fs} at disk {n} offset {} length {} \
                 (type {}, attributes {:#018x})",
                t.start, t.len, layout.recovery.type_guid, layout.recovery.attributes
            );
            assert_eq!(fs, "NTFS");
            assert!(matches!(ext.as_slice(), [x] if x.disk_number == n
                && x.starting_offset == t.start && x.length == t.len));
        }
        Err(e) => {
            println!("BOOT-004 recovery-format refused: {e}");
            panic!("BOOT-004 recovery-format refused: {e} (the agent needs the fallback)");
        }
    }
    for l in letters {
        let _ = volume::remove_letter(l);
    }
    drop(vhd);
}
