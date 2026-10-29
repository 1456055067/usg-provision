//! GPT encode, write and strict read-back (REQ-DISK-009), on in-memory
//! devices and sparse regular files only.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity),
//   SI-10 (Information Input Validation), SA-11 (Developer Testing)
// - SPEC: specs/disk.md#REQ-DISK-009, #REQ-DISK-010
// - specs/standards/gpt.md §2 to §7

pub mod common;

use std::path::PathBuf;

use common::{GB, TestRng, auth_for, layout, round_down};
use usgp_disk::crc32::crc32;
use usgp_disk::gpt::{ENTRY_COUNT, ENTRY_SIZE};
use usgp_disk::mbr::{self, Lba0};
use usgp_disk::{
    BlockDevice, FileBlockDevice, GptCopy, GptError, GptLimits, MemBlockDevice, WindowsUefiLayout,
    WipePlan, parse_gpt, wipe_and_write,
};

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Writes `l` onto a fresh in-memory disk through the real executor.
fn try_written(l: &WindowsUefiLayout) -> TestResult<MemBlockDevice> {
    let mut dev = MemBlockDevice::new(l.disk_bytes(), l.block)?;
    let wipe = WipePlan::for_disk(l, &[])?;
    wipe_and_write(&mut dev, &auth_for(l.disk_bytes(), l.block)?, &wipe, l)?;
    Ok(dev)
}

macro_rules! written {
    ($l:expr) => {
        try_written($l).unwrap()
    };
}

fn try_read_lba(dev: &mut dyn BlockDevice, lba: u64) -> std::io::Result<Vec<u8>> {
    let b = dev.logical_sector();
    let mut buf = vec![0u8; b as usize];
    dev.read_at(lba * u64::from(b), &mut buf)?;
    Ok(buf)
}

macro_rules! read_lba {
    ($dev:expr, $lba:expr) => {
        try_read_lba($dev, $lba).unwrap()
    };
}

macro_rules! write_lba {
    ($dev:expr, $lba:expr, $buf:expr) => {{
        let b = u64::from($dev.logical_sector());
        $dev.write_at($lba * b, $buf).unwrap();
    }};
}

fn last_lba(dev: &dyn BlockDevice) -> u64 {
    dev.len() / u64::from(dev.logical_sector()) - 1
}

/// Recomputes HeaderCRC32 over the first 92 bytes (field zeroed).
fn reseal_header(h: &mut [u8]) {
    h[16..20].fill(0);
    let c = crc32(&h[..92]);
    h[16..20].copy_from_slice(&c.to_le_bytes());
}

fn parse(dev: &mut dyn BlockDevice) -> Result<usgp_disk::GptView, GptError> {
    parse_gpt(dev, &GptLimits::default())
}

#[test]
fn crc_vectors() {
    // CRC-32 check values for the reflected 0x04C11DB7 algorithm
    // (OPEN-GPT-1 parameters, plan §1.2(c)).
    assert_eq!(crc32(b""), 0);
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    assert_eq!(
        crc32(b"The quick brown fox jumps over the lazy dog"),
        0x414F_A339
    );
    let mut c = usgp_disk::crc32::Crc32::new();
    c.update(b"12345");
    c.update(b"6789");
    assert_eq!(c.finish(), 0xCBF4_3926);
}

#[test]
fn roundtrip_512_and_4096() {
    for (lg, ph) in [(512, 512), (512, 4096), (4096, 4096)] {
        let l = layout(128 * GB, lg, ph, 1).unwrap();
        let mut dev = written!(&l);
        let v = parse(&mut dev).unwrap();
        assert!(l.gpt_plan().unwrap().matches(&v));
        assert_eq!(v.disk_guid, l.disk_guid);
        assert_eq!(v.entries.len(), 4);
        for ((slot, e), p) in v.entries.iter().zip(l.parts()) {
            assert_eq!(*slot + 1, p.number);
            assert_eq!(e.type_guid, p.type_guid);
            assert_eq!(e.unique_guid, p.unique_guid);
            assert_eq!((e.first_lba, e.last_lba), (p.first_lba, p.last_lba));
            assert_eq!(e.attributes, p.attributes);
            assert_eq!(e.name_lossy(), "");
        }
    }
}

#[test]
fn roundtrip_random_sizes() {
    let mut rng = TestRng::new(99);
    for lg in [512u32, 4096] {
        for _ in 0..25 {
            let size = round_down(64 * GB + rng.next_u64() % (20_000 * GB), lg);
            let l = layout(size, lg, lg, rng.next_u64()).unwrap();
            let mut dev = written!(&l);
            let v = parse(&mut dev).unwrap();
            assert!(l.gpt_plan().unwrap().matches(&v), "{lg} {size}");
        }
    }
}

#[test]
fn entries_16k() {
    for (lg, first) in [(512u32, 34u64), (4096, 6)] {
        let l = layout(128 * GB, lg, lg, 2).unwrap();
        let mut dev = written!(&l);
        let v = parse(&mut dev).unwrap();
        assert_eq!(v.entry_count, 128);
        assert_eq!(v.entry_size, 128);
        assert_eq!(u64::from(ENTRY_COUNT * ENTRY_SIZE), 16_384);
        assert_eq!(v.first_usable, first, "{lg}");
        assert_eq!(v.primary_array_lba, 2);
        let arr = 16_384 / u64::from(lg);
        assert_eq!(v.backup_array_lba, v.total_lbas - 1 - arr);
        assert_eq!(v.last_usable, v.backup_array_lba - 1);
    }
}

#[test]
fn backup_mirrors_primary() {
    let l = layout(100 * GB, 512, 512, 3).unwrap();
    let mut dev = written!(&l);
    let last = last_lba(&dev);
    let p = read_lba!(&mut dev, 1);
    let b = read_lba!(&mut dev, last);
    // MyLBA and AlternateLBA swapped.
    assert_eq!(&p[24..32], &1u64.to_le_bytes());
    assert_eq!(&p[32..40], &last.to_le_bytes());
    assert_eq!(&b[24..32], &last.to_le_bytes());
    assert_eq!(&b[32..40], &1u64.to_le_bytes());
    // Same usable range, disk GUID, entry count/size, array CRC.
    assert_eq!(&p[40..72], &b[40..72]);
    assert_eq!(&p[80..92], &b[80..92]);
    // Arrays identical.
    let arr_len = 16_384usize;
    let mut pa = vec![0u8; arr_len];
    let mut ba = vec![0u8; arr_len];
    dev.read_at(2 * 512, &mut pa).unwrap();
    let b_arr_lba = u64::from_le_bytes(b[72..80].try_into().unwrap());
    dev.read_at(b_arr_lba * 512, &mut ba).unwrap();
    assert_eq!(pa, ba);
    // Header fields as UEFI requires.
    assert_eq!(&p[0..8], b"EFI PART");
    assert_eq!(&p[8..12], &0x0001_0000u32.to_le_bytes());
    assert_eq!(&p[12..16], &92u32.to_le_bytes());
    assert_eq!(&p[20..24], &[0, 0, 0, 0]);
    assert!(p[92..].iter().all(|&x| x == 0));
    assert_eq!(
        u32::from_le_bytes(p[88..92].try_into().unwrap()),
        crc32(&pa)
    );
}

#[test]
fn protective_mbr_as_uefi_defines() {
    let l = layout(100 * GB, 512, 512, 4).unwrap();
    let mut dev = written!(&l);
    let m = read_lba!(&mut dev, 0);
    assert!(
        m[..446].iter().all(|&x| x == 0),
        "boot code, signature, unknown zero"
    );
    let r = &m[446..462];
    assert_eq!(r[0], 0x00);
    assert_eq!(&r[1..4], &[0x00, 0x02, 0x00]);
    assert_eq!(r[4], 0xEE);
    assert_eq!(&r[5..8], &[0xFF, 0xFF, 0xFF]);
    assert_eq!(&r[8..12], &1u32.to_le_bytes());
    let total = l.total_lbas;
    assert_eq!(&r[12..16], &u32::try_from(total - 1).unwrap().to_le_bytes());
    assert!(m[462..510].iter().all(|&x| x == 0), "records 2-4 zero");
    assert_eq!(&m[510..512], &[0x55, 0xAA]);
    assert_eq!(mbr::read_lba0(&m), Lba0::Protective);
}

#[test]
fn protective_mbr_size_saturates_beyond_32_bits() {
    // 4 TB at 512-byte sectors is more than 2^32 sectors.
    let l = layout(4_000 * GB, 512, 512, 5).unwrap();
    let mut dev = written!(&l);
    let m = read_lba!(&mut dev, 0);
    assert_eq!(&m[458..462], &[0xFF, 0xFF, 0xFF, 0xFF]);
    // 4Kn: the whole block is the MBR plus zeros.
    let l = layout(round_down(128 * GB, 4096), 4096, 4096, 5).unwrap();
    let mut dev = written!(&l);
    let m = read_lba!(&mut dev, 0);
    assert_eq!(m.len(), 4096);
    assert_eq!(&m[510..512], &[0x55, 0xAA]);
    assert!(m[512..].iter().all(|&x| x == 0));
}

#[test]
fn readback_detects_tamper_primary_header() {
    let l = layout(100 * GB, 512, 512, 6).unwrap();
    let mut dev = written!(&l);
    let mut h = read_lba!(&mut dev, 1);
    h[60] ^= 1; // inside DiskGUID
    write_lba!(&mut dev, 1, &h);
    assert!(matches!(
        parse(&mut dev),
        Err(GptError::Header {
            copy: GptCopy::Primary,
            reason: "HeaderCRC32"
        })
    ));
}

#[test]
fn readback_detects_tamper_primary_array() {
    let l = layout(round_down(100 * GB, 4096), 4096, 4096, 7).unwrap();
    let mut dev = written!(&l);
    let mut a = read_lba!(&mut dev, 2);
    a[40] ^= 0x80; // EndingLBA of entry 0
    write_lba!(&mut dev, 2, &a);
    assert!(matches!(
        parse(&mut dev),
        Err(GptError::Array {
            copy: GptCopy::Primary,
            reason: "PartitionEntryArrayCRC32"
        })
    ));
}

#[test]
fn readback_detects_tamper_backup() {
    let l = layout(100 * GB, 512, 512, 8).unwrap();
    let mut dev = written!(&l);
    let last = last_lba(&dev);
    let mut h = read_lba!(&mut dev, last);
    h[0] = b'X';
    write_lba!(&mut dev, last, &h);
    assert!(matches!(
        parse(&mut dev),
        Err(GptError::Header {
            copy: GptCopy::Backup,
            reason: "signature"
        })
    ));

    // Backup array corrupted.
    let mut dev = written!(&l);
    let arr_lba = last - 32;
    let mut a = read_lba!(&mut dev, arr_lba);
    a[0] ^= 1;
    write_lba!(&mut dev, arr_lba, &a);
    assert!(matches!(
        parse(&mut dev),
        Err(GptError::Array {
            copy: GptCopy::Backup,
            ..
        })
    ));
}

#[test]
fn backup_with_different_disk_guid_refused() {
    let l = layout(100 * GB, 512, 512, 9).unwrap();
    let mut dev = written!(&l);
    let last = last_lba(&dev);
    let mut h = read_lba!(&mut dev, last);
    h[56] ^= 1;
    reseal_header(&mut h);
    write_lba!(&mut dev, last, &h);
    assert!(matches!(
        parse(&mut dev),
        Err(GptError::BackupMismatch("DiskGUID"))
    ));
}

#[test]
fn my_lba_must_match_where_read() {
    let l = layout(100 * GB, 512, 512, 10).unwrap();
    let mut dev = written!(&l);
    let last = last_lba(&dev);
    // Put the primary header where the backup belongs.
    let p = read_lba!(&mut dev, 1);
    write_lba!(&mut dev, last, &p);
    assert!(matches!(
        parse(&mut dev),
        Err(GptError::Header {
            copy: GptCopy::Backup,
            reason: "MyLBA is not the LBA it was read from"
        })
    ));
}

#[test]
fn nonzero_reserved_and_tail_refused() {
    let l = layout(100 * GB, 512, 512, 11).unwrap();
    for off in [20usize, 100, 511] {
        let mut dev = written!(&l);
        let mut h = read_lba!(&mut dev, 1);
        h[off] = 1;
        reseal_header(&mut h);
        write_lba!(&mut dev, 1, &h);
        assert!(
            matches!(
                parse(&mut dev),
                Err(GptError::Header {
                    copy: GptCopy::Primary,
                    ..
                })
            ),
            "offset {off}"
        );
    }
}

/// Rewrites entry 0 in both arrays and reseals both headers.
fn rewrite_entry0(dev: &mut MemBlockDevice, edit: &dyn Fn(&mut [u8])) -> std::io::Result<()> {
    let last = last_lba(dev);
    for (hdr_lba, arr_lba) in [(1u64, 2u64), (last, last - 32)] {
        let mut arr = vec![0u8; 16_384];
        dev.read_at(arr_lba * 512, &mut arr)?;
        edit(&mut arr[..128]);
        dev.write_at(arr_lba * 512, &arr)?;
        let mut h = try_read_lba(dev, hdr_lba)?;
        h[88..92].copy_from_slice(&crc32(&arr).to_le_bytes());
        reseal_header(&mut h);
        dev.write_at(hdr_lba * 512, &h)?;
    }
    Ok(())
}

type Edit = Box<dyn Fn(&mut [u8])>;

#[test]
fn entry_rules_checked_even_with_valid_crcs() {
    let l = layout(100 * GB, 512, 512, 12).unwrap();
    let msr_first = l.msr.first_lba;
    let cases: Vec<(&str, Edit)> = vec![
        (
            "overlaps another partition",
            Box::new(move |e: &mut [u8]| e[40..48].copy_from_slice(&msr_first.to_le_bytes())),
        ),
        (
            "outside the usable range",
            Box::new(|e: &mut [u8]| e[32..40].copy_from_slice(&1u64.to_le_bytes())),
        ),
        (
            "StartingLBA after EndingLBA",
            Box::new(|e: &mut [u8]| e[40..48].copy_from_slice(&2047u64.to_le_bytes())),
        ),
        (
            "undefined attribute bits set",
            Box::new(|e: &mut [u8]| e[48] = 0b1000),
        ),
        (
            "nil unique GUID",
            Box::new(|e: &mut [u8]| e[16..32].fill(0)),
        ),
    ];
    for (want, edit) in cases {
        let mut dev = written!(&l);
        rewrite_entry0(&mut dev, &*edit).unwrap();
        match parse(&mut dev) {
            Err(GptError::Entry { reason, .. }) => assert_eq!(reason, want),
            other => panic!("{want}: {other:?}"),
        }
    }
}

#[test]
fn no_protective_mbr_refused() {
    let l = layout(100 * GB, 512, 512, 13).unwrap();
    let mut dev = written!(&l);
    write_lba!(&mut dev, 0, &[0u8; 512]);
    assert!(matches!(parse(&mut dev), Err(GptError::NoProtectiveMbr(_))));
    let mut legacy = [0u8; 512];
    legacy[446 + 4] = 0x07;
    legacy[446 + 8..446 + 12].copy_from_slice(&2048u32.to_le_bytes());
    legacy[446 + 12..446 + 16].copy_from_slice(&100_000u32.to_le_bytes());
    legacy[510] = 0x55;
    legacy[511] = 0xAA;
    write_lba!(&mut dev, 0, &legacy);
    assert!(matches!(
        parse(&mut dev),
        Err(GptError::NoProtectiveMbr("legacy MBR"))
    ));
    match mbr::read_lba0(&legacy) {
        Lba0::Legacy(r) => {
            assert_eq!(r.len(), 1);
            assert_eq!((r[0].slot, r[0].os_type, r[0].start_lba), (1, 0x07, 2048));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn blank_and_short_devices_refused() {
    let mut blank = MemBlockDevice::new(100 * GB, 512).unwrap();
    assert!(matches!(
        parse(&mut blank),
        Err(GptError::NoProtectiveMbr(_))
    ));
    let mut tiny = MemBlockDevice::new(16 * 512, 512).unwrap();
    assert!(matches!(
        parse(&mut tiny),
        Err(GptError::DeviceTooSmall { .. })
    ));
    let mut empty = MemBlockDevice::new(0, 512).unwrap();
    assert!(matches!(
        parse(&mut empty),
        Err(GptError::DeviceTooSmall { .. })
    ));
}

#[test]
fn other_sector_sizes_refused_by_parser() {
    for s in [520u32, 1024, 2048, 8192] {
        let mut dev = MemBlockDevice::new(u64::from(s) * 100_000, s).unwrap();
        assert!(matches!(
            parse(&mut dev),
            Err(GptError::UnsupportedSectorSize(x)) if x == s
        ));
    }
}

#[test]
fn oversized_entry_count_hits_limit_before_reading() {
    let l = layout(100 * GB, 512, 512, 14).unwrap();
    let mut dev = written!(&l);
    let mut h = read_lba!(&mut dev, 1);
    h[80..84].copy_from_slice(&u32::MAX.to_le_bytes());
    reseal_header(&mut h);
    write_lba!(&mut dev, 1, &h);
    assert!(matches!(parse(&mut dev), Err(GptError::Limit(_))));
    // Entry size not 128 × 2^n.
    let mut dev = written!(&l);
    let mut h = read_lba!(&mut dev, 1);
    h[84..88].copy_from_slice(&384u32.to_le_bytes());
    reseal_header(&mut h);
    write_lba!(&mut dev, 1, &h);
    assert!(matches!(
        parse(&mut dev),
        Err(GptError::Header {
            reason: "SizeOfPartitionEntry",
            ..
        })
    ));
    // Header size over the block.
    let mut dev = written!(&l);
    let mut h = read_lba!(&mut dev, 1);
    h[12..16].copy_from_slice(&513u32.to_le_bytes());
    write_lba!(&mut dev, 1, &h);
    assert!(matches!(
        parse(&mut dev),
        Err(GptError::Header {
            reason: "HeaderSize",
            ..
        })
    ));
}

fn tmp(name: &str) -> std::io::Result<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("usgp-disk-tests");
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join(format!("{name}-{}.img", std::process::id())))
}

#[test]
fn loopback_file_roundtrip() {
    for lg in [512u32, 4096] {
        let path = tmp(&format!("roundtrip-{lg}")).unwrap();
        let size = round_down(70 * GB, lg);
        let l = layout(size, lg, lg, 15).unwrap();
        {
            let mut dev = FileBlockDevice::create(&path, size, lg).unwrap();
            let wipe = WipePlan::for_disk(&l, &[]).unwrap();
            wipe_and_write(&mut dev, &auth_for(size, lg).unwrap(), &wipe, &l).unwrap();
        }
        let mut dev = FileBlockDevice::open(&path, lg, false).unwrap();
        let v = parse(&mut dev).unwrap();
        assert!(l.gpt_plan().unwrap().matches(&v));
        drop(dev);
        std::fs::remove_file(&path).unwrap();
    }
}

#[test]
fn file_device_refuses_non_regular_files() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    assert!(FileBlockDevice::open(&dir, 512, false).is_err());
    #[cfg(unix)]
    {
        // A character device: refused before it is opened.
        let err = FileBlockDevice::open(std::path::Path::new("/dev/null"), 512, false).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        // A symlink to a regular file is refused too (no following).
        let target = tmp("symlink-target").unwrap();
        std::fs::write(&target, vec![0u8; 4096]).unwrap();
        let link = tmp("symlink").unwrap();
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(FileBlockDevice::open(&link, 512, false).is_err());
        std::fs::remove_file(&link).unwrap();
        std::fs::remove_file(&target).unwrap();
    }
}

#[test]
fn misaligned_or_out_of_range_io_refused() {
    let mut dev = MemBlockDevice::new(1024 * 512, 512).unwrap();
    let mut buf = [0u8; 512];
    assert!(dev.read_at(1, &mut buf).is_err());
    assert!(dev.read_at(1024 * 512, &mut buf).is_err());
    assert!(dev.write_at(0, &[0u8; 100]).is_err());
    assert!(dev.write_at(u64::MAX - 511, &[0u8; 512]).is_err());
    assert_eq!(dev.write_count(), 0);
}
