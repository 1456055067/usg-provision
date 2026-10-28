//! The simulated platform (feature `sim`): the whole job on a loopback
//! disk file, applied into a directory, with firmware variables in a JSON
//! file; and the other disk file left unchanged (plan section 10.1).
//!
//! Run with `cargo test -p usgp-deploy --features sim`.

// COMPLIANCE MAPPING:
// - NIST 800-53: SA-11, CM-7 (regular files only)
// - SPEC: specs/disk.md#REQ-DISK-009, #REQ-DISK-015
// - SPEC: specs/preinstall-env.md#REQ-PE-017; specs/boot-network.md#REQ-BOOT-065
#![cfg(feature = "sim")]

pub mod common;

use std::path::Path;

use common::*;
use usgp_deploy::sim::{SIM_BOOT_MARKER, SimDisk, SimPlatform};
use usgp_disk::FileBlockDevice;
use usgp_disk::gpt::{GptLimits, parse_gpt};
use usgp_proto::DiskToken;

#[test]
fn sim_platform_runs_the_whole_job() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("deploy-sim");
    let _ = std::fs::remove_dir_all(&dir);
    let work = dir.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let target = dir.join("target.img");
    drop(FileBlockDevice::create(&target, DISK_BYTES, 512).unwrap());
    let other = dir.join("other.img");
    let other_bytes = usgp_image::testkit::builder::pseudorandom(1 << 20, 5);
    std::fs::write(&other, &other_bytes).unwrap();
    let fw_file = dir.join("firmware.json");
    std::fs::write(&fw_file, br#"{"Boot0000":"010203","BootOrder":"0000"}"#).unwrap();

    let fx = Fixture::new(small_wim());
    let mut pf = SimPlatform::new(&work, &fw_file);
    pf.add_disk(SimDisk {
        token: DiskToken::from_random_bytes([0x5a; 16]),
        path: target.clone(),
        facts: facts(),
    });
    pf.add_disk(SimDisk {
        token: DiskToken::from_random_bytes([0x11; 16]),
        path: other.clone(),
        facts: facts(),
    });
    let mut link = link_for(&fx);
    let o = run(&fx, &mut pf, &mut link);
    let ok = o.result.expect("job succeeds");

    // GPT valid on the file.
    let mut dev = FileBlockDevice::open(&target, 512, false).unwrap();
    assert_eq!(
        parse_gpt(&mut dev, &GptLimits::default())
            .unwrap()
            .entries
            .len(),
        4
    );
    // Tree applied into the Windows volume's directory.
    assert_eq!(
        std::fs::read(work.join("vol-3").join("readme.txt")).unwrap(),
        b"hello\n"
    );
    // Boot files marker on the ESP.
    assert!(work.join("vol-1").join(SIM_BOOT_MARKER).is_file());
    // Firmware file: our option first, the network option kept.
    let fw: std::collections::BTreeMap<String, String> =
        serde_json::from_slice(&std::fs::read(&fw_file).unwrap()).unwrap();
    let n = ok.boot.option;
    let le = n.to_le_bytes();
    assert_eq!(fw["BootOrder"], format!("{:02x}{:02x}0000", le[0], le[1]));
    assert!(fw.contains_key(&format!("Boot{n:04X}")));
    assert_eq!(fw["Boot0000"], "010203");
    // The other disk file is unchanged.
    assert_eq!(std::fs::read(&other).unwrap(), other_bytes);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn sim_platform_rebases_links_onto_the_windows_root() {
    use usgp_image::testkit::tree::abs_link_data;
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("deploy-sim-links");
    let _ = std::fs::remove_dir_all(&dir);
    let work = dir.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let target = dir.join("target.img");
    drop(FileBlockDevice::create(&target, DISK_BYTES, 512).unwrap());
    let fw_file = dir.join("firmware.json");

    let fx = Fixture::new(link_wim());
    let mut pf = SimPlatform::new(&work, &fw_file);
    pf.set_windows_root("S:\\");
    pf.add_disk(SimDisk {
        token: DiskToken::from_random_bytes([0x5a; 16]),
        path: target,
        facts: facts(),
    });
    let mut link = link_for(&fx);
    let o = run(&fx, &mut pf, &mut link);
    assert!(o.result.is_ok(), "{:?}", o.result.err());

    let log = pf.reparse_log();
    let find = |p: &str| log.iter().find(|r| r.path == p).unwrap();
    // The reparse buffer is an 8-byte header, then the data.
    let j = find("links\\junction");
    assert!(j.rebased);
    assert_eq!(j.bytes[8..], abs_link_data("S:\\links\\target-dir", true));
    let d = find("links\\abs-dir");
    assert!(d.rebased);
    assert_eq!(d.bytes[8..], abs_link_data("S:\\links\\target-dir", false));
    let out = find("links\\junction-out");
    assert!(!out.rebased);
    assert_eq!(out.bytes[8..], abs_link_data("T:\\outside", true));
    assert!(
        work.join("vol-3")
            .join("links")
            .join("target-file.txt")
            .is_file()
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
