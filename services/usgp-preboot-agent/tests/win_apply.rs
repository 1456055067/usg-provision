//! Windows-only checks of the real host (plan WU-12 `tests/win_apply.rs`;
//! section 10.2). Read-only: no disk or firmware variable is written.
//! Runs on the `windows-agent` CI job, as administrator.

#![cfg(test)]
#![cfg(windows)]

use usgp_preboot_agent::host::Host;
use usgp_preboot_agent::platform_win::WinHost;
use usgp_proto::device::DeviceArch;

#[test]
fn facts_and_disks_are_read_without_writing() {
    let mut h = WinHost::open().unwrap();
    let f = h.facts().unwrap();
    assert_eq!(f.arch, DeviceArch::X64);
    assert!(!f.macs.is_empty());
    let disks = h.disks().unwrap();
    assert!(!disks.is_empty());
    // The runner's system disk hosts the running environment.
    assert!(disks.iter().any(|d| d.facts.hosts_boot_environment));
    for d in &disks {
        assert_eq!(d.kinds.len(), d.facts.partitions.len());
        // BOOT-002: every listed disk carries its interface path, which
        // the write handle is opened by.
        assert!(d.discriminator.interface_path.is_some());
    }
    // NIST-001: start-up and the reads above leave no privilege in use.
    use usgp_winapi::privilege::{self, Privilege};
    for p in [
        Privilege::SystemEnvironment,
        Privilege::Restore,
        Privilege::Backup,
        Privilege::Security,
        Privilege::CreateSymbolicLink,
    ] {
        assert_eq!(privilege::users(p), 0, "{}", p.name());
    }
}
