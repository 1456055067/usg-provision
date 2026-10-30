//! M4 WU-5 checks on the Windows CI runner: the SYSTEM-only protected
//! DACL, the locked password page, and the local-account calls.
//!
//! The account tests act only on a throwaway local account the runner
//! creates beforehand and names in `USGP_TEST_ACCOUNT`; without it they
//! return early. The built-in Administrator (RID 500) is changed only when
//! `USGP_TEST_RID500=1` is also set (the runner VM), and is left disabled.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Testing and Evaluation), AC-3, IA-5,
//!   SC-28
//! - SPEC: specs/standards/windows-storage-firmware-api.md §20, §30, §31

#![cfg(windows)]

use std::fs::{self, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;

use usgp_winapi::account::{self, LocalAccount};
use usgp_winapi::memlock::LockedWide;
use usgp_winapi::{acl, fsquery};

/// `WRITE_DAC` | `READ_CONTROL`, from windows-sys.
fn dac_access() -> u32 {
    use windows_sys::Win32::Storage::FileSystem::{READ_CONTROL, WRITE_DAC};
    WRITE_DAC | READ_CONTROL
}

#[test]
fn protected_system_only_dacl_is_applied() {
    let dir = std::env::temp_dir().join(format!("usgp-acl-{}", std::process::id()));
    fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("job.key");
    fs::write(&path, b"x").expect("write");
    {
        let f = OpenOptions::new()
            .access_mode(dac_access())
            .open(&path)
            .expect("open with WRITE_DAC");
        acl::protect_file_system_only(&f).expect("protect");
    }
    let sddl = fsquery::sddl(&path).expect("read back");
    println!("observed: protected DACL read back as {sddl}");
    let (flags, entries) = dacl_parts(&sddl).expect("SDDL has a DACL part");
    // Topic 23 §20: SetSecurityInfo may add the auto-inherited flag (AI);
    // only "protected" (P) is required.
    assert!(flags.contains('P'), "DACL not protected: {sddl}");
    assert!(
        flags.replace("AI", "").replace('P', "").is_empty(),
        "unexpected DACL flags {flags:?}: {sddl}"
    );
    assert_eq!(
        entries,
        ["A;;FA;;;SY"],
        "exactly one entry, SYSTEM full: {sddl}"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// The DACL flags and entries of an SDDL string: the text after `D:` up to
/// the first `(`, then each parenthesised entry, up to the next part
/// (`S:`) or the end.
fn dacl_parts(sddl: &str) -> Option<(String, Vec<String>)> {
    let rest = sddl.split_once("D:")?.1;
    let rest = rest.split_once("S:").map_or(rest, |(d, _)| d);
    let (flags, aces) = rest.split_once('(').map_or((rest, ""), |(f, a)| (f, a));
    let entries = if aces.is_empty() {
        Vec::new()
    } else {
        format!("({aces}")
            .split(')')
            .filter(|s| !s.is_empty())
            .map(|s| s.trim_start_matches('(').to_owned())
            .collect()
    };
    Some((flags.to_owned(), entries))
}

#[test]
fn locked_page_holds_and_wipes_a_secret() {
    let mut w = LockedWide::new().expect("lock a page");
    w.set("Abc-123").expect("set");
    assert_eq!(w.as_wide_nul().len(), 8);
    assert_eq!(w.as_wide_nul().last(), Some(&0));
    assert!(w.set("a\0b").is_err());
    assert_eq!(w.as_wide_nul(), &[0]);
    let long = "x".repeat(LockedWide::capacity() + 1);
    assert!(w.set(&long).is_err());
    w.close().expect("unlock reports no lost lock");
}

#[test]
fn throwaway_account_password_and_flags() {
    let Ok(name) = std::env::var("USGP_TEST_ACCOUNT") else {
        println!("USGP_TEST_ACCOUNT not set; skipped");
        return;
    };
    let acct = LocalAccount::by_name(&name).expect("valid name");
    let mut pw = LockedWide::new().expect("lock");
    pw.set("Tq7!vRw2#Lm9$Kp4&Zx8@Hn3").expect("set");
    acct.set_password(&pw).expect("set password");
    pw.close().expect("unlock");
    acct.set_enabled(false).expect("disable");
    assert!(!acct.is_enabled().expect("read"));
    acct.set_enabled(true).expect("enable");
    assert!(acct.is_enabled().expect("read"));
    acct.set_enabled(false).expect("leave disabled");
}

#[test]
fn builtin_administrator_is_found_by_sid() {
    if std::env::var("USGP_TEST_RID500").as_deref() != Ok("1") {
        println!("USGP_TEST_RID500 not set; skipped");
        return;
    }
    let admin = account::builtin_administrator().expect("RID 500");
    println!("RID 500 is {}", admin.name());
    admin.set_enabled(true).expect("enable");
    admin.set_enabled(false).expect("disable again");
}
