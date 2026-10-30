//! M4 WU-7a item 11 / WU-10: the Windows platform implements every engine
//! `Platform` method itself, none of them refuses with `Unsupported`, and
//! the trait has no default bodies left to fall back on.
//!
//! Calling the M4 methods on the real platform needs Windows PE, a target
//! volume and DISM, and has side effects, so this test reads the sources
//! instead (on every host, so the CI hosts catch a regression too); the
//! compiler enforces the rest now that the defaults are gone. The lab
//! (MT-3) exercises the calls.

// COMPLIANCE MAPPING:
// - NIST 800-53: SA-11 (Developer Testing and Evaluation)
// - NIST 800-53: CM-7 - no M4 step silently unsupported on Windows.
// - DECISION: docs/decisions/0024 item 4

#![cfg(test)]

use std::path::Path;

fn read(rel: &str) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(root.join(rel)).expect(rel)
}

/// The text from `start` to the matching closing brace at column 0.
fn block<'a>(text: &'a str, start: &str) -> &'a str {
    let i = text
        .find(start)
        .unwrap_or_else(|| panic!("{start} not found"));
    let rest = &text[i..];
    let end = rest.find("\n}\n").expect("block end");
    &rest[..=end]
}

/// The method names declared in a trait block, and whether any has a body.
fn trait_methods(block: &str) -> (Vec<String>, bool) {
    let mut names = Vec::new();
    let mut has_body = false;
    let mut decl = String::new();
    for line in block.lines().skip(1) {
        let t = line.trim_start();
        if decl.is_empty() && !t.starts_with("fn ") {
            continue;
        }
        decl.push_str(t);
        decl.push(' ');
        if t.ends_with(';') || t.ends_with('{') {
            if t.ends_with('{') {
                has_body = true;
            }
            let name = decl
                .trim_start_matches("fn ")
                .split(['(', '<'])
                .next()
                .unwrap_or_default()
                .trim()
                .to_owned();
            names.push(name);
            decl.clear();
        }
    }
    (names, has_body)
}

/// The body of method `name` inside an impl block.
fn method_body<'a>(imp: &'a str, name: &str) -> Option<&'a str> {
    let i = imp.find(&format!("    fn {name}("))?;
    let rest = &imp[i..];
    let end = rest.find("\n    }\n")?;
    Some(&rest[..end])
}

#[test]
fn every_platform_method_is_implemented_on_windows() {
    let trait_src = read("../../crates/usgp-deploy/src/platform.rs");
    let (methods, has_body) = trait_methods(block(&trait_src, "pub trait Platform {"));
    assert!(!has_body, "Platform has a default body again: {methods:?}");
    for m in [
        "open_target",
        "stage_sink",
        "dism_add_driver",
        "dism_list_drivers",
        "remove_staging",
        "staging_exists",
        "write_protected_file",
        "stage_archive_file",
        "create_target_file",
        "agent_binary",
    ] {
        assert!(
            methods.iter().any(|n| n == m),
            "{m} missing from {methods:?}"
        );
    }

    let win = read("src/platform_win.rs");
    let imp = block(&win, "impl Platform for WinPlatform<'_> {");
    for m in &methods {
        let body = method_body(imp, m).unwrap_or_else(|| panic!("WinPlatform lacks {m}"));
        assert!(
            !body.contains("Unsupported"),
            "WinPlatform::{m} refuses with Unsupported"
        );
    }
}

#[test]
fn every_post_setup_method_is_implemented() {
    let trait_src = read("../../crates/usgp-deploy/src/postsetup.rs");
    let (methods, has_body) = trait_methods(block(&trait_src, "pub trait PostSetupPlatform {"));
    assert!(!has_body);
    assert!(methods.len() >= 11, "{methods:?}");
    let imp_src = read("src/installed.rs");
    let imp = block(
        &imp_src,
        "impl<A: AccountOps> PostSetupPlatform for InstalledPlatform<A> {",
    );
    for m in &methods {
        let body = method_body(imp, m).unwrap_or_else(|| panic!("InstalledPlatform lacks {m}"));
        assert!(
            !body.contains("Unsupported"),
            "{m} refuses with Unsupported"
        );
    }
    let win = read("src/postsetup_win.rs");
    let acct = block(&win, "impl AccountOps for WinAccount {");
    for m in ["lock", "unlock", "set_admin_password"] {
        assert!(method_body(acct, m).is_some(), "WinAccount lacks {m}");
    }
}
