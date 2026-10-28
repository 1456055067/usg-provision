//! Start-up tests for the `usgp-preboot-agent` binary.
//!
//! `--self-test` is the fail-closed FIPS check (decision 0001, NIST 800-53
//! SC-13; plan section 1.2(d)): exit 0 only in FIPS mode. A run without a
//! usable configuration refuses to start.

#![cfg(test)]

use std::process::Command;

fn agent() -> Command {
    Command::new(env!("CARGO_BIN_EXE_usgp-preboot-agent"))
}

#[test]
fn self_test_passes_in_fips_mode() {
    let out = agent().arg("--self-test").output().expect("spawn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "exit {:?}; {stdout}{stderr}",
        out.status.code()
    );
    assert!(stderr.is_empty(), "unexpected stderr: {stderr}");
    assert!(stdout.contains("fips mode: active"), "{stdout}");
    assert!(stdout.contains("result: PASS"), "{stdout}");
}

#[test]
fn missing_configuration_refuses_to_start() {
    let out = agent()
        .args(["--config", "/nonexistent/agent.toml"])
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot start"));
}

#[test]
fn unknown_arguments_are_refused() {
    let out = agent().arg("--skip-tls").output().expect("spawn");
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("usage"));
}

#[cfg(not(windows))]
#[test]
fn unknown_configuration_keys_refuse_start() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("agent-cfg-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("agent.toml");
    std::fs::write(
        &cfg,
        "server_url = \"https://127.0.0.1:8444\"\ntrust_anchors = \"a.pem\"\n\
         plan_key_pub = \"p.pub\"\ncontent_key_pub = \"c.pub\"\nverify_tls = false\n",
    )
    .unwrap();
    let out = agent().arg("--config").arg(&cfg).output().expect("spawn");
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("verify_tls"));
    let _ = std::fs::remove_dir_all(&dir);
}
