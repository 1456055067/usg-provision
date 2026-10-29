//! Start-up tests for the `usgp-preboot-agent` binary.
//!
//! `--self-test` is the fail-closed FIPS check (decision 0001, NIST 800-53
//! SC-13; plan section 1.2(d)): exit 0 only in FIPS mode. A run without a
//! usable configuration refuses to start.

#![cfg(test)]

mod proc;

use std::process::{Command, Output};

/// Runs the binary with `args`, standard input null, bounded in time.
fn run(args: &[&std::ffi::OsStr]) -> Output {
    let mut c = agent();
    c.args(args);
    proc::run(c, None, proc::LIMIT)
}

fn agent() -> Command {
    Command::new(env!("CARGO_BIN_EXE_usgp-preboot-agent"))
}

#[test]
fn self_test_passes_in_fips_mode() {
    let out = run(&["--self-test".as_ref()]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "exit {:?}; {stdout}{stderr}",
        out.status.code()
    );
    assert!(stderr.is_empty(), "unexpected stderr: {stderr}");
    assert!(stdout.contains("fips mode: active"), "{stdout}");
    assert!(stdout.contains("fips module: "), "{stdout}");
    assert!(stdout.contains("result: PASS"), "{stdout}");
}

#[test]
fn missing_configuration_refuses_to_start() {
    let out = run(&["--config".as_ref(), "/nonexistent/agent.toml".as_ref()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot start"));
}

#[test]
fn unknown_arguments_are_refused() {
    let out = run(&["--skip-tls".as_ref()]);
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
    let out = run(&["--config".as_ref(), cfg.as_os_str()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("verify_tls"));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A valid configuration but no server listening: the persistent
/// "cannot reach the server" screen is shown, and EOF on the null standard
/// input ends the wait with the server-unreachable code (7) and no power
/// action.
#[cfg(not(windows))]
#[test]
fn unreachable_server_shows_a_persistent_screen_until_eof() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("agent-unreachable-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let pki = usgp_crypto::test_pki::TestPki::generate().unwrap();
    std::fs::write(dir.join("anchors.pem"), pki.root.cert_pem().unwrap()).unwrap();
    for name in ["plan.pub", "content.pub"] {
        let k = usgp_crypto::SigningKey::generate().unwrap();
        std::fs::write(dir.join(name), k.verifying_key().to_spki_pem().unwrap()).unwrap();
    }
    // A port with nothing listening.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let cfg = dir.join("agent.toml");
    std::fs::write(
        &cfg,
        format!(
            "server_url = \"https://127.0.0.1:{port}\"\nserver_name = \"localhost\"\n\
             trust_anchors = \"anchors.pem\"\nplan_key_pub = \"plan.pub\"\n\
             content_key_pub = \"content.pub\"\nnetwork_wait_s = 10\nconnect_timeout_s = 2\n"
        ),
    )
    .unwrap();
    let work = dir.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let sim = dir.join("sim.toml");
    std::fs::write(
        &sim,
        format!(
            "work_dir = {work:?}\nfirmware_file = {:?}\ndhcp_addresses = [\"192.0.2.10\"]\n\
             firmware = \"uefi\"\narch = \"x64\"\nsecure_boot = \"on\"\n\
             memory_bytes = 8589934592\nmacs = [\"02:00:00:00:10:07\"]\n",
            dir.join("fw.json")
        ),
    )
    .unwrap();
    let out = run(&[
        "--config".as_ref(),
        cfg.as_os_str(),
        "--sim".as_ref(),
        sim.as_os_str(),
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(7), "{stdout}");
    assert!(
        stdout.contains("Cannot reach the provisioning server"),
        "{stdout}"
    );
    assert!(
        stdout.contains("Nothing more will happen until you act."),
        "{stdout}"
    );
    assert!(stdout.contains("Type R and Enter to restart"), "{stdout}");
    assert!(!stdout.contains("power:"), "EOF must not restart: {stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}
