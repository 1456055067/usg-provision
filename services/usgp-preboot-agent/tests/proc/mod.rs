//! Runs the agent binary with a bounded wait, so a hang fails the test in
//! seconds instead of holding the CI job. Standard input is either null
//! (EOF at once) or a fixed script followed by EOF.

#![cfg(test)]
#![allow(dead_code)]

use std::io::{Read, Write};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// Most time one run of the binary may take in a test.
pub const LIMIT: Duration = Duration::from_secs(60);

/// Runs `cmd` with `input` on standard input (`None`: null), and kills it
/// and fails the test if it is still running after `limit`.
pub fn run(mut cmd: Command, input: Option<&[u8]>, limit: Duration) -> Output {
    cmd.stdin(if input.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn the agent");
    if let (Some(data), Some(mut stdin)) = (input, child.stdin.take()) {
        stdin.write_all(data).expect("write stdin");
        // Dropped here: the agent sees EOF after the script.
    }
    let mut out = child.stdout.take().expect("stdout");
    let mut err = child.stderr.take().expect("stderr");
    let t_out = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = out.read_to_end(&mut b);
        b
    });
    let t_err = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = err.read_to_end(&mut b);
        b
    });
    let t0 = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().expect("wait") {
            break s;
        }
        if t0.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            let stdout = t_out.join().unwrap_or_default();
            panic!(
                "the agent did not exit within {limit:?}; stdout so far:\n{}",
                String::from_utf8_lossy(&stdout)
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    Output {
        status,
        stdout: t_out.join().unwrap_or_default(),
        stderr: t_err.join().unwrap_or_default(),
    }
}
