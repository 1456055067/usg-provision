//! Writes TFTP fuzz seed packets built by this crate's own encoders.
//!
//! Usage: `cargo run -p usgp-tftp --example gen_fuzz_seeds -- <out-dir>`
//!
//! The directory must already exist. Every seed is generated here; none
//! comes from captured traffic. Seeds starting with selector byte `0x00`
//! are raw packets for the parse/round-trip path; seeds starting with
//! `0x01` are the RRQ followed by a script for the transfer path (the
//! script format is defined by the fuzz target in WU-8; these seeds carry
//! only the leading RRQ so the target can extend them).

use std::path::PathBuf;
use std::process::ExitCode;

use usgp_tftp::{
    ErrorCode, Opcode, encode_ack, encode_data, encode_error, encode_oack, encode_request,
};

fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    let rrq_opts = encode_request(
        Opcode::Rrq,
        b"usgp-test-payload.efi",
        b"octet",
        &[(b"blksize", b"1468"), (b"tsize", b"0")],
    );
    let raw = vec![
        (
            "rrq-plain",
            encode_request(Opcode::Rrq, b"usgp-test-payload.efi", b"octet", &[]),
        ),
        ("rrq-options", rrq_opts.clone()),
        (
            "rrq-timeout-windowsize",
            encode_request(
                Opcode::Rrq,
                b"a/b.efi",
                b"OCTET",
                &[(b"timeout", b"5"), (b"windowsize", b"4")],
            ),
        ),
        ("wrq", encode_request(Opcode::Wrq, b"x", b"octet", &[])),
        ("data", encode_data(1, b"payload")),
        ("ack0", encode_ack(0)),
        ("ack1", encode_ack(1)),
        (
            "error8",
            encode_error(ErrorCode::OptionNegotiation, "rejected"),
        ),
        (
            "oack",
            encode_oack(&[(b"blksize", b"1468"), (b"tsize", b"5632")]),
        ),
    ];
    let mut out = Vec::new();
    for (name, p) in raw {
        let mut v = vec![0u8];
        v.extend_from_slice(&p);
        out.push((name, v));
    }
    let mut script = vec![1u8];
    script.extend_from_slice(&rrq_opts);
    out.push(("transfer-rrq-options", script));
    out
}

fn main() -> ExitCode {
    let Some(dir) = std::env::args_os().nth(1).map(PathBuf::from) else {
        eprintln!("usage: gen_fuzz_seeds <out-dir>");
        return ExitCode::from(2);
    };
    for (name, bytes) in seeds() {
        let path = dir.join(format!("{name}.bin"));
        if let Err(e) = std::fs::write(&path, &bytes) {
            eprintln!("write {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
        println!("{} ({} octets)", path.display(), bytes.len());
    }
    ExitCode::SUCCESS
}
