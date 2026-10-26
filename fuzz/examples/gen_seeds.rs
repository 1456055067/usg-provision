//! Writes the WU-8 fuzz seeds into `fuzz/corpus/{dhcp_packet,tftp_packet}/`.
//!
//! Usage (from `fuzz/`): `cargo run --example gen_seeds -- corpus`
//!
//! Every seed is built here by our own encoders (`usgp_dhcp::craft`,
//! `usgp_tftp::encode_*`); none comes from captured traffic, logs or
//! images (fuzz/README.md, seed origin rule). The seed list is recorded in
//! `fuzz/corpus/*/SOURCE.md`. Names start with `wu8-` so they never clash
//! with the seeds written by the crate examples.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use usgp_dhcp::craft::RequestBuilder;
use usgp_tftp::{Opcode, encode_ack, encode_request};

fn dhcp_seeds() -> Vec<(&'static str, Vec<u8>)> {
    let relay = Ipv4Addr::new(10, 20, 2, 1);
    vec![
        (
            "wu8-discover-opt82-255",
            RequestBuilder::pxe_discover()
                .giaddr(relay)
                .hops(1)
                .option(82, vec![0xa5; 255])
                .build(),
        ),
        (
            "wu8-discover-max-msg-1500",
            RequestBuilder::pxe_discover()
                .option(57, 1500u16.to_be_bytes().to_vec())
                .build(),
        ),
        (
            "wu8-request-ciaddr-unicast",
            RequestBuilder::pxe_request()
                .ciaddr(Ipv4Addr::new(10, 20, 1, 50))
                .option(54, vec![10, 20, 1, 2])
                .build(),
        ),
        (
            "wu8-discover-split-opt82",
            // RFC 3396: two instances of option 82 are concatenated.
            RequestBuilder::pxe_discover()
                .giaddr(relay)
                .option(82, vec![1, 4, b'e', b't'])
                .option(82, vec![b'h', b'0'])
                .build(),
        ),
        (
            "wu8-bootp-no-msg-type",
            RequestBuilder::pxe_discover().without(53).build(),
        ),
    ]
}

/// Transfer-script header (see `fuzz_targets/tftp_packet.rs`): selector 1,
/// file length (LE), config octet A, config octet B, RRQ length, RRQ.
fn script(len: u16, a: u8, b: u8, rrq: &[u8], ops: &[u8]) -> Vec<u8> {
    let mut v = vec![1u8];
    v.extend_from_slice(&len.to_le_bytes());
    v.push(a);
    v.push(b);
    v.push(u8::try_from(rrq.len()).unwrap_or(u8::MAX));
    v.extend_from_slice(rrq);
    v.extend_from_slice(ops);
    v
}

fn tftp_seeds() -> Vec<(&'static str, Vec<u8>)> {
    let name = b"usgp-test-payload.efi";
    let plain = encode_request(Opcode::Rrq, name, b"octet", &[]);
    let opts = encode_request(
        Opcode::Rrq,
        name,
        b"octet",
        &[(b"blksize", b"512"), (b"tsize", b"0")],
    );
    let tiny = encode_request(Opcode::Rrq, name, b"octet", &[(b"blksize", b"8")]);
    let netascii = encode_request(Opcode::Rrq, name, b"netascii", &[]);
    // A = 5 retries, 2 handshake retries, block-size cap index 1 (1468).
    let a = 5 | (2 << 3) | (1 << 5);
    // B = 120 s max duration, default max file size.
    let b = 120 << 1;
    // Early timer (op 5), future ACK (op 2), ACK 9 (op 3), then op 6 with
    // a raw 4-octet ACK 1.
    let mut early = vec![5u8, 2, 3, 0, 9, 6, 4];
    early.extend_from_slice(&encode_ack(1));
    vec![
        // 2000 octets, no options: ACK 1..4 completes.
        (
            "wu8-script-plain-complete",
            script(2000, a, b, &plain, &[0, 0, 0, 0]),
        ),
        // OACK then ACK 0, duplicate ACK, ACKs to completion.
        (
            "wu8-script-oack-dup-ack",
            script(1500, a, b, &opts, &[0, 1, 0, 1, 0, 0]),
        ),
        // Timer resends until the handshake cap.
        (
            "wu8-script-timeouts",
            script(1000, a, b, &plain, &[4, 4, 4, 4]),
        ),
        (
            "wu8-script-early-future-raw",
            script(700, a, b, &plain, &early),
        ),
        // Client ERROR 8 (op 7, arg 8).
        (
            "wu8-script-client-error",
            script(100, a, b, &opts, &[7 | (8 << 3)]),
        ),
        // Wrong file slice (op 7, arg 31).
        (
            "wu8-script-data-mismatch",
            script(100, a, b, &plain, &[0, 7 | (31 << 3)]),
        ),
        // blksize 8 with a 600-octet file: 76 blocks.
        ("wu8-script-blksize-8", script(600, a, b, &tiny, &[0; 80])),
        // Exact multiple of the block size: empty final block.
        (
            "wu8-script-exact-multiple",
            script(1024, a, b, &plain, &[0, 0, 0]),
        ),
        // max_file_size = len - 1: refused.
        ("wu8-script-too-large", script(100, a, b | 1, &plain, &[])),
        // netascii: refused.
        ("wu8-script-netascii", script(100, a, b, &netascii, &[])),
        // max_duration 0: the first timer ends the transfer.
        ("wu8-script-max-duration-0", script(100, a, 0, &plain, &[4])),
    ]
}

fn write_all(dir: &Path, seeds: Vec<(&'static str, Vec<u8>)>) -> Result<(), ExitCode> {
    // Create the target directory so a fresh corpus root works (CR-305).
    if let Err(e) = std::fs::create_dir_all(dir) {
        eprintln!("create {}: {e}", dir.display());
        return Err(ExitCode::FAILURE);
    }
    for (name, bytes) in seeds {
        let path = dir.join(format!("{name}.bin"));
        if let Err(e) = std::fs::write(&path, &bytes) {
            eprintln!("write {}: {e}", path.display());
            return Err(ExitCode::FAILURE);
        }
        println!("{} ({} octets)", path.display(), bytes.len());
    }
    Ok(())
}

fn main() -> ExitCode {
    let Some(root) = std::env::args_os().nth(1).map(PathBuf::from) else {
        eprintln!("usage: gen_seeds <corpus-root>");
        return ExitCode::from(2);
    };
    if let Err(c) = write_all(&root.join("dhcp_packet"), dhcp_seeds()) {
        return c;
    }
    if let Err(c) = write_all(&root.join("tftp_packet"), tftp_seeds()) {
        return c;
    }
    ExitCode::SUCCESS
}
