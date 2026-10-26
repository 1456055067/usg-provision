//! Writes DHCP fuzz seed packets built by this crate's own request builder.
//!
//! Usage: `cargo run -p usgp-dhcp --example gen_fuzz_seeds -- <out-dir>`
//!
//! The directory is created if missing. Every seed is generated here from
//! `usgp_dhcp::craft::RequestBuilder`; none comes from captured traffic.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::ExitCode;

use usgp_dhcp::craft::RequestBuilder;

fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    let tag71 = vec![71, 4, 0, 0, 0, 0, 255];
    let relay = Ipv4Addr::new(10, 20, 2, 1);
    let mut file = vec![93, 2, 0, 7, 255];
    file.resize(128, 0);
    let mut sname = vec![54, 4, 10, 20, 1, 2, 255];
    sname.resize(64, 0);
    vec![
        ("discover", RequestBuilder::pxe_discover().build()),
        (
            "discover-relayed-opt82",
            RequestBuilder::pxe_discover()
                .giaddr(relay)
                .hops(1)
                .option(82, vec![1, 4, b'e', b't', b'h', b'0', 2, 2, 0, 1])
                .build(),
        ),
        (
            "request-server-id",
            RequestBuilder::pxe_request()
                .option(54, vec![10, 20, 1, 2])
                .build(),
        ),
        (
            "request-tag71",
            RequestBuilder::pxe_request()
                .ciaddr(Ipv4Addr::new(10, 20, 1, 50))
                .option(43, tag71)
                .build(),
        ),
        (
            "discover-overload-3",
            RequestBuilder::pxe_discover()
                .without(93)
                .option(52, vec![3])
                .file_area(file)
                .sname_area(sname)
                .build(),
        ),
        (
            "discover-multi-arch",
            RequestBuilder::pxe_discover()
                .set_option(93, vec![0, 0, 0, 7, 0, 11])
                .set_option(60, b"PXEClient".to_vec())
                .build(),
        ),
        (
            // An arbitrary non-PXE class string (RFC 2132 §9.13).
            "discover-non-pxe",
            RequestBuilder::pxe_discover()
                .set_option(60, b"usgp-non-pxe-client".to_vec())
                .build(),
        ),
    ]
}

fn main() -> ExitCode {
    let Some(dir) = std::env::args_os().nth(1).map(PathBuf::from) else {
        eprintln!("usage: gen_fuzz_seeds <out-dir>");
        return ExitCode::from(2);
    };
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("create {}: {e}", dir.display());
        return ExitCode::FAILURE;
    }
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
