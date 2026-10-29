//! Writes fuzz seed files made only by our own `WimBuilder` and XPRESS
//! test encoder (decision 0006 items 1-3; plan WU-9).
//!
//! Usage: `cargo run -p usgp-image --features testkit --example
//! gen_fuzz_seeds -- <corpus-dir>`. Writes `<corpus-dir>/<target>/*.bin`
//! for the targets `wim_header`, `wim_xml`, `wim_lookup`, `wim_check`,
//! `xpress_chunk`, and (M3, WU-4 for WU-14) `wim_metadata` (a decoded
//! metadata resource) and `wim_apply_plan` (a whole WIM file with a
//! directory tree, for metadata → plan → `MemorySink`).

// COMPLIANCE MAPPING:
// - NIST 800-53: SA-11 (Developer Testing and Evaluation)
// - DECISION: docs/decisions/0006-wim-format-by-black-box-test-files.md

#[cfg(feature = "testkit")]
fn main() -> std::process::ExitCode {
    match seeds::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("gen_fuzz_seeds: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(feature = "testkit"))]
fn main() -> std::process::ExitCode {
    eprintln!("gen_fuzz_seeds: build with --features testkit");
    std::process::ExitCode::from(2)
}

#[cfg(feature = "testkit")]
mod seeds {
    use std::io;
    use std::path::{Path, PathBuf};

    use usgp_image::Compression;
    use usgp_image::testkit::builder::pseudorandom;
    use usgp_image::testkit::tree::rel_link_data;
    use usgp_image::testkit::{BuildInfo, NodeSpec, TreeSpec, WimBuilder, xpress_enc};
    use usgp_image::wim::xml::encode_utf16;

    fn slice(b: &[u8], offset: u64, len: u64) -> io::Result<Vec<u8>> {
        let bad = || io::Error::new(io::ErrorKind::InvalidData, "builder layout");
        let s = usize::try_from(offset).map_err(|_| bad())?;
        let n = usize::try_from(len).map_err(|_| bad())?;
        let e = s.checked_add(n).ok_or_else(bad)?;
        b.get(s..e).map(<[u8]>::to_vec).ok_or_else(bad)
    }

    fn write(dir: &Path, target: &str, name: &str, data: &[u8]) -> io::Result<()> {
        let d = dir.join(target);
        std::fs::create_dir_all(&d)?;
        std::fs::write(d.join(format!("{name}.bin")), data)
    }

    pub(super) fn run() -> io::Result<()> {
        let out: PathBuf = std::env::args_os()
            .nth(1)
            .map(PathBuf::from)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "usage: gen_fuzz_seeds <corpus-dir>",
                )
            })?;
        let files: Vec<(&str, (Vec<u8>, BuildInfo))> = vec![
            (
                "none-1",
                WimBuilder::new(Compression::None).image("a", "b").build()?,
            ),
            (
                "xpress-1",
                WimBuilder::new(Compression::Xpress)
                    .image("a", "b")
                    .build()?,
            ),
            (
                "xpress-3-integrity-boot",
                WimBuilder::new(Compression::Xpress)
                    .image("one", "first")
                    .image("two", "second")
                    .image("three", "third")
                    .integrity(true)
                    .boot_index(2)
                    .build()?,
            ),
            (
                "lzx-flags",
                WimBuilder::new(Compression::Xpress)
                    .image("a", "b")
                    .header_flags(0x0004_0082)
                    .build()?,
            ),
        ];
        for (name, (bytes, info)) in &files {
            write(&out, "wim_check", name, bytes)?;
            write(&out, "wim_header", name, &slice(bytes, 0, 208)?)?;
            write(
                &out,
                "wim_lookup",
                name,
                &slice(bytes, info.lookup.offset, info.lookup.stored_size)?,
            )?;
            write(
                &out,
                "wim_xml",
                name,
                &slice(bytes, info.xml.offset, info.xml.stored_size)?,
            )?;
        }
        write(
            &out,
            "wim_xml",
            "entities",
            &encode_utf16(
                "<WIM><IMAGE INDEX=\"1\"><NAME>a &amp; &#x42;</NAME><X><Y>z</Y></X></IMAGE></WIM>",
            ),
        )?;
        let text = b"the quick brown fox jumps over the lazy dog ".repeat(800);
        let chunk = text.get(..32768).unwrap_or(&text);
        write(&out, "xpress_chunk", "text", &xpress_enc::compress(chunk))?;
        write(
            &out,
            "xpress_chunk",
            "zeros",
            &xpress_enc::compress(&[0u8; 32768]),
        )?;
        write(
            &out,
            "xpress_chunk",
            "random",
            &xpress_enc::compress(&pseudorandom(4096, 7)),
        )?;
        write(
            &out,
            "xpress_chunk",
            "literals",
            &xpress_enc::compress_literals(b"literal only data"),
        )?;

        // M3: metadata and apply seeds (synthetic trees only).
        let small = TreeSpec::new(vec![
            NodeSpec::file("a.txt", b"a\n").short("A.TXT"),
            NodeSpec::file("s.txt", b"main").stream("usgp-s", b"named"),
            NodeSpec::dir(
                "d",
                vec![
                    NodeSpec::file("h1", b"linked").link(7),
                    NodeSpec::file("h2", b"linked").link(7),
                    NodeSpec::symlink("l", false, &rel_link_data("h1")),
                ],
            ),
        ]);
        write(&out, "wim_metadata", "small", &small.encode().bytes)?;
        write(
            &out,
            "wim_metadata",
            "sample",
            &TreeSpec::sample().encode().bytes,
        )?;
        for (name, c) in [("none", Compression::None), ("xpress", Compression::Xpress)] {
            let (bytes, _) = WimBuilder::new(c)
                .tree_image("seed", "d", small.clone())
                .build()?;
            write(&out, "wim_apply_plan", name, &bytes)?;
        }
        Ok(())
    }
}
