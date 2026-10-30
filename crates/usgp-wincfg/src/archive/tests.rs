//! Archive reader tests (plan §10 "Archive" and "Inflate").

// Test code only; same convention as `unattend/tests.rs` and `dism.rs`.
#![allow(clippy::indexing_slicing)]

use super::testkit::{CabBuilder, Op, ZipBuilder, ZipEntrySpec, deflate_fixed, deflate_stored};
use super::*;

const INF: &[u8] =
    b"[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=Net\r\nCatalogFile=net.cat\r\n";

fn lim() -> ArchiveLimits {
    ArchiveLimits::default()
}

fn check(bytes: &[u8]) -> Result<ArchiveReport, ArchiveError> {
    validate_archive(&bytes, bytes.len() as u64, &lim())
}

fn driver_zip() -> ZipBuilder {
    ZipBuilder::default()
        .entry(ZipEntrySpec::stored("drv/", b""))
        .entry(ZipEntrySpec::stored("drv/net.inf", INF))
        .entry(ZipEntrySpec::stored("drv/net.cat", b"catalog"))
        .entry(ZipEntrySpec::stored(
            "drv/net.sys",
            &[0x4D, 0x5A, 0, 1, 2, 3],
        ))
        .entry(ZipEntrySpec::stored("setup.exe", b"MZ"))
}

/// Records sink calls.
#[derive(Default)]
struct Rec {
    log: Vec<String>,
    files: Vec<(String, Vec<u8>)>,
}

impl ExtractSink for Rec {
    fn create_dir(&mut self, p: &RelPath) -> std::io::Result<()> {
        self.log.push(format!("dir {p}"));
        Ok(())
    }
    fn begin_file(&mut self, p: &RelPath, _: u64) -> std::io::Result<()> {
        self.log.push(format!("file {p}"));
        self.files.push((p.to_string(), Vec::new()));
        Ok(())
    }
    fn write(&mut self, d: &[u8]) -> std::io::Result<()> {
        self.files.last_mut().unwrap().1.extend_from_slice(d);
        Ok(())
    }
    fn end_file(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn reason(r: Result<ArchiveReport, ArchiveError>) -> &'static str {
    r.map(|_| "ok").unwrap_or_else(|e| e.reason())
}

#[test]
fn zip_stored_report_and_extract() {
    let z = driver_zip().build();
    let r = check(&z).unwrap();
    assert_eq!(r.kind, ArchiveKind::Zip);
    assert_eq!(r.entries, 5);
    assert_eq!(r.infs.len(), 1);
    assert_eq!(r.infs[0].as_str(), "drv/net.inf");
    assert_eq!(r.ignored_executables, 1);
    let mut s = Rec::default();
    extract_archive(&z.as_slice(), z.len() as u64, &lim(), &mut s).unwrap();
    assert_eq!(s.log[0], "dir drv");
    assert_eq!(s.files[0], ("drv/net.inf".into(), INF.to_vec()));
}

#[test]
fn zip_deflate_miniz_and_ours() {
    let big: Vec<u8> = (0..200_000u32)
        .map(|i| (i % 251) as u8 ^ (i / 1000) as u8)
        .collect();
    let comp = miniz_oxide::deflate::compress_to_vec(&big, 6);
    let z = driver_zip()
        .entry(ZipEntrySpec::deflated("drv/big.bin", &big, comp))
        .entry(ZipEntrySpec::deflated(
            "drv/s.bin",
            b"hello",
            deflate_stored(b"hello"),
        ))
        .build();
    let mut s = Rec::default();
    let r = extract_archive(&z.as_slice(), z.len() as u64, &lim(), &mut s).unwrap();
    assert_eq!(r.expanded, (INF.len() + 7 + 6 + 2 + big.len() + 5) as u64);
    let got = s.files.iter().find(|f| f.0 == "drv/big.bin").unwrap();
    assert_eq!(got.1, big);
}

#[test]
fn zip64_and_descriptor() {
    let mut e = ZipEntrySpec::stored("a/x.inf", INF);
    e.zip64 = true;
    let mut c = ZipEntrySpec::stored("a/net.cat", b"c");
    c.descriptor = true;
    let mut d = ZipEntrySpec::stored("a/d.bin", b"dd");
    d.descriptor = true;
    d.zip64 = true;
    let mut b = ZipBuilder::default().entry(e).entry(c).entry(d);
    b.zip64_end = true;
    let mut x = b.entries[0].clone();
    x.name = b"a/net.inf".to_vec();
    b.entries[0] = x;
    let r = check(&b.build()).unwrap();
    assert_eq!(r.infs[0].as_str(), "a/net.inf");
}

#[test]
fn empty_zip_has_no_packages() {
    let z = ZipBuilder::default().build();
    assert_eq!(reason(check(&z)), "no_inf_packages");
}

/// WU-7a item 8: `Plain` (agent packages) skips only the INF rule.
#[test]
fn plain_mode_skips_only_the_inf_rule() {
    let z = ZipBuilder::default()
        .entry(ZipEntrySpec::stored("agent.json", b"{}"))
        .entry(ZipEntrySpec::stored("setup.exe", b"MZ"))
        .build();
    assert_eq!(reason(check(&z)), "no_inf_packages");
    let r =
        validate_archive_mode(&z.as_slice(), z.len() as u64, &lim(), ArchiveMode::Plain).unwrap();
    assert!(r.infs.is_empty());
    assert_eq!(r.entries, 2);
    assert_eq!(r.ignored_executables, 1);
    // Every other bound still applies.
    let mut l = lim();
    l.max_entries = 1;
    let e = validate_archive_mode(&z.as_slice(), z.len() as u64, &l, ArchiveMode::Plain);
    assert_eq!(reason(e), "limit_exceeded");
    let mut bad = z.clone();
    let n = bad.len();
    bad.truncate(n - 4);
    assert!(
        validate_archive_mode(
            &bad.as_slice(),
            bad.len() as u64,
            &lim(),
            ArchiveMode::Plain
        )
        .is_err()
    );
    // A driver archive reads the same in either mode.
    let d = driver_zip().build();
    let a = check(&d).unwrap();
    let b =
        validate_archive_mode(&d.as_slice(), d.len() as u64, &lim(), ArchiveMode::Plain).unwrap();
    assert_eq!(a, b);
}

#[test]
fn inf_without_catalog_present_is_not_a_package() {
    let z = ZipBuilder::default()
        .entry(ZipEntrySpec::stored("a/net.inf", INF))
        .entry(ZipEntrySpec::stored("b/net.cat", b"c"))
        .build();
    assert_eq!(reason(check(&z)), "no_inf_packages");
}

#[test]
fn zip_refusals() {
    let base = || driver_zip();
    let with = |f: &dyn Fn(&mut ZipEntrySpec)| {
        let mut b = base();
        f(&mut b.entries[1]);
        b.build()
    };
    assert_eq!(reason(check(&with(&|e| e.flags = 1))), "encrypted");
    assert_eq!(reason(check(&with(&|e| e.flags = 1 << 6))), "encrypted");
    assert_eq!(reason(check(&with(&|e| e.flags = 1 << 13))), "encrypted");
    assert_eq!(reason(check(&with(&|e| e.method = 99))), "encrypted");
    assert_eq!(reason(check(&with(&|e| e.flags = 1 << 5))), "patched_data");
    for (m, n) in [
        (9u16, "deflate64"),
        (12, "bzip2"),
        (14, "lzma"),
        (93, "zstandard"),
        (95, "xz"),
    ] {
        let z = with(&|e| e.method = m);
        match check(&z) {
            Err(ArchiveError::ZipMethodUnsupported { method, name }) => {
                assert_eq!((method, name), (m, n));
            }
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(
        reason(check(&with(
            &|e| e.local_name = Some(b"drv/nex.inf".to_vec())
        ))),
        "header_mismatch"
    );
    assert_eq!(
        reason(check(&with(&|e| e.local_flags = Some(1 << 11)))),
        "header_mismatch"
    );
    assert_eq!(
        reason(check(&with(&|e| e.local_crc = Some(7)))),
        "header_mismatch"
    );
    // Same wrong CRC in both headers: caught on output.
    assert_eq!(
        reason(check(&with(&|e| {
            e.crc ^= 1;
            e.local_crc = Some(e.crc);
        }))),
        "crc_mismatch"
    );
    // Unix symlink.
    assert_eq!(
        reason(check(&with(&|e| {
            e.made_by = 3 << 8;
            e.external = 0o120_777 << 16;
        }))),
        "special_entry"
    );
    // Non-ASCII without the UTF-8 flag; and with it.
    assert_eq!(
        reason(check(&with(&|e| e.name = b"drv/n\xe9.inf".to_vec()))),
        "bad_name"
    );
    // Multi-disk.
    let mut b = base();
    b.disk = 1;
    assert_eq!(reason(check(&b.build())), "multi_disk");
    // Traversal.
    assert_eq!(
        reason(check(&with(&|e| e.name = b"../net.inf".to_vec()))),
        "bad_name"
    );
    assert_eq!(
        reason(check(&with(&|e| e.name = b"drv\\net.inf".to_vec()))),
        "bad_name"
    );
}

#[test]
fn zip_duplicates_and_overlap() {
    let z = driver_zip()
        .entry(ZipEntrySpec::stored("DRV/NET.INF", b"x"))
        .build();
    assert_eq!(reason(check(&z)), "duplicate_name");
    let mut b = driver_zip().entry(ZipEntrySpec::stored("drv/other.bin", b"x"));
    // Point the last entry at the first local header: overlap (and mismatch).
    let n = b.entries.len();
    b.entries[n - 1].local_offset = Some(0);
    let r = reason(check(&b.build()));
    assert!(r == "header_mismatch" || r == "overlap", "{r}");
    // Two central entries with the same local header.
    let mut b = driver_zip();
    let dup = b.entries[2].clone();
    let mut dup2 = dup.clone();
    dup2.local_offset = Some(0);
    b.entries.push(dup2);
    let r = reason(check(&b.build()));
    assert!(r == "duplicate_name" || r == "overlap", "{r}");
}

#[test]
fn zip_bomb_ratio() {
    let zeros = vec![0u8; 2_000_000];
    let comp = miniz_oxide::deflate::compress_to_vec(&zeros, 9);
    assert!(comp.len() * 1000 < zeros.len());
    let z = driver_zip()
        .entry(ZipEntrySpec::deflated("drv/z.bin", &zeros, comp))
        .build();
    assert_eq!(reason(check(&z)), "limit_exceeded");
    // Declared size smaller than the stream yields: budget stops it.
    let data = vec![7u8; 5000];
    let mut e = ZipEntrySpec::deflated("drv/z.bin", &data, deflate_stored(&data));
    e.usize = 10;
    let z = driver_zip().entry(e).build();
    assert_eq!(reason(check(&z)), "bad_deflate");
}

#[test]
fn zip_truncated_at_every_offset() {
    let z = driver_zip()
        .entry(ZipEntrySpec::deflated(
            "drv/s.bin",
            b"hello",
            deflate_stored(b"hello"),
        ))
        .build();
    for cut in 0..z.len() {
        let t = &z[..cut];
        assert!(check(t).is_err(), "cut {cut}");
    }
    // Every single-byte corruption: no panic.
    for i in 0..z.len() {
        let mut c = z.clone();
        c[i] ^= 0x5A;
        let _ = check(&c);
    }
}

#[test]
fn limits_respected() {
    let z = driver_zip().build();
    let mut l = lim();
    l.max_entries = 2;
    assert_eq!(
        validate_archive(&z.as_slice(), z.len() as u64, &l)
            .unwrap_err()
            .reason(),
        "limit_exceeded"
    );
    let mut l = lim();
    l.max_archive_bytes = 10;
    assert!(validate_archive(&z.as_slice(), z.len() as u64, &l).is_err());
    let mut l = lim();
    l.max_inf_bytes = 4;
    assert!(validate_archive(&z.as_slice(), z.len() as u64, &l).is_err());
}

fn driver_cab() -> CabBuilder {
    CabBuilder::default()
        .file("drv\\net.inf", INF)
        .file("drv\\net.cat", b"catalog")
        .file("drv\\net.sys", &[1, 2, 3])
}

#[test]
fn cab_none_and_mszip() {
    let mut c = driver_cab();
    c.checksums = true;
    let r = check(&c.build()).unwrap();
    assert_eq!(r.kind, ArchiveKind::Cab);
    assert_eq!(r.infs[0].as_str(), "drv/net.inf");
    c.compression = 1;
    let mut s = Rec::default();
    let bytes = c.build();
    extract_archive(&bytes.as_slice(), bytes.len() as u64, &lim(), &mut s).unwrap();
    assert_eq!(s.files[1], ("drv/net.cat".into(), b"catalog".to_vec()));
    c.reserve = (10, 3, 4);
    check(&c.build()).unwrap();
}

#[test]
fn cab_multi_block_with_history() {
    // Two 32 KiB blocks; the second is a fixed block whose matches reach
    // back into the first block's history (SRC-185 §2).
    let mut content: Vec<u8> = (0..32_768u32).map(|i| (i * 7 % 256) as u8).collect();
    let block1 = deflate_stored(&content);
    let mut ops = Vec::new();
    let mut second = Vec::new();
    while second.len() + 258 <= 32_768 - 8 {
        ops.push(Op::Match(258, 32_768));
        let start = content.len() + second.len() - 32_768;
        let all: Vec<u8> = content.iter().chain(second.iter()).copied().collect();
        second.extend_from_slice(&all[start..start + 258]);
    }
    while second.len() < 32_768 {
        ops.push(Op::Lit(9));
        second.push(9);
    }
    let block2 = deflate_fixed(&ops);
    let inf_len = INF.len();
    // Put the INF and catalog at the start; the rest is one big file.
    let mut payload = content.clone();
    payload.extend_from_slice(&second);
    content = payload;
    let mut c = CabBuilder::default()
        .file("net.inf", &content[..inf_len])
        .file("big.bin", &content[inf_len..]);
    c.compression = 1;
    c.checksums = true;
    c.mszip_blocks = Some(vec![block1, block2]);
    // The INF bytes are not a valid INF, so expect no packages, but the
    // whole folder must decode first (size and checksum checks pass).
    assert_eq!(reason(check(&c.build())), "no_inf_packages");
    // With a fresh window per block the match would be refused.
    let mut s = Rec::default();
    let b = c.build();
    let _ = extract_archive(&b.as_slice(), b.len() as u64, &lim(), &mut s);
    assert_eq!(s.files[1].1, content[inf_len..].to_vec());
}

#[test]
fn cab_refusals() {
    let mut c = driver_cab();
    c.compression = 3;
    match check(&c.build()) {
        Err(ArchiveError::CabCompressionUnsupported { type_value }) => assert_eq!(type_value, 3),
        other => panic!("{other:?}"),
    }
    let mut c = driver_cab();
    c.compression = 0x1503;
    assert_eq!(reason(check(&c.build())), "cab_compression_unsupported");
    let mut c = driver_cab();
    c.compression = 2;
    assert_eq!(reason(check(&c.build())), "cab_compression_unsupported");
    for f in [1u16, 2] {
        let mut c = driver_cab();
        c.extra_flags = f;
        assert_eq!(reason(check(&c.build())), "multi_cabinet");
    }
    let mut c = driver_cab();
    c.folder_index = Some(0xFFFE);
    assert_eq!(reason(check(&c.build())), "multi_cabinet");
    let mut c = driver_cab();
    c.folder_index = Some(1);
    assert_eq!(reason(check(&c.build())), "malformed");
    let mut c = driver_cab();
    c.version = Some((1, 2));
    assert_eq!(reason(check(&c.build())), "cab_version_unsupported");
    // Bad checksum.
    let mut c = driver_cab();
    c.checksums = true;
    let mut b = c.build();
    let n = b.len();
    b[n - 1] ^= 1;
    assert_eq!(reason(check(&b)), "cab_checksum");
    // Traversal names.
    for bad in ["..\\x.inf", "\\x.inf", "c:\\x.inf", "a\\..\\b"] {
        let c = CabBuilder::default().file(bad, INF);
        assert_eq!(reason(check(&c.build())), "bad_name", "{bad}");
    }
    // Missing CK.
    let mut c = driver_cab();
    c.compression = 1;
    c.mszip_blocks = Some(vec![deflate_stored(b"x")]);
    let mut b = c.build();
    let pos = b.windows(2).rposition(|w| w == b"CK").unwrap();
    b[pos] = b'X';
    let r = reason(check(&b));
    assert!(r == "malformed" || r == "cab_checksum", "{r}");
}

#[test]
fn cab_truncated_and_corrupted() {
    let mut c = driver_cab();
    c.compression = 1;
    c.checksums = true;
    let b = c.build();
    for cut in 0..b.len() {
        assert!(check(&b[..cut]).is_err(), "cut {cut}");
    }
    for i in 0..b.len() {
        let mut x = b.clone();
        x[i] ^= 0xA5;
        let _ = check(&x);
    }
}

#[test]
fn unknown_format() {
    assert_eq!(
        reason(check(b"hello world, not an archive")),
        "unknown_format"
    );
    assert_eq!(reason(check(b"")), "truncated");
}

/// Deterministic xorshift for the differential test.
fn rng(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}

#[test]
fn inflate_differential_against_miniz() {
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    for round in 0..300 {
        let n = (rng(&mut seed) % 70_000) as usize;
        let alphabet = 1 + (rng(&mut seed) % 255) as u8;
        let data: Vec<u8> = (0..n)
            .map(|_| (rng(&mut seed) % u64::from(alphabet)) as u8)
            .collect();
        let level = (round % 11) as u8;
        let comp = miniz_oxide::deflate::compress_to_vec(&data, level);
        let ours = inflate::inflate_slice(&comp, data.len() as u64).unwrap();
        assert_eq!(ours, data, "round {round}");
        // Random corruption: whenever we accept, miniz must agree exactly.
        if !comp.is_empty() {
            let mut bad = comp.clone();
            let i = (rng(&mut seed) as usize) % bad.len();
            bad[i] ^= 1 << (rng(&mut seed) % 8);
            if let Ok(o) = inflate::inflate_slice(&bad, 1 << 20) {
                let m = miniz_oxide::inflate::decompress_to_vec(&bad).unwrap();
                assert_eq!(o, m, "round {round}");
            }
        }
    }
    // Random garbage streams.
    for _ in 0..3000 {
        let n = (rng(&mut seed) % 64) as usize;
        let g: Vec<u8> = (0..n).map(|_| rng(&mut seed) as u8).collect();
        if let Ok(o) = inflate::inflate_slice(&g, 1 << 20) {
            let m = miniz_oxide::inflate::decompress_to_vec(&g).unwrap();
            assert_eq!(o, m);
        }
    }
}

#[test]
fn rfc1951_fixed_vectors() {
    // Literal-only and match with distance 1 (run).
    let s = deflate_fixed(&[Op::Lit(b'a'), Op::Match(10, 1), Op::Lit(b'b')]);
    assert_eq!(inflate::inflate_slice(&s, 100).unwrap(), b"aaaaaaaaaaab");
    assert_eq!(
        miniz_oxide::inflate::decompress_to_vec(&s).unwrap(),
        b"aaaaaaaaaaab"
    );
    // Distance before the start of output.
    let s = deflate_fixed(&[Op::Lit(b'a'), Op::Match(3, 2)]);
    assert!(matches!(
        inflate::inflate_slice(&s, 100),
        Err(ArchiveError::Inflate(InflateError::DistanceTooFar))
    ));
    // Length 258 and every byte value.
    let mut ops: Vec<Op> = (0..=255u8).map(Op::Lit).collect();
    ops.push(Op::Match(258, 256));
    let s = deflate_fixed(&ops);
    let out = inflate::inflate_slice(&s, 10_000).unwrap();
    assert_eq!(out, miniz_oxide::inflate::decompress_to_vec(&s).unwrap());
    assert_eq!(out.len(), 256 + 258);
}
