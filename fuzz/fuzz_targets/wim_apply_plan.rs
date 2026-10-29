//! Fuzz target `wim_apply_plan`: a whole WIM file through the verified
//! chunk reader, the verify pass and the apply into `MemorySink`
//! (`usgp-image` `apply`), and the decision 0022 re-base rule
//! (`usgp-image` `wim::reparse::prepare`) on its own.
//!
//! Input (our design, WU-14):
//!
//! - starts with the WIM signature `MSWIM\0\0\0`: the whole input is the
//!   file (the form of the `wim_apply_plan` seeds written by
//!   `crates/usgp-image/examples/gen_fuzz_seeds.rs`); image 1, root `W:\`;
//! - otherwise octet 0 selects:
//!   - bit 0 clear, apply: bits 1-2 the image index (0 to 3), bit 3 the
//!     root (`W:\` or `U:\deep\apply-here`), bit 4 set: flip the byte at
//!     the offset in the next 4 octets (u32 LE, modulo the file length)
//!     after the chunk digests are taken; the rest is the file;
//!   - bit 0 set, re-base rule: octet 1 the header flags H (0: `RP_FIX`,
//!     1: none, else the next 4 octets), octet 2 the tag T (0 symbolic
//!     link, 1 mount point, else the next 4 octets), octet 3 the +92 value
//!     M (0: 0, 1: 0x00010000, else the next 4 octets), octet 4 the root
//!     (`W:`, `W:\`, `U:\deep\apply-here`); the rest is the stored data B.
//!
//! Limits (impl-notes-wu4 "For WU-14"): `ApplyLimits::new(1 MiB)` with
//! tightened metadata and file-structure limits; `MemorySink` holds at
//! most 1 MiB.
//!
//! Invariants:
//!
//! - no panic; every refusal has a listed reason code and operator text;
//! - the verify pass and the apply agree: same refusal, or the apply
//!   succeeds with the verify pass's preview; the bytes written are at
//!   most the preview's total, which is within the limit; the target holds
//!   one path per entry;
//! - a byte flipped after the digests were taken is always refused with
//!   `content_integrity_failed` (SI-7), by both passes, and nothing is
//!   written past the failure;
//! - every reparse buffer set on the target has its tag's header (length,
//!   `Reserved` 0), and a re-based one names the apply root;
//! - re-base rule (reference model): a tag other than symbolic link or
//!   mount point, or M other than 0 or 0x00010000, is refused; M =
//!   0x00010000 copies B unchanged behind a rebuilt header; M = 0 is
//!   accepted only with `RP_FIX` and gives exactly `\??\A R` and `A R`
//!   in DISM's layout (A the root, R from the stored `\??\D:R`), Flags 0;
//!   every accepted buffer is itself well formed (accepted again as a
//!   copy), and with a drive-only root re-basing it again changes nothing.

#![no_main]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity),
//   SI-10 (Information Input Validation), SC-5 (Denial of Service
//   Protection), SA-11 (Developer Testing and Evaluation)
// - SPEC: specs/preinstall-env.md#REQ-PE-016, #REQ-PE-017
// - SPEC: specs/standards/wim.md §4, §5, §6, §6.1
// - SPEC: specs/standards/reparse-and-security-descriptors.md §2 to §5
// - DECISION: docs/decisions/0011, 0022

use libfuzzer_sys::fuzz_target;
use usgp_image::apply::{
    ApplyError, ApplyLimits, ApplyRoot, MAX_REPARSE_BYTES, MemorySink, ReparseError, apply,
    verify_pass,
};
use usgp_image::testkit::MemoryChunks;
use usgp_image::wim::header::{FLAG_RP_FIX, MAGIC};
use usgp_image::wim::metadata::{MetadataError, MetadataLimits, REPARSE_FIELD_RELATIVE, tag};
use usgp_image::wim::reparse::prepare;
use usgp_image::{NoProgress, WimError, WimLimits};

const BUDGET: u64 = 1 << 20;

fn limits() -> ApplyLimits {
    ApplyLimits {
        max_total_bytes: BUDGET,
        max_reparse_bytes: MAX_REPARSE_BYTES,
        metadata: MetadataLimits {
            max_bytes: 1 << 20,
            max_entries: 10_000,
            ..MetadataLimits::DEFAULT
        },
        wim: WimLimits {
            max_xml_bytes: 1 << 20,
            max_images: 16,
            max_lookup_bytes: 1 << 20,
            max_metadata_bytes: 1 << 20,
            max_metadata_total_bytes: 4 << 20,
            ..WimLimits::DEFAULT
        },
    }
}

const ROOTS: [&str; 3] = ["W:", "W:\\", "U:\\deep\\apply-here"];

fn root(i: u8) -> ApplyRoot {
    let text = ROOTS[usize::from(i) % ROOTS.len()];
    ApplyRoot::parse(text).expect("fixed root parses")
}

fn known(e: &ApplyError) {
    let c = e.reason_code();
    assert!(
        ApplyError::REASON_CODES.contains(&c)
            || WimError::REASON_CODES.contains(&c)
            || MetadataError::REASON_CODES.contains(&c)
            || ReparseError::REASON_CODES.contains(&c),
        "unlisted reason {e:?}"
    );
    assert!(!e.operator_message().is_empty(), "empty operator text");
}

fn header_ok(t: u32, bytes: &[u8], data: &[u8]) {
    assert_eq!(bytes.len(), data.len() + 8, "buffer length");
    assert_eq!(bytes.get(..4), Some(&t.to_le_bytes()[..]), "tag in header");
    let len = u16::try_from(data.len()).expect("data within 65535");
    assert_eq!(
        bytes.get(4..6),
        Some(&len.to_le_bytes()[..]),
        "length in header"
    );
    assert_eq!(bytes.get(6..8), Some(&[0u8, 0][..]), "Reserved not zero");
    assert_eq!(bytes.get(8..), Some(data), "data after header");
}

fn whole_file(file: &[u8], index: u32, r: &ApplyRoot, flip: Option<usize>) {
    let l = limits();
    let mut src = MemoryChunks::new(file.to_vec());
    if let Some(at) = flip {
        src.tamper(at);
    }
    let crypto = usgp_crypto::provider();
    let v = verify_pass(&mut src, index, r, &l, &mut NoProgress, crypto);
    if let Err(e) = &v {
        known(e);
    }
    let mut src = MemoryChunks::new(file.to_vec());
    if let Some(at) = flip {
        src.tamper(at);
    }
    let mut sink = MemorySink::with_limit(BUDGET);
    let a = apply(&mut src, index, r, &mut sink, &l, &mut NoProgress, crypto);
    if flip.is_some() {
        // One content chunk (inputs are under 8 MiB): every read checks it.
        for res in [v.as_ref().err(), a.as_ref().err()] {
            assert!(
                matches!(res, Some(ApplyError::ContentIntegrity { chunk: 0 })),
                "tampered file not refused by its chunk digest: {res:?}"
            );
        }
        assert!(
            sink.entries()
                .all(|(_, n)| n.data.is_empty() && n.streams.is_empty()),
            "data written from a tampered file"
        );
        return;
    }
    match (&v, &a) {
        (Ok(p), Ok(rep)) => {
            assert!(index >= 1, "image index 0 accepted");
            assert_eq!(&rep.preview, p, "apply preview differs from verify");
            assert!(p.total_bytes <= BUDGET, "total over the limit");
            assert!(
                rep.bytes_written <= p.total_bytes,
                "wrote more than the total"
            );
            let paths = u64::try_from(sink.entries().count()).unwrap_or(u64::MAX);
            assert_eq!(paths, p.entries, "one path per entry");
            let rtext = r.to_text();
            for (_, n) in sink.entries() {
                if let Some(b) = &n.reparse {
                    assert!(
                        b.tag() == tag::SYMLINK || b.tag() == tag::JUNCTION,
                        "reparse tag {:#x}",
                        b.tag()
                    );
                    header_ok(b.tag(), b.bytes(), b.data());
                    if b.rebased() {
                        let units: Vec<u16> = rtext.encode_utf16().collect();
                        let le: Vec<u8> = units.iter().flat_map(|u| u.to_le_bytes()).collect();
                        assert!(
                            b.data().windows(le.len()).any(|w| w == le),
                            "re-based buffer does not name the apply root"
                        );
                    }
                }
            }
        }
        (Err(e), Err(f)) => assert_eq!(e, f, "verify and apply refuse differently"),
        _ => panic!("verify {v:?} but apply {a:?}"),
    }
}

/// Stored data split as the reference model reads it (topic 24 §3, §4).
struct Stored {
    sub: Vec<u16>,
}

fn u16s(b: &[u8]) -> Vec<u16> {
    b.as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect()
}

fn stored(t: u32, b: &[u8]) -> Option<Stored> {
    let head = if t == tag::SYMLINK { 12 } else { 8 };
    let f = |at: usize| {
        Some(usize::from(u16::from_le_bytes([
            *b.get(at)?,
            *b.get(at + 1)?,
        ])))
    };
    let (so, sl) = (f(0)?, f(2)?);
    let path = b.get(head..)?;
    Some(Stored {
        sub: u16s(path.get(so..so.checked_add(sl)?)?),
    })
}

/// The data DISM's layout gives for substitute `sub` and print `print`.
fn layout(t: u32, sub: &[u16], print: &[u16]) -> Vec<u8> {
    let sb = u16::try_from(sub.len() * 2).unwrap_or(u16::MAX);
    let pb = u16::try_from(print.len() * 2).unwrap_or(u16::MAX);
    let mut d = Vec::new();
    d.extend_from_slice(&0u16.to_le_bytes());
    d.extend_from_slice(&sb.to_le_bytes());
    d.extend_from_slice(&sb.saturating_add(2).to_le_bytes());
    d.extend_from_slice(&pb.to_le_bytes());
    if t == tag::SYMLINK {
        d.extend_from_slice(&0u32.to_le_bytes());
    }
    for u in sub.iter().chain(&[0]).chain(print).chain(&[0]) {
        d.extend_from_slice(&u.to_le_bytes());
    }
    d
}

fn word(rest: &mut &[u8]) -> u32 {
    let mut w = [0u8; 4];
    for b in &mut w {
        if let Some((x, r)) = rest.split_first() {
            *b = *x;
            *rest = r;
        }
    }
    u32::from_le_bytes(w)
}

fn rebase_rule(input: &[u8]) {
    let [hs, ts, ms, rs, tail @ ..] = input else {
        return;
    };
    let mut rest: &[u8] = tail;
    let h = match hs {
        0 => FLAG_RP_FIX,
        1 => 0,
        _ => word(&mut rest),
    };
    let t = match ts {
        0 => tag::SYMLINK,
        1 => tag::JUNCTION,
        _ => word(&mut rest),
    };
    let m = match ms {
        0 => 0,
        1 => REPARSE_FIELD_RELATIVE,
        _ => word(&mut rest),
    };
    let r = root(*rs);
    let b = rest;
    let out = prepare(h, t, m, b, &r);
    let buf = match out {
        Ok(buf) => buf,
        Err(e) => {
            assert!(ReparseError::REASON_CODES.contains(&e.reason_code()));
            assert!(!e.to_string().is_empty());
            if t != tag::SYMLINK && t != tag::JUNCTION {
                assert_eq!(e, ReparseError::Unsupported, "unknown tag");
            }
            return;
        }
    };
    assert!(
        t == tag::SYMLINK || t == tag::JUNCTION,
        "tag {t:#x} accepted"
    );
    assert_eq!(buf.tag(), t, "tag changed");
    header_ok(t, buf.bytes(), buf.data());
    match m {
        REPARSE_FIELD_RELATIVE => {
            assert!(!buf.rebased(), "copy marked re-based");
            assert_eq!(buf.data(), b, "copy changed the data");
        }
        0 => {
            assert!(buf.rebased(), "M = 0 not re-based");
            assert!(h & FLAG_RP_FIX != 0, "re-based without RP_FIX");
            let s = stored(t, b).expect("accepted data has its fixed part");
            // \??\D:R -> R.
            let nt: Vec<u16> = "\\??\\".encode_utf16().collect();
            let after = s.sub.strip_prefix(&nt[..]).expect("substitute has \\??\\");
            let rest_r = after.get(2..).expect("drive and colon");
            let a: Vec<u16> = r.to_text().encode_utf16().collect();
            let mut print = a.clone();
            print.extend_from_slice(rest_r);
            let mut sub = nt.clone();
            sub.extend_from_slice(&print);
            assert_eq!(buf.data(), layout(t, &sub, &print), "re-based data");
            if r.to_text().len() == 2 {
                let again = prepare(h, t, 0, buf.data(), &r).expect("re-based data re-bases");
                assert_eq!(again, buf, "re-basing onto a drive root is not idempotent");
            }
        }
        _ => panic!("M = {m:#x} accepted"),
    }
    let copy = prepare(h, t, REPARSE_FIELD_RELATIVE, buf.data(), &r)
        .expect("accepted output is well formed");
    assert_eq!(copy.data(), buf.data(), "copy of the output differs");
}

fuzz_target!(|input: &[u8]| {
    if input.starts_with(&MAGIC) {
        whole_file(input, 1, &root(1), None);
        return;
    }
    let Some((&sel, rest)) = input.split_first() else {
        return;
    };
    if sel & 1 == 1 {
        rebase_rule(rest);
        return;
    }
    let index = u32::from((sel >> 1) & 3);
    let r = root(if sel & 8 != 0 { 2 } else { 1 });
    if sel & 0x10 != 0 {
        let mut rest = rest;
        let at = usize::try_from(word(&mut rest)).unwrap_or(0);
        if rest.is_empty() {
            return;
        }
        whole_file(rest, index, &r, Some(at % rest.len()));
    } else {
        whole_file(rest, index, &r, None);
    }
});
