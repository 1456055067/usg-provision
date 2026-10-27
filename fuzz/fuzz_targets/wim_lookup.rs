//! Fuzz target `wim_lookup`: arbitrary bytes as a WIM lookup table.
//!
//! The same bytes are parsed by `parse_table` for both accepted
//! compressions, two file lengths and two image limits. Invariants (plan
//! WU-9, §10):
//!
//! - no panic, and every refusal carries a listed reason code;
//! - the result (including which refusal) equals an independent
//!   per-entry walk with `check_entry`:
//!   accepted only if the length is a multiple of 50, every entry passes
//!   and the metadata entries are within the image limit; the accepted
//!   metadata entries are exactly the metadata-flagged entries in order;
//! - then the whole-table checks equal a naive pairwise model: no two
//!   file (non-metadata) entries share a hash (metadata entries may:
//!   BOOT-011), no two non-empty ranges share a byte, metadata offsets
//!   strictly rise in lookup order (SEC-003, BOOT-001, BOOT-003);
//!   the compressed file resources are reported sorted by offset;
//! - every 50-byte entry re-encodes byte for byte;
//! - a table accepted for a file of length L is also accepted, with the
//!   same result, for any longer file;
//! - the chunk-table arithmetic never panics.

#![no_main]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), SA-11 (Developer
//   Testing and Evaluation)
// - SPEC: specs/os-images.md#REQ-IMG-037, #REQ-IMG-022
// - SPEC: specs/standards/wim.md §3 (lookup table), §4 (chunk table)
// - DECISION: docs/decisions/0006-wim-format-by-black-box-test-files.md

use libfuzzer_sys::fuzz_target;
use usgp_image::wim::header::Compression;
use usgp_image::wim::lookup::{
    ENTRY_LEN, LookupEntry, LookupScan, check_entry, chunk_count, chunk_table_len, parse_table,
};
use usgp_image::wim::reshdr::ResourceHeader;
use usgp_image::{WimError, WimLimits};

fn assert_listed(e: &WimError) {
    let code = e.reason_code();
    assert!(
        WimError::REASON_CODES.contains(&code),
        "unlisted reason code {code}"
    );
    assert!(!e.operator_message().is_empty(), "empty operator message");
}

/// The expected outcome, computed entry by entry.
fn model(
    table: &[u8],
    compression: Compression,
    file_len: u64,
    max_images: u32,
) -> Result<LookupScan, WimError> {
    if !table.len().is_multiple_of(ENTRY_LEN) {
        return Err(WimError::Malformed {
            what: "lookup table size",
        });
    }
    let mut scan = LookupScan {
        metadata: Vec::new(),
        entries: 0,
        compressed_files: Vec::new(),
    };
    let mut all: Vec<LookupEntry> = Vec::new();
    for raw in table.as_chunks::<ENTRY_LEN>().0 {
        let e = LookupEntry::parse(raw).expect("50-byte entry parses");
        check_entry(&e, compression, file_len)?;
        scan.entries += 1;
        if e.reshdr.is_metadata() {
            if scan.metadata.len() >= max_images as usize {
                return Err(WimError::LimitExceeded { what: "images" });
            }
            scan.metadata.push(e);
        }
        all.push(e);
    }
    // Naive pairwise whole-table checks, in the library's order. Only
    // file entries take part in the hash rule (BOOT-011).
    let files_only: Vec<&LookupEntry> = all.iter().filter(|e| !e.reshdr.is_metadata()).collect();
    for (i, a) in files_only.iter().enumerate() {
        for b in &files_only[i + 1..] {
            if a.sha1 == b.sha1 {
                return Err(WimError::DuplicateResource);
            }
        }
    }
    let shares = |a: &ResourceHeader, b: &ResourceHeader| {
        a.stored_size != 0
            && b.stored_size != 0
            && a.offset < b.offset + b.stored_size
            && b.offset < a.offset + a.stored_size
    };
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            if shares(&a.reshdr, &b.reshdr) {
                return Err(WimError::ResourceOverlap);
            }
        }
    }
    for w in scan.metadata.windows(2) {
        if w[0].reshdr.offset >= w[1].reshdr.offset {
            return Err(WimError::MetadataOrderNotSupported);
        }
    }
    let mut files: Vec<ResourceHeader> = all
        .iter()
        .map(|e| e.reshdr)
        .filter(|r| r.is_compressed() && !r.is_metadata())
        .collect();
    files.sort_by_key(|r| (r.offset, r.stored_size));
    scan.compressed_files = files;
    Ok(scan)
}

fuzz_target!(|data: &[u8]| {
    for raw in data.as_chunks::<ENTRY_LEN>().0 {
        let e = LookupEntry::parse(raw).expect("50-byte entry parses");
        assert_eq!(&e.to_bytes()[..], raw, "entry does not re-encode");
        let _ = chunk_table_len(e.reshdr.original_size);
        let _ = chunk_count(e.reshdr.original_size);
    }
    let short = u64::try_from(data.len()).unwrap_or(u64::MAX);
    for compression in [Compression::None, Compression::Xpress] {
        for max_images in [WimLimits::DEFAULT.max_images, 2] {
            let mut previous: Option<LookupScan> = None;
            for file_len in [short, 1 << 40, u64::MAX] {
                let got = parse_table(data, compression, file_len, max_images);
                let want = model(data, compression, file_len, max_images);
                match (&got, &want) {
                    (Ok(g), Ok(w)) => {
                        assert_eq!(g, w, "accepted scan differs from the model");
                        assert_eq!(g.entries, (data.len() / ENTRY_LEN) as u64);
                        assert!(g.metadata.len() <= max_images as usize);
                        assert!(g.metadata.iter().all(|m| m.reshdr.is_metadata()));
                        // Accepted ranges never share a byte, so their
                        // stored sizes sum to at most the file length.
                        let total: u64 = g.compressed_files.iter().map(|r| r.stored_size).sum();
                        assert!(total <= file_len, "resources overlap");
                    }
                    (Err(g), Err(w)) => {
                        assert_eq!(g, w, "refusal differs from the model");
                        assert_listed(g);
                    }
                    _ => panic!("parse_table {got:?} but the model says {want:?}"),
                }
                // Monotone in the file length.
                if let Some(p) = &previous {
                    assert_eq!(got.as_ref().ok(), Some(p), "longer file refused");
                }
                previous = got.ok();
            }
        }
    }
});
