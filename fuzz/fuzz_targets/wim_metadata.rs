//! Fuzz target `wim_metadata`: arbitrary bytes as a decoded WIM metadata
//! resource (`usgp-image` `parse_metadata`).
//!
//! The whole input is the resource, as the `wim_metadata` seeds written
//! by `crates/usgp-image/examples/gen_fuzz_seeds.rs` are.
//!
//! Limits (impl-notes-wu4 "For WU-14"): `max_bytes` 1 MiB and
//! `max_entries` 10,000, the rest the defaults.
//!
//! Invariants:
//!
//! - no panic; every refusal has a listed reason code and operator text;
//! - an accepted tree: root first, a directory with no name, short name
//!   or streams; every other entry named with a valid component, after
//!   its parent, which is a directory, at depth parent + 1 within
//!   `max_depth`; at most `max_entries` entries and `max_streams_per_entry`
//!   streams; names within `max_name_units` and paths within
//!   `max_path_units`; no two names in one directory equal ignoring ASCII
//!   case; no reserved name at the root (M-19); known attribute bits only
//!   (M-10); every security index names a descriptor (M-14) of at most
//!   `max_sd_bytes`; the kind agrees with the directory and reparse bits,
//!   reparse data only on links and junctions; directories carry no data
//!   and no hard link; the names of one hard-link group agree in data,
//!   attributes and descriptor (M-12);
//! - `dir_and_file_counts` equals a count of the entries;
//! - limits are monotone: the defaults accept what the tight limits
//!   accept, with the same tree; one entry fewer, or one level less
//!   depth, than the tree needs is refused with `wim_meta_limit_exceeded`.

#![no_main]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), SC-5 (Denial of
//   Service Protection), SA-11 (Developer Testing and Evaluation)
// - SPEC: specs/preinstall-env.md#REQ-PE-016, #REQ-PE-017
// - SPEC: specs/standards/wim.md §6, §6.1
// - FINDINGS: findings-boot-obs.md "What WU-4 may rely on" (M-01 to M-23)

use std::collections::{HashMap, HashSet};

use libfuzzer_sys::fuzz_target;
use usgp_image::wim::metadata::{
    EntryKind, ImageTree, MetadataError, MetadataLimits, attr, parse_metadata,
};
use usgp_image::wim::names::Component;

const TIGHT: MetadataLimits = MetadataLimits {
    max_bytes: 1 << 20,
    max_entries: 10_000,
    ..MetadataLimits::DEFAULT
};

fn known(e: &MetadataError) {
    assert!(
        MetadataError::REASON_CODES.contains(&e.reason_code()),
        "unlisted reason {e:?}"
    );
    assert!(!e.operator_message().is_empty(), "empty operator text");
}

fn check_tree(t: &ImageTree, l: &MetadataLimits) {
    let n = t.entries.len();
    assert!(n >= 1, "no root");
    assert!(
        u64::try_from(n).unwrap_or(u64::MAX) <= u64::from(l.max_entries.max(1)),
        "entry limit"
    );
    assert!(
        u64::try_from(t.security.len()).unwrap_or(u64::MAX)
            <= u64::from(l.max_security_descriptors),
        "descriptor limit"
    );
    for d in &t.security {
        assert!(
            u64::try_from(d.len()).unwrap_or(u64::MAX) <= u64::from(l.max_sd_bytes),
            "descriptor size limit"
        );
    }
    // Path length of each entry in UTF-16 units, components plus
    // separators (M-16), and the sibling names seen per directory.
    let mut path_units: Vec<u64> = Vec::with_capacity(n);
    let mut siblings: HashMap<usize, HashSet<String>> = HashMap::new();
    let mut links: HashMap<u64, usize> = HashMap::new();
    let (mut dirs, mut files) = (0u64, 0u64);
    for (i, e) in t.entries.iter().enumerate() {
        let a = e.attributes.0;
        assert_eq!(a & !attr::KNOWN, 0, "unknown attribute bits accepted");
        assert!(
            usize::try_from(e.security).is_ok_and(|s| s < t.security.len()),
            "security index out of range"
        );
        assert!(
            e.streams.len() <= usize::from(l.max_streams_per_entry),
            "streams"
        );
        let is_dir = a & attr::DIRECTORY != 0;
        let is_reparse = a & attr::REPARSE != 0;
        match e.kind {
            EntryKind::Directory => {
                assert!(is_dir && !is_reparse, "directory kind");
                assert!(e.data.is_none(), "data on a directory");
                assert!(e.link_group.is_none(), "hard link on a directory");
                assert!(e.reparse.is_none(), "reparse data on a directory");
            }
            EntryKind::File => {
                assert!(!is_dir && !is_reparse, "file kind");
                assert!(e.reparse.is_none(), "reparse data on a file");
            }
            EntryKind::Symlink { directory } => {
                assert!(is_reparse && directory == is_dir, "symlink kind");
                assert!(e.reparse.is_some(), "symlink without data");
            }
            EntryKind::Junction => {
                assert!(is_reparse && is_dir, "junction kind");
                assert!(e.reparse.is_some(), "junction without data");
            }
        }
        if i == 0 {
            assert!(
                e.parent.is_none() && e.name.is_none(),
                "root has a parent or name"
            );
            assert!(
                e.short_name.is_none() && e.streams.is_empty(),
                "root has extras"
            );
            assert_eq!(e.kind, EntryKind::Directory, "root not a directory");
            assert_eq!(e.depth, 0, "root depth");
            path_units.push(0);
            continue;
        }
        if e.kind == EntryKind::Directory {
            dirs += 1;
        } else {
            files += 1;
        }
        let p = e.parent.expect("non-root entry has a parent");
        assert!(p < i, "parent after child");
        let parent = &t.entries[p];
        assert_eq!(parent.kind, EntryKind::Directory, "parent not a directory");
        assert_eq!(e.depth, parent.depth + 1, "depth");
        assert!(e.depth <= l.max_depth, "depth limit");
        let name = e.name.as_ref().expect("non-root entry has a name").as_str();
        assert!(Component::new(name).is_ok(), "invalid component accepted");
        let units = u64::try_from(name.encode_utf16().count()).unwrap_or(u64::MAX);
        assert!(units <= u64::from(l.max_name_units), "name length");
        let total = path_units[p] + 1 + units;
        assert!(total <= u64::from(l.max_path_units), "path length");
        path_units.push(total);
        if p == 0 {
            assert!(
                !name.eq_ignore_ascii_case("System Volume Information") && !name.starts_with('$'),
                "reserved root name accepted"
            );
        }
        assert!(
            siblings
                .entry(p)
                .or_default()
                .insert(name.to_ascii_lowercase()),
            "two names in one directory equal ignoring case"
        );
        if let Some(g) = e.link_group {
            let f = &t.entries[*links.entry(g).or_insert(i)];
            assert_eq!(f.data, e.data, "hard links differ in data");
            assert_eq!(
                f.attributes, e.attributes,
                "hard links differ in attributes"
            );
            assert_eq!(f.security, e.security, "hard links differ in descriptor");
        }
    }
    assert_eq!(
        t.dir_and_file_counts(),
        (dirs, files),
        "dir_and_file_counts"
    );
}

fuzz_target!(|data: &[u8]| {
    let tight = parse_metadata(data, &TIGHT);
    let tree = match tight {
        Ok(t) => t,
        Err(e) => {
            known(&e);
            if let Err(d) = parse_metadata(data, &MetadataLimits::DEFAULT) {
                known(&d);
            }
            return;
        }
    };
    check_tree(&tree, &TIGHT);
    assert_eq!(
        parse_metadata(data, &MetadataLimits::DEFAULT).as_ref(),
        Ok(&tree),
        "default limits disagree with tighter limits"
    );
    let n = u32::try_from(tree.entries.len()).unwrap_or(u32::MAX);
    if n >= 2 {
        let fewer = MetadataLimits {
            max_entries: n - 1,
            ..TIGHT
        };
        let r = parse_metadata(data, &fewer);
        assert!(
            matches!(&r, Err(e) if e.reason_code() == "wim_meta_limit_exceeded"),
            "one entry over the limit: {r:?}"
        );
    }
    let depth = tree.entries.iter().map(|e| e.depth).max().unwrap_or(0);
    if depth >= 1 {
        let shallower = MetadataLimits {
            max_depth: depth - 1,
            ..TIGHT
        };
        let r = parse_metadata(data, &shallower);
        assert!(
            matches!(&r, Err(e) if e.reason_code() == "wim_meta_limit_exceeded"),
            "one level over the depth limit: {r:?}"
        );
    }
});
