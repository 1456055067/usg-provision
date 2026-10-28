//! Checks our parser against WIM files made by Microsoft's DISM in the
//! same workflow run (plan WU-W item 2; decision 0006), and our test
//! builder's layout against DISM's (`builder_matches_dism`).
//!
//! Contract: scripts/wim-samples/README.md, "Linux consumer". With the
//! `dism-samples` feature on, `USGP_WIM_SAMPLES` unset or not a directory
//! is a test **failure**, never a skip. Any `not-produced` row, missing
//! file or SHA-256 mismatch fails.
//!
//! Rows with expected `observe` record the parser's result without
//! judging it. S11A, S11B, S12A and S12B (BOOT-011, BOOT-012) were
//! `observe` until run 40599556702 was recorded (OBS-018 to OBS-023);
//! they are now judged by [`RECORDED`] even in an artifact whose manifest
//! still says `observe`, and `serviced_layouts_match_observations` checks
//! the recorded layout facts byte by byte. A row with status
//! `dism-refused` (DISM itself refused the step) has no file and is
//! printed; on a recorded row it fails, as it contradicts the record.
//!
//! The samples are never committed (OPEN-PE-LIC); they exist only as a
//! workflow artifact.
//!
//! Sets: `USGP_WIM_SAMPLES` names one artifact directory. The Standard
//! artifact (`wim-samples`: S01 to S12B) and the Metadata artifact
//! (`wim-samples-metadata`: S13, S14, S15, S17) are both accepted. A test
//! that needs rows of the other set prints that they are absent and
//! returns; a test that finds only part of its set fails. Every test
//! judges something in at least one set.
//!
//! M3 (WU-4) adds `metadata_matches_observations` (S13, S14 and S15
//! metadata decoded by the product's parser and compared with their tree
//! manifests, OBS-024 to OBS-048), `metadata_samples_apply` (S17 applied,
//! S13 to S15 refused with a named reason), `builder_metadata_matches_dism`
//! (the testkit encoder's entry forms against S13's), and S14 and S17 in
//! the raw-chunk decode check (OBS-046).

// COMPLIANCE MAPPING:
// - NIST 800-53: SA-11 (Developer Testing and Evaluation), SI-10
// - SPEC: specs/os-images.md#REQ-IMG-037, #REQ-IMG-038, #REQ-IMG-040,
//   #REQ-IMG-042
// - DECISION: docs/decisions/0006-wim-format-by-black-box-test-files.md
#![cfg(feature = "dism-samples")]

#[cfg(test)]
mod dism {
    use std::collections::BTreeMap;
    use std::fs::File;
    use std::io::{BufReader, Read};
    use std::path::{Path, PathBuf};

    use std::collections::{BTreeSet, HashMap};

    use usgp_crypto::CryptoProvider;
    use usgp_image::apply::{ApplyLimits, ApplyRoot, MemoryNodeKind, MemorySink, XmlCounts, apply};
    use usgp_image::testkit::{MemoryChunks, TreeSpec, WimBuilder, decode_resource};
    use usgp_image::wim::header::{WimHeader, parse_header};
    use usgp_image::wim::integrity::IntegrityTableHeader;
    use usgp_image::wim::lookup::{LookupEntry, parse_table};
    use usgp_image::wim::metadata::{
        EntryKind, ImageTree, MetadataLimits, REPARSE_FIELD_RELATIVE, attr, parse_metadata, tag,
    };
    use usgp_image::wim::reshdr::ResourceHeader;
    use usgp_image::wim::xml::{BOM, parse_xml};
    use usgp_image::{Compression, NoProgress, WimError, WimLimits, WimSummary, check_wim};

    const ENV: &str = "USGP_WIM_SAMPLES";

    /// Samples that were `observe` rows, with the outcome recorded from
    /// run 40599556702 and the record that states it.
    const RECORDED: &[(&str, &str, &str)] = &[
        ("S11A", "accept", "OBS-018"),
        ("S11B", "accept", "OBS-018"),
        ("S12A", "accept", "OBS-021"),
        ("S12B", "accept", "OBS-023"),
    ];

    fn recorded(id: &str) -> Option<(&'static str, &'static str)> {
        RECORDED
            .iter()
            .find(|(r, _, _)| *r == id)
            .map(|(_, token, obs)| (*token, *obs))
    }

    fn samples_dir() -> PathBuf {
        let dir = std::env::var_os(ENV).unwrap_or_else(|| {
            panic!("{ENV} is not set: the dism-samples tests need the wim-samples artifact")
        });
        let dir = PathBuf::from(dir);
        assert!(dir.is_dir(), "{ENV} is not a directory: {}", dir.display());
        dir
    }

    /// Tab-separated, UTF-8 without BOM, LF line ends, header row first.
    fn read_tsv(path: &Path, header: &[&str]) -> Vec<Vec<String>> {
        let text =
            std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert!(
            !text.starts_with('\u{feff}'),
            "{} has a BOM",
            path.display()
        );
        assert!(!text.contains('\r'), "{} has CR line ends", path.display());
        let mut lines = text.lines().filter(|l| !l.is_empty());
        let head: Vec<&str> = lines.next().expect("header row").split('\t').collect();
        assert_eq!(head, header, "{} header", path.display());
        lines
            .map(|l| {
                let row: Vec<String> = l.split('\t').map(str::to_owned).collect();
                assert_eq!(row.len(), header.len(), "{}: bad row {l:?}", path.display());
                row
            })
            .collect()
    }

    struct Row {
        id: String,
        file: String,
        bytes: u64,
        sha256: String,
        compression: String,
        images: u32,
        expected: String,
    }

    fn manifest(dir: &Path) -> Vec<Row> {
        let rows = read_tsv(
            &dir.join("manifest.tsv"),
            &[
                "id",
                "file",
                "bytes",
                "sha256",
                "compression",
                "images",
                "expected",
                "status",
            ],
        );
        assert!(!rows.is_empty(), "manifest.tsv has no rows");
        let mut out = Vec::new();
        for r in rows {
            let [
                id,
                file,
                bytes,
                sha256,
                compression,
                images,
                expected,
                status,
            ] = <[String; 8]>::try_from(r).unwrap();
            // README: S08's row (large job only) says it was not uploaded.
            if status == "produced (not uploaded)" {
                continue;
            }
            // README: an observation sample whose DISM step DISM refused.
            if status == "dism-refused" {
                assert_eq!(expected, "observe", "{id}: dism-refused on a judged row");
                assert!(
                    recorded(&id).is_none(),
                    "{id}: DISM refused a step it completed in the recorded run"
                );
                println!("{id} {file}: DISM refused the sample step (see commands.log)");
                continue;
            }
            assert_eq!(status, "produced", "{id} {file}: status {status}");
            out.push(Row {
                id,
                file,
                bytes: bytes.parse().unwrap(),
                sha256,
                compression,
                images: images.parse().unwrap(),
                expected,
            });
        }
        out
    }

    /// The images DISM's own `/Get-WimInfo` listed in `<id>.wiminfo.txt`
    /// (first listing; for rows whose names DISM chose, such as S11B).
    fn wiminfo_editions(dir: &Path, id: &str) -> Vec<(u32, String, String)> {
        let path = dir.join(format!("{id}.wiminfo.txt"));
        let text =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let mut out: Vec<(u32, String, String)> = Vec::new();
        let mut cur: Option<(u32, Option<String>, Option<String>)> = None;
        let mut flush = |c: Option<(u32, Option<String>, Option<String>)>| {
            if let Some((i, Some(n), Some(d))) = c
                && !out.iter().any(|(k, _, _)| *k == i)
            {
                out.push((i, n, d));
            }
        };
        for line in text.lines() {
            let field = |key: &str| {
                line.split_once(':')
                    .filter(|(k, _)| k.trim() == key)
                    .map(|(_, v)| v.trim().to_owned())
            };
            if let Some(v) = field("Index") {
                flush(cur.take());
                cur = Some((v.parse().unwrap(), None, None));
            } else if let Some(c) = cur.as_mut() {
                if c.1.is_none() {
                    c.1 = field("Name");
                } else if c.2.is_none() {
                    c.2 = field("Description");
                }
            }
        }
        flush(cur);
        out.sort();
        out
    }

    /// `id` → (index, name, description) rows.
    fn editions(dir: &Path) -> BTreeMap<String, Vec<(u32, String, String)>> {
        let mut m: BTreeMap<String, Vec<(u32, String, String)>> = BTreeMap::new();
        for r in read_tsv(
            &dir.join("editions.tsv"),
            &["id", "index", "name", "description"],
        ) {
            let [id, index, name, description] = <[String; 4]>::try_from(r).unwrap();
            m.entry(id)
                .or_default()
                .push((index.parse().unwrap(), name, description));
        }
        m
    }

    fn sha256_hex(path: &Path) -> String {
        let mut f = BufReader::new(File::open(path).unwrap());
        let mut h = usgp_crypto::provider().sha256_hasher();
        let mut buf = vec![0u8; 1 << 16];
        loop {
            let n = f.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        h.finish().to_hex()
    }

    fn check(path: &Path) -> Result<WimSummary, WimError> {
        let len = std::fs::metadata(path).unwrap().len();
        let mut f = BufReader::new(File::open(path).unwrap());
        check_wim(
            &mut f,
            len,
            &WimLimits::DEFAULT,
            usgp_crypto::provider(),
            &mut NoProgress,
        )
    }

    /// What a manifest row expects of the parser.
    enum Expect {
        Accept,
        Refuse(&'static str),
        /// Unobserved layout (S11, S12): the result is printed, not judged.
        Observe,
    }

    fn expected_reason(token: &str) -> Expect {
        match token {
            "accept" => Expect::Accept,
            "observe" => Expect::Observe,
            "refuse:lzx" => Expect::Refuse("wim_lzx_not_supported"),
            "refuse:spanned" => Expect::Refuse("wim_split_not_supported"),
            "refuse:compression-unsupported" => Expect::Refuse("wim_compression_not_supported"),
            other => panic!("unknown expected token {other:?}"),
        }
    }

    #[test]
    fn manifest_files_present_and_hashes_match() {
        let dir = samples_dir();
        for row in manifest(&dir) {
            let path = dir.join(&row.file);
            assert!(path.is_file(), "{}: {} missing", row.id, row.file);
            assert_eq!(
                std::fs::metadata(&path).unwrap().len(),
                row.bytes,
                "{} size",
                row.file
            );
            assert_eq!(sha256_hex(&path), row.sha256, "{} SHA-256", row.file);
        }
    }

    #[test]
    fn every_sample_meets_its_expectation() {
        let dir = samples_dir();
        let editions = editions(&dir);
        let rows = manifest(&dir);
        let mut accepted = 0;
        let mut refused = 0;
        for row in &rows {
            let path = dir.join(&row.file);
            let result = check(&path);
            let token = match (row.expected.as_str(), recorded(&row.id)) {
                ("observe", Some((token, obs))) => {
                    println!(
                        "recorded {} ({}): manifest says observe; judged as {token} ({obs})",
                        row.id, row.file
                    );
                    token
                }
                (e, Some((token, obs))) => {
                    assert_eq!(e, token, "{}: manifest differs from {obs}", row.id);
                    token
                }
                (e, None) => e,
            };
            match expected_reason(token) {
                Expect::Observe => match &result {
                    Ok(s) => println!(
                        "observe {} ({}): accepted, {} images, compression {}",
                        row.id,
                        row.file,
                        s.image_count,
                        s.compression.as_str()
                    ),
                    Err(e) => println!(
                        "observe {} ({}): refused {} ({e})",
                        row.id,
                        row.file,
                        e.reason_code()
                    ),
                },
                Expect::Accept => {
                    let s = result.unwrap_or_else(|e| {
                        panic!("{} ({}) refused: {} {e}", row.id, row.file, e.reason_code())
                    });
                    accepted += 1;
                    assert_eq!(s.image_count, row.images, "{} images", row.id);
                    let want = match row.compression.as_str() {
                        "none" => Compression::None,
                        "xpress" => Compression::Xpress,
                        other => panic!("{}: accept with compression {other}", row.id),
                    };
                    assert_eq!(s.compression, want, "{} compression", row.id);
                    // S11B's names are DISM's choice (Build-Samples
                    // records no expectation): compare with DISM's own
                    // report instead.
                    let rows = match editions.get(&row.id) {
                        Some(r) => r.clone(),
                        None if row.id == "S11B" => wiminfo_editions(&dir, &row.id),
                        None => panic!("{}: no editions.tsv rows", row.id),
                    };
                    let got: Vec<(u32, String, String)> = s
                        .editions
                        .iter()
                        .map(|e| (e.index, e.name.clone(), e.description.clone()))
                        .collect();
                    let mut want = rows;
                    want.sort();
                    assert_eq!(got, want, "{} editions", row.id);
                    if row.id == "S05" {
                        assert!(s.has_integrity_table, "S05 integrity table");
                    }
                }
                Expect::Refuse(code) => {
                    refused += 1;
                    let e = result.err().unwrap_or_else(|| {
                        panic!("{} ({}) accepted, expected {code}", row.id, row.file)
                    });
                    assert_eq!(e.reason_code(), code, "{} ({})", row.id, row.file);
                }
            }
        }
        // The Metadata artifact has accept rows only.
        let expects_refusals = rows.iter().any(|r| r.expected.starts_with("refuse"));
        assert!(
            accepted > 0 && (refused > 0 || !expects_refusals),
            "manifest lacks accept or refuse rows"
        );
    }

    /// Ids of `set` present in `rows`: all, or none (then the caller
    /// returns). Part of a set fails.
    fn set_present(rows: &[Row], set: &[&str], test: &str) -> bool {
        let present = set
            .iter()
            .filter(|id| rows.iter().any(|r| r.id == **id))
            .count();
        if present == 0 {
            println!("{test}: no {set:?} rows in this artifact");
            return false;
        }
        assert_eq!(present, set.len(), "{test}: partial set {set:?}");
        true
    }

    /// The structural facts the builder must share with DISM's output.
    #[derive(Debug, PartialEq, Eq)]
    struct Layout {
        magic_and_size: (u32, u32),
        version: u32,
        flags: u32,
        field_20: u32,
        part: (u16, u16),
        image_count: u32,
        lookup_flags: u8,
        xml_flags: u8,
        boot_metadata_zero: bool,
        boot_index: u32,
        integrity_flags: Option<u8>,
        integrity_chunk: Option<u32>,
        unused_zero: bool,
        first_resource_at: u64,
        xml_follows_lookup: bool,
        last_structure_ends_file: bool,
        metadata_first: bool,
        metadata_flags: Vec<u8>,
        metadata_part_and_count: Vec<(u16, u32)>,
        metadata_offsets_rise: bool,
        file_resource_before_each_metadata: bool,
        lookup_follows_last_metadata: bool,
        some_file_shared_by_every_image: bool,
        all_parts_one: bool,
        uncompressed_sizes_equal: bool,
        xml_bom: bool,
        xml_starts_with_wim: bool,
        xml_top_totalbytes_is_offset: bool,
        image_paths: Vec<Vec<String>>,
        names: Vec<(u32, String, String)>,
    }

    fn slice(b: &[u8], rh: &ResourceHeader) -> Vec<u8> {
        let s = usize::try_from(rh.offset).unwrap();
        let e = s + usize::try_from(rh.stored_size).unwrap();
        b[s..e].to_vec()
    }

    fn layout(b: &[u8]) -> Layout {
        let h: WimHeader = parse_header(b).unwrap();
        let len = u64::try_from(b.len()).unwrap();
        let compression = if h.flags & 0x2 != 0 {
            Compression::Xpress
        } else {
            Compression::None
        };
        let table = slice(b, &h.lookup);
        let scan = parse_table(&table, compression, len, 1024).unwrap();
        let entries: Vec<LookupEntry> = table
            .chunks(50)
            .map(|c| LookupEntry::parse(c).unwrap())
            .collect();
        let meta_n = scan.image_metadata().len();
        let xml_raw = slice(b, &h.xml);
        let xml = parse_xml(&xml_raw, &WimLimits::DEFAULT).unwrap();
        let text: String = char::decode_utf16(
            xml_raw[2..]
                .chunks(2)
                .map(|u| u16::from_le_bytes([u[0], u[1]])),
        )
        .map(Result::unwrap)
        .collect();
        let integrity = (!h.integrity.is_zero())
            .then(|| IntegrityTableHeader::parse(&slice(b, &h.integrity)).unwrap());
        let ends: Vec<u64> = [h.lookup, h.xml, h.integrity]
            .iter()
            .filter(|r| !r.is_zero())
            .map(|r| r.offset + r.stored_size)
            .collect();
        Layout {
            magic_and_size: (u32::from_le_bytes(b[0..4].try_into().unwrap()), h.cb_size),
            version: h.version,
            flags: h.flags,
            field_20: h.field_20,
            part: (h.part_number, h.total_parts),
            image_count: h.image_count,
            lookup_flags: h.lookup.flags,
            xml_flags: h.xml.flags,
            boot_metadata_zero: h.boot_metadata.is_zero(),
            boot_index: h.boot_index,
            integrity_flags: (!h.integrity.is_zero()).then_some(h.integrity.flags),
            integrity_chunk: integrity.map(|t| t.chunk_size),
            unused_zero: b[148..208].iter().all(|&x| x == 0),
            first_resource_at: entries.iter().map(|e| e.reshdr.offset).min().unwrap(),
            xml_follows_lookup: h.xml.offset == h.lookup.offset + h.lookup.stored_size,
            last_structure_ends_file: ends.iter().max() == Some(&len),
            metadata_first: entries[..meta_n].iter().all(|e| e.reshdr.is_metadata())
                && entries[meta_n..].iter().all(|e| !e.reshdr.is_metadata()),
            metadata_flags: scan
                .image_metadata()
                .iter()
                .map(|e| e.reshdr.flags)
                .collect(),
            metadata_part_and_count: scan
                .image_metadata()
                .iter()
                .map(|e| (e.part_number, e.ref_count))
                .collect(),
            metadata_offsets_rise: scan
                .image_metadata()
                .windows(2)
                .all(|w| w[0].reshdr.offset < w[1].reshdr.offset),
            // Interleaving: each image's new file resources come right
            // before its metadata (OBS-009, S04).
            file_resource_before_each_metadata: {
                let mut prev_end = 0u64;
                scan.image_metadata().iter().all(|m| {
                    let ok = entries[meta_n..]
                        .iter()
                        .any(|f| f.reshdr.offset >= prev_end && f.reshdr.offset < m.reshdr.offset);
                    prev_end = m.reshdr.offset + m.reshdr.stored_size;
                    ok
                })
            },
            lookup_follows_last_metadata: scan
                .image_metadata()
                .last()
                .is_some_and(|m| m.reshdr.offset + m.reshdr.stored_size == h.lookup.offset),
            some_file_shared_by_every_image: entries[meta_n..]
                .iter()
                .any(|e| e.ref_count == h.image_count),
            all_parts_one: entries.iter().all(|e| e.part_number == 1),
            uncompressed_sizes_equal: entries
                .iter()
                .filter(|e| !e.reshdr.is_compressed())
                .all(|e| e.reshdr.stored_size == e.reshdr.original_size),
            xml_bom: xml_raw.starts_with(&BOM),
            xml_starts_with_wim: text.starts_with("<WIM>") && text.ends_with("</WIM>"),
            xml_top_totalbytes_is_offset: xml.total_bytes == Some(h.xml.offset),
            image_paths: xml
                .images
                .iter()
                .map(|i| i.elements.iter().map(|l| l.path.clone()).collect())
                .collect(),
            names: xml
                .images
                .iter()
                .map(|i| (i.index, i.name.clone(), i.description.clone()))
                .collect(),
        }
    }

    fn dism_file(dir: &Path, rows: &[Row], id: &str) -> Vec<u8> {
        let row = rows
            .iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("{id} not in manifest.tsv"));
        std::fs::read(dir.join(&row.file)).unwrap()
    }

    #[test]
    fn builder_matches_dism() {
        let dir = samples_dir();
        let rows = manifest(&dir);
        if !set_present(&rows, &["S01", "S02", "S04", "S05"], "builder_matches_dism") {
            return;
        }
        let editions = editions(&dir);
        for (id, compression, integrity) in [
            ("S01", Compression::None, false),
            ("S02", Compression::Xpress, false),
            ("S05", Compression::Xpress, true),
            // BOOT-005: 12 images (capture + 11 appends): metadata order,
            // interleaving, reference counts, metadata entries first.
            ("S04", Compression::Xpress, false),
        ] {
            let dism = layout(&dism_file(&dir, &rows, id));
            let mut b = WimBuilder::new(compression).integrity(integrity);
            for (_, name, desc) in editions.get(id).unwrap() {
                b = b.image(name, desc);
            }
            let (ours, _) = b.build().unwrap();
            let ours = layout(&ours);
            assert_eq!(ours, dism, "builder layout differs from DISM's {id}");
        }
    }

    fn metadata_entries(b: &[u8]) -> Vec<LookupEntry> {
        let h = parse_header(b).unwrap();
        slice(b, &h.lookup)
            .chunks(50)
            .map(|c| LookupEntry::parse(c).unwrap())
            .filter(|e| e.reshdr.is_metadata())
            .collect()
    }

    fn all_entries(b: &[u8]) -> Vec<LookupEntry> {
        let h = parse_header(b).unwrap();
        slice(b, &h.lookup)
            .chunks(50)
            .map(|c| LookupEntry::parse(c).unwrap())
            .collect()
    }

    /// SHA-1 of every non-empty file of every tree in `trees.txt`, by
    /// tree name (`== tree <name> ==` headers; `file <path> length=<n>
    /// sha1=<hex>` lines).
    fn tree_hashes(dir: &Path) -> BTreeMap<String, Vec<[u8; 20]>> {
        let path = dir.join("trees.txt");
        let text =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let mut out: BTreeMap<String, Vec<[u8; 20]>> = BTreeMap::new();
        let mut cur: Option<String> = None;
        for line in text.lines() {
            if let Some(name) = line
                .strip_prefix("== tree ")
                .and_then(|r| r.strip_suffix(" =="))
            {
                cur = Some(name.to_owned());
                continue;
            }
            let Some(tree) = cur.as_ref().filter(|_| line.starts_with("file ")) else {
                continue;
            };
            let words: Vec<&str> = line.split_whitespace().collect();
            // The empty file's hash names no resource; leave it out.
            if words.contains(&"length=0") {
                continue;
            }
            let Some(hex) = words.iter().find_map(|w| w.strip_prefix("sha1=")) else {
                continue;
            };
            let mut h = [0u8; 20];
            for (k, b) in h.iter_mut().enumerate() {
                *b = u8::from_str_radix(&hex[2 * k..2 * k + 2], 16).unwrap();
            }
            out.entry(tree.clone()).or_default().push(h);
        }
        out
    }

    fn contains(hay: &[u8], needle: &[u8; 20]) -> bool {
        hay.windows(20).any(|w| w == needle)
    }

    /// The layout facts OBS-018 and OBS-021 rest on, as booleans, so the
    /// builder's serviced layouts can be compared with DISM's.
    #[derive(Debug, PartialEq, Eq)]
    struct ServicedShape {
        metadata_count: usize,
        distinct_metadata: usize,
        adjacent_equal_entries: bool,
        first_after_every_other_entry: bool,
        rest_rise: bool,
        first_ends_at_lookup: bool,
    }

    fn serviced_shape(b: &[u8]) -> ServicedShape {
        let h = parse_header(b).unwrap();
        let m = metadata_entries(b);
        let all = all_entries(b);
        let first = m[0];
        let len = u64::try_from(b.len()).unwrap();
        let scan = parse_table(&slice(b, &h.lookup), Compression::Xpress, len, 1024).unwrap();
        ServicedShape {
            metadata_count: m.len(),
            distinct_metadata: scan.distinct_metadata().count(),
            adjacent_equal_entries: m.windows(2).any(|w| w[0] == w[1]),
            first_after_every_other_entry: all
                .iter()
                .skip(1)
                .all(|e| e.reshdr.offset + e.reshdr.stored_size <= first.reshdr.offset),
            rest_rise: m[1..]
                .windows(2)
                .all(|w| w[0].reshdr.offset < w[1].reshdr.offset),
            first_ends_at_lookup: first.reshdr.offset + first.reshdr.stored_size == h.lookup.offset,
        }
    }

    /// OBS-018 (S11A, S11B), OBS-021 and OBS-022 (S12A), OBS-023 (S12B):
    /// the recorded layout facts, checked on the bytes, and the builder's
    /// `reuse_metadata` / `move_first_metadata` layouts against them.
    #[test]
    fn serviced_layouts_match_observations() {
        let dir = samples_dir();
        let rows = manifest(&dir);
        let present: Vec<&str> = RECORDED
            .iter()
            .map(|(id, _, _)| *id)
            .filter(|id| rows.iter().any(|r| r.id == *id))
            .collect();
        if present.is_empty() {
            // Artifacts before run 40599556702 have no S11 or S12 rows; the
            // workflow requires them in every new run.
            println!("no S11 or S12 rows in this artifact");
            return;
        }
        assert_eq!(present.len(), RECORDED.len(), "partial S11/S12 rows");
        let s04 = dism_file(&dir, &rows, "S04");
        let s04_meta = metadata_entries(&s04);

        // OBS-018: two equal entries, one range, read once.
        for id in ["S11A", "S11B"] {
            let b = dism_file(&dir, &rows, id);
            let m = metadata_entries(&b);
            assert_eq!(m.len(), 2, "{id}");
            assert_eq!(m[0], m[1], "{id}: entries differ");
            assert_eq!((m[0].part_number, m[0].ref_count), (1, 1), "{id}");
            let shape = serviced_shape(&b);
            assert_eq!(shape.distinct_metadata, 1, "{id}");
            let mut w = WimBuilder::new(Compression::Xpress).reuse_metadata(true);
            for k in 1..=2 {
                w = w.image_spec(usgp_image::testkit::ImageSpec {
                    name: format!("n{k}"),
                    description: None,
                    files: vec![b"same\n".repeat(900)],
                });
            }
            // The superseded lookup table and XML DISM leaves between
            // the metadata and the live lookup table (OBS-020) are not
            // written by the builder; that one fact is not compared.
            let ours = ServicedShape {
                first_ends_at_lookup: shape.first_ends_at_lookup,
                ..serviced_shape(&w.build().unwrap().0)
            };
            assert_eq!(ours, shape, "builder reuse layout differs from {id}");
        }

        // OBS-021, OBS-022: S12A is S04 with entry 1 moved after every
        // other resource; entries 2 to 12 unchanged; the old copy left
        // in place, byte for byte.
        let b = dism_file(&dir, &rows, "S12A");
        let m = metadata_entries(&b);
        assert_eq!(m.len(), 12);
        assert_eq!(m[1..], s04_meta[1..], "S12A entries 2 to 12");
        let old = s04_meta[0].reshdr;
        assert_eq!(slice(&b, &old), slice(&s04, &old), "S12A stale copy");
        assert!(
            all_entries(&b).iter().all(|e| e.reshdr != old),
            "stale copy is named"
        );
        // OBS-021 index fact, through the product's reader (BOOT-002):
        // lookup position 1 (image 1) holds both tree-service hashes and
        // tree-01's own hashes; position 2 holds no hash that only
        // tree-01 has.
        let trees = tree_hashes(&dir);
        let service = trees
            .get("tree-service")
            .expect("tree-service in trees.txt");
        assert_eq!(service.len(), 2, "tree-service files");
        let only_01: Vec<[u8; 20]> = trees["tree-01"]
            .iter()
            .filter(|h| {
                trees
                    .iter()
                    .all(|(t, hs)| t == "tree-01" || !hs.contains(h))
            })
            .copied()
            .collect();
        assert!(!only_01.is_empty(), "tree-01 has no hash of its own");
        let decoded = |e: &LookupEntry| {
            let out = decode_resource(&b, &e.reshdr).unwrap();
            assert_eq!(usgp_crypto::digest::legacy_sha1(&out).0, e.sha1);
            out
        };
        let image1 = decoded(&m[0]);
        let image2 = decoded(&m[1]);
        for h in service.iter().chain(&only_01) {
            assert!(contains(&image1, h), "S12A position 1 lacks {h:02x?}");
        }
        for h in &only_01 {
            assert!(
                !contains(&image2, h),
                "S12A position 2 holds tree-01's {h:02x?}"
            );
        }

        let shape = serviced_shape(&b);
        assert!(
            shape.first_after_every_other_entry && shape.rest_rise && shape.first_ends_at_lookup
        );
        let mut w = WimBuilder::new(Compression::Xpress).move_first_metadata(true);
        for k in 1..=12 {
            w = w.image(&format!("n{k}"), "d");
        }
        let ours = serviced_shape(&w.build().unwrap().0);
        assert_eq!(ours, shape, "builder move layout differs from S12A");

        // OBS-023: S12B keeps rising offsets; the appended image's
        // metadata has the deleted image's hash at a new offset.
        let b = dism_file(&dir, &rows, "S12B");
        let m = metadata_entries(&b);
        assert_eq!(m[..11], s04_meta[1..], "S12B entries 1 to 11");
        assert_eq!(m[11].sha1, s04_meta[0].sha1);
        assert!(m[11].reshdr.offset > s04_meta[11].reshdr.offset);
        assert!(
            m.windows(2)
                .all(|w| w[0].reshdr.offset < w[1].reshdr.offset)
        );
    }

    /// Every compressed lookup entry of every XPRESS file, including each
    /// split part's own table (OBS-017), decoded by the product's resource
    /// reader and XPRESS decoder and compared with the entry's SHA-1
    /// (BOOT-004; also proves the strict refill rule of BOOT-002 accepts
    /// every DISM chunk). Split parts are refused by `check_wim`, so their
    /// tables are walked here directly.
    ///
    /// M3 (BOOT-004, OBS-046): chunks stored at 32768 bytes are raw at any
    /// position; S14 lookup entry 3030 (chunks 0, 1, 4 and 5 raw) and S17
    /// entries 1 and 2 (chunk 1, then chunk 0, raw) are checked by
    /// position, and must decode to their SHA-1.
    #[test]
    fn every_dism_compressed_resource_decodes() {
        let dir = samples_dir();
        let rows = manifest(&dir);
        let mut resources = 0u64;
        let mut chunks = 0u64;
        let mut raw_seen: BTreeMap<(String, usize), Vec<u64>> = BTreeMap::new();
        let mut raw_by_size: BTreeMap<(String, u64), Vec<Vec<u64>>> = BTreeMap::new();
        for row in rows.iter().filter(|r| r.compression == "xpress") {
            let b = std::fs::read(dir.join(&row.file)).unwrap();
            let h = parse_header(&b).unwrap();
            let table = slice(&b, &h.lookup);
            let mut in_file = 0;
            for (k, raw) in table.chunks(50).enumerate() {
                let e = LookupEntry::parse(raw).unwrap();
                if !e.reshdr.is_compressed() {
                    continue;
                }
                let positions = raw_chunk_positions(&b, &e.reshdr);
                if !positions.is_empty() {
                    raw_by_size
                        .entry((row.id.clone(), e.reshdr.original_size))
                        .or_default()
                        .push(positions.clone());
                    raw_seen.insert((row.id.clone(), k), positions);
                }
                let out = decode_resource(&b, &e.reshdr).unwrap_or_else(|err| {
                    panic!(
                        "{} offset {}: {} {err}",
                        row.file,
                        e.reshdr.offset,
                        err.reason_code()
                    )
                });
                assert_eq!(
                    u64::try_from(out.len()).unwrap(),
                    e.reshdr.original_size,
                    "{} offset {}",
                    row.file,
                    e.reshdr.offset
                );
                assert_eq!(
                    usgp_crypto::digest::legacy_sha1(&out).0,
                    e.sha1,
                    "{} offset {}: SHA-1",
                    row.file,
                    e.reshdr.offset
                );
                in_file += 1;
                chunks += e.reshdr.original_size.div_ceil(32768);
            }
            assert!(in_file > 0, "{}: no compressed resource", row.file);
            resources += in_file;
        }
        // R1 (OBS-011, OBS-012): 83 resources, 369 chunk instances over
        // S02, S04, S05, S09 and the seven S06 parts; later runs add more.
        if rows.iter().any(|r| r.id == "S02") {
            assert!(resources >= 83 && chunks >= 369, "{resources} {chunks}");
        }
        // OBS-046: the raw chunks seen, by position.
        if set_present(&rows, &["S14", "S17"], "raw chunk positions") {
            // By resource size, as lookup positions differ between runs
            // (R3: S14 entry 3030, S17 entries 1 and 2).
            let by = |id: &str, size: u64| {
                let mut v = raw_by_size
                    .get(&(id.to_owned(), size))
                    .cloned()
                    .unwrap_or_default();
                v.sort();
                v
            };
            assert_eq!(
                by("S14", 196_608),
                vec![vec![0, 1, 4, 5]],
                "S14 sparse file"
            );
            assert_eq!(by("S17", 65_536), vec![vec![0], vec![1]], "S17 mixed files");
        }
        // OBS-057: S17B's short final chunks (100, 32767, 5000 bytes) are
        // stored raw; M-21.
        if set_present(&rows, &["S17B"], "short raw chunks") {
            for size in [32_868u64, 65_535, 37_768] {
                assert_eq!(
                    raw_by_size.get(&("S17B".to_owned(), size)).cloned(),
                    Some(vec![vec![1]]),
                    "S17B resource of {size}"
                );
            }
        }
        let raw_total: usize = raw_seen.values().map(Vec::len).sum();
        println!(
            "decoded {resources} compressed resources, {chunks} chunks, \
             {raw_total} raw chunks in {} resources",
            raw_seen.len()
        );
    }

    /// 0-based positions of the chunks of compressed resource `rh` stored
    /// at their expanded size (OBS-011 table layout, 4-byte entries;
    /// OBS-046, OBS-057).
    fn raw_chunk_positions(b: &[u8], rh: &ResourceHeader) -> Vec<u64> {
        let n = rh.original_size.div_ceil(32768);
        let table_len = (n - 1) * 4;
        let start = usize::try_from(rh.offset).unwrap();
        let mut ends: Vec<u64> = (0..n - 1)
            .map(|i| {
                let at = start + 4 * usize::try_from(i).unwrap();
                u64::from(u32::from_le_bytes(b[at..at + 4].try_into().unwrap()))
            })
            .collect();
        ends.push(rh.stored_size - table_len);
        let mut prev = 0;
        let mut out = Vec::new();
        for (i, end) in ends.into_iter().enumerate() {
            let expanded = (rh.original_size - 32768 * i as u64).min(32768);
            // M-21: raw exactly when stored == expanded (OBS-046, OBS-057).
            if end - prev == expanded {
                out.push(i as u64);
            }
            prev = end;
        }
        out
    }

    // ---- M3: metadata (OBS-024 to OBS-048) ----

    /// The decoded metadata of image 1 of `b`, checked against its SHA-1.
    fn metadata_bytes(b: &[u8]) -> Vec<u8> {
        let m = metadata_entries(b)[0];
        let out = decode_resource(b, &m.reshdr).unwrap();
        assert_eq!(usgp_crypto::digest::legacy_sha1(&out).0, m.sha1);
        out
    }

    /// `\`-joined path of every entry ("." for the root).
    fn entry_paths(t: &ImageTree) -> Vec<String> {
        let mut out: Vec<String> = Vec::with_capacity(t.entries.len());
        for e in &t.entries {
            let p = match (e.parent, &e.name) {
                (Some(0), Some(n)) => n.as_str().to_owned(),
                (Some(i), Some(n)) => format!("{}\\{}", out[i], n.as_str()),
                _ => ".".to_owned(),
            };
            out.push(p);
        }
        out
    }

    struct ManifestRow {
        kind: String,
        attributes: u32,
        times: [u64; 3],
        length: Option<u64>,
        sha256: Option<String>,
        streams: Vec<(String, u64, String)>,
        sddl: Option<String>,
        link_target: Option<String>,
        hard_links: Vec<String>,
        reparse_tag: Option<u32>,
    }

    fn opt(v: &str) -> Option<String> {
        (v != "-").then(|| v.to_owned())
    }

    /// `tree-meta.manifest.tsv` or `volume-root.manifest.tsv`, by path.
    fn tree_manifest(path: &Path) -> BTreeMap<String, ManifestRow> {
        // R4 adds `sd-binary` and `link-dacl` (OBS-053, OBS-054); they are
        // .NET's re-serialisation and the link's own DACL, not compared
        // here (BOOT-R4-002, BOOT-R4-004).
        let text = std::fs::read_to_string(path).unwrap();
        let header_len = text.lines().next().unwrap().split('\t').count();
        let mut header: Vec<&str> = vec![
            "path",
            "type",
            "attributes",
            "creation",
            "last-access",
            "last-write",
            "length",
            "sha256",
            "streams",
            "sddl",
            "link-target",
            "hard-links",
            "reparse-tag",
        ];
        if header_len == 15 {
            header.extend(["sd-binary", "link-dacl"]);
        }
        let rows: Vec<Vec<String>> = read_tsv(path, &header)
            .into_iter()
            .map(|mut r| {
                r.truncate(13);
                r
            })
            .collect();
        let hex32 = |v: &str| u32::from_str_radix(v.trim_start_matches("0x"), 16).unwrap();
        rows.into_iter()
            .map(|r| {
                let [p, kind, a, c, la, lw, len, sha, st, sddl, lt, hl, rt] =
                    <[String; 13]>::try_from(r).unwrap();
                let streams = opt(&st)
                    .map(|v| {
                        v.split(';')
                            .map(|one| {
                                let mut it = one.rsplitn(3, ':');
                                let sha = it.next().unwrap().to_owned();
                                let len = it.next().unwrap().parse().unwrap();
                                let name = it.next().unwrap().to_owned();
                                (name, len, sha)
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                (
                    p,
                    ManifestRow {
                        kind,
                        attributes: hex32(&a),
                        times: [c.parse().unwrap(), la.parse().unwrap(), lw.parse().unwrap()],
                        length: opt(&len).map(|v| v.parse().unwrap()),
                        sha256: opt(&sha),
                        streams,
                        sddl: opt(&sddl),
                        link_target: opt(&lt),
                        hard_links: opt(&hl)
                            .map(|v| v.split('|').map(str::to_owned).collect())
                            .unwrap_or_default(),
                        reparse_tag: opt(&rt).map(|v| hex32(&v)),
                    },
                )
            })
            .collect()
    }

    /// Decoded content of resource `hash` in `b`, by the product's reader.
    fn content(b: &[u8], lookup: &HashMap<[u8; 20], ResourceHeader>, hash: [u8; 20]) -> Vec<u8> {
        let out = decode_resource(b, &lookup[&hash]).unwrap();
        assert_eq!(usgp_crypto::digest::legacy_sha1(&out).0, hash);
        out
    }

    fn sha256_of(d: &[u8]) -> String {
        usgp_crypto::sha256(d).to_hex()
    }

    /// Compares the parsed tree of `b` with a tree manifest whose paths
    /// carry `prefix` below the manifest root (S15: the volume root holds
    /// `tree-meta`; hard-link paths are volume paths).
    ///
    /// With `content_recorded` false (S15: `volume-root.manifest.tsv`
    /// reads no content, scripts/wim-samples/README.md), content and named
    /// streams are decoded and checked against their SHA-1 but not
    /// compared with the manifest; S13 and S14 compare the same files
    /// strictly.
    fn compare_with_manifest(
        id: &str,
        b: &[u8],
        t: &ImageTree,
        m: &BTreeMap<String, ManifestRow>,
        link_prefix: &str,
        content_recorded: bool,
    ) {
        let h = parse_header(b).unwrap();
        let lookup: HashMap<[u8; 20], ResourceHeader> = all_entries(b)
            .into_iter()
            .filter(|e| !e.reshdr.is_metadata())
            .map(|e| (e.sha1, e.reshdr))
            .collect();
        let _ = h;
        let paths = entry_paths(t);
        // OBS-044: the system-information folder is not in the image.
        let expected: BTreeSet<&String> = m
            .keys()
            .filter(|p| *p != "System Volume Information")
            .collect();
        let got: BTreeSet<&String> = paths.iter().collect();
        assert_eq!(got, expected, "{id}: path sets differ");
        // Link groups by value (OBS-035).
        let mut groups: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
        for (e, p) in t.entries.iter().zip(&paths) {
            if let Some(g) = e.link_group {
                groups.entry(g).or_default().insert(p.clone());
            }
        }
        // OBS-038: each descriptor index has one SDDL string.
        let mut sddl_of: BTreeMap<u32, BTreeSet<String>> = BTreeMap::new();
        for (e, p) in t.entries.iter().zip(&paths) {
            let r = &m[p];
            // OBS-033: attributes as reported.
            assert_eq!(e.attributes.0, r.attributes, "{id} {p} attributes");
            // OBS-034: creation, last access, last write.
            assert_eq!(
                [e.times.creation, e.times.last_access, e.times.last_write],
                r.times,
                "{id} {p} times"
            );
            if let Some(sddl) = &r.sddl {
                sddl_of.entry(e.security).or_default().insert(sddl.clone());
            }
            match r.kind.as_str() {
                "dir" => assert_eq!(e.kind, EntryKind::Directory, "{id} {p}"),
                "file" => {
                    assert_eq!(e.kind, EntryKind::File, "{id} {p}");
                    let data = e.data.map(|h| content(b, &lookup, h)).unwrap_or_default();
                    if !content_recorded {
                        assert_eq!(r.sha256, None, "{id} {p}");
                    } else if e.attributes.0 & attr::ENCRYPTED != 0 {
                        // OBS-040: stored in a form that is not the
                        // plaintext.
                        assert_ne!(Some(sha256_of(&data)), r.sha256, "{id} {p}");
                    } else {
                        assert_eq!(Some(data.len() as u64), r.length, "{id} {p} length");
                        assert_eq!(Some(sha256_of(&data)), r.sha256, "{id} {p} content");
                    }
                }
                k if k.starts_with("reparse:") => {
                    let rp = e.reparse.unwrap_or_else(|| panic!("{id} {p} no reparse"));
                    // OBS-036: the tag as Windows reports it.
                    assert_eq!(Some(rp.tag), r.reparse_tag, "{id} {p} tag");
                    let want = if k == "reparse:Junction" {
                        EntryKind::Junction
                    } else {
                        EntryKind::Symlink {
                            directory: e.attributes.0 & attr::DIRECTORY != 0,
                        }
                    };
                    assert_eq!(e.kind, want, "{id} {p}");
                    // OBS-036: +92 is 0x00010000 exactly on the relative
                    // targets (no drive letter in the manifest target).
                    let target = r.link_target.as_deref().unwrap_or("");
                    let relative = !target.contains(':');
                    assert_eq!(rp.field_92 == REPARSE_FIELD_RELATIVE, relative, "{id} {p}");
                    let data = content(b, &lookup, rp.data);
                    assert!(!data.is_empty());
                }
                other => panic!("{id} {p}: type {other}"),
            }
            // OBS-032: named streams with their content.
            let mut got: Vec<(String, u64, String)> = e
                .streams
                .iter()
                .map(|s| {
                    let d = s.hash.map(|h| content(b, &lookup, h)).unwrap_or_default();
                    (s.name.as_str().to_owned(), d.len() as u64, sha256_of(&d))
                })
                .collect();
            got.sort();
            let mut want = r.streams.clone();
            want.sort();
            if content_recorded {
                assert_eq!(got, want, "{id} {p} streams");
            }
            // OBS-035: hard-link names.
            if !r.hard_links.is_empty() {
                let g = e.link_group.unwrap_or_else(|| panic!("{id} {p}: no group"));
                let want: BTreeSet<String> = r
                    .hard_links
                    .iter()
                    .map(|l| l.strip_prefix(link_prefix).unwrap().to_owned())
                    .collect();
                assert_eq!(groups[&g], want, "{id} {p} link group");
            } else {
                assert!(e.link_group.is_none(), "{id} {p}: unexpected group");
            }
        }
        for (k, v) in &sddl_of {
            assert_eq!(v.len(), 1, "{id}: descriptor {k} has several SDDL strings");
        }
        println!(
            "{id}: {} entries match the manifest (content compared: {content_recorded})",
            t.entries.len()
        );
        let distinct: BTreeSet<&String> = sddl_of.values().flatten().collect();
        assert_eq!(
            distinct.len(),
            sddl_of.len(),
            "{id}: one SDDL under two indexes"
        );
    }

    /// OBS-024 to OBS-048 on S13, S14 and S15, through the product's
    /// parser (M-01 to M-23).
    #[test]
    fn metadata_matches_observations() {
        let dir = samples_dir();
        let rows = manifest(&dir);
        if !set_present(
            &rows,
            &["S13", "S14", "S15"],
            "metadata_matches_observations",
        ) {
            return;
        }
        let tree_meta = tree_manifest(&dir.join("tree-meta.manifest.tsv"));
        let volume = tree_manifest(&dir.join("volume-root.manifest.tsv"));
        let mut decoded: BTreeMap<&str, Vec<u8>> = BTreeMap::new();
        for (id, entries, descriptors, root_at) in [
            ("S13", 3057usize, 7usize, 1096usize),
            ("S14", 3057, 7, 1096),
            ("S15", 3058, 8, 1312),
        ] {
            let b = dism_file(&dir, &rows, id);
            let m = metadata_bytes(&b);
            let t = parse_metadata(&m, &MetadataLimits::DEFAULT)
                .unwrap_or_else(|e| panic!("{id}: {} {e}", e.reason_code()));
            // OBS-024, OBS-026, OBS-048.
            assert_eq!(t.entries.len(), entries, "{id} entries");
            assert_eq!(t.security.len(), descriptors, "{id} descriptors");
            let total = u32::from_le_bytes(m[0..4].try_into().unwrap()) as usize;
            assert_eq!(total.next_multiple_of(8), root_at, "{id} root offset");
            assert_eq!(
                u64::from_le_bytes(m[root_at..root_at + 8].try_into().unwrap()),
                104
            );
            let (prefix, manifest) = if id == "S15" {
                ("\\", &volume)
            } else {
                ("\\tree-meta\\", &tree_meta)
            };
            compare_with_manifest(id, &b, &t, manifest, prefix, id != "S15");
            // OBS-028: the explicitly set short name.
            let paths = entry_paths(&t);
            let explicit = paths
                .iter()
                .position(|p| p.ends_with("shortnames\\explicit-short-name-target.txt"))
                .unwrap();
            assert_eq!(
                t.entries[explicit].short_name.as_ref().map(|s| s.as_str()),
                Some("EXPLICIT.TXT")
            );
            // OBS-048 counts; M-23 (warning-level in the product).
            let xml = parse_xml(
                &slice(&b, &parse_header(&b).unwrap().xml),
                &WimLimits::DEFAULT,
            )
            .unwrap();
            let img = &xml.images[0];
            let (dirs, files) = t.dir_and_file_counts();
            assert_eq!(
                img.leaf("DIRCOUNT").map(str::to_owned),
                Some(dirs.to_string()),
                "{id}"
            );
            assert_eq!(
                img.leaf("FILECOUNT").map(str::to_owned),
                Some(files.to_string()),
                "{id}"
            );
            decoded.insert(id, m);
        }
        // OBS-043: XPRESS metadata decodes to the uncompressed capture's
        // bytes.
        assert_eq!(
            decoded["S13"], decoded["S14"],
            "S14 metadata differs from S13"
        );
        // Every accepted image of the set parses.
        for row in rows.iter().filter(|r| r.expected == "accept") {
            let b = dism_file(&dir, &rows, &row.id);
            parse_metadata(&metadata_bytes(&b), &MetadataLimits::DEFAULT)
                .unwrap_or_else(|e| panic!("{}: {}", row.id, e.reason_code()));
        }
    }

    /// Every accepted image of the Standard set parses as metadata too
    /// (S01 33 entries, OBS-048), so earlier samples keep working.
    #[test]
    fn standard_set_metadata_parses() {
        let dir = samples_dir();
        let rows = manifest(&dir);
        if !set_present(&rows, &["S01"], "standard_set_metadata_parses") {
            return;
        }
        let mut images = 0;
        for row in rows
            .iter()
            .filter(|r| r.expected == "accept" || recorded(&r.id).is_some())
        {
            let b = dism_file(&dir, &rows, &row.id);
            let h = parse_header(&b).unwrap();
            let len = u64::try_from(b.len()).unwrap();
            let compression = if h.flags & 0x2 != 0 {
                Compression::Xpress
            } else {
                Compression::None
            };
            let scan = parse_table(&slice(&b, &h.lookup), compression, len, 1024).unwrap();
            // SEC-002: each distinct metadata resource once.
            for (index, e) in scan.distinct_metadata() {
                let m = decode_resource(&b, &e.reshdr).unwrap();
                let t = parse_metadata(&m, &MetadataLimits::DEFAULT).unwrap_or_else(|err| {
                    panic!("{} index {index}: {} {err}", row.id, err.reason_code())
                });
                if row.id == "S01" {
                    assert_eq!(t.entries.len(), 33, "S01 entries (OBS-048)");
                    assert_eq!(t.security.len(), 2, "S01 descriptors (OBS-024)");
                }
                images += 1;
            }
        }
        println!("parsed {images} distinct metadata resources");
    }

    fn mem_apply(
        b: Vec<u8>,
        root: &str,
    ) -> (
        Result<usgp_image::apply::ApplyReport, usgp_image::apply::ApplyError>,
        MemorySink,
    ) {
        let mut sink = MemorySink::new();
        let r = apply(
            &mut MemoryChunks::new(b),
            1,
            &ApplyRoot::parse(root).unwrap(),
            &mut sink,
            &ApplyLimits::new(1 << 32),
            &mut NoProgress,
            usgp_crypto::provider(),
        );
        (r, sink)
    }

    /// S17 applies (raw chunks, OBS-046) and its two files have the SHA-1
    /// recorded in `trees.txt`; S13 to S15 hold an EFS file, a junction
    /// and absolute links, so the product refuses them by name before any
    /// write (M-10, M-13, OPEN-WIM-12).
    #[test]
    fn metadata_samples_apply() {
        let dir = samples_dir();
        let rows = manifest(&dir);
        if !set_present(
            &rows,
            &["S13", "S14", "S15", "S17"],
            "metadata_samples_apply",
        ) {
            return;
        }
        let (r, sink) = mem_apply(dism_file(&dir, &rows, "S17"), "W:\\");
        let report = r.unwrap_or_else(|e| panic!("S17: {} {e}", e.reason_code()));
        assert_eq!(report.preview.xml_counts, XmlCounts::Match);
        let want = &tree_hashes(&dir)["tree-mixed"];
        let mut got = Vec::new();
        for (p, n) in sink.entries() {
            if n.kind == MemoryNodeKind::File {
                got.push(usgp_crypto::digest::legacy_sha1(&n.data).0);
                assert_eq!(n.data.len(), 65536, "{p:?}");
            }
        }
        got.sort();
        let mut want = want.clone();
        want.sort();
        assert_eq!(got, want, "S17 content");
        // Decision 0022 applies their links and junctions; the EFS file
        // (OBS-040) still refuses the image.
        for id in ["S13", "S14", "S15"] {
            let (r, sink) = mem_apply(dism_file(&dir, &rows, id), "W:\\");
            let e = r.unwrap_err();
            assert_eq!(e.reason_code(), "wim_efs_not_supported", "{id}");
            assert!(sink.ops().is_empty(), "{id}: written before refusal");
        }
    }

    /// `fsutil reparsepoint query` output (`<id>.reparse.txt`): per path,
    /// the tag and the "Reparse Data" bytes.
    fn reparse_dump(path: &Path) -> BTreeMap<String, (u32, Vec<u8>)> {
        let text =
            std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let mut out = BTreeMap::new();
        let mut cur: Option<(String, u32, Vec<u8>, bool)> = None;
        let mut flush = |c: Option<(String, u32, Vec<u8>, bool)>| {
            if let Some((p, t, d, _)) = c {
                out.insert(p, (t, d));
            }
        };
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("== ") {
                flush(cur.take());
                // "== <id> <path> (exit 0)"
                let rest = rest.split_once(' ').unwrap().1;
                let p = rest.rsplit_once(" (exit").unwrap().0;
                cur = Some((p.to_owned(), 0, Vec::new(), false));
                continue;
            }
            let Some(c) = cur.as_mut() else { continue };
            if let Some(v) = line.strip_prefix("Reparse Tag Value : 0x") {
                c.1 = u32::from_str_radix(v.trim(), 16).unwrap();
            } else if line.starts_with("Reparse Data:") {
                c.3 = true;
            } else if c.3 && line.len() > 6 && line.as_bytes()[4] == b':' {
                let hex = &line[7..line.len().min(56)];
                c.2.extend(
                    hex.split_whitespace()
                        .map(|h| u8::from_str_radix(h, 16).unwrap()),
                );
            }
        }
        flush(cur);
        out
    }

    /// Decision 0022 against DISM (OBS-050, OBS-051): S13B applied to `S:\`
    /// and to `U:\deep\apply-here`, and S13C to `V:\`, through the
    /// product's apply, give byte for byte the reparse data DISM's apply
    /// left (S16B, S16C, S16D in the Reference artifact named by
    /// `USGP_WIM_REFERENCE`): the 8 re-based buffers and every copy.
    #[test]
    fn rebase_matches_dism_reference() {
        let dir = samples_dir();
        let rows = manifest(&dir);
        if !set_present(&rows, &["S13B", "S13C"], "rebase_matches_dism_reference") {
            return;
        }
        let refdir = std::env::var_os("USGP_WIM_REFERENCE").map(PathBuf::from).unwrap_or_else(|| {
            panic!("USGP_WIM_REFERENCE is not set: S13B/S13C need the wim-samples-reference artifact")
        });
        assert!(refdir.is_dir(), "USGP_WIM_REFERENCE is not a directory");
        let mut rebased_total = 0;
        for (id, root, dump, rebased_want) in [
            ("S13B", "S:\\", "S16B.reparse.txt", 4),
            ("S13B", "U:\\deep\\apply-here", "S16C.reparse.txt", 4),
            ("S13C", "V:\\", "S16D.reparse.txt", 0),
        ] {
            let want = reparse_dump(&refdir.join(dump));
            assert_eq!(want.len(), 12, "{dump}: reparse points");
            let (r, sink) = mem_apply(dism_file(&dir, &rows, id), root);
            r.unwrap_or_else(|e| panic!("{id} to {root}: {} {e}", e.reason_code()));
            let mut seen = 0;
            let mut rebased = 0;
            for (p, n) in sink.entries() {
                let Some(b) = &n.reparse else { continue };
                let key = p.to_text();
                let (tag, data) = want.get(&key).unwrap_or_else(|| panic!("{dump}: no {key}"));
                assert_eq!(b.tag(), *tag, "{dump} {key} tag");
                assert_eq!(b.data(), data.as_slice(), "{dump} {key} data");
                seen += 1;
                rebased += usize::from(b.rebased());
            }
            assert_eq!(seen, 12, "{id} to {root}");
            assert_eq!(rebased, rebased_want, "{id} to {root}: re-based");
            rebased_total += rebased;
        }
        assert_eq!(rebased_total, 8, "the 8 byte-exact re-base predictions");
        println!("reparse buffers equal DISM's: 36 of 36 (8 re-based)");
    }

    /// OPEN-WIM-13: the volume-root capture S15 (RP_FIX set, captured
    /// from the volume root, so its stored targets keep `\tree-meta`)
    /// against DISM's applies of it to `W:\` (S16E) and to
    /// `X:\deep\apply-here` (S16F), from the R5 Reference artifact
    /// (`USGP_WIM_REFERENCE`). S15 holds the EFS file (OBS-040), so the
    /// whole image is refused; each link's stored data is therefore run
    /// through the same decision 0022 function the apply uses
    /// (`wim::reparse::prepare`) with the file's header flags. Every
    /// entry's result is printed; any difference fails the test and is
    /// for decision, not for a rule change. Skipped (printed) with a
    /// Reference artifact without S16E/S16F (R4).
    #[test]
    fn volume_root_rebase_against_dism_reference() {
        let dir = samples_dir();
        let rows = manifest(&dir);
        if !set_present(&rows, &["S15"], "volume_root_rebase_against_dism_reference") {
            return;
        }
        let refdir = std::env::var_os("USGP_WIM_REFERENCE")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                panic!("USGP_WIM_REFERENCE is not set: S15 needs the Reference artifact")
            });
        if !refdir.join("S16E.reparse.txt").is_file() {
            assert!(
                !refdir.join("S16F.reparse.txt").is_file(),
                "S16F without S16E"
            );
            println!(
                "volume_root_rebase_against_dism_reference: no S16E/S16F in this Reference artifact"
            );
            return;
        }
        let b = dism_file(&dir, &rows, "S15");
        let h = parse_header(&b).unwrap();
        let lookup: HashMap<[u8; 20], ResourceHeader> = all_entries(&b)
            .into_iter()
            .filter(|e| !e.reshdr.is_metadata())
            .map(|e| (e.sha1, e.reshdr))
            .collect();
        let t = parse_metadata(&metadata_bytes(&b), &MetadataLimits::DEFAULT).unwrap();
        let paths = entry_paths(&t);
        let mut mismatches = Vec::new();
        let mut matched = 0;
        for (root, dump) in [
            ("W:\\", "S16E.reparse.txt"),
            ("X:\\deep\\apply-here", "S16F.reparse.txt"),
        ] {
            let want = reparse_dump(&refdir.join(dump));
            let r = ApplyRoot::parse(root).unwrap();
            let mut seen = 0;
            for (e, p) in t.entries.iter().zip(&paths) {
                let Some(rp) = e.reparse else { continue };
                seen += 1;
                let stored = content(&b, &lookup, rp.data);
                let got =
                    usgp_image::wim::reparse::prepare(h.flags, rp.tag, rp.field_92, &stored, &r);
                let (wtag, wdata) = want.get(p).unwrap_or_else(|| panic!("{dump}: no {p}"));
                let hex = |d: &[u8]| d.iter().map(|x| format!("{x:02x}")).collect::<String>();
                match got {
                    Ok(buf) if buf.tag() == *wtag && buf.data() == wdata.as_slice() => {
                        matched += 1;
                        println!(
                            "MATCH {dump} {p}: M=0x{:08x} {} {} bytes",
                            rp.field_92,
                            if buf.rebased() { "re-based" } else { "copied" },
                            buf.data().len()
                        );
                    }
                    Ok(buf) => {
                        println!(
                            "DIFF {dump} {p}: M=0x{:08x} rebased={}\n  stored  {}\n  ours    {}\n  dism    {}",
                            rp.field_92,
                            buf.rebased(),
                            hex(&stored),
                            hex(buf.data()),
                            hex(wdata)
                        );
                        mismatches.push(format!("{dump} {p}"));
                    }
                    Err(err) => {
                        println!(
                            "REFUSED {dump} {p}: M=0x{:08x} {}\n  stored  {}\n  dism    {}",
                            rp.field_92,
                            err.reason_code(),
                            hex(&stored),
                            hex(wdata)
                        );
                        mismatches.push(format!("{dump} {p} ({})", err.reason_code()));
                    }
                }
            }
            assert_eq!(seen, want.len(), "{dump}: reparse points");
        }
        println!(
            "S15 against S16E/S16F: {matched} match, {} differ",
            mismatches.len()
        );
        assert!(mismatches.is_empty(), "differs from DISM: {mismatches:?}");
    }

    /// M-15, OBS-055: S13B's sparse blocks, parsed and validated by the
    /// product, give the deallocated ranges recorded, last first; the
    /// sparse file without holes has no block.
    #[test]
    fn sparse_blocks_match_observations() {
        let dir = samples_dir();
        let rows = manifest(&dir);
        if !set_present(&rows, &["S13B"], "sparse_blocks_match_observations") {
            return;
        }
        let m = metadata_bytes(&dism_file(&dir, &rows, "S13B"));
        let t = parse_metadata(&m, &MetadataLimits::DEFAULT).unwrap();
        let paths = entry_paths(&t);
        let ranges = |name: &str| {
            let i = paths
                .iter()
                .position(|p| p.ends_with(&format!("sparse\\{name}")))
                .unwrap_or_else(|| panic!("no {name}"));
            t.entries[i].sparse_ranges.clone()
        };
        let k = 0x10000u64;
        assert_eq!(
            ranges("three-holes.bin"),
            vec![(5 * k, 6 * k), (3 * k, 4 * k), (k, 2 * k)]
        );
        assert_eq!(ranges("two-holes.bin"), vec![(3 * k, 4 * k), (k, 2 * k)]);
        assert_eq!(ranges("hole-at-start.bin"), vec![(0, k)]);
        assert_eq!(ranges("hole-at-end.bin"), vec![(k, 2 * k)]);
        assert_eq!(ranges("all-hole.bin"), vec![(0, 3 * k)]);
        assert!(ranges("flag-only.bin").is_empty());
    }

    /// The entry forms (OBS-025 to OBS-039) of a metadata resource, as the
    /// product's parser sees them.
    fn forms(m: &[u8], t: &ImageTree) -> BTreeSet<&'static str> {
        let mut f = BTreeSet::new();
        let total = u32::from_le_bytes(m[0..4].try_into().unwrap()) as usize;
        if m[total..total.next_multiple_of(8)].iter().all(|&b| b == 0) {
            f.insert("root at the next multiple of 8, zero gap");
        }
        if t.security.iter().all(|d| d.starts_with(&[1, 0, 4])) {
            f.insert("descriptors start 01 00 04");
        }
        for e in &t.entries {
            let named = !e.streams.is_empty();
            f.insert(match (e.kind, named, e.data.is_some()) {
                (EntryKind::Directory, false, _) => "directory",
                (EntryKind::Directory, true, _) => "directory with named stream",
                (EntryKind::File, false, true) => "file with data",
                (EntryKind::File, false, false) => "empty file",
                (EntryKind::File, true, true) => "file with data and named streams",
                (EntryKind::File, true, false) => "empty main stream with named streams",
                (EntryKind::Symlink { directory: true }, _, _) => "directory symbolic link",
                (EntryKind::Symlink { directory: false }, _, _) => "file symbolic link",
                (EntryKind::Junction, _, _) => "junction",
            });
            if e.streams.iter().any(|s| s.hash.is_none()) {
                f.insert("empty named stream");
            }
            if e.short_name.is_some() {
                f.insert("short name");
            }
            if e.link_group.is_some() {
                f.insert("hard-link name");
            }
            if e.attributes.0 & attr::SPARSE != 0 {
                f.insert("sparse file");
            }
            if e.name
                .as_ref()
                .is_some_and(|n| n.as_str().chars().any(|c| c as u32 > 0xFFFF))
            {
                f.insert("non-BMP name");
            }
            if let Some(r) = e.reparse
                && r.tag == tag::SYMLINK
                && r.field_92 == REPARSE_FIELD_RELATIVE
            {
                f.insert("relative symbolic link");
            }
        }
        f
    }

    /// The testkit encoder (`TreeSpec`) writes only entry forms DISM wrote
    /// in S13 (and S01 for the non-BMP name), so synthetic apply tests
    /// exercise observed layouts only (decision 0006 item 4).
    #[test]
    fn builder_metadata_matches_dism() {
        let dir = samples_dir();
        let rows = manifest(&dir);
        if !set_present(&rows, &["S13"], "builder_metadata_matches_dism") {
            return;
        }
        let m = metadata_bytes(&dism_file(&dir, &rows, "S13"));
        let t = parse_metadata(&m, &MetadataLimits::DEFAULT).unwrap();
        let mut dism = forms(&m, &t);
        // In S01's tree (the Standard set), not in S13: OBS-027 the
        // non-BMP name, OBS-031 a plain empty file (`text\empty.txt`).
        dism.insert("non-BMP name");
        dism.insert("empty file");
        let spec = TreeSpec::sample();
        let ours_bytes = spec.encode().bytes;
        let ours_tree = parse_metadata(&ours_bytes, &MetadataLimits::DEFAULT).unwrap();
        let ours = forms(&ours_bytes, &ours_tree);
        let extra: Vec<_> = ours.difference(&dism).collect();
        assert!(
            extra.is_empty(),
            "builder writes forms DISM did not: {extra:?}"
        );
        println!("forms shared with S13: {}", ours.len());
    }
}
