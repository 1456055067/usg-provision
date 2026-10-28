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

    use usgp_crypto::CryptoProvider;
    use usgp_image::testkit::{WimBuilder, decode_resource};
    use usgp_image::wim::header::{WimHeader, parse_header};
    use usgp_image::wim::integrity::IntegrityTableHeader;
    use usgp_image::wim::lookup::{LookupEntry, parse_table};
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
        assert!(
            accepted > 0 && refused > 0,
            "manifest lacks accept or refuse rows"
        );
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
    #[test]
    fn every_dism_compressed_resource_decodes() {
        let dir = samples_dir();
        let rows = manifest(&dir);
        let mut resources = 0u64;
        let mut chunks = 0u64;
        for row in rows.iter().filter(|r| r.compression == "xpress") {
            let b = std::fs::read(dir.join(&row.file)).unwrap();
            let h = parse_header(&b).unwrap();
            let table = slice(&b, &h.lookup);
            let mut in_file = 0;
            for raw in table.chunks(50) {
                let e = LookupEntry::parse(raw).unwrap();
                if !e.reshdr.is_compressed() {
                    continue;
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
        assert!(resources >= 83 && chunks >= 369, "{resources} {chunks}");
        println!("decoded {resources} compressed resources, {chunks} chunks");
    }
}
