//! Writes the WU-8 and WU-9 fuzz seeds into `fuzz/corpus/<target>/`.
//!
//! Usage (from `fuzz/`): `cargo run --example gen_seeds -- corpus`
//!
//! Every seed is built here by our own encoders (`usgp_dhcp::craft`,
//! `usgp_tftp::encode_*`, the `usgp-image` test WIM builder and XPRESS
//! test encoder, and `usgp-proto` types serialized with `serde_json`);
//! none comes from captured traffic, logs, third-party WIM or XPRESS
//! samples, or images (fuzz/README.md, seed origin rule; decision 0006).
//! The seed list is recorded in `fuzz/corpus/*/SOURCE.md`. Names start with
//! `wu8-` or `wu9-` so they never clash with the seeds written by the crate
//! examples.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use usgp_crypto::Sha256Digest;
use usgp_dhcp::craft::RequestBuilder;
use usgp_image::Compression;
use usgp_image::testkit::builder::{ImageSpec, pseudorandom};
use usgp_image::testkit::xpress_enc::{self, Block, Token};
use usgp_image::testkit::{BuildInfo, WimBuilder};
use usgp_image::wim::xml::encode_utf16;
use usgp_proto::api::{
    ClonePackageRequest, CreateUploadRequest, EditionDeclarationRequest, PackageRequest,
    PeDeclarationRequest,
};
use usgp_proto::content_manifest::SCHEMA_V1 as CONTENT_SCHEMA_V1;
use usgp_proto::envelope::{PayloadType, SignatureAlg, SignatureV1, SignedEnvelopeV1};
use usgp_proto::facts::{Architecture, Edition, EditionFacts, Fact, KitVersion, Release};
use usgp_proto::limits::CHUNK_SIZE;
use usgp_proto::{
    ContentId, ContentKind, ContentManifestV1, DisplayName, EditionIndex, FileName,
    ManifestEdition, OperatorId, PackageId, PackageImageV1, PackageManifestV1, PackagePeV1,
    UnixMicros, WimCompression, WimSummaryV1, WimText,
};
use usgp_tftp::{Opcode, encode_ack, encode_request};

type Seeds = Vec<(&'static str, Vec<u8>)>;

/// Turns a builder or constructor error into a message for `main`.
fn ok<T, E: std::fmt::Debug>(r: Result<T, E>, what: &str) -> Result<T, String> {
    r.map_err(|e| format!("{what}: {e:?}"))
}

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

fn write_all(dir: &Path, seeds: Seeds) -> Result<(), ExitCode> {
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
    let wu9 = match wu9_seeds() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("gen_seeds: {e}");
            return ExitCode::FAILURE;
        }
    };
    for (target, seeds) in wu9 {
        if let Err(c) = write_all(&root.join(target), seeds) {
            return c;
        }
    }
    ExitCode::SUCCESS
}

// ---------------------------------------------------------------------------
// WU-9: WIM, XPRESS and API seeds
// ---------------------------------------------------------------------------

fn slice(b: &[u8], offset: u64, len: u64) -> Result<Vec<u8>, String> {
    let s = ok(usize::try_from(offset), "offset")?;
    let n = ok(usize::try_from(len), "length")?;
    let e = s.checked_add(n).ok_or("range overflow")?;
    b.get(s..e)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| "builder layout".to_owned())
}

/// An image with one small file, so the seed files stay small (the check
/// reads metadata, not file content).
fn small(name: &str, description: &str) -> ImageSpec {
    ImageSpec {
        name: name.to_owned(),
        description: Some(description.to_owned()),
        files: vec![b"a small file".to_vec()],
    }
}

/// Extra WIM files beyond `usgp-image/examples/gen_fuzz_seeds.rs`; each is
/// also split into its header, lookup table and XML resource.
fn wim_seeds() -> Result<[Seeds; 4], String> {
    let no_desc = ImageSpec {
        name: "no description".to_owned(),
        description: None,
        files: vec![b"one file".to_vec()],
    };
    let builds: Vec<(&'static str, (Vec<u8>, BuildInfo))> = vec![
        (
            "wu9-none-3-boot-3",
            ok(
                WimBuilder::new(Compression::None)
                    .image_spec(small("one", "first"))
                    .image_spec(small("two", "second"))
                    .image_spec(small("three", "third"))
                    .boot_index(3)
                    .build(),
                "none-3",
            )?,
        ),
        (
            "wu9-none-integrity",
            ok(
                WimBuilder::new(Compression::None)
                    .image_spec(small("a", "b"))
                    .integrity(true)
                    .build(),
                "none-integrity",
            )?,
        ),
        (
            "wu9-xpress-no-description",
            ok(
                WimBuilder::new(Compression::Xpress)
                    .image_spec(no_desc)
                    .build(),
                "no-description",
            )?,
        ),
        (
            "wu9-xpress-bad-metadata-hash",
            ok(
                WimBuilder::new(Compression::Xpress)
                    .image_spec(small("a", "b"))
                    .image_spec(small("c", "d"))
                    .bad_metadata_hash(2)
                    .build(),
                "bad-metadata-hash",
            )?,
        ),
        (
            // BOOT-011: two images with identical metadata (one SHA-1) at
            // distinct ranges; accepted.
            "wu9-xpress-identical-metadata",
            ok(
                WimBuilder::new(Compression::Xpress)
                    .image_spec(small("a", "b"))
                    .image_spec(small("c", "d"))
                    .identical_metadata(true)
                    .build(),
                "identical-metadata",
            )?,
        ),
        (
            // OBS-018 (S11A, S11B): two images name one metadata resource
            // through equal lookup entries; accepted, read once.
            "wu9-xpress-reused-metadata",
            ok(
                WimBuilder::new(Compression::Xpress)
                    .image_spec(small("a", "b"))
                    .image_spec(small("a", "b"))
                    .reuse_metadata(true)
                    .build(),
                "reused-metadata",
            )?,
        ),
        (
            // OBS-021, OBS-022 (S12A): image 1's metadata moved after every
            // other resource, the old copy left unnamed; accepted.
            "wu9-xpress-moved-first-metadata",
            ok(
                WimBuilder::new(Compression::Xpress)
                    .image_spec(small("a", "b"))
                    .image_spec(small("c", "d"))
                    .image_spec(small("e", "f"))
                    .move_first_metadata(true)
                    .build(),
                "moved-first-metadata",
            )?,
        ),
        (
            "wu9-count-mismatch",
            ok(
                WimBuilder::new(Compression::None)
                    .image_spec(small("a", "b"))
                    .image_count(2)
                    .build(),
                "count-mismatch",
            )?,
        ),
        (
            "wu9-split-part",
            ok(
                WimBuilder::new(Compression::None)
                    .image_spec(small("a", "b"))
                    .part(1, 2)
                    .build(),
                "split",
            )?,
        ),
        (
            "wu9-xml-doctype",
            ok(
                WimBuilder::new(Compression::None)
                    .image_spec(small("a", "b"))
                    .xml_text("<!DOCTYPE WIM><WIM><IMAGE INDEX=\"1\"><NAME>a</NAME></IMAGE></WIM>")
                    .build(),
                "doctype",
            )?,
        ),
    ];
    let (mut check, mut header, mut lookup, mut xml) = (vec![], vec![], vec![], vec![]);
    for (name, (bytes, info)) in builds {
        header.push((name, slice(&bytes, 0, 208)?));
        lookup.push((
            name,
            slice(&bytes, info.lookup.offset, info.lookup.stored_size)?,
        ));
        xml.push((name, slice(&bytes, info.xml.offset, info.xml.stored_size)?));
        check.push((name, bytes));
    }
    // XML only: nesting, entities, line ends, two images out of order.
    xml.push((
        "wu9-two-images-reversed",
        encode_utf16(
            "<WIM><TOTALBYTES>100</TOTALBYTES><IMAGE INDEX=\"2\"><NAME>b</NAME></IMAGE>\
             <IMAGE INDEX=\"1\"><NAME>a</NAME><DESCRIPTION>d\r\ne</DESCRIPTION>\
             <WINDOWS><VERSION><BUILD>1</BUILD></VERSION></WINDOWS></IMAGE></WIM>",
        ),
    ));
    xml.push((
        "wu9-comment-decl",
        encode_utf16(
            "<?xml version=\"1.0\"?><!-- c --><WIM><IMAGE INDEX=\"1\"><NAME>&lt;&#65;&gt;</NAME>\
             <TOTALBYTES>5</TOTALBYTES></IMAGE></WIM>",
        ),
    ));
    Ok([check, header, lookup, xml])
}

/// Decode-mode XPRESS seed: `0x00`, `expected - 1` (LE u16), chunk.
fn decode_seed(expected: usize, chunk: &[u8]) -> Result<Vec<u8>, String> {
    let n = expected.checked_sub(1).ok_or("expected length 0")?;
    let n = ok(u16::try_from(n), "expected length")?;
    let mut v = vec![0u8];
    v.extend_from_slice(&n.to_le_bytes());
    v.extend_from_slice(chunk);
    Ok(v)
}

fn blocks(tokens: Vec<Token>) -> Result<Vec<u8>, String> {
    ok(
        xpress_enc::encode_blocks(&[Block::with_optimal_lengths(tokens)]),
        "encode_blocks",
    )
}

fn xpress_seeds() -> Result<Seeds, String> {
    let text = b"the quick brown fox jumps over the lazy dog ".repeat(1600);
    let t32 = text.get(..32768).ok_or("text")?;
    let t1000 = text.get(..1000).ok_or("text")?;
    let t64 = text.get(..65536).ok_or("text")?;
    let random = pseudorandom(4096, 7);
    // Overfull table: every symbol has a 1-bit code.
    let mut overfull = ok(
        xpress_enc::encode_blocks(&[Block {
            lengths: [1u8; 512],
            tokens: Vec::new(),
        }]),
        "overfull",
    )?;
    overfull.extend_from_slice(&[0; 8]);
    // Literal 'q', match header 15 with extra length bytes 255, 3, 0
    // (extended length 3 < 15), end.
    let ext_small = blocks(vec![
        Token::Literal(b'q'),
        Token::Raw {
            symbol: 256 + 15,
            length_bytes: vec![255, 3, 0],
            offset_bits: 0,
        },
        Token::End,
    ])?;
    // Match before the start of the output.
    let before_start = blocks(vec![
        Token::Literal(1),
        Token::Match {
            length: 3,
            offset: 2,
        },
        Token::End,
    ])?;
    // Symbol 256 in the middle of the stream (a match of 3 at offset 1).
    let end_mid = blocks(vec![
        Token::Literal(b'a'),
        Token::End,
        Token::Literal(b'b'),
        Token::End,
    ])?;
    let full = xpress_enc::compress(t1000);
    let truncated = full.get(..full.len() / 2).ok_or("truncate")?.to_vec();
    let mut round_text = vec![1u8];
    round_text.extend_from_slice(text.get(..3000).ok_or("text")?);
    let mut round_random = vec![1u8];
    round_random.extend_from_slice(&pseudorandom(300, 9));
    Ok(vec![
        (
            "wu9-text-32768",
            decode_seed(32768, &xpress_enc::compress(t32))?,
        ),
        (
            "wu9-zeros-32768",
            decode_seed(32768, &xpress_enc::compress(&[0u8; 32768]))?,
        ),
        (
            "wu9-random-4096",
            decode_seed(4096, &xpress_enc::compress(&random))?,
        ),
        (
            "wu9-literals-17",
            decode_seed(17, &xpress_enc::compress_literals(b"literal only data"))?,
        ),
        ("wu9-text-1000", decode_seed(1000, &full)?),
        (
            "wu9-text-65536",
            decode_seed(65536, &xpress_enc::compress(t64))?,
        ),
        ("wu9-overfull-table", decode_seed(10, &overfull)?),
        ("wu9-ext-length-3", decode_seed(19, &ext_small)?),
        ("wu9-offset-before-start", decode_seed(100, &before_start)?),
        ("wu9-end-mid-stream", decode_seed(5, &end_mid)?),
        ("wu9-truncated-half", decode_seed(1000, &truncated)?),
        ("wu9-round-trip-text", round_text),
        ("wu9-round-trip-random", round_random),
    ])
}

fn json<T: serde::Serialize>(sel: u8, v: &T) -> Result<Vec<u8>, String> {
    let mut out = vec![sel];
    out.extend_from_slice(&ok(serde_json::to_vec(v), "serialize")?);
    Ok(out)
}

fn with_sel(sel: u8, bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![sel];
    out.extend_from_slice(bytes);
    out
}

fn api_seeds() -> Result<Seeds, String> {
    let sha = "ab".repeat(32);
    let pe_decl = PeDeclarationRequest {
        architecture: "x64".to_owned(),
        kit_version: "10.1.26100.1".to_owned(),
    };
    let upload_image = CreateUploadRequest {
        kind: "image".to_owned(),
        display_name: "Win 11 Ent".to_owned(),
        file_name: "install.wim".to_owned(),
        size: 10_500 << 20,
        sha256: sha.clone(),
        pe_declaration: None,
    };
    let upload_pe = CreateUploadRequest {
        kind: "pe".to_owned(),
        display_name: "PE x64".to_owned(),
        file_name: "boot.wim".to_owned(),
        size: 400 << 20,
        sha256: sha.clone(),
        pe_declaration: Some(pe_decl.clone()),
    };
    let upload_pe_missing = CreateUploadRequest {
        pe_declaration: None,
        ..upload_pe.clone()
    };
    let package = PackageRequest {
        name: "Field laptops".to_owned(),
        description: Some("x64 Enterprise".to_owned()),
        image_id: "0b7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e6f".to_owned(),
        edition_index: 1,
        pe_id: "1c9e8a70-2b3d-4e5f-9a0b-c1d2e3f40516".to_owned(),
    };
    let package_bad = PackageRequest {
        edition_index: 0,
        description: None,
        ..package.clone()
    };
    let decl = EditionDeclarationRequest {
        release: "windows-11".to_owned(),
        edition: "enterprise".to_owned(),
        architecture: "x64".to_owned(),
    };
    let clone = ClonePackageRequest {
        name: "Field laptops (copy)".to_owned(),
    };

    let key = Sha256Digest([7; 32]);
    let content = ContentManifestV1 {
        schema: CONTENT_SCHEMA_V1,
        kind: ContentKind::Image,
        content_id: ok(
            ContentId::parse("0b7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e6f"),
            "id",
        )?,
        display_name: ok(DisplayName::new("Win 11 Ent"), "name")?,
        file_name: ok(FileName::new("install.wim"), "file name")?,
        size: CHUNK_SIZE + 5,
        sha256: Sha256Digest([0xaa; 32]),
        chunk_size: CHUNK_SIZE,
        chunk_sha256: vec![Sha256Digest([0xbb; 32]); 2],
        wim: WimSummaryV1 {
            compression: WimCompression::Xpress,
            image_count: 2,
            boot_index: 0,
            editions: vec![
                ManifestEdition {
                    index: ok(EditionIndex::new(1), "index")?,
                    name: ok(WimText::new("Edition 1"), "text")?,
                    description: ok(WimText::new("d"), "text")?,
                    total_bytes: Some(1000),
                },
                ManifestEdition {
                    index: ok(EditionIndex::new(2), "index")?,
                    name: ok(WimText::new("Edition 2"), "text")?,
                    description: ok(WimText::new(""), "text")?,
                    total_bytes: None,
                },
            ],
        },
        ready_at: ok(UnixMicros::new(1_793_000_000_000_000), "time")?,
        key_id: key,
    };
    let content_payload = ok(content.to_payload(), "content payload")?;
    let package_manifest = PackageManifestV1 {
        schema: 1,
        package_id: ok(
            PackageId::parse("1c9e8a70-2b3d-4e5f-9a0b-c1d2e3f40516"),
            "id",
        )?,
        revision: 3,
        name: ok(DisplayName::new("Field laptops"), "name")?,
        image: PackageImageV1 {
            content_sha256: Sha256Digest([0xaa; 32]),
            edition_index: ok(EditionIndex::new(1), "index")?,
            edition_name: ok(WimText::new("Edition 1"), "text")?,
            facts: EditionFacts {
                release: Fact::declared(Release::Windows11),
                edition: Fact::declared(Edition::Enterprise),
                architecture: Fact::declared(Architecture::X64),
            },
            declared_by: ok(
                OperatorId::parse("2d0f9b81-3c4e-4f60-8b1c-d2e3f4051627"),
                "id",
            )?,
            declared_audit_seq: 42,
        },
        pe: PackagePeV1 {
            content_sha256: Sha256Digest([0xcc; 32]),
            usable_index: ok(EditionIndex::new(1), "index")?,
            architecture: Fact::declared(Architecture::X64),
            kit_version: Fact::declared(ok(KitVersion::parse("10.1.26100.1"), "kit")?),
        },
        signed_at: ok(UnixMicros::new(1_793_000_000_000_001), "time")?,
        key_id: key,
    };
    let package_payload = ok(package_manifest.to_payload(), "package payload")?;
    // Not a real signature: the parser only checks its size.
    let sig = ok(
        SignatureV1::new(key, SignatureAlg::EcdsaP384Sha384, vec![0x30; 103]),
        "signature",
    )?;
    let envelope = ok(
        SignedEnvelopeV1::new(
            PayloadType::ContentManifestV1,
            content_payload.clone(),
            vec![sig],
        ),
        "envelope",
    )?;
    let envelope_json = ok(envelope.to_json(), "envelope json")?;

    Ok(vec![
        ("wu9-upload-image", json(0, &upload_image)?),
        ("wu9-upload-pe", json(0, &upload_pe)?),
        (
            "wu9-upload-pe-missing-declaration",
            json(0, &upload_pe_missing)?,
        ),
        (
            "wu9-upload-unknown-field",
            with_sel(0, br#"{"kind":"image","extra":1}"#),
        ),
        ("wu9-package", json(1, &package)?),
        ("wu9-package-index-0", json(1, &package_bad)?),
        ("wu9-edition-declaration", json(2, &decl)?),
        ("wu9-clone", json(3, &clone)?),
        ("wu9-pe-declaration", json(4, &pe_decl)?),
        ("wu9-envelope-content", with_sel(5, &envelope_json)),
        ("wu9-content-manifest", with_sel(6, &content_payload)),
        ("wu9-package-manifest", with_sel(7, &package_payload)),
        ("wu9-if-match-r7", with_sel(8, b"\"r7\"")),
        ("wu9-if-match-weak", with_sel(8, b"W/\"r7\"")),
        ("wu9-if-match-leading-zero", with_sel(8, b"\"r007\"")),
        ("wu9-if-match-star", with_sel(8, b"*")),
    ])
}

fn wu9_seeds() -> Result<Vec<(&'static str, Seeds)>, String> {
    let [check, header, lookup, xml] = wim_seeds()?;
    Ok(vec![
        ("wim_check", check),
        ("wim_header", header),
        ("wim_lookup", lookup),
        ("wim_xml", xml),
        ("xpress_chunk", xpress_seeds()?),
        ("api_json", api_seeds()?),
    ])
}
