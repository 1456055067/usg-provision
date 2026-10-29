//! Writes the M3 (plan WU-14) fuzz seeds into `fuzz/corpus/<target>/`.
//!
//! Usage (from `fuzz/`): `cargo run --example gen_seeds_m3 -- corpus`
//!
//! Every seed is built here by our own code: the `usgp-disk` layout, GPT
//! and UEFI load-option encoders, the `usgp-image` test WIM and tree
//! builders, the `usgp-tftp` packet encoders, `usgp-proto` types (their
//! own serializers, or JSON text written here in the wire shape of M3 plan
//! §3.1 and checked against the parser before it is written), and
//! `pe_coff::sample`. None comes from captured traffic, logs, firmware
//! variables, disks, images or files of any other product or deployment
//! (fuzz/README.md, seed origin rule). The seed list is recorded in
//! `fuzz/corpus/*/SOURCE.md`. Names start with `wu14-`, so they never
//! clash with the seeds written by the crate examples.

// COMPLIANCE MAPPING:
// - NIST 800-53: SA-11 (Developer Testing and Evaluation)
// - DECISION: docs/decisions/0002 (fuzz harness), 0006 item 4 (synthetic
//   WIM files only)

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use usgp_crypto::Sha256Digest;
use usgp_disk::uefi::{LoadOption, Node, encode_boot_order};
use usgp_disk::{Bus, DiskFacts, DiskIdentity, GptPlan, Guid, PartitionEntry, WindowsUefiLayout};
use usgp_image::Compression;
use usgp_image::testkit::tree::{abs_link_data, rel_link_data};
use usgp_image::testkit::{NodeSpec, TreeSpec, WimBuilder};
use usgp_proto::agent_config::AgentConfigFile;
use usgp_proto::api::parse_request;
use usgp_proto::content_manifest::chunk_count;
use usgp_proto::device::{
    AgentNonce, CancelV1, ChooseDiskV1, ChoosePackageV1, CodeSubmitV1, ConfirmV1, ConfirmedV1,
    DeviceHelloV1, DevicePackageListV1, EndSessionV1, MacAddress, MacList, SessionOpenedV1,
    SessionStatusV1,
};
use usgp_proto::disk::{Bus as WireBus, DiskDescriptorParts, DiskDescriptorV1, DiskToken};
use usgp_proto::envelope::{PayloadType, SignatureAlg, SignatureV1, SignedEnvelopeV1};
use usgp_proto::job_plan::{
    JobPlanV1, LayoutPolicyV1, PlanDeviceV1, PlanImageV1, PlanPackageV1, PlanStepV1, PlanWipeV1,
    RetryPolicyV1, WipeScope,
};
use usgp_proto::limits::{CHUNK_SIZE, MAX_DEVICE_JSON_BYTES};
use usgp_proto::pe_coff::sample;
use usgp_proto::pe_kit::PeKitV1;
use usgp_proto::progress::{ProgressAckV1, ProgressV1, Step};
use usgp_proto::{
    BootFileName, BootManifest, BootServiceId, ContentId, ContentKind, ContentManifestV1, DiskText,
    DisplayName, EditionIndex, FileName, JobId, ManifestEdition, ManifestEntry, PackageId,
    SessionId, UnixMicros, WimCompression, WimSummaryV1, WimText,
};
use usgp_tftp::{Opcode, encode_request};

type Seeds = Vec<(&'static str, Vec<u8>)>;

fn ok<T, E: std::fmt::Debug>(r: Result<T, E>, what: &str) -> Result<T, String> {
    r.map_err(|e| format!("{what}: {e:?}"))
}

fn with_sel(sel: u8, bytes: &[u8]) -> Vec<u8> {
    let mut v = vec![sel];
    v.extend_from_slice(bytes);
    v
}

fn write_all(dir: &Path, seeds: Seeds) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    for (name, bytes) in seeds {
        let path = dir.join(format!("{name}.bin"));
        std::fs::write(&path, &bytes).map_err(|e| format!("write {}: {e}", path.display()))?;
        println!("{} ({} octets)", path.display(), bytes.len());
    }
    Ok(())
}

/// A deterministic byte source for GUIDs (a 64-bit LCG with Knuth's
/// MMIX constants; not random, seeds only).
fn counter(seed: u64) -> impl FnMut(&mut [u8]) {
    let mut n = seed;
    move |b: &mut [u8]| {
        for x in b {
            n = n
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *x = n.to_be_bytes()[0];
        }
    }
}

// ------------------------------------------------------------------ GPT --

/// `gpt_readback` framing: selector, total LBAs, head, tail.
fn gpt_frame(sel: u8, total: u32, head: &[u8], tail: &[u8]) -> Result<Vec<u8>, String> {
    let h = ok(u16::try_from(head.len()), "head length")?;
    let mut v = vec![sel];
    v.extend_from_slice(&total.to_le_bytes());
    v.extend_from_slice(&h.to_le_bytes());
    v.extend_from_slice(head);
    v.extend_from_slice(tail);
    Ok(v)
}

/// The plan's writes laid out as one head (from LBA 0) and one tail
/// (ending at the last LBA).
fn head_tail(plan: &GptPlan) -> Result<(Vec<u8>, Vec<u8>), String> {
    let block = u64::from(plan.block());
    let total = plan.total_lbas();
    let writes = ok(plan.writes(), "plan writes")?;
    let mid = total / 2 * block;
    let end = total * block;
    let mut head = Vec::new();
    let mut tail_start = end;
    for (off, buf) in &writes {
        if *off < mid {
            let e = ok(usize::try_from(*off), "offset")? + buf.len();
            head.resize(head.len().max(e), 0);
            let s = ok(usize::try_from(*off), "offset")?;
            head[s..e].copy_from_slice(buf);
        } else {
            tail_start = tail_start.min(*off);
        }
    }
    let tlen = ok(usize::try_from(end - tail_start), "tail")?;
    let mut tail = vec![0u8; tlen];
    for (off, buf) in &writes {
        if *off >= mid {
            let s = ok(usize::try_from(off - tail_start), "offset")?;
            tail[s..s + buf.len()].copy_from_slice(buf);
        }
    }
    Ok((head, tail))
}

fn entry(
    type_guid: Guid,
    rng: &mut dyn FnMut(&mut [u8]),
    first: u64,
    last: u64,
    name: &str,
) -> PartitionEntry {
    let mut u = [0u8; 16];
    rng(&mut u);
    let mut n = [0u16; 36];
    for (d, s) in n.iter_mut().zip(name.encode_utf16()) {
        *d = s;
    }
    PartitionEntry {
        type_guid,
        unique_guid: Guid(u),
        first_lba: first,
        last_lba: last,
        attributes: 0,
        name: n,
    }
}

fn gpt_seeds() -> Result<Seeds, String> {
    use usgp_disk::guid::types;
    let mut rng = counter(3);
    let mut disk_guid = [0u8; 16];
    rng(&mut disk_guid);
    // 512-byte sectors, 4096 LBAs (2 MiB): usable 34..=4062.
    let two = ok(
        GptPlan::new(
            512,
            4096,
            Guid(disk_guid),
            vec![
                entry(types::ESP, &mut rng, 34, 2081, "EFI system partition"),
                entry(
                    types::BASIC_DATA,
                    &mut rng,
                    2082,
                    4062,
                    "Basic data partition",
                ),
            ],
        ),
        "plan 512",
    )?;
    let (h2, t2) = head_tail(&two)?;
    let empty = ok(
        GptPlan::new(512, 4096, Guid(disk_guid), vec![]),
        "empty plan",
    )?;
    let (he, te) = head_tail(&empty)?;
    // 4096-byte sectors, 512 LBAs (2 MiB): usable 6..=506.
    let four = ok(
        GptPlan::new(
            4096,
            512,
            Guid(disk_guid),
            vec![entry(types::BASIC_DATA, &mut rng, 6, 506, "data")],
        ),
        "plan 4096",
    )?;
    let (h4, t4) = head_tail(&four)?;
    // A legacy MBR: one record, type 0x07, at LBA 2048.
    let mut legacy = vec![0u8; 512];
    legacy[446 + 4] = 0x07;
    legacy[446 + 8..446 + 12].copy_from_slice(&2048u32.to_le_bytes());
    legacy[446 + 12..446 + 16].copy_from_slice(&2048u32.to_le_bytes());
    legacy[510] = 0x55;
    legacy[511] = 0xAA;
    Ok(vec![
        ("wu14-gpt-512-two-parts", gpt_frame(0, 4096, &h2, &t2)?),
        (
            "wu14-gpt-512-two-parts-limits-128",
            gpt_frame(0x04, 4096, &h2, &t2)?,
        ),
        (
            "wu14-gpt-512-two-parts-limits-4",
            gpt_frame(0x08, 4096, &h2, &t2)?,
        ),
        ("wu14-gpt-512-empty", gpt_frame(0, 4096, &he, &te)?),
        ("wu14-gpt-512-no-backup", gpt_frame(0, 4096, &h2, &[])?),
        ("wu14-gpt-4096-one-part", gpt_frame(1, 512, &h4, &t4)?),
        ("wu14-gpt-1024-sectors", gpt_frame(2, 2048, &h2, &t2)?),
        ("wu14-gpt-legacy-mbr", gpt_frame(0, 4096, &legacy, &[])?),
    ])
}

/// The ESP of a 64 GB Windows layout from our layout planner.
fn windows_layout() -> Result<WindowsUefiLayout, String> {
    let facts = DiskFacts {
        identity: DiskIdentity {
            device_number: 1,
            model: "Seed NVMe".to_owned(),
            serial: Some("SEED-0001".to_owned()),
        },
        bus: Bus::Nvme,
        removable: false,
        read_only: false,
        logical_sector: 512,
        physical_sector: 4096,
        size_bytes: 64_000_000_000,
        hosts_boot_environment: false,
        partitions: Vec::new(),
    };
    ok(
        WindowsUefiLayout::compute(&facts, 600 * 1024 * 1024, &mut counter(9)),
        "layout",
    )
}

fn efi_seeds() -> Result<Seeds, String> {
    let l = windows_layout()?;
    let opt = LoadOption::windows_boot_manager(&l.esp);
    let enc = ok(opt.encode(), "encode")?;
    let mut extra = opt.clone();
    extra.optional_data = b"WINDOWS\0".to_vec();
    if let Some(p) = extra.paths.first_mut() {
        p.insert(
            0,
            Node::Other {
                node_type: 0x01,
                sub_type: 0x01,
                data: vec![0, 0x1c, 0, 0, 0, 0],
            },
        );
    }
    extra.paths.push(vec![
        Node::FilePath("\\EFI\\BOOT\\BOOTX64.EFI".to_owned()),
        Node::EndInstance,
        Node::FilePath("\\EFI\\BOOT\\SPARE.EFI".to_owned()),
        Node::EndEntire,
    ]);
    let enc_extra = ok(extra.encode(), "encode extra")?;
    let mut limits = vec![255u8, 255, 64, 255, 255];
    limits.extend_from_slice(&enc);
    let esp = &l.esp;
    let mut part = Vec::new();
    part.extend_from_slice(&esp.number.to_le_bytes());
    part.extend_from_slice(&esp.first_lba.to_le_bytes());
    part.extend_from_slice(&(esp.last_lba - esp.first_lba).to_le_bytes());
    part.extend_from_slice(&esp.unique_guid.0);
    part.push(3);
    Ok(vec![
        ("wu14-efi-windows-boot-manager", with_sel(0, &enc)),
        ("wu14-efi-optional-data-multi-path", with_sel(0, &enc_extra)),
        ("wu14-efi-limits-prefix", with_sel(0, &limits)),
        (
            "wu14-efi-boot-order",
            with_sel(1, &encode_boot_order(&[3, 1, 0, 2, 1])),
        ),
        ("wu14-efi-boot-order-odd", with_sel(1, &[1, 0, 2])),
        ("wu14-efi-name-boot0001", with_sel(2, b"Boot0001")),
        ("wu14-efi-name-bootorder", with_sel(2, b"BootOrder")),
        ("wu14-efi-name-lower", with_sel(2, b"Boot00a1")),
        ("wu14-efi-name-pk", with_sel(2, b"PK")),
        ("wu14-efi-esp", with_sel(3, &part)),
    ])
}

// ------------------------------------------------------------------ WIM --

fn link_tree() -> TreeSpec {
    TreeSpec::new(vec![NodeSpec::dir(
        "links",
        vec![
            NodeSpec::file("target-file.txt", b"t\n"),
            NodeSpec::dir("target-dir", vec![NodeSpec::file("inner", b"i")]),
            NodeSpec::symlink(
                "abs-file.txt",
                false,
                &abs_link_data("T:\\links\\target-file.txt", false),
            )
            .field_92(0),
            NodeSpec::junction("junction", &abs_link_data("T:\\links\\target-dir", true))
                .field_92(0),
            NodeSpec::junction("copied", &abs_link_data("T:\\outside", true)),
            NodeSpec::symlink("rel.txt", false, &rel_link_data("..\\x.txt")),
        ],
    )])
}

fn deep_tree() -> TreeSpec {
    let mut n = NodeSpec::file("leaf.txt", b"deep");
    for d in ["e", "d", "c", "b", "a"] {
        n = NodeSpec::dir(d, vec![n]);
    }
    TreeSpec::new(vec![n, NodeSpec::file("A.TXT", b"x").short("A.TXT")])
}

fn metadata_seeds() -> Seeds {
    vec![
        ("wu14-links", link_tree().encode().bytes),
        ("wu14-deep", deep_tree().encode().bytes),
        ("wu14-empty-root", TreeSpec::new(vec![]).encode().bytes),
    ]
}

fn apply_seeds() -> Result<Seeds, String> {
    let (links, _) = ok(
        WimBuilder::new(Compression::Xpress)
            .tree_image("links", "d", link_tree())
            .build(),
        "links wim",
    )?;
    let (two, _) = ok(
        WimBuilder::new(Compression::None)
            .tree_image("one", "d", deep_tree())
            .tree_image("two", "d", link_tree())
            .build(),
        "two-image wim",
    )?;
    let mut tampered = vec![0x12u8];
    tampered.extend_from_slice(&300u32.to_le_bytes());
    tampered.extend_from_slice(&links);
    let rebase = |h: u8, t: u8, m: u8, r: u8, b: &[u8]| {
        let mut v = vec![1u8, h, t, m, r];
        v.extend_from_slice(b);
        v
    };
    Ok(vec![
        ("wu14-apply-links-w", with_sel(0x02, &links)),
        ("wu14-apply-links-deep-root", with_sel(0x0A, &links)),
        ("wu14-apply-image-2", with_sel(0x04, &two)),
        ("wu14-apply-image-0", with_sel(0x00, &two)),
        ("wu14-apply-tampered", tampered),
        (
            "wu14-rebase-symlink",
            rebase(0, 0, 0, 1, &abs_link_data("T:\\a\\b.txt", false)),
        ),
        (
            "wu14-rebase-junction-drive-root",
            rebase(0, 1, 0, 0, &abs_link_data("T:\\a\\dir", true)),
        ),
        (
            "wu14-rebase-junction-deep-root",
            rebase(0, 1, 0, 2, &abs_link_data("T:\\a\\dir", true)),
        ),
        (
            "wu14-rebase-without-rp-fix",
            rebase(1, 0, 0, 1, &abs_link_data("T:\\a", false)),
        ),
        (
            "wu14-rebase-copy-relative",
            rebase(1, 0, 1, 1, &rel_link_data("..\\x")),
        ),
        (
            "wu14-rebase-dot-junction",
            rebase(0, 1, 1, 1, &abs_link_data("T:\\a\\..\\b", true)),
        ),
    ])
}

// ----------------------------------------------------------------- TFTP --

/// `tftp_window` framing (see the target).
fn window(len: u32, max_win: u16, a: u8, b: u8, rrq: &[u8], ops: &[u8]) -> Result<Vec<u8>, String> {
    let mut v = len.to_le_bytes()[..3].to_vec();
    v.extend_from_slice(&max_win.to_le_bytes());
    v.push(a);
    v.push(b);
    v.push(ok(u8::try_from(rrq.len()), "RRQ length")?);
    v.extend_from_slice(rrq);
    v.extend_from_slice(ops);
    Ok(v)
}

fn rrq(opts: &[(&[u8], &[u8])]) -> Vec<u8> {
    encode_request(Opcode::Rrq, b"boot/boot.wim", b"octet", opts)
}

fn window_seeds() -> Result<Seeds, String> {
    // a: wrap | max_retries << 2 | handshake_retries << 5.
    let a = |wrap: u8| wrap | (5 << 2) | (2 << 5);
    // b: block-size cap index | (max_duration / 20 s) << 3; 600 s.
    let b = |cap: u8| cap | (30 << 3);
    let w8 = rrq(&[
        (b"blksize", b"512"),
        (b"windowsize", b"8"),
        (b"tsize", b"0"),
    ]);
    let w64 = rrq(&[(b"blksize", b"8"), (b"windowsize", b"64")]);
    let w16 = rrq(&[(b"blksize", b"64"), (b"windowsize", b"16")]);
    let plain = rrq(&[]);
    // Ops: 0 drain, 1 ACK highest, 2 partial ACK, 4 timer at deadline,
    // 6 run, 7 ERROR / stale ACK (see the target).
    let run = |rounds_div_64: u8| 6 | ((rounds_div_64 - 1) << 3);
    Ok(vec![
        (
            "wu14-window-8-complete",
            window(5000, 8, a(0), b(1), &w8, &[run(1)])?,
        ),
        (
            "wu14-window-wrap-zero",
            window(600_000, 64, a(0), b(0), &w64, &[run(32)])?,
        ),
        (
            "wu14-window-wrap-one",
            window(600_000, 64, a(1), b(0), &w64, &[run(32)])?,
        ),
        (
            "wu14-window-wrap-off-refused",
            window(600_000, 64, a(2), b(0), &w64, &[run(1)])?,
        ),
        (
            "wu14-window-partial-acks",
            window(
                3000,
                16,
                a(0),
                b(6),
                &w16,
                &[1, 0, 2 | (3 << 3), 0, 4, 7 | (17 << 3), 1, 0, 1, 0, 1],
            )?,
        ),
        (
            "wu14-window-lockstep",
            window(2000, 1, a(0), b(1), &plain, &[run(1)])?,
        ),
        (
            "wu14-window-retry-cap",
            window(3000, 8, a(0), b(1), &w8, &[1, 4, 4, 4, 4, 4, 4, 4])?,
        ),
        (
            "wu14-window-client-error",
            window(3000, 8, a(0), b(1), &w8, &[1, 0, 7 | (8 << 3)])?,
        ),
        (
            "wu14-window-exact-multiple",
            window(4096, 8, a(0), b(1), &w8, &[run(1)])?,
        ),
        (
            "wu14-window-raw-ack",
            window(1000, 4, a(0), b(1), &w8, &[3, 0, 0, 3, 0, 1, 3, 0xff, 0xff])?,
        ),
    ])
}

fn name_seeds() -> Seeds {
    let long = "a".repeat(128);
    vec![
        ("wu14-name-backslash", with_sel(0, b"\\Boot\\BCD")),
        ("wu14-name-slash", with_sel(0, b"/Boot/BCD")),
        ("wu14-name-plain", with_sel(0, b"bootmgfw.efi")),
        ("wu14-name-mixed", with_sel(0, b"\\sources/boot.wim")),
        ("wu14-name-dotdot", with_sel(0, b"..\\x")),
        ("wu14-name-double-slash", with_sel(0, b"a//b")),
        ("wu14-name-dot", with_sel(0, b"a/./b")),
        ("wu14-name-too-long", with_sel(0, long.as_bytes())),
        ("wu14-name-percent", with_sel(0, b"%2e%2e/x")),
        (
            "wu14-names-collision",
            with_sel(1, b"Boot/BCD\0bootmgfw.efi\0boot/bcd"),
        ),
    ]
}

// ---------------------------------------------------------------- proto --

const SESSION: &str = "5a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
const JOB: &str = "6b2c3d4e-5f60-4b7c-9d8e-0f1a2b3c4d5e";
const BOOT_SERVICE: &str = "7c3d4e5f-6071-4c8d-ae9f-1a2b3c4d5e6f";
const PACKAGE: &str = "1c9e8a70-2b3d-4e5f-9a0b-c1d2e3f40516";
const CONTENT: &str = "0b7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e6f";

fn disk() -> Result<DiskDescriptorV1, String> {
    ok(
        DiskDescriptorV1::new(DiskDescriptorParts {
            disk_token: DiskToken::from_random_bytes([0x5a; 16]),
            bus: WireBus::Nvme,
            model: DiskText::sanitized("Example NVMe 1TB"),
            serial: DiskText::sanitized("SN-0001"),
            size_bytes: 1_000_204_886_016,
            logical_sector: 512,
            physical_sector: 4096,
            removable: false,
            partitions: Vec::new(),
        }),
        "disk",
    )
}

/// Parses `json` as `T` with the device listener's cap; `want_ok` says
/// whether the seed is meant to be accepted.
fn device<T: serde::de::DeserializeOwned>(
    sel: u8,
    json: &str,
    want_ok: bool,
) -> Result<Vec<u8>, String> {
    let r = parse_request::<T>(json.as_bytes(), MAX_DEVICE_JSON_BYTES);
    if r.is_ok() != want_ok {
        return Err(format!("seed {json} parses: {}", r.is_ok()));
    }
    Ok(with_sel(sel, json.as_bytes()))
}

fn key(n: u8) -> Sha256Digest {
    Sha256Digest([n; 32])
}

/// Not real signatures: the targets use test-double verifiers.
fn envelope(ty: PayloadType, payload: Vec<u8>, k: u8) -> Result<SignedEnvelopeV1, String> {
    let s = ok(
        SignatureV1::new(key(k), SignatureAlg::EcdsaP384Sha384, vec![0x30; 103]),
        "signature",
    )?;
    ok(SignedEnvelopeV1::new(ty, payload, vec![s]), "envelope")
}

fn content_manifest() -> Result<ContentManifestV1, String> {
    let size = 3 * CHUNK_SIZE + 17;
    let n = ok(usize::try_from(chunk_count(size)), "chunks")?;
    Ok(ContentManifestV1 {
        schema: 1,
        kind: ContentKind::Image,
        content_id: ok(ContentId::parse(CONTENT), "content id")?,
        display_name: ok(DisplayName::new("Win 11 Ent"), "name")?,
        file_name: ok(FileName::new("install.wim"), "file")?,
        size,
        sha256: Sha256Digest([0xaa; 32]),
        chunk_size: CHUNK_SIZE,
        chunk_sha256: (0..n)
            .map(|i| Sha256Digest([u8::try_from(i).unwrap_or(0); 32]))
            .collect(),
        wim: WimSummaryV1 {
            compression: WimCompression::Xpress,
            image_count: 2,
            boot_index: 0,
            editions: vec![
                ManifestEdition {
                    index: ok(EditionIndex::new(1), "index")?,
                    name: ok(WimText::new("Edition 1"), "text")?,
                    description: ok(WimText::new("d"), "text")?,
                    total_bytes: Some(20_000_000_001),
                },
                ManifestEdition {
                    index: ok(EditionIndex::new(2), "index")?,
                    name: ok(WimText::new("Edition 2"), "text")?,
                    description: ok(WimText::new("d"), "text")?,
                    total_bytes: Some(20_000_000_002),
                },
            ],
        },
        ready_at: ok(UnixMicros::new(1_793_000_000_000_000), "time")?,
        key_id: key(12),
    })
}

fn plan(cm_payload: &[u8]) -> Result<JobPlanV1, String> {
    let mac = |n: u8| ok(MacAddress::new([0x02, 0, 0, 0, 0, n]), "mac");
    Ok(JobPlanV1 {
        schema: 1,
        job_id: ok(JobId::parse(JOB), "job")?,
        session_id: ok(SessionId::parse(SESSION), "session")?,
        boot_service_id: ok(BootServiceId::parse(BOOT_SERVICE), "service")?,
        issued_at_us: ok(UnixMicros::new(1_793_000_000_000_123), "time")?,
        key_id: key(11),
        agent_nonce: AgentNonce::from_random_bytes([0x42; 32]),
        device: PlanDeviceV1 {
            macs: ok(MacList::new(vec![mac(1)?, mac(2)?]), "macs")?,
        },
        package: PlanPackageV1 {
            id: ok(PackageId::parse(PACKAGE), "package")?,
            revision: 3,
            manifest_sha256: Sha256Digest([0xcc; 32]),
        },
        image: PlanImageV1 {
            content_sha256: Sha256Digest([0xaa; 32]),
            size: 3 * CHUNK_SIZE + 17,
            content_manifest_sha256: usgp_crypto::sha256(cm_payload),
            edition_index: ok(EditionIndex::new(2), "index")?,
            edition_name: ok(WimText::new("Edition 2"), "text")?,
            total_bytes: 20_000_000_002,
        },
        disk: usgp_proto::PlanDiskV1::from(&disk()?),
        layout_policy: LayoutPolicyV1::STANDARD,
        wipe: PlanWipeV1 {
            audit_seq: 4242,
            record_hash: Sha256Digest([0xdd; 32]),
            scope: WipeScope::TablesAndVolumeHeads1Mib,
        },
        steps: Step::ALL
            .iter()
            .map(|s| PlanStepV1 {
                step: *s,
                kind: s.kind(),
                timeout_s: 21_600,
            })
            .collect(),
        retry: RetryPolicyV1 {
            attempts: 5,
            base_ms: 2000,
            max_ms: 60_000,
        },
        stall_timeout_s: 1800,
        report_interval_s: 30,
    })
}

fn confirmed(p: &JobPlanV1, cm: &[u8]) -> Result<Vec<u8>, String> {
    let c = ConfirmedV1 {
        job_id: p.job_id,
        plan: envelope(
            PayloadType::JobPlanV1,
            ok(p.to_payload(), "plan payload")?,
            11,
        )?,
        content_manifest: envelope(PayloadType::ContentManifestV1, cm.to_vec(), 12)?,
    };
    ok(serde_json::to_vec(&c), "confirmed json")
}

fn job_plan_seeds() -> Result<Seeds, String> {
    let cm = ok(content_manifest()?.to_payload(), "content payload")?;
    let p = plan(&cm)?;
    let payload = ok(p.to_payload(), "plan payload")?;
    let good = confirmed(&p, &cm)?;
    let mut other_edition = p.clone();
    other_edition.image.edition_name = ok(WimText::new("Edition 1"), "text")?;
    let mismatch = confirmed(&other_edition, &cm)?;
    let mut bad_steps = serde_json::to_value(&p).map_err(|e| e.to_string())?;
    if let Some(steps) = bad_steps.get_mut("steps").and_then(|s| s.as_array_mut()) {
        steps.reverse();
    }
    let bad_steps = ok(serde_json::to_vec(&bad_steps), "json")?;
    let mode = |m: u8, body: &[u8]| {
        let mut v = vec![1u8, m];
        v.extend_from_slice(body);
        v
    };
    Ok(vec![
        ("wu14-plan-payload", with_sel(0, &payload)),
        ("wu14-plan-payload-steps-reversed", with_sel(0, &bad_steps)),
        ("wu14-confirmed-all-accept-own-expectation", mode(7, &good)),
        (
            "wu14-confirmed-all-accept-fixed-expectation",
            mode(3, &good),
        ),
        ("wu14-confirmed-plan-refused", mode(6, &good)),
        ("wu14-confirmed-content-refused", mode(5, &good)),
        ("wu14-confirmed-edition-mismatch", mode(7, &mismatch)),
    ])
}

fn device_seeds() -> Result<Seeds, String> {
    let hello = r#"{"schema":1,"agent_version":"0.3.0","firmware":"uefi","arch":"x64","secure_boot":"on","memory_bytes":8589934592,"macs":["02:00:00:00:00:01","02:00:00:00:00:02"]}"#;
    let disk_json = ok(serde_json::to_string(&disk()?), "disk json")?;
    let choose_disk = format!(r#"{{"disk":{disk_json}}}"#);
    let nonce = AgentNonce::from_random_bytes([0x42; 32]);
    let confirm = format!(
        r#"{{"package_id":"{PACKAGE}","revision":3,"disk_token":"{}","confirm":"wipe-disk","agent_nonce":"{nonce}"}}"#,
        DiskToken::from_random_bytes([0x5a; 16])
    );
    let package = format!(
        r#"{{"package_id":"{PACKAGE}","revision":3,"name":"Field laptops","description":"Win 11","os":{{"release":"windows-11","edition":"enterprise","architecture":"x64","source":"declared"}},"image_bytes":5000000000,"required_disk_bytes":64000000000}}"#
    );
    let list = format!(r#"{{"packages":[{package}]}}"#);
    let opened = format!(
        r#"{{"session_id":"{SESSION}","token":"{}","display_code":"AB1-X9Z","state":"awaiting_authorisation","poll_ms":2000,"expires_at":1793000003600000}}"#,
        "M".repeat(42) + "A"
    );
    let cm = ok(content_manifest()?.to_payload(), "content payload")?;
    let good = confirmed(&plan(&cm)?, &cm)?;
    Ok(vec![
        ("wu14-hello", device::<DeviceHelloV1>(0, hello, true)?),
        (
            "wu14-hello-unknown-field",
            device::<DeviceHelloV1>(
                0,
                &hello.replace("{\"schema\":1,", "{\"schema\":1,\"hostname\":\"x\","),
                false,
            )?,
        ),
        (
            "wu14-code",
            device::<CodeSubmitV1>(1, r#"{"code":"abcde-fghjk"}"#, true)?,
        ),
        (
            "wu14-code-bad",
            device::<CodeSubmitV1>(1, r#"{"code":"SECRETCODEX"}"#, false)?,
        ),
        (
            "wu14-choose-package",
            device::<ChoosePackageV1>(
                2,
                &format!(r#"{{"package_id":"{PACKAGE}","revision":3}}"#),
                true,
            )?,
        ),
        (
            "wu14-choose-disk",
            device::<ChooseDiskV1>(3, &choose_disk, true)?,
        ),
        ("wu14-confirm", device::<ConfirmV1>(4, &confirm, true)?),
        ("wu14-cancel", device::<CancelV1>(5, "{}", true)?),
        (
            "wu14-end-no-disk",
            device::<EndSessionV1>(
                6,
                r#"{"reason":"no_disk","refused_disks":[{"bus":"usb","size_bytes":32000000000,"reason":"usb_disk"}]}"#,
                true,
            )?,
        ),
        (
            "wu14-progress",
            device::<ProgressV1>(
                7,
                r#"{"seq":2,"step":1,"event":"progress","bytes_done":10,"bytes_total":100,"item":{"role":"image","name":"install.wim"}}"#,
                true,
            )?,
        ),
        (
            "wu14-progress-failed",
            device::<ProgressV1>(
                7,
                r#"{"seq":9,"step":1,"event":"failed","failure":{"step":1,"category":"integrity","code":"chunk_digest_mismatch","files":[{"role":"image","name":"install.wim"}],"count":1,"attempts":1}}"#,
                true,
            )?,
        ),
        (
            "wu14-session-opened",
            device::<SessionOpenedV1>(8, &opened, true)?,
        ),
        (
            "wu14-session-status",
            device::<SessionStatusV1>(
                9,
                r#"{"state":"authorised","display_code":"AB1-X9Z","code_attempts_left":5,"expires_at":1793000003600000,"boot_service_name":"Bench"}"#,
                true,
            )?,
        ),
        (
            "wu14-package-list",
            device::<DevicePackageListV1>(10, &list, true)?,
        ),
        (
            "wu14-progress-ack",
            device::<ProgressAckV1>(11, r#"{"ack_seq":2,"job_state":"running"}"#, true)?,
        ),
        ("wu14-confirmed", with_sel(12, &good)),
        ("wu14-text-mac", with_sel(13, b"\x0002:00:00:00:0A:01")),
        (
            "wu14-text-token",
            with_sel(13, format!("\x01{}A", "M".repeat(42)).as_bytes()),
        ),
        (
            "wu14-text-authorization",
            with_sel(13, format!("\x02bearer {}A", "M".repeat(42)).as_bytes()),
        ),
        ("wu14-text-code", with_sel(13, b"\x03abcde fghjo")),
        ("wu14-text-display-code", with_sel(13, b"\x04ab1-x9z")),
        (
            "wu14-text-nonce",
            with_sel(13, format!("\x05{nonce}").as_bytes()),
        ),
        (
            "wu14-text-disk-token",
            with_sel(13, b"\x065a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"),
        ),
        (
            "wu14-text-disk-guid",
            with_sel(13, b"\x07C0FFEE00-1234-4abc-8def-0123456789AB"),
        ),
    ])
}

fn manifest_seeds() -> Result<Seeds, String> {
    let n = |s: &str| ok(BootFileName::try_from(s), s);
    let d1 = Sha256Digest([0xba; 32]);
    let d2 = Sha256Digest([0xe3; 32]);
    let file = |name: &str, d: Sha256Digest| -> Result<ManifestEntry, String> {
        Ok(ManifestEntry {
            name: n(name)?,
            size: 5632,
            sha256: d,
        })
    };
    let files = vec![
        file("bootmgfw.efi", d1)?,
        file("Boot/BCD", d1)?,
        file("Boot/boot.sdi", d1)?,
        file("Boot/boot.wim", d2)?,
        file("Boot/Fonts/wgl4_boot.ttf", d1)?,
    ];
    let kit = PeKitV1 {
        boot_program: n("bootmgfw.efi")?,
        bcd: n("Boot/BCD")?,
        sdi: n("Boot/boot.sdi")?,
        wim: n("Boot/boot.wim")?,
        fonts: vec![n("Boot/Fonts/wgl4_boot.ttf")?],
        pe_content_sha256: d2,
    };
    let plain = ok(
        BootManifest::new(vec![file("usgp-test-payload.efi", d1)?]),
        "plain",
    )?;
    let with_kit = ok(
        ok(BootManifest::new(files.clone()), "files")?.with_pe_kit(kit.clone()),
        "kit",
    )?;
    let mut wrong_digest = kit.clone();
    wrong_digest.pe_content_sha256 = d1;
    let wrong = ok(
        ok(BootManifest::new(files.clone()), "files")?.with_pe_kit(wrong_digest),
        "kit",
    )?;
    let mut unpublished = kit;
    unpublished.fonts = vec![n("Boot/Fonts/missing.ttf")?];
    let missing = ok(
        ok(BootManifest::new(files), "files")?.with_pe_kit(unpublished),
        "kit",
    )?;
    Ok(vec![
        ("wu14-manifest-plain", plain.to_toml().into_bytes()),
        ("wu14-manifest-pe-kit", with_kit.to_toml().into_bytes()),
        (
            "wu14-manifest-pe-kit-digest-mismatch",
            wrong.to_toml().into_bytes(),
        ),
        (
            "wu14-manifest-pe-kit-unpublished-font",
            missing.to_toml().into_bytes(),
        ),
    ])
}

fn pe_seeds() -> Seeds {
    use usgp_proto::pe_coff::{MACHINE_X64, MAGIC_PE32_PLUS};
    let good = sample::uefi_x64();
    let mut far = good.clone();
    far[0x3C..0x40].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
    vec![
        ("wu14-pe-uefi-x64", good.clone()),
        ("wu14-pe-x86", sample::header(0x014C, MAGIC_PE32_PLUS, 10)),
        ("wu14-pe-arm64", sample::header(0xAA64, MAGIC_PE32_PLUS, 10)),
        ("wu14-pe-pe32", sample::header(MACHINE_X64, 0x10B, 10)),
        (
            "wu14-pe-subsystem-11",
            sample::header(MACHINE_X64, MAGIC_PE32_PLUS, 11),
        ),
        ("wu14-pe-truncated", good[..0x90].to_vec()),
        ("wu14-pe-pointer-past-end", far),
    ]
}

fn agent_config_seeds() -> Result<Seeds, String> {
    let full = AgentConfigFile {
        server_url: "https://provision.example.gov:8444".to_owned(),
        server_name: Some("provision.example.gov".to_owned()),
        trust_anchors: "trust-anchors.pem".into(),
        plan_key_pub: "plan.pub".into(),
        content_key_pub: "content.pub".into(),
        network_wait_s: Some(120),
        connect_timeout_s: Some(15),
    };
    let minimal = AgentConfigFile {
        server_url: "https://10.0.0.5".to_owned(),
        server_name: None,
        trust_anchors: "a.pem".into(),
        plan_key_pub: "p.pub".into(),
        content_key_pub: "c.pub".into(),
        network_wait_s: None,
        connect_timeout_s: None,
    };
    let v6 = AgentConfigFile {
        server_url: "https://[fd00::5]:8444/".to_owned(),
        ..minimal.clone()
    };
    let t = |f: &AgentConfigFile| ok(f.to_toml(), "toml").map(|s| with_sel(0, s.as_bytes()));
    Ok(vec![
        ("wu14-agent-full", t(&full)?),
        ("wu14-agent-minimal", t(&minimal)?),
        ("wu14-agent-ipv6", t(&v6)?),
        (
            "wu14-url-name-port",
            with_sel(1, b"https://provision.example.gov:8444"),
        ),
        ("wu14-url-upper-scheme", with_sel(1, b"HTTPS://10.0.0.5/")),
        (
            "wu14-url-userinfo",
            with_sel(1, b"https://user@host.example"),
        ),
        ("wu14-url-path", with_sel(1, b"https://host.example/v1")),
    ])
}

fn feed_url_seeds() -> Seeds {
    vec![
        (
            "wu14-feed-url-name-port",
            b"https://server.example.gov:8443".to_vec(),
        ),
        ("wu14-feed-url-ipv4", b"https://10.0.0.1".to_vec()),
        ("wu14-feed-url-ipv6", b"https://[fd00::1]:443/".to_vec()),
        ("wu14-feed-url-digits", b"https://123.45".to_vec()),
        ("wu14-feed-url-http", b"http://server.example.gov".to_vec()),
        (
            "wu14-feed-url-port-0",
            b"https://server.example.gov:0".to_vec(),
        ),
    ]
}

fn boot_policy_seeds() -> Seeds {
    vec![
        ("wu14-feed-in-order", vec![0, 2, 3, 5]),
        ("wu14-feed-rollback", vec![2, 0]),
        ("wu14-feed-reuse-unchanged", vec![0, 1, 0]),
        ("wu14-feed-refusals", vec![6, 7, 8, 9, 10, 11, 0]),
        ("wu14-feed-cache-then-server", vec![0x40, 2, 0x42]),
        ("wu14-feed-same-generation-other-list", vec![2, 4]),
        ("wu14-feed-flip", vec![0, 0xC2, 0x00, 0x40, 2]),
        ("wu14-feed-raw", vec![0xE0, 2, b'{', b'}', 0]),
    ]
}

fn main() -> ExitCode {
    let Some(root) = std::env::args_os().nth(1).map(PathBuf::from) else {
        eprintln!("usage: gen_seeds_m3 <corpus-root>");
        return ExitCode::from(2);
    };
    let all = || -> Result<Vec<(&'static str, Seeds)>, String> {
        Ok(vec![
            ("gpt_readback", gpt_seeds()?),
            ("efi_load_option", efi_seeds()?),
            ("wim_metadata", metadata_seeds()),
            ("wim_apply_plan", apply_seeds()?),
            ("tftp_window", window_seeds()?),
            ("tftp_name", name_seeds()),
            ("device_session_msgs", device_seeds()?),
            ("job_plan", job_plan_seeds()?),
            ("boot_manifest", manifest_seeds()?),
            ("pe_coff", pe_seeds()),
            ("agent_config", agent_config_seeds()?),
            ("relay_feed_url", feed_url_seeds()),
            ("relay_boot_policy", boot_policy_seeds()),
        ])
    };
    let result = all().and_then(|targets| {
        for (t, seeds) in targets {
            write_all(&root.join(t), seeds)?;
        }
        Ok(())
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("gen_seeds_m3: {e}");
            ExitCode::FAILURE
        }
    }
}
