//! Writes the M4 (plan WU-12) fuzz seeds into `fuzz/corpus/<target>/`.
//!
//! Usage (from `fuzz/`): `cargo run --example gen_seeds_m4 -- corpus`
//!
//! Every seed is built here by our own code: answer-file templates, INF
//! text and driver listings written in this file from the open
//! descriptions the plan cites (plan sections 1.5 and 1.6,
//! `specs/standards/unattend.md`, `zip-cab.md`, `offline-drivers.md`
//! §7.3); ZIP and cabinet files from the `usgp-wincfg` test writers;
//! DEFLATE streams from those writers and from `miniz_oxide`'s encoder;
//! and `usgp-proto` bodies from its own types and serializers, or JSON
//! text written here and checked against the parser before it is written.
//! None comes from captured traffic, logs, images, driver packages, tool
//! output or files of any other product or deployment (fuzz/README.md,
//! seed origin rule). The seed list is recorded in
//! `fuzz/corpus/*/SOURCE.md`. Names start with `wu12-`.

// COMPLIANCE MAPPING:
// - NIST 800-53: SA-11 (Developer Testing and Evaluation)
// - DECISION: docs/decisions/0002 (fuzz harness)

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use usgp_crypto::Sha256Digest;
use usgp_proto::api::parse_request;
use usgp_proto::content_manifest::chunk_count;
use usgp_proto::envelope::{PayloadType, SignatureAlg, SignatureV1, SignedEnvelopeV1};
use usgp_proto::limits::{CHUNK_SIZE, MAX_DEVICE_JSON_BYTES};
use usgp_proto::names::RelPath as WireRelPath;
use usgp_proto::resume::{ResumeNonce, ResumeSignature};
use usgp_proto::status::{ArchiveFormat, ContentKindV2};
use usgp_proto::{
    AgentPackageManifestV1, ArchiveSummaryV1, B64Bytes, ContentId, ContentManifestV2, DisplayName,
    EscrowAccount, EscrowConfirmV1, EscrowSubmitV1, FailureV2, FileName, JobId, PostSetupConfigV1,
    ProgressV2, ResumeChallengeV1, ResumeRequestV1, ResumedV1, UnixMicros,
};
use usgp_wincfg::archive::inflate::inflate_slice;
use usgp_wincfg::archive::testkit::{
    CabBuilder, Op, ZipBuilder, ZipEntrySpec, deflate_fixed, deflate_stored,
};
use usgp_wincfg::dism::parse_driver_table;
use usgp_wincfg::unattend::{Limits, Template};
use usgp_wincfg::{ArchiveLimits, ArchiveMode, validate_archive_mode};

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

// ---------------------------------------------------------------- unattend

const NS: &str = "urn:schemas-microsoft-com:unattend";

fn doc(body: &str) -> Vec<u8> {
    format!(r#"<?xml version="1.0" encoding="utf-8"?><unattend xmlns="{NS}">{body}</unattend>"#)
        .into_bytes()
}

fn unattend_seeds() -> Result<Seeds, String> {
    let good = doc(concat!(
        r#"<settings pass="specialize"><component name="Shell-Setup">"#,
        r#"<ComputerName>{{device.computer_name}}</ComputerName>"#,
        r#"<TimeZone>{{time_zone}}</TimeZone></component>"#,
        r#"<component name="Join"><Identification><JoinDomain>{{domain}}</JoinDomain>"#,
        r#"<MachineObjectOU>{{machine_ou}}</MachineObjectOU></Identification></component>"#,
        r#"</settings>"#,
    ));
    let plain = doc(
        r#"<settings pass="oobeSystem"><component name="c" attr="a &amp; b"><!-- note --><X>text</X></component></settings>"#,
    );
    let attr_ref =
        doc(r#"<settings pass="specialize"><component name="{{device.site}}"/></settings>"#);
    let secret = doc(
        r#"<settings pass="oobeSystem"><component name="c"><AdministratorPassword><Value>x</Value></AdministratorPassword></component></settings>"#,
    );
    let command = doc(
        r#"<settings pass="specialize"><component name="c"><RunSynchronous><Path>{{device.x}}</Path></RunSynchronous></component></settings>"#,
    );
    let lim = Limits::default();
    for (what, b) in [
        ("good", &good),
        ("plain", &plain),
        ("attr", &attr_ref),
        ("secret", &secret),
        ("command", &command),
    ] {
        ok(Template::parse(b, &lim), what)?;
    }
    let doctype = format!(
        r#"<?xml version="1.0"?><!DOCTYPE unattend [<!ENTITY a "b">]><unattend xmlns="{NS}">&a;</unattend>"#
    )
    .into_bytes();
    let bad_ref = doc("<settings><X>{{bad name}}</X></settings>");
    let wrong_root = br#"<?xml version="1.0"?><other xmlns="urn:example"/>"#.to_vec();
    for (what, b) in [
        ("doctype", &doctype),
        ("bad_ref", &bad_ref),
        ("wrong_root", &wrong_root),
    ] {
        if Template::parse(b, &lim).is_ok() {
            return Err(format!("unattend {what}: expected refusal"));
        }
    }
    Ok(vec![
        ("wu12-good", good),
        ("wu12-plain", plain),
        ("wu12-attr-ref", attr_ref),
        ("wu12-secret-setting", secret),
        ("wu12-ref-in-command", command),
        ("wu12-doctype", doctype),
        ("wu12-bad-ref", bad_ref),
        ("wu12-wrong-root", wrong_root),
    ])
}

// ---------------------------------------------------------------- archives

const INF_NET: &str = "; Synthetic INF written for fuzz seeds.\r\n[Version]\r\nSignature = \"$Windows NT$\"\r\nClass = Net\r\nProvider = %Mfg%\r\nCatalogFile = net.cat\r\nDriverVer = 01/02/2026,1.2.3.4\r\n\r\n[Strings]\r\nMfg = \"Example\"\r\n";

fn zip_driver_stored() -> Vec<u8> {
    ZipBuilder::default()
        .entry(ZipEntrySpec::stored("net/", b""))
        .entry(ZipEntrySpec::stored("net/net.inf", INF_NET.as_bytes()))
        .entry(ZipEntrySpec::stored("net/net.cat", b"catalog"))
        .entry(ZipEntrySpec::stored(
            "net/net.sys",
            &[0x4D, 0x5A, 0, 0, 1, 2, 3, 4],
        ))
        .build()
}

fn archive_ok(b: &[u8], mode: ArchiveMode, what: &str) -> Result<(), String> {
    ok(
        validate_archive_mode(&b, b.len() as u64, &ArchiveLimits::default(), mode),
        what,
    )
    .map(|_| ())
}

fn zip_seeds() -> Result<Seeds, String> {
    let stored = zip_driver_stored();
    let text: Vec<u8> = b"abcabcabcabc driver text ".repeat(8);
    let mut ops: Vec<Op> = b"abc".iter().map(|&b| Op::Lit(b)).collect();
    ops.push(Op::Match(30, 3));
    let fixed_content = {
        let mut v = b"abc".to_vec();
        for i in 0..30 {
            v.push(*b"abc".get(i % 3).unwrap_or(&b'a'));
        }
        v
    };
    let deflated = ZipBuilder::default()
        .entry(ZipEntrySpec::deflated(
            "drv/a.inf",
            INF_NET.replace("net.cat", "a.cat").as_bytes(),
            miniz_oxide::deflate::compress_to_vec(
                INF_NET.replace("net.cat", "a.cat").as_bytes(),
                6,
            ),
        ))
        .entry(ZipEntrySpec::stored("drv/a.cat", b"c"))
        .entry(ZipEntrySpec::deflated(
            "drv/fixed.bin",
            &fixed_content,
            deflate_fixed(&ops),
        ))
        .entry(ZipEntrySpec::deflated(
            "drv/stored.bin",
            &text,
            deflate_stored(&text),
        ))
        .build();
    let mut z64 = ZipBuilder::default();
    let mut e = ZipEntrySpec::stored("p/q.inf", INF_NET.replace("net.cat", "q.cat").as_bytes());
    e.zip64 = true;
    z64 = z64.entry(e);
    let mut c = ZipEntrySpec::stored("p/q.cat", b"c");
    c.descriptor = true;
    z64 = z64.entry(c);
    z64.zip64_end = true;
    let z64 = z64.build();
    let agent = ZipBuilder::default()
        .entry(ZipEntrySpec::stored(
            "agent.json",
            br#"{"installer":"setup.msi"}"#,
        ))
        .entry(ZipEntrySpec::stored("setup.msi", b"not a real installer"))
        .build();
    archive_ok(&stored, ArchiveMode::DriverPackages, "zip stored")?;
    archive_ok(&deflated, ArchiveMode::DriverPackages, "zip deflated")?;
    archive_ok(&z64, ArchiveMode::DriverPackages, "zip64")?;
    archive_ok(&agent, ArchiveMode::Plain, "zip agent")?;
    let traversal = ZipBuilder::default()
        .entry(ZipEntrySpec::stored("../evil.inf", b"x"))
        .build();
    let mut bad_crc = ZipEntrySpec::stored("a/b.txt", b"hello");
    bad_crc.crc ^= 1;
    let bad_crc = ZipBuilder::default().entry(bad_crc).build();
    Ok(vec![
        ("wu12-driver-stored", stored),
        ("wu12-driver-deflate", deflated),
        ("wu12-zip64-descriptor", z64),
        ("wu12-agent-package", agent),
        ("wu12-traversal", traversal),
        ("wu12-bad-crc", bad_crc),
    ])
}

fn cab_seeds() -> Result<Seeds, String> {
    let files = |b: CabBuilder| {
        b.file("net\\net.inf", INF_NET.as_bytes())
            .file("net\\net.cat", b"catalog")
            .file("net\\net.sys", &[0x4D, 0x5A, 0, 0, 9, 8, 7])
    };
    let plain = files(CabBuilder::default()).build();
    let mszip = files(CabBuilder {
        compression: 1,
        checksums: true,
        ..CabBuilder::default()
    })
    .build();
    let reserve = files(CabBuilder {
        reserve: (4, 2, 1),
        checksums: true,
        ..CabBuilder::default()
    })
    .build();
    let big: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
    let multi_block = CabBuilder::default()
        .file("d\\d.inf", INF_NET.replace("net.cat", "d.cat").as_bytes())
        .file("d\\d.cat", b"c")
        .file("d\\blob.bin", &big)
        .build();
    archive_ok(&plain, ArchiveMode::DriverPackages, "cab plain")?;
    archive_ok(&mszip, ArchiveMode::DriverPackages, "cab mszip")?;
    archive_ok(&reserve, ArchiveMode::DriverPackages, "cab reserve")?;
    archive_ok(&multi_block, ArchiveMode::DriverPackages, "cab multi-block")?;
    let lzx = files(CabBuilder {
        compression: 3,
        ..CabBuilder::default()
    })
    .build();
    Ok(vec![
        ("wu12-cab-none", plain),
        ("wu12-cab-mszip", mszip),
        ("wu12-cab-reserve", reserve),
        ("wu12-cab-two-blocks", multi_block),
        ("wu12-cab-type-3", lzx),
    ])
}

fn inflate_seeds() -> Result<Seeds, String> {
    let text = b"Driver package text, repeated. Driver package text, repeated. 0123456789";
    let mut ops: Vec<Op> = b"xyz".iter().map(|&b| Op::Lit(b)).collect();
    ops.push(Op::Match(258, 3));
    ops.push(Op::Lit(b'!'));
    let dynamic = miniz_oxide::deflate::compress_to_vec(&text.repeat(20), 9);
    for (what, s) in [
        ("stored", deflate_stored(text)),
        ("fixed", deflate_fixed(&ops)),
        ("dynamic", dynamic.clone()),
    ] {
        ok(inflate_slice(&s, 1 << 20), what)?;
    }
    Ok(vec![
        ("wu12-stored", with_sel(0, &deflate_stored(text))),
        ("wu12-fixed-match", with_sel(0, &deflate_fixed(&ops))),
        ("wu12-dynamic", with_sel(0, &dynamic)),
        // Block type 3 (reserved), final bit set.
        ("wu12-reserved-type", with_sel(0, &[0x07, 0x00])),
        ("wu12-roundtrip-level6", with_sel(1, &with_sel(6, text))),
        ("wu12-roundtrip-level0", with_sel(1, &with_sel(0, b"short"))),
    ])
}

fn inf_seeds() -> Seeds {
    let utf16 = {
        let mut v = vec![0xFF, 0xFE];
        v.extend(
            INF_NET
                .replace("net.cat", "x.cat")
                .encode_utf16()
                .flat_map(u16::to_le_bytes),
        );
        v
    };
    vec![
        ("wu12-windows-nt", INF_NET.replace("net.cat", "x.cat").into_bytes()),
        ("wu12-utf16", utf16),
        (
            "wu12-chicago-decorated",
            b"[version]\nsignature=$CHICAGO$\nCatalogFile.NTamd64 = y.cat ; comment\nCatalogFile=x.cat\n"
                .to_vec(),
        ),
        (
            "wu12-missing-catalog",
            b"[Version]\nSignature=\"$Windows NT$\"\nCatalogFile=z.cat\n".to_vec(),
        ),
        (
            "wu12-no-version",
            b"[Strings]\nSignature=\"$Windows NT$\"\nCatalogFile=x.cat\n".to_vec(),
        ),
        (
            "wu12-quoted-semicolon",
            b"[Version]\nSignature=\"$Windows NT$;x\"\nCatalogFile=x.cat\n".to_vec(),
        ),
    ]
}

// --------------------------------------------------------------- dism table

const DRIVER_BLOCK: &str = "Published Name : oem1.inf\nOriginal File Name : net.inf\nInbox : No\nClass Name : Net\nProvider Name : Example Corp\nDate : 1/2/2026\nVersion : 1.2.3.4\n";

fn dism_seeds() -> Result<Seeds, String> {
    let two = format!(
        "Tool banner 1.0\n\nDriver packages listing:\n\n{DRIVER_BLOCK}\n{}\nThe operation completed.\n",
        DRIVER_BLOCK
            .replace("oem1", "oem2")
            .replace("Inbox : No", "Inbox : Yes")
    );
    let rows = ok(parse_driver_table(&two), "dism two")?;
    if rows.len() != 2 {
        return Err("dism two: expected 2 rows".into());
    }
    let crlf = two.replace('\n', "\r\n");
    ok(parse_driver_table(&crlf), "dism crlf")?;
    let missing = DRIVER_BLOCK.replace("Version : 1.2.3.4\n", "");
    let dup = format!("{DRIVER_BLOCK}Inbox : Yes\n");
    let bad_inbox = DRIVER_BLOCK.replace("Inbox : No", "Inbox : maybe");
    for (what, t) in [
        ("missing", &missing),
        ("dup", &dup),
        ("bad_inbox", &bad_inbox),
    ] {
        if parse_driver_table(t).is_ok() {
            return Err(format!("dism {what}: expected refusal"));
        }
    }
    Ok(vec![
        ("wu12-two-drivers", two.into_bytes()),
        ("wu12-two-drivers-crlf", crlf.into_bytes()),
        ("wu12-missing-version", missing.into_bytes()),
        ("wu12-duplicate-field", dup.into_bytes()),
        ("wu12-bad-inbox", bad_inbox.into_bytes()),
    ])
}

// ------------------------------------------------------------ proto bodies

fn key(n: u8) -> Sha256Digest {
    Sha256Digest([n; 32])
}

fn device<T: serde::de::DeserializeOwned>(json: &str, what: &str) -> Result<Vec<u8>, String> {
    ok(
        parse_request::<T>(json.as_bytes(), MAX_DEVICE_JSON_BYTES),
        what,
    )?;
    Ok(json.as_bytes().to_vec())
}

fn job_json() -> Result<Vec<u8>, String> {
    let sig = ok(
        SignatureV1::new(key(3), SignatureAlg::EcdsaP384Sha384, vec![0x30; 103]),
        "signature",
    )?;
    let plan = ok(
        SignedEnvelopeV1::new(PayloadType::JobPlanV2, b"{}".to_vec(), vec![sig]),
        "envelope",
    )?;
    let c = PostSetupConfigV1 {
        schema: 1,
        server_url: "https://prov.example:8443".into(),
        server_name: "prov.example".into(),
        trust_anchors_pem: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".into(),
        plan_key_pem: "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n".into(),
        plan,
        job_id: ok(
            JobId::parse("6b2c3d4e-5f60-4b7c-9d8e-0f1a2b3c4d5e"),
            "job id",
        )?,
        agent_sha256: key(9),
        agent_package_file: ok(FileName::new("agent.zip"), "file name")?,
        job_key_file: ok(FileName::new("job.key"), "file name")?,
    };
    ok(c.to_json(), "job.json")
}

fn postsetup_seeds() -> Result<Seeds, String> {
    let nonce = ok(ResumeNonce::new(vec![7; 32]), "nonce")?;
    let challenge = ResumeChallengeV1 {
        nonce: nonce.clone(),
        expires_at: ok(UnixMicros::new(1_793_000_000_000_000), "time")?,
    };
    let request = ResumeRequestV1 {
        nonce,
        sig: ok(ResumeSignature::new(vec![0x30; 70]), "sig")?,
    };
    let token = "A".repeat(43);
    let resumed = format!(r#"{{"token":"{token}","expires_at":1793000000000000,"ack_seq":12}}"#);
    let resumed = device::<ResumedV1>(&resumed, "resumed")?;
    let mut point = vec![0x04];
    point.extend_from_slice(&[0x11; 96]);
    let submit = EscrowSubmitV1 {
        key_id: key(5),
        eph_pub_b64: ok(B64Bytes::new(point), "point")?,
        nonce_b64: ok(B64Bytes::new(vec![0x22; 12]), "gcm nonce")?,
        ct_b64: ok(B64Bytes::new(vec![0x33; 40]), "ct")?,
        account: EscrowAccount::Administrator,
    };
    let js = |v: &dyn erased::Ser| v.json();
    let confirm_ok = device::<EscrowConfirmV1>(r#"{"set":true}"#, "confirm")?;
    let confirm_fail = device::<EscrowConfirmV1>(
        r#"{"set":false,"code":"admin_password_set_failed:5"}"#,
        "confirm failed",
    )?;
    let p_start = device::<ProgressV2>(
        r#"{"schema":2,"seq":1,"step":7,"event":"step_started"}"#,
        "progress start",
    )?;
    let p_restart = device::<ProgressV2>(
        r#"{"schema":2,"seq":5,"step":8,"event":"step_completed","restart_pending":true}"#,
        "progress restart",
    )?;
    let p_bytes = device::<ProgressV2>(
        r#"{"schema":2,"seq":2,"step":4,"event":"progress","bytes_done":10,"bytes_total":20,"item":{"role":"driver_archive","name":"net.zip"}}"#,
        "progress bytes",
    )?;
    let failure = r#"{"step":4,"category":"local","code":"driver_not_staged:abc:x.inf","files":[{"role":"driver_archive","name":"net.zip"}],"count":1,"attempts":1}"#;
    let p_failed = device::<ProgressV2>(
        &format!(r#"{{"schema":2,"seq":3,"step":4,"event":"failed","failure":{failure}}}"#),
        "progress failed",
    )?;
    let p_done = device::<ProgressV2>(
        r#"{"schema":2,"seq":9,"step":9,"event":"succeeded"}"#,
        "progress done",
    )?;
    let f = device::<FailureV2>(failure, "failure")?;
    Ok(vec![
        ("wu12-challenge", with_sel(0, &js(&challenge)?)),
        ("wu12-resume-request", with_sel(1, &js(&request)?)),
        ("wu12-resumed", with_sel(2, &resumed)),
        ("wu12-escrow-submit", with_sel(3, &js(&submit)?)),
        ("wu12-escrow-confirm", with_sel(4, &confirm_ok)),
        ("wu12-escrow-confirm-failed", with_sel(4, &confirm_fail)),
        ("wu12-progress-start", with_sel(5, &p_start)),
        ("wu12-progress-restart", with_sel(5, &p_restart)),
        ("wu12-progress-bytes", with_sel(5, &p_bytes)),
        ("wu12-progress-failed", with_sel(5, &p_failed)),
        ("wu12-progress-succeeded", with_sel(5, &p_done)),
        ("wu12-failure", with_sel(6, &f)),
        ("wu12-job-json", with_sel(7, &job_json()?)),
    ])
}

/// Serialization through a trait object, so the seed list stays a table.
mod erased {
    pub trait Ser {
        fn json(&self) -> Result<Vec<u8>, String>;
    }
    impl<T: serde::Serialize> Ser for T {
        fn json(&self) -> Result<Vec<u8>, String> {
            serde_json::to_vec(self).map_err(|e| format!("serialize: {e}"))
        }
    }
}

fn agent_manifest_seeds() -> Result<Seeds, String> {
    let a = br#"{"installer":"setup/Agent.MSI"}"#.to_vec();
    let b = br#"{"installer":"a.exe","args":["/S","/norestart"],"success_exit_codes":[0,3010],"timeout_s":3600,"service_name":"agentsvc"}"#.to_vec();
    for (what, j) in [("msi", &a), ("exe", &b)] {
        ok(AgentPackageManifestV1::from_json(j), what)?;
    }
    let bat = br#"{"installer":"a.bat"}"#.to_vec();
    let shell = br#"{"installer":"a.exe","shell":true}"#.to_vec();
    for (what, j) in [("bat", &bat), ("shell", &shell)] {
        if AgentPackageManifestV1::from_json(j).is_ok() {
            return Err(format!("agent manifest {what}: expected refusal"));
        }
    }
    Ok(vec![
        ("wu12-msi", a),
        ("wu12-exe-full", b),
        ("wu12-bat-refused", bat),
        ("wu12-unknown-key", shell),
    ])
}

fn manifest_v2(kind: ContentKindV2, size: u64) -> Result<ContentManifestV2, String> {
    let n = usize::try_from(chunk_count(size)).map_err(|e| e.to_string())?;
    let infs = match kind {
        ContentKindV2::DriverArchive => vec![
            ok(WireRelPath::new("net/net.inf"), "path")?,
            ok(WireRelPath::new("storage/disk.INF"), "path")?,
        ],
        ContentKindV2::AgentPackage => Vec::new(),
    };
    Ok(ContentManifestV2 {
        schema: 2,
        kind,
        content_id: ok(
            ContentId::parse("1b7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e6f"),
            "id",
        )?,
        display_name: ok(DisplayName::new("NIC drivers"), "name")?,
        file_name: ok(FileName::new("drivers.zip"), "file")?,
        size,
        sha256: key(0xaa),
        chunk_size: CHUNK_SIZE,
        chunk_sha256: vec![key(0xbb); n],
        archive: ArchiveSummaryV1 {
            format: ArchiveFormat::Zip,
            entries: 6,
            expanded_bytes: 4096,
            infs,
        },
        ready_at: ok(UnixMicros::new(1_793_000_000_000_000), "time")?,
        key_id: key(7),
    })
}

fn content_v2_seeds() -> Result<Seeds, String> {
    let driver = ok(
        manifest_v2(ContentKindV2::DriverArchive, 5)?.to_payload(),
        "driver",
    )?;
    let agent = ok(
        manifest_v2(ContentKindV2::AgentPackage, CHUNK_SIZE * 2 + 1)?.to_payload(),
        "agent",
    )?;
    let mut bad = manifest_v2(ContentKindV2::AgentPackage, 5)?;
    bad.archive.infs = vec![ok(WireRelPath::new("x.inf"), "path")?];
    let bad = serde_json::to_vec(&bad).map_err(|e| e.to_string())?;
    if ContentManifestV2::from_payload(&bad).is_ok() {
        return Err("content v2 bad: expected refusal".into());
    }
    Ok(vec![
        ("wu12-driver-archive", driver),
        ("wu12-agent-package-3-chunks", agent),
        ("wu12-agent-with-inf", bad),
    ])
}

fn main() -> ExitCode {
    let Some(root) = std::env::args_os().nth(1).map(PathBuf::from) else {
        eprintln!("usage: gen_seeds_m4 <corpus-root>");
        return ExitCode::from(2);
    };
    let all = || -> Result<Vec<(&'static str, Seeds)>, String> {
        Ok(vec![
            ("unattend_template", unattend_seeds()?),
            ("zip_archive", zip_seeds()?),
            ("cab_archive", cab_seeds()?),
            ("inflate_diff", inflate_seeds()?),
            ("inf_version", inf_seeds()),
            ("dism_driver_table", dism_seeds()?),
            ("postsetup_msgs", postsetup_seeds()?),
            ("agent_package_manifest", agent_manifest_seeds()?),
            ("content_manifest_v2", content_v2_seeds()?),
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
            eprintln!("gen_seeds_m4: {e}");
            ExitCode::FAILURE
        }
    }
}
