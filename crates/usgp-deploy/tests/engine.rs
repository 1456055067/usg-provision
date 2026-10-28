//! The step engine end to end against test doubles (plan WU-8, section
//! 10.1): the full flow, the progress sequence, every step's failure, the
//! tamper cases (acceptance 4: nothing written), the wipe-guard refusals,
//! retries and time limits. Disks are in memory or loopback files only.

// COMPLIANCE MAPPING:
// - NIST 800-53: SA-11 (Developer Testing and Evaluation), SI-7, SI-7(6),
//   AC-3, SI-11, SC-5
// - SPEC: specs/progress.md#REQ-JOB-002..008, #REQ-JOB-011..013
// - SPEC: specs/preinstall-env.md#REQ-PE-016, #REQ-PE-017, #REQ-PE-019
// - SPEC: specs/disk.md#REQ-DISK-006, #REQ-DISK-009, #REQ-DISK-012..015
// - SPEC: specs/boot-network.md#REQ-BOOT-065, #REQ-BOOT-066
// - DECISION: docs/decisions/0018 items 7 to 10, 0021 item 4

pub mod common;

use std::rc::Rc;
use std::time::Duration;

use common::*;
use usgp_deploy::platform::{PlatformError, PlatformErrorKind};
use usgp_deploy::{EngineConfig, FwError, LinkError};
use usgp_disk::gpt::{GptLimits, parse_gpt};
use usgp_disk::uefi::{UefiLimits, parse_boot_order, parse_load_option};
use usgp_disk::{FileBlockDevice, MemBlockDevice};
use usgp_image::apply::MemorySink;
use usgp_proto::progress::{FailureCategory, FileRole, JobState, ProgressEvent, Step};

const EXPECTED_STATES: [(u8, ProgressEvent); 10] = [
    (1, ProgressEvent::StepStarted),
    (1, ProgressEvent::StepCompleted),
    (2, ProgressEvent::StepStarted),
    (2, ProgressEvent::StepCompleted),
    (3, ProgressEvent::StepStarted),
    (3, ProgressEvent::StepCompleted),
    (4, ProgressEvent::StepStarted),
    (4, ProgressEvent::StepCompleted),
    (5, ProgressEvent::StepStarted),
    (5, ProgressEvent::Succeeded),
];

// ---------------------------------------------------------------------------
// Full flow
// ---------------------------------------------------------------------------

#[test]
fn full_flow_writes_gpt_applies_and_puts_windows_first() {
    let fx = Fixture::new(small_wim());
    let (mut pf, dev) = TestPlatform::mem();
    let mut link = link_for(&fx);
    let o = run(&fx, &mut pf, &mut link);
    let ok = o.result.as_ref().expect("job succeeds");

    // GPT on the disk is valid and is the layout reported (REQ-DISK-009,
    // REQ-DISK-014).
    let mut d = dev.clone();
    let view = parse_gpt(&mut d, &GptLimits::default()).unwrap();
    assert_eq!(view.entries.len(), 4);
    let parts = ok.layout.partitions();
    assert_eq!(parts.len(), 4);
    for (p, (_, e)) in parts.iter().zip(&view.entries) {
        assert_eq!(p.start_bytes, e.first_lba * 512);
    }
    assert_eq!(parts[0].label.as_ref().unwrap().as_str(), "System");
    assert!(parts[1].fs.is_none(), "the MSR is not formatted");

    // The image was applied to the Windows volume (REQ-PE-017).
    let sink = &pf.vols.sink;
    assert!(pf.vols.sink_opened);
    let readme = sink.node(&path("readme.txt")).expect("readme applied");
    assert_eq!(readme.data, b"hello\n");
    assert!(sink.same_node(
        &path("links\\hard-original.txt"),
        &path("links\\sub\\hard-three.txt")
    ));
    assert!(ok.bytes_written > 0);

    // Boot files, then our option first, the old one kept after it
    // (REQ-BOOT-065, REQ-BOOT-066).
    assert_eq!(pf.boot.calls, 1);
    let order = parse_boot_order(&pf.fw.vars["BootOrder"], &UefiLimits::default()).unwrap();
    assert_eq!(order, vec![ok.boot.option, 0]);
    assert_ne!(ok.boot.option, 0);
    let ours = &pf.fw.vars[&format!("Boot{:04X}", ok.boot.option)];
    let opt = parse_load_option(ours, &UefiLimits::default()).unwrap();
    assert_eq!(opt.description_lossy(), "Windows Boot Manager");
    assert_eq!(
        pf.fw.vars["Boot0000"],
        vec![1, 2, 3],
        "other options untouched"
    );
    assert!(
        pf.fw
            .written
            .iter()
            .all(|n| n == "BootOrder" || n.starts_with("Boot"))
    );

    // The Windows volume was formatted on the root promised before the wipe.
    assert_eq!(pf.vols.format_roots, vec!["W:".to_owned()]);

    // Two content passes (decision 0021 item 4): every chunk twice.
    let n = link.chunk_count();
    assert!(link.fetches.len() as u64 >= 2 * n);
    assert!(dev.writes() > 0);
}

#[test]
fn progress_sequence_on_screen_and_to_the_server() {
    let fx = Fixture::new(small_wim());
    let (mut pf, _dev) = TestPlatform::mem();
    let mut link = link_for(&fx);
    let o = run(&fx, &mut pf, &mut link);
    let ok = o.result.as_ref().unwrap();

    // Server: every state change, in order, strictly increasing seq.
    assert_eq!(link.states(), EXPECTED_STATES);
    let seqs: Vec<u64> = link.acked.iter().map(|r| r.seq).collect();
    assert!(seqs.windows(2).all(|w| w[0] < w[1]), "{seqs:?}");
    assert_eq!(ok.reports, link.acked);
    // Step 2's completion carries the layout (REQ-DISK-014).
    let done2 = link
        .acked
        .iter()
        .find(|r| r.step == Step::PARTITION_FORMAT && r.event == ProgressEvent::StepCompleted)
        .unwrap();
    assert_eq!(done2.layout.as_ref(), Some(&ok.layout));
    // Byte progress during the download step names the image.
    let prog = link
        .acked
        .iter()
        .find(|r| r.event == ProgressEvent::Progress)
        .expect("a progress report");
    assert_eq!(prog.step, Step::VERIFY_CONTENT);
    assert_eq!(prog.item.as_ref().unwrap().role, FileRole::Image);
    assert_eq!(prog.item.as_ref().unwrap().name.as_str(), "install.wim");
    assert_eq!(prog.bytes_total, Some(fx.wim.len() as u64));

    // Screen: the same steps, success only at the end (REQ-JOB-004).
    assert_eq!(
        o.view.states(),
        vec![
            Shown::Started,
            Shown::StepStarted(1),
            Shown::StepCompleted(1),
            Shown::StepStarted(2),
            Shown::StepCompleted(2),
            Shown::StepStarted(3),
            Shown::StepCompleted(3),
            Shown::StepStarted(4),
            Shown::StepCompleted(4),
            Shown::StepStarted(5),
            Shown::Succeeded,
        ]
    );
    assert!(o.view.0.contains(&Shown::Progress(1)));
    assert!(o.view.0.contains(&Shown::Progress(3)));
}

#[test]
fn full_flow_on_a_loopback_file() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("deploy-loopback");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let target = dir.join("target.img");
    drop(FileBlockDevice::create(&target, DISK_BYTES, 512).unwrap());
    // Another disk image next to it, which must stay unchanged.
    let other = dir.join("other.img");
    let other_bytes = usgp_image::testkit::builder::pseudorandom(1 << 20, 3);
    std::fs::write(&other, &other_bytes).unwrap();

    let fx = Fixture::new(small_wim());
    let mut pf = TestPlatform::with(DevSource::File(target.clone(), 512));
    let mut link = link_for(&fx);
    let o = run(&fx, &mut pf, &mut link);
    let ok = o.result.expect("job succeeds");

    let mut dev = FileBlockDevice::open(&target, 512, false).unwrap();
    let view = parse_gpt(&mut dev, &GptLimits::default()).unwrap();
    assert_eq!(view.entries.len(), 4);
    assert_eq!(
        view.disk_guid.to_string().to_ascii_lowercase(),
        format!("{:?}", ok.layout.disk_guid())
            .to_ascii_lowercase()
            .replace("diskguid(", "")
            .replace(')', "")
    );
    assert_eq!(std::fs::read(&other).unwrap(), other_bytes);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn rebased_links_use_the_promised_drive_letter() {
    use usgp_image::testkit::tree::abs_link_data;
    for (root, letter) in [("W:\\", "W"), ("R:", "R")] {
        let fx = Fixture::new(link_wim());
        let (mut pf, _dev) = TestPlatform::mem();
        pf.vols.windows_root = root.to_owned();
        let mut link = link_for(&fx);
        let o = run(&fx, &mut pf, &mut link);
        assert!(o.result.is_ok(), "{:?}", o.result.err());
        let reparse = |p: &str| {
            pf.vols
                .sink
                .node(&path(p))
                .unwrap()
                .reparse
                .clone()
                .unwrap()
        };
        let j = reparse("links\\junction");
        assert!(j.rebased());
        assert_eq!(
            j.data(),
            abs_link_data(&format!("{letter}:\\links\\target-dir"), true)
        );
        let d = reparse("links\\abs-dir");
        assert!(d.rebased());
        assert_eq!(
            d.data(),
            abs_link_data(&format!("{letter}:\\links\\target-dir"), false)
        );
        let out = reparse("links\\junction-out");
        assert!(!out.rebased());
        assert_eq!(out.data(), abs_link_data("T:\\outside", true));
    }
}

#[test]
fn apply_root_that_is_not_a_bare_drive_letter_fails_before_any_write() {
    for bad in [
        "W:\\mnt",
        "W:\\Windows\\",
        "w:\\",
        "\\\\?\\Volume{00000000-0000-0000-0000-000000000000}\\",
        "\\\\server\\share",
        "",
    ] {
        let fx = Fixture::new(small_wim());
        let (mut pf, dev) = TestPlatform::mem();
        pf.vols.windows_root = bad.to_owned();
        let mut link = link_for(&fx);
        let o = run(&fx, &mut pf, &mut link);
        let f = failure(&o, &link);
        assert_eq!(f.step, Step::VERIFY_CONTENT, "{bad:?}");
        assert_eq!(f.category, FailureCategory::Local);
        assert_eq!(f.code.as_str(), "apply_root_unsupported");
        assert!(link.fetches.is_empty(), "decided before the verify pass");
        assert_nothing_written(&pf, &dev);
    }
}

#[test]
fn windows_volume_on_another_letter_is_refused_before_apply() {
    for reported in [Some("V:\\".to_owned()), Some("W:\\mnt".to_owned()), None] {
        let fx = Fixture::new(small_wim());
        let (mut pf, _dev) = TestPlatform::mem();
        pf.vols.reported_root = Some(reported.clone());
        let mut link = link_for(&fx);
        let o = run(&fx, &mut pf, &mut link);
        let f = failure(&o, &link);
        assert_eq!(f.step, Step::PARTITION_FORMAT, "{reported:?}");
        assert_eq!(f.code.as_str(), "format_failed");
        assert!(f.message.contains("planned drive letter"), "{}", f.message);
        assert!(!pf.vols.sink_opened);
    }
}

// ---------------------------------------------------------------------------
// Tampering fails before any write (acceptance 4)
// ---------------------------------------------------------------------------

fn assert_nothing_written(pf: &TestPlatform, dev: &SharedDev) {
    assert_eq!(pf.opens, 0, "the target disk was never opened");
    assert_eq!(dev.writes(), 0);
    assert_eq!(pf.vols.formats, 0);
    assert!(pf.fw.written.is_empty());
}

#[test]
fn tampered_plan_signature_fails_before_any_write() {
    let fx = Fixture::new(small_wim());
    let (mut pf, dev) = TestPlatform::mem();
    let mut link = link_for(&fx);
    let o = run_envs(
        &fx,
        &fx.plan_env_tampered(Some(20)),
        &fx.content_env(),
        &mut pf,
        &mut link,
        EngineConfig::default(),
    );
    let f = failure(&o, &link);
    assert_eq!(f.step, Step::VERIFY_CONTENT);
    assert_eq!(f.category, FailureCategory::Integrity);
    assert_eq!(f.code.as_str(), "plan_signature_invalid");
    assert!(!f.disk_written);
    assert!(link.fetches.is_empty(), "no content fetched for a bad plan");
    assert_nothing_written(&pf, &dev);
}

#[test]
fn plan_from_an_untrusted_key_fails() {
    let fx = Fixture::new(small_wim());
    let (mut pf, dev) = TestPlatform::mem();
    let mut link = link_for(&fx);
    let rogue = usgp_crypto::SigningKey::generate().unwrap();
    let o = run_envs(
        &fx,
        &fx.plan_env_signed_by(&rogue),
        &fx.content_env(),
        &mut pf,
        &mut link,
        EngineConfig::default(),
    );
    assert_eq!(failure(&o, &link).code.as_str(), "plan_signature_invalid");
    assert_nothing_written(&pf, &dev);
}

#[test]
fn tampered_content_manifest_fails_before_any_write() {
    let fx = Fixture::new(small_wim());
    let (mut pf, dev) = TestPlatform::mem();
    let mut link = link_for(&fx);
    let o = run_envs(
        &fx,
        &fx.plan_env(),
        &fx.content_env_tampered(Some(30)),
        &mut pf,
        &mut link,
        EngineConfig::default(),
    );
    let f = failure(&o, &link);
    assert_eq!(f.category, FailureCategory::Integrity);
    assert_eq!(f.code.as_str(), "content_manifest_mismatch");
    assert_nothing_written(&pf, &dev);
}

#[test]
fn replayed_plan_with_another_nonce_fails() {
    let mut fx = Fixture::new(small_wim());
    let (mut pf, dev) = TestPlatform::mem();
    let mut link = link_for(&fx);
    let env = fx.plan_env();
    let content = fx.content_env();
    fx.nonce = usgp_proto::device::AgentNonce::from_random_bytes([0x43; 32]);
    let o = run_envs(
        &fx,
        &env,
        &content,
        &mut pf,
        &mut link,
        EngineConfig::default(),
    );
    assert_eq!(failure(&o, &link).code.as_str(), "plan_nonce_mismatch");
    assert_nothing_written(&pf, &dev);
}

#[test]
fn tampered_chunk_fails_in_the_verify_pass_before_any_write() {
    let fx = Fixture::new(small_wim());
    let (mut pf, dev) = TestPlatform::mem();
    let mut link = link_for(&fx);
    link.tamper_fetch = Some(0);
    let o = run(&fx, &mut pf, &mut link);
    let f = failure(&o, &link);
    assert_eq!(f.step, Step::VERIFY_CONTENT);
    assert_eq!(f.category, FailureCategory::Integrity);
    assert_eq!(f.code.as_str(), "chunk_digest_mismatch");
    assert_eq!(f.attempts, 1, "integrity failures are not retried");
    assert_eq!(f.count, 1);
    assert_eq!(f.files[0].role, FileRole::Image);
    assert_eq!(f.files[0].name.as_str(), "install.wim");
    assert!(!f.disk_written);
    assert_eq!(link.fetches.len(), 1);
    assert_nothing_written(&pf, &dev);
    // Only step 1 started; the failure is final.
    assert_eq!(
        link.states(),
        vec![(1, ProgressEvent::StepStarted), (1, ProgressEvent::Failed)]
    );
}

#[test]
fn tampered_later_chunk_fails_before_any_write() {
    let fx = Fixture::new(two_chunk_wim());
    let (mut pf, dev) = TestPlatform::mem();
    let mut link = link_for(&fx);
    assert_eq!(link.chunk_count(), 2);
    // The verify pass reads chunk 0 first; tamper the first fetch of
    // chunk 1, wherever it falls.
    let mut probe = link_for(&fx);
    let _ = run(&fx, &mut TestPlatform::mem().0, &mut probe);
    let first_one = probe.fetches.iter().position(|&n| n == 1).unwrap();
    link.tamper_fetch = Some(first_one);
    let o = run(&fx, &mut pf, &mut link);
    let f = failure(&o, &link);
    assert_eq!(f.step, Step::VERIFY_CONTENT);
    assert_eq!(f.code.as_str(), "chunk_digest_mismatch");
    assert!(f.message.contains("chunk 1"), "{}", f.message);
    assert_nothing_written(&pf, &dev);
}

#[test]
fn tampered_chunk_in_the_apply_pass_fails_step_3() {
    let fx = Fixture::new(small_wim());
    let (mut pf, _dev) = TestPlatform::mem();
    let mut probe = link_for(&fx);
    let _ = run(&fx, &mut TestPlatform::mem().0, &mut probe);
    // The first fetch of the apply pass follows the verify pass's fetches.
    let pass1 = probe.fetches.len() / 2;
    let mut link = link_for(&fx);
    link.tamper_fetch = Some(pass1);
    let o = run(&fx, &mut pf, &mut link);
    let f = failure(&o, &link);
    assert_eq!(f.step, Step::APPLY_IMAGE);
    assert_eq!(f.category, FailureCategory::Integrity);
    assert_eq!(f.code.as_str(), "chunk_digest_mismatch");
    assert!(f.disk_written);
    assert!(
        pf.fw.written.is_empty(),
        "boot settings untouched (REQ-JOB-008)"
    );
    assert_eq!(pf.boot.calls, 0);
}

// ---------------------------------------------------------------------------
// Network: retry, exhaustion, refusal
// ---------------------------------------------------------------------------

#[test]
fn transient_fetch_failures_are_retried_with_growing_delays() {
    let fx = Fixture::new(small_wim());
    let (mut pf, _dev) = TestPlatform::mem();
    let mut link = link_for(&fx);
    link.transient_fetches = 2;
    let o = run(&fx, &mut pf, &mut link);
    assert!(o.result.is_ok(), "{:?}", o.result.err());
    // 2 s, then 4 s (base 2000 ms, doubling).
    assert_eq!(link.clock.slept.get(), Duration::from_secs(6));
}

#[test]
fn network_failure_after_every_retry_names_the_file_and_attempts() {
    let fx = Fixture::new(small_wim());
    let (mut pf, dev) = TestPlatform::mem();
    let mut link = link_for(&fx);
    link.fetch_error = Some(LinkError::Transient);
    let o = run(&fx, &mut pf, &mut link);
    let f = failure(&o, &link);
    assert_eq!(f.step, Step::VERIFY_CONTENT);
    assert_eq!(f.category, FailureCategory::Network);
    assert_eq!(f.code.as_str(), "server_unreachable");
    assert_eq!(f.attempts, fx.plan.retry.attempts);
    assert_eq!(f.files.len(), 1);
    assert_nothing_written(&pf, &dev);
}

#[test]
fn missing_content_is_not_retried() {
    let fx = Fixture::new(small_wim());
    let (mut pf, dev) = TestPlatform::mem();
    let mut link = link_for(&fx);
    link.fetch_error = Some(LinkError::NotFound);
    let o = run(&fx, &mut pf, &mut link);
    let f = failure(&o, &link);
    assert_eq!(f.category, FailureCategory::Refused);
    assert_eq!(f.code.as_str(), "content_not_found");
    assert_eq!(f.attempts, 1);
    assert_eq!(link.clock.slept.get(), Duration::ZERO);
    assert_nothing_written(&pf, &dev);
}

#[test]
fn server_integrity_failure_is_named() {
    let fx = Fixture::new(small_wim());
    let (mut pf, dev) = TestPlatform::mem();
    let mut link = link_for(&fx);
    link.fetch_error = Some(LinkError::ServerIntegrity);
    let o = run(&fx, &mut pf, &mut link);
    let f = failure(&o, &link);
    assert_eq!(f.category, FailureCategory::Integrity);
    assert_eq!(f.code.as_str(), "integrity_failed");
    assert_nothing_written(&pf, &dev);
}

#[test]
fn network_loss_during_apply_fails_step_3() {
    let fx = Fixture::new(small_wim());
    let (mut pf, _dev) = TestPlatform::mem();
    let mut probe = link_for(&fx);
    let _ = run(&fx, &mut TestPlatform::mem().0, &mut probe);
    let mut link = link_for(&fx);
    link.fail_after = Some(probe.fetches.len() / 2);
    let o = run(&fx, &mut pf, &mut link);
    let f = failure(&o, &link);
    assert_eq!(f.step, Step::APPLY_IMAGE);
    assert_eq!(f.category, FailureCategory::Network);
}

#[test]
fn reports_queue_while_the_server_is_away_and_arrive_in_order() {
    let fx = Fixture::new(small_wim());
    let (mut pf, _dev) = TestPlatform::mem();
    let mut link = link_for(&fx);
    // The first eight report attempts fail: the steps carry on
    // (REQ-DISK-012) and the queue is delivered later.
    link.transient_reports = 8;
    let o = run(&fx, &mut pf, &mut link);
    assert!(o.result.is_ok(), "{:?}", o.result.err());
    assert_eq!(link.states(), EXPECTED_STATES);
    let seqs: Vec<u64> = link.acked.iter().map(|r| r.seq).collect();
    assert!(seqs.windows(2).all(|w| w[0] < w[1]), "{seqs:?}");
}

// ---------------------------------------------------------------------------
// Step 2: wipe guard and disk failures
// ---------------------------------------------------------------------------

fn step2_refusal(pf: &mut TestPlatform, fx: &Fixture) -> usgp_deploy::JobFailure {
    let mut link = link_for(fx);
    let o = run(fx, pf, &mut link);
    let f = failure(&o, &link);
    assert_eq!(f.step, Step::PARTITION_FORMAT);
    assert!(!f.disk_written);
    assert_eq!(pf.vols.formats, 0);
    f
}

#[test]
fn opened_disk_that_is_not_the_confirmed_one_is_refused() {
    let fx = Fixture::new(small_wim());
    let (mut pf, dev) = TestPlatform::mem();
    pf.facts.identity.serial = Some("SN-9999".to_owned());
    let f = step2_refusal(&mut pf, &fx);
    assert_eq!(f.category, FailureCategory::Refused);
    assert_eq!(f.code.as_str(), "disk_identity_mismatch");
    assert!(
        f.message.contains("Test NVMe"),
        "names the disk: {}",
        f.message
    );
    assert_eq!(dev.writes(), 0);
}

#[test]
fn device_of_another_size_is_refused_by_the_wipe_guard() {
    let fx = Fixture::new(small_wim());
    // The platform reports the confirmed facts, but the device it opened
    // is larger: the executor's preflight refuses.
    let dev = SharedDev::new(DISK_BYTES + 512 * 8, 512);
    let mut pf = TestPlatform::with(DevSource::Mem(dev.clone()));
    let f = step2_refusal(&mut pf, &fx);
    assert_eq!(f.code.as_str(), "disk_identity_mismatch");
    assert_eq!(dev.writes(), 0);
}

#[test]
fn plan_without_a_durable_wipe_record_is_refused() {
    let mut fx = Fixture::new(small_wim());
    fx.plan.wipe.record_hash = usgp_common::Sha256Digest([0; 32]);
    let (mut pf, dev) = TestPlatform::mem();
    let f = step2_refusal(&mut pf, &fx);
    assert_eq!(f.category, FailureCategory::Refused);
    assert_eq!(f.code.as_str(), "wipe_not_authorised");
    assert_eq!(dev.writes(), 0);
}

#[test]
fn disk_that_became_ineligible_is_refused() {
    let fx = Fixture::new(small_wim());
    let cases: [fn(&mut usgp_disk::DiskFacts); 4] = [
        |f| f.removable = true,
        |f| f.hosts_boot_environment = true,
        |f| f.read_only = true,
        |f| f.bus = usgp_disk::Bus::Usb,
    ];
    for (i, c) in cases.iter().enumerate() {
        let (mut pf, dev) = TestPlatform::mem();
        c(&mut pf.facts);
        let f = step2_refusal(&mut pf, &fx);
        let want = if i == 3 {
            "disk_identity_mismatch" // the bus differs from the plan's
        } else {
            "disk_not_eligible"
        };
        assert_eq!(f.code.as_str(), want, "case {i}");
        assert_eq!(dev.writes(), 0);
    }
}

#[test]
fn disk_open_failure_is_named() {
    let fx = Fixture::new(small_wim());
    let (mut pf, dev) = TestPlatform::mem();
    pf.fail_open = Some(PlatformError::new(
        PlatformErrorKind::Refused,
        "open target disk",
    ));
    let f = step2_refusal(&mut pf, &fx);
    assert_eq!(f.category, FailureCategory::Local);
    assert_eq!(f.code.as_str(), "disk_open_failed");
    assert_eq!(dev.writes(), 0);
}

#[test]
fn format_failure_stops_before_apply() {
    let fx = Fixture::new(small_wim());
    let (mut pf, _dev) = TestPlatform::mem();
    pf.vols.fail = Some(PlatformError::new(
        PlatformErrorKind::Io(std::io::ErrorKind::Other),
        "format volume",
    ));
    let mut link = link_for(&fx);
    let o = run(&fx, &mut pf, &mut link);
    let f = failure(&o, &link);
    assert_eq!(f.step, Step::PARTITION_FORMAT);
    assert_eq!(f.category, FailureCategory::Local);
    assert_eq!(f.code.as_str(), "format_failed");
    assert!(f.disk_written);
    assert!(
        !pf.vols.sink_opened,
        "no apply after a failed format (REQ-DISK-013)"
    );
}

#[test]
fn format_result_that_differs_from_the_plan_is_refused() {
    let fx = Fixture::new(small_wim());
    let (mut pf, _dev) = TestPlatform::mem();
    pf.vols.wrong_label = true;
    let mut link = link_for(&fx);
    let o = run(&fx, &mut pf, &mut link);
    let f = failure(&o, &link);
    assert_eq!(f.code.as_str(), "format_failed");
    assert!(!pf.vols.sink_opened);
}

// ---------------------------------------------------------------------------
// Steps 3 to 5
// ---------------------------------------------------------------------------

#[test]
fn apply_target_failure_fails_step_3() {
    let fx = Fixture::new(small_wim());
    let (mut pf, _dev) = TestPlatform::mem();
    pf.vols.sink = MemorySink::with_limit(16);
    let mut link = link_for(&fx);
    let o = run(&fx, &mut pf, &mut link);
    let f = failure(&o, &link);
    assert_eq!(f.step, Step::APPLY_IMAGE);
    assert_eq!(f.category, FailureCategory::Local);
    assert_eq!(f.code.as_str(), "apply_target_failed");
    assert_eq!(pf.boot.calls, 0);
}

#[test]
fn boot_file_failure_fails_step_4() {
    let fx = Fixture::new(small_wim());
    let (mut pf, _dev) = TestPlatform::mem();
    pf.boot.fail = Some(PlatformError::new(
        PlatformErrorKind::Io(std::io::ErrorKind::Other),
        "create boot files",
    ));
    let mut link = link_for(&fx);
    let o = run(&fx, &mut pf, &mut link);
    let f = failure(&o, &link);
    assert_eq!(f.step, Step::MAKE_BOOTABLE);
    assert_eq!(f.code.as_str(), "boot_files_failed");
    assert!(pf.fw.written.is_empty());
}

#[test]
fn firmware_failure_fails_step_4() {
    let fx = Fixture::new(small_wim());
    let (mut pf, _dev) = TestPlatform::mem();
    pf.fw.fail_set = Some(FwError::Denied);
    let mut link = link_for(&fx);
    let o = run(&fx, &mut pf, &mut link);
    let f = failure(&o, &link);
    assert_eq!(f.step, Step::MAKE_BOOTABLE);
    assert_eq!(f.code.as_str(), "boot_entry_failed");
}

#[test]
fn malformed_boot_order_is_not_overwritten() {
    let fx = Fixture::new(small_wim());
    let (mut pf, _dev) = TestPlatform::mem();
    pf.fw.vars.insert("BootOrder".to_owned(), vec![1, 2, 3]);
    let mut link = link_for(&fx);
    let o = run(&fx, &mut pf, &mut link);
    let f = failure(&o, &link);
    assert_eq!(f.step, Step::MAKE_BOOTABLE);
    assert_eq!(f.code.as_str(), "boot_entry_failed");
    assert_eq!(pf.fw.vars["BootOrder"], vec![1, 2, 3]);
    assert!(pf.fw.written.is_empty());
}

#[test]
fn firmware_that_drops_writes_fails_the_read_back() {
    let fx = Fixture::new(small_wim());
    let (mut pf, _dev) = TestPlatform::mem();
    pf.fw.drop_writes = true;
    let mut link = link_for(&fx);
    let o = run(&fx, &mut pf, &mut link);
    let f = failure(&o, &link);
    assert_eq!(f.code.as_str(), "boot_entry_failed");
    assert!(f.message.contains("read-back"), "{}", f.message);
}

#[test]
fn success_not_recorded_by_the_server_fails_step_5() {
    let fx = Fixture::new(small_wim());
    let (mut pf, _dev) = TestPlatform::mem();
    let mut link = link_for(&fx);
    link.success_state = JobState::Failed;
    let o = run(&fx, &mut pf, &mut link);
    let f = failure(&o, &link);
    assert_eq!(f.step, Step::REPORT_RESTART);
    assert_eq!(f.category, FailureCategory::Refused);
    assert_eq!(f.code.as_str(), "success_not_accepted");
}

#[test]
fn success_report_refused_fails_step_5() {
    let fx = Fixture::new(small_wim());
    let (mut pf, _dev) = TestPlatform::mem();
    let mut link = link_for(&fx);
    link.success_error = Some(LinkError::Refused);
    let o = run(&fx, &mut pf, &mut link);
    let f = failure(&o, &link);
    assert_eq!(f.step, Step::REPORT_RESTART);
    assert_eq!(f.code.as_str(), "success_not_accepted");
}

#[test]
fn success_report_undeliverable_fails_step_5_as_network() {
    let fx = Fixture::new(small_wim());
    let (mut pf, _dev) = TestPlatform::mem();
    let mut link = link_for(&fx);
    link.success_error = Some(LinkError::Transient);
    let o = run(&fx, &mut pf, &mut link);
    let f = o.result.clone().unwrap_err();
    assert_eq!(f.step, Step::REPORT_RESTART);
    assert_eq!(f.category, FailureCategory::Network);
    assert_eq!(f.code.as_str(), "server_unreachable");
    assert_eq!(o.view.0.last(), Some(&Shown::Failed(f)));
    assert!(!o.view.0.contains(&Shown::Succeeded));
}

// ---------------------------------------------------------------------------
// Time limits (REQ-JOB-011)
// ---------------------------------------------------------------------------

#[test]
fn step_timeout_is_named() {
    let mut fx = Fixture::new(small_wim());
    fx.plan.steps[0].timeout_s = 60;
    let (mut pf, dev) = TestPlatform::mem();
    let mut link = link_for(&fx);
    link.fetch_delay = Duration::from_secs(61);
    let o = run(&fx, &mut pf, &mut link);
    let f = failure(&o, &link);
    assert_eq!(f.step, Step::VERIFY_CONTENT);
    assert_eq!(f.category, FailureCategory::Timeout);
    assert_eq!(f.code.as_str(), "step_timeout");
    assert_nothing_written(&pf, &dev);
}

#[test]
fn stalled_transfer_is_named() {
    let mut fx = Fixture::new(small_wim());
    fx.plan.stall_timeout_s = 30;
    let (mut pf, dev) = TestPlatform::mem();
    let mut link = link_for(&fx);
    link.fetch_error = Some(LinkError::Transient);
    link.fetch_delay = Duration::from_secs(20);
    let o = run(&fx, &mut pf, &mut link);
    let f = failure(&o, &link);
    assert_eq!(f.category, FailureCategory::Timeout);
    assert_eq!(f.code.as_str(), "stalled");
    assert!(f.attempts < fx.plan.retry.attempts);
    assert_nothing_written(&pf, &dev);
}

#[test]
fn slow_platform_step_is_not_a_stall() {
    let mut fx = Fixture::new(small_wim());
    fx.plan.stall_timeout_s = 30;
    let (mut pf, _dev) = TestPlatform::mem();
    let mut link = link_for(&fx);
    // BCDBoot takes longer than the stall limit but within the step's own.
    pf.boot.delay = Some((Rc::clone(&link.clock), Duration::from_secs(300)));
    let o = run(&fx, &mut pf, &mut link);
    assert!(o.result.is_ok(), "{:?}", o.result.err());
}

#[test]
fn slow_boot_file_step_times_out() {
    let mut fx = Fixture::new(small_wim());
    fx.plan.steps[3].timeout_s = 600;
    let (mut pf, _dev) = TestPlatform::mem();
    let mut link = link_for(&fx);
    pf.boot.delay = Some((Rc::clone(&link.clock), Duration::from_secs(601)));
    let o = run(&fx, &mut pf, &mut link);
    let f = failure(&o, &link);
    assert_eq!(f.step, Step::MAKE_BOOTABLE);
    assert_eq!(f.code.as_str(), "step_timeout");
    assert!(pf.fw.written.is_empty());
}

// ---------------------------------------------------------------------------
// Structure
// ---------------------------------------------------------------------------

/// The wipe authorisation is built in one place only: the engine, after
/// the plan is verified (plan section 3.7; DEC-0018 item 7).
#[test]
fn wipe_authorisation_is_built_only_by_the_engine() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = Vec::new();
    for entry in std::fs::read_dir(&src).unwrap() {
        let p = entry.unwrap().path();
        let text = std::fs::read_to_string(&p).unwrap();
        let n = text.matches("WipeAuthorisation::new(").count();
        if n > 0 {
            found.push((p.file_name().unwrap().to_string_lossy().into_owned(), n));
        }
    }
    assert_eq!(found, vec![("engine.rs".to_owned(), 1)]);
}

#[test]
fn in_memory_disk_never_touched_by_a_refused_plan_is_all_zero() {
    let fx = Fixture::new(small_wim());
    let (mut pf, dev) = TestPlatform::mem();
    let mut link = link_for(&fx);
    let _ = run_envs(
        &fx,
        &fx.plan_env_tampered(Some(5)),
        &fx.content_env(),
        &mut pf,
        &mut link,
        EngineConfig::default(),
    );
    let d: &MemBlockDevice = &dev.0.borrow();
    assert!(d.nonzero_lbas().is_empty());
}
