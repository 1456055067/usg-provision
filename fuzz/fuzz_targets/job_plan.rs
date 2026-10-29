//! Fuzz target `job_plan`: the signed job plan (`usgp-proto` `job_plan`)
//! as the pre-boot agent receives it.
//!
//! Octet 0 selects (modulo 2):
//!
//! - 0: the rest is a plan payload for `JobPlanV1::from_payload`;
//! - 1: octet 1 is a mode, the rest a confirm response
//!   (`ConfirmedV1::from_json`) whose two envelopes go through
//!   `VerifiedJobPlan::verify`. Mode bit 0: the plan verifier accepts
//!   (else it refuses everything); bit 1: the content verifier accepts;
//!   bit 2: the expectation is taken from the plan itself (else fixed
//!   values that match nothing). The verifiers are test doubles: the
//!   signature check itself is `usgp-crypto`'s, covered by its own tests;
//!   here they check that they are asked about exactly the signing input
//!   of the envelope's payload. The digest is `usgp-crypto`'s SHA-256.
//!
//! Invariants (M3 plan §3.2; plan WU-14):
//!
//! - no panic; an accepted payload validates, re-encodes to canonical
//!   bytes and parses back to itself, and names a timeout for each of the
//!   five steps;
//! - verify before parse: with the plan verifier refusing, the result is
//!   always the plan-signature refusal and the content verifier is never
//!   asked;
//! - reference model of checks 1 to 6: the plan refusal happens exactly
//!   when the plan payload type is wrong, the payload does not parse, or
//!   its `key_id` is not the signing key; the binding refusals follow the
//!   plan's order; an accepted plan equals the parsed payload, carries the
//!   expected nonce, session, job, package and disk, and names the
//!   SHA-256 of the content manifest payload, which parses to the
//!   returned manifest;
//! - every refusal is an integrity failure with one of the four plan
//!   reason codes.

#![no_main]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7(6) (Cryptographic Protection: verify before parse),
//   SC-23 (Session Authenticity: plan bound to session, job, nonce),
//   SI-10 (Information Input Validation), SA-11 (Developer Testing)
// - SPEC: specs/progress.md#REQ-JOB-005, #REQ-JOB-007, #REQ-JOB-008
// - SPEC: specs/targeting.md#REQ-TGT-006, #REQ-TGT-015
// - SPEC: specs/disk.md#REQ-DISK-015

use std::cell::RefCell;

use libfuzzer_sys::fuzz_target;
use usgp_crypto::Sha256Digest;
use usgp_proto::device::{AgentNonce, ConfirmedV1};
use usgp_proto::disk::{DiskDescriptorParts, DiskDescriptorV1};
use usgp_proto::envelope::{
    PayloadType, SignatureAlg, SignatureVerifier, SignedEnvelopeV1, signing_input,
};
use usgp_proto::job_plan::{JobPlanV1, PlanError, PlanExpectation, VerifiedJobPlan};
use usgp_proto::progress::{FailureCategory, Step};
use usgp_proto::{JobId, PackageId, SessionId, SignedManifestError, codes};

/// A stand-in verifier: accepts every signature if `accept`, and records
/// each message it is asked about.
struct Stub {
    accept: bool,
    asked: RefCell<Vec<Vec<u8>>>,
}

impl Stub {
    fn new(accept: bool) -> Self {
        Self {
            accept,
            asked: RefCell::new(Vec::new()),
        }
    }
}

impl SignatureVerifier for Stub {
    fn verify(&self, _: &Sha256Digest, _: SignatureAlg, message: &[u8], _: &[u8]) -> bool {
        self.asked.borrow_mut().push(message.to_vec());
        self.accept
    }
}

/// Payload bytes and first key id, read with an accept-all verifier.
fn opened(env: &SignedEnvelopeV1, ty: PayloadType) -> Option<(Vec<u8>, Sha256Digest)> {
    let all = Stub::new(true);
    env.verified_payload(ty, &all)
        .ok()
        .map(|v| (v.bytes.to_vec(), v.key_id))
}

fn payload(b: &[u8]) {
    let Ok(p) = JobPlanV1::from_payload(b) else {
        return;
    };
    assert!(p.validate().is_ok(), "accepted plan does not validate");
    let enc = p.to_payload().expect("accepted plan encodes");
    let again = JobPlanV1::from_payload(&enc).expect("own payload parses");
    assert_eq!(again, p, "plan does not round-trip");
    assert_eq!(again.to_payload().ok(), Some(enc), "payload not canonical");
    for s in Step::ALL {
        assert!(
            p.timeout_s(s).is_some_and(|t| t >= 1),
            "no timeout for a step"
        );
    }
}

fn disk_of(p: &JobPlanV1) -> Option<DiskDescriptorV1> {
    DiskDescriptorV1::new(DiskDescriptorParts {
        disk_token: p.disk.disk_token,
        bus: p.disk.bus,
        model: p.disk.model.clone(),
        serial: p.disk.serial.clone(),
        size_bytes: p.disk.size_bytes,
        logical_sector: p.disk.logical_sector,
        physical_sector: p.disk.physical_sector,
        removable: false,
        partitions: Vec::new(),
    })
    .ok()
}

fn fixed_disk() -> DiskDescriptorV1 {
    DiskDescriptorV1::new(DiskDescriptorParts {
        disk_token: usgp_proto::DiskToken::from_random_bytes([0x5a; 16]),
        bus: usgp_proto::disk::Bus::Nvme,
        model: usgp_proto::DiskText::sanitized("fuzz"),
        serial: usgp_proto::DiskText::sanitized("fuzz"),
        size_bytes: 1 << 40,
        logical_sector: 512,
        physical_sector: 4096,
        removable: false,
        partitions: Vec::new(),
    })
    .expect("fixed disk descriptor is valid")
}

fn verify(mode: u8, body: &[u8]) {
    let Ok(c) = ConfirmedV1::from_json(body) else {
        return;
    };
    let plan_keys = Stub::new(mode & 1 != 0);
    let content_keys = Stub::new(mode & 2 != 0);
    let sha = |b: &[u8]| usgp_crypto::sha256(b);
    let plan_open = opened(&c.plan, PayloadType::JobPlanV1);
    let parsed = plan_open
        .as_ref()
        .and_then(|(b, k)| JobPlanV1::from_payload(b).ok().filter(|p| p.key_id == *k));

    let fixed_nonce = AgentNonce::from_random_bytes([0x42; 32]);
    let fixed = fixed_disk();
    let from_plan = mode & 4 != 0;
    let (nonce, disk, session, job, package, revision) = match (&parsed, from_plan) {
        (Some(p), true) => match disk_of(p) {
            Some(d) => (
                p.agent_nonce,
                d,
                p.session_id,
                p.job_id,
                p.package.id,
                p.package.revision,
            ),
            None => return,
        },
        _ => (
            fixed_nonce,
            fixed,
            SessionId::from_random_bytes([1; 16]),
            JobId::from_random_bytes([2; 16]),
            PackageId::from_random_bytes([3; 16]),
            1,
        ),
    };
    let expect = PlanExpectation {
        agent_nonce: &nonce,
        session_id: session,
        job_id: job,
        package_id: package,
        package_revision: revision,
        disk: &disk,
    };
    let r = VerifiedJobPlan::verify(
        &c.plan,
        &plan_keys,
        &c.content_manifest,
        &content_keys,
        &sha,
        &expect,
    );

    // The verifiers were asked only about the signing input of the
    // envelope's own payload.
    if let Some((b, _)) = &plan_open {
        let want = signing_input(PayloadType::JobPlanV1, b);
        assert!(
            plan_keys.asked.borrow().iter().all(|m| *m == want),
            "plan signing input"
        );
    }
    if let Some((b, _)) = opened(&c.content_manifest, PayloadType::ContentManifestV1) {
        let want = signing_input(PayloadType::ContentManifestV1, &b);
        assert!(
            content_keys.asked.borrow().iter().all(|m| *m == want),
            "content signing input"
        );
    }

    if mode & 1 == 0 {
        assert!(
            matches!(&r, Err(PlanError::Plan(SignedManifestError::Envelope(_)))),
            "plan refused by its verifier but not a signature failure"
        );
        assert!(
            content_keys.asked.borrow().is_empty(),
            "content checked before the plan"
        );
        return;
    }
    let e = match r {
        Ok(v) => {
            let p = parsed.as_ref().expect("verified plan parses");
            assert_eq!(v.plan(), p, "verified plan differs from its payload");
            assert_eq!(v.plan().agent_nonce, nonce);
            assert_eq!(
                (v.plan().session_id, v.plan().job_id),
                (session, job),
                "session or job"
            );
            assert_eq!(
                (v.plan().package.id, v.plan().package.revision),
                (package, revision)
            );
            assert!(v.plan().disk.matches(&disk), "disk");
            let (cb, _) = opened(&c.content_manifest, PayloadType::ContentManifestV1)
                .expect("verified content manifest opens");
            assert_eq!(
                sha(&cb),
                v.plan().image.content_manifest_sha256,
                "manifest digest"
            );
            let cm = usgp_proto::ContentManifestV1::from_payload(&cb).expect("manifest parses");
            assert_eq!(v.content_manifest(), &cm, "content manifest differs");
            assert!(mode & 2 != 0, "content accepted by a refusing verifier");
            return;
        }
        Err(e) => e,
    };
    assert_eq!(
        e.category(),
        FailureCategory::Integrity,
        "not an integrity failure"
    );
    let code = e.code();
    assert!(
        [
            codes::PLAN_SIGNATURE_INVALID,
            codes::PLAN_NONCE_MISMATCH,
            codes::PLAN_BINDING_MISMATCH,
            codes::CONTENT_MANIFEST_MISMATCH,
        ]
        .contains(&code),
        "reason code"
    );
    let _ = e.to_string();
    match (&e, &parsed) {
        (PlanError::Plan(_), Some(_)) => panic!("valid plan payload refused: {e}"),
        (PlanError::Plan(_), None) => {}
        (_, None) => panic!("invalid plan payload got past check 2: {e}"),
        (PlanError::NonceMismatch, Some(p)) => assert_ne!(p.agent_nonce, nonce),
        (PlanError::SessionMismatch, Some(p)) => {
            assert_eq!(p.agent_nonce, nonce);
            assert_ne!(p.session_id, session);
        }
        (PlanError::JobMismatch, Some(p)) => assert_ne!(p.job_id, job),
        (PlanError::PackageMismatch, Some(p)) => {
            assert!(p.package.id != package || p.package.revision != revision);
        }
        (PlanError::DiskMismatch, Some(p)) => assert!(!p.disk.matches(&disk)),
        (_, Some(p)) => {
            // Check 6: bindings 3 to 5 held.
            assert_eq!(p.agent_nonce, nonce, "content checked before the nonce");
            assert!(p.disk.matches(&disk), "content checked before the disk");
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    if sel % 2 == 0 {
        payload(rest);
    } else if let Some((&mode, body)) = rest.split_first() {
        verify(mode, body);
    }
});
