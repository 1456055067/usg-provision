//! Fuzz target `postsetup_msgs`: the bodies of the post-restart protocol
//! (resume, escrow, v2 progress) as the device listener parses them
//! (`parse_request` with `MAX_DEVICE_JSON_BYTES`), and `job.json`
//! (`usgp-proto` `resume`, `escrow`, `progress`, `postsetup`).
//!
//! Octet 0 selects (modulo 8); the rest is the input: 0
//! `ResumeChallengeV1`, 1 `ResumeRequestV1`, 2 `ResumedV1`, 3
//! `EscrowSubmitV1`, 4 `EscrowConfirmV1`, 5 `ProgressV2`, 6 `FailureV2`,
//! 7 `PostSetupConfigV1::from_json`.
//!
//! Invariants:
//!
//! - no panic; `body_too_large` exactly over the cap, before parsing; a
//!   parser detail is at most 200 characters;
//! - every accepted body re-serializes and re-parses to itself
//!   (`ResumedV1`, which holds a token and has no `PartialEq`, to the
//!   same JSON), and `job.json` round-trips through `to_json`;
//! - the resumed token is never shown by `Debug`;
//! - escrow: the ephemeral key is a 97-octet uncompressed point, the
//!   nonce 12 octets, the ciphertext 17 to 512 octets; a confirm has a
//!   code exactly when `set` is false;
//! - progress v2: schema 2, `seq` from 1, `bytes_done` within
//!   `bytes_total`, `succeeded` only on step 9, `restart_pending` only on
//!   step 8 `step_completed`, a failure exactly on `failed` and for the
//!   same step, attempts 1 or more;
//! - `job.json`: validates, and its plan is a v2 job plan envelope.

#![no_main]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), IA-5 (tokens never
//   shown), SC-8, SA-11
// - SPEC: specs/workflow.md#REQ-SEQ-002, #REQ-SEQ-006, #REQ-SEQ-007
// - SPEC: specs/agent-handoff.md; specs/configuration.md (escrow)
// - RFC 8259 (JSON); RFC 4648 §4 (base64); SEC 1 §2.3.3 (point form)

use std::fmt::Debug;

use libfuzzer_sys::fuzz_target;
use serde::Serialize;
use serde::de::DeserializeOwned;
use usgp_proto::api::{RequestError, parse_request};
use usgp_proto::envelope::PayloadType;
use usgp_proto::limits::{MAX_DEVICE_JSON_BYTES, MAX_ESCROW_CT_BYTES};
use usgp_proto::postsetup::PostSetupConfigError;
use usgp_proto::{
    EscrowConfirmV1, EscrowSubmitV1, FailureV2, PostSetupConfigV1, ProgressEvent, ProgressV2,
    ResumeChallengeV1, ResumeRequestV1, ResumedV1, StepV2,
};

fn check_error(e: &RequestError, len: usize) {
    let _ = e.to_error_body();
    match e {
        RequestError::TooLarge { len: l, max } => {
            assert_eq!((*l, *max), (len, MAX_DEVICE_JSON_BYTES));
            assert!(len > MAX_DEVICE_JSON_BYTES, "too large under the cap");
        }
        RequestError::Json { detail } => {
            assert!(len <= MAX_DEVICE_JSON_BYTES, "parsed a body over the cap");
            assert!(detail.chars().count() <= 200, "detail over 200 chars");
        }
        _ => {}
    }
}

fn body<T: DeserializeOwned + Serialize + PartialEq + Debug>(b: &[u8]) -> Option<T> {
    match parse_request::<T>(b, MAX_DEVICE_JSON_BYTES) {
        Ok(v) => {
            let json = serde_json::to_vec(&v).expect("body serializes");
            let again: T = parse_request(&json, usize::MAX).expect("own JSON re-parses");
            assert_eq!(again, v, "body does not round-trip");
            Some(v)
        }
        Err(e) => {
            check_error(&e, b.len());
            None
        }
    }
}

fn failure(f: &FailureV2) {
    f.validate().expect("accepted failure validates");
    assert!(f.attempts >= 1);
    assert!(f.count as usize >= f.files.len(), "count below files");
}

fn progress(p: &ProgressV2) {
    assert_eq!(p.schema, 2);
    assert!(p.seq >= 1);
    if let (Some(d), Some(t)) = (p.bytes_done, p.bytes_total) {
        assert!(d <= t, "bytes_done over bytes_total");
    }
    if p.event == ProgressEvent::Succeeded {
        assert_eq!(p.step, StepV2::LAST, "succeeded before step 9");
    }
    if p.restart_pending.is_some() {
        assert_eq!(p.step, StepV2::INSTALL_AGENT);
        assert_eq!(p.event, ProgressEvent::StepCompleted);
    }
    match (&p.failure, p.event == ProgressEvent::Failed) {
        (Some(f), true) => {
            assert_eq!(f.step, p.step, "failure for another step");
            failure(f);
        }
        (None, false) => {}
        _ => panic!("failure without failed, or failed without failure"),
    }
}

fn resumed(b: &[u8]) {
    match parse_request::<ResumedV1>(b, MAX_DEVICE_JSON_BYTES) {
        Ok(v) => {
            let token = v.token.expose().to_owned();
            assert!(!format!("{v:?}").contains(&token), "token shown by Debug");
            let json = serde_json::to_vec(&v).expect("body serializes");
            let again: ResumedV1 = parse_request(&json, usize::MAX).expect("own JSON re-parses");
            assert_eq!(serde_json::to_vec(&again).ok(), Some(json), "not stable");
        }
        Err(e) => check_error(&e, b.len()),
    }
}

fn job_json(b: &[u8]) {
    match PostSetupConfigV1::from_json(b) {
        Ok(c) => {
            c.validate().expect("accepted job.json validates");
            assert_eq!(c.plan.payload_type(), PayloadType::JobPlanV2);
            let out = c.to_json().expect("accepted job.json re-encodes");
            let again = PostSetupConfigV1::from_json(&out).expect("own job.json parses");
            assert_eq!(again, c, "job.json does not round-trip");
        }
        Err(PostSetupConfigError::TooLarge { len }) => assert_eq!(len, b.len()),
        Err(e) => {
            let _ = e.to_string();
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    match sel % 8 {
        0 => {
            body::<ResumeChallengeV1>(rest);
        }
        1 => {
            body::<ResumeRequestV1>(rest);
        }
        2 => resumed(rest),
        3 => {
            if let Some(s) = body::<EscrowSubmitV1>(rest) {
                assert_eq!(s.eph_pub_b64.as_bytes().len(), 97);
                assert_eq!(s.eph_pub_b64.as_bytes().first(), Some(&0x04));
                assert_eq!(s.nonce_b64.as_bytes().len(), 12);
                let n = s.ct_b64.as_bytes().len();
                assert!((17..=MAX_ESCROW_CT_BYTES).contains(&n), "ciphertext length");
            }
        }
        4 => {
            if let Some(c) = body::<EscrowConfirmV1>(rest) {
                assert_ne!(
                    c.set,
                    c.code.is_some(),
                    "code must come with set false only"
                );
            }
        }
        5 => {
            if let Some(p) = body::<ProgressV2>(rest) {
                progress(&p);
            }
        }
        6 => {
            if let Some(f) = body::<FailureV2>(rest) {
                failure(&f);
            }
        }
        _ => job_json(rest),
    }
});
