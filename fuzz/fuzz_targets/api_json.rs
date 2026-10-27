//! Fuzz target `api_json`: arbitrary bytes as a control-plane JSON body,
//! a signed envelope, a manifest payload or an `If-Match` value.
//!
//! Octet 0 selects the parser (modulo 9); the rest is the input:
//!
//! 0 `CreateUploadRequest`, 1 `PackageRequest`, 2
//! `EditionDeclarationRequest`, 3 `ClonePackageRequest`, 4
//! `PeDeclarationRequest` (each through `parse_request` and `validate`),
//! 5 `SignedEnvelopeV1::from_json`, 6 `ContentManifestV1::from_payload`,
//! 7 `PackageManifestV1::from_payload`, 8 `if_match_revision`.
//!
//! Invariants (plan WU-9, §10):
//!
//! - no panic; every error yields an error body without panicking, and a
//!   JSON parser detail is at most 200 characters;
//! - `parse_request` refuses with `body_too_large` exactly when the body
//!   is over the cap, before parsing; under a smaller cap it agrees with
//!   the default cap on every body that fits;
//! - an accepted request re-serializes and re-parses to itself; a request
//!   that validates turns back into a request that validates to the same
//!   value;
//! - an accepted envelope or manifest re-serializes and re-parses to
//!   itself (manifests: to the same canonical bytes);
//! - `if_match_revision` accepts only the exact strong tag `"r<n>"` that
//!   `package_etag(n)` would write.

#![no_main]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), SA-11 (Developer
//   Testing and Evaluation)
// - SPEC: specs/operator-access.md (request validation), specs/os-images.md
//   (content manifest), decision 0013 (declarations)
// - RFC 8259 - JSON; RFC 9110 §8.8.3, §13.1.1 - entity tags, If-Match

use std::fmt::Debug;

use libfuzzer_sys::fuzz_target;
use serde::Serialize;
use serde::de::DeserializeOwned;
use usgp_proto::api::{
    ClonePackageRequest, CreateUploadRequest, EditionDeclarationRequest, FieldError,
    PackageRequest, PeDeclarationRequest, RequestError, if_match_revision, package_etag,
    parse_request,
};
use usgp_proto::envelope::SignedEnvelopeV1;
use usgp_proto::limits::DEFAULT_MAX_JSON_BYTES;
use usgp_proto::{ContentManifestV1, PackageManifestV1, codes};

const SMALL_CAP: usize = 256;

/// A request type with its validated form and the way back.
trait Req: DeserializeOwned + Serialize + PartialEq + Debug {
    type Valid: PartialEq + Debug;
    fn check(&self) -> Result<Self::Valid, FieldError>;
    fn back(v: &Self::Valid) -> Self;
}

macro_rules! req {
    ($t:ty, $v:ty) => {
        impl Req for $t {
            type Valid = $v;
            fn check(&self) -> Result<$v, FieldError> {
                self.validate()
            }
            fn back(v: &$v) -> Self {
                Self::from(v)
            }
        }
    };
}

req!(CreateUploadRequest, usgp_proto::api::CreateUpload);
req!(PackageRequest, usgp_proto::api::PackageSpec);
req!(
    EditionDeclarationRequest,
    usgp_proto::api::EditionDeclaration
);
req!(ClonePackageRequest, usgp_proto::DisplayName);
req!(PeDeclarationRequest, usgp_proto::api::PeDeclaration);

fn check_request_error(e: &RequestError, len: usize, cap: usize) {
    let _ = e.to_error_body();
    match e {
        RequestError::TooLarge { len: l, max } => {
            assert_eq!((*l, *max), (len, cap));
            assert!(len > cap, "too large under the cap");
            assert_eq!(e.code(), codes::BODY_TOO_LARGE);
        }
        RequestError::Json { detail } => {
            assert!(len <= cap, "parsed a body over the cap");
            assert!(detail.chars().count() <= 200, "detail over 200 chars");
            assert_eq!(e.code(), codes::INVALID_JSON);
        }
        _ => {}
    }
}

fn request<T: Req>(body: &[u8]) {
    let full = parse_request::<T>(body, DEFAULT_MAX_JSON_BYTES);
    let small = parse_request::<T>(body, SMALL_CAP);
    if let Err(e) = &small {
        check_request_error(e, body.len(), SMALL_CAP);
    }
    if body.len() <= SMALL_CAP {
        assert_eq!(full, small, "caps disagree on a body that fits both");
    }
    let req = match full {
        Ok(r) => r,
        Err(e) => {
            check_request_error(&e, body.len(), DEFAULT_MAX_JSON_BYTES);
            return;
        }
    };
    // Wire round trip.
    let json = serde_json::to_vec(&req).expect("request serializes");
    let again = parse_request::<T>(&json, usize::MAX).expect("own JSON re-parses");
    assert_eq!(again, req, "request does not round-trip");
    match req.check() {
        Ok(v) => {
            let back = T::back(&v);
            assert_eq!(back.check().as_ref(), Ok(&v), "validated form unstable");
            let json = serde_json::to_vec(&back).expect("request serializes");
            let again = parse_request::<T>(&json, usize::MAX).expect("own JSON re-parses");
            assert_eq!(again.check().as_ref(), Ok(&v), "validated form unstable");
        }
        Err(fe) => {
            let _ = fe.to_error_body();
            assert!(!fe.message.is_empty(), "empty field message");
        }
    }
}

fn envelope(body: &[u8]) {
    if let Ok(env) = SignedEnvelopeV1::from_json(body) {
        let n = env.signatures().len();
        assert!((1..=8).contains(&n), "{n} signatures accepted");
        for s in env.signatures() {
            assert!((1..=512).contains(&s.sig().len()), "signature size");
        }
        let json = env.to_json().expect("envelope serializes");
        let again = SignedEnvelopeV1::from_json(&json).expect("own JSON re-parses");
        assert!(again == env, "envelope does not round-trip");
    }
}

fn content_manifest(body: &[u8]) {
    if let Ok(m) = ContentManifestV1::from_payload(body) {
        let p = m.to_payload().expect("manifest serializes");
        let again = ContentManifestV1::from_payload(&p).expect("own payload re-parses");
        assert_eq!(again, m, "manifest does not round-trip");
        assert_eq!(again.to_payload().ok(), Some(p), "payload not canonical");
    }
}

fn package_manifest(body: &[u8]) {
    if let Ok(m) = PackageManifestV1::from_payload(body) {
        let p = m.to_payload().expect("manifest serializes");
        let again = PackageManifestV1::from_payload(&p).expect("own payload re-parses");
        assert_eq!(again, m, "manifest does not round-trip");
        assert_eq!(again.to_payload().ok(), Some(p), "payload not canonical");
    }
}

fn if_match(value: &[u8]) {
    if let Some(r) = if_match_revision(value) {
        assert_eq!(package_etag(r).as_bytes(), value, "non-canonical If-Match");
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, body)) = data.split_first() else {
        return;
    };
    match sel % 9 {
        0 => request::<CreateUploadRequest>(body),
        1 => request::<PackageRequest>(body),
        2 => request::<EditionDeclarationRequest>(body),
        3 => request::<ClonePackageRequest>(body),
        4 => request::<PeDeclarationRequest>(body),
        5 => envelope(body),
        6 => content_manifest(body),
        7 => package_manifest(body),
        _ => if_match(body),
    }
});
