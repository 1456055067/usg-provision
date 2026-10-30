//! Fuzz target `content_manifest_v2`: a v2 content manifest payload, for a
//! driver archive or an agent package (`usgp-proto`
//! `ContentManifestV2::from_payload`, `open`).
//!
//! Invariants:
//!
//! - no panic; `TooLarge` exactly over `MAX_MANIFEST_PAYLOAD_BYTES`;
//! - an accepted manifest: schema 2; chunk size `CHUNK_SIZE`; as many
//!   chunk digests as `chunk_count(size)`, whose `chunk` lengths sum to
//!   `size`, with `chunk(n)` `None`; at least one entry; a driver archive
//!   lists 1 to 4,096 distinct `.inf` paths, an agent package none; never
//!   more INFs than entries;
//! - `to_payload` is canonical: it parses back to the same manifest and
//!   is stable;
//! - verify before parse: in an envelope, a refusing verifier always gives
//!   the envelope refusal, whatever the payload; an accepting verifier
//!   gives the payload's own result (or the key-id check).

#![no_main]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity),
//   SI-10 (Information Input Validation), SA-11
// - SPEC: specs/drivers.md#REQ-DRV-006, specs/agent-handoff.md#REQ-AGT-001,
//   specs/os-images.md#REQ-IMG-050, #REQ-IMG-052
// - RFC 8259 (JSON); FIPS 180-4 (SHA-256, digests only)

use libfuzzer_sys::fuzz_target;
use usgp_crypto::Sha256Digest;
use usgp_proto::content_manifest::{SCHEMA_V2, chunk_count};
use usgp_proto::envelope::{
    PayloadType, SignatureAlg, SignatureV1, SignatureVerifier, SignedEnvelopeV1,
};
use usgp_proto::limits::{CHUNK_SIZE, MAX_MANIFEST_PAYLOAD_BYTES};
use usgp_proto::status::ContentKindV2;
use usgp_proto::{ContentManifestV2, SignedManifestError};

/// A stand-in verifier (the ECDSA check is `usgp-crypto`'s, tested there).
struct Stub(bool);

impl SignatureVerifier for Stub {
    fn verify(&self, _: &Sha256Digest, _: SignatureAlg, _: &[u8], _: &[u8]) -> bool {
        self.0
    }
}

fn check(m: &ContentManifestV2) {
    assert_eq!(m.schema, SCHEMA_V2);
    assert_eq!(m.chunk_size, CHUNK_SIZE);
    let n = chunk_count(m.size);
    assert_eq!(m.chunk_sha256.len() as u64, n, "chunk digest count");
    let mut total = 0u64;
    for i in 0..n {
        let (len, _) = m.chunk(i).expect("chunk inside the file");
        assert!(len > 0 && len <= CHUNK_SIZE, "chunk length");
        total += len;
    }
    assert_eq!(total, m.size, "chunks do not cover the file");
    assert!(m.chunk(n).is_none(), "chunk past the end");
    let a = &m.archive;
    assert!(a.entries >= 1);
    assert!(
        a.infs.len() as u64 <= u64::from(a.entries),
        "more INFs than entries"
    );
    match m.kind {
        ContentKindV2::DriverArchive => assert!((1..=4096).contains(&a.infs.len())),
        ContentKindV2::AgentPackage => assert!(a.infs.is_empty()),
    }
    for (i, p) in a.infs.iter().enumerate() {
        assert!(p.has_extension(".inf"), "INF path without .inf");
        assert!(a.infs.iter().take(i).all(|o| o != p), "INF listed twice");
    }
}

fn envelope_checks(data: &[u8], direct: &Result<ContentManifestV2, SignedManifestError>) {
    let Ok(sig) = SignatureV1::new(
        Sha256Digest([7; 32]),
        SignatureAlg::EcdsaP384Sha384,
        vec![0x30; 8],
    ) else {
        return;
    };
    let Ok(env) = SignedEnvelopeV1::new(PayloadType::ContentManifestV2, data.to_vec(), vec![sig])
    else {
        return;
    };
    assert!(
        matches!(
            ContentManifestV2::open(&env, &Stub(false)),
            Err(SignedManifestError::Envelope(_))
        ),
        "parsed before the signature check"
    );
    match (ContentManifestV2::open(&env, &Stub(true)), direct) {
        (Ok(a), Ok(b)) => {
            assert_eq!(&a, b);
            assert_eq!(a.key_id, Sha256Digest([7; 32]));
        }
        (Err(SignedManifestError::KeyIdMismatch), Ok(b)) => {
            assert_ne!(b.key_id, Sha256Digest([7; 32]));
        }
        (Err(_), Err(_)) => {}
        (a, b) => panic!(
            "open and from_payload disagree: {:?} / {:?}",
            a.is_ok(),
            b.is_ok()
        ),
    }
}

fuzz_target!(|data: &[u8]| {
    let r = ContentManifestV2::from_payload(data);
    match &r {
        Ok(m) => {
            check(m);
            let p = m.to_payload().expect("accepted manifest re-encodes");
            let again = ContentManifestV2::from_payload(&p).expect("own payload parses");
            assert_eq!(&again, m, "manifest does not round-trip");
            assert_eq!(again.to_payload().ok(), Some(p), "payload not stable");
        }
        Err(SignedManifestError::TooLarge { len }) => {
            assert_eq!(*len, data.len());
            assert!(data.len() > MAX_MANIFEST_PAYLOAD_BYTES);
        }
        Err(_) => assert!(
            data.len() <= MAX_MANIFEST_PAYLOAD_BYTES,
            "parsed over the cap"
        ),
    }
    envelope_checks(data, &r);
});
