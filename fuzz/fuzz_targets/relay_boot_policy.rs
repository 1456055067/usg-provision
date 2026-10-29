//! Fuzz target `relay_boot_policy`: sequences of signed boot-policy lists
//! and arbitrary envelope bytes fed to the relay's
//! `BootPolicyFeed::apply_bytes` (`usgp-relay` `feed`), as pulled from the
//! server or read from the cache file.
//!
//! A real signature cannot be found by mutation, so the target signs a
//! fixed set of lists once per process (`usgp-crypto` ECDSA P-384 with a
//! key generated at start-up; the TLS client the feed holds is built from
//! `usgp-crypto`'s test PKI and is never used: no socket is opened, and no
//! cache file is configured). The input is a script over that set:
//!
//! ```text
//! op < 0xC0         apply list (op & 0x3F) % N; bit 6 set: as read from
//!                   the cache file
//! 0xC0 <= op < 0xE0 apply list (op & 0x1F) % N with one bit flipped: the
//!                   octet at the offset in the next 2 octets (u16 BE,
//!                   modulo its length), bit (low octet & 7)
//! op >= 0xE0        apply the next k octets as envelope bytes (k = the
//!                   next octet)
//! ```
//!
//! Invariants (M3 plan §3.6; decision 0021; impl-notes-wu11 "WU-14"):
//!
//! - no panic; before any list is applied the gate is `Awaiting` (fail
//!   closed);
//! - every result equals a reference model of the documented order:
//!   envelope shape, then the pinned-key signature and payload type, then
//!   the payload's shape and `key_id`, then the boot service, then
//!   rollback (a lower generation), then a reused generation (same
//!   generation, other content); otherwise the list is applied, or is
//!   `Unchanged` if it is the list in effect;
//! - the gate always holds exactly the model's list: generation, payload
//!   SHA-256, boot service, and the stopped MACs with their jobs;
//! - a refused list never changes the gate; a changed octet never applies
//!   anything other than the original list would.

#![no_main]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7(6) (Cryptographic Protection), SC-23 (rollback and
//   reuse refused), SI-17 (Fail-Safe Procedures: last good list kept),
//   SI-10, SA-11
// - SPEC: specs/boot-network.md#REQ-BOOT-067
// - DECISION: docs/decisions/0021 items 2 and 3

use std::path::PathBuf;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use usgp_crypto::test_pki::TestPki;
use usgp_crypto::tls::{ClientTls, TlsMinVersion};
use usgp_crypto::{Sha256Digest, SigningKey, sign_typed};
use usgp_dhcp::MacAddr;
use usgp_proto::device::MacAddress;
use usgp_proto::envelope::{PayloadType, SignatureAlg, SignatureV1, SignedEnvelopeV1};
use usgp_proto::ids::{BootServiceId, JobId, UnixMicros};
use usgp_proto::{BootPolicyV1, BootStopEntryV1};
use usgp_relay::config::{FeedUrl, ServerFeedConfig};
use usgp_relay::feed::{Applied, BootPolicyFeed, FeedMaterial, PinnedPolicyKey, Rejection, Source};
use usgp_relay::suppress::{FeedGate, Suppression};

const MACS: [[u8; 6]; 3] = [
    [0x52, 0x54, 0x00, 0x00, 0x0a, 0x01],
    [0x52, 0x54, 0x00, 0x00, 0x0a, 0x02],
    [0x52, 0x54, 0x00, 0x00, 0x0a, 0x03],
];

/// What the model expects of one list.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Signed by the pinned key, valid, for this relay's service.
    Good,
    /// Not signed by the pinned key, or the wrong payload type.
    BadSignature,
    /// Signed, but the payload is not a valid list for its key.
    Invalid,
    /// Signed and valid, for another boot service.
    OtherService,
}

struct List {
    json: Vec<u8>,
    kind: Kind,
    generation: u64,
    digest: Sha256Digest,
    /// Stopped MACs (indexes into `MACS`) and their job byte.
    stops: Vec<(usize, u8)>,
}

struct Fixture {
    cfg: ServerFeedConfig,
    material: FeedMaterial,
    service: BootServiceId,
    lists: Vec<List>,
}

fn job(n: u8) -> JobId {
    JobId::from_random_bytes([n; 16])
}

/// The envelope JSON of `payload`, typed `ty`, signed by `key` as a
/// document of type `sig_ty`.
fn seal(key: &SigningKey, ty: PayloadType, payload: Vec<u8>, sig_ty: PayloadType) -> Vec<u8> {
    let sig = sign_typed(key, sig_ty.as_str(), &payload).expect("sign");
    let s = SignatureV1::new(key.key_id().0, SignatureAlg::EcdsaP384Sha384, sig).expect("sig");
    SignedEnvelopeV1::new(ty, payload, vec![s])
        .expect("envelope")
        .to_json()
        .expect("json")
}

fn fixture() -> Fixture {
    let pki = TestPki::generate().expect("test PKI");
    let key = SigningKey::generate().expect("policy key");
    let other_key = SigningKey::generate().expect("other key");
    let service = BootServiceId::from_random_bytes([0x6f; 16]);
    let other_service = BootServiceId::from_random_bytes([0x11; 16]);
    let tls = ClientTls::new(
        &pki.client_settings(Some(&pki.client), TlsMinVersion::Tls12)
            .expect("client settings"),
    )
    .expect("client TLS");
    let material = FeedMaterial {
        tls,
        key: PinnedPolicyKey::new(key.verifying_key().clone()),
    };
    let cfg = ServerFeedConfig {
        url: FeedUrl::parse("https://127.0.0.1:9").expect("url"),
        server_name: "localhost".to_owned(),
        trust_anchors: PathBuf::from("unused-ca.pem"),
        client_cert: PathBuf::from("unused-relay.pem"),
        client_key: PathBuf::from("unused-relay.key"),
        boot_policy_key_pub: PathBuf::from("unused-policy.pub.pem"),
        boot_service_id: service,
        poll_interval: Duration::from_secs(30),
        cache_file: None,
    };
    let policy =
        |svc: BootServiceId, generation: u64, stops: &[(usize, u8)], k: &SigningKey| BootPolicyV1 {
            schema: 1,
            boot_service_id: svc,
            generation,
            issued_at_us: UnixMicros::new(1_793_000_000_000_000).expect("time"),
            key_id: k.key_id().0,
            stops: stops
                .iter()
                .map(|&(m, j)| BootStopEntryV1 {
                    mac: MacAddress::new(MACS[m]).expect("mac"),
                    job_id: job(j),
                })
                .collect(),
        };
    let ty = PayloadType::BootPolicyV1;
    let mut lists = Vec::new();
    let mut add = |kind: Kind, p: BootPolicyV1, k: &SigningKey, raw: bool, sig_ty: PayloadType| {
        let payload = if raw {
            serde_json::to_vec(&p).expect("payload")
        } else {
            p.to_payload().expect("payload")
        };
        let digest = usgp_crypto::sha256(&payload);
        lists.push(List {
            json: seal(k, sig_ty, payload, sig_ty),
            kind,
            generation: p.generation,
            digest,
            stops: p
                .stops
                .iter()
                .map(|s| {
                    let m = MACS.iter().position(|x| x == s.mac.octets()).unwrap_or(0);
                    let j = (0u8..=255).find(|&j| job(j) == s.job_id).unwrap_or(0);
                    (m, j)
                })
                .collect(),
        });
    };
    let good = |g, s: &[(usize, u8)]| policy(service, g, s, &key);
    add(Kind::Good, good(1, &[(0, 1)]), &key, false, ty);
    add(Kind::Good, good(1, &[(1, 2)]), &key, false, ty);
    add(Kind::Good, good(2, &[(0, 3), (1, 4)]), &key, false, ty);
    add(Kind::Good, good(3, &[]), &key, false, ty);
    add(Kind::Good, good(2, &[(2, 5)]), &key, false, ty);
    add(
        Kind::Good,
        good(10, &[(0, 6), (1, 7), (2, 8)]),
        &key,
        false,
        ty,
    );
    add(
        Kind::OtherService,
        policy(other_service, 7, &[(0, 9)], &key),
        &key,
        false,
        ty,
    );
    add(
        Kind::BadSignature,
        policy(service, 4, &[(0, 10)], &other_key),
        &other_key,
        false,
        ty,
    );
    add(
        Kind::BadSignature,
        good(5, &[(1, 11)]),
        &key,
        false,
        PayloadType::ContentManifestV1,
    );
    let mut schema2 = good(6, &[]);
    schema2.schema = 2;
    add(Kind::Invalid, schema2, &key, true, ty);
    // Signed by the pinned key, but the payload names another key.
    add(
        Kind::Invalid,
        policy(service, 8, &[], &other_key),
        &key,
        false,
        ty,
    );
    let mut dup = good(9, &[(0, 12)]);
    dup.stops.push(BootStopEntryV1 {
        mac: MacAddress::new(MACS[0]).expect("mac"),
        job_id: job(13),
    });
    add(Kind::Invalid, dup, &key, true, ty);
    Fixture {
        cfg,
        material,
        service,
        lists,
    }
}

static FIXTURE: LazyLock<Fixture> = LazyLock::new(fixture);

/// The list in effect, per the model.
type State = Option<usize>;

fn expected(f: &Fixture, state: State, i: usize) -> Result<Applied, &'static str> {
    let l = &f.lists[i];
    match l.kind {
        Kind::BadSignature => return Err("signature"),
        Kind::Invalid => return Err("invalid"),
        Kind::OtherService => return Err("wrong_boot_service"),
        Kind::Good => {}
    }
    match state.map(|s| &f.lists[s]) {
        Some(cur) if l.generation < cur.generation => Err("rollback"),
        Some(cur) if l.generation == cur.generation => {
            if l.digest == cur.digest {
                Ok(Applied::Unchanged)
            } else {
                Err("generation_reused")
            }
        }
        _ => Ok(Applied::New {
            generation: l.generation,
        }),
    }
}

fn check_gate(f: &Fixture, feed: &BootPolicyFeed, state: State) {
    match (feed.gate(), state) {
        (FeedGate::Awaiting, None) => {}
        (FeedGate::Applied(stops), Some(s)) => {
            let l = &f.lists[s];
            assert_eq!(stops.generation(), l.generation, "generation in effect");
            assert_eq!(stops.payload_sha256(), l.digest, "list in effect");
            assert_eq!(stops.boot_service_id(), f.service, "boot service");
            assert_eq!(stops.len(), l.stops.len(), "stop count");
            for (m, mac) in MACS.iter().enumerate() {
                let want = l.stops.iter().find(|(x, _)| *x == m).map(|(_, j)| job(*j));
                let mac = MacAddr::new(*mac).expect("mac");
                assert_eq!(stops.job_for(mac), want, "stop for a MAC");
            }
        }
        (g, s) => panic!("gate {} but model {:?}", g.label(), s),
    }
}

fn label(r: &Result<Applied, Rejection>) -> Result<Applied, &'static str> {
    match r {
        Ok(a) => Ok(*a),
        Err(e) => Err(e.label()),
    }
}

fuzz_target!(|script: &[u8]| {
    let f = &*FIXTURE;
    let suppression = Arc::new(Suppression::disabled());
    let feed = BootPolicyFeed::new(f.cfg.clone(), f.material.clone(), Arc::clone(&suppression));
    let mut state: State = None;
    check_gate(f, &feed, state);
    let n = f.lists.len();
    let mut ops = script.iter();
    for _ in 0..32 {
        let Some(&op) = ops.next() else { break };
        if op < 0xC0 {
            let i = usize::from(op & 0x3F) % n;
            let source = if op & 0x40 != 0 {
                Source::Cache
            } else {
                Source::Server
            };
            let r = feed.apply_bytes(&f.lists[i].json, source);
            let want = expected(f, state, i);
            assert_eq!(label(&r), want, "list {i}");
            if matches!(want, Ok(Applied::New { .. })) {
                state = Some(i);
            }
        } else if op < 0xE0 {
            let i = usize::from(op & 0x1F) % n;
            let (Some(&hi), Some(&lo)) = (ops.next(), ops.next()) else {
                break;
            };
            let mut json = f.lists[i].json.clone();
            let at = usize::from(u16::from_be_bytes([hi, lo])) % json.len();
            json[at] ^= 1 << (lo & 7);
            let r = feed.apply_bytes(&json, Source::Server);
            if r.is_ok() {
                // Only an equivalent encoding of the same list can apply.
                let want = expected(f, state, i);
                assert_eq!(label(&r), want, "changed list {i} applied differently");
                if matches!(want, Ok(Applied::New { .. })) {
                    state = Some(i);
                }
            }
        } else {
            let Some(&k) = ops.next() else { break };
            let raw: Vec<u8> = ops.by_ref().take(usize::from(k)).copied().collect();
            let r = feed.apply_bytes(&raw, Source::Server);
            assert!(r.is_err(), "unsigned bytes applied");
        }
        check_gate(f, &feed, state);
    }
});
