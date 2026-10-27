//! Integrity on every use (REQ-IMG-050, REQ-PE-008; decision 0011).

use std::os::unix::fs::PermissionsExt;

use usgp_proto::{ContentManifestV1, ContentState, SignedEnvelopeV1};

use crate::common::{Harness, Pinned, Who};

const MIB: usize = 1024 * 1024;

/// A 9 MiB "image" (two chunks).
fn big(tag: u8) -> Vec<u8> {
    let mut v = format!("FAKEWIM:1:{tag}:").into_bytes();
    v.resize(9 * MIB, tag);
    v
}

fn tamper(h: &Harness, sha: &usgp_common::Sha256Digest, at: usize) {
    let p = h.api.files().object_path(sha);
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut b = std::fs::read(&p).unwrap();
    b[at] ^= 0xff;
    std::fs::write(&p, b).unwrap();
}

#[tokio::test]
async fn download_verified_and_manifest_signed() {
    let h = Harness::start().await;
    let data = big(1);
    let id = h.ready("image", "Big", &data, None).await;
    let r = h.get(Who::Admin, &format!("/v1/content/{id}")).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body, data);
    let sha = usgp_crypto::sha256(&data);
    assert_eq!(
        r.header("etag").unwrap(),
        format!("\"sha256:{}\"", sha.to_hex())
    );
    assert_eq!(r.header("content-length").unwrap(), data.len().to_string());
    let m = h
        .get(Who::Admin, &format!("/v1/images/{id}/manifest"))
        .await;
    let env = SignedEnvelopeV1::from_json(&m.body).unwrap();
    let v = env
        .verified_payload(
            usgp_proto::PayloadType::ContentManifestV1,
            &Pinned(h.content_pub.clone()),
        )
        .unwrap();
    let man = ContentManifestV1::from_payload(v.bytes).unwrap();
    assert_eq!(man.sha256, sha);
    assert_eq!(man.chunk_sha256.len(), 2);
    assert_eq!(man.chunk_sha256[1], usgp_crypto::sha256(&data[8 * MIB..]));
    let done = h.wait_events("content.download.completed", 1).await;
    assert!(
        done[0]
            .detail
            .contains(&format!("\"bytes_sent\":\"{}\"", data.len()))
    );
}

/// A changed byte in the first chunk: 500 before any byte is sent; the
/// content becomes Failed and its Ready packages not usable.
#[tokio::test]
async fn tamper_first_chunk_500_marked_failed_package_not_usable() {
    let h = Harness::start().await;
    let (pkg, image, _pe) = h.ready_package("tamper").await;
    let c = h.wait_settled(image).await;
    tamper(&h, &c.sha256, 3);
    let r = h.get(Who::Admin, &format!("/v1/content/{image}")).await;
    assert_eq!(r.status, 500);
    assert_eq!(r.code(), "integrity_failed");
    let c = h.wait_settled(image).await;
    assert_eq!(c.state, ContentState::Failed);
    assert_eq!(c.reason.unwrap().code, "integrity_failed_on_use");
    let p = h
        .get(Who::Admin, &format!("/v1/packages/{pkg}"))
        .await
        .json();
    assert_eq!(p["status"], "not_usable");
    assert_eq!(p["status_reason"]["code"], "not_ready_content:image");
    assert_eq!(h.events("content.integrity.failed").len(), 1);
    let changed = h.events("package.status.changed");
    assert_eq!(changed.len(), 1);
    assert_eq!(
        changed[0].initiating_seq,
        Some(h.events("content.integrity.failed")[0].seq)
    );
}

/// A changed byte in the second chunk: the first chunk is sent, then the
/// stream is cut (the client never receives the bad chunk); the content
/// becomes Failed.
#[tokio::test]
async fn tamper_later_chunk_stream_aborted_marked_failed() {
    let h = Harness::start().await;
    let data = big(2);
    let id = h.ready("image", "Big2", &data, None).await;
    let sha = usgp_crypto::sha256(&data);
    tamper(&h, &sha, 8 * MIB + 10);
    let r = h.get(Who::Admin, &format!("/v1/content/{id}")).await;
    assert_eq!(r.status, 200);
    assert_ne!(
        r.body, data,
        "the tampered chunk must not be delivered whole"
    );
    assert!(r.body.len() < data.len() || r.body == b"<aborted>");
    let aborted = h.wait_events("content.download.aborted", 1).await;
    assert!(aborted[0].reason.as_deref().unwrap().contains("chunk 1"));
    let c = h.wait_settled(id).await;
    assert_eq!(c.state, ContentState::Failed);
}

/// A manifest that no trusted key signed (here: a server whose trusted
/// content key is not the one that signed the stored manifests) is not
/// relied on: the content is not served and is marked failed.
#[tokio::test]
async fn bad_manifest_signature_refused() {
    let h = Harness::start().await;
    let id = h.ready("image", "Sig", b"FAKEWIM:1:sig", None).await;
    let other = usgp_crypto::SigningKey::generate().unwrap();
    let pubk = other.verifying_key().clone();
    let addr = h
        .second_server(usgp_api::ContentKeys::new(other, vec![pubk]).unwrap())
        .await;
    let admin = h.cert(Who::Admin);
    let m = h
        .req_at(
            addr,
            admin,
            "GET",
            &format!("/v1/images/{id}/manifest"),
            &[],
            None,
        )
        .await;
    assert_eq!(m.status, 500);
    assert_eq!(m.code(), "integrity_failed");
    let c = h.wait_settled(id).await;
    assert_eq!(c.state, ContentState::Failed);
    let r = h
        .req_at(addr, admin, "GET", &format!("/v1/content/{id}"), &[], None)
        .await;
    assert_eq!(r.status, 409, "a failed item is not served");
}

/// An object whose length differs from the signed size is not served.
#[tokio::test]
async fn truncated_object_refused() {
    let h = Harness::start().await;
    let data = b"FAKEWIM:1:trunc".to_vec();
    let id = h.ready("image", "Trunc", &data, None).await;
    let p = h.api.files().object_path(&usgp_crypto::sha256(&data));
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&p, &data[..data.len() - 1]).unwrap();
    let r = h.get(Who::Admin, &format!("/v1/content/{id}")).await;
    assert_eq!(r.status, 500);
    assert_eq!(r.code(), "integrity_failed");
    assert_eq!(h.wait_settled(id).await.state, ContentState::Failed);
}
