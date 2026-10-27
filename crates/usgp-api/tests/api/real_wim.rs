//! End to end through the production `WimChecker` with builder-made WIMs
//! (usgp-image `testkit`): upload → check → editions → declaration →
//! package Ready → signed manifests → verified download; and LZX-flagged
//! and split files refused with their reason codes (REQ-IMG-030, -037,
//! -038, -040, -042, -043, -050; REQ-PE-002, -004; decisions 0013, 0014).

use std::sync::Arc;

use usgp_api::WimChecker;
use usgp_image::Compression;
use usgp_image::testkit::builder::WimBuilder;
use usgp_proto::{
    ContentManifestV1, ContentState, PackageManifestV1, PayloadType, SignedEnvelopeV1,
};

use crate::common::{Harness, Opts, Pinned, Who};

async fn real() -> Harness {
    Harness::with(Opts {
        checker: Some(Arc::new(WimChecker::new(usgp_image::WimLimits::DEFAULT))),
        ..Opts::default()
    })
    .await
}

fn image(c: Compression, n: u32, integrity: bool) -> Vec<u8> {
    let mut b = WimBuilder::new(c).integrity(integrity);
    for i in 1..=n {
        b = b.image(&format!("Windows Test {i}"), &format!("Edition number {i}"));
    }
    b.build().unwrap().0
}

fn pe() -> Vec<u8> {
    WimBuilder::new(Compression::Xpress)
        .image("Microsoft Windows PE (amd64)", "PE")
        .boot_index(1)
        .build()
        .unwrap()
        .0
}

async fn full_flow(h: &Harness, compression: Compression, tag: &str, integrity: bool) {
    let data = image(compression, 4, integrity);
    let id = h.ready("image", &format!("Image {tag}"), &data, None).await;
    let v = h.get(Who::Admin, &format!("/v1/images/{id}")).await.json();
    assert_eq!(v["image_count"], 4);
    assert_eq!(v["compression"], compression.as_str());
    let eds = v["editions"].as_array().unwrap();
    assert_eq!(eds.len(), 4);
    assert_eq!(eds[2]["name"], "Windows Test 3");
    assert_eq!(eds[2]["description"], "Edition number 3");

    let pe_data = pe();
    let pe_id = h
        .ready(
            "pe",
            &format!("PE {tag}"),
            &pe_data,
            Some(("x64", "10.1.26100.1")),
        )
        .await;
    assert_eq!(
        h.get(Who::Admin, &format!("/v1/pe/{pe_id}")).await.json()["usable_index"],
        1
    );

    let r = h.declare(id, 2, "windows-11", "enterprise", "x64").await;
    assert_eq!(r.status, 200);
    // M2: no documented XML fact, so every fact is `declared`.
    assert_eq!(r.json()["facts"]["architecture"]["source"], "declared");
    let r = h.create_package(&format!("Pkg {tag}"), id, 2, pe_id).await;
    assert_eq!(r.status, 201, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["status"], "ready");
    let pkg = r.json()["id"].as_str().unwrap().to_owned();

    let pin = Pinned(h.content_pub.clone());
    let env = SignedEnvelopeV1::from_json(
        &h.get(Who::Admin, &format!("/v1/packages/{pkg}/manifest"))
            .await
            .body,
    )
    .unwrap();
    let pm = PackageManifestV1::open(&env, &pin).unwrap();
    assert_eq!(pm.image.content_sha256, usgp_crypto::sha256(&data));
    assert_eq!(pm.pe.content_sha256, usgp_crypto::sha256(&pe_data));
    assert_eq!(pm.image.edition_name.as_str(), "Windows Test 2");

    for (path, cid, bytes) in [("images", id, &data), ("pe", pe_id, &pe_data)] {
        let env = SignedEnvelopeV1::from_json(
            &h.get(Who::Admin, &format!("/v1/{path}/{cid}/manifest"))
                .await
                .body,
        )
        .unwrap();
        let cm = ContentManifestV1::open(&env, &pin).unwrap();
        assert_eq!(cm.content_id, cid);
        assert_eq!(cm.sha256, usgp_crypto::sha256(bytes));
        assert_eq!(
            cm.wim.compression.as_str(),
            compression_of(path, compression)
        );
        assert!(
            env.verified_payload(PayloadType::ContentManifestV1, &pin)
                .is_ok()
        );
        // Verified download: same bytes, per-chunk digests as signed.
        let d = h.get(Who::Admin, &format!("/v1/content/{cid}")).await;
        assert_eq!(d.status, 200);
        assert_eq!(&d.body, bytes);
        for (i, chunk) in d.body.chunks(8 * 1024 * 1024).enumerate() {
            assert_eq!(cm.chunk_sha256[i], usgp_crypto::sha256(chunk));
        }
    }
}

fn compression_of(path: &str, image: Compression) -> &'static str {
    if path == "pe" {
        "xpress"
    } else {
        image.as_str()
    }
}

#[tokio::test]
async fn uncompressed_multi_edition_end_to_end() {
    let h = real().await;
    full_flow(&h, Compression::None, "none", false).await;
}

#[tokio::test]
async fn xpress_multi_edition_with_integrity_end_to_end() {
    let h = real().await;
    full_flow(&h, Compression::Xpress, "xpress", true).await;
}

/// LZX (decision 0014) and split parts (REQ-IMG-038) are refused by the
/// real check with their reason codes; nothing becomes Ready, staging is
/// removed, and the failure is audited.
#[tokio::test]
async fn lzx_and_split_refused_with_reason() {
    let h = real().await;
    let cases: Vec<(&str, Vec<u8>, &str)> = vec![
        (
            "LZX",
            WimBuilder::new(Compression::Xpress)
                .image("a", "b")
                .header_flags(0x0004_0082)
                .build()
                .unwrap()
                .0,
            "wim_lzx_not_supported",
        ),
        (
            "Split part 2",
            WimBuilder::new(Compression::Xpress)
                .image("a", "b")
                .header_flags(0x0002_008a)
                .part(2, 7)
                .build()
                .unwrap()
                .0,
            "wim_split_not_supported",
        ),
        (
            "Split part 1",
            WimBuilder::new(Compression::None)
                .image("a", "b")
                .part(1, 2)
                .build()
                .unwrap()
                .0,
            "wim_split_not_supported",
        ),
    ];
    for (name, data, code) in cases {
        let id = h.upload("image", name, &data, None).await;
        let c = h.wait_settled(id).await;
        assert_eq!(c.state, ContentState::Failed, "{name}");
        let v = h.get(Who::Admin, &format!("/v1/images/{id}")).await.json();
        assert_eq!(v["reason"]["code"], code, "{name}");
        assert!(v["editions"].as_array().unwrap().is_empty());
        assert!(
            h.events("content.failed")
                .iter()
                .any(|r| r.reason.as_deref() == Some(code)
                    && r.target_id.as_deref() == Some(id.to_string().as_str()))
        );
        assert_eq!(
            h.get(Who::Admin, &format!("/v1/content/{id}")).await.status,
            409
        );
    }
    assert!(h.api.files().list_staging().unwrap().is_empty());
}
