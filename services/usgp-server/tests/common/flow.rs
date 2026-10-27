//! The M2 exit-criterion-1 flow against a running server, shared by
//! `e2e_pg.rs` (small builder WIM) and `large_upload_pg.rs` (10.5 GiB
//! builder WIM): upload a multi-edition WIM, check it, list its
//! editions, declare one edition windows-11 / enterprise / x64, import an
//! x64 PE, create a **Ready** package, verify the signed package and
//! content manifests with the pinned content key, and re-download each
//! file with every chunk digest and the whole-file digest checked
//! (plan M2 sections 0 item 3, 3.2, 3.3, 5.7, 10).
//!
//! Every comparison is against digests the test computed itself from the
//! source, not against what the server reports.

use std::net::SocketAddr;
use std::time::Duration;

use usgp_crypto::VerifyingKey;
use usgp_proto::api::{EditionView, ImageList, ImageView, PackageView, PeView};
use usgp_proto::facts::{Architecture, Edition, FactSource, Release, SupportState};
use usgp_proto::limits::CHUNK_SIZE;
use usgp_proto::{
    ContentManifestV1, ContentState, PackageManifestV1, PackageStatus, SignedEnvelopeV1,
    WimCompression,
};

use super::pg::wait_state;
use super::stream::{self, Body, Digests, Pinned, view};
use super::{Fixture, https, json_str};

/// One file to upload, with the digests the test computed for it.
pub struct Source<'a> {
    /// The bytes or the file.
    pub body: Body<'a>,
    /// Its digests (computed by the test from the source).
    pub digests: Digests,
}

/// What the image is expected to contain.
pub struct Expect<'a> {
    /// Display name used for the upload.
    pub display_name: &'a str,
    /// Compression the check must report.
    pub compression: WimCompression,
    /// `(name, description)` of each edition, by index.
    pub editions: &'a [(String, String)],
    /// The edition to declare and package (1-based).
    pub chosen: u32,
    /// How long the check may take.
    pub ready_within: Duration,
}

/// Ids produced by the flow.
#[derive(Debug, Clone)]
pub struct FlowIds {
    /// Image content id.
    pub image: String,
    /// PE content id.
    pub pe: String,
    /// Package id.
    pub package: String,
}

/// `POST /v1/uploads`, then the body by `PUT`; returns the content id.
pub async fn upload(
    addr: SocketAddr,
    f: &Fixture,
    kind: &str,
    display_name: &str,
    src: &Source<'_>,
    pe_declaration: Option<(&str, &str)>,
) -> String {
    let pe = pe_declaration.map_or_else(String::new, |(arch, kit)| {
        format!(r#","pe_declaration":{{"architecture":"{arch}","kit_version":"{kit}"}}"#)
    });
    let create = format!(
        r#"{{"kind":"{kind}","display_name":"{display_name}","file_name":"{}.wim","size":{},"sha256":"{}"{pe}}}"#,
        display_name.to_ascii_lowercase().replace(' ', "-"),
        src.digests.size,
        src.digests.total.to_hex()
    );
    let r = https(
        addr,
        &f.pki,
        Some(&f.pki.client),
        "POST",
        "/v1/uploads",
        Some(&create),
    )
    .await
    .unwrap();
    assert_eq!(r.status, 201, "{}", r.body);
    let upload_id = json_str(&r.body, "upload_id").unwrap();
    let content_id = json_str(&r.body, "content_id").unwrap();
    let body = match &src.body {
        Body::File(p) => Body::File(p),
        Body::Bytes(b) => Body::Bytes(b),
    };
    let r = stream::put(
        addr,
        &f.pki,
        &f.pki.client,
        &format!("/v1/uploads/{upload_id}"),
        body,
    )
    .await
    .unwrap();
    assert_eq!(r.status, 202, "{}", r.text());
    content_id
}

/// Fetches and verifies a content manifest against the source digests.
async fn content_manifest(
    addr: SocketAddr,
    f: &Fixture,
    path: &str,
    id: &str,
    src: &Digests,
    pin: &Pinned,
) -> ContentManifestV1 {
    let r = stream::get(
        addr,
        &f.pki,
        &f.pki.client,
        &format!("/v1/{path}/{id}/manifest"),
    )
    .await
    .unwrap();
    assert_eq!(r.status, 200, "{}", r.text());
    let env = SignedEnvelopeV1::from_json(&r.body).unwrap();
    let cm = ContentManifestV1::open(&env, pin).unwrap();
    assert_eq!(cm.content_id.to_string(), id);
    assert_eq!(cm.size, src.size);
    assert_eq!(cm.sha256, src.total);
    assert_eq!(cm.chunk_size, CHUNK_SIZE);
    assert_eq!(cm.chunk_sha256, src.chunks, "signed chunk digests differ");
    cm
}

/// Downloads `id` and checks every chunk and the whole file against the
/// signed manifest and the source digests.
async fn verified_download(
    addr: SocketAddr,
    f: &Fixture,
    id: &str,
    cm: &ContentManifestV1,
    src: &Digests,
) {
    let d = stream::download_digests(addr, &f.pki, &f.pki.client, &format!("/v1/content/{id}"))
        .await
        .unwrap();
    assert_eq!(d.content_length, cm.size);
    assert_eq!(
        stream::header(&d.head, "etag"),
        Some(format!("\"sha256:{}\"", cm.sha256.to_hex()).as_str())
    );
    assert_eq!(d.digests.chunks.len(), cm.chunk_sha256.len());
    for (i, (got, signed)) in d.digests.chunks.iter().zip(&cm.chunk_sha256).enumerate() {
        assert_eq!(
            got, signed,
            "downloaded chunk {i} does not match its signed digest"
        );
    }
    assert_eq!(d.digests.total, cm.sha256, "downloaded file digest differs");
    assert_eq!(&d.digests, src);
}

/// The whole flow. `other_key` is a key that did not sign anything; the
/// manifests must not open with it.
pub async fn wim_to_ready_package(
    addr: SocketAddr,
    f: &Fixture,
    image: &Source<'_>,
    expect: &Expect<'_>,
    pe: &Source<'_>,
    other_key: &VerifyingKey,
) -> FlowIds {
    let pin = Pinned(f.content_pub.clone());
    let n = u32::try_from(expect.editions.len()).unwrap();

    // Upload and check the image; list its editions.
    let image_id = upload(addr, f, "image", expect.display_name, image, None).await;
    let r = wait_state(
        addr,
        f,
        &format!("/v1/images/{image_id}"),
        "ready",
        expect.ready_within,
    )
    .await;
    let v: ImageView = view(r.body.as_bytes());
    assert_eq!(v.state, ContentState::Ready);
    assert_eq!(v.size, image.digests.size);
    assert_eq!(v.sha256, Some(image.digests.total));
    assert_eq!(v.compression, Some(expect.compression));
    assert_eq!(v.image_count, Some(n));
    assert_eq!(v.editions.len(), expect.editions.len());
    for (ed, (i, (name, desc))) in v.editions.iter().zip((1u32..).zip(expect.editions)) {
        assert_eq!(ed.index.get(), i);
        assert_eq!(ed.name.as_str(), name);
        assert_eq!(ed.description.as_str(), desc);
        // Undeclared editions are `unknown` (REQ-OS-009).
        assert!(ed.facts.is_none());
        assert_eq!(ed.support.status, SupportState::Unknown);
    }
    let r = https(addr, &f.pki, Some(&f.pki.client), "GET", "/v1/images", None)
        .await
        .unwrap();
    assert_eq!(r.status, 200, "{}", r.body);
    let list: ImageList = view(r.body.as_bytes());
    assert!(
        list.images
            .iter()
            .any(|i| i.id.to_string() == image_id && i.editions.len() == expect.editions.len()),
        "image not listed with its editions"
    );

    // Import an x64 PE.
    let pe_id = upload(
        addr,
        f,
        "pe",
        "Builder PE x64",
        pe,
        Some(("x64", "10.1.26100.1")),
    )
    .await;
    let r = wait_state(
        addr,
        f,
        &format!("/v1/pe/{pe_id}"),
        "ready",
        Duration::from_secs(120),
    )
    .await;
    let pv: PeView = view(r.body.as_bytes());
    assert_eq!(pv.sha256, Some(pe.digests.total));
    assert_eq!(pv.usable_index.map(|i| i.get()), Some(1));
    assert_eq!(pv.architecture.value, Architecture::X64);
    assert_eq!(pv.architecture.source, FactSource::Declared);

    // Declare the chosen edition (decision 0013): every fact `declared`.
    let r = https(
        addr,
        &f.pki,
        Some(&f.pki.client),
        "PUT",
        &format!(
            "/v1/images/{image_id}/editions/{}/declaration",
            expect.chosen
        ),
        Some(r#"{"release":"windows-11","edition":"enterprise","architecture":"x64"}"#),
    )
    .await
    .unwrap();
    assert_eq!(r.status, 200, "{}", r.body);
    let ev: EditionView = view(r.body.as_bytes());
    let facts = ev.facts.unwrap();
    assert_eq!(facts.release.value, Release::Windows11);
    assert_eq!(facts.edition.value, Edition::Enterprise);
    assert_eq!(facts.architecture.value, Architecture::X64);
    for s in [
        facts.release.source,
        facts.edition.source,
        facts.architecture.source,
    ] {
        assert_eq!(s, FactSource::Declared);
    }
    assert_eq!(ev.support.status, SupportState::Supported);

    // A Ready package.
    let body = format!(
        r#"{{"name":"Exit one package","image_id":"{image_id}","edition_index":{},"pe_id":"{pe_id}"}}"#,
        expect.chosen
    );
    let r = https(
        addr,
        &f.pki,
        Some(&f.pki.client),
        "POST",
        "/v1/packages",
        Some(&body),
    )
    .await
    .unwrap();
    assert_eq!(r.status, 201, "{}", r.body);
    let p: PackageView = view(r.body.as_bytes());
    assert_eq!(p.status, PackageStatus::Ready, "{:?}", p.status_reason);
    let package_id = p.id.to_string();

    // Signed package manifest, verified with the pinned key only.
    let r = stream::get(
        addr,
        &f.pki,
        &f.pki.client,
        &format!("/v1/packages/{package_id}/manifest"),
    )
    .await
    .unwrap();
    assert_eq!(r.status, 200, "{}", r.text());
    let env = SignedEnvelopeV1::from_json(&r.body).unwrap();
    assert!(
        PackageManifestV1::open(&env, &Pinned(other_key.clone())).is_err(),
        "package manifest opened with a key that did not sign it"
    );
    let pm = PackageManifestV1::open(&env, &pin).unwrap();
    assert_eq!(pm.package_id.to_string(), package_id);
    assert_eq!(pm.revision, p.revision);
    assert_eq!(pm.image.content_sha256, image.digests.total);
    assert_eq!(pm.image.edition_index.get(), expect.chosen);
    let chosen = usize::try_from(expect.chosen - 1).unwrap();
    assert_eq!(
        pm.image.edition_name.as_str(),
        expect.editions[chosen].0.as_str()
    );
    assert_eq!(pm.image.facts, facts);
    assert_eq!(pm.pe.content_sha256, pe.digests.total);
    assert_eq!(pm.pe.usable_index.get(), 1);
    assert_eq!(pm.pe.architecture.value, Architecture::X64);

    // Signed content manifests and verified re-download of both files.
    let cm = content_manifest(addr, f, "images", &image_id, &image.digests, &pin).await;
    assert_eq!(cm.wim.compression, expect.compression);
    assert_eq!(cm.wim.image_count, n);
    assert_eq!(cm.wim.editions.len(), expect.editions.len());
    for (e, (name, desc)) in cm.wim.editions.iter().zip(expect.editions) {
        assert_eq!(e.name.as_str(), name);
        assert_eq!(e.description.as_str(), desc);
    }
    let r = stream::get(
        addr,
        &f.pki,
        &f.pki.client,
        &format!("/v1/images/{image_id}/manifest"),
    )
    .await
    .unwrap();
    let env = SignedEnvelopeV1::from_json(&r.body).unwrap();
    assert!(
        ContentManifestV1::open(&env, &Pinned(other_key.clone())).is_err(),
        "content manifest opened with a key that did not sign it"
    );
    verified_download(addr, f, &image_id, &cm, &image.digests).await;

    let pcm = content_manifest(addr, f, "pe", &pe_id, &pe.digests, &pin).await;
    verified_download(addr, f, &pe_id, &pcm, &pe.digests).await;

    FlowIds {
        image: image_id,
        pe: pe_id,
        package: package_id,
    }
}

/// Re-verifies a package after a restart: still Ready, manifest still
/// opens with the pinned key, and names the same image digest.
pub async fn package_still_ready(addr: SocketAddr, f: &Fixture, ids: &FlowIds, image: &Digests) {
    let r = https(
        addr,
        &f.pki,
        Some(&f.pki.client),
        "GET",
        &format!("/v1/packages/{}", ids.package),
        None,
    )
    .await
    .unwrap();
    assert_eq!(r.status, 200, "{}", r.body);
    let p: PackageView = view(r.body.as_bytes());
    assert_eq!(p.status, PackageStatus::Ready);
    let r = stream::get(
        addr,
        &f.pki,
        &f.pki.client,
        &format!("/v1/packages/{}/manifest", ids.package),
    )
    .await
    .unwrap();
    assert_eq!(r.status, 200, "{}", r.text());
    let env = SignedEnvelopeV1::from_json(&r.body).unwrap();
    let pm = PackageManifestV1::open(&env, &Pinned(f.content_pub.clone())).unwrap();
    assert_eq!(pm.image.content_sha256, image.total);
}
