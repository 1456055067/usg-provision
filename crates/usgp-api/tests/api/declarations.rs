//! Edition declarations (decision 0013; REQ-IMG-043, REQ-OS-009).

use usgp_image::facts::FileFact;
use usgp_proto::Architecture;

use crate::common::{Harness, Who};

#[tokio::test]
async fn declare_ok_source_declared() {
    let h = Harness::start().await;
    let image = h.ready_image(3, "decl").await;
    let r = h.declare(image, 2, "windows-11", "enterprise", "x64").await;
    assert_eq!(r.status, 200);
    let j = r.json();
    assert_eq!(j["index"], 2);
    for f in ["release", "edition", "architecture"] {
        assert_eq!(j["facts"][f]["source"], "declared", "{f}");
    }
    assert_eq!(j["support"]["status"], "supported");
    assert!(j["declared_by"].is_string());
    // Out of scope is recorded, with the reason (refused only at package
    // selection).
    let r = h.declare(image, 3, "windows-10", "pro", "arm64").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["support"]["status"], "not_supported");
    assert_eq!(
        r.json()["support"]["reason"],
        "release_not_supported:windows-10"
    );
    let v = h.get(Who::Admin, &format!("/v1/images/{image}")).await;
    let eds = v.json()["editions"].clone();
    assert_eq!(eds[0]["support"]["status"], "unknown");
    assert_eq!(eds[0]["support"]["reason"], "os_support_unknown");
    assert_eq!(eds[1]["facts"]["edition"]["value"], "enterprise");
    let rec = h.events("edition.declared");
    assert_eq!(rec.len(), 2);
    assert!(rec[1].detail.contains("\"support\":\"not_supported\""));
    // Re-declaring shows the old values in the record.
    let r = h.declare(image, 3, "windows-11", "enterprise", "x64").await;
    assert_eq!(r.status, 200);
    assert!(
        h.events("edition.declared")[2]
            .detail
            .contains("\"old_release\":\"windows-10\"")
    );
}

#[tokio::test]
async fn invalid_value_422() {
    let h = Harness::start().await;
    let image = h.ready_image(1, "inv").await;
    let before = h.snapshot().await;
    for (rel, ed, arch, code) in [
        ("Windows-11", "enterprise", "x64", "invalid_value:release"),
        ("windows-11", "ltsc", "x64", "invalid_value:edition"),
        (
            "windows-11",
            "enterprise",
            "amd64",
            "invalid_value:architecture",
        ),
    ] {
        let r = h.declare(image, 1, rel, ed, arch).await;
        assert_eq!(r.status, 422);
        assert_eq!(r.code(), code);
    }
    let r = h.declare(image, 2, "windows-11", "enterprise", "x64").await;
    assert_eq!(r.status, 404);
    assert_eq!(h.snapshot().await, before);
    assert_eq!(h.events("edition.declaration.refused").len(), 4);
}

/// Decision 0013 item 2: a declaration contradicting a fact the file
/// states is refused and audited (test checker stating x86).
#[tokio::test]
async fn contradiction_422_audited() {
    let h = Harness::start().await;
    let image = h.ready_image(1, "contra").await;
    h.fake.facts.lock().unwrap().architecture = FileFact::Stated(Architecture::X86);
    let r = h.declare(image, 1, "windows-11", "enterprise", "x64").await;
    assert_eq!(r.status, 422);
    assert_eq!(r.code(), "declaration_contradicts_file:architecture");
    let rec = h.events("edition.declaration.refused");
    assert_eq!(
        rec[0].reason.as_deref(),
        Some("declaration_contradicts_file:architecture")
    );
    assert!(rec[0].detail.contains("\"file\":\"x86\""));
    // A matching file fact is recorded as verified.
    let r = h.declare(image, 1, "windows-11", "enterprise", "x86").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["facts"]["architecture"]["source"], "verified");
    assert_eq!(r.json()["facts"]["release"]["source"], "declared");
}

#[tokio::test]
async fn in_use_409_and_not_ready_409() {
    let h = Harness::start().await;
    let (pkg, image, _pe) = h.ready_package("inuse").await;
    let r = h.declare(image, 1, "windows-11", "pro", "x64").await;
    assert_eq!(r.status, 409);
    assert_eq!(r.code(), "in_use");
    assert_eq!(r.json()["error"]["dependants"][0]["id"], pkg);
    // Not ready: an open upload's content.
    let r = h.create_upload("image", "Open", b"FAKEWIM:1:o", None).await;
    let id = r.json()["content_id"].as_str().unwrap().to_owned();
    let r = h
        .req(
            Who::Admin,
            "PUT",
            &format!("/v1/images/{id}/editions/1/declaration"),
            &[],
            Some(
                br#"{"release":"windows-11","edition":"enterprise","architecture":"x64"}"#.to_vec(),
            ),
        )
        .await;
    assert_eq!(r.status, 409);
    assert_eq!(r.code(), "not_ready");
}
