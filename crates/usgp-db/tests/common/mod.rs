//! Shared fixtures and store-generic scenarios. The same scenarios run on
//! the in-memory store (`memory_repo.rs`, everywhere) and on PostgreSQL
//! (`repo_pg.rs`, `audit_pg.rs`, CI), so both keep the same rules.
//!
//! Declared `pub mod common` by each test crate, so helpers one binary
//! does not use are not dead code.

pub mod m3;
#[cfg(feature = "pg-integration")]
pub mod pg;

use std::time::{SystemTime, UNIX_EPOCH};

use usgp_audit::{
    Actor, AuditChain, AuditDraft, AuditRead, CheckpointPolicy, Checkpointer, Detail, Interface,
    Outcome, verify_store,
};
use usgp_common::Sha256Digest;
use usgp_crypto::{KeyId, SigningKey, VerifyingKey};
use usgp_db::{
    Content, DbError, NewContent, NewEdition, Operator, OperatorRole, OperatorStatus, Package,
    PeDeclaration, ReadyContent, Reason, RepoTx, Store, StoredManifest, Upload, WimFacts,
};
use usgp_proto::{
    Architecture, ContentId, ContentKind, ContentState, Description, DisplayName, Edition,
    EditionFacts, Fact, FileName, KitVersion, OperatorId, PackageId, PackageStatus, Release,
    SupportState, UnixMicros, UploadId, UploadState, WimCompression, WimText,
};

/// `N` bytes from the FIPS DRBG.
pub fn rand_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    usgp_crypto::fill_random(&mut b).unwrap();
    b
}

/// The current time.
pub fn now() -> UnixMicros {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    UnixMicros::new(i64::try_from(d.as_micros()).unwrap()).unwrap()
}

/// A random digest.
pub fn digest() -> Sha256Digest {
    Sha256Digest(rand_bytes())
}

/// An administrator with a random certificate fingerprint.
pub fn operator(name: &str) -> Operator {
    Operator {
        id: OperatorId::from_random_bytes(rand_bytes()),
        display_name: DisplayName::new(name).unwrap(),
        cert_sha256: digest(),
        cert_subject: format!("CN={name}"),
        cert_issuer: "CN=usgp test operator ca".into(),
        cert_serial: "0a1b".into(),
        cert_not_after: UnixMicros::new(4_000_000_000_000_000).unwrap(),
        role: Some(OperatorRole::Administrator),
        status: OperatorStatus::Active,
        created_at: now(),
        created_by: "uid:0".into(),
    }
}

/// An x64 PE declaration.
pub fn pe_declaration() -> PeDeclaration {
    PeDeclaration {
        architecture: Fact::declared(Architecture::X64),
        kit_version: Fact::declared(KitVersion::parse("10.1.26100.1").unwrap()),
    }
}

/// A content row and its upload session.
pub fn new_upload(by: OperatorId, kind: ContentKind, sha: Sha256Digest) -> (NewContent, Upload) {
    let id = ContentId::from_random_bytes(rand_bytes());
    let at = now();
    let c = NewContent {
        id,
        kind,
        display_name: DisplayName::new("Windows 11 Enterprise x64").unwrap(),
        file_name: FileName::new("install with spaces.wim").unwrap(),
        size: 4096,
        sha256: sha,
        created_by: by,
        initiating_audit_seq: None,
        created_at: at,
        pe: (kind == ContentKind::Pe).then(pe_declaration),
    };
    let u = Upload {
        id: UploadId::from_random_bytes(rand_bytes()),
        content_id: id,
        operator_id: by,
        declared_size: 4096,
        declared_sha256: sha,
        state: UploadState::Open,
        staging_name: format!("staging-{}", Sha256Digest(rand_bytes()).to_hex()),
        created_at: at,
        expires_at: UnixMicros::new(at.as_micros() + 86_400_000_000).unwrap(),
    };
    (c, u)
}

/// A stand-in signed manifest (the repository stores bytes only).
pub fn manifest(byte: u8) -> StoredManifest {
    StoredManifest {
        payload: vec![b'{', byte, b'}'],
        signature: vec![0x30, 0x02, 0x01, byte],
        key_id: KeyId(Sha256Digest([byte; 32])),
    }
}

/// Check results for `image_count` editions.
pub fn ready(kind: ContentKind, image_count: u32) -> ReadyContent {
    ReadyContent {
        wim: WimFacts {
            compression: WimCompression::Xpress,
            image_count,
            boot_index: u32::from(kind == ContentKind::Pe),
        },
        usable_index: (kind == ContentKind::Pe).then_some(1),
        editions: (1..=image_count)
            .map(|i| NewEdition {
                index: i,
                name: WimText::new(format!("Edition {i}")).unwrap(),
                description: WimText::new(format!("Description {i}")).unwrap(),
                total_bytes: Some(1000 * u64::from(i)),
            })
            .collect(),
        manifest: manifest(7),
        pe: None,
        at: now(),
    }
}

/// A new, not-usable package.
pub fn package(image: ContentId, index: u32, pe: ContentId, by: OperatorId) -> Package {
    let at = now();
    Package {
        id: PackageId::from_random_bytes(rand_bytes()),
        name: DisplayName::new("Finance laptops").unwrap(),
        description: Some(Description::new("Win 11 Ent").unwrap()),
        image_id: image,
        edition_index: index,
        pe_id: pe,
        revision: 1,
        status: PackageStatus::NotUsable,
        status_reason: Some("os_support_unknown".into()),
        manifest: None,
        created_by: by,
        created_at: at,
        updated_at: at,
    }
}

/// A success draft by the system actor.
pub fn draft(event: &str, kind: &str, id: &str) -> AuditDraft {
    AuditDraft::new(event, Outcome::Success, Actor::system(), Interface::System)
        .target(kind, id)
        .detail(Detail::new().with("test", "1"))
}

/// The audit chain, an initialised genesis, and a checkpointer.
pub struct Audit {
    /// Chain writer.
    pub chain: AuditChain,
    /// Checkpoint signer.
    pub checkpointer: Checkpointer,
    /// Trusted key for the verifier.
    pub public: VerifyingKey,
}

/// Writes the genesis record and returns the chain.
pub async fn init_audit<S: Store>(store: &S) -> Audit {
    let key = SigningKey::generate().unwrap();
    let public = key.verifying_key().clone();
    let checkpointer = Checkpointer::new(key, CheckpointPolicy::default()).unwrap();
    let chain = AuditChain::new("ctl-test").unwrap();
    let mut tx = store.begin().await.unwrap();
    let g = chain
        .ensure_genesis(&mut tx, &checkpointer.key_id())
        .await
        .unwrap();
    assert!(g.is_some());
    tx.commit().await.unwrap();
    // A second call finds the chain.
    let mut tx = store.begin().await.unwrap();
    assert!(
        chain
            .ensure_genesis(&mut tx, &checkpointer.key_id())
            .await
            .unwrap()
            .is_none()
    );
    tx.commit().await.unwrap();
    Audit {
        chain,
        checkpointer,
        public,
    }
}

/// Appends `event` in `tx` and returns its seq.
pub async fn append<T: RepoTx>(a: &Audit, tx: &mut T, event: &str, kind: &str, id: &str) -> u64 {
    a.chain
        .append(tx, &draft(event, kind, id))
        .await
        .unwrap()
        .seq
}

/// Enrols an operator (audited) and returns it.
pub async fn enrol<S: Store>(store: &S, a: &Audit, name: &str) -> Operator {
    let op = operator(name);
    let mut tx = store.begin().await.unwrap();
    tx.insert_operator(&op).await.unwrap();
    append(
        a,
        &mut tx,
        "operator.enrolled",
        "operator",
        &op.id.to_string(),
    )
    .await;
    tx.commit().await.unwrap();
    op
}

/// Uploads and checks a content item to Ready through every state.
pub async fn make_ready<S: Store>(
    store: &S,
    a: &Audit,
    by: OperatorId,
    kind: ContentKind,
    image_count: u32,
) -> Content {
    let (c, u) = new_upload(by, kind, digest());
    let mut tx = store.begin().await.unwrap();
    let seq = append(
        a,
        &mut tx,
        "content.upload.created",
        "content",
        &c.id.to_string(),
    )
    .await;
    let c = NewContent {
        initiating_audit_seq: Some(seq),
        ..c
    };
    tx.create_upload(&c, &u).await.unwrap();
    tx.commit().await.unwrap();

    let mut tx = store.begin().await.unwrap();
    tx.set_upload_state(u.id, &[UploadState::Open], UploadState::Streaming)
        .await
        .unwrap();
    tx.set_upload_state(u.id, &[UploadState::Streaming], UploadState::Complete)
        .await
        .unwrap();
    tx.set_content_state(
        c.id,
        &[ContentState::Receiving],
        ContentState::Checking,
        None,
        now(),
    )
    .await
    .unwrap();
    append(
        a,
        &mut tx,
        "content.upload.received",
        "content",
        &c.id.to_string(),
    )
    .await;
    tx.commit().await.unwrap();

    let mut tx = store.begin().await.unwrap();
    tx.set_content_ready(c.id, &ready(kind, image_count))
        .await
        .unwrap();
    append(a, &mut tx, "content.ready", "content", &c.id.to_string()).await;
    tx.commit().await.unwrap();

    let mut tx = store.begin().await.unwrap();
    let got = tx.content(c.id).await.unwrap().unwrap();
    tx.commit().await.unwrap();
    got
}

// --------------------------------------------------------------- flows --

/// A state change without an audit record cannot commit, and leaves
/// nothing behind.
pub async fn flow_unaudited_change_refused<S: Store>(store: &S, _a: &Audit) {
    let op = operator("unaudited");
    let mut tx = store.begin().await.unwrap();
    tx.insert_operator(&op).await.unwrap();
    assert!(matches!(tx.commit().await, Err(DbError::Unaudited)));
    let mut tx = store.begin().await.unwrap();
    assert!(tx.operator(op.id).await.unwrap().is_none());
    // A read-only transaction commits without a record.
    tx.commit().await.unwrap();
}

/// Change and record commit together; rollback and drop discard both.
pub async fn flow_atomic_with_audit<S: Store + AuditRead>(store: &S, a: &Audit) {
    let head0 = store.head().await.unwrap().unwrap();

    let op = operator("rolled back");
    let mut tx = store.begin().await.unwrap();
    tx.insert_operator(&op).await.unwrap();
    append(
        a,
        &mut tx,
        "operator.enrolled",
        "operator",
        &op.id.to_string(),
    )
    .await;
    tx.rollback().await;
    assert_eq!(store.head().await.unwrap().unwrap(), head0);

    let mut tx = store.begin().await.unwrap();
    tx.insert_operator(&op).await.unwrap();
    append(
        a,
        &mut tx,
        "operator.enrolled",
        "operator",
        &op.id.to_string(),
    )
    .await;
    drop(tx);
    assert_eq!(store.head().await.unwrap().unwrap(), head0);

    let mut tx = store.begin().await.unwrap();
    assert!(tx.operator(op.id).await.unwrap().is_none());
    tx.insert_operator(&op).await.unwrap();
    let seq = append(
        a,
        &mut tx,
        "operator.enrolled",
        "operator",
        &op.id.to_string(),
    )
    .await;
    tx.commit().await.unwrap();
    let head = store.head().await.unwrap().unwrap();
    assert_eq!(head.seq, seq);
    assert_eq!(head.seq, head0.seq + 1);

    let mut tx = store.begin().await.unwrap();
    assert_eq!(tx.operator(op.id).await.unwrap().unwrap(), op);
    assert_eq!(
        tx.operator_by_cert(&op.cert_sha256)
            .await
            .unwrap()
            .unwrap()
            .id,
        op.id
    );
    tx.commit().await.unwrap();
}

/// One certificate maps to one operator; a duplicate poisons the
/// transaction as PostgreSQL does.
pub async fn flow_operator_rules<S: Store>(store: &S, a: &Audit) {
    let op = enrol(store, a, "first").await;
    let mut dup = operator("second");
    dup.cert_sha256 = op.cert_sha256;
    let mut tx = store.begin().await.unwrap();
    let e = tx.insert_operator(&dup).await.unwrap_err();
    assert!(e.is_conflict(), "{e:?}");
    assert!(matches!(tx.list_operators().await, Err(DbError::TxFailed)));
    assert!(matches!(tx.commit().await, Err(DbError::TxFailed)));

    let mut tx = store.begin().await.unwrap();
    tx.set_operator_status(op.id, OperatorStatus::Disabled)
        .await
        .unwrap();
    append(
        a,
        &mut tx,
        "operator.disabled",
        "operator",
        &op.id.to_string(),
    )
    .await;
    tx.commit().await.unwrap();
    let mut tx = store.begin().await.unwrap();
    assert_eq!(
        tx.operator(op.id).await.unwrap().unwrap().status,
        OperatorStatus::Disabled
    );
    let missing = OperatorId::from_random_bytes(rand_bytes());
    assert!(
        tx.set_operator_status(missing, OperatorStatus::Disabled)
            .await
            .unwrap_err()
            .is_not_found()
    );
    tx.rollback().await;
}

/// Upload states, duplicate digests, compare-and-set, Ready, editions and
/// declarations (REQ-IMG-020, decision 0013). The operator is enrolled
/// through `admin` (on PostgreSQL the application role cannot write
/// operators, decision 0016).
pub async fn flow_content_lifecycle<A: Store, S: Store>(admin: &A, store: &S, a: &Audit) {
    let op = enrol(admin, a, "uploader").await;
    let sha = digest();
    let (c, u) = new_upload(op.id, ContentKind::Image, sha);
    let mut tx = store.begin().await.unwrap();
    tx.create_upload(&c, &u).await.unwrap();
    append(
        a,
        &mut tx,
        "content.upload.created",
        "content",
        &c.id.to_string(),
    )
    .await;
    tx.commit().await.unwrap();

    // Same digest while live → conflict (409 with the existing id).
    let (c2, u2) = new_upload(op.id, ContentKind::Image, sha);
    let mut tx = store.begin().await.unwrap();
    assert_eq!(tx.content_by_sha256(&sha).await.unwrap().unwrap().id, c.id);
    assert!(tx.create_upload(&c2, &u2).await.unwrap_err().is_conflict());
    tx.rollback().await;

    let mut tx = store.begin().await.unwrap();
    assert_eq!(tx.count_active_uploads(Some(op.id)).await.unwrap(), 1);
    assert_eq!(tx.count_active_uploads(None).await.unwrap(), 1);
    // Wrong source state → conflict; the transaction stays usable.
    let e = tx
        .set_upload_state(u.id, &[UploadState::Streaming], UploadState::Complete)
        .await
        .unwrap_err();
    assert!(e.is_conflict(), "{e:?}");
    tx.set_upload_state(u.id, &[UploadState::Open], UploadState::Streaming)
        .await
        .unwrap();
    // Ready only from checking.
    assert!(
        tx.set_content_ready(c.id, &ready(ContentKind::Image, 2))
            .await
            .unwrap_err()
            .is_conflict()
    );
    // Failed needs a reason.
    assert!(matches!(
        tx.set_content_state(
            c.id,
            &[ContentState::Receiving],
            ContentState::Failed,
            None,
            now()
        )
        .await,
        Err(DbError::InvalidArgument { .. })
    ));
    append(
        a,
        &mut tx,
        "content.upload.streaming",
        "upload",
        &u.id.to_string(),
    )
    .await;
    tx.commit().await.unwrap();

    // Interrupted body → failed with reason; the digest is free again.
    let mut tx = store.begin().await.unwrap();
    tx.set_upload_state(u.id, &[UploadState::Streaming], UploadState::Failed)
        .await
        .unwrap();
    let reason = Reason {
        code: "interrupted".into(),
        text: "the upload body ended early".into(),
    };
    tx.set_content_state(
        c.id,
        &[ContentState::Receiving],
        ContentState::Failed,
        Some(&reason),
        now(),
    )
    .await
    .unwrap();
    append(
        a,
        &mut tx,
        "content.upload.failed",
        "content",
        &c.id.to_string(),
    )
    .await;
    tx.commit().await.unwrap();
    let mut tx = store.begin().await.unwrap();
    let failed = tx.content(c.id).await.unwrap().unwrap();
    assert_eq!(failed.state, ContentState::Failed);
    assert_eq!(failed.reason, Some(reason));
    assert!(tx.content_by_sha256(&sha).await.unwrap().is_none());
    assert_eq!(tx.count_active_uploads(None).await.unwrap(), 0);
    tx.create_upload(&c2, &u2).await.unwrap();
    append(
        a,
        &mut tx,
        "content.upload.created",
        "content",
        &c2.id.to_string(),
    )
    .await;
    tx.commit().await.unwrap();

    // A full Ready image with 12 editions (REQ-IMG-042).
    let image = make_ready(store, a, op.id, ContentKind::Image, 12).await;
    assert_eq!(image.state, ContentState::Ready);
    assert_eq!(image.file_name.as_str(), "install with spaces.wim");
    assert!(image.manifest.is_some());
    assert_eq!(image.wim.unwrap().image_count, 12);
    assert!(image.initiating_audit_seq.is_some());

    let mut tx = store.begin().await.unwrap();
    let eds = tx.editions(image.id).await.unwrap();
    assert_eq!(eds.len(), 12);
    assert!(
        eds.iter()
            .all(|e| e.support == SupportState::Unknown && e.declaration.is_none())
    );
    let listed = tx
        .list_content(Some(ContentKind::Image), &[ContentState::Ready])
        .await
        .unwrap();
    assert!(listed.iter().any(|x| x.id == image.id));
    assert!(
        tx.list_content(Some(ContentKind::Pe), &[])
            .await
            .unwrap()
            .iter()
            .all(|x| x.kind == ContentKind::Pe)
    );

    // Declaration: recorded with source and the record's seq.
    let seq = append(
        a,
        &mut tx,
        "edition.declared",
        "content",
        &image.id.to_string(),
    )
    .await;
    let decl = usgp_db::EditionDeclaration {
        facts: EditionFacts {
            release: Fact::declared(Release::Windows11),
            edition: Fact::declared(Edition::Enterprise),
            architecture: Fact::declared(Architecture::X64),
        },
        declared_by: op.id,
        declared_at: now(),
        declared_audit_seq: seq,
    };
    tx.set_edition_declaration(image.id, 1, &decl, SupportState::Supported, None)
        .await
        .unwrap();
    assert!(
        tx.set_edition_declaration(image.id, 13, &decl, SupportState::Supported, None)
            .await
            .unwrap_err()
            .is_not_found()
    );
    tx.commit().await.unwrap();
    let mut tx = store.begin().await.unwrap();
    let e1 = tx.edition(image.id, 1).await.unwrap().unwrap();
    assert_eq!(e1.declaration, Some(decl));
    assert_eq!(e1.support, SupportState::Supported);
    tx.rollback().await;

    // A PE carries its declaration from creation.
    let pe = make_ready(store, a, op.id, ContentKind::Pe, 1).await;
    assert_eq!(pe.pe, Some(pe_declaration()));
    assert_eq!(pe.usable_index, Some(1));

    // PE declaration required for PE, forbidden for images.
    let (mut bad, bu) = new_upload(op.id, ContentKind::Image, digest());
    bad.pe = Some(pe_declaration());
    let mut tx = store.begin().await.unwrap();
    assert!(matches!(
        tx.create_upload(&bad, &bu).await,
        Err(DbError::InvalidArgument { .. })
    ));
    tx.rollback().await;
}

/// Package rules: references, revision compare-and-set, status, dependants
/// (decision 0015 item 2), delete. The operator is enrolled through
/// `admin`.
pub async fn flow_package_lifecycle<A: Store, S: Store>(admin: &A, store: &S, a: &Audit) {
    let op = enrol(admin, a, "packager").await;
    let image = make_ready(store, a, op.id, ContentKind::Image, 2).await;
    let pe = make_ready(store, a, op.id, ContentKind::Pe, 1).await;

    // A PE in the image slot, or a missing edition → constraint.
    for bad in [
        package(pe.id, 1, pe.id, op.id),
        package(image.id, 3, pe.id, op.id),
        package(image.id, 1, image.id, op.id),
    ] {
        let mut tx = store.begin().await.unwrap();
        let e = tx.insert_package(&bad).await.unwrap_err();
        assert!(matches!(e, DbError::Constraint { .. }), "{e:?}");
        tx.rollback().await;
    }

    let p = package(image.id, 1, pe.id, op.id);
    let mut tx = store.begin().await.unwrap();
    tx.insert_package(&p).await.unwrap();
    append(a, &mut tx, "package.created", "package", &p.id.to_string()).await;
    tx.commit().await.unwrap();

    // Revision compare-and-set (If-Match / 412).
    let mut edit = p.clone();
    edit.revision = 2;
    edit.edition_index = 2;
    edit.description = None;
    let mut tx = store.begin().await.unwrap();
    assert!(tx.update_package(&edit, 5).await.is_err());
    tx.rollback().await;
    let mut tx = store.begin().await.unwrap();
    let mut stale = edit.clone();
    stale.revision = 6;
    assert!(
        tx.update_package(&stale, 5)
            .await
            .unwrap_err()
            .is_conflict()
    );
    tx.update_package(&edit, 1).await.unwrap();
    append(a, &mut tx, "package.edited", "package", &p.id.to_string()).await;
    tx.commit().await.unwrap();

    let mut tx = store.begin().await.unwrap();
    let got = tx.lock_package(p.id).await.unwrap().unwrap();
    assert_eq!(got.revision, 2);
    assert_eq!(got.edition_index, 2);
    assert_eq!(got.description, None);
    // Ready needs a manifest.
    tx.set_package_status(p.id, PackageStatus::Ready, None, Some(&manifest(9)), now())
        .await
        .unwrap();
    append(
        a,
        &mut tx,
        "package.status.changed",
        "package",
        &p.id.to_string(),
    )
    .await;
    tx.commit().await.unwrap();

    let mut tx = store.begin().await.unwrap();
    let got = tx.package(p.id).await.unwrap().unwrap();
    assert_eq!(got.status, PackageStatus::Ready);
    assert_eq!(got.manifest, Some(manifest(9)));
    assert_eq!(got.revision, 2);
    let deps = tx.packages_using_content(pe.id).await.unwrap();
    assert_eq!(deps.len(), 1);
    assert_eq!(deps.first().unwrap().id, p.id);
    assert_eq!(
        tx.packages_using_edition(image.id, 2).await.unwrap().len(),
        1
    );
    assert!(
        tx.packages_using_edition(image.id, 1)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        tx.list_packages()
            .await
            .unwrap()
            .iter()
            .any(|x| x.id == p.id)
    );
    tx.rollback().await;

    // Delete with the wrong revision → conflict; right one → gone.
    let mut tx = store.begin().await.unwrap();
    assert!(tx.delete_package(p.id, 1).await.unwrap_err().is_conflict());
    tx.delete_package(p.id, 2).await.unwrap();
    append(a, &mut tx, "package.deleted", "package", &p.id.to_string()).await;
    tx.commit().await.unwrap();
    let mut tx = store.begin().await.unwrap();
    assert!(tx.package(p.id).await.unwrap().is_none());
    assert!(tx.delete_package(p.id, 2).await.unwrap_err().is_not_found());
    tx.rollback().await;
}

/// Checkpoint the chain and verify it end to end.
pub async fn flow_chain_verifies<S: Store + AuditRead>(store: &S, a: &Audit) {
    let mut tx = store.begin().await.unwrap();
    let w = a
        .checkpointer
        .checkpoint_if_due(&a.chain, &mut tx, true)
        .await
        .unwrap();
    assert!(w.is_some());
    tx.commit().await.unwrap();
    let report = verify_store(store, std::slice::from_ref(&a.public), 7)
        .await
        .unwrap();
    assert!(report.is_intact(), "{:?}", report.first_finding());
    assert!(report.checkpoints_matched >= 1);
    assert!(report.records_checked >= 2);
}
