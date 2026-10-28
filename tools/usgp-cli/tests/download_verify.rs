//! End-to-end CLI tests over real mutual TLS (plan WU-8, section 10):
//! the built `usgp-cli` binary against an in-process hyper server on
//! `usgp_crypto::tls::ServerTls` with the test PKI (`tests/common`).
//!
//! - `good`, `tampered_chunk`, `bad_signature`: verified download
//!   (REQ-IMG-050, plan section 5.7).
//! - the operator's client certificate reaches the server; an untrusted
//!   server is refused; a 401 is explained.
//! - uploads stream with `Content-Length`, never chunked, and carry the
//!   declared digest.
//! - the signed package manifest is verified before it is written.

#[cfg(test)]
mod common;

#[cfg(test)]
mod tls {
    use std::fs;

    use usgp_common::Sha256Digest;
    use usgp_crypto::SigningKey;
    use usgp_proto::api::{self, CreateUploadRequest, CreateUploadResponse, UploadAccepted};
    use usgp_proto::content_manifest::{ContentManifestV1, ManifestEdition, WimSummaryV1};
    use usgp_proto::envelope::{PayloadType, SignatureAlg, SignatureV1, SignedEnvelopeV1};
    use usgp_proto::facts::{Architecture, Edition, EditionFacts, Fact, KitVersion, Release};
    use usgp_proto::ids::{ContentId, OperatorId, PackageId, UnixMicros, UploadId};
    use usgp_proto::limits::CHUNK_SIZE;
    use usgp_proto::names::{DisplayName, EditionIndex, FileName, WimText};
    use usgp_proto::package_manifest::{PackageImageV1, PackageManifestV1, PackagePeV1};
    use usgp_proto::status::{ContentKind, ContentState, UploadState, WimCompression};

    use crate::common::{Env, route, stderr, stdout};

    const ID: &str = "0b7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e6f";
    const PKG: &str = "1c9e8a70-2b3d-4e5f-9a0b-c1d2e3f40516";
    const UPLOAD: &str = "5d1e2f3a-4b5c-4d6e-8f70-8192a3b4c5d6";

    fn sign(key: &SigningKey, ty: PayloadType, payload: Vec<u8>) -> Vec<u8> {
        let sig = usgp_crypto::sign_typed(key, ty.as_str(), &payload).unwrap();
        let s = SignatureV1::new(key.key_id().0, SignatureAlg::EcdsaP384Sha384, sig).unwrap();
        SignedEnvelopeV1::new(ty, payload, vec![s])
            .unwrap()
            .to_json()
            .unwrap()
    }

    /// Two chunks: one full 8 MiB chunk and a short one.
    fn data() -> Vec<u8> {
        let n = usize::try_from(CHUNK_SIZE).unwrap() + 1000;
        (0..n).map(|i| u8::try_from(i % 251).unwrap()).collect()
    }

    fn content_manifest(key: &SigningKey, d: &[u8]) -> Vec<u8> {
        let chunk = usize::try_from(CHUNK_SIZE).unwrap();
        let m = ContentManifestV1 {
            schema: 1,
            kind: ContentKind::Image,
            content_id: ContentId::parse(ID).unwrap(),
            display_name: DisplayName::new("Win 11 Ent").unwrap(),
            file_name: FileName::new("install image.wim").unwrap(),
            size: u64::try_from(d.len()).unwrap(),
            sha256: usgp_crypto::sha256(d),
            chunk_size: CHUNK_SIZE,
            chunk_sha256: d.chunks(chunk).map(usgp_crypto::sha256).collect(),
            wim: WimSummaryV1 {
                compression: WimCompression::Xpress,
                image_count: 1,
                boot_index: 0,
                editions: vec![ManifestEdition {
                    index: EditionIndex::new(1).unwrap(),
                    name: WimText::new("Edition 1").unwrap(),
                    description: WimText::new("d").unwrap(),
                    total_bytes: None,
                }],
            },
            ready_at: UnixMicros::new(1).unwrap(),
            key_id: key.key_id().0,
        };
        sign(key, PayloadType::ContentManifestV1, m.to_payload().unwrap())
    }

    fn manifest_path() -> String {
        format!("/v1/images/{ID}/manifest")
    }

    fn content_path() -> String {
        format!("/v1/content/{ID}")
    }

    fn download(env: &Env, out: &std::path::Path) -> std::process::Output {
        env.run(
            &["image", "download", ID, "--out", out.to_str().unwrap()],
            b"",
        )
    }

    fn part(out: &std::path::Path) -> std::path::PathBuf {
        let mut s = out.as_os_str().to_owned();
        s.push(".part");
        s.into()
    }

    #[test]
    fn good() {
        let key = SigningKey::generate().unwrap();
        let d = data();
        let etag = api::content_etag(&usgp_crypto::sha256(&d));
        let env = Env::new(
            vec![
                route("GET", &manifest_path(), 200, content_manifest(&key, &d)),
                route("GET", &content_path(), 200, d.clone()).with_header("etag", &etag),
            ],
            Some(key.verifying_key()),
        );
        let out = env.dir.join("install image.wim");
        let o = download(&env, &out);
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        assert_eq!(fs::read(&out).unwrap(), d);
        assert!(!part(&out).exists());
        assert!(stdout(&o).contains("verified: 2 chunks"), "{}", stdout(&o));
        // Every request carried the operator's certificate.
        let seen = env.seen();
        assert_eq!(seen.len(), 2);
        for s in &seen {
            assert_eq!(
                s.client_cert_sha256.as_deref(),
                Some(env.operator_sha256().as_str())
            );
            assert!(s.header("host").unwrap().starts_with("127.0.0.1:"));
            assert_eq!(s.method, "GET");
            assert_eq!(s.query, None);
        }
    }

    #[test]
    fn tampered_chunk() {
        let key = SigningKey::generate().unwrap();
        let d = data();
        let mut bad = d.clone();
        *bad.last_mut().unwrap() ^= 1;
        let env = Env::new(
            vec![
                route("GET", &manifest_path(), 200, content_manifest(&key, &d)),
                route("GET", &content_path(), 200, bad),
            ],
            Some(key.verifying_key()),
        );
        let out = env.dir.join("x.wim");
        let o = download(&env, &out);
        assert_eq!(o.status.code(), Some(1));
        assert!(
            stderr(&o).contains("chunk 1 does not match the signed manifest"),
            "{}",
            stderr(&o)
        );
        assert!(!out.exists());
        assert!(!part(&out).exists());
    }

    #[test]
    fn bad_signature() {
        let key = SigningKey::generate().unwrap();
        let other = SigningKey::generate().unwrap();
        let d = data();
        let env = Env::new(
            vec![
                route("GET", &manifest_path(), 200, content_manifest(&other, &d)),
                route("GET", &content_path(), 200, d),
            ],
            Some(key.verifying_key()),
        );
        let out = env.dir.join("x.wim");
        let o = download(&env, &out);
        assert_eq!(o.status.code(), Some(1));
        assert!(
            stderr(&o).contains("manifest not trusted"),
            "{}",
            stderr(&o)
        );
        assert!(!out.exists() && !part(&out).exists());
        // The content itself was never requested.
        let seen = env.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen.first().unwrap().path, manifest_path());
    }

    #[test]
    fn untrusted_server_refused() {
        let env = Env::with_trust(
            vec![route("GET", "/v1/limits", 200, b"{}".to_vec())],
            None,
            true,
        );
        let o = env.run(&["limits"], b"");
        assert_eq!(o.status.code(), Some(1));
        assert!(stderr(&o).contains("untrusted"), "{}", stderr(&o));
        assert!(env.seen().is_empty());
    }

    #[test]
    fn unauthenticated_401_explained() {
        let body = serde_json::to_vec(&api::ErrorBody::new(
            usgp_proto::ErrorCode::new("unknown_certificate").unwrap(),
            api::Message::new("certificate not enrolled").unwrap(),
        ))
        .unwrap();
        let env = Env::new(
            vec![
                route("GET", "/v1/limits", 401, body)
                    .with_header("www-authenticate", api::WWW_AUTHENTICATE),
            ],
            None,
        );
        let o = env.run(&["limits"], b"");
        assert_eq!(o.status.code(), Some(1));
        let e = stderr(&o);
        assert!(e.contains("HTTP 401 unknown_certificate"), "{e}");
        assert!(e.contains("not authenticated"), "{e}");
    }

    #[test]
    fn upload_streams_with_content_length() {
        let session = CreateUploadResponse {
            upload_id: UploadId::parse(UPLOAD).unwrap(),
            content_id: ContentId::parse(ID).unwrap(),
            state: UploadState::Open,
            expires_at: UnixMicros::new(2).unwrap(),
        };
        let accepted = UploadAccepted {
            content_id: ContentId::parse(ID).unwrap(),
            state: ContentState::Checking,
        };
        let env = Env::new(
            vec![
                route(
                    "POST",
                    "/v1/uploads",
                    201,
                    serde_json::to_vec(&session).unwrap(),
                ),
                route(
                    "PUT",
                    &format!("/v1/uploads/{UPLOAD}"),
                    202,
                    serde_json::to_vec(&accepted).unwrap(),
                ),
            ],
            None,
        );
        let d = data();
        let file = env.dir.join("install image.wim");
        fs::write(&file, &d).unwrap();
        let o = env.run(
            &[
                "image",
                "upload",
                file.to_str().unwrap(),
                "--name",
                "Win 11",
            ],
            b"",
        );
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        assert!(stdout(&o).contains("state:  checking"), "{}", stdout(&o));
        let seen = env.seen();
        let (create, put) = (seen.first().unwrap(), seen.get(1).unwrap());
        let req: CreateUploadRequest = serde_json::from_slice(&create.body).unwrap();
        assert_eq!(req.file_name, "install image.wim");
        assert_eq!(req.sha256, usgp_crypto::sha256(&d).to_hex());
        assert_eq!(
            put.header("content-length"),
            Some(d.len().to_string().as_str())
        );
        assert_eq!(put.header("transfer-encoding"), None);
        assert_eq!(put.header("content-type"), Some("application/octet-stream"));
        assert_eq!(put.body, d);
    }

    #[test]
    fn package_manifest_verified_over_tls() {
        let key = SigningKey::generate().unwrap();
        let m = PackageManifestV1 {
            schema: 1,
            package_id: PackageId::parse(PKG).unwrap(),
            revision: 3,
            name: DisplayName::new("Laptops").unwrap(),
            image: PackageImageV1 {
                content_sha256: Sha256Digest([0xaa; 32]),
                edition_index: EditionIndex::new(1).unwrap(),
                edition_name: WimText::new("Ent\x1b[2J").unwrap(),
                facts: EditionFacts {
                    release: Fact::declared(Release::Windows11),
                    edition: Fact::declared(Edition::Enterprise),
                    architecture: Fact::declared(Architecture::X64),
                },
                declared_by: OperatorId::parse("2c9e8a70-2b3d-4e5f-9a0b-c1d2e3f40516").unwrap(),
                declared_audit_seq: 7,
            },
            pe: PackagePeV1 {
                content_sha256: Sha256Digest([0xbb; 32]),
                usable_index: EditionIndex::new(1).unwrap(),
                architecture: Fact::declared(Architecture::X64),
                kit_version: Fact::declared(KitVersion::parse("10.1.26100.1").unwrap()),
            },
            signed_at: UnixMicros::new(0).unwrap(),
            key_id: key.key_id().0,
        };
        let env_bytes = sign(
            &key,
            PayloadType::PackageManifestV1,
            m.to_payload().unwrap(),
        );
        let env = Env::new(
            vec![route(
                "GET",
                &format!("/v1/packages/{PKG}/manifest"),
                200,
                env_bytes.clone(),
            )],
            Some(key.verifying_key()),
        );
        let out = env.dir.join("pkg.json");
        let o = env.run(
            &["package", "manifest", PKG, "--out", out.to_str().unwrap()],
            b"",
        );
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        assert_eq!(fs::read(&out).unwrap(), env_bytes);
        let text = stdout(&o);
        assert!(text.contains("release: windows-11 (declared)"), "{text}");
        assert!(text.contains("Ent\\u{001b}[2J"), "{text}");
        assert!(!text.contains('\x1b'));
    }
}
