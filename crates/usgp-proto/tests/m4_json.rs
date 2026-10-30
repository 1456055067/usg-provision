//! M4 wire types (plan WU-4): the v2 job plan and its verification, the
//! confirm with the job key, and the post-setup `job.json`. Round trips,
//! strict parsing, tampering and binding checks; no secret fields.
//!
//! No cryptography here: the verifier and the digest are test doubles
//! (keyed checksums), as in `device_json.rs`.

// COMPLIANCE MAPPING:
// - NIST 800-53: SA-11 (Developer Testing and Evaluation), SI-10, SI-7(6),
//   SC-23 (plan bound to the nonce and the job key)
// - SPEC: specs/workflow.md#REQ-SEQ-002, specs/configuration.md#REQ-CFG-004,
//   specs/drivers.md#REQ-DRV-006, specs/agent-handoff.md#REQ-AGT-001

#[cfg(test)]
mod m4_json {
    use base64ct::{Base64, Encoding};
    use usgp_common::Sha256Digest;
    use usgp_proto::content_manifest::{
        ArchiveSummaryV1, ContentManifestV1, ContentManifestV2, ManifestEdition, WimSummaryV1,
        chunk_count,
    };
    use usgp_proto::device::{AgentNonce, ConfirmV2, ConfirmedV2, MacAddress, MacList};
    use usgp_proto::disk::{
        Bus, DiskDescriptorParts, DiskDescriptorV1, DiskToken, ExistingPartitionV1, PartitionKind,
        PlanDiskV1,
    };
    use usgp_proto::envelope::{
        PayloadType, SignatureAlg, SignatureV1, SignatureVerifier, SignedEnvelopeV1, signing_input,
    };
    use usgp_proto::job_plan::{
        EscrowAccount, JobPlanV2, LayoutPolicyV1, PlanAgentV2, PlanAnswerFileV2, PlanContentV2,
        PlanDeviceV1, PlanDriverV2, PlanError, PlanEscrowV2, PlanExpectation, PlanExpectationV2,
        PlanImageV1, PlanPackageV1, PlanPostSetupV2, PlanStepV2, PlanWipeV1, RetryPolicyV1,
        VerifiedJobPlanV2, WipeScope,
    };
    use usgp_proto::limits::CHUNK_SIZE;
    use usgp_proto::postsetup::PostSetupConfigV1;
    use usgp_proto::progress::StepV2;
    use usgp_proto::{
        AgentPackageId, ArchiveFormat, B64Bytes, BootServiceId, ContentId, ContentKind,
        ContentKindV2, DiskText, DisplayName, DriverArchiveId, EditionIndex, FileName, JobId,
        P384Spki, PackageId, PartitionLabel, RelPath, SessionId, SignedManifestError, Tag,
        UnixMicros, UrlPath, WimCompression, WimText, codes,
    };
    // -----------------------------------------------------------------------
    // Test doubles (no cryptography)
    // -----------------------------------------------------------------------

    /// FNV-1a over `data`, spread to 32 bytes. Not a cryptographic hash;
    /// enough to show that a changed byte changes the "digest".
    fn fake_sha(data: &[u8]) -> Sha256Digest {
        let mut out = [0u8; 32];
        for (i, chunk) in out.chunks_mut(8).enumerate() {
            let mut h: u64 = 0xcbf2_9ce4_8422_2325 ^ (i as u64);
            for b in data {
                h ^= u64::from(*b);
                h = h.wrapping_mul(0x0000_0100_0000_01b3);
            }
            chunk.copy_from_slice(&h.to_be_bytes());
        }
        Sha256Digest(out)
    }

    fn key(n: u8) -> Sha256Digest {
        Sha256Digest([n; 32])
    }

    /// "Signature" = key id byte || fake digest of the signing input.
    fn fake_sign(k: u8, message: &[u8]) -> Vec<u8> {
        let mut v = vec![k];
        v.extend_from_slice(&fake_sha(message).0);
        v
    }

    struct Keys(Vec<Sha256Digest>);

    impl SignatureVerifier for Keys {
        fn verify(&self, key_id: &Sha256Digest, _: SignatureAlg, msg: &[u8], sig: &[u8]) -> bool {
            self.0.contains(key_id) && sig == fake_sign(key_id.0[0], msg)
        }
    }

    fn seal(ty: PayloadType, payload: Vec<u8>, k: u8) -> SignedEnvelopeV1 {
        let sig = fake_sign(k, &signing_input(ty, &payload));
        let s = SignatureV1::new(key(k), SignatureAlg::EcdsaP384Sha384, sig).unwrap();
        SignedEnvelopeV1::new(ty, payload, vec![s]).unwrap()
    }

    /// Re-wraps an envelope with one payload byte changed, keeping the
    /// original signature.
    fn tamper(env: &SignedEnvelopeV1, at: usize) -> SignedEnvelopeV1 {
        let json = env.to_json().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
        let b64 = v["payload_b64"].as_str().unwrap();
        use base64ct::{Base64, Encoding};
        let mut payload = Base64::decode_vec(b64).unwrap();
        payload[at] ^= 0x01;
        SignedEnvelopeV1::new(env.payload_type(), payload, env.signatures().to_vec()).unwrap()
    }

    const PLAN_KEY: u8 = 11;
    const CONTENT_KEY: u8 = 12;

    // -----------------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------------

    const SESSION: &str = "5a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
    const JOB: &str = "6b2c3d4e-5f60-4b7c-9d8e-0f1a2b3c4d5e";
    const BOOT_SERVICE: &str = "7c3d4e5f-6071-4c8d-ae9f-1a2b3c4d5e6f";
    const PACKAGE: &str = "1c9e8a70-2b3d-4e5f-9a0b-c1d2e3f40516";
    const CONTENT: &str = "0b7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e6f";

    fn mac(n: u8) -> MacAddress {
        MacAddress::new([0x02, 0, 0, 0, 0, n]).unwrap()
    }

    fn disk() -> DiskDescriptorV1 {
        DiskDescriptorV1::new(DiskDescriptorParts {
            disk_token: DiskToken::from_random_bytes([0x5a; 16]),
            bus: Bus::Nvme,
            model: DiskText::sanitized("Example NVMe 1TB"),
            serial: DiskText::sanitized("SN-0001"),
            size_bytes: 1_000_204_886_016,
            logical_sector: 512,
            physical_sector: 4096,
            removable: false,
            partitions: vec![ExistingPartitionV1 {
                index: 1,
                kind: PartitionKind::Basic,
                start_bytes: 1_048_576,
                size_bytes: 500_000_000_000,
                label: PartitionLabel::sanitized("Data"),
            }],
        })
        .unwrap()
    }

    fn content_manifest() -> ContentManifestV1 {
        let size = 3 * CHUNK_SIZE + 17;
        let n = usize::try_from(chunk_count(size)).unwrap();
        ContentManifestV1 {
            schema: 1,
            kind: ContentKind::Image,
            content_id: ContentId::parse(CONTENT).unwrap(),
            display_name: DisplayName::new("Win 11 Ent").unwrap(),
            file_name: usgp_proto::FileName::new("install.wim").unwrap(),
            size,
            sha256: Sha256Digest([0xaa; 32]),
            chunk_size: CHUNK_SIZE,
            chunk_sha256: (0..n).map(|i| Sha256Digest([i as u8; 32])).collect(),
            wim: WimSummaryV1 {
                compression: WimCompression::Xpress,
                image_count: 2,
                boot_index: 0,
                editions: (1..=2u32)
                    .map(|i| ManifestEdition {
                        index: EditionIndex::new(u64::from(i)).unwrap(),
                        name: WimText::new(format!("Edition {i}")).unwrap(),
                        description: WimText::new("d").unwrap(),
                        total_bytes: Some(20_000_000_000 + u64::from(i)),
                    })
                    .collect(),
            },
            ready_at: UnixMicros::new(1_793_000_000_000_000).unwrap(),
            key_id: key(CONTENT_KEY),
        }
    }

    fn content_env() -> SignedEnvelopeV1 {
        seal(
            PayloadType::ContentManifestV1,
            content_manifest().to_payload().unwrap(),
            CONTENT_KEY,
        )
    }

    fn nonce() -> AgentNonce {
        AgentNonce::from_random_bytes([0x42; 32])
    }

    // -----------------------------------------------------------------------
    // M4 fixtures
    // -----------------------------------------------------------------------

    const DRIVER_A: &str = "2d3e4f50-6172-4d8e-9fa0-b1c2d3e4f506";
    const DRIVER_B: &str = "3e4f5061-7283-4e9f-a0b1-c2d3e4f50617";
    const AGENT_PKG: &str = "4f506172-8394-4fa0-b1c2-d3e4f5061728";
    const ANSWER: &[u8] = b"<?xml version=\"1.0\"?><unattend/>";

    fn job_key() -> P384Spki {
        spki(0x31)
    }

    fn escrow_key() -> P384Spki {
        spki(0x32)
    }

    fn spki(fill: u8) -> P384Spki {
        let mut der = vec![
            0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04,
        ];
        der.resize(120, fill);
        P384Spki::from_der(&der).unwrap()
    }

    fn infs() -> Vec<RelPath> {
        vec![RelPath::new("net/e1d.inf").unwrap()]
    }

    /// A v2 (archive) manifest for a driver archive or agent package.
    fn archive_manifest(kind: ContentKindV2, sha: u8) -> ContentManifestV2 {
        let size = CHUNK_SIZE + 9;
        let n = usize::try_from(chunk_count(size)).unwrap();
        ContentManifestV2 {
            schema: 2,
            kind,
            content_id: ContentId::parse(CONTENT).unwrap(),
            display_name: DisplayName::new("archive").unwrap(),
            file_name: usgp_proto::FileName::new("archive.zip").unwrap(),
            size,
            sha256: Sha256Digest([sha; 32]),
            chunk_size: CHUNK_SIZE,
            chunk_sha256: vec![Sha256Digest([sha; 32]); n],
            archive: ArchiveSummaryV1 {
                format: ArchiveFormat::Zip,
                entries: 3,
                expanded_bytes: 70_000,
                infs: match kind {
                    ContentKindV2::DriverArchive => infs(),
                    ContentKindV2::AgentPackage => Vec::new(),
                },
            },
            ready_at: UnixMicros::new(1_793_000_000_000_000).unwrap(),
            key_id: key(CONTENT_KEY),
        }
    }

    fn manifest_env(m: &ContentManifestV2) -> SignedEnvelopeV1 {
        seal(
            PayloadType::ContentManifestV2,
            m.to_payload().unwrap(),
            CONTENT_KEY,
        )
    }

    fn driver_manifests() -> Vec<ContentManifestV2> {
        vec![
            archive_manifest(ContentKindV2::DriverArchive, 0xa1),
            archive_manifest(ContentKindV2::DriverArchive, 0xa2),
        ]
    }

    fn agent_manifest() -> ContentManifestV2 {
        archive_manifest(ContentKindV2::AgentPackage, 0xb1)
    }

    fn sha_of(m: &ContentManifestV2) -> Sha256Digest {
        fake_sha(&m.to_payload().unwrap())
    }

    fn plan2() -> JobPlanV2 {
        let cm_payload = content_manifest().to_payload().unwrap();
        let drivers = driver_manifests();
        JobPlanV2 {
            schema: 2,
            job_id: JobId::parse(JOB).unwrap(),
            session_id: SessionId::parse(SESSION).unwrap(),
            boot_service_id: BootServiceId::parse(BOOT_SERVICE).unwrap(),
            issued_at_us: UnixMicros::new(1_793_000_000_000_123).unwrap(),
            key_id: key(PLAN_KEY),
            agent_nonce: nonce(),
            device: PlanDeviceV1 {
                macs: MacList::new(vec![mac(1)]).unwrap(),
            },
            package: PlanPackageV1 {
                id: PackageId::parse(PACKAGE).unwrap(),
                revision: 3,
                manifest_sha256: Sha256Digest([0xcc; 32]),
            },
            image: PlanImageV1 {
                content_sha256: Sha256Digest([0xaa; 32]),
                size: 3 * CHUNK_SIZE + 17,
                content_manifest_sha256: fake_sha(&cm_payload),
                edition_index: EditionIndex::new(2).unwrap(),
                edition_name: WimText::new("Edition 2").unwrap(),
                total_bytes: 20_000_000_002,
            },
            disk: PlanDiskV1::from(&disk()),
            layout_policy: LayoutPolicyV1::STANDARD,
            wipe: PlanWipeV1 {
                audit_seq: 4242,
                record_hash: Sha256Digest([0xdd; 32]),
                scope: WipeScope::TablesAndVolumeHeads1Mib,
            },
            steps: StepV2::ALL
                .iter()
                .map(|s| PlanStepV2 {
                    step: *s,
                    kind: s.kind(),
                    timeout_s: 3600,
                })
                .collect(),
            retry: RetryPolicyV1 {
                attempts: 5,
                base_ms: 2000,
                max_ms: 60_000,
            },
            stall_timeout_s: 1800,
            report_interval_s: 30,
            answer_file: PlanAnswerFileV2 {
                sha256: fake_sha(ANSWER),
                b64: B64Bytes::new(ANSWER.to_vec()).unwrap(),
            },
            drivers: [DRIVER_A, DRIVER_B]
                .iter()
                .zip(&drivers)
                .map(|(id, m)| PlanDriverV2 {
                    archive_id: DriverArchiveId::parse(id).unwrap(),
                    content_sha256: m.sha256,
                    content_manifest_sha256: sha_of(m),
                    infs: infs(),
                })
                .collect(),
            agent: PlanAgentV2 {
                agent_package_id: AgentPackageId::parse(AGENT_PKG).unwrap(),
                content_sha256: agent_manifest().sha256,
                content_manifest_sha256: sha_of(&agent_manifest()),
            },
            tags: vec![Tag::new("site:hq").unwrap()],
            escrow: Some(PlanEscrowV2 {
                key_id: fake_sha(escrow_key().as_der()),
                spki_b64: escrow_key(),
                account: EscrowAccount::Administrator,
            }),
            job_key_id: fake_sha(job_key().as_der()),
            postsetup: PlanPostSetupV2 {
                resume_url_path: UrlPath::new(format!("/v1/device/jobs/{JOB}/resume")).unwrap(),
            },
        }
    }

    fn plan2_env(p: &JobPlanV2) -> SignedEnvelopeV1 {
        seal(PayloadType::JobPlanV2, p.to_payload().unwrap(), PLAN_KEY)
    }

    struct Envs {
        image: SignedEnvelopeV1,
        drivers: Vec<SignedEnvelopeV1>,
        agent: SignedEnvelopeV1,
    }

    fn envs() -> Envs {
        Envs {
            image: content_env(),
            drivers: driver_manifests().iter().map(manifest_env).collect(),
            agent: manifest_env(&agent_manifest()),
        }
    }

    fn verify2(
        plan: &SignedEnvelopeV1,
        e: &Envs,
        job_key_id: Sha256Digest,
    ) -> Result<VerifiedJobPlanV2, PlanError> {
        let n = nonce();
        let d = disk();
        VerifiedJobPlanV2::verify(
            plan,
            &Keys(vec![key(PLAN_KEY)]),
            &PlanContentV2 {
                image: &e.image,
                drivers: &e.drivers,
                agent: &e.agent,
            },
            &Keys(vec![key(CONTENT_KEY)]),
            &fake_sha,
            &PlanExpectationV2 {
                base: PlanExpectation {
                    agent_nonce: &n,
                    session_id: SessionId::parse(SESSION).unwrap(),
                    job_id: JobId::parse(JOB).unwrap(),
                    package_id: PackageId::parse(PACKAGE).unwrap(),
                    package_revision: 3,
                    disk: &d,
                },
                job_key_id,
            },
        )
    }

    fn good_job_key_id() -> Sha256Digest {
        fake_sha(job_key().as_der())
    }

    // -----------------------------------------------------------------------
    // Job plan v2
    // -----------------------------------------------------------------------

    #[test]
    fn plan2_round_trip_and_open() {
        let p = plan2();
        let payload = p.to_payload().unwrap();
        assert_eq!(JobPlanV2::from_payload(&payload).unwrap(), p);
        let opened = JobPlanV2::open(&plan2_env(&p), &Keys(vec![key(PLAN_KEY)])).unwrap();
        assert_eq!(opened, p);
        // A v2 payload under the v1 type, or a v1 envelope, is refused.
        let as_v1 = seal(PayloadType::JobPlanV1, payload, PLAN_KEY);
        assert!(JobPlanV2::open(&as_v1, &Keys(vec![key(PLAN_KEY)])).is_err());
    }

    #[test]
    fn plan2_has_no_secret_fields() {
        let v: serde_json::Value = serde_json::to_value(plan2()).unwrap();
        let mut ks = Vec::new();
        keys(&v, &mut ks);
        for k in ks {
            let l = k.to_ascii_lowercase();
            // `disk_token` is a random disk name, not a secret (M3).
            assert!(
                l == "disk_token"
                    || !["password", "secret", "credential", "private", "token"]
                        .iter()
                        .any(|w| l.contains(w)),
                "{k}"
            );
        }
    }

    fn keys(v: &serde_json::Value, out: &mut Vec<String>) {
        match v {
            serde_json::Value::Object(m) => {
                for (k, v) in m {
                    out.push(k.clone());
                    keys(v, out);
                }
            }
            serde_json::Value::Array(a) => a.iter().for_each(|v| keys(v, out)),
            _ => {}
        }
    }

    type Mutate2 = Box<dyn Fn(&mut JobPlanV2)>;

    #[test]
    fn plan2_validation_rules() {
        let cases: Vec<(&str, Mutate2)> = vec![
            ("schema", Box::new(|p| p.schema = 1)),
            ("5 steps", Box::new(|p| p.steps.truncate(5))),
            ("kind", Box::new(|p| p.steps[3].kind = p.steps[4].kind)),
            ("timeout", Box::new(|p| p.steps[8].timeout_s = 0)),
            (
                "dup driver",
                Box::new(|p| {
                    let d = p.drivers[0].clone();
                    p.drivers.push(d);
                }),
            ),
            ("no infs", Box::new(|p| p.drivers[0].infs.clear())),
            (
                "not inf",
                Box::new(|p| p.drivers[0].infs = vec![RelPath::new("a.sys").unwrap()]),
            ),
            (
                "too many tags",
                Box::new(|p| p.tags = vec![Tag::new("t").unwrap(); 65]),
            ),
            ("revision", Box::new(|p| p.package.revision = 0)),
            (
                "resume path of another job",
                Box::new(|p| {
                    p.postsetup.resume_url_path =
                        UrlPath::new(format!("/v1/device/jobs/{SESSION}/resume")).unwrap();
                }),
            ),
            (
                "resume path elsewhere",
                Box::new(|p| {
                    p.postsetup.resume_url_path =
                        UrlPath::new(format!("/v1/device/jobs/{JOB}/resume/x")).unwrap();
                }),
            ),
            (
                "resume path upper case",
                Box::new(|p| {
                    p.postsetup.resume_url_path = UrlPath::new(format!(
                        "/v1/device/jobs/{}/resume",
                        JOB.to_ascii_uppercase()
                    ))
                    .unwrap();
                }),
            ),
        ];
        for (name, m) in cases {
            let mut p = plan2();
            m(&mut p);
            assert!(p.validate().is_err(), "{name}");
            assert!(p.to_payload().is_err(), "{name}");
        }
        let mut p = plan2();
        p.escrow = None;
        p.drivers.clear();
        p.tags.clear();
        assert!(p.validate().is_ok());
    }

    #[test]
    fn plan2_strict_parse() {
        let mut v: serde_json::Value = serde_json::to_value(plan2()).unwrap();
        v["extra"] = serde_json::json!(1);
        assert!(JobPlanV2::from_payload(v.to_string().as_bytes()).is_err());
        let mut v: serde_json::Value = serde_json::to_value(plan2()).unwrap();
        v["escrow"]["account"] = serde_json::json!("guest");
        assert!(JobPlanV2::from_payload(v.to_string().as_bytes()).is_err());
        let mut v: serde_json::Value = serde_json::to_value(plan2()).unwrap();
        v["job_key_id"] = serde_json::Value::Null;
        assert!(JobPlanV2::from_payload(v.to_string().as_bytes()).is_err());
        let mut v: serde_json::Value = serde_json::to_value(plan2()).unwrap();
        v["postsetup"]["resume_url_path"] = serde_json::json!("/a/../b");
        assert!(JobPlanV2::from_payload(v.to_string().as_bytes()).is_err());
        let mut v: serde_json::Value = serde_json::to_value(plan2()).unwrap();
        v["answer_file"]["b64"] = serde_json::json!("");
        assert!(JobPlanV2::from_payload(v.to_string().as_bytes()).is_err());
        assert!(matches!(
            JobPlanV2::from_payload(b"{\"schema\":2}"),
            Err(SignedManifestError::Json(_))
        ));
    }

    #[test]
    fn verified_plan2_accepts_matching() {
        let v = verify2(&plan2_env(&plan2()), &envs(), good_job_key_id()).unwrap();
        assert_eq!(v.plan(), &plan2());
        assert_eq!(v.driver_manifests(), driver_manifests().as_slice());
        assert_eq!(v.agent_manifest(), &agent_manifest());
        assert_eq!(v.content_manifest(), &content_manifest());
    }

    #[test]
    fn verified_plan2_refusals() {
        let env = plan2_env(&plan2());

        let e = verify2(&tamper(&env, 40), &envs(), good_job_key_id()).unwrap_err();
        assert_eq!(e.code(), codes::PLAN_SIGNATURE_INVALID);

        let e = verify2(&env, &envs(), Sha256Digest([0; 32])).unwrap_err();
        assert!(matches!(e, PlanError::JobKeyMismatch), "{e:?}");
        assert_eq!(e.code(), codes::JOB_KEY_MISMATCH);

        let mut p = plan2();
        p.escrow.as_mut().unwrap().key_id = Sha256Digest([1; 32]);
        let e = verify2(&plan2_env(&p), &envs(), good_job_key_id()).unwrap_err();
        assert!(matches!(e, PlanError::EscrowKeyIdMismatch), "{e:?}");

        let mut p = plan2();
        p.answer_file.sha256 = Sha256Digest([1; 32]);
        let e = verify2(&plan2_env(&p), &envs(), good_job_key_id()).unwrap_err();
        assert!(matches!(e, PlanError::AnswerFileDigest), "{e:?}");

        let mut e2 = envs();
        e2.drivers.pop();
        let e = verify2(&env, &e2, good_job_key_id()).unwrap_err();
        assert!(matches!(e, PlanError::DriverManifestCount), "{e:?}");

        let mut e2 = envs();
        e2.drivers.swap(0, 1);
        let e = verify2(&env, &e2, good_job_key_id()).unwrap_err();
        assert!(matches!(e, PlanError::ContentManifestDigest), "{e:?}");

        let mut e2 = envs();
        e2.agent = tamper(&e2.agent, 10);
        let e = verify2(&env, &e2, good_job_key_id()).unwrap_err();
        assert!(matches!(e, PlanError::ContentManifest(_)), "{e:?}");

        // Manifest digest right but file SHA-256 different from the plan.
        let mut p = plan2();
        p.agent.content_sha256 = Sha256Digest([9; 32]);
        let e = verify2(&plan2_env(&p), &envs(), good_job_key_id()).unwrap_err();
        assert!(matches!(e, PlanError::ContentMismatch(_)), "{e:?}");
        assert_eq!(e.code(), codes::CONTENT_MANIFEST_MISMATCH);
    }

    /// Re-signs the plan so that drivers and agent point at `drivers` and
    /// `agent`, and returns the plan envelope and the content envelopes.
    fn rebind(
        drivers: &[ContentManifestV2],
        agent: &ContentManifestV2,
    ) -> (SignedEnvelopeV1, Envs) {
        let mut p = plan2();
        for (d, m) in p.drivers.iter_mut().zip(drivers) {
            d.content_sha256 = m.sha256;
            d.content_manifest_sha256 = sha_of(m);
        }
        p.agent.content_sha256 = agent.sha256;
        p.agent.content_manifest_sha256 = sha_of(agent);
        let e = Envs {
            image: content_env(),
            drivers: drivers.iter().map(manifest_env).collect(),
            agent: manifest_env(agent),
        };
        (plan2_env(&p), e)
    }

    #[test]
    fn verified_plan2_checks_archive_manifests() {
        // Control: rebinding the good manifests still verifies.
        let (env, e) = rebind(&driver_manifests(), &agent_manifest());
        assert!(verify2(&env, &e, good_job_key_id()).is_ok());

        // A driver slot holding an agent-package manifest.
        let mut ds = driver_manifests();
        ds[1] = archive_manifest(ContentKindV2::AgentPackage, 0xa2);
        let (env, e) = rebind(&ds, &agent_manifest());
        let err = verify2(&env, &e, good_job_key_id()).unwrap_err();
        assert!(
            matches!(err, PlanError::ContentMismatch("drivers[].kind")),
            "{err:?}"
        );

        // The agent slot holding a driver-archive manifest.
        let ag = archive_manifest(ContentKindV2::DriverArchive, 0xb1);
        let (env, e) = rebind(&driver_manifests(), &ag);
        let err = verify2(&env, &e, good_job_key_id()).unwrap_err();
        assert!(
            matches!(err, PlanError::ContentMismatch("agent.kind")),
            "{err:?}"
        );

        // A driver manifest whose INF list is not the plan's.
        for other in [
            vec![RelPath::new("net/other.inf").unwrap()],
            vec![
                RelPath::new("net/e1d.inf").unwrap(),
                RelPath::new("x.inf").unwrap(),
            ],
        ] {
            let mut ds = driver_manifests();
            ds[0].archive.infs = other;
            let (env, e) = rebind(&ds, &agent_manifest());
            let err = verify2(&env, &e, good_job_key_id()).unwrap_err();
            assert!(
                matches!(err, PlanError::ContentMismatch("drivers[].infs")),
                "{err:?}"
            );
        }

        // An archive manifest signed under the v1 payload type is refused,
        // and so is an image (v1) manifest in an archive slot.
        let mut e = envs();
        e.drivers[0] = seal(
            PayloadType::ContentManifestV1,
            driver_manifests()[0].to_payload().unwrap(),
            CONTENT_KEY,
        );
        let err = verify2(&plan2_env(&plan2()), &e, good_job_key_id()).unwrap_err();
        assert!(matches!(err, PlanError::ContentManifest(_)), "{err:?}");
        let mut e = envs();
        e.agent = content_env();
        let err = verify2(&plan2_env(&plan2()), &e, good_job_key_id()).unwrap_err();
        assert!(matches!(err, PlanError::ContentManifest(_)), "{err:?}");

        // An archive manifest in the image slot is refused.
        let mut e = envs();
        e.image = manifest_env(&agent_manifest());
        let err = verify2(&plan2_env(&plan2()), &e, good_job_key_id()).unwrap_err();
        assert!(matches!(err, PlanError::ContentManifest(_)), "{err:?}");
    }

    #[test]
    fn content_manifest_v2_open() {
        let m = agent_manifest();
        let k = Keys(vec![key(CONTENT_KEY)]);
        assert_eq!(ContentManifestV2::open(&manifest_env(&m), &k).unwrap(), m);
        assert!(ContentManifestV1::open(&manifest_env(&m), &k).is_err());
    }

    // -----------------------------------------------------------------------
    // Confirm v2
    // -----------------------------------------------------------------------

    #[test]
    fn confirm_v2_requires_job_key() {
        let base = format!(
            r#""package_id":"{PACKAGE}","revision":3,"disk_token":"{}","confirm":"wipe-disk","agent_nonce":"{}""#,
            DiskToken::from_random_bytes([0x5a; 16]),
            nonce()
        );
        let ok = format!(r#"{{{base},"job_key_spki_b64":"{}"}}"#, job_key());
        let c: ConfirmV2 = serde_json::from_str(&ok).unwrap();
        assert_eq!(c.job_key_spki_b64, job_key());
        let back = serde_json::to_string(&c).unwrap();
        assert_eq!(serde_json::from_str::<ConfirmV2>(&back).unwrap(), c);
        assert!(serde_json::from_str::<ConfirmV2>(&format!("{{{base}}}")).is_err());
        let bad = format!(
            r#"{{{base},"job_key_spki_b64":"{}"}}"#,
            Base64::encode_string(&[0u8; 120])
        );
        assert!(serde_json::from_str::<ConfirmV2>(&bad).is_err());
    }

    #[test]
    fn confirmed_v2_round_trip() {
        let e = envs();
        let c = ConfirmedV2 {
            job_id: JobId::parse(JOB).unwrap(),
            plan: plan2_env(&plan2()),
            content_manifest: e.image,
            driver_manifests: e.drivers,
            agent_manifest: e.agent,
        };
        let j = serde_json::to_vec(&c).unwrap();
        assert_eq!(ConfirmedV2::from_json(&j).unwrap(), c);
        // The 64 MiB cap: a named error before parsing. Just under the
        // cap is parsed (whitespace padding is valid JSON).
        let cap = usgp_proto::limits::MAX_CONFIRM_V2_RESPONSE_BYTES;
        assert_eq!(cap, 64 * 1024 * 1024);
        let mut ok = j.clone();
        ok.resize(cap, b' ');
        assert_eq!(ConfirmedV2::from_json(&ok).unwrap(), c);
        let mut big = j.clone();
        big.resize(cap + 1, b' ');
        assert!(matches!(
            ConfirmedV2::from_json(&big),
            Err(usgp_proto::device::ConfirmedError::V2TooLarge { len }) if len == cap + 1
        ));
    }

    // -----------------------------------------------------------------------
    // Post-setup job.json
    // -----------------------------------------------------------------------

    type MutateCfg = Box<dyn Fn(&mut PostSetupConfigV1)>;

    fn postsetup() -> PostSetupConfigV1 {
        PostSetupConfigV1 {
            schema: 1,
            server_url: "https://provision.example.gov:8444".into(),
            server_name: "provision.example.gov".into(),
            trust_anchors_pem: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
                .into(),
            plan_key_pem: "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n".into(),
            plan: plan2_env(&plan2()),
            job_id: JobId::parse(JOB).unwrap(),
            agent_sha256: Sha256Digest([0x77; 32]),
            agent_package_file: FileName::new("agent-package.zip").unwrap(),
            job_key_file: FileName::new("job.key").unwrap(),
        }
    }

    #[test]
    fn postsetup_round_trip_and_rules() {
        let c = postsetup();
        let j = c.to_json().unwrap();
        assert_eq!(PostSetupConfigV1::from_json(&j).unwrap(), c);

        let cases: Vec<(&str, MutateCfg)> = vec![
            ("schema", Box::new(|c| c.schema = 2)),
            (
                "http",
                Box::new(|c| c.server_url = "http://x.example".into()),
            ),
            ("name", Box::new(|c| c.server_name = "bad name".into())),
            ("anchors", Box::new(|c| c.trust_anchors_pem = "x".into())),
            (
                "private",
                Box::new(|c| {
                    c.plan_key_pem.push_str("-----BEGIN PRIVATE KEY-----\n");
                }),
            ),
            (
                "v1 plan",
                Box::new(|c| {
                    c.plan = seal(PayloadType::JobPlanV1, b"{}".to_vec(), PLAN_KEY);
                }),
            ),
            (
                "same file",
                Box::new(|c| c.job_key_file = c.agent_package_file.clone()),
            ),
        ];
        for (name, m) in cases {
            let mut c = postsetup();
            m(&mut c);
            assert!(c.validate().is_err(), "{name}");
        }
        let mut v: serde_json::Value = serde_json::from_slice(&j).unwrap();
        v["job_key_file"] = serde_json::json!("..\\job.key");
        assert!(PostSetupConfigV1::from_json(v.to_string().as_bytes()).is_err());
        v["job_key_file"] = serde_json::json!("job.key");
        v["password"] = serde_json::json!("x");
        assert!(PostSetupConfigV1::from_json(v.to_string().as_bytes()).is_err());
    }
}
