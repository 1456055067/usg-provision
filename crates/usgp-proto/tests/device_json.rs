//! M3 wire and signed types: device session bodies, disk descriptors,
//! progress reports, the signed job plan and boot-policy list, and the
//! operator additions. Round trips, strict parsing (unknown fields and
//! values), size limits, tampering, and the absence of secret and content
//! fields (plan WU-2, section 8 rows TGT-015, DISK-016, JOB-014).
//!
//! No cryptography here: the verifier and the digest are test doubles
//! (keyed checksums) so that a changed byte is detected. Real ECDSA and
//! SHA-256 are in `usgp-crypto` and are exercised by its own tests and by
//! the agent and server tests.

// COMPLIANCE MAPPING:
// - NIST 800-53: SA-11 (Developer Testing and Evaluation), SI-10 (Input
//   Validation), SI-7(6) (signed plan and policy, tamper refused),
//   SC-23 (plan bound to session, job and nonce; policy rollback refused)
// - SPEC: specs/targeting.md#REQ-TGT-006, #REQ-TGT-013, #REQ-TGT-015
// - SPEC: specs/disk.md#REQ-DISK-006, #REQ-DISK-016
// - SPEC: specs/progress.md#REQ-JOB-005, #REQ-JOB-008, #REQ-JOB-012,
//   #REQ-JOB-014
// - SPEC: specs/preinstall-env.md#REQ-PE-016
// - SPEC: specs/boot-network.md#REQ-BOOT-067

#[cfg(test)]
mod device_json {
    use usgp_common::Sha256Digest;
    use usgp_proto::api::{ErrorBody, Message, RequestError, parse_request};
    use usgp_proto::boot_policy::{BootPolicyError, BootPolicyV1, BootStopEntryV1};
    use usgp_proto::content_manifest::{
        ContentManifestV1, ManifestEdition, WimSummaryV1, chunk_count,
    };
    use usgp_proto::device::{
        AgentNonce, AuthCode, CancelV1, ChooseDiskV1, ChoosePackageV1, CodeSubmitV1, ConfirmV1,
        ConfirmedError, ConfirmedV1, DeviceHelloV1, DevicePackageListV1, DisplayCode, EndSessionV1,
        MacAddress, MacList, SessionOpenedV1, SessionState, SessionStatusV1, SessionToken,
        WipeConfirmation,
    };
    use usgp_proto::disk::{
        Bus, DiskDescriptorParts, DiskDescriptorV1, DiskGuid, DiskToken, ExistingPartitionV1,
        FileSystem, LayoutReportV1, PartitionKind, PlanDiskV1, WrittenPartitionV1,
    };
    use usgp_proto::envelope::{
        PayloadType, SignatureAlg, SignatureV1, SignatureVerifier, SignedEnvelopeV1, signing_input,
    };
    use usgp_proto::job_plan::{
        JobPlanV1, LayoutPolicyV1, PlanDeviceV1, PlanError, PlanExpectation, PlanImageV1,
        PlanPackageV1, PlanStepV1, PlanWipeV1, RetryPolicyV1, VerifiedJobPlan, WipeScope,
    };
    use usgp_proto::limits::{
        CHUNK_SIZE, MAX_BOOT_STOPS, MAX_CONFIRM_RESPONSE_BYTES, MAX_DEVICE_JSON_BYTES,
        MAX_MANIFEST_PAYLOAD_BYTES,
    };
    use usgp_proto::ops::{AuthCodeIssuedV1, AuthCodeList, BootServiceView, JobView};
    use usgp_proto::progress::{
        FailureCategory, FailureV1, JobState, ProgressEvent, ProgressV1, Step,
    };
    use usgp_proto::{
        AuthCodeId, BootServiceId, ContentId, ContentKind, DiskText, DisplayName, EditionIndex,
        JobId, PackageId, PartitionLabel, SessionId, SignedManifestError, UnixMicros,
        WimCompression, WimText, codes,
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
    const POLICY_KEY: u8 = 13;

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

    fn plan() -> JobPlanV1 {
        let cm_payload = content_manifest().to_payload().unwrap();
        JobPlanV1 {
            schema: 1,
            job_id: JobId::parse(JOB).unwrap(),
            session_id: SessionId::parse(SESSION).unwrap(),
            boot_service_id: BootServiceId::parse(BOOT_SERVICE).unwrap(),
            issued_at_us: UnixMicros::new(1_793_000_000_000_123).unwrap(),
            key_id: key(PLAN_KEY),
            agent_nonce: nonce(),
            device: PlanDeviceV1 {
                macs: MacList::new(vec![mac(1), mac(2)]).unwrap(),
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
            steps: Step::ALL
                .iter()
                .map(|s| PlanStepV1 {
                    step: *s,
                    kind: s.kind(),
                    timeout_s: 21_600,
                })
                .collect(),
            retry: RetryPolicyV1 {
                attempts: 5,
                base_ms: 2000,
                max_ms: 60_000,
            },
            stall_timeout_s: 1800,
            report_interval_s: 30,
        }
    }

    fn plan_env(p: &JobPlanV1) -> SignedEnvelopeV1 {
        seal(PayloadType::JobPlanV1, p.to_payload().unwrap(), PLAN_KEY)
    }

    fn parse<T: serde::de::DeserializeOwned>(json: &str) -> Result<T, RequestError> {
        parse_request(json.as_bytes(), MAX_DEVICE_JSON_BYTES)
    }

    /// Every object key anywhere in a JSON value.
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

    /// Words that would name a secret field (REQ-TGT-015, REQ-JOB-014).
    /// `disk_token` is a random per-enumeration disk name, not a secret.
    fn secret_like(k: &str) -> bool {
        let k = k.to_ascii_lowercase();
        if k == "disk_token" {
            return false;
        }
        [
            "token",
            "password",
            "secret",
            "credential",
            "code",
            "private",
        ]
        .iter()
        .any(|w| k.contains(w))
            || (k.contains("key") && k != "key_id")
    }

    // -----------------------------------------------------------------------
    // Session open and status
    // -----------------------------------------------------------------------

    const HELLO: &str = r#"{"schema":1,"agent_version":"0.3.0","firmware":"uefi","arch":"x64","secure_boot":"on","memory_bytes":8589934592,"macs":["02:00:00:00:00:01","02:00:00:00:00:02"]}"#;

    #[test]
    fn hello_round_trip_and_strictness() {
        let h: DeviceHelloV1 = parse(HELLO).unwrap();
        assert_eq!(h.macs.as_slice(), &[mac(1), mac(2)]);
        assert_eq!(serde_json::to_string(&h).unwrap(), HELLO);
        for bad in [
            HELLO.replace("\"schema\":1", "\"schema\":2"),
            HELLO.replace("\"uefi\"", "\"UEFI\""),
            HELLO.replace("\"x64\"", "\"amd64\""),
            HELLO.replace("\"on\"", "\"yes\""),
            HELLO.replace("02:00:00:00:00:02", "03:00:00:00:00:02"),
            HELLO.replace("02:00:00:00:00:02", "02:00:00:00:00:01"),
            HELLO.replace("[\"02:00:00:00:00:01\",\"02:00:00:00:00:02\"]", "[]"),
            HELLO.replace("\"0.3.0\"", "\"0.3.0\\n\""),
            HELLO.replace("{\"schema\":1,", "{\"schema\":1,\"hostname\":\"x\","),
            HELLO.replace("{\"schema\":1,", "{\"schema\":1,\"schema\":1,"),
            HELLO.replace(",\"memory_bytes\":8589934592", ""),
            format!("{HELLO}x"),
        ] {
            assert!(parse::<DeviceHelloV1>(&bad).is_err(), "{bad}");
        }
        let macs: Vec<String> = (1..=17)
            .map(|i| format!("\"02:00:00:00:00:{i:02x}\""))
            .collect();
        let many = HELLO.replace(
            "[\"02:00:00:00:00:01\",\"02:00:00:00:00:02\"]",
            &format!("[{}]", macs.join(",")),
        );
        assert!(parse::<DeviceHelloV1>(&many).is_err());
    }

    #[test]
    fn body_size_limit() {
        let big = format!("{{\"x\":\"{}\"}}", "a".repeat(MAX_DEVICE_JSON_BYTES));
        assert!(matches!(
            parse::<CancelV1>(&big),
            Err(RequestError::TooLarge { .. })
        ));
        let oversize = vec![b' '; MAX_CONFIRM_RESPONSE_BYTES + 1];
        assert!(matches!(
            ConfirmedV1::from_json(&oversize),
            Err(ConfirmedError::TooLarge { .. })
        ));
    }

    #[test]
    fn session_opened_carries_token_only_in_body() {
        let opened = SessionOpenedV1 {
            session_id: SessionId::parse(SESSION).unwrap(),
            token: SessionToken::from_random_bytes(&[0x33; 32]),
            display_code: DisplayCode::from_random_bytes([1, 2, 3, 4]),
            state: SessionState::AwaitingAuthorisation,
            poll_ms: 2000,
            expires_at: UnixMicros::new(1_793_000_003_600_000).unwrap(),
        };
        let token_text = opened.token.expose().to_owned();
        let body = opened.to_json_zeroizing().unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains(&token_text));
        assert!(!format!("{opened:?}").contains(&token_text));
        let back: SessionOpenedV1 = serde_json::from_slice(&body).unwrap();
        assert_eq!(back.token.expose(), token_text);
        assert_eq!(back.display_code, opened.display_code);
        let bad = text.replace(&token_text, &"A".repeat(42));
        assert!(serde_json::from_str::<SessionOpenedV1>(&bad).is_err());
    }

    #[test]
    fn status_round_trip() {
        let json = r#"{"state":"authorised","display_code":"AB1-X9Z","code_attempts_left":5,"expires_at":1793000003600000,"boot_service_name":"Bench"}"#;
        let s: SessionStatusV1 = parse(json).unwrap();
        assert_eq!(serde_json::to_string(&s).unwrap(), json);
        assert!(parse::<SessionStatusV1>(&json.replace("authorised", "authorized")).is_err());
        let with_reason = json.replace(
            "\"boot_service_name\":\"Bench\"",
            "\"reason_code\":\"session_refused\"",
        );
        let s: SessionStatusV1 = parse(&with_reason).unwrap();
        assert_eq!(s.reason_code, Some(codes::SESSION_REFUSED));
    }

    #[test]
    fn code_submit_normalises_and_redacts() {
        let c: CodeSubmitV1 = parse(r#"{"code":"abcde-fghjk"}"#).unwrap();
        assert_eq!(c.code.normalized(), "ABCDEFGHJK");
        assert!(!format!("{c:?}").contains("ABCDE"));
        let body = c.to_json_zeroizing().unwrap();
        assert_eq!(&body[..], br#"{"code":"ABCDE-FGHJK"}"#);
        // Crockford aliases and spaces normalise; output stays canonical.
        let c: CodeSubmitV1 = parse(r#"{"code":"abcde fghjo"}"#).unwrap();
        assert_eq!(c.code.normalized(), "ABCDEFGHJ0");
        assert_eq!(c.code.grouped().as_str(), "ABCDE-FGHJ0");
        for bad in [
            r#"{"code":"abcde-fghj"}"#,
            r#"{"code":"abcde-fghju"}"#,
            r#"{"code":"abcde_fghjk"}"#,
            r#"{"code":"abcde-fghjk","x":1}"#,
            r#"{"code":1234567890}"#,
            r#"{}"#,
        ] {
            assert!(parse::<CodeSubmitV1>(bad).is_err(), "{bad}");
        }
        // The refusal error never contains the value typed.
        let e = parse::<CodeSubmitV1>(r#"{"code":"SECRETCODEX"}"#).unwrap_err();
        assert!(!e.to_string().contains("SECRETCODEX"));
    }

    #[test]
    fn code_refusal_body_has_attempts_left() {
        let mut b = ErrorBody::new(
            codes::CODE_NOT_ACCEPTED,
            Message::new("The code was not accepted.").unwrap(),
        );
        b.error.attempts_left = Some(3);
        let json = serde_json::to_string(&b).unwrap();
        assert_eq!(
            json,
            r#"{"error":{"code":"code_not_accepted","message":"The code was not accepted.","attempts_left":3}}"#
        );
        assert_eq!(serde_json::from_str::<ErrorBody>(&json).unwrap(), b);
    }

    // -----------------------------------------------------------------------
    // Packages and choices
    // -----------------------------------------------------------------------

    fn pkg_json(id: &str, rev: u64) -> String {
        format!(
            r#"{{"package_id":"{id}","revision":{rev},"name":"Field laptops","description":"Win 11","os":{{"release":"windows-11","edition":"enterprise","architecture":"x64","source":"declared"}},"image_bytes":5000000000,"required_disk_bytes":64000000000}}"#
        )
    }

    #[test]
    fn package_list() {
        let json = format!("{{\"packages\":[{}]}}", pkg_json(PACKAGE, 3));
        let l: DevicePackageListV1 = parse(&json).unwrap();
        assert_eq!(serde_json::to_string(&l).unwrap(), json);
        let id = PackageId::parse(PACKAGE).unwrap();
        assert!(l.find(id, 3).is_some());
        assert!(l.find(id, 2).is_none());
        assert!(parse::<DevicePackageListV1>("{\"packages\":[]}").is_ok());
        let dup = format!(
            "{{\"packages\":[{},{}]}}",
            pkg_json(PACKAGE, 3),
            pkg_json(PACKAGE, 4)
        );
        assert!(parse::<DevicePackageListV1>(&dup).is_err());
        let rev0 = format!("{{\"packages\":[{}]}}", pkg_json(PACKAGE, 0));
        assert!(parse::<DevicePackageListV1>(&rev0).is_err());
        let extra = json.replace("\"image_bytes\"", "\"secret\":\"x\",\"image_bytes\"");
        assert!(parse::<DevicePackageListV1>(&extra).is_err());
        let many: Vec<String> = (0..257u32)
            .map(|i| {
                let id = PackageId::from_random_bytes([
                    1,
                    2,
                    3,
                    4,
                    5,
                    6,
                    7,
                    8,
                    9,
                    10,
                    11,
                    12,
                    0,
                    0,
                    (i >> 8) as u8,
                    i as u8,
                ]);
                pkg_json(&id.to_string(), 1)
            })
            .collect();
        let big = format!("{{\"packages\":[{}]}}", many.join(","));
        assert!(
            serde_json::from_str::<DevicePackageListV1>(&big).is_err(),
            "257 packages"
        );
    }

    #[test]
    fn choose_package() {
        let j = format!(r#"{{"package_id":"{PACKAGE}","revision":3}}"#);
        let c: ChoosePackageV1 = parse(&j).unwrap();
        assert_eq!(c.revision, 3);
        assert!(parse::<ChoosePackageV1>(&j.replace(":3", ":0")).is_err());
        assert!(parse::<ChoosePackageV1>(&j.replace("}", ",\"x\":1}")).is_err());
    }

    #[test]
    fn disk_descriptor_round_trip() {
        let body = ChooseDiskV1 { disk: disk() };
        let json = serde_json::to_string(&body).unwrap();
        let back: ChooseDiskV1 = parse(&json).unwrap();
        assert_eq!(back, body);
        // Too-large partition, removed sector size, bad token, unknown bus.
        for bad in [
            json.replace(
                "\"size_bytes\":500000000000",
                "\"size_bytes\":1000204886016",
            ),
            json.replace("\"logical_sector\":512", "\"logical_sector\":520"),
            json.replace(&"5a".repeat(16), &"5A".repeat(16)),
            json.replace("\"nvme\"", "\"thunderbolt\""),
            json.replace("\"Example NVMe 1TB\"", "\"Example\\u0007\""),
            json.replace("\"Example NVMe 1TB\"", &format!("\"{}\"", "M".repeat(65))),
            json.replace("\"Data\"", &format!("\"{}\"", "L".repeat(33))),
            json.replace("\"kind\":\"basic\"", "\"kind\":\"ntfs\""),
        ] {
            assert!(parse::<ChooseDiskV1>(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn disk_descriptor_has_no_content_fields() {
        // REQ-DISK-016: the descriptor's fields are only what describes the
        // disk; anything else (file names, content, volume data) is
        // refused.
        let v = serde_json::to_value(disk()).unwrap();
        let mut k = Vec::new();
        keys(&v, &mut k);
        k.sort();
        k.dedup();
        assert_eq!(
            k,
            [
                "bus",
                "disk_token",
                "index",
                "kind",
                "label",
                "logical_sector",
                "model",
                "partitions",
                "physical_sector",
                "removable",
                "serial",
                "size_bytes",
                "start_bytes",
            ]
        );
        let json = serde_json::to_string(&disk()).unwrap();
        for field in ["files", "content", "volume_label", "boot_sector"] {
            let extra = json.replacen('{', &format!("{{\"{field}\":[],"), 1);
            assert!(serde_json::from_str::<DiskDescriptorV1>(&extra).is_err());
            let in_part = json.replace("\"index\":1", &format!("\"{field}\":\"x\",\"index\":1"));
            assert!(serde_json::from_str::<DiskDescriptorV1>(&in_part).is_err());
        }
    }

    #[test]
    fn confirm_requires_explicit_wipe_value() {
        let n = nonce().to_string();
        let tok = "5a".repeat(16);
        let j = format!(
            r#"{{"package_id":"{PACKAGE}","revision":3,"disk_token":"{tok}","confirm":"wipe-disk","agent_nonce":"{n}"}}"#
        );
        let c: ConfirmV1 = parse(&j).unwrap();
        assert_eq!(c.confirm, WipeConfirmation::WipeDisk);
        assert_eq!(c.agent_nonce, nonce());
        assert_eq!(serde_json::to_string(&c).unwrap(), j);
        for bad in [
            j.replace("wipe-disk", "yes"),
            j.replace("wipe-disk", "WIPE-DISK"),
            j.replace(",\"confirm\":\"wipe-disk\"", ""),
            j.replace(&n, &n[..43]),
            j.replace(":3,", ":0,"),
            j.replace("}", ",\"skip_confirm\":true}"),
        ] {
            assert!(parse::<ConfirmV1>(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn confirmed_round_trip() {
        let c = ConfirmedV1 {
            job_id: JobId::parse(JOB).unwrap(),
            plan: plan_env(&plan()),
            content_manifest: content_env(),
        };
        let json = serde_json::to_vec(&c).unwrap();
        assert_eq!(ConfirmedV1::from_json(&json).unwrap(), c);
        let mut extra = json.clone();
        extra.pop();
        extra.extend_from_slice(b",\"x\":1}");
        assert!(ConfirmedV1::from_json(&extra).is_err());
    }

    #[test]
    fn cancel_and_end() {
        assert!(parse::<CancelV1>("{}").is_ok());
        assert!(parse::<CancelV1>("{\"x\":1}").is_err());
        assert!(parse::<CancelV1>("[]").is_err());
        let e: EndSessionV1 = parse(r#"{"reason":"nothing_to_offer"}"#).unwrap();
        assert!(e.refused_disks.is_empty());
        assert_eq!(
            serde_json::to_string(&e).unwrap(),
            r#"{"reason":"nothing_to_offer"}"#
        );
        let one = r#"{"bus":"usb","size_bytes":32000000000,"reason":"usb_disk"}"#;
        let j = format!(r#"{{"reason":"no_disk","refused_disks":[{one}]}}"#);
        let e: EndSessionV1 = parse(&j).unwrap();
        assert_eq!(e.refused_disks.len(), 1);
        let too_many = format!(
            r#"{{"reason":"no_disk","refused_disks":[{}]}}"#,
            vec![one; 33].join(",")
        );
        assert!(parse::<EndSessionV1>(&too_many).is_err());
        assert!(parse::<EndSessionV1>(r#"{"reason":"bored"}"#).is_err());
        assert!(parse::<EndSessionV1>(&j.replace("usb_disk", "looks_fine")).is_err());
        assert!(parse::<EndSessionV1>(&j.replace("\"bus\"", "\"model\":\"x\",\"bus\"")).is_err());
    }

    // -----------------------------------------------------------------------
    // Progress
    // -----------------------------------------------------------------------

    fn layout() -> LayoutReportV1 {
        LayoutReportV1::new(
            vec![
                WrittenPartitionV1 {
                    index: 1,
                    kind: PartitionKind::Esp,
                    start_bytes: 1 << 20,
                    size_bytes: 200 << 20,
                    fs: Some(FileSystem::Fat32),
                    label: PartitionLabel::sanitized("System"),
                },
                WrittenPartitionV1 {
                    index: 2,
                    kind: PartitionKind::Msr,
                    start_bytes: 201 << 20,
                    size_bytes: 16 << 20,
                    fs: None,
                    label: None,
                },
            ],
            DiskGuid::parse("0b7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e6f").unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn progress_round_trips() {
        let p = ProgressV1 {
            seq: 7,
            step: Step::PARTITION_FORMAT,
            event: ProgressEvent::StepCompleted,
            bytes_done: None,
            bytes_total: None,
            item: None,
            layout: Some(layout()),
            failure: None,
        };
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(parse::<ProgressV1>(&json).unwrap(), p);
        assert!(!json.contains("null"));

        let dl = r#"{"seq":2,"step":1,"event":"progress","bytes_done":10,"bytes_total":100,"item":{"role":"image","name":"install.wim"}}"#;
        let p: ProgressV1 = parse(dl).unwrap();
        assert_eq!(serde_json::to_string(&p).unwrap(), dl);
    }

    #[test]
    fn progress_rules() {
        let fail = r#"{"seq":9,"step":1,"event":"failed","failure":{"step":1,"category":"integrity","code":"chunk_digest_mismatch","files":[{"role":"image","name":"install.wim"}],"count":1,"attempts":1}}"#;
        let p: ProgressV1 = parse(fail).unwrap();
        let f = p.failure.as_ref().unwrap();
        assert_eq!(f.category, FailureCategory::Integrity);
        assert_eq!(f.code, codes::CHUNK_DIGEST_MISMATCH);
        assert_eq!(serde_json::to_string(&p).unwrap(), fail);

        let file = r#"{"role":"image","name":"install.wim"}"#;
        let files33 = vec![file; 33].join(",");
        for bad in [
            // failed without a failure; failure on another event
            r#"{"seq":9,"step":1,"event":"failed"}"#.to_owned(),
            fail.replace("\"event\":\"failed\"", "\"event\":\"progress\""),
            // failure for another step
            fail.replace("\"failure\":{\"step\":1", "\"failure\":{\"step\":2"),
            // count below files, attempts 0, too many files
            fail.replace("\"count\":1", "\"count\":0"),
            fail.replace("\"attempts\":1", "\"attempts\":0"),
            fail.replace(file, &files33),
            // unknown category, unknown event, step 6, seq 0
            fail.replace("integrity", "cosmic"),
            fail.replace("\"failed\",\"failure\"", "\"crashed\",\"failure\""),
            fail.replace("\"step\":1,\"event\"", "\"step\":6,\"event\""),
            fail.replace("\"seq\":9", "\"seq\":0"),
            // a bad code, an unknown field in a file item
            fail.replace("chunk_digest_mismatch", "Chunk Mismatch"),
            fail.replace(
                "\"name\":\"install.wim\"",
                "\"name\":\"install.wim\",\"bytes\":\"AAAA\"",
            ),
            r#"{"seq":2,"step":1,"event":"progress","bytes_done":101,"bytes_total":100}"#
                .to_owned(),
            r#"{"seq":2,"step":1,"event":"progress","item":{"role":"image","name":"a\nb"}}"#
                .to_owned(),
        ] {
            assert!(parse::<ProgressV1>(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn failure_has_no_secret_fields() {
        // REQ-JOB-014: the failure shape has no field that could hold a
        // secret value.
        let f = FailureV1 {
            step: Step::APPLY_IMAGE,
            category: FailureCategory::Network,
            code: codes::RETRIES_EXHAUSTED,
            files: vec![],
            count: 0,
            attempts: 5,
        };
        let v = serde_json::to_value(&f).unwrap();
        let mut k = Vec::new();
        keys(&v, &mut k);
        assert!(k.iter().all(|k| !secret_like(k) || k == "code"), "{k:?}");
    }

    // -----------------------------------------------------------------------
    // Job plan
    // -----------------------------------------------------------------------

    #[test]
    fn plan_round_trip_and_open() {
        let p = plan();
        let payload = p.to_payload().unwrap();
        assert_eq!(JobPlanV1::from_payload(&payload).unwrap(), p);
        let opened = JobPlanV1::open(&plan_env(&p), &Keys(vec![key(PLAN_KEY)])).unwrap();
        assert_eq!(opened, p);
        // Deterministic encoding.
        assert_eq!(p.to_payload().unwrap(), payload);
        assert_eq!(p.timeout_s(Step::APPLY_IMAGE), Some(21_600));
    }

    #[test]
    fn plan_has_no_secret_fields() {
        // REQ-TGT-015: the M3 plan carries no secrets.
        let v = serde_json::to_value(plan()).unwrap();
        let mut k = Vec::new();
        keys(&v, &mut k);
        let bad: Vec<_> = k.iter().filter(|k| secret_like(k)).collect();
        assert!(bad.is_empty(), "{bad:?}");
    }

    #[test]
    fn plan_tamper_and_type_refused() {
        let p = plan();
        let env = plan_env(&p);
        let keys = Keys(vec![key(PLAN_KEY)]);
        // A changed payload byte: the signature no longer verifies.
        for at in [0, 10, 200, p.to_payload().unwrap().len() - 1] {
            assert!(matches!(
                JobPlanV1::open(&tamper(&env, at), &keys),
                Err(SignedManifestError::Envelope(_))
            ));
        }
        // Untrusted key.
        assert!(JobPlanV1::open(&env, &Keys(vec![key(1)])).is_err());
        // The same bytes signed as another payload type.
        let as_content = seal(
            PayloadType::ContentManifestV1,
            p.to_payload().unwrap(),
            PLAN_KEY,
        );
        assert!(JobPlanV1::open(&as_content, &keys).is_err());
        // Signed by another trusted key than key_id names.
        let other = seal(PayloadType::JobPlanV1, p.to_payload().unwrap(), 99);
        assert!(matches!(
            JobPlanV1::open(&other, &Keys(vec![key(PLAN_KEY), key(99)])),
            Err(SignedManifestError::KeyIdMismatch)
        ));
    }

    /// A change applied to a plan fixture.
    type Mutate = Box<dyn Fn(&mut JobPlanV1)>;

    #[test]
    fn plan_validation_rules() {
        let ok = plan();
        assert!(ok.validate().is_ok());
        let cases: Vec<(&str, Mutate)> = vec![
            ("schema", Box::new(|p| p.schema = 2)),
            ("revision", Box::new(|p| p.package.revision = 0)),
            ("size", Box::new(|p| p.image.size = 0)),
            ("esp", Box::new(|p| p.layout_policy.esp_mib_512 = 100)),
            ("msr", Box::new(|p| p.layout_policy.msr_mib = 128)),
            ("align", Box::new(|p| p.layout_policy.align_mib = 0)),
            (
                "min disk",
                Box::new(|p| p.layout_policy.min_disk_bytes = 1_000_000),
            ),
            (
                "disk below min",
                Box::new(|p| p.disk.size_bytes = 32_000_000_000),
            ),
            ("disk sector", Box::new(|p| p.disk.logical_sector = 1024)),
            ("wipe seq", Box::new(|p| p.wipe.audit_seq = 0)),
            (
                "steps short",
                Box::new(|p| {
                    p.steps.pop();
                }),
            ),
            ("steps order", Box::new(|p| p.steps.swap(1, 2))),
            (
                "step kind",
                Box::new(|p| p.steps[0].kind = Step::APPLY_IMAGE.kind()),
            ),
            ("step timeout 0", Box::new(|p| p.steps[2].timeout_s = 0)),
            (
                "step timeout long",
                Box::new(|p| p.steps[2].timeout_s = 30 * 24 * 3600),
            ),
            ("retry 0", Box::new(|p| p.retry.attempts = 0)),
            ("retry many", Box::new(|p| p.retry.attempts = 1000)),
            ("retry base", Box::new(|p| p.retry.base_ms = 70_000)),
            ("retry max", Box::new(|p| p.retry.max_ms = u32::MAX)),
            ("stall", Box::new(|p| p.stall_timeout_s = 0)),
            ("report", Box::new(|p| p.report_interval_s = 7200)),
        ];
        for (name, f) in cases {
            let mut p = ok.clone();
            f(&mut p);
            assert!(p.validate().is_err(), "{name}");
            assert!(p.to_payload().is_err(), "{name}");
        }
        // A larger minimum disk is allowed.
        let mut p = ok.clone();
        p.layout_policy.min_disk_bytes = 128_000_000_000;
        assert!(p.validate().is_ok());
    }

    #[test]
    fn plan_strict_parse_and_size() {
        let text = String::from_utf8(plan().to_payload().unwrap()).unwrap();
        for bad in [
            text.replacen("{\"schema\":1,", "{\"schema\":1,\"expires_at\":5,", 1),
            text.replacen("{\"schema\":1,", "{\"schema\":1,\"schema\":1,", 1),
            text.replace("tables+volume-heads-1mib", "everything"),
            text.replace("\"kind\":\"verify_content\"", "\"kind\":\"verify\""),
            text.replace("\"retry\":{", "\"retry\":{\"jitter\":true,"),
            text.replace("\"wipe\":{", "\"wipe\":{\"password\":\"x\","),
            format!("{text}\n{{}}"),
        ] {
            assert!(JobPlanV1::from_payload(bad.as_bytes()).is_err(), "{bad}");
        }
        let big = vec![b' '; MAX_MANIFEST_PAYLOAD_BYTES + 1];
        assert!(matches!(
            JobPlanV1::from_payload(&big),
            Err(SignedManifestError::TooLarge { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // Verified job plan (plan section 3.2 checks 1 to 6)
    // -----------------------------------------------------------------------

    struct Ctx {
        nonce: AgentNonce,
        disk: DiskDescriptorV1,
        session: SessionId,
        job: JobId,
        package: PackageId,
        revision: u64,
    }

    impl Ctx {
        fn new() -> Self {
            Self {
                nonce: nonce(),
                disk: disk(),
                session: SessionId::parse(SESSION).unwrap(),
                job: JobId::parse(JOB).unwrap(),
                package: PackageId::parse(PACKAGE).unwrap(),
                revision: 3,
            }
        }

        fn verify(
            &self,
            plan: &SignedEnvelopeV1,
            content: &SignedEnvelopeV1,
        ) -> Result<VerifiedJobPlan, PlanError> {
            VerifiedJobPlan::verify(
                plan,
                &Keys(vec![key(PLAN_KEY)]),
                content,
                &Keys(vec![key(CONTENT_KEY)]),
                &fake_sha,
                &PlanExpectation {
                    agent_nonce: &self.nonce,
                    session_id: self.session,
                    job_id: self.job,
                    package_id: self.package,
                    package_revision: self.revision,
                    disk: &self.disk,
                },
            )
        }
    }

    #[test]
    fn verified_plan_accepts_matching() {
        let ctx = Ctx::new();
        let v = ctx.verify(&plan_env(&plan()), &content_env()).unwrap();
        assert_eq!(v.plan(), &plan());
        assert_eq!(v.content_manifest(), &content_manifest());
    }

    #[test]
    fn verified_plan_refusals() {
        let good_plan = plan_env(&plan());
        let good_content = content_env();

        // Check 1: a tampered plan fails on its signature, before anything
        // else (even with every other value wrong).
        let mut ctx = Ctx::new();
        ctx.nonce = AgentNonce::from_random_bytes([0; 32]);
        let e = ctx
            .verify(&tamper(&good_plan, 50), &good_content)
            .unwrap_err();
        assert!(matches!(e, PlanError::Plan(_)), "{e:?}");
        assert_eq!(e.code(), codes::PLAN_SIGNATURE_INVALID);
        assert_eq!(e.category(), FailureCategory::Integrity);

        // Check 2: a plan signed by the content key is not a plan.
        let e = Ctx::new()
            .verify(
                &seal(
                    PayloadType::JobPlanV1,
                    plan().to_payload().unwrap(),
                    CONTENT_KEY,
                ),
                &good_content,
            )
            .unwrap_err();
        assert!(matches!(e, PlanError::Plan(_)), "{e:?}");

        // Check 3: nonce.
        assert!(matches!(
            ctx.verify(&good_plan, &good_content),
            Err(PlanError::NonceMismatch)
        ));

        // Check 4: session, job, package.
        let mut ctx = Ctx::new();
        ctx.session = SessionId::from_random_bytes([1; 16]);
        assert!(matches!(
            ctx.verify(&good_plan, &good_content),
            Err(PlanError::SessionMismatch)
        ));
        let mut ctx = Ctx::new();
        ctx.job = JobId::from_random_bytes([1; 16]);
        assert!(matches!(
            ctx.verify(&good_plan, &good_content),
            Err(PlanError::JobMismatch)
        ));
        let mut ctx = Ctx::new();
        ctx.revision = 4;
        assert!(matches!(
            ctx.verify(&good_plan, &good_content),
            Err(PlanError::PackageMismatch)
        ));

        // Check 5: another disk (same token, other serial).
        let mut ctx = Ctx::new();
        let d = disk();
        ctx.disk = DiskDescriptorV1::new(DiskDescriptorParts {
            disk_token: d.disk_token(),
            bus: d.bus(),
            model: d.model().clone(),
            serial: DiskText::sanitized("SN-0002"),
            size_bytes: d.size_bytes(),
            logical_sector: d.logical_sector(),
            physical_sector: d.physical_sector(),
            removable: d.removable(),
            partitions: d.partitions().to_vec(),
        })
        .unwrap();
        let e = ctx.verify(&good_plan, &good_content).unwrap_err();
        assert!(matches!(e, PlanError::DiskMismatch));
        assert_eq!(e.code(), codes::PLAN_BINDING_MISMATCH);

        // Check 6: tampered content manifest, wrong content key, digest
        // mismatch, and content that differs from the plan.
        let ctx = Ctx::new();
        let e = ctx
            .verify(&good_plan, &tamper(&good_content, 30))
            .unwrap_err();
        assert!(matches!(e, PlanError::ContentManifest(_)), "{e:?}");
        assert_eq!(e.code(), codes::CONTENT_MANIFEST_MISMATCH);
        let by_plan_key = seal(
            PayloadType::ContentManifestV1,
            content_manifest().to_payload().unwrap(),
            PLAN_KEY,
        );
        assert!(matches!(
            ctx.verify(&good_plan, &by_plan_key),
            Err(PlanError::ContentManifest(_))
        ));
        let mut other = content_manifest();
        other.ready_at = UnixMicros::new(1).unwrap();
        let other_env = seal(
            PayloadType::ContentManifestV1,
            other.to_payload().unwrap(),
            CONTENT_KEY,
        );
        assert!(matches!(
            ctx.verify(&good_plan, &other_env),
            Err(PlanError::ContentManifestDigest)
        ));
        // A plan whose image facts differ from a correctly bound manifest.
        for (field, f) in [
            (
                "size",
                Box::new(|p: &mut JobPlanV1| p.image.size += 1) as Mutate,
            ),
            (
                "sha256",
                Box::new(|p| p.image.content_sha256 = Sha256Digest([1; 32])),
            ),
            (
                "edition_index",
                Box::new(|p| p.image.edition_index = EditionIndex::new(3).unwrap()),
            ),
            (
                "edition_name",
                Box::new(|p| p.image.edition_name = WimText::new("Edition 1").unwrap()),
            ),
            ("total_bytes", Box::new(|p| p.image.total_bytes = 1)),
        ] {
            let mut p = plan();
            f(&mut p);
            match ctx.verify(&plan_env(&p), &good_content) {
                Err(PlanError::ContentMismatch(got)) => assert_eq!(got, field),
                other => panic!("{field}: {other:?}"),
            }
        }
    }

    // -----------------------------------------------------------------------
    // Boot policy
    // -----------------------------------------------------------------------

    fn policy(generation: u64, stops: Vec<BootStopEntryV1>) -> BootPolicyV1 {
        BootPolicyV1 {
            schema: 1,
            boot_service_id: BootServiceId::parse(BOOT_SERVICE).unwrap(),
            generation,
            issued_at_us: UnixMicros::new(1_793_000_000_000_000).unwrap(),
            key_id: key(POLICY_KEY),
            stops,
        }
    }

    fn stop(n: u8) -> BootStopEntryV1 {
        BootStopEntryV1 {
            mac: mac(n),
            job_id: JobId::parse(JOB).unwrap(),
        }
    }

    #[test]
    fn boot_policy_round_trip_and_checks() {
        let p = policy(5, vec![stop(1), stop(2)]);
        let env = seal(
            PayloadType::BootPolicyV1,
            p.to_payload().unwrap(),
            POLICY_KEY,
        );
        let keys = Keys(vec![key(POLICY_KEY)]);
        let opened = BootPolicyV1::open(&env, &keys).unwrap();
        assert_eq!(opened, p);
        assert!(opened.stop_set().contains(&mac(2)));
        let me = BootServiceId::parse(BOOT_SERVICE).unwrap();
        assert!(opened.check_for(me, None).is_ok());
        assert!(opened.check_for(me, Some(5)).is_ok());
        assert!(opened.check_for(me, Some(4)).is_ok());
        assert_eq!(
            opened.check_for(me, Some(6)),
            Err(BootPolicyError::Rollback { have: 6, got: 5 })
        );
        assert_eq!(
            opened.check_for(BootServiceId::from_random_bytes([3; 16]), None),
            Err(BootPolicyError::WrongBootService)
        );
        // Tampered, wrong type, wrong key.
        assert!(BootPolicyV1::open(&tamper(&env, 40), &keys).is_err());
        let as_plan = seal(PayloadType::JobPlanV1, p.to_payload().unwrap(), POLICY_KEY);
        assert!(BootPolicyV1::open(&as_plan, &keys).is_err());
        assert!(BootPolicyV1::open(&env, &Keys(vec![key(PLAN_KEY)])).is_err());
    }

    #[test]
    fn boot_policy_limits_and_strictness() {
        assert!(policy(0, vec![]).validate().is_err());
        assert!(policy(1, vec![]).validate().is_ok());
        assert!(policy(1, vec![stop(1), stop(1)]).validate().is_err());
        let mut p = policy(1, vec![]);
        p.schema = 2;
        assert!(p.validate().is_err());
        let full: Vec<_> = (0..=MAX_BOOT_STOPS as u32)
            .map(|i| BootStopEntryV1 {
                mac: MacAddress::new([0x02, 0, (i >> 16) as u8, (i >> 8) as u8, i as u8, 1])
                    .unwrap(),
                job_id: JobId::parse(JOB).unwrap(),
            })
            .collect();
        assert_eq!(full.len(), MAX_BOOT_STOPS + 1);
        let mut p = policy(1, full);
        assert!(p.validate().is_err());
        p.stops.pop();
        assert!(p.validate().is_ok());
        assert!(p.to_payload().unwrap().len() < MAX_MANIFEST_PAYLOAD_BYTES);

        let text = String::from_utf8(policy(2, vec![stop(1)]).to_payload().unwrap()).unwrap();
        for bad in [
            text.replacen("{\"schema\":1,", "{\"schema\":1,\"allow\":[],", 1),
            text.replace("\"job_id\"", "\"note\":\"x\",\"job_id\""),
            text.replace("02:00:00:00:00:01", "01:00:00:00:00:01"),
            text.replace("\"generation\":2", "\"generation\":-2"),
        ] {
            assert!(BootPolicyV1::from_payload(bad.as_bytes()).is_err(), "{bad}");
        }
    }

    // -----------------------------------------------------------------------
    // Operator additions
    // -----------------------------------------------------------------------

    #[test]
    fn issued_code_shown_once_views_have_no_value() {
        let issued = AuthCodeIssuedV1 {
            id: AuthCodeId::parse("8d4e5f60-7182-4d9e-bfa0-2b3c4d5e6f70").unwrap(),
            code: AuthCode::from_random_bytes(&[9, 8, 7, 6, 5, 4, 3, 2]),
            expires_at: UnixMicros::new(1_793_000_000_900_000).unwrap(),
        };
        let grouped = issued.code.grouped().to_string();
        let body = issued.to_json_zeroizing().unwrap();
        assert!(std::str::from_utf8(&body).unwrap().contains(&grouped));
        assert!(!format!("{issued:?}").contains(&grouped));

        // A list view with a code field is refused (none is ever sent).
        let view = r#"{"codes":[{"id":"8d4e5f60-7182-4d9e-bfa0-2b3c4d5e6f70","state":"active","issued_by":"2d0f9b81-3c4e-4f60-8b1c-d2e3f4051627","issued_at":1,"expires_at":2}]}"#;
        let l: AuthCodeList = serde_json::from_str(view).unwrap();
        assert_eq!(serde_json::to_string(&l).unwrap(), view);
        let with_code = view.replace("\"state\"", "\"code\":\"ABCDE-FGHJK\",\"state\"");
        assert!(serde_json::from_str::<AuthCodeList>(&with_code).is_err());
    }

    #[test]
    fn job_view_round_trip() {
        let p = plan();
        let v = JobView {
            id: p.job_id,
            session_id: p.session_id,
            boot_service_id: p.boot_service_id,
            package_id: p.package.id,
            package_revision: 3,
            edition_index: p.image.edition_index,
            macs: p.device.macs.clone(),
            disk: disk(),
            layout: Some(layout()),
            state: JobState::Failed,
            current_step: Step::VERIFY_CONTENT,
            steps: vec![],
            bytes_done: Some(5),
            bytes_total: Some(10),
            percent: usgp_proto::ops::percent(5, 10),
            failure: Some(FailureV1 {
                step: Step::VERIFY_CONTENT,
                category: FailureCategory::Integrity,
                code: codes::CHUNK_DIGEST_MISMATCH,
                files: vec![],
                count: 1,
                attempts: 1,
            }),
            failed_at: Some(UnixMicros::new(9).unwrap()),
            attempts: 1,
            previous_job_id: None,
            acknowledged: false,
            started_at: UnixMicros::new(1).unwrap(),
            last_report_at: None,
            finished_at: None,
        };
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(serde_json::from_str::<JobView>(&json).unwrap(), v);
        let mut k = Vec::new();
        keys(&serde_json::to_value(&v).unwrap(), &mut k);
        assert!(k.iter().all(|k| !secret_like(k) || k == "code"), "{k:?}");
        assert!(
            serde_json::from_str::<JobView>(&json.replace("\"failed\"", "\"cancelled\"")).is_err()
        );
    }

    #[test]
    fn boot_service_view_round_trip() {
        let json = r#"{"id":"7c3d4e5f-6071-4c8d-ae9f-1a2b3c4d5e6f","name":"Bench","served_subnets":["10.20.0.0/16"],"status":"active","packages":[],"usable_count":0,"warning":{"code":"boot_service.no_usable_package","message":"No package can be offered."}}"#;
        let v: BootServiceView = serde_json::from_str(json).unwrap();
        assert_eq!(serde_json::to_string(&v).unwrap(), json);
        assert!(
            serde_json::from_str::<BootServiceView>(&json.replace("10.20.0.0/16", "10.20.0.1/16"))
                .is_err()
        );
    }
}
