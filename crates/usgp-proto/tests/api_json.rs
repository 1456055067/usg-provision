//! API JSON bodies: strict parsing, field validation with named reason
//! codes, wire shapes of responses, and the absence of secret fields
//! (plan WU-4, section 10 "Declarations" and "API" rows).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), SI-11 (Error
//   Handling), SA-11 (Developer Testing and Evaluation)
// - SPEC: specs/os-images.md#REQ-IMG-004, #REQ-IMG-022, #REQ-IMG-033,
//   #REQ-IMG-041, #REQ-IMG-043, #REQ-IMG-054
// - SPEC: specs/preinstall-env.md#REQ-PE-005
// - SPEC: specs/operator-access.md#REQ-RBAC-006, #REQ-AUD-003

#[cfg(test)]
mod api_json {
    use usgp_common::Sha256Digest;
    use usgp_proto::api::{
        ClonePackageRequest, CreateUpload, CreateUploadRequest, EditionDeclaration,
        EditionDeclarationRequest, EditionView, ErrorBody, ImageList, ImageView, LimitsView,
        Message, PackageImageView, PackagePeView, PackageRef, PackageRequest, PackageView,
        PeDeclaration, PeDeclarationRequest, PeView, Reason, RequestError, SupportView,
        parse_request,
    };
    use usgp_proto::limits::DEFAULT_MAX_JSON_BYTES;
    use usgp_proto::{
        Architecture, ContentId, ContentKind, ContentState, Description, DisplayName, Edition,
        EditionFacts, EditionIndex, Fact, FileName, KitVersion, OperatorId, PackageId,
        PackageStatus, Release, SupportState, UnixMicros, WimCompression, WimText, codes,
    };

    const SHA: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const IMG: &str = "0b7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e6f";
    const PE: &str = "3e1fac92-4d5f-4071-9c2d-e3f405162738";
    const OP: &str = "2d0f9b81-3c4e-4f60-8b1c-d2e3f4051627";
    const PKG: &str = "1c9e8a70-2b3d-4e5f-9a0b-c1d2e3f40516";

    fn parse<T: serde::de::DeserializeOwned>(json: &str) -> Result<T, RequestError> {
        parse_request(json.as_bytes(), DEFAULT_MAX_JSON_BYTES)
    }

    fn upload(json: &str) -> CreateUploadRequest {
        parse(json).unwrap_or_else(|e| panic!("{json}: {e}"))
    }

    fn image_upload_json(file_name: &str, size: u64) -> String {
        format!(
            r#"{{"kind":"image","display_name":"Win 11","file_name":"{file_name}","size":{size},"sha256":"{SHA}"}}"#
        )
    }

    #[test]
    fn file_name_with_spaces_roundtrip() {
        // REQ-IMG-033
        let req = upload(&image_upload_json("Windows 11 Enterprise install.wim", 10));
        let v = req.validate().unwrap();
        assert_eq!(v.file_name.as_str(), "Windows 11 Enterprise install.wim");
        let back = CreateUploadRequest::from(&v);
        assert_eq!(back, req);
        let json = serde_json::to_string(&back).unwrap();
        assert!(json.contains("\"file_name\":\"Windows 11 Enterprise install.wim\""));
    }

    #[test]
    fn zero_size_refused_empty_file() {
        // REQ-IMG-004
        let e = upload(&image_upload_json("a.wim", 0))
            .validate()
            .unwrap_err();
        assert_eq!(e.code, codes::EMPTY_FILE);
        assert_eq!(e.field, "size");
    }

    #[test]
    fn shape_errors_are_invalid_json() {
        for bad in [
            // unknown field
            format!(
                r#"{{"kind":"image","display_name":"a","file_name":"a","size":1,"sha256":"{SHA}","x":1}}"#
            ),
            // duplicate field
            format!(
                r#"{{"kind":"image","kind":"pe","display_name":"a","file_name":"a","size":1,"sha256":"{SHA}"}}"#
            ),
            // missing field
            r#"{"kind":"image","display_name":"a","file_name":"a","size":1}"#.to_owned(),
            // wrong types
            format!(
                r#"{{"kind":"image","display_name":"a","file_name":"a","size":"1","sha256":"{SHA}"}}"#
            ),
            format!(
                r#"{{"kind":"image","display_name":"a","file_name":"a","size":-1,"sha256":"{SHA}"}}"#
            ),
            format!(
                r#"{{"kind":"image","display_name":"a","file_name":"a","size":1.5,"sha256":"{SHA}"}}"#
            ),
            format!(
                r#"{{"kind":"image","display_name":"a","file_name":"a","size":18446744073709551616,"sha256":"{SHA}"}}"#
            ),
            // trailing data
            format!("{} {{}}", image_upload_json("a", 1)),
            // not JSON
            "kind=image".to_owned(),
            String::new(),
            "[]".to_owned(),
        ] {
            let e = parse::<CreateUploadRequest>(&bad).unwrap_err();
            assert_eq!(e.code(), codes::INVALID_JSON, "{bad}");
            assert_eq!(e.to_error_body().error.code, codes::INVALID_JSON);
        }
    }

    #[test]
    fn body_cap_checked_before_parsing() {
        let body = vec![b' '; DEFAULT_MAX_JSON_BYTES + 1];
        let e = parse_request::<CreateUploadRequest>(&body, DEFAULT_MAX_JSON_BYTES).unwrap_err();
        assert_eq!(
            e,
            RequestError::TooLarge {
                len: DEFAULT_MAX_JSON_BYTES + 1,
                max: DEFAULT_MAX_JSON_BYTES
            }
        );
        let b = e.to_error_body();
        assert_eq!(b.error.code, codes::BODY_TOO_LARGE);
        assert_eq!(b.error.limit_bytes, Some(65536));
    }

    #[test]
    fn deep_nesting_does_not_panic() {
        let deep = format!("{}{}", "[".repeat(10_000), "]".repeat(10_000));
        assert!(parse_request::<CreateUploadRequest>(deep.as_bytes(), 1 << 20).is_err());
    }

    #[test]
    fn name_rules_have_named_codes() {
        let long = "x".repeat(129);
        let cases = [
            (
                format!(
                    r#"{{"kind":"image","display_name":"","file_name":"a","size":1,"sha256":"{SHA}"}}"#
                ),
                "empty:display_name",
            ),
            (
                format!(
                    r#"{{"kind":"image","display_name":"{long}","file_name":"a","size":1,"sha256":"{SHA}"}}"#
                ),
                "too_long:display_name",
            ),
            (
                format!(
                    r#"{{"kind":"image","display_name":"a\u0007","file_name":"a","size":1,"sha256":"{SHA}"}}"#
                ),
                "invalid_character:display_name",
            ),
            (
                format!(
                    r#"{{"kind":"image","display_name":"a","file_name":"..\\x","size":1,"sha256":"{SHA}"}}"#
                ),
                "invalid_character:file_name",
            ),
            (
                format!(
                    r#"{{"kind":"image","display_name":"a","file_name":"a/b","size":1,"sha256":"{SHA}"}}"#
                ),
                "invalid_character:file_name",
            ),
            (
                format!(
                    r#"{{"kind":"image","display_name":"a","file_name":"..","size":1,"sha256":"{SHA}"}}"#
                ),
                "invalid_value:file_name",
            ),
            (
                r#"{"kind":"image","display_name":"a","file_name":"a","size":1,"sha256":"00"}"#
                    .to_owned(),
                "invalid_value:sha256",
            ),
            (
                format!(
                    r#"{{"kind":"iso","display_name":"a","file_name":"a","size":1,"sha256":"{SHA}"}}"#
                ),
                "invalid_value:kind",
            ),
        ];
        for (json, code) in cases {
            let e = upload(&json).validate().unwrap_err();
            assert_eq!(e.code.as_str(), code, "{json}");
            // The value never appears in the message.
            assert!(!e.message.contains(&long), "{json}");
        }
    }

    #[test]
    fn pe_declaration_required_and_forbidden() {
        // REQ-PE-005 item 1: declared at import.
        let pe_no_decl = format!(
            r#"{{"kind":"pe","display_name":"PE","file_name":"boot.wim","size":1,"sha256":"{SHA}"}}"#
        );
        let e = upload(&pe_no_decl).validate().unwrap_err();
        assert_eq!(e.code.as_str(), "required:pe_declaration");

        let image_with_decl = format!(
            r#"{{"kind":"image","display_name":"a","file_name":"a","size":1,"sha256":"{SHA}",
                "pe_declaration":{{"architecture":"x64","kit_version":"10.1.26100.1"}}}}"#
        );
        let e = upload(&image_with_decl).validate().unwrap_err();
        assert_eq!(e.code.as_str(), "not_allowed:pe_declaration");

        let ok = format!(
            r#"{{"kind":"pe","display_name":"PE","file_name":"boot.wim","size":1,"sha256":"{SHA}",
                "pe_declaration":{{"architecture":"x64","kit_version":"10.1.26100.1"}}}}"#
        );
        let v = upload(&ok).validate().unwrap();
        assert_eq!(v.kind, ContentKind::Pe);
        assert_eq!(
            v.pe_declaration,
            Some(PeDeclaration {
                architecture: Architecture::X64,
                kit_version: KitVersion::parse("10.1.26100.1").unwrap(),
            })
        );
        assert_eq!(CreateUploadRequest::from(&v), upload(&ok));
    }

    #[test]
    fn pe_non_x64_is_syntactically_valid_scope_is_the_servers() {
        // The server refuses non-x64 with pe_architecture_not_supported:<arch>
        // (REQ-PE-005); here the declaration only has to be well formed.
        for arch in ["x86", "arm64", "arm"] {
            let d = PeDeclarationRequest {
                architecture: arch.to_owned(),
                kit_version: "10.1.26100.1".to_owned(),
            };
            assert_eq!(d.validate().unwrap().architecture.as_str(), arch);
            let code = codes::PE_ARCHITECTURE_NOT_SUPPORTED
                .with_param(arch)
                .unwrap();
            assert_eq!(
                code.as_str(),
                format!("pe_architecture_not_supported:{arch}")
            );
        }
    }

    #[test]
    fn kit_version_format() {
        for (kit, ok) in [
            ("10.1.26100.9457", true),
            ("10.0", true),
            ("10", false),
            ("10.1.2.3.4", false),
            ("10.1.70000", false),
            ("+10.1", false),
            ("10. 1", false),
            ("10.01", false),
            ("", false),
        ] {
            let d = PeDeclarationRequest {
                architecture: "x64".to_owned(),
                kit_version: kit.to_owned(),
            };
            match d.validate() {
                Ok(v) => {
                    assert!(ok, "{kit:?} accepted");
                    assert_eq!(v.kit_version.to_string(), kit);
                }
                Err(e) => {
                    assert!(!ok, "{kit:?} refused");
                    assert_eq!(e.code.as_str(), "invalid_value:kit_version");
                }
            }
        }
    }

    #[test]
    fn edition_declaration_closed_values() {
        // Decision 0013: closed sets; out-of-scope values are valid input
        // (recorded, then judged by os_support).
        let d: EditionDeclarationRequest =
            parse(r#"{"release":"windows-10","edition":"enterprise-ltsc","architecture":"arm64"}"#)
                .unwrap();
        assert_eq!(
            d.validate().unwrap(),
            EditionDeclaration {
                release: Release::Windows10,
                edition: Edition::EnterpriseLtsc,
                architecture: Architecture::Arm64,
            }
        );
        for (json, code) in [
            (
                r#"{"release":"Windows 11","edition":"enterprise","architecture":"x64"}"#,
                "invalid_value:release",
            ),
            (
                r#"{"release":"windows-11","edition":"Enterprise","architecture":"x64"}"#,
                "invalid_value:edition",
            ),
            (
                r#"{"release":"windows-11","edition":"enterprise","architecture":"amd64"}"#,
                "invalid_value:architecture",
            ),
        ] {
            let d: EditionDeclarationRequest = parse(json).unwrap();
            let e = d.validate().unwrap_err();
            assert_eq!(e.code.as_str(), code);
            assert!(e.message.contains("must be one of"));
        }
        // No feature-update field exists (REQ-OS-008).
        assert!(
            parse::<EditionDeclarationRequest>(
                r#"{"release":"windows-11","edition":"enterprise","architecture":"x64","feature_update":"24H2"}"#
            )
            .is_err()
        );
        let v = EditionDeclaration {
            release: Release::Windows11,
            edition: Edition::Enterprise,
            architecture: Architecture::X64,
        };
        assert_eq!(
            serde_json::to_string(&EditionDeclarationRequest::from(&v)).unwrap(),
            r#"{"release":"windows-11","edition":"enterprise","architecture":"x64"}"#
        );
    }

    #[test]
    fn package_request_validation() {
        let ok = format!(
            r#"{{"name":"Field laptops","description":"Ent x64","image_id":"{IMG}","edition_index":3,"pe_id":"{PE}"}}"#
        );
        let r: PackageRequest = parse(&ok).unwrap();
        let v = r.validate().unwrap();
        assert_eq!(v.edition_index.get(), 3);
        assert_eq!(PackageRequest::from(&v), r);
        // Index vs. image count is the server's check (REQ-IMG-041).
        assert!(v.edition_index.check(2).is_err());
        assert!(v.edition_index.check(12).is_ok());

        let no_desc =
            format!(r#"{{"name":"n","image_id":"{IMG}","edition_index":1,"pe_id":"{PE}"}}"#);
        assert_eq!(
            parse::<PackageRequest>(&no_desc)
                .unwrap()
                .validate()
                .unwrap()
                .description,
            None
        );

        for (json, code) in [
            (
                format!(r#"{{"name":"n","image_id":"{IMG}","edition_index":0,"pe_id":"{PE}"}}"#),
                "out_of_range:edition_index",
            ),
            (
                format!(
                    r#"{{"name":"n","image_id":"{IMG}","edition_index":4294967296,"pe_id":"{PE}"}}"#
                ),
                "out_of_range:edition_index",
            ),
            (
                format!(r#"{{"name":"n","image_id":"../etc","edition_index":1,"pe_id":"{PE}"}}"#),
                "invalid_value:image_id",
            ),
            (
                format!(
                    r#"{{"name":"n","image_id":"{IMG}","edition_index":1,"pe_id":"00000000-0000-0000-0000-000000000000"}}"#
                ),
                "invalid_value:pe_id",
            ),
            (
                format!(
                    r#"{{"name":"n","description":"{}","image_id":"{IMG}","edition_index":1,"pe_id":"{PE}"}}"#,
                    "d".repeat(1025)
                ),
                "too_long:description",
            ),
            (
                format!(r#"{{"name":"","image_id":"{IMG}","edition_index":1,"pe_id":"{PE}"}}"#),
                "empty:name",
            ),
        ] {
            let e = parse::<PackageRequest>(&json)
                .unwrap()
                .validate()
                .unwrap_err();
            assert_eq!(e.code.as_str(), code, "{json}");
        }

        let c: ClonePackageRequest = parse(r#"{"name":"copy"}"#).unwrap();
        assert_eq!(c.validate().unwrap().as_str(), "copy");
        assert!(parse::<ClonePackageRequest>(r#"{"name":"copy","id":"x"}"#).is_err());
    }

    fn sample_package_view() -> PackageView {
        PackageView {
            id: PackageId::parse(PKG).unwrap(),
            name: DisplayName::new("Field laptops").unwrap(),
            description: Some(Description::new("Ent x64").unwrap()),
            revision: 2,
            status: PackageStatus::NotUsable,
            status_reason: Some(Reason {
                code: codes::OS_SUPPORT_UNKNOWN,
                message: Message::new("edition 1 has no declaration").unwrap(),
            }),
            image: PackageImageView {
                image_id: ContentId::parse(IMG).unwrap(),
                display_name: DisplayName::new("Win 11").unwrap(),
                edition_index: EditionIndex::new(1).unwrap(),
                edition_name: WimText::new("Windows 11 Enterprise").unwrap(),
                facts: None,
                support: SupportView {
                    status: SupportState::Unknown,
                    reason: Some(codes::OS_SUPPORT_UNKNOWN),
                },
            },
            pe: PackagePeView {
                pe_id: ContentId::parse(PE).unwrap(),
                display_name: DisplayName::new("PE x64").unwrap(),
                architecture: Fact::declared(Architecture::X64),
                kit_version: Fact::declared(KitVersion::parse("10.1.26100.1").unwrap()),
                kit_warning: None,
            },
            created_by: OperatorId::parse(OP).unwrap(),
            created_at: UnixMicros::new(1).unwrap(),
            updated_at: UnixMicros::new(2).unwrap(),
        }
    }

    fn sample_image_view() -> ImageView {
        ImageView {
            id: ContentId::parse(IMG).unwrap(),
            display_name: DisplayName::new("Win 11").unwrap(),
            file_name: FileName::new("install image.wim").unwrap(),
            size: 11_000_000_000,
            sha256: Some(Sha256Digest::from_hex(SHA).unwrap()),
            state: ContentState::Ready,
            reason: None,
            created_by: OperatorId::parse(OP).unwrap(),
            created_at: UnixMicros::new(1).unwrap(),
            updated_at: UnixMicros::new(2).unwrap(),
            compression: Some(WimCompression::Xpress),
            image_count: Some(1),
            boot_index: Some(0),
            editions: vec![EditionView {
                index: EditionIndex::new(1).unwrap(),
                name: WimText::new("Windows 11 Enterprise").unwrap(),
                description: WimText::new("Windows 11 Enterprise").unwrap(),
                total_bytes: Some(20_000_000_000),
                facts: Some(EditionFacts {
                    release: Fact::declared(Release::Windows11),
                    edition: Fact::declared(Edition::Enterprise),
                    architecture: Fact::declared(Architecture::X64),
                }),
                declared_by: Some(OperatorId::parse(OP).unwrap()),
                declared_at: Some(UnixMicros::new(3).unwrap()),
                support: SupportView {
                    status: SupportState::Supported,
                    reason: None,
                },
            }],
        }
    }

    fn sample_pe_view() -> PeView {
        PeView {
            id: ContentId::parse(PE).unwrap(),
            display_name: DisplayName::new("PE x64").unwrap(),
            file_name: FileName::new("boot.wim").unwrap(),
            size: 400_000_000,
            sha256: Some(Sha256Digest::from_hex(SHA).unwrap()),
            state: ContentState::Ready,
            reason: None,
            imported_by: OperatorId::parse(OP).unwrap(),
            imported_at: UnixMicros::new(1).unwrap(),
            updated_at: UnixMicros::new(2).unwrap(),
            usable_index: Some(EditionIndex::new(1).unwrap()),
            architecture: Fact::declared(Architecture::X64),
            kit_version: Fact::declared(KitVersion::parse("10.1.26100.1").unwrap()),
            kit_warning: Some(Reason {
                code: codes::KIT_VERSION_KNOWN_BAD,
                message: Message::new("this kit release is known not to work").unwrap(),
            }),
            used_by: vec![PackageRef {
                id: PackageId::parse(PKG).unwrap(),
                name: DisplayName::new("Field laptops").unwrap(),
            }],
        }
    }

    fn round_trip<T>(v: &T) -> String
    where
        T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let json = serde_json::to_string(v).unwrap();
        let back: T = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, v);
        json
    }

    #[test]
    fn views_round_trip_and_show_sources() {
        // REQ-IMG-043 item 3: each fact carries its source.
        let img = round_trip(&sample_image_view());
        assert!(img.contains(r#""release":{"value":"windows-11","source":"declared"}"#));
        assert!(img.contains(r#""support":{"status":"supported","reason":null}"#));
        round_trip(&ImageList {
            images: vec![sample_image_view()],
        });
        let pe = round_trip(&sample_pe_view());
        assert!(pe.contains(r#""kit_version":{"value":"10.1.26100.1","source":"declared"}"#));
        let pkg = round_trip(&sample_package_view());
        assert!(pkg.contains(r#""status":"not_usable""#));
        assert!(pkg.contains(r#""reason":"os_support_unknown""#));
        round_trip(&LimitsView::new(32 << 30, 65536));
    }

    #[test]
    fn responses_refuse_unknown_fields() {
        let json = serde_json::to_string(&sample_package_view()).unwrap();
        let extra = json.replacen("{\"id\"", "{\"admin_password\":\"x\",\"id\"", 1);
        assert!(serde_json::from_str::<PackageView>(&extra).is_err());
        let limits = r#"{"max_upload_bytes":1,"max_json_bytes":1,"max_display_name_chars":1,
            "max_description_chars":1,"max_file_name_bytes":1,"chunk_size":1,"x":1}"#;
        assert!(serde_json::from_str::<LimitsView>(limits).is_err());
    }

    #[test]
    fn error_body_shapes() {
        let simple = ErrorBody::new(codes::NOT_FOUND, Message::new("no such image").unwrap());
        assert_eq!(
            round_trip(&simple),
            r#"{"error":{"code":"not_found","message":"no such image"}}"#
        );
        let mut in_use = ErrorBody::new(
            codes::IN_USE,
            Message::new("the image is used by 1 package").unwrap(),
        );
        in_use.error.dependants.push(PackageRef {
            id: PackageId::parse(PKG).unwrap(),
            name: DisplayName::new("Field laptops").unwrap(),
        });
        let j = round_trip(&in_use);
        assert!(j.contains(&format!(
            r#""dependants":[{{"id":"{PKG}","name":"Field laptops"}}]"#
        )));
        let mut dup = ErrorBody::new(codes::DUPLICATE, Message::new("already uploaded").unwrap());
        dup.error.existing_id = Some(ContentId::parse(IMG).unwrap());
        round_trip(&dup);
        let mut big = ErrorBody::new(codes::TOO_LARGE, Message::new("over the limit").unwrap());
        big.error.limit_bytes = Some(32 << 30);
        assert!(round_trip(&big).contains(r#""limit_bytes":34359738368"#));
        assert!(
            serde_json::from_str::<ErrorBody>(
                r#"{"error":{"code":"x","message":"m","stack":"…"}}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<ErrorBody>(r#"{"error":{"code":"Bad Code","message":"m"}}"#)
                .is_err()
        );
    }

    #[test]
    fn no_secret_fields_in_types() {
        // REQ-IMG-054, REQ-RBAC-006, REQ-AUD-003: M2 API types carry no
        // secret. Every serialized response and request is checked for field
        // names that would suggest one.
        let upload = CreateUploadRequest::from(&CreateUpload {
            kind: ContentKind::Pe,
            display_name: DisplayName::new("PE").unwrap(),
            file_name: FileName::new("boot.wim").unwrap(),
            size: 1,
            sha256: Sha256Digest::from_hex(SHA).unwrap(),
            pe_declaration: Some(PeDeclaration {
                architecture: Architecture::X64,
                kit_version: KitVersion::parse("10.0").unwrap(),
            }),
        });
        let docs = [
            serde_json::to_value(sample_image_view()).unwrap(),
            serde_json::to_value(sample_pe_view()).unwrap(),
            serde_json::to_value(sample_package_view()).unwrap(),
            serde_json::to_value(LimitsView::new(1, 1)).unwrap(),
            serde_json::to_value(upload).unwrap(),
        ];
        fn walk(v: &serde_json::Value, out: &mut Vec<String>) {
            match v {
                serde_json::Value::Object(m) => {
                    for (k, v) in m {
                        out.push(k.clone());
                        walk(v, out);
                    }
                }
                serde_json::Value::Array(a) => a.iter().for_each(|v| walk(v, out)),
                _ => {}
            }
        }
        let mut keys = Vec::new();
        for d in &docs {
            walk(d, &mut keys);
        }
        for k in keys {
            for bad in [
                "password",
                "secret",
                "private",
                "token",
                "credential",
                "pin",
            ] {
                assert!(!k.contains(bad), "field {k:?} looks secret-bearing");
            }
        }
    }
}
