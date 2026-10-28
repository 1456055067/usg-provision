//! Process-level tests for the M3 operator commands (plan WU-13): exit
//! codes and usage, and exchanges with the in-process stub API over real
//! mutual TLS (`tests/common`):
//!
//! - `code issue` prints the code once on stdout and nowhere else;
//! - `session approve --display-code` finds the waiting session and binds
//!   the approval to the code;
//! - `boot-service set-packages` sends `If-Match`;
//! - `job show` shows a failed job's persistent error;
//! - `boot-stop clear` posts to the stop.

#[cfg(test)]
mod common;

#[cfg(test)]
mod tls {
    use usgp_proto::device::{DeviceArch, FirmwareKind, SecureBootState, SessionState};
    use usgp_proto::ids::{AuthCodeId, BootServiceId, PackageId, SessionId, UnixMicros};
    use usgp_proto::names::{AgentVersion, DisplayName};
    use usgp_proto::ops::{
        AuthCodeIssuedV1, BootServiceStatus, BootServiceView, DeviceSessionList, DeviceSessionView,
        IpCidr, SubnetList,
    };
    use usgp_proto::{AuthCode, DisplayCode, MacAddress, MacList};

    use crate::common::{Env, route, stderr, stdout};

    const CODE_ID: &str = "4a1e2f3a-4b5c-4d6e-8f70-8192a3b4c5d6";
    const CODE: &str = "7K3QZ-M9XWD";
    const SID: &str = "6a1e2f3a-4b5c-4d6e-8f70-8192a3b4c5d6";
    const BS: &str = "9a1e2f3a-4b5c-4d6e-8f70-8192a3b4c5d6";
    const PKG: &str = "1c9e8a70-2b3d-4e5f-9a0b-c1d2e3f40516";
    const JOB: &str = "8a1e2f3a-4b5c-4d6e-8f70-8192a3b4c5d6";
    const STOP: &str = "aa1e2f3a-4b5c-4d6e-8f70-8192a3b4c5d6";

    fn issued() -> Vec<u8> {
        AuthCodeIssuedV1 {
            id: AuthCodeId::parse(CODE_ID).unwrap(),
            code: AuthCode::parse(CODE).unwrap(),
            expires_at: UnixMicros::new(1_793_097_001_000_000).unwrap(),
        }
        .to_json_zeroizing()
        .unwrap()
        .to_vec()
    }

    /// REQ-TGT-013: the code is shown once to the issuing operator and is
    /// never echoed anywhere else (stderr, other output forms).
    #[test]
    fn code_issue_shows_code_once_on_stdout_only() {
        let e = Env::new(
            vec![
                route("POST", "/v1/auth-codes", 201, issued())
                    .with_header("cache-control", "no-store"),
            ],
            None,
        );
        let o = e.run(&["code", "issue", "--ttl", "900", "--note", "bench 4"], b"");
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        let out = stdout(&o);
        let err = stderr(&o);
        assert_eq!(out.matches(CODE).count(), 1, "{out}");
        assert!(!out.contains("7K3QZM9XWD"), "{out}");
        assert!(!err.contains("7K3QZ"), "{err}");
        assert!(!err.contains("M9XWD"), "{err}");
        assert!(out.contains("shown only once"), "{out}");
        let seen = e.seen();
        let req = seen.first().unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(
            req.client_cert_sha256.as_deref(),
            Some(e.operator_sha256().as_str())
        );
        let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
        assert_eq!(body, serde_json::json!({"ttl_s": 900, "note": "bench 4"}));
    }

    /// A refused issue explains the refusal and prints no code.
    #[test]
    fn code_issue_refusal_prints_no_code() {
        let e = Env::new(
            vec![route(
                "POST",
                "/v1/auth-codes",
                403,
                br#"{"error":{"code":"authz.denied","message":"denied"}}"#.to_vec(),
            )],
            None,
        );
        let o = e.run(&["code", "issue"], b"");
        assert_eq!(o.status.code(), Some(1));
        assert!(o.stdout.is_empty());
        assert!(
            stderr(&o).contains("operator role does not allow"),
            "{}",
            stderr(&o)
        );
    }

    fn session(state: SessionState) -> DeviceSessionView {
        DeviceSessionView {
            id: SessionId::parse(SID).unwrap(),
            state,
            macs: MacList::new(vec![MacAddress::parse("02:00:00:00:00:01").unwrap()]).unwrap(),
            source_ip: "192.0.2.10".parse().unwrap(),
            firmware: FirmwareKind::Uefi,
            arch: DeviceArch::X64,
            secure_boot: SecureBootState::On,
            memory_bytes: 8 << 30,
            agent_version: AgentVersion::new("0.3.0").unwrap(),
            boot_service_id: None,
            boot_service_name: None,
            display_code: DisplayCode::parse("ABC-123").unwrap(),
            auth_method: None,
            failed_code_attempts: 0,
            created_at: UnixMicros::new(0).unwrap(),
            last_seen_at: UnixMicros::new(0).unwrap(),
            expires_at: UnixMicros::new(900_000_000).unwrap(),
            chosen_package_id: None,
            chosen_package_revision: None,
            chosen_disk: None,
        }
    }

    /// REQ-TGT-014: approval by the display code read off the device.
    #[test]
    fn session_approve_by_display_code() {
        let list = DeviceSessionList {
            sessions: vec![session(SessionState::AwaitingAuthorisation)],
        };
        let e = Env::new(
            vec![
                route(
                    "GET",
                    "/v1/device-sessions",
                    200,
                    serde_json::to_vec(&list).unwrap(),
                ),
                route(
                    "POST",
                    &format!("/v1/device-sessions/{SID}/approve"),
                    200,
                    serde_json::to_vec(&session(SessionState::Authorised)).unwrap(),
                ),
            ],
            None,
        );
        let o = e.run(&["session", "approve", "--display-code", "abc 123"], b"");
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        assert!(stdout(&o).contains(&format!("approved session {SID}")));
        let seen = e.seen();
        assert_eq!(seen.len(), 2);
        let list_req = seen.first().unwrap();
        assert_eq!(list_req.path, "/v1/device-sessions");
        assert_eq!(
            list_req.query.as_deref(),
            Some("state=awaiting_authorisation")
        );
        let post = seen.get(1).unwrap();
        let body: serde_json::Value = serde_json::from_slice(&post.body).unwrap();
        assert_eq!(body, serde_json::json!({"display_code": "ABC-123"}));

        // A display code no waiting session shows: nothing approved.
        let o = e.run(&["session", "approve", "--display-code", "XYZ-789"], b"");
        assert_eq!(o.status.code(), Some(1));
        assert!(stderr(&o).contains("no session awaiting authorisation"));
        assert_eq!(e.seen().len(), 3);
    }

    fn service() -> Vec<u8> {
        serde_json::to_vec(&BootServiceView {
            id: BootServiceId::parse(BS).unwrap(),
            name: DisplayName::new("Lab segment").unwrap(),
            served_subnets: SubnetList::new(vec![IpCidr::parse("10.20.0.0/16").unwrap()]).unwrap(),
            status: BootServiceStatus::Active,
            packages: vec![usgp_proto::api::PackageRef {
                id: PackageId::parse(PKG).unwrap(),
                name: DisplayName::new("Laptops").unwrap(),
            }],
            usable_count: 1,
            warning: None,
        })
        .unwrap()
    }

    /// RFC 9110 §13.1.1: the change is conditional on the tag read.
    #[test]
    fn boot_service_set_packages_sends_if_match() {
        let e = Env::new(
            vec![
                route("GET", &format!("/v1/boot-services/{BS}"), 200, service())
                    .with_header("etag", "\"bsp-1\""),
                route(
                    "PUT",
                    &format!("/v1/boot-services/{BS}/packages"),
                    200,
                    service(),
                )
                .with_header("etag", "\"bsp-2\""),
            ],
            None,
        );
        let o = e.run(&["boot-service", "set-packages", BS, PKG], b"");
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        let seen = e.seen();
        let put = seen.get(1).unwrap();
        assert_eq!(put.method, "PUT");
        assert_eq!(put.header("if-match"), Some("\"bsp-1\""));
        let body: serde_json::Value = serde_json::from_slice(&put.body).unwrap();
        assert_eq!(body, serde_json::json!({"package_ids": [PKG]}));
        assert!(
            stdout(&o).contains("assignment tag: \"bsp-2\""),
            "{}",
            stdout(&o)
        );

        // With the reviewed tag, no read; the server's 412 is explained.
        let e = Env::new(
            vec![route(
                "PUT",
                &format!("/v1/boot-services/{BS}/packages"),
                412,
                br#"{"error":{"code":"precondition_failed","message":"changed"}}"#.to_vec(),
            )],
            None,
        );
        let o = e.run(
            &[
                "boot-service",
                "set-packages",
                BS,
                "--none",
                "--if-match",
                "\"bsp-0\"",
            ],
            b"",
        );
        assert_eq!(o.status.code(), Some(1));
        assert!(
            stderr(&o).contains("changed since it was read"),
            "{}",
            stderr(&o)
        );
        let seen = e.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen.first().unwrap().header("if-match"), Some("\"bsp-0\""));
    }

    fn failed_job() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "id": JOB,
            "session_id": SID,
            "boot_service_id": BS,
            "package_id": PKG,
            "package_revision": 3,
            "edition_index": 2,
            "macs": ["02:00:00:00:00:01"],
            "disk": {
                "disk_token": "00112233445566778899aabbccddeeff",
                "bus": "nvme",
                "model": "Disk 1",
                "serial": "S1",
                "size_bytes": 128_000_000_000u64,
                "logical_sector": 512,
                "physical_sector": 4096,
                "removable": false,
                "partitions": []
            },
            "state": "failed",
            "current_step": 1,
            "steps": [{"step": 1, "kind": "verify_content", "state": "failed"}],
            "failure": {
                "step": 1,
                "category": "integrity",
                "code": "chunk_digest_mismatch",
                "files": [{"role": "image", "name": "install.wim"}],
                "count": 1,
                "attempts": 1
            },
            "failed_at": 1_793_097_001_000_000i64,
            "attempts": 1,
            "acknowledged": false,
            "started_at": 1_793_097_000_000_000i64
        }))
        .unwrap()
    }

    /// REQ-JOB-005/006: the persistent error is visible to the operator.
    #[test]
    fn job_show_has_persistent_error() {
        let e = Env::new(
            vec![route("GET", &format!("/v1/jobs/{JOB}"), 200, failed_job())],
            None,
        );
        let o = e.run(&["job", "show", JOB], b"");
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        let out = stdout(&o);
        assert!(out.contains("state:    failed"), "{out}");
        assert!(
            out.contains("chunk_digest_mismatch (integrity), needs attention"),
            "{out}"
        );
        assert!(out.contains("image install.wim"), "{out}");
    }

    #[test]
    fn boot_stop_clear_posts_without_body() {
        let stop = serde_json::json!({
            "id": STOP,
            "boot_service_id": BS,
            "mac": "02:00:00:00:00:01",
            "job_id": JOB,
            "created_at": 0,
            "cleared_at": 1_000_000
        });
        let e = Env::new(
            vec![route(
                "POST",
                &format!("/v1/boot-stops/{STOP}/clear"),
                200,
                serde_json::to_vec(&stop).unwrap(),
            )],
            None,
        );
        let o = e.run(&["boot-stop", "clear", STOP], b"");
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        assert!(stdout(&o).contains(&format!("cleared boot stop {STOP}")));
        assert!(e.seen().first().unwrap().body.is_empty());
    }
}

#[cfg(test)]
mod cli {
    use std::path::Path;
    use std::process::{Command, Output};

    const ID: &str = "0b7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e6f";

    fn cli(home: &Path, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_usgp-cli"))
            .args(args)
            .env("HOME", home)
            .output()
            .expect("spawn usgp-cli")
    }

    fn stderr(o: &Output) -> String {
        String::from_utf8_lossy(&o.stderr).into_owned()
    }

    #[test]
    fn usage_errors_exit_2_with_usage() {
        let home = std::env::temp_dir();
        for args in [
            &["code"][..],
            &["code", "issue", "--ttl", "soon"],
            &["session", "approve", ID],
            &["job", "retry", ID],
            &["boot-service", "set-packages", ID],
            &["boot-stop", "clear"],
        ] {
            let o = cli(&home, args);
            assert_eq!(o.status.code(), Some(2), "{args:?}: {}", stderr(&o));
            assert!(stderr(&o).contains("usage: usgp-cli"), "{args:?}");
            assert!(o.stdout.is_empty(), "{args:?}");
        }
    }

    #[test]
    fn help_lists_m3_commands() {
        let o = cli(&std::env::temp_dir(), &["code", "--help"]);
        assert_eq!(o.status.code(), Some(0));
        let out = String::from_utf8(o.stdout).unwrap();
        for want in [
            "code issue [--ttl SECONDS] [--note TEXT]",
            "session approve --display-code CODE [ID]",
            "job list [--state S] | show ID | ack ID",
            "boot-service set-packages ID (PACKAGE_ID... | --none) [--if-match TAG]",
            "boot-stop list | clear ID",
            "boot-manifest create --pe-kit",
            "never generated",
        ] {
            assert!(out.contains(want), "missing {want:?} in {out}");
        }
    }
}
