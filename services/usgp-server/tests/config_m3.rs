//! M3 additions to `server.toml` (plan M3 section 3.9; WU-10): the
//! device listener, operator codes, job settings and the plan,
//! boot-policy and code HMAC keys.
//!
//! | Rule | Test |
//! |------|------|
//! | the plan's example parses onto `ApiConfig.device`; values as written | `m3_example_parses` |
//! | without M3 sections: listener off, no keys, `DeviceConfig` defaults | `m3_defaults_off` |
//! | listener on needs the three keys, its certificate and key, its own address | `device_listener_requirements` |
//! | the three keys come together, each its own file | `provisioning_keys_together_and_distinct` |
//! | ranges (usgp-api `DeviceConfig::validate`) and unknown keys refused | `m3_ranges_and_unknown_keys` |
//! | `prepare` loads the keys and device TLS; key reuse, short HMAC key, readable key refused | `prepare_loads_m3_material` |
//! | `--check-config` prints key ids and the device listener, never a secret | `check_config_m3` |
//! | `keygen` for plan, boot-policy and code-hmac | `keygen_m3_purposes` |

#[cfg(test)]
pub mod common;

#[cfg(test)]
mod config_m3 {
    use std::process::{Command, Output};
    use std::time::Duration;

    use usgp_api::DeviceConfig;
    use usgp_common::config::TrustPolicy;
    use usgp_crypto::tls::TlsMinVersion;
    use usgp_server::config::{ConfigLoadError, load, parse_text};
    use usgp_server::keys::KeyLoadError;
    use usgp_server::serve::{ServeError, prepare};

    use crate::common::{Fixture, Scratch, admin_uid, set_mode};

    const M2_EXAMPLE: &str = include_str!("fixtures/server-v1.toml");
    const M3_EXAMPLE: &str = include_str!("fixtures/server-m3.toml");

    fn key_of(e: &ConfigLoadError) -> String {
        match e {
            ConfigLoadError::Invalid(i) => i.key.clone(),
            ConfigLoadError::File(f) => format!("file: {f}"),
        }
    }

    fn with(base: &str, find: &str, replace: &str) -> String {
        assert!(base.contains(find), "fixture lacks {find:?}");
        base.replacen(find, replace, 1)
    }

    fn refused(text: &str) -> String {
        key_of(&parse_text(text, None).expect_err("must be refused"))
    }

    fn trust() -> TrustPolicy {
        TrustPolicy::with_admin(admin_uid())
    }

    fn server(args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_usgp-server"))
            .args(args)
            .output()
            .expect("spawn usgp-server")
    }

    fn text(b: &[u8]) -> String {
        String::from_utf8_lossy(b).into_owned()
    }

    #[test]
    fn m3_example_parses() {
        let c = parse_text(M3_EXAMPLE, None).unwrap();
        let d = &c.api.device;
        assert!(d.enabled);
        // Every value of the example equals the documented default.
        assert_eq!(
            *d,
            DeviceConfig {
                enabled: true,
                ..DeviceConfig::default()
            }
        );
        let l = c.device_listener.as_ref().unwrap();
        assert_eq!(l.listen.to_string(), "192.0.2.10:8444");
        assert_eq!(
            l.cert_chain.to_str(),
            Some("/etc/usgp-server/tls/device.pem")
        );
        assert_eq!(l.min_version, TlsMinVersion::Tls12);
        let k = c.provisioning.as_ref().unwrap();
        assert_eq!(k.plan_key.to_str(), Some("/etc/usgp-server/keys/plan.p8"));
        assert_eq!(
            k.boot_policy_key.to_str(),
            Some("/etc/usgp-server/keys/boot-policy.p8")
        );
        assert_eq!(
            k.code_hmac_key.to_str(),
            Some("/etc/usgp-server/keys/code-hmac.key")
        );
        // Values other than the defaults land in the right fields.
        let t = with(M3_EXAMPLE, "poll_ms = 2000", "poll_ms = 5000");
        let t = with(&t, "max_ttl_s = 3600", "max_ttl_s = 7200");
        let t = with(&t, "lost_after_s = 900", "lost_after_s = 600");
        let t = with(&t, "timeout_apply_s = 21600", "timeout_apply_s = 3600");
        let t = with(
            &t,
            "progress_min_interval_ms = 2000",
            "progress_min_interval_ms = 500",
        );
        // Finding SEC-001 settings.
        let t = with(
            &t,
            "max_pending_sessions_per_boot_service = 32",
            "max_pending_sessions_per_boot_service = 8",
        );
        let t = with(
            &t,
            "unauthorised_idle_timeout_s = 120",
            "unauthorised_idle_timeout_s = 300",
        );
        let t = with(
            &t,
            "session_opens_per_min = 120",
            "session_opens_per_min = 60",
        );
        let c = parse_text(&t, None).unwrap();
        assert_eq!(c.api.device.max_pending_sessions_per_boot_service, 8);
        assert_eq!(
            c.api.device.unauthorised_idle_timeout,
            Duration::from_secs(300)
        );
        assert_eq!(c.api.device.session_opens_per_min, 60);
        assert_eq!(c.api.device.poll_ms, 5000);
        assert_eq!(c.api.device.code_max_ttl, Duration::from_secs(7200));
        assert_eq!(c.api.device.jobs.lost_after, Duration::from_secs(600));
        assert_eq!(c.api.device.jobs.timeout_apply_s, 3600);
        assert_eq!(
            c.api.device.progress_min_interval,
            Duration::from_millis(500)
        );
    }

    #[test]
    fn m3_defaults_off() {
        let c = parse_text(M2_EXAMPLE, None).unwrap();
        assert_eq!(c.api.device, DeviceConfig::default());
        assert!(!c.api.device.enabled);
        assert!(c.device_listener.is_none());
        assert!(c.provisioning.is_none());
        // Keys without the listener: allowed (the relay feed needs the
        // boot-policy key; codes can be issued).
        let t = with(M3_EXAMPLE, "enabled = true", "enabled = false");
        let c = parse_text(&t, None).unwrap();
        assert!(c.device_listener.is_none());
        assert!(c.provisioning.is_some());
        assert!(!c.api.device.enabled);
    }

    #[test]
    fn device_listener_requirements() {
        // On without the keys.
        let no_keys = with(
            M3_EXAMPLE,
            "plan_key = \"/etc/usgp-server/keys/plan.p8\"\n\
             boot_policy_key = \"/etc/usgp-server/keys/boot-policy.p8\"\n",
            "",
        );
        let no_keys = with(
            &no_keys,
            "hmac_key = \"/etc/usgp-server/keys/code-hmac.key\"\n",
            "",
        );
        assert_eq!(refused(&no_keys), "device_api.enabled");
        // On without its certificate or key.
        let t = with(
            M3_EXAMPLE,
            "cert_chain = \"/etc/usgp-server/tls/device.pem\"\n",
            "",
        );
        assert_eq!(refused(&t), "device_api.cert_chain");
        let t = with(
            M3_EXAMPLE,
            "private_key = \"/etc/usgp-server/tls/device.key\"\n",
            "",
        );
        assert_eq!(refused(&t), "device_api.private_key");
        // Relative path, bad address, bad TLS version.
        let t = with(
            M3_EXAMPLE,
            "\"/etc/usgp-server/tls/device.pem\"",
            "\"device.pem\"",
        );
        assert_eq!(refused(&t), "device_api.cert_chain");
        let t = with(M3_EXAMPLE, "\"192.0.2.10:8444\"", "\"device-host\"");
        assert_eq!(refused(&t), "device_api.listen");
        let t = with(
            M3_EXAMPLE,
            "min_version = \"1.2\"\nmax_connections = 256",
            "min_version = \"1.1\"\nmax_connections = 256",
        );
        assert_eq!(refused(&t), "device_api.min_version");
        // The operator listener's address.
        let t = with(M3_EXAMPLE, "\"192.0.2.10:8444\"", "\"127.0.0.1:8443\"");
        assert_eq!(refused(&t), "device_api.listen");
        // Default address: loopback.
        let t = with(M3_EXAMPLE, "listen = \"192.0.2.10:8444\"\n", "");
        let c = parse_text(&t, None).unwrap();
        assert_eq!(
            c.device_listener.unwrap().listen.to_string(),
            "127.0.0.1:8444"
        );
        // Off: its certificate and key may be absent.
        let t = with(M3_EXAMPLE, "enabled = true", "enabled = false");
        let t = with(&t, "cert_chain = \"/etc/usgp-server/tls/device.pem\"\n", "");
        assert!(parse_text(&t, None).is_ok());
    }

    #[test]
    fn provisioning_keys_together_and_distinct() {
        let off = with(M3_EXAMPLE, "enabled = true", "enabled = false");
        let t = with(&off, "plan_key = \"/etc/usgp-server/keys/plan.p8\"\n", "");
        assert_eq!(refused(&t), "signing.plan_key");
        let t = with(
            &off,
            "boot_policy_key = \"/etc/usgp-server/keys/boot-policy.p8\"\n",
            "",
        );
        assert_eq!(refused(&t), "signing.boot_policy_key");
        let t = with(
            &off,
            "hmac_key = \"/etc/usgp-server/keys/code-hmac.key\"\n",
            "",
        );
        assert_eq!(refused(&t), "codes.hmac_key");
        // One key per purpose: no file serves two.
        let t = with(
            M3_EXAMPLE,
            "plan_key = \"/etc/usgp-server/keys/plan.p8\"",
            "plan_key = \"/etc/usgp-server/keys/content.p8\"",
        );
        assert_eq!(refused(&t), "signing.plan_key");
        let t = with(
            M3_EXAMPLE,
            "boot_policy_key = \"/etc/usgp-server/keys/boot-policy.p8\"",
            "boot_policy_key = \"/etc/usgp-server/keys/plan.p8\"",
        );
        assert_eq!(refused(&t), "signing.boot_policy_key");
        let t = with(
            M3_EXAMPLE,
            "hmac_key = \"/etc/usgp-server/keys/code-hmac.key\"",
            "hmac_key = \"/etc/usgp-server/keys/audit.p8\"",
        );
        assert_eq!(refused(&t), "codes.hmac_key");
    }

    #[test]
    fn m3_ranges_and_unknown_keys() {
        for (find, replace, key) in [
            (
                "max_json_bytes = 65536\npending",
                "max_json_bytes = 65537\npending",
                "device_api.max_json_bytes",
            ),
            (
                "pending_session_ttl_s = 3600",
                "pending_session_ttl_s = 10",
                "device_api.pending_session_ttl_s",
            ),
            (
                "code_attempts_per_session = 5",
                "code_attempts_per_session = 0",
                "device_api.code_attempts_per_session",
            ),
            (
                "max_pending_sessions_per_ip = 4",
                "max_pending_sessions_per_ip = 65",
                "device_api.max_pending_sessions",
            ),
            ("poll_ms = 2000", "poll_ms = 100", "device_api.poll_ms"),
            // Finding SEC-001.
            (
                "max_pending_sessions_per_boot_service = 32",
                "max_pending_sessions_per_boot_service = 65",
                "device_api.max_pending_sessions_per_boot_service",
            ),
            (
                "unauthorised_idle_timeout_s = 120",
                "unauthorised_idle_timeout_s = 10",
                "device_api.unauthorised_idle_timeout_s",
            ),
            (
                "session_opens_per_min = 120",
                "session_opens_per_min = 0",
                "device_api.session_opens_per_min",
            ),
            (
                "default_ttl_s = 900",
                "default_ttl_s = 7200",
                "codes.default_ttl_s",
            ),
            (
                "max_ttl_s = 3600",
                "max_ttl_s = 90000",
                "codes.default_ttl_s",
            ),
            (
                "retry_base_ms = 2000",
                "retry_base_ms = 70000",
                "jobs.retry_base_ms",
            ),
            (
                "retry_attempts = 5",
                "retry_attempts = 0",
                "jobs.retry_attempts",
            ),
            (
                "timeout_boot_s = 1800",
                "timeout_boot_s = 0",
                "jobs.timeout_s",
            ),
            (
                "lost_after_s = 900",
                "lost_after_s = 30",
                "jobs.lost_after_s",
            ),
            // Negative values are refused before the range check.
            (
                "max_connections = 256",
                "max_connections = -1",
                "device_api.max_connections",
            ),
            ("poll_ms = 2000", "poll_ms = -2000", "device_api.poll_ms"),
        ] {
            let t = with(M3_EXAMPLE, find, replace);
            assert_eq!(refused(&t), key, "{replace}");
        }
        // Unknown keys refuse start (CM-7), in every new section; there
        // is no setting to skip TLS or signature checks.
        for (section, extra) in [
            ("[device_api]\n", "require_client_cert = false\n"),
            ("[device_api]\n", "skip_tls = true\n"),
            ("[codes]\n", "length = 6\n"),
            ("[jobs]\n", "verify_signatures = false\n"),
        ] {
            let t = with(M3_EXAMPLE, section, &format!("{section}{extra}"));
            assert!(
                key_of(&parse_text(&t, None).unwrap_err()).starts_with("file:"),
                "{extra}"
            );
        }
        let t = format!("{M3_EXAMPLE}\n[boot_policy]\npoll_s = 30\n");
        assert!(parse_text(&t, None).is_err());
    }

    #[test]
    fn prepare_loads_m3_material() {
        let f = Fixture::new("m3-prepare");
        let path = f.write_config(&f.config_text_m3(&f.unreachable_db()));
        let cfg = load(&path, &trust()).unwrap().config;
        let p = prepare(&cfg, &trust()).unwrap();
        let k = p.provisioning.as_ref().unwrap();
        assert_eq!(k.plan_key_id(), f.plan_pub.key_id());
        assert_eq!(k.boot_policy_key_id(), f.policy_pub.key_id());
        assert!(p.device_tls.as_ref().unwrap().is_fips());
        // Redacted.
        assert!(format!("{k:?}").contains("<redacted>"));

        // The plan key file holding the content key: refused (one key,
        // one purpose), exit 78.
        let f = Fixture::new("m3-reuse");
        std::fs::copy(f.scratch.path("content.p8"), f.scratch.path("plan.p8")).unwrap();
        let cfg = load(
            &f.write_config(&f.config_text_m3(&f.unreachable_db())),
            &trust(),
        )
        .unwrap()
        .config;
        let e = prepare(&cfg, &trust()).unwrap_err();
        assert_eq!(e.reason(), "plan_key_reused");
        assert_eq!(e.exit_code(), 78);
        // Plan and boot-policy keys the same key.
        let f = Fixture::new("m3-reuse2");
        std::fs::copy(f.scratch.path("plan.p8"), f.scratch.path("boot-policy.p8")).unwrap();
        let cfg = load(
            &f.write_config(&f.config_text_m3(&f.unreachable_db())),
            &trust(),
        )
        .unwrap()
        .config;
        assert_eq!(
            prepare(&cfg, &trust()).unwrap_err().reason(),
            "boot_policy_key_reused"
        );

        // The HMAC key: exactly 32 bytes; a trailing newline or a short
        // file is refused, and so is a file readable by others.
        for (bytes, mode, what) in [
            (vec![7u8; 31], 0o600, "31 bytes"),
            (
                {
                    let mut v = vec![7u8; 32];
                    v.push(b'\n');
                    v
                },
                0o600,
                "newline",
            ),
            (vec![7u8; 32], 0o644, "readable by others"),
        ] {
            let f = Fixture::new("m3-hmac");
            f.scratch.write("code-hmac.key", &bytes, mode);
            let cfg = load(
                &f.write_config(&f.config_text_m3(&f.unreachable_db())),
                &trust(),
            )
            .unwrap()
            .config;
            match prepare(&cfg, &trust()) {
                Err(ServeError::Key(
                    e @ (KeyLoadError::Key { .. } | KeyLoadError::KeyFile { .. }),
                )) => {
                    assert_eq!(e.key(), "codes.hmac_key", "{what}");
                    // The error never carries key bytes.
                    assert!(!e.to_string().contains("\u{7}"), "{what}");
                }
                other => panic!("{what}: {other:?}"),
            }
        }

        // The device key readable by others is refused like the
        // operator listener's.
        let f = Fixture::new("m3-devkey");
        let cfg = load(
            &f.write_config(&f.config_text_m3(&f.unreachable_db())),
            &trust(),
        )
        .unwrap()
        .config;
        set_mode(&f.scratch.path("server.key"), 0o644);
        let e = prepare(&cfg, &trust()).unwrap_err();
        assert_eq!(e.exit_code(), 78);
    }

    #[test]
    fn check_config_m3() {
        let f = Fixture::new("m3-check");
        let p = f.write_config(&f.config_text_m3(&f.unreachable_db()));
        let uid = admin_uid().to_string();
        let out = server(&["--check-config", p.to_str().unwrap(), "--admin-uid", &uid]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        let stdout = text(&out.stdout);
        assert!(stdout.contains("configuration: valid"), "{stdout}");
        assert!(
            stdout.contains(&format!("plan key id: {}", f.plan_pub.key_id())),
            "{stdout}"
        );
        assert!(
            stdout.contains(&format!("boot-policy key id: {}", f.policy_pub.key_id())),
            "{stdout}"
        );
        assert!(stdout.contains("device listen: 127.0.0.1:0"), "{stdout}");
        assert!(!stdout.contains("PRIVATE KEY"));
        let hmac = std::fs::read(f.scratch.path("code-hmac.key")).unwrap();
        let hex: String = hmac.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!stdout.contains(&hex));
        // An invalid M3 value: exit 78 naming the key.
        let bad = f
            .config_text_m3(&f.unreachable_db())
            .replace("max_ttl_s = 3600", "max_ttl_s = 30");
        let p = f.write_config(&bad);
        let out = server(&["--check-config", p.to_str().unwrap(), "--admin-uid", &uid]);
        assert_eq!(out.status.code(), Some(78), "{}", text(&out.stderr));
        // The M2 configuration: keys not configured, listener off.
        let p = f.write_config(&f.config_text(&f.unreachable_db()));
        let out = server(&["--check-config", p.to_str().unwrap(), "--admin-uid", &uid]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        let stdout = text(&out.stdout);
        assert!(stdout.contains("device listen: off"), "{stdout}");
        assert!(
            stdout.contains("provisioning keys: not configured"),
            "{stdout}"
        );
    }

    #[test]
    fn keygen_m3_purposes() {
        use std::os::unix::fs::PermissionsExt;
        let s = Scratch::new("keygen-m3");
        for purpose in ["plan", "boot-policy"] {
            let k = s.path(&format!("{purpose}.p8"));
            let pubk = s.path(&format!("{purpose}.pub"));
            let out = server(&[
                "keygen",
                "--purpose",
                purpose,
                "--out-key",
                k.to_str().unwrap(),
                "--out-pub",
                pubk.to_str().unwrap(),
            ]);
            assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
            let public =
                usgp_crypto::VerifyingKey::from_spki_pem(&std::fs::read(&pubk).unwrap()).unwrap();
            let stdout = text(&out.stdout);
            assert!(stdout.contains(&public.key_id().to_hex()), "{stdout}");
            assert!(stdout.contains(&format!("purpose: {purpose}")), "{stdout}");
        }
        // The code HMAC key: exactly 32 raw bytes, 0600, no public file.
        let k = s.path("code-hmac.key");
        let args = [
            "keygen",
            "--purpose",
            "code-hmac",
            "--out-key",
            k.to_str().unwrap(),
        ];
        let out = server(&args);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        let meta = std::fs::metadata(&k).unwrap();
        assert_eq!(meta.len(), 32);
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        let bytes = std::fs::read(&k).unwrap();
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let stdout = text(&out.stdout);
        assert!(stdout.contains("purpose: code-hmac"), "{stdout}");
        assert!(stdout.contains("key.generated"), "{stdout}");
        assert!(
            !stdout.contains(&hex) && !stdout.contains("key id:"),
            "{stdout}"
        );
        // The mirrored record in the shape e2e_pg parses: `event` and
        // `interface` at top level, the record fields inside `detail`,
        // which is a JSON string (so `"actor_kind":"..."` is not literal
        // text in the line).
        let lines: Vec<String> = stdout.lines().map(str::to_owned).collect();
        let recs = crate::common::pg::mirrored(&lines);
        let rec = recs
            .iter()
            .find(|r| r.event == "key.generated")
            .unwrap_or_else(|| panic!("no key.generated: {stdout}"));
        assert_eq!(rec.interface, "server-cli");
        assert_eq!(rec.detail["actor_kind"], "local_user");
        assert!(
            !stdout.contains("\"actor_kind\":\"local_user\""),
            "{stdout}"
        );
        // Never overwritten.
        let out = server(&args);
        assert_eq!(out.status.code(), Some(1));
        assert_eq!(std::fs::read(&k).unwrap(), bytes);
        // `--out-pub` is a usage error for code-hmac; required otherwise.
        let out = server(&[
            "keygen",
            "--purpose",
            "code-hmac",
            "--out-key",
            s.path("c2").to_str().unwrap(),
            "--out-pub",
            s.path("c2.pub").to_str().unwrap(),
        ]);
        assert_eq!(out.status.code(), Some(2));
        let out = server(&[
            "keygen",
            "--purpose",
            "plan",
            "--out-key",
            s.path("p2").to_str().unwrap(),
        ]);
        assert_eq!(out.status.code(), Some(2));
        assert!(!s.path("c2").exists() && !s.path("p2").exists());
    }
}
