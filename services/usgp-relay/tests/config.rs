//! Configuration validation (plan section 3.4): defaults, every range and
//! rule, and the file trust checks.
//!
//! Range rules are exercised on `ConfigDocument` values; the golden v1
//! files (`tests/fixtures/`) and `load` cover TOML decoding end to end.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: CM-6, SI-10, SC-7, CM-5, SI-7 (trusted files)
//! - SPEC: specs/boot-network.md#REQ-BOOT-022, #REQ-BOOT-044, #REQ-BOOT-053

#[cfg(test)]
pub mod common;

#[cfg(test)]
mod config {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use usgp_common::config::{ConfigError, TrustPolicy, TrustRule};
    use usgp_common::telemetry::Level;
    use usgp_relay::config::{
        BootDocument, ConfigDocument, ConfigLoadError, InterfaceDocument, LimitsDocument,
        LogDocument, MAX_CONFIG_BYTES, RelayConfig, SuppressionDocument, TftpDocument,
        check_trust_paths, load, parse_document,
    };
    use usgp_relay::suppress::SuppressionList;

    use crate::common::{
        PROGRAM, Scratch, admin_uid, config, doc, set_mode, trust, write_config_toml,
    };

    const GOLDEN: &str = include_str!("fixtures/relay-v1.toml");
    const GOLDEN_SUPPRESSION: &str = include_str!("fixtures/suppress-v1.toml");

    #[test]
    fn golden_v1_config_parses() {
        let c = RelayConfig::from_document(&parse_document(GOLDEN).unwrap()).unwrap();
        let names: Vec<(&str, Ipv4Addr)> = c
            .interfaces
            .iter()
            .map(|i| (i.name.as_str(), i.address))
            .collect();
        assert_eq!(
            names,
            vec![
                ("relay0", Ipv4Addr::new(10, 20, 1, 2)),
                ("eth1.30", Ipv4Addr::new(10, 30, 0, 2)),
            ]
        );
        assert_eq!(
            c.boot.manifest,
            std::path::Path::new("/etc/usgp-relay/boot-manifest.toml")
        );
        assert_eq!(c.boot.root, std::path::Path::new("/srv/usgp-relay/boot"));
        assert_eq!(c.boot.uefi_x64_program.as_str(), PROGRAM);
        let l = c.limits;
        assert_eq!(l.dhcp_client_burst, 9);
        assert_eq!(l.dhcp_client_refill, Duration::from_millis(2100));
        assert_eq!(l.dhcp_relay_burst, 201);
        assert_eq!(l.dhcp_relay_per_sec, 51);
        assert_eq!(l.dhcp_global_per_sec, 201);
        assert_eq!(l.dhcp_relayed_global_per_sec, 202);
        assert_eq!(l.tracked_clients, 4097);
        assert_eq!(l.tftp_max_transfers, 65);
        assert_eq!(l.tftp_max_pending, 17);
        assert_eq!(l.tftp_per_client_transfers, 5);
        assert_eq!(l.tftp_rrq_burst, 9);
        assert_eq!(l.tftp_rrq_refill, Duration::from_millis(1100));
        assert_eq!(l.tftp_rrq_global_per_sec, 51);
        assert_eq!(l.tftp_rrq_global_burst, 101);
        assert_eq!(l.tftp_error_per_sec, 21);
        assert_eq!(l.verify_concurrency, 3);
        let t = c.tftp;
        assert_eq!(t.max_block_size, 1428);
        assert_eq!(t.initial_timeout, Duration::from_millis(1500));
        assert_eq!(t.min_timeout, Duration::from_millis(300));
        assert_eq!(t.max_timeout, Duration::from_millis(9000));
        assert_eq!(t.max_retries, 6);
        assert_eq!(t.handshake_retries, 3);
        assert_eq!(t.handshake_timeout, Duration::from_millis(2100));
        assert_eq!(t.max_transfer, Duration::from_secs(601));
        assert_eq!(t.max_file_size, 33_554_432);
        assert_eq!(t.max_window_size, 4);
        assert_eq!(t.block_wrap, usgp_tftp::BlockWrap::One);
        let f = c.server_feed.as_ref().expect("server_feed enabled");
        assert_eq!(f.url.host, "server.lab");
        assert_eq!(f.url.port, 8443);
        assert_eq!(f.server_name, "api.server.lab");
        assert_eq!(
            f.boot_service_id.to_string(),
            "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b"
        );
        assert_eq!(f.poll_interval, Duration::from_secs(45));
        assert_eq!(
            f.cache_file.as_deref(),
            Some(std::path::Path::new("/var/lib/usgp-relay/boot-policy.json"))
        );
        assert_eq!(c.recheck_interval, Duration::from_secs(61));
        assert_eq!(
            c.suppression.file.as_deref(),
            Some(std::path::Path::new("/etc/usgp-relay/suppress.toml"))
        );
        assert_eq!(c.suppression.reload_interval, Duration::from_secs(3));
        assert_eq!(c.log.level, Level::DEBUG);
        assert_eq!(c.log.node_name.as_deref(), Some("relay-a.lab"));
    }

    #[test]
    fn golden_v1_suppression_parses() {
        let d = usgp_relay::suppress::parse_document(GOLDEN_SUPPRESSION).unwrap();
        let l = SuppressionList::from_document(&d).unwrap();
        assert_eq!(l.len(), 2);
        let mac = "52:54:00:12:34:56".parse().unwrap();
        assert!(l.contains(mac, None));
        let guid = "00112233-4455-6677-8899-aabbccddeeff".parse().unwrap();
        assert!(l.contains("52:54:00:00:00:09".parse().unwrap(), Some(guid)));
    }

    #[test]
    fn golden_with_any_unknown_key_refused() {
        // Adding an unknown key to any table of the golden file is refused
        // (deny_unknown_fields at every level).
        for table in [
            "[[interface]]",
            "[boot]",
            "[limits]",
            "[tftp]",
            "[content]",
            "[suppression]",
            "[server_feed]",
            "[log]",
        ] {
            let text = GOLDEN.replacen(table, &format!("{table}\nunknown_key = 1"), 1);
            assert!(
                matches!(
                    parse_document(&text),
                    Err(ConfigLoadError::File(ConfigError::Parse { .. }))
                ),
                "{table}"
            );
        }
        let text = format!("unknown_top = 1\n{GOLDEN}");
        assert!(parse_document(&text).is_err());
    }

    #[test]
    fn load_end_to_end() {
        let s = Scratch::new("load-e2e");
        s.publish(&[(PROGRAM, b"payload")]);
        let p = write_config_toml(&s, "[log]\nlevel = \"warn\"\n");
        let loaded = load(&p, trust()).unwrap();
        assert_eq!(loaded.config, {
            let mut c = config(&s);
            c.log.level = Level::WARN;
            // SEC-010: the loaded root is the canonical path.
            c.boot.root = std::fs::canonicalize(s.root()).unwrap();
            c
        });
        let bytes = std::fs::read(&p).unwrap();
        assert_eq!(loaded.sha256, usgp_crypto::sha256(&bytes));
    }

    #[test]
    fn load_reports_parse_position() {
        let s = Scratch::new("load-pos");
        s.publish(&[(PROGRAM, b"payload")]);
        let p = write_config_toml(&s, "[limits]\nnot_a_key = 3\n");
        match load(&p, trust()).unwrap_err() {
            ConfigLoadError::File(ConfigError::Parse { line, .. }) => assert!(line > 10, "{line}"),
            other => panic!("{other:?}"),
        }
        let p = write_config_toml(&s, "[limits]\ndhcp_client_burst = 0\n");
        assert_eq!(
            load(&p, trust()).unwrap_err().field(),
            "limits.dhcp_client_burst"
        );
    }

    fn field_of(d: &ConfigDocument) -> String {
        RelayConfig::from_document(d).unwrap_err().field
    }

    #[test]
    fn minimal_document_gets_plan_defaults() {
        let s = Scratch::new("defaults");
        let c = config(&s);
        assert_eq!(c.interfaces.len(), 1);
        assert_eq!(c.boot.uefi_x64_program.as_str(), PROGRAM);
        let l = c.limits;
        assert_eq!(l.dhcp_client_burst, 8);
        assert_eq!(l.dhcp_client_refill, Duration::from_millis(2000));
        assert_eq!(l.dhcp_relay_burst, 200);
        assert_eq!(l.dhcp_relay_per_sec, 50);
        assert_eq!(l.dhcp_global_per_sec, 200);
        assert_eq!(l.dhcp_relayed_global_per_sec, 200);
        assert_eq!(l.tracked_clients, 4096);
        assert_eq!(l.tftp_max_transfers, 64);
        // SEC-001: pending cap well above the established cap.
        assert_eq!(l.tftp_max_pending, 256);
        assert_eq!(l.tftp_per_client_transfers, 4);
        assert_eq!(l.tftp_rrq_burst, 8);
        assert_eq!(l.tftp_rrq_refill, Duration::from_millis(1000));
        assert_eq!(l.tftp_rrq_global_per_sec, 50);
        assert_eq!(l.tftp_rrq_global_burst, 100);
        assert_eq!(l.tftp_error_per_sec, 20);
        assert_eq!(l.verify_concurrency, 2);
        let t = c.tftp;
        assert_eq!(t.max_block_size, 1468);
        assert_eq!(t.initial_timeout, Duration::from_millis(1000));
        assert_eq!(t.min_timeout, Duration::from_millis(250));
        assert_eq!(t.max_timeout, Duration::from_millis(8000));
        assert_eq!(t.max_retries, 5);
        // SEC-001: one resend and at most 2 s before the first ACK.
        assert_eq!(t.handshake_retries, 1);
        assert_eq!(t.handshake_timeout, Duration::from_millis(2000));
        // M3 (plan section 3.9): Windows PE image defaults, window 8,
        // wrap to zero.
        assert_eq!(t.max_transfer, Duration::from_secs(1800));
        assert_eq!(t.max_file_size, 1_073_741_824);
        assert_eq!(t.max_window_size, 8);
        assert_eq!(t.block_wrap, usgp_tftp::BlockWrap::Zero);
        assert_eq!(c.tftp_window_config(), usgp_tftp::WindowConfig::default());
        assert_eq!(c.server_feed, None);
        assert_eq!(c.recheck_interval, Duration::from_secs(60));
        assert_eq!(c.suppression.file, None);
        assert_eq!(c.suppression.reload_interval, Duration::from_secs(2));
        assert_eq!(c.log.level, Level::INFO);
        assert_eq!(c.log.node_name, None);
        // The sans-IO server config carries the same values; the relay
        // shortens the handshake (one resend) relative to the library
        // default and uses the M3 large-file limits.
        assert_eq!(
            c.tftp_server_config(),
            usgp_tftp::ServerConfig {
                handshake_retries: 1,
                max_file_size: usgp_tftp::LARGE_FILE_MAX_SIZE,
                max_duration: usgp_tftp::LARGE_FILE_MAX_DURATION,
                ..usgp_tftp::ServerConfig::default()
            }
        );
        assert_eq!(
            c.tftp_listener_config().handshake_timeout,
            Duration::from_millis(2000)
        );
        // Outside `load`, only root is trusted.
        let d = RelayConfig::from_document(&doc(&s)).unwrap();
        assert_eq!(d.trust, TrustPolicy::root_only());
    }

    #[test]
    fn schema_version_rules() {
        let s = Scratch::new("schema");
        for v in [None, Some(0), Some(2), Some(-1)] {
            let mut d = doc(&s);
            d.schema_version = v;
            assert_eq!(field_of(&d), "schema_version", "{v:?}");
        }
    }

    #[test]
    fn interface_count_rules() {
        let s = Scratch::new("iface-count");
        let mut d = doc(&s);
        d.interface.clear();
        assert_eq!(field_of(&d), "interface");
        let mut d = doc(&s);
        d.interface = (0..17u8)
            .map(|i| InterfaceDocument {
                name: Some(format!("eth{i}")),
                address: Some(format!("10.0.{i}.1")),
                prefix_len: None,
            })
            .collect();
        assert_eq!(field_of(&d), "interface");
        d.interface.pop();
        assert!(RelayConfig::from_document(&d).is_ok());
    }

    fn with_iface(s: &Scratch, name: Option<&str>, addr: Option<&str>) -> ConfigDocument {
        let mut d = doc(s);
        d.interface = vec![InterfaceDocument {
            name: name.map(str::to_owned),
            address: addr.map(str::to_owned),
            prefix_len: None,
        }];
        d
    }

    #[test]
    fn interface_name_rules() {
        let s = Scratch::new("iface-name");
        for bad in [
            None,
            Some(""),
            Some("abcdefghijklmnop"),
            Some("eth 0"),
            Some("*"),
            Some(".."),
        ] {
            let d = with_iface(&s, bad, Some("10.0.0.1"));
            assert_eq!(field_of(&d), "interface[0].name", "{bad:?}");
        }
        let mut d = doc(&s);
        d.interface.push(InterfaceDocument {
            name: d.interface[0].name.clone(),
            address: Some("10.0.0.9".to_owned()),
            prefix_len: None,
        });
        assert_eq!(field_of(&d), "interface[1].name");
    }

    /// SEC-010: a boot root configured through a symbolic link is resolved
    /// once at load; retargeting the link later does not change where boot
    /// files are read from.
    #[tokio::test]
    async fn boot_root_resolved_once_at_load() {
        let s = Scratch::new("root-canon");
        let data = b"verified payload".to_vec();
        s.publish(&[(PROGRAM, &data)]);
        // A second directory holding a different file of the same name.
        let other = s.dir.join("other");
        std::fs::create_dir(&other).unwrap();
        set_mode(&other, 0o755);
        std::fs::write(other.join(PROGRAM), b"other bytes, same length").unwrap();
        let link = s.dir.join("root-link");
        std::os::unix::fs::symlink(s.root(), &link).unwrap();
        let p = s.dir.join("relay.toml");
        let text = std::fs::read_to_string(write_config_toml(&s, ""))
            .unwrap()
            .replace(
                &format!("root = \"{}\"", s.root().display()),
                &format!("root = \"{}\"", link.display()),
            );
        std::fs::write(&p, text).unwrap();
        set_mode(&p, 0o644);
        let cfg = load(&p, trust()).unwrap().config;
        let canonical = std::fs::canonicalize(s.root()).unwrap();
        assert_eq!(cfg.boot.root, canonical);
        let store = crate::common::content(&cfg).await;
        // Retarget the link: reads still come from the checked directory.
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&other, &link).unwrap();
        let got = store.get_verified(PROGRAM.as_bytes()).await.unwrap();
        assert_eq!(&got[..], &data[..]);
    }

    #[test]
    fn interface_prefix_len_rules() {
        let s = Scratch::new("iface-prefix");
        let mut d = doc(&s);
        assert_eq!(
            RelayConfig::from_document(&d).unwrap().interfaces[0].prefix_len,
            None
        );
        for ok in [8i64, 24, 31] {
            d.interface[0].prefix_len = Some(ok);
            let c = RelayConfig::from_document(&d).unwrap();
            assert_eq!(c.interfaces[0].prefix_len, u8::try_from(ok).ok());
        }
        for bad in [-1i64, 0, 7, 32, 33, 256] {
            d.interface[0].prefix_len = Some(bad);
            assert_eq!(field_of(&d), "interface[0].prefix_len", "{bad}");
        }
        let text = "schema_version = 1\n[[interface]]\nname = \"relay0\"\n\
                    address = \"10.20.1.2\"\nprefix_len = 24\n\
                    [boot]\nmanifest = \"/m\"\nroot = \"/r\"\n\
                    uefi_x64_program = \"p.efi\"\n";
        let c = RelayConfig::from_document(&parse_document(text).unwrap()).unwrap();
        let i = &c.interfaces[0];
        assert_eq!(i.prefix_len, Some(24));
        assert!(i.on_segment(Ipv4Addr::new(10, 20, 1, 77)));
        assert!(!i.on_segment(Ipv4Addr::new(10, 20, 2, 77)));
    }

    #[test]
    fn interface_address_rules_req_022() {
        let s = Scratch::new("iface-addr");
        for bad in [
            None,
            Some("not-an-ip"),
            Some("10.0.0"),
            Some("10.0.0.1/24"),
            Some("0.0.0.0"),
            Some("127.0.0.1"),
            Some("169.254.3.4"),
            Some("224.0.0.1"),
            Some("240.0.0.1"),
            Some("255.255.255.255"),
            Some("::1"),
        ] {
            let d = with_iface(&s, Some("eth0"), bad);
            assert_eq!(field_of(&d), "interface[0].address", "{bad:?}");
        }
        let mut d = doc(&s);
        d.interface.push(InterfaceDocument {
            name: Some("eth9".to_owned()),
            address: d.interface[0].address.clone(),
            prefix_len: None,
        });
        assert_eq!(field_of(&d), "interface[1].address");
    }

    type BootEdit = fn(&mut BootDocument);

    #[test]
    fn boot_rules() {
        let s = Scratch::new("boot");
        let mut d = doc(&s);
        d.boot = None;
        assert_eq!(field_of(&d), "boot");
        let cases: [(&str, BootEdit); 7] = [
            ("boot.manifest", |b| b.manifest = None),
            ("boot.manifest", |b| {
                b.manifest = Some("relative.toml".into())
            }),
            ("boot.root", |b| b.root = None),
            ("boot.root", |b| b.root = Some("root".into())),
            ("boot.uefi_x64_program", |b| b.uefi_x64_program = None),
            ("boot.uefi_x64_program", |b| {
                b.uefi_x64_program = Some("../x.efi".into());
            }),
            ("boot.uefi_x64_program", |b| {
                b.uefi_x64_program = Some("/abs.efi".into());
            }),
        ];
        for (field, f) in cases {
            let mut d = doc(&s);
            f(d.boot.as_mut().unwrap());
            assert_eq!(field_of(&d), field);
        }
    }

    /// (key, setter, minimum, maximum) for every numeric key.
    type Setter = fn(&mut ConfigDocument, i64);

    fn numeric_keys() -> Vec<(&'static str, Setter, i64, i64)> {
        fn l(d: &mut ConfigDocument) -> &mut LimitsDocument {
            d.limits.get_or_insert_with(LimitsDocument::default)
        }
        fn t(d: &mut ConfigDocument) -> &mut TftpDocument {
            d.tftp.get_or_insert_with(TftpDocument::default)
        }
        vec![
            (
                "limits.dhcp_client_burst",
                |d, v| l(d).dhcp_client_burst = Some(v),
                1,
                100,
            ),
            (
                "limits.dhcp_client_refill_ms",
                |d, v| l(d).dhcp_client_refill_ms = Some(v),
                100,
                60_000,
            ),
            (
                "limits.dhcp_relay_burst",
                |d, v| l(d).dhcp_relay_burst = Some(v),
                1,
                10_000,
            ),
            (
                "limits.dhcp_relay_per_sec",
                |d, v| l(d).dhcp_relay_per_sec = Some(v),
                1,
                10_000,
            ),
            (
                "limits.dhcp_global_per_sec",
                |d, v| l(d).dhcp_global_per_sec = Some(v),
                1,
                10_000,
            ),
            (
                "limits.dhcp_relayed_global_per_sec",
                |d, v| l(d).dhcp_relayed_global_per_sec = Some(v),
                1,
                10_000,
            ),
            (
                "limits.tracked_clients",
                |d, v| l(d).tracked_clients = Some(v),
                64,
                65_536,
            ),
            (
                "limits.tftp_max_transfers",
                |d, v| l(d).tftp_max_transfers = Some(v),
                1,
                1024,
            ),
            (
                "limits.tftp_max_pending",
                |d, v| l(d).tftp_max_pending = Some(v),
                1,
                4096,
            ),
            (
                "limits.tftp_per_client_transfers",
                |d, v| l(d).tftp_per_client_transfers = Some(v),
                1,
                64,
            ),
            (
                "limits.tftp_rrq_burst",
                |d, v| l(d).tftp_rrq_burst = Some(v),
                1,
                100,
            ),
            (
                "limits.tftp_rrq_refill_ms",
                |d, v| l(d).tftp_rrq_refill_ms = Some(v),
                100,
                60_000,
            ),
            (
                "limits.tftp_rrq_global_per_sec",
                |d, v| l(d).tftp_rrq_global_per_sec = Some(v),
                1,
                10_000,
            ),
            (
                "limits.tftp_rrq_global_burst",
                |d, v| l(d).tftp_rrq_global_burst = Some(v),
                1,
                10_000,
            ),
            (
                "limits.tftp_error_per_sec",
                |d, v| l(d).tftp_error_per_sec = Some(v),
                1,
                1000,
            ),
            (
                "limits.verify_concurrency",
                |d, v| l(d).verify_concurrency = Some(v),
                1,
                16,
            ),
            (
                "tftp.max_block_size",
                |d, v| t(d).max_block_size = Some(v),
                8,
                65_464,
            ),
            ("tftp.max_retries", |d, v| t(d).max_retries = Some(v), 1, 10),
            (
                "tftp.handshake_retries",
                |d, v| t(d).handshake_retries = Some(v),
                1,
                10,
            ),
            (
                "tftp.handshake_timeout_ms",
                |d, v| t(d).handshake_timeout_ms = Some(v),
                100,
                60_000,
            ),
            (
                "tftp.max_transfer_secs",
                |d, v| t(d).max_transfer_secs = Some(v),
                10,
                7200,
            ),
            (
                "tftp.max_window_size",
                |d, v| t(d).max_window_size = Some(v),
                1,
                64,
            ),
            (
                "tftp.max_file_size_bytes",
                |d, v| t(d).max_file_size_bytes = Some(v),
                1,
                4_294_967_295,
            ),
            (
                "content.recheck_interval_secs",
                |d, v| {
                    d.content
                        .get_or_insert_with(Default::default)
                        .recheck_interval_secs = Some(v);
                },
                5,
                3600,
            ),
            (
                "suppression.reload_interval_secs",
                |d, v| {
                    d.suppression
                        .get_or_insert_with(Default::default)
                        .reload_interval_secs = Some(v);
                },
                1,
                300,
            ),
        ]
    }

    #[test]
    fn every_numeric_key_range() {
        let s = Scratch::new("ranges");
        for (key, set, min, max) in numeric_keys() {
            for ok in [min, max] {
                let mut d = doc(&s);
                set(&mut d, ok);
                assert!(RelayConfig::from_document(&d).is_ok(), "{key}={ok}");
            }
            for bad in [min - 1, max + 1, -1, i64::MIN, i64::MAX] {
                if (min..=max).contains(&bad) {
                    continue;
                }
                let mut d = doc(&s);
                set(&mut d, bad);
                assert_eq!(field_of(&d), key, "{key}={bad}");
            }
        }
    }

    #[test]
    fn timeouts_must_be_ordered() {
        let s = Scratch::new("timeouts");
        let set = |min, init, max| {
            let mut d = doc(&s);
            d.tftp = Some(TftpDocument {
                min_timeout_ms: Some(min),
                initial_timeout_ms: Some(init),
                max_timeout_ms: Some(max),
                ..TftpDocument::default()
            });
            RelayConfig::from_document(&d)
        };
        assert!(set(100, 100, 100).is_ok());
        assert!(set(250, 1000, 8000).is_ok());
        assert_eq!(
            set(1001, 1000, 8000).unwrap_err().field,
            "tftp.min_timeout_ms"
        );
        assert_eq!(
            set(250, 9000, 8000).unwrap_err().field,
            "tftp.initial_timeout_ms"
        );
        for (min, init, max) in [(99, 1000, 8000), (250, 99, 8000), (250, 1000, 60_001)] {
            assert!(set(min, init, max).is_err());
        }
    }

    #[test]
    fn log_rules() {
        let s = Scratch::new("log");
        for (level, ok) in [
            ("error", true),
            ("warn", true),
            ("info", true),
            ("debug", true),
            ("trace", false),
            ("INFO", false),
            ("", false),
        ] {
            let mut d = doc(&s);
            d.log = Some(LogDocument {
                level: Some(level.to_owned()),
                node_name: None,
            });
            assert_eq!(RelayConfig::from_document(&d).is_ok(), ok, "{level}");
        }
        for (name, ok) in [
            ("relay-a.example", true),
            (&*"n".repeat(64), true),
            (&*"n".repeat(65), false),
            ("", false),
            ("bad\nname", false),
        ] {
            let mut d = doc(&s);
            d.log = Some(LogDocument {
                level: None,
                node_name: Some(name.to_owned()),
            });
            let r = RelayConfig::from_document(&d);
            assert_eq!(r.is_ok(), ok, "{name:?}");
            if !ok {
                assert_eq!(r.unwrap_err().field, "log.node_name");
            }
        }
    }

    #[test]
    fn suppression_file_must_be_absolute() {
        let s = Scratch::new("supp-path");
        let mut d = doc(&s);
        d.suppression = Some(SuppressionDocument {
            file: Some("suppress.toml".to_owned()),
            reload_interval_secs: None,
        });
        assert_eq!(field_of(&d), "suppression.file");
        d.suppression = Some(SuppressionDocument {
            file: Some("/etc/usgp-relay/suppress.toml".to_owned()),
            reload_interval_secs: None,
        });
        let c = RelayConfig::from_document(&d).unwrap();
        assert_eq!(
            c.suppression.file.as_deref(),
            Some(std::path::Path::new("/etc/usgp-relay/suppress.toml"))
        );
    }

    #[test]
    fn errors_do_not_echo_values() {
        let s = Scratch::new("no-echo");
        let d = with_iface(&s, Some("eth0"), Some("secret-ish-value"));
        let e = RelayConfig::from_document(&d).unwrap_err();
        assert!(!e.to_string().contains("secret-ish-value"), "{e}");
    }

    #[test]
    fn config_has_no_secret_keys() {
        // REQ-BOOT-043: the schema holds no credential or key material.
        let s = Scratch::new("schema-review");
        let text = format!("{:?}", config(&s)).to_ascii_lowercase();
        for word in ["password", "secret", "token", "credential", "private"] {
            assert!(!text.contains(word), "{word}");
        }
    }

    #[test]
    fn local_addresses_lists_every_interface() {
        let s = Scratch::new("locals");
        let mut d = doc(&s);
        d.interface.push(InterfaceDocument {
            name: Some("eth1".to_owned()),
            address: Some("10.30.0.2".to_owned()),
            prefix_len: None,
        });
        let c = RelayConfig::from_document(&d).unwrap();
        assert_eq!(
            c.local_addresses(),
            vec![Ipv4Addr::new(10, 20, 1, 2), Ipv4Addr::new(10, 30, 0, 2)]
        );
    }

    // --- file checks ------------------------------------------------------

    #[test]
    fn missing_config_file() {
        let s = Scratch::new("cfg-missing");
        let e = load(&s.dir.join("relay.toml"), trust()).unwrap_err();
        assert!(
            matches!(e, ConfigLoadError::File(ConfigError::Io { .. })),
            "{e:?}"
        );
    }

    #[test]
    fn world_writable_config_refused() {
        let s = Scratch::new("cfg-ww");
        let p = s.dir.join("relay.toml");
        std::fs::write(&p, "schema_version = 1\n").unwrap();
        set_mode(&p, 0o666);
        let e = load(&p, trust()).unwrap_err();
        assert!(
            matches!(
                e,
                ConfigLoadError::File(ConfigError::Untrusted {
                    rule: TrustRule::WorldWritable,
                    ..
                })
            ),
            "{e:?}"
        );
    }

    fn untrusted_rule(e: &ConfigLoadError) -> Option<TrustRule> {
        match e {
            ConfigLoadError::File(ConfigError::Untrusted { rule, .. }) => Some(*rule),
            _ => None,
        }
    }

    /// NIST-002 / SEC-005: a group-writable configuration or manifest is
    /// refused, as is one in a directory others can write to.
    #[test]
    fn group_writable_config_and_manifest_refused() {
        let s = Scratch::new("cfg-gw");
        s.publish(&[(PROGRAM, b"payload")]);
        let p = write_config_toml(&s, "");
        load(&p, trust()).unwrap();

        set_mode(&p, 0o664);
        let e = load(&p, trust()).unwrap_err();
        assert_eq!(untrusted_rule(&e), Some(TrustRule::GroupWritable), "{e:?}");
        set_mode(&p, 0o644);

        set_mode(&s.manifest_path(), 0o664);
        let e = load(&p, trust()).unwrap_err();
        assert_eq!(untrusted_rule(&e), Some(TrustRule::GroupWritable), "{e:?}");
        // The content store's own read applies the same rule.
        let c = config(&s);
        let e = usgp_relay::content::ContentStore::load(
            &c.boot.manifest,
            &c.boot.root,
            &c.boot.uefi_x64_program,
            c.tftp.max_file_size,
            1,
            &c.trust,
        )
        .unwrap_err();
        assert!(e.to_string().contains("group-writable"), "{e}");
        set_mode(&s.manifest_path(), 0o644);
        load(&p, trust()).unwrap();
    }

    #[test]
    fn writable_parent_directory_refused() {
        let s = Scratch::new("cfg-parent");
        s.publish(&[(PROGRAM, b"payload")]);
        let p = write_config_toml(&s, "");
        // The directory holding the configuration and the manifest.
        for bad in [0o775, 0o777] {
            set_mode(&s.dir, bad);
            let e = load(&p, trust()).unwrap_err();
            assert_eq!(
                untrusted_rule(&e),
                Some(TrustRule::WritableDirectory),
                "{bad:o} {e:?}"
            );
        }
        set_mode(&s.dir, 0o755);
        load(&p, trust()).unwrap();
    }

    #[test]
    fn owner_must_be_root_or_admin_uid() {
        let s = Scratch::new("cfg-owner");
        s.publish(&[(PROGRAM, b"payload")]);
        let p = write_config_toml(&s, "");
        if admin_uid() == 0 {
            // Running as root: every file here is root-owned and trusted.
            load(&p, TrustPolicy::root_only()).unwrap();
            return;
        }
        let e = load(&p, TrustPolicy::root_only()).unwrap_err();
        assert_eq!(untrusted_rule(&e), Some(TrustRule::Owner), "{e:?}");
        let other = TrustPolicy::with_admin(admin_uid().wrapping_add(1));
        let e = load(&p, other).unwrap_err();
        assert_eq!(untrusted_rule(&e), Some(TrustRule::Owner), "{e:?}");
        // The policy given to `load` is the one carried for later reads.
        assert_eq!(load(&p, trust()).unwrap().config.trust, trust());
    }

    #[test]
    fn symlinked_config_not_followed() {
        let s = Scratch::new("cfg-link");
        s.publish(&[(PROGRAM, b"payload")]);
        let p = write_config_toml(&s, "");
        let link = s.dir.join("link.toml");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        let e = load(&link, trust()).unwrap_err();
        assert!(
            matches!(e, ConfigLoadError::File(ConfigError::Symlink { .. })),
            "{e:?}"
        );
    }

    #[test]
    fn oversize_config_refused() {
        let s = Scratch::new("cfg-big");
        let p = s.dir.join("relay.toml");
        let len = usize::try_from(MAX_CONFIG_BYTES).unwrap() + 1;
        std::fs::write(&p, "#".repeat(len)).unwrap();
        set_mode(&p, 0o644);
        let e = load(&p, trust()).unwrap_err();
        assert!(
            matches!(e, ConfigLoadError::File(ConfigError::TooLarge { .. })),
            "{e:?}"
        );
    }

    #[test]
    fn config_file_is_only_read_req_053() {
        let s = Scratch::new("cfg-ro");
        let p = s.dir.join("relay.toml");
        std::fs::write(&p, "schema_version = 1\n").unwrap();
        set_mode(&p, 0o644);
        let before = std::fs::metadata(&p).unwrap();
        let _ = load(&p, trust());
        let after = std::fs::metadata(&p).unwrap();
        assert_eq!(before.modified().unwrap(), after.modified().unwrap());
        assert_eq!(before.len(), after.len());
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "schema_version = 1\n");
    }

    #[test]
    fn trust_paths_checked() {
        let s = Scratch::new("trust");
        s.publish(&[(PROGRAM, b"x")]);
        let c = config(&s);
        check_trust_paths(&c).unwrap();

        set_mode(&s.manifest_path(), 0o646);
        let e = check_trust_paths(&c).unwrap_err();
        assert_eq!(untrusted_rule(&e), Some(TrustRule::WorldWritable), "{e:?}");
        set_mode(&s.manifest_path(), 0o644);

        for bad in [0o777, 0o775] {
            set_mode(&s.root(), bad);
            assert!(untrusted_rule(&check_trust_paths(&c).unwrap_err()).is_some());
        }
        set_mode(&s.root(), 0o755);

        let mut not_dir = c.clone();
        not_dir.boot.root = s.manifest_path();
        let e = check_trust_paths(&not_dir).unwrap_err();
        assert_eq!(e.field(), "boot.root");

        let mut missing = c;
        missing.boot.root = s.dir.join("nope");
        assert!(matches!(
            check_trust_paths(&missing),
            Err(ConfigLoadError::File(ConfigError::Io { .. }))
        ));
    }

    fn feed_doc(s: &Scratch) -> ConfigDocument {
        let mut d = doc(s);
        d.server_feed = Some(usgp_relay::config::ServerFeedDocument {
            enabled: Some(true),
            url: Some("https://10.0.0.5:8443".to_owned()),
            server_name: Some("server.lab".to_owned()),
            trust_anchors: Some("/etc/usgp-relay/feed/ca.pem".to_owned()),
            client_cert: Some("/etc/usgp-relay/feed/relay.pem".to_owned()),
            client_key: Some("/etc/usgp-relay/feed/relay.key".to_owned()),
            boot_policy_key_pub: Some("/etc/usgp-relay/feed/policy.pem".to_owned()),
            boot_service_id: Some("6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b".to_owned()),
            poll_interval_s: None,
            cache_file: None,
        });
        d
    }

    /// M3 `[server_feed]` (plan section 3.9): off by default, every key
    /// checked when enabled, `https` only, no way to skip TLS.
    #[test]
    fn server_feed_rules() {
        let s = Scratch::new("feed-rules");
        let c = RelayConfig::from_document(&feed_doc(&s)).unwrap();
        let f = c.server_feed.unwrap();
        assert_eq!(f.url.host, "10.0.0.5");
        assert_eq!(f.url.port, 8443);
        assert_eq!(f.poll_interval, Duration::from_secs(30));
        assert_eq!(f.cache_file, None);

        // Disabled (explicitly or by default): no feed, other keys ignored.
        let mut d = feed_doc(&s);
        d.server_feed.as_mut().unwrap().enabled = Some(false);
        d.server_feed.as_mut().unwrap().url = Some("not a url".to_owned());
        assert_eq!(RelayConfig::from_document(&d).unwrap().server_feed, None);
        let mut d = feed_doc(&s);
        d.server_feed.as_mut().unwrap().enabled = None;
        assert_eq!(RelayConfig::from_document(&d).unwrap().server_feed, None);

        type Edit = fn(&mut usgp_relay::config::ServerFeedDocument);
        let cases: [(&str, Edit); 14] = [
            ("server_feed.url", |f| f.url = None),
            ("server_feed.url", |f| {
                f.url = Some("http://10.0.0.5".to_owned())
            }),
            ("server_feed.url", |f| f.url = Some("https://".to_owned())),
            ("server_feed.url", |f| {
                f.url = Some("https://h.lab/v1/x".to_owned());
            }),
            ("server_feed.url", |f| {
                f.url = Some("https://user@h.lab".to_owned());
            }),
            ("server_feed.url", |f| {
                f.url = Some("https://h.lab:0".to_owned())
            }),
            ("server_feed.url", |f| {
                f.url = Some("https://h.lab:65536".to_owned());
            }),
            ("server_feed.url", |f| {
                f.url = Some("https://-h.lab".to_owned())
            }),
            ("server_feed.boot_service_id", |f| f.boot_service_id = None),
            ("server_feed.boot_service_id", |f| {
                f.boot_service_id = Some("00000000-0000-0000-0000-000000000000".to_owned());
            }),
            ("server_feed.trust_anchors", |f| {
                f.trust_anchors = Some("relative.pem".to_owned());
            }),
            ("server_feed.client_key", |f| f.client_key = None),
            ("server_feed.client_key", |f| {
                f.client_key = f.client_cert.clone();
            }),
            ("server_feed.cache_file", |f| {
                f.cache_file = Some("cache.json".to_owned());
            }),
        ];
        for (field, edit) in cases {
            let mut d = feed_doc(&s);
            edit(d.server_feed.as_mut().unwrap());
            assert_eq!(field_of(&d), field, "{field}");
        }
        for (v, ok) in [(5, true), (3600, true), (4, false), (3601, false)] {
            let mut d = feed_doc(&s);
            d.server_feed.as_mut().unwrap().poll_interval_s = Some(v);
            assert_eq!(RelayConfig::from_document(&d).is_ok(), ok, "{v}");
        }
        // IPv6 literal and default port.
        let mut d = feed_doc(&s);
        d.server_feed.as_mut().unwrap().url = Some("https://[fd00::5]".to_owned());
        d.server_feed.as_mut().unwrap().server_name = Some("server.lab".to_owned());
        let f = RelayConfig::from_document(&d).unwrap().server_feed.unwrap();
        assert_eq!((f.url.host.as_str(), f.url.port), ("fd00::5", 443));
        assert_eq!(f.url.authority(), "[fd00::5]:443");
        // The server name defaults to the URL host.
        let mut d = feed_doc(&s);
        d.server_feed.as_mut().unwrap().server_name = None;
        let f = RelayConfig::from_document(&d).unwrap().server_feed.unwrap();
        assert_eq!(f.server_name, "10.0.0.5");
    }

    /// M3 `[tftp] block_wrap` labels.
    #[test]
    fn block_wrap_labels() {
        let s = Scratch::new("wrap-labels");
        for (label, want) in [
            ("zero", Some(usgp_tftp::BlockWrap::Zero)),
            ("one", Some(usgp_tftp::BlockWrap::One)),
            ("off", Some(usgp_tftp::BlockWrap::Off)),
            ("Zero", None),
            ("", None),
            ("wrap", None),
        ] {
            let mut d = doc(&s);
            d.tftp = Some(TftpDocument {
                block_wrap: Some(label.to_owned()),
                ..TftpDocument::default()
            });
            match want {
                Some(w) => assert_eq!(RelayConfig::from_document(&d).unwrap().tftp.block_wrap, w),
                None => assert_eq!(field_of(&d), "tftp.block_wrap", "{label}"),
            }
        }
    }

    /// The feed's files are trust anchors: `load` refuses a world-writable
    /// one (CM-5).
    #[test]
    fn feed_files_must_be_trusted() {
        let s = Scratch::new("feed-trust");
        s.publish(&[(PROGRAM, b"payload")]);
        let dir = s.dir.join("feed");
        std::fs::create_dir_all(&dir).unwrap();
        set_mode(&dir, 0o755);
        for n in ["ca.pem", "relay.pem", "relay.key", "policy.pem"] {
            std::fs::write(dir.join(n), b"x").unwrap();
            set_mode(&dir.join(n), 0o644);
        }
        set_mode(&dir.join("relay.key"), 0o600);
        let extra = format!(
            "[server_feed]\nenabled = true\nurl = \"https://10.0.0.5\"\n\
             trust_anchors = \"{d}/ca.pem\"\nclient_cert = \"{d}/relay.pem\"\n\
             client_key = \"{d}/relay.key\"\nboot_policy_key_pub = \"{d}/policy.pem\"\n\
             boot_service_id = \"6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b\"\n",
            d = dir.display()
        );
        let p = write_config_toml(&s, &extra);
        assert!(load(&p, trust()).unwrap().config.server_feed.is_some());
        set_mode(&dir.join("ca.pem"), 0o666);
        assert!(matches!(
            load(&p, trust()).unwrap_err(),
            ConfigLoadError::File(ConfigError::Untrusted {
                rule: TrustRule::WorldWritable,
                ..
            })
        ));
    }
}
