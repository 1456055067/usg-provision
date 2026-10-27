//! `server.toml` loading and file material (plan M2 section 3.5, 5.2,
//! 5.4, 5.5; decision 0012).
//!
//! | Rule | Test |
//! |------|------|
//! | the plan's example parses; defaults are the plan's | `plan_example_parses`, `defaults_are_secure` |
//! | unknown keys refused, including any password or URL form (0012) | `password_and_url_keys_refused`, `unknown_keys_refused` |
//! | `content.max_upload_bytes` at most 1 TiB | `max_upload_at_most_one_tebibyte` |
//! | ranges, absolute paths, required sections | `out_of_range_and_missing_values_refused` |
//! | `[wim]` may only lower limits | `wim_overrides_lower_only` |
//! | trusted-file rules on the config and every named file | `config_file_trust_rules`, `named_files_trust_rules` |
//! | content and audit keys differ | `content_and_audit_keys_must_differ` |
//! | certificate-only database settings | `database_settings_certificate_only` |

#[cfg(test)]
pub mod common;

#[cfg(test)]
mod config {
    use std::time::Duration;

    use usgp_common::config::{ConfigError, TrustPolicy, TrustRule};
    use usgp_crypto::tls::TlsMinVersion;
    use usgp_server::config::{ConfigLoadError, load, parse_text};
    use usgp_server::files::read_trusted_bytes;
    use usgp_server::material::{DbRole, db_settings};
    use usgp_server::serve::{ServeError, prepare};

    use crate::common::{Fixture, admin_uid, set_mode};

    const PLAN_EXAMPLE: &str = include_str!("fixtures/server-v1.toml");

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

    fn trust() -> TrustPolicy {
        TrustPolicy::with_admin(admin_uid())
    }

    #[test]
    fn plan_example_parses() {
        let c = parse_text(PLAN_EXAMPLE, None).unwrap();
        assert_eq!(c.node_name, "ctl-01");
        assert_eq!(c.listen.to_string(), "127.0.0.1:8443");
        assert_eq!(c.tls.min_version, TlsMinVersion::Tls12);
        assert_eq!(c.tls.client_crls.len(), 1);
        assert_eq!(c.tls.crl_reload, Duration::from_secs(300));
        assert_eq!(c.database.port, 5432);
        assert_eq!(c.database.pool_size, 8);
        assert_eq!(c.api.content.max_upload_bytes, 34_359_738_368);
        assert_eq!(c.api.content.max_open_uploads_per_operator, 2);
        assert_eq!(c.checkpoint.every_records, 100);
        assert_eq!(c.checkpoint.every, Duration::from_secs(60));
        assert_eq!(c.api.wim_limits, usgp_image::WimLimits::DEFAULT);
    }

    #[test]
    fn defaults_are_secure() {
        // Drop every optional key: loopback listener, TLS 1.2 minimum,
        // 300 s CRL reload, 32 GiB upload limit.
        let minimal = r#"
schema_version = 1
node_name = "n"
[tls]
cert_chain = "/a"
private_key = "/b"
client_trust_anchors = "/c"
client_crls = ["/d"]
[database]
host = "db"
dbname = "usgp"
user = "usgp_app"
server_ca = "/e"
client_cert = "/f"
client_key = "/g"
[content]
root = "/h"
[signing]
content_key = "/i"
audit_key = "/j"
"#;
        let c = parse_text(minimal, None).unwrap();
        assert_eq!(c.listen.to_string(), "127.0.0.1:8443");
        assert!(c.listen.ip().is_loopback());
        assert_eq!(c.tls.min_version, TlsMinVersion::Tls12);
        assert_eq!(c.tls.crl_reload, Duration::from_secs(300));
        assert!(c.tls.acceptable_policy_oids.is_empty());
        assert_eq!(c.api.content.max_upload_bytes, 32 * 1024 * 1024 * 1024);
        assert_eq!(c.api.limits.max_connections, 64);
        assert_eq!(c.api.unauth_records_per_source_per_min, 10);
        assert!(c.api.known_bad_kit_versions.is_empty());
        assert_eq!(c.log_level, usgp_common::telemetry::Level::INFO);
        // The node name falls back to the host name, and is required
        // when there is none.
        let no_node = minimal.replace("node_name = \"n\"\n", "");
        assert_eq!(
            parse_text(&no_node, Some("host-1".into()))
                .unwrap()
                .node_name,
            "host-1"
        );
        assert_eq!(
            key_of(&parse_text(&no_node, None).unwrap_err()),
            "node_name"
        );
    }

    #[test]
    fn password_and_url_keys_refused() {
        // Decision 0012: no key can carry a password or a connection
        // string; every such key is unknown and refused.
        for extra in [
            "password = \"secret\"",
            "passfile = \"/root/.pgpass\"",
            "url = \"postgres://u:p@db/usgp\"",
            "connection_string = \"host=db password=p\"",
            "sslmode = \"disable\"",
        ] {
            let text = with(
                PLAN_EXAMPLE,
                "pool_size = 8",
                &format!("pool_size = 8\n{extra}"),
            );
            let e = parse_text(&text, None).unwrap_err();
            assert!(
                matches!(&e, ConfigLoadError::File(ConfigError::Parse { message, .. })
                    if message.contains("unknown field")),
                "{extra}: {e}"
            );
            // The refusal text names the key, never the value.
            assert!(!e.to_string().contains("secret"), "{e}");
            assert!(!e.to_string().contains("u:p@"), "{e}");
        }
    }

    #[test]
    fn unknown_keys_refused() {
        for (find, replace) in [
            (
                "node_name = \"ctl-01\"",
                "node_name = \"ctl-01\"\nnode = \"x\"",
            ),
            ("[log]", "[metrics]\nport = 1\n[log]"),
            ("crl_reload_s = 300", "crl_reload_s = 300\nocsp = true"),
            ("[wim]", "[wim]\nmax_files = 1"),
        ] {
            let e = parse_text(&with(PLAN_EXAMPLE, find, replace), None).unwrap_err();
            assert!(
                matches!(e, ConfigLoadError::File(ConfigError::Parse { .. })),
                "{replace}: {e}"
            );
        }
    }

    #[test]
    fn max_upload_at_most_one_tebibyte() {
        let tib: u64 = 1024 * 1024 * 1024 * 1024;
        let ok = with(
            PLAN_EXAMPLE,
            "max_upload_bytes = 34359738368",
            &format!("max_upload_bytes = {tib}"),
        );
        assert_eq!(
            parse_text(&ok, None).unwrap().api.content.max_upload_bytes,
            tib
        );
        for bad in [tib + 1, 0] {
            let t = with(
                PLAN_EXAMPLE,
                "max_upload_bytes = 34359738368",
                &format!("max_upload_bytes = {bad}"),
            );
            assert_eq!(
                key_of(&parse_text(&t, None).unwrap_err()),
                "content.max_upload_bytes"
            );
        }
        let neg = with(
            PLAN_EXAMPLE,
            "max_upload_bytes = 34359738368",
            "max_upload_bytes = -1",
        );
        assert_eq!(
            key_of(&parse_text(&neg, None).unwrap_err()),
            "content.max_upload_bytes"
        );
    }

    #[test]
    fn out_of_range_and_missing_values_refused() {
        let cases: &[(&str, &str, &str)] = &[
            ("schema_version = 1", "schema_version = 2", "schema_version"),
            ("schema_version = 1\n", "", "schema_version"),
            ("node_name = \"ctl-01\"", "node_name = \"\"", "node_name"),
            (
                "listen = \"127.0.0.1:8443\"",
                "listen = \"localhost:8443\"",
                "api.listen",
            ),
            (
                "max_connections = 64",
                "max_connections = 0",
                "api.max_connections",
            ),
            (
                "idle_timeout_s = 120",
                "idle_timeout_s = 0",
                "api.idle_timeout_s",
            ),
            (
                "min_version = \"1.2\"",
                "min_version = \"1.1\"",
                "tls.min_version",
            ),
            (
                "client_crls = [\"/etc/usgp-server/tls/crl/agency.crl\"]",
                "client_crls = []",
                "tls.client_crls",
            ),
            (
                "client_crls = [\"/etc/usgp-server/tls/crl/agency.crl\"]",
                "",
                "tls.client_crls",
            ),
            (
                "client_crls = [\"/etc/usgp-server/tls/crl/agency.crl\"]",
                "client_crls = [\"/a\", \"crl/relative.crl\"]",
                "tls.client_crls[1]",
            ),
            ("crl_reload_s = 300", "crl_reload_s = 0", "tls.crl_reload_s"),
            (
                "acceptable_policy_oids = []",
                "acceptable_policy_oids = [\"not-an-oid\"]",
                "tls.acceptable_policy_oids",
            ),
            (
                "cert_chain = \"/etc/usgp-server/tls/server.pem\"",
                "cert_chain = \"tls/server.pem\"",
                "tls.cert_chain",
            ),
            ("port = 5432", "port = 70000", "database.port"),
            ("host = \"db.internal\"", "host = \"\"", "database.host"),
            ("pool_size = 8", "pool_size = 0", "database.pool_size"),
            (
                "client_key = \"/etc/usgp-server/db/client.key\"",
                "",
                "database.client_key",
            ),
            (
                "root = \"/var/lib/usgp-server/content\"",
                "root = \"content\"",
                "content.root",
            ),
            (
                "check_concurrency = 1",
                "check_concurrency = 0",
                "content.check_concurrency",
            ),
            (
                "audit_key = \"/etc/usgp-server/keys/audit.p8\"",
                "audit_key = \"/etc/usgp-server/keys/content.p8\"",
                "signing.audit_key",
            ),
            (
                "checkpoint_every_records = 100",
                "checkpoint_every_records = 0",
                "audit.checkpoint_every_records",
            ),
            (
                "unauth_records_per_source_per_min = 10",
                "unauth_records_per_source_per_min = 0",
                "audit.unauth_records_per_source_per_min",
            ),
            ("level = \"info\"", "level = \"trace\"", "log.level"),
            (
                "[wim]",
                "[pe]\nknown_bad_kit_versions = [\"10.0\", \"01.2\"]\n[wim]",
                "pe.known_bad_kit_versions[1]",
            ),
        ];
        for (find, replace, key) in cases {
            let text = with(PLAN_EXAMPLE, find, replace);
            let e = parse_text(&text, None).unwrap_err();
            assert_eq!(key_of(&e), *key, "{replace:?}: {e}");
        }
        let ok = with(
            PLAN_EXAMPLE,
            "[wim]",
            "[pe]\nknown_bad_kit_versions = [\"10.1.26100.1\"]\n[wim]",
        );
        assert_eq!(
            parse_text(&ok, None)
                .unwrap()
                .api
                .known_bad_kit_versions
                .len(),
            1
        );
    }

    #[test]
    fn wim_overrides_lower_only() {
        let d = usgp_image::WimLimits::DEFAULT;
        let lower = with(
            PLAN_EXAMPLE,
            "[wim]",
            "[wim]\nmax_images = 12\nmax_xml_depth = 8",
        );
        let c = parse_text(&lower, None).unwrap();
        assert_eq!(c.api.wim_limits.max_images, 12);
        assert_eq!(c.api.wim_limits.max_xml_depth, 8);
        assert_eq!(c.api.wim_limits.max_xml_bytes, d.max_xml_bytes);
        let raise = with(
            PLAN_EXAMPLE,
            "[wim]",
            &format!("[wim]\nmax_images = {}", d.max_images + 1),
        );
        assert_eq!(
            key_of(&parse_text(&raise, None).unwrap_err()),
            "wim.max_images"
        );
        let zero = with(PLAN_EXAMPLE, "[wim]", "[wim]\nmax_xml_bytes = 0");
        assert_eq!(
            key_of(&parse_text(&zero, None).unwrap_err()),
            "wim.max_xml_bytes"
        );
    }

    #[test]
    fn config_file_trust_rules() {
        let f = Fixture::new("cfg-trust");
        let path = f.write_config(&f.config_text(&f.unreachable_db()));
        let loaded = load(&path, &trust()).unwrap();
        assert_eq!(
            loaded.sha256,
            usgp_crypto::sha256(&std::fs::read(&path).unwrap())
        );
        // Group-writable: refused.
        set_mode(&path, 0o664);
        assert!(matches!(
            load(&path, &trust()),
            Err(ConfigLoadError::File(ConfigError::Untrusted {
                rule: TrustRule::GroupWritable,
                ..
            }))
        ));
        set_mode(&path, 0o644);
        // Owned by someone other than root or the administrator uid.
        if admin_uid() != 0 {
            assert!(matches!(
                load(&path, &TrustPolicy::root_only()),
                Err(ConfigLoadError::File(ConfigError::Untrusted {
                    rule: TrustRule::Owner,
                    ..
                }))
            ));
        }
        // A symbolic link is never followed.
        let link = f.scratch.path("link.toml");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(matches!(
            load(&link, &trust()),
            Err(ConfigLoadError::File(ConfigError::Symlink { .. }))
        ));
        // Larger than 64 KiB.
        let big = format!(
            "{}#{}\n",
            f.config_text(&f.unreachable_db()),
            "x".repeat(70_000)
        );
        let p = f.write_config(&big);
        assert!(matches!(
            load(&p, &trust()),
            Err(ConfigLoadError::File(ConfigError::TooLarge { .. }))
        ));
    }

    #[test]
    fn named_files_trust_rules() {
        let f = Fixture::new("files-trust");
        let path = f.write_config(&f.config_text(&f.unreachable_db()));
        let cfg = load(&path, &trust()).unwrap().config;
        let p = prepare(&cfg, &trust()).unwrap();
        assert_eq!(p.crls.crls.len(), 3);
        assert!(p.server_tls.is_fips());
        assert_eq!(p.audit_key_id, f.audit_pub.key_id());
        assert_eq!(p.content_key_id, f.content_pub.key_id());

        // A group-writable private key is refused and named.
        let key = f.scratch.path("audit.p8");
        set_mode(&key, 0o620);
        match prepare(&cfg, &trust()) {
            Err(e @ ServeError::Key(_)) => {
                assert_eq!(e.field().as_deref(), Some("signing.audit_key"));
                assert_eq!(e.exit_code(), 78);
            }
            other => panic!("{other:?}"),
        }
        // Group-readable (root:usgp-server 0640) is accepted when the
        // group is the service's (here: the test's own group).
        set_mode(&key, 0o640);
        prepare(&cfg, &trust()).unwrap();
        // SEC-005: readable by others is refused for every private key.
        set_mode(&key, 0o604);
        match prepare(&cfg, &trust()) {
            Err(e @ ServeError::Key(_)) => {
                assert_eq!(e.field().as_deref(), Some("signing.audit_key"));
                assert!(e.to_string().contains("readable by others"), "{e}");
            }
            other => panic!("{other:?}"),
        }
        set_mode(&key, 0o600);
        let tls_key = f.scratch.path("server.key");
        set_mode(&tls_key, 0o644);
        match prepare(&cfg, &trust()) {
            Err(e @ ServeError::Material(_)) => {
                assert_eq!(e.field().as_deref(), Some("tls.private_key"));
            }
            other => panic!("{other:?}"),
        }
        set_mode(&tls_key, 0o600);
        let db_key = f.scratch.path("db-client.key");
        set_mode(&db_key, 0o604);
        let e = usgp_server::material::db_settings(
            &cfg.database,
            usgp_server::material::DbRole::App,
            &trust(),
        )
        .unwrap_err();
        assert_eq!(e.key(), "database.client_key");
        set_mode(&db_key, 0o600);
        prepare(&cfg, &trust()).unwrap();

        // A missing CRL refuses start-up, naming the entry.
        std::fs::rename(f.scratch.path("crl-2.der"), f.scratch.path("crl-2.moved")).unwrap();
        match prepare(&cfg, &trust()) {
            Err(e @ ServeError::Material(_)) => {
                assert_eq!(e.field().as_deref(), Some("tls.client_crls[2]"));
            }
            other => panic!("{other:?}"),
        }
        std::fs::rename(f.scratch.path("crl-2.moved"), f.scratch.path("crl-2.der")).unwrap();

        // A key file replaced by a symbolic link is refused.
        let real = f.scratch.path("server.key");
        let moved = f.scratch.path("server-real.key");
        std::fs::rename(&real, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &real).unwrap();
        match prepare(&cfg, &trust()) {
            Err(e @ ServeError::Material(_)) => {
                assert_eq!(e.field().as_deref(), Some("tls.private_key"));
            }
            other => panic!("{other:?}"),
        }
        std::fs::remove_file(&real).unwrap();
        std::fs::rename(&moved, &real).unwrap();

        // The bounded reader refuses oversized files.
        let big = f.scratch.write("big.bin", &vec![0u8; 2048], 0o644);
        assert!(matches!(
            read_trusted_bytes(&big, 1024, &trust()),
            Err(ConfigError::TooLarge { .. })
        ));
        assert_eq!(
            read_trusted_bytes(&big, 2048, &trust()).unwrap().len(),
            2048
        );
    }

    #[test]
    fn content_and_audit_keys_must_differ() {
        // Two files holding the same key: one key per purpose (plan
        // section 5.2).
        let f = Fixture::new("same-key");
        std::fs::copy(f.scratch.path("content.p8"), f.scratch.path("audit.p8")).unwrap();
        let path = f.write_config(&f.config_text(&f.unreachable_db()));
        let cfg = load(&path, &trust()).unwrap().config;
        match prepare(&cfg, &trust()) {
            Err(e @ ServeError::Refused { .. }) => {
                assert_eq!(e.reason(), "audit_key_equals_content_key");
                assert_eq!(e.exit_code(), 78);
            }
            other => panic!("{other:?}"),
        }
        // The audit key listed as an earlier content key: also refused.
        let f = Fixture::new("audit-as-content");
        let text = f.config_text(&f.unreachable_db()).replace(
            "[audit]",
            &format!(
                "previous_content_pubs = [\"{}\"]\n\n[audit]",
                f.scratch.path("audit.pub").display()
            ),
        );
        let cfg = load(&f.write_config(&text), &trust()).unwrap().config;
        assert_eq!(
            prepare(&cfg, &trust()).unwrap_err().reason(),
            "audit_key_trusted_for_content"
        );
    }

    #[test]
    fn database_settings_certificate_only() {
        let f = Fixture::new("db-settings");
        let cfg = load(
            &f.write_config(&f.config_text(&f.unreachable_db())),
            &trust(),
        )
        .unwrap()
        .config;
        let s = db_settings(&cfg.database, DbRole::App, &trust()).unwrap();
        assert_eq!(s.user, "usgp_app");
        assert_eq!(s.tls_server_name(), "localhost");
        assert!(!format!("{s:?}").contains("PRIVATE KEY"));
        // Owner settings come from the command line, not the file.
        let owner_cert = f.scratch.path("db-client.pem");
        let owner_key = f.scratch.path("db-client.key");
        let o = db_settings(
            &cfg.database,
            DbRole::Owner {
                user: "usgp_owner",
                cert: &owner_cert,
                key: &owner_key,
            },
            &trust(),
        )
        .unwrap();
        assert_eq!(o.user, "usgp_owner");
        // A connection-string form in a field is refused by
        // assert_certificate_only (decision 0012).
        let mut bad = cfg.database.clone();
        bad.dbname = "usgp password=x".into();
        let e = db_settings(&bad, DbRole::App, &trust()).unwrap_err();
        assert!(e.to_string().contains("dbname"), "{e}");
        assert!(!e.to_string().contains("password=x"), "{e}");
        // An empty client key file is refused.
        let mut empty = cfg.database.clone();
        empty.client_key = f.scratch.write("empty.key", b"", 0o600);
        assert!(db_settings(&empty, DbRole::App, &trust()).is_err());

        // Decision 0016: the admin role has its own settings.
        let a = db_settings(&cfg.database, DbRole::Admin, &trust()).unwrap();
        assert_eq!(a.user, "usgp_admin");
        let mut none = cfg.database.clone();
        none.admin = None;
        assert_eq!(
            db_settings(&none, DbRole::Admin, &trust())
                .unwrap_err()
                .key(),
            "database.admin"
        );
    }

    /// Decision 0016: `[database.admin]` must be a separate role with its
    /// own certificate and key; no password key exists there either.
    #[test]
    fn admin_role_section_rules() {
        let f = Fixture::new("db-admin");
        let base = f.config_text(&f.unreachable_db());
        let parse = |t: &str| usgp_server::config::parse_text(t, None);
        parse(&base).unwrap();
        let same_user = base.replace("user = \"usgp_admin\"", "user = \"usgp_app\"");
        let e = parse(&same_user).unwrap_err();
        assert!(e.to_string().contains("database.admin.user"), "{e}");
        let same_key = base.replace("db-admin.key", "db-client.key");
        let e = parse(&same_key).unwrap_err();
        assert!(e.to_string().contains("database.admin.client_key"), "{e}");
        let pw = base.replace("[database.admin]\n", "[database.admin]\npassword = \"x\"\n");
        assert!(parse(&pw).is_err());
        let missing = base.replace("user = \"usgp_admin\"\n", "");
        let e = parse(&missing).unwrap_err();
        assert!(e.to_string().contains("database.admin.user"), "{e}");
    }

    /// SEC-001, SEC-004, NIST-001, NIST-010 settings: defaults and
    /// ranges.
    #[test]
    fn connection_and_audit_cap_settings() {
        let f = Fixture::new("caps");
        let base = f.config_text(&f.unreachable_db());
        let c = usgp_server::config::parse_text(&base, None).unwrap();
        assert_eq!(c.api.limits.max_connections_per_source, 16);
        assert_eq!(c.api.limits.max_handshakes_per_source, 8);
        assert_eq!(c.api.limits.reserved_cert_connections, 16);
        assert_eq!(
            c.api.limits.max_connection_age,
            std::time::Duration::from_secs(300)
        );
        assert_eq!(c.api.unauth_records_global_per_min, 300);
        assert_eq!(c.api.credential_failure_records_per_source_per_min, 60);
        assert_eq!(c.api.credential_failure_records_global_per_min, 600);
        // A smaller server scales the defaults down.
        let small = base.replace(
            "listen = \"127.0.0.1:0\"",
            "listen = \"127.0.0.1:0\"\nmax_connections = 8",
        );
        let c = usgp_server::config::parse_text(&small, None).unwrap();
        assert_eq!(c.api.limits.max_connections_per_source, 8);
        assert_eq!(c.api.limits.reserved_cert_connections, 2);
        for (line, key) in [
            ("max_connection_age_s = 0", "api.max_connection_age_s"),
            (
                "reserved_cert_connections = 64",
                "api.reserved_cert_connections",
            ),
            (
                "max_handshakes_per_source = 17",
                "api.max_handshakes_per_source",
            ),
        ] {
            let t = base.replace(
                "listen = \"127.0.0.1:0\"",
                &format!("listen = \"127.0.0.1:0\"\n{line}"),
            );
            let e = usgp_server::config::parse_text(&t, None).unwrap_err();
            assert!(e.to_string().contains(key), "{line}: {e}");
        }
        let t = base.replace(
            "checkpoint_every_s = 60",
            "checkpoint_every_s = 60\ncredential_failure_records_global_per_min = 0",
        );
        let e = usgp_server::config::parse_text(&t, None).unwrap_err();
        assert!(
            e.to_string()
                .contains("audit.credential_failure_records_global_per_min"),
            "{e}"
        );

        // SEC-013: heartbeat checkpoint interval, default 900 s.
        let c = usgp_server::config::parse_text(&base, None).unwrap();
        assert_eq!(c.checkpoint.heartbeat, Duration::from_secs(900));
        let t = base.replace(
            "checkpoint_every_s = 60",
            "checkpoint_every_s = 60\ncheckpoint_heartbeat_s = 120",
        );
        let c = usgp_server::config::parse_text(&t, None).unwrap();
        assert_eq!(c.checkpoint.heartbeat, Duration::from_secs(120));
        for bad in ["59", "86401"] {
            let t = base.replace(
                "checkpoint_every_s = 60",
                &format!("checkpoint_every_s = 60\ncheckpoint_heartbeat_s = {bad}"),
            );
            let e = usgp_server::config::parse_text(&t, None).unwrap_err();
            assert!(
                e.to_string().contains("audit.checkpoint_heartbeat_s"),
                "{e}"
            );
        }
    }
}
