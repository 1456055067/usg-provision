//! End to end on PostgreSQL (plan M2 section 10, "E2E"; WU-3b CI job
//! `pg-integration`). Runs the built `usgp-server` binary as a child
//! process against the CI database, over real mutual TLS.
//!
//! Needs the `USGP_TEST_PG_*` variables (WU-3b contract) and a **fresh**
//! database (`USGP_TEST_PG_DBNAME` as `scripts/pg-test-setup.sh up`
//! creates it). Without the variables the test **fails**; it never skips.
//!
//! Flow:
//!
//! 1. `migrate` as the owner (certificate login), twice (idempotent);
//! 2. `operator enrol` (administrator) and a second operator, disabled;
//! 3. `serve`: genesis, `server.start`; no certificate → 401; disabled
//!    operator → 401; administrator → limits; a non-WIM upload → Failed
//!    with its reason (REQ-IMG-022, -037);
//! 4. exit criterion 1 at small scale on PostgreSQL (`common::flow`): a
//!    builder-made 6-edition XPRESS WIM with an integrity table and a
//!    builder-made x64 PE are uploaded and checked by the production
//!    `WimChecker`; the editions are listed; edition 2 is declared
//!    windows-11 / enterprise / x64; the package is **Ready**; the signed
//!    package and content manifests open with the pinned content key
//!    (and not with another key); both files are re-downloaded with every
//!    chunk digest and the whole-file digest checked against digests the
//!    test computed itself;
//! 5. an upload session left open; SIGTERM → exit 0, `server.stop` and a
//!    final checkpoint mirrored;
//! 6. restart → the open session's content is Failed
//!    `interrupted_by_restart` (REQ-IMG-021) while the Ready package
//!    from step 4 is still Ready with a verifying manifest; SIGTERM;
//! 7. `audit verify` with the audit key → exit 0 (intact); with another
//!    key → exit 1.
//!
//! M3 (plan WU-10; the same flow as `device_e2e.rs` on the in-memory
//! store): the configuration enables the device listener with the plan,
//! boot-policy and code keys; step 2 adds `boot-service enrol` (a relay
//! certificate on 127.0.0.0/8; the operator's certificate is refused);
//! step 4 continues with `common::device::run` (code authorisation,
//! package, disk, confirm, verified plan, verified chunks, progress to
//! success, the relay's signed policy showing the stop); after the
//! restart of step 6 the stop is still listed, the operator clears it
//! (`POST /v1/boot-stops/{id}/clear`, decision 0021 item 3) and the
//! relay's policy no longer lists the device.
//!
//! Modified-row detection on PostgreSQL is `usgp-db` `audit_pg` (owner
//! tampering) and, through this command's code, `tests/serve.rs`
//! (`audit_verify_detects_tampering`); this package has no SQL client to
//! edit a row itself.
//!
//! The 10.5 GiB version of step 4 is `large_upload_pg.rs` (WU-10).

#![cfg(feature = "pg-integration")]

#[cfg(test)]
pub mod common;

#[cfg(test)]
mod e2e {
    use std::time::Duration;

    use usgp_image::Compression;
    use usgp_image::testkit::builder::WimBuilder;
    use usgp_proto::WimCompression;

    use usgp_crypto::test_pki::LeafSpec;

    use crate::common::device;
    use crate::common::flow::{self, Expect, Source};
    use crate::common::pg::{PgSetup, device_addr, text, wait_state};
    use crate::common::stream::{Body, digest_bytes};
    use crate::common::{Fixture, https, json_str};

    /// Editions of the small multi-edition WIM.
    const EDITIONS: u32 = 6;

    fn editions() -> Vec<(String, String)> {
        (1..=EDITIONS)
            .map(|i| {
                (
                    format!("Synthetic Edition {i}"),
                    format!("Builder-made edition {i}"),
                )
            })
            .collect()
    }

    /// A 6-edition XPRESS WIM with an integrity table, and an x64 PE
    /// (boot index 1), both from the usgp-image test builder.
    fn wims() -> (Vec<u8>, Vec<u8>) {
        let mut b = WimBuilder::new(Compression::Xpress).integrity(true);
        for (name, desc) in editions() {
            b = b.image(&name, &desc);
        }
        let image = b.build().unwrap().0;
        let pe = WimBuilder::new(Compression::Xpress)
            .image("Builder PE x64", "Preinstallation environment")
            .boot_index(1)
            .build()
            .unwrap()
            .0;
        (image, pe)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn e2e_flow_on_postgres() {
        let f = Fixture::new("e2e-pg");
        // Copies the CI files in, so the trust rules see this test's own
        // files (owner = the test uid, passed as --admin-uid).
        // M3: the device listener and its keys (plan section 3.9).
        let pg = PgSetup::new(&f, |t| f.m3_overlay(&t));
        let cfg = pg.cfg();

        // 1. Migrations, as the owner; the second run applies nothing.
        pg.migrate_fresh();
        let out = pg.migrate();
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        assert!(text(&out.stdout).contains("migrations applied: none"));

        // 2. Operators.
        let admin_pem = f.scratch.path("operator.pem");
        let out = pg.enrol(admin_pem.to_str().unwrap(), "Operator One");
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        assert!(text(&out.stdout).contains("audit.chain.genesis"));
        assert!(text(&out.stdout).contains("operator.enrolled"));
        let other_pem = f
            .scratch
            .write("other.pem", &f.pki.client_other_policy.chain_pem(), 0o644);
        let out = pg.enrol(other_pem.to_str().unwrap(), "Operator Two");
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        let other_id = text(&out.stdout)
            .lines()
            .find_map(|l| l.strip_prefix("operator id: ").map(str::to_owned))
            .unwrap();
        // The same certificate again: refused.
        let out = pg.enrol(admin_pem.to_str().unwrap(), "Duplicate");
        assert_eq!(out.status.code(), Some(1));
        let out = crate::common::pg::server(&[
            "operator",
            "disable",
            "--config",
            cfg,
            "--id",
            &other_id,
            "--admin-uid",
            &crate::common::pg::uid(),
        ]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));

        // M3: enrol the relay as a boot service (administrative role).
        let relay = f
            .pki
            .intermediate
            .issue(&LeafSpec::client("relay e2e pg"))
            .unwrap();
        let relay_pem = f.scratch.write("relay.pem", &relay.chain_pem(), 0o644);
        let enrol_relay = |cert: &str, name: &str| {
            crate::common::pg::server(&[
                "boot-service",
                "enrol",
                "--config",
                cfg,
                "--cert",
                cert,
                "--name",
                name,
                "--subnet",
                "127.0.0.0/8",
                "--admin-uid",
                &crate::common::pg::uid(),
            ])
        };
        // An operator's certificate is refused (both would be locked out).
        let out = enrol_relay(admin_pem.to_str().unwrap(), "Not A Relay");
        assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
        assert!(text(&out.stdout).contains("certificate_bound_to_operator"));
        let out = enrol_relay(relay_pem.to_str().unwrap(), "Relay E2E");
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        assert!(text(&out.stdout).contains("boot_service.enrolled"));
        let bs_id = text(&out.stdout)
            .lines()
            .find_map(|l| l.strip_prefix("boot service id: ").map(str::to_owned))
            .unwrap();

        // 3. Serve.
        let mut s = pg.serve();
        let addr = s.addr;
        let device_at = device_addr(&s.wait_for("\"event\":\"server.start\""));
        assert_ne!(device_at, addr);
        let r = https(addr, &f.pki, None, "GET", "/v1/limits", None)
            .await
            .unwrap();
        assert_eq!(r.status, 401);
        assert!(r.head.contains("www-authenticate: usgp-client-cert"));
        let r = https(
            addr,
            &f.pki,
            Some(&f.pki.client_other_policy),
            "GET",
            "/v1/limits",
            None,
        )
        .await
        .unwrap();
        assert_eq!(r.status, 401);
        let r = https(addr, &f.pki, Some(&f.pki.client), "GET", "/v1/limits", None)
            .await
            .unwrap();
        assert_eq!(r.status, 200, "{}", r.body);
        assert!(r.body.contains("\"max_upload_bytes\":1048576"));

        // A non-WIM upload: received, checked, Failed with a reason.
        let bytes = "not a windows image file. ".repeat(160);
        let digest = usgp_crypto::sha256(bytes.as_bytes()).to_hex();
        let create = format!(
            r#"{{"kind":"image","display_name":"Not a WIM","file_name":"not a wim.wim","size":{},"sha256":"{digest}"}}"#,
            bytes.len()
        );
        let r = https(
            addr,
            &f.pki,
            Some(&f.pki.client),
            "POST",
            "/v1/uploads",
            Some(&create),
        )
        .await
        .unwrap();
        assert_eq!(r.status, 201, "{}", r.body);
        let upload_id = json_str(&r.body, "upload_id").unwrap();
        let content_id = json_str(&r.body, "content_id").unwrap();
        let r = https(
            addr,
            &f.pki,
            Some(&f.pki.client),
            "PUT",
            &format!("/v1/uploads/{upload_id}"),
            Some(&bytes),
        )
        .await
        .unwrap();
        assert_eq!(r.status, 202, "{}", r.body);
        let r = wait_state(
            addr,
            &f,
            &format!("/v1/images/{content_id}"),
            "failed",
            Duration::from_secs(30),
        )
        .await;
        assert!(r.body.contains("wim_"), "{}", r.body);

        // 4. Exit criterion 1 at small scale: builder WIM + PE to a Ready
        // package with signed, verified manifests and verified downloads.
        let (image_bytes, pe_bytes) = wims();
        assert!(
            image_bytes.len() < 1_048_576 && pe_bytes.len() < 1_048_576,
            "builder files exceed the configured upload limit"
        );
        let image = Source {
            body: Body::Bytes(&image_bytes),
            digests: digest_bytes(&image_bytes),
        };
        let pe = Source {
            body: Body::Bytes(&pe_bytes),
            digests: digest_bytes(&pe_bytes),
        };
        let eds = editions();
        let ids = flow::wim_to_ready_package(
            addr,
            &f,
            &image,
            &Expect {
                display_name: "Builder Multi Edition",
                compression: WimCompression::Xpress,
                editions: &eds,
                chosen: 2,
                ready_within: Duration::from_secs(60),
            },
            &pe,
            &f.audit_pub,
        )
        .await;

        // M3: a device session on PostgreSQL to success; the relay's
        // policy shows the stop.
        let out = Box::pin(device::run(
            addr,
            device_at,
            &f,
            &bs_id,
            &ids.package,
            image.digests.total,
            &relay,
        ))
        .await;
        let r = device::op(addr, &f, "GET", "/v1/boot-stops", &[], None).await;
        assert_eq!(r.status, 200, "{}", r.text());
        let stop_id = r.json()["stops"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["mac"] == out.mac.to_string())
            .map(|v| v["id"].as_str().unwrap().to_owned())
            .expect("the device's boot stop");

        // A session left open across a restart.
        let open = format!(
            r#"{{"kind":"image","display_name":"Interrupted","file_name":"x.wim","size":4096,"sha256":"{}"}}"#,
            "cd".repeat(32)
        );
        let r = https(
            addr,
            &f.pki,
            Some(&f.pki.client),
            "POST",
            "/v1/uploads",
            Some(&open),
        )
        .await
        .unwrap();
        assert_eq!(r.status, 201, "{}", r.body);
        let open_id = json_str(&r.body, "content_id").unwrap();

        // 5. Graceful stop.
        let (code, lines) = pg.stop(s);
        assert_eq!(code, Some(0), "{}", lines.join("\n"));
        let all = lines.join("\n");
        for e in [
            "\"event\":\"server.start\"",
            "\"event\":\"auth.unauthenticated\"",
            "\"event\":\"auth.operator_disabled\"",
            "\"event\":\"content.upload.received\"",
            "\"event\":\"content.failed\"",
            "\"event\":\"content.ready\"",
            "\"event\":\"content.manifest.signed\"",
            "\"event\":\"pe.declared\"",
            "\"event\":\"edition.declared\"",
            "\"event\":\"package.created\"",
            "\"event\":\"package.manifest.signed\"",
            "\"event\":\"package.manifest.read\"",
            "\"event\":\"content.manifest.read\"",
            "\"event\":\"content.download\"",
            "\"event\":\"content.download.completed\"",
            "\"event\":\"server.stop\"",
            "\"event\":\"audit.checkpoint\"",
            // M3.
            "\"event\":\"boot_service.packages.set\"",
            "\"event\":\"auth_code.issued\"",
            "\"event\":\"device.session.opened\"",
            "\"event\":\"auth_code.used\"",
            "\"event\":\"device.session.authorised\"",
            "\"event\":\"device.session.package_chosen\"",
            "\"event\":\"device.session.disk_chosen\"",
            "\"event\":\"disk.wipe.authorised\"",
            "\"event\":\"job.created\"",
            "\"event\":\"job.plan.issued\"",
            "\"event\":\"job.content.read\"",
            "\"event\":\"job.step.completed\"",
            "\"event\":\"job.succeeded\"",
            "\"event\":\"boot_stop.added\"",
            "\"event\":\"boot_policy.read\"",
            "\"actor_kind\":\"device_session\"",
            "\"interface\":\"device_api\"",
            "\"actor_kind\":\"boot_service\"",
            "\"interface\":\"relay_feed\"",
        ] {
            assert!(all.contains(e), "{e} missing:\n{all}");
        }
        assert!(all.contains(&out.job_id) && all.contains(&out.session_id));
        assert!(!all.contains("\"event\":\"content.download.aborted\""));
        assert!(!all.contains("\"event\":\"content.integrity.failed\""));
        assert!(
            lines
                .last()
                .is_some_and(|l| l.contains("\"event\":\"audit.checkpoint\"")),
            "the last record is not the shutdown checkpoint:\n{all}"
        );
        assert!(!all.contains("PRIVATE KEY"));

        // 6. Restart recovery: the open session fails, the package stays
        // Ready and its manifest still verifies.
        let s = pg.serve();
        // M3: the stop survived the restart; the operator clears it and
        // the relay's policy no longer stops the device.
        let g = device::open_policy(&f, &device::pull(s.addr, &f, &relay, 0).await);
        assert_eq!(g.generation, out.generation);
        assert!(g.stop_set().contains(&out.mac));
        let clear = format!("/v1/boot-stops/{stop_id}/clear");
        let r = device::op(s.addr, &f, "POST", &clear, &[], None).await;
        assert_eq!(r.status, 200, "{}", r.text());
        let r = device::op(s.addr, &f, "POST", &clear, &[], None).await;
        assert_eq!(r.status, 409, "{}", r.text());
        let g = device::open_policy(&f, &device::pull(s.addr, &f, &relay, out.generation).await);
        assert_eq!(g.generation, out.generation + 1);
        assert!(!g.stop_set().contains(&out.mac));
        let r = wait_state(
            s.addr,
            &f,
            &format!("/v1/images/{open_id}"),
            "failed",
            Duration::from_secs(30),
        )
        .await;
        assert!(r.body.contains("interrupted_by_restart"), "{}", r.body);
        flow::package_still_ready(s.addr, &f, &ids, &image.digests).await;
        let (code, _) = pg.stop(s);
        assert_eq!(code, Some(0));

        // 7. Audit verify (local command).
        let audit_pub = f.scratch.path("audit.pub");
        let out = pg.audit_verify(audit_pub.to_str().unwrap());
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}{}",
            text(&out.stdout),
            text(&out.stderr)
        );
        assert!(text(&out.stdout).contains("audit chain: intact"));
        let content_pub = f.scratch.path("content.pub");
        let out = pg.audit_verify(content_pub.to_str().unwrap());
        assert_eq!(out.status.code(), Some(1), "{}", text(&out.stdout));
        assert!(text(&out.stdout).contains("checkpoint_untrusted_key"));
    }
}
