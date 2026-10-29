//! M3 end to end on the in-memory store (plan M3 section 10.1; WU-10):
//! `serve` in-process with the device listener, the production
//! `WimChecker` and the M3 keys from trusted files; the local
//! administrative commands `boot-service enrol|disable` through their
//! library functions; the boot stop is cleared through the operator
//! route. The PostgreSQL version of the same flow is `e2e_pg.rs` (CI,
//! `pg-integration`).
//!
//! | Behaviour | Test |
//! |-----------|------|
//! | code authorisation → package → disk → confirm → verified plan → verified chunks → progress → success; relay policy shows the stop; the operator's clear (`POST /v1/boot-stops/{id}/clear`) lifts it; disabled relay refused; chain intact | `device_session_to_success_and_boot_stop` |
//! | `boot-service enrol` refusals (operator certificate, duplicate, name, no EKU, bad subnet) and `operator enrol` of a relay certificate | `boot_service_admin_refusals` |
//! | listener off: the device port is not bound and `server.start` says so | `device_listener_off_by_default` |
//! | `boot-service raise-generation` after a restore: raised and recorded; equal, lower, 0 and unknown service refused (finding NIST-013) | `raise_generation_after_restore` |

#[cfg(test)]
pub mod common;

#[cfg(test)]
mod device_e2e {
    use std::net::SocketAddr;
    use std::time::Duration;

    use tokio::sync::oneshot;
    use tokio::task::JoinHandle;
    use usgp_audit::{AuditChain, AuditRecord};
    use usgp_common::config::TrustPolicy;
    use usgp_crypto::test_pki::{LeafSpec, TestCert};
    use usgp_db::{MemoryStore, OperatorRole, RepoTx, SCHEMA_VERSION, Store};
    use usgp_image::Compression;
    use usgp_image::testkit::builder::WimBuilder;
    use usgp_proto::{DisplayName, WimCompression};
    use usgp_server::audit_cmd;
    use usgp_server::boot_service_cmd::{
        self, BootServiceCmdError, BootServiceEnrolment, Disabled, parse_subnets,
    };
    use usgp_server::config::{LoadedConfig, load};
    use usgp_server::events::{self, LocalUser};
    use usgp_server::operator::{self, Enrolment, OperatorCmdError};
    use usgp_server::serve::{Listening, RunOptions, ServeError, prepare, run};

    use crate::common::device::{self, open_policy, pull};
    use crate::common::flow::{self, Expect, Source};
    use crate::common::stream::{Body, digest_bytes};
    use crate::common::{Fixture, admin_uid};

    fn trust() -> TrustPolicy {
        TrustPolicy::with_admin(admin_uid())
    }

    fn opts() -> RunOptions {
        RunOptions {
            trust: trust(),
            allow_shared_admin_uid: true,
            service_uid: Some(admin_uid()),
        }
    }

    fn who() -> LocalUser {
        LocalUser { uid: admin_uid() }
    }

    fn chain() -> AuditChain {
        AuditChain::new("test-node").unwrap()
    }

    struct Running {
        at: Listening,
        stop: oneshot::Sender<()>,
        task: JoinHandle<Result<(), ServeError>>,
    }

    impl Running {
        async fn stop(self) -> Result<(), ServeError> {
            let _ = self.stop.send(());
            self.task.await.unwrap()
        }
    }

    async fn start(l: LoadedConfig, store: &MemoryStore) -> Running {
        let prepared = prepare(&l.config, &trust()).unwrap();
        let (ready_tx, ready_rx) = oneshot::channel();
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let store = store.clone();
        let task = tokio::spawn(async move {
            let shutdown = async move {
                let _ = stop_rx.await;
                "test"
            };
            run(
                store,
                &l,
                prepared,
                opts(),
                SCHEMA_VERSION,
                shutdown,
                Some(ready_tx),
            )
            .await
        });
        let at = tokio::time::timeout(Duration::from_secs(20), ready_rx)
            .await
            .expect("server did not start")
            .expect("server stopped before serving");
        Running {
            at,
            stop: stop_tx,
            task,
        }
    }

    async fn enrol_admin(f: &Fixture, store: &MemoryStore) {
        events::ensure_genesis(store, &chain(), &f.audit_pub.key_id())
            .await
            .unwrap();
        operator::enrol(
            store,
            &chain(),
            &who(),
            &Enrolment {
                cert: f.pki.client.peer_certificate().unwrap(),
                name: DisplayName::new("Operator One").unwrap(),
                role: Some(OperatorRole::Administrator),
            },
        )
        .await
        .unwrap();
    }

    fn relay_cert(f: &Fixture, name: &str) -> TestCert {
        f.pki.intermediate.issue(&LeafSpec::client(name)).unwrap()
    }

    fn enrolment(cert: &TestCert, name: &str, subnets: &[&str]) -> BootServiceEnrolment {
        BootServiceEnrolment {
            cert: cert.peer_certificate().unwrap(),
            name: DisplayName::new(name).unwrap(),
            subnets: parse_subnets(&subnets.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
                .unwrap(),
        }
    }

    /// A 3-edition XPRESS WIM and an x64 PE from the test builder.
    fn wims() -> (Vec<u8>, Vec<u8>) {
        let mut b = WimBuilder::new(Compression::Xpress);
        for i in 1..=3 {
            b = b.image(&format!("Synthetic Edition {i}"), &format!("Edition {i}"));
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

    fn of<'a>(records: &'a [AuditRecord], event: &str) -> Vec<&'a AuditRecord> {
        records.iter().filter(|r| r.event == event).collect()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn device_session_to_success_and_boot_stop() {
        let f = Fixture::new("device-e2e");
        let store = MemoryStore::new();
        enrol_admin(&f, &store).await;
        let relay = relay_cert(&f, "relay e2e");
        let bs = boot_service_cmd::enrol(
            &store,
            &chain(),
            &who(),
            &enrolment(&relay, "Relay E2E", &["127.0.0.0/8"]),
        )
        .await
        .unwrap();
        let path = f.write_config(&f.config_text_m3(&f.unreachable_db()));
        let s = start(load(&path, &trust()).unwrap(), &store).await;
        let api = s.at.api;
        let dev: SocketAddr = s.at.device.expect("device listener bound");
        assert_ne!(api, dev);

        // The operator's Ready package (M2 flow, production checker).
        let (image_bytes, pe_bytes) = wims();
        let image = Source {
            body: Body::Bytes(&image_bytes),
            digests: digest_bytes(&image_bytes),
        };
        let pe = Source {
            body: Body::Bytes(&pe_bytes),
            digests: digest_bytes(&pe_bytes),
        };
        let eds: Vec<(String, String)> = (1..=3)
            .map(|i| (format!("Synthetic Edition {i}"), format!("Edition {i}")))
            .collect();
        // Boxed: the flows are large futures (debug builds, 2 MiB test
        // thread stacks).
        let ids = Box::pin(flow::wim_to_ready_package(
            api,
            &f,
            &image,
            &Expect {
                display_name: "Builder Image",
                compression: WimCompression::Xpress,
                editions: &eds,
                chosen: 2,
                ready_within: Duration::from_secs(60),
            },
            &pe,
            &f.audit_pub,
        ))
        .await;
        // The device flow to success and the relay's stop.
        let out = Box::pin(device::run(
            api,
            dev,
            &f,
            &bs.id.to_string(),
            &ids.package,
            image.digests.total,
            &relay,
        ))
        .await;

        // The operator's clear (decision 0021 item 3: the audited operator
        // route): the stop is lifted and the generation raised.
        let mut tx = store.begin().await.unwrap();
        let stops = tx.list_boot_stops(Some(bs.id), true).await.unwrap();
        tx.rollback().await;
        assert_eq!(stops.len(), 1);
        assert_eq!(stops[0].mac, out.mac);
        let clear = format!("/v1/boot-stops/{}/clear", stops[0].id);
        let r = device::op(api, &f, "POST", &clear, &[], None).await;
        assert_eq!(r.status, 200, "{}", r.text());
        let g3 = open_policy(&f, &pull(api, &f, &relay, out.generation).await);
        assert_eq!(g3.generation, out.generation + 1);
        assert!(!g3.stop_set().contains(&out.mac));
        let r = device::op(api, &f, "POST", &clear, &[], None).await;
        assert_eq!(r.status, 409, "{}", r.text());
        let mut tx = store.begin().await.unwrap();
        let after = tx.boot_stop(stops[0].id).await.unwrap().unwrap();
        tx.rollback().await;
        assert!(after.cleared_at.is_some() && after.cleared_by.is_some());

        // `boot-service disable`: the relay is refused from now on.
        assert_eq!(
            boot_service_cmd::disable(&store, &chain(), &who(), bs.id)
                .await
                .unwrap(),
            Disabled::Changed
        );
        assert_eq!(
            boot_service_cmd::disable(&store, &chain(), &who(), bs.id)
                .await
                .unwrap(),
            Disabled::AlreadyDisabled
        );
        assert_eq!(pull(api, &f, &relay, 0).await.status, 401);

        s.stop().await.unwrap();

        // Audit: every device choice and job state change, by the session
        // through the device listener; the relay through the relay feed;
        // the administrative commands by the local user (AU-3).
        let records = store.audit_records();
        for e in [
            "boot_service.enrolled",
            "boot_service.packages.set",
            "auth_code.issued",
            "device.session.opened",
            "auth_code.used",
            "device.session.authorised",
            "device.session.packages.read",
            "device.session.package_chosen",
            "device.session.disk_chosen",
            "disk.wipe.authorised",
            "job.created",
            "job.plan.issued",
            "job.content.read",
            "job.step.started",
            "job.step.completed",
            "job.succeeded",
            "boot_stop.added",
            "boot_policy.read",
            "boot_stop.cleared",
            "boot_service.disabled",
            "auth.boot_service_disabled",
        ] {
            assert!(!of(&records, e).is_empty(), "no {e}");
        }
        for e in [
            "device.session.opened",
            "device.session.package_chosen",
            "device.session.disk_chosen",
            "job.succeeded",
        ] {
            for r in of(&records, e) {
                assert_eq!(r.actor_kind, "device_session", "{r:?}");
                assert_eq!(r.actor_id.as_deref(), Some(out.session_id.as_str()));
                assert_eq!(r.interface, "device_api", "{r:?}");
            }
        }
        let wipe = of(&records, "disk.wipe.authorised");
        assert_eq!(wipe.len(), 1);
        assert_eq!(wipe[0].target_id.as_deref(), Some(out.job_id.as_str()));
        for r in of(&records, "boot_policy.read") {
            assert_eq!(r.actor_kind, "boot_service");
            assert_eq!(r.interface, "relay_feed");
        }
        for r in of(&records, "boot_stop.cleared") {
            assert_eq!(r.actor_kind, "operator", "{r:?}");
            assert_eq!(r.interface, "api", "{r:?}");
        }
        for e in ["boot_service.enrolled", "boot_service.disabled"] {
            for r in of(&records, e) {
                assert_eq!(r.actor_kind, "local_user", "{r:?}");
                assert_eq!(r.interface, "server-cli", "{r:?}");
            }
        }
        let start = of(&records, "server.start");
        assert!(start[0].detail.contains(&f.plan_pub.key_id().to_string()));
        assert!(start[0].detail.contains(&f.policy_pub.key_id().to_string()));
        assert!(start[0].detail.contains(&dev.to_string()));
        // No code, token or key value in any record.
        let all: String = records.iter().map(|r| format!("{r:?}\n")).collect();
        assert!(!all.contains("PRIVATE KEY"));
        // The chain verifies with the audit key.
        let report = audit_cmd::verify(&store, std::slice::from_ref(&f.audit_pub))
            .await
            .unwrap();
        assert!(report.is_intact(), "{report:?}");
    }

    /// Finding NIST-013: an administrator raises a boot service's
    /// boot-policy generation after a database restore; it never goes
    /// down or stays equal; each attempt is recorded.
    #[tokio::test(flavor = "multi_thread")]
    async fn raise_generation_after_restore() {
        let f = Fixture::new("bs-raise");
        let store = MemoryStore::new();
        enrol_admin(&f, &store).await;
        let c = chain();
        let relay = relay_cert(&f, "relay raise");
        let bs = boot_service_cmd::enrol(
            &store,
            &c,
            &who(),
            &enrolment(&relay, "Relay Raise", &["10.9.0.0/16"]),
        )
        .await
        .unwrap();
        // Before any stop change the generation is 0; raise to 500.
        assert_eq!(
            boot_service_cmd::raise_generation(&store, &c, &who(), bs.id, 500)
                .await
                .unwrap(),
            0
        );
        let mut tx = store.begin().await.unwrap();
        assert_eq!(tx.boot_policy_generation(bs.id).await.unwrap(), 500);
        tx.rollback().await;
        for to in [500, 499] {
            assert!(matches!(
                boot_service_cmd::raise_generation(&store, &c, &who(), bs.id, to).await,
                Err(BootServiceCmdError::Refused("generation_not_higher"))
            ));
        }
        assert!(matches!(
            boot_service_cmd::raise_generation(&store, &c, &who(), bs.id, 0).await,
            Err(BootServiceCmdError::Invalid(_))
        ));
        assert!(matches!(
            boot_service_cmd::raise_generation(
                &store,
                &c,
                &who(),
                usgp_proto::BootServiceId::from_random_bytes([4; 16]),
                900
            )
            .await,
            Err(BootServiceCmdError::Refused("boot_service_not_found"))
        ));
        let records = store.audit_records();
        let raised: Vec<_> = records
            .iter()
            .filter(|r| r.event == boot_service_cmd::GENERATION_RAISED)
            .collect();
        assert_eq!(raised.len(), 1);
        assert_eq!(raised[0].actor_kind, "local_user");
        assert!(raised[0].detail.contains("\"previous_generation\":\"0\""));
        assert!(raised[0].detail.contains("\"generation\":\"500\""));
        assert_eq!(
            records
                .iter()
                .filter(|r| r.event == boot_service_cmd::GENERATION_RAISE_REFUSED)
                .count(),
            3
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn boot_service_admin_refusals() {
        let f = Fixture::new("bs-admin");
        let store = MemoryStore::new();
        enrol_admin(&f, &store).await;
        let c = chain();
        // A certificate bound to an operator.
        let r = boot_service_cmd::enrol(
            &store,
            &c,
            &who(),
            &enrolment(&f.pki.client, "Relay Op", &["10.0.0.0/8"]),
        )
        .await;
        assert!(matches!(
            r,
            Err(BootServiceCmdError::Refused(
                "certificate_bound_to_operator"
            ))
        ));
        // No client-auth EKU.
        let r = boot_service_cmd::enrol(
            &store,
            &c,
            &who(),
            &enrolment(&f.pki.client_no_eku, "Relay NoEku", &["10.0.0.0/8"]),
        )
        .await;
        assert!(matches!(
            r,
            Err(BootServiceCmdError::Refused("certificate_eku"))
        ));
        let relay = relay_cert(&f, "relay a");
        boot_service_cmd::enrol(
            &store,
            &c,
            &who(),
            &enrolment(&relay, "Relay A", &["10.1.0.0/16", "2001:db8::/32"]),
        )
        .await
        .unwrap();
        // The same certificate again; another certificate with the name.
        let r = boot_service_cmd::enrol(
            &store,
            &c,
            &who(),
            &enrolment(&relay, "Relay A2", &["10.2.0.0/16"]),
        )
        .await;
        assert!(matches!(
            r,
            Err(BootServiceCmdError::Refused("certificate_already_enrolled"))
        ));
        let r = boot_service_cmd::enrol(
            &store,
            &c,
            &who(),
            &enrolment(&relay_cert(&f, "relay b"), "Relay A", &["10.3.0.0/16"]),
        )
        .await;
        assert!(matches!(
            r,
            Err(BootServiceCmdError::Refused("name_in_use"))
        ));
        // The relay's certificate cannot become an operator's.
        let r = operator::enrol(
            &store,
            &c,
            &who(),
            &Enrolment {
                cert: relay.peer_certificate().unwrap(),
                name: DisplayName::new("Not An Operator").unwrap(),
                role: Some(OperatorRole::Administrator),
            },
        )
        .await;
        assert!(matches!(
            r,
            Err(OperatorCmdError::Refused(
                "certificate_bound_to_boot_service"
            ))
        ));
        // Unknown boot service.
        let r = boot_service_cmd::disable(
            &store,
            &c,
            &who(),
            usgp_proto::BootServiceId::from_random_bytes([3; 16]),
        )
        .await;
        assert!(matches!(
            r,
            Err(BootServiceCmdError::Refused("boot_service_not_found"))
        ));
        // Subnets: host bits, repeats, none, more than 64.
        for bad in [
            vec!["10.0.0.1/8".to_owned()],
            vec!["10.0.0.0/8".to_owned(), "10.0.0.0/8".to_owned()],
            vec![],
            (0..65).map(|i| format!("10.{i}.0.0/16")).collect(),
            vec!["not-a-subnet".to_owned()],
        ] {
            assert!(parse_subnets(&bad).is_err(), "{bad:?}");
        }
        // Every refusal is recorded with its reason; the enrolment with
        // the certificate and subnets.
        let records = store.audit_records();
        let reasons: Vec<&str> = records
            .iter()
            .filter(|r| r.event == "boot_service.enrol.refused")
            .filter_map(|r| r.reason.as_deref())
            .collect();
        for want in [
            "certificate_bound_to_operator",
            "certificate_eku",
            "certificate_already_enrolled",
            "name_in_use",
        ] {
            assert!(reasons.contains(&want), "{want}: {reasons:?}");
        }
        let enrolled = of(&records, "boot_service.enrolled");
        assert_eq!(enrolled.len(), 1);
        assert!(enrolled[0].detail.contains("10.1.0.0/16,2001:db8::/32"));
        assert!(
            enrolled[0]
                .detail
                .contains(&relay.peer_certificate().unwrap().sha256.to_string())
        );
        assert!(
            of(&records, "operator.enrol.refused")
                .iter()
                .any(|r| { r.reason.as_deref() == Some("certificate_bound_to_boot_service") })
        );
        assert_eq!(
            of(&records, "boot_service.disable.refused")[0]
                .reason
                .as_deref(),
            Some("boot_service_not_found")
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn device_listener_off_by_default() {
        let f = Fixture::new("device-off");
        let store = MemoryStore::new();
        let path = f.write_config(&f.config_text(&f.unreachable_db()));
        let s = start(load(&path, &trust()).unwrap(), &store).await;
        assert!(s.at.device.is_none());
        s.stop().await.unwrap();
        let records = store.audit_records();
        let start = of(&records, "server.start");
        assert!(
            start[0].detail.contains("\"device_listen\":\"off\""),
            "{}",
            start[0].detail
        );
        assert!(start[0].detail.contains("\"plan_key_id\":\"none\""));
    }
}
