//! The relay's boot-policy route (M3 plan section 3.6, as `usgp-relay`'s
//! feed client expects it): mTLS with the relay certificate bound to its
//! boot-service record; 304 when current; otherwise 200 with a signed
//! `BootPolicyV1` (`key_id` set, generations from 1); the stop list
//! follows job success and the operator's clear. Also boot-service
//! assignment with its derived `ETag`.

use usgp_crypto::test_pki::TestCert;
use usgp_proto::ops::BootServiceStatus;
use usgp_proto::{BootPolicyV1, BootServiceId, MacAddress, SignedEnvelopeV1};

use crate::common::{Harness, Pinned, Resp, Who, nonce};

async fn pull(h: &Harness, relay: &TestCert, have: u64) -> Resp {
    h.req_as(
        Some(relay),
        "GET",
        &format!("/v1/relay/boot-policy?have={have}"),
        &[],
        None,
    )
    .await
}

fn open(h: &Harness, r: &Resp) -> BootPolicyV1 {
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let env = SignedEnvelopeV1::from_json(&r.body).unwrap();
    BootPolicyV1::open(&env, &Pinned(h.policy_pub.clone())).unwrap()
}

/// First pull: generation 1, empty list, signed with the boot-policy key;
/// then 304 while current; a stale `have` gets the list again.
#[tokio::test]
async fn generation_from_one_and_not_modified() {
    let h = Harness::m3().await;
    let relay = h.relay_cert("relay gen");
    let bs = h
        .enrol_boot_service(
            &relay,
            "Relay gen",
            &["10.20.0.0/16"],
            BootServiceStatus::Active,
        )
        .await;
    let p = open(&h, &pull(&h, &relay, 0).await);
    assert_eq!(p.generation, 1);
    assert_eq!(p.boot_service_id, bs);
    assert_eq!(p.key_id, h.policy_pub.key_id().0);
    assert!(p.stops.is_empty());
    p.check_for(bs, None).unwrap();
    // Not signed with the content key.
    let r = pull(&h, &relay, 0).await;
    let env = SignedEnvelopeV1::from_json(&r.body).unwrap();
    assert!(BootPolicyV1::open(&env, &Pinned(h.content_pub.clone())).is_err());
    let r = pull(&h, &relay, 1).await;
    assert_eq!(r.status, 304);
    assert!(r.body.is_empty());
    assert_eq!(h.events("boot_policy.generation.initialised").len(), 1);
    let reads = h.events("boot_policy.read");
    assert_eq!(reads.len(), 3, "two lists and the first 304");
    assert!(
        reads
            .iter()
            .all(|r| r.target_id.as_deref() == Some(bs.to_string().as_str()))
    );
    // The relay is the actor, through the relay feed (plan M3 section 7).
    assert!(reads.iter().all(|r| r.actor_kind == "boot_service"
        && r.actor_id.as_deref() == Some(bs.to_string().as_str())
        && r.interface == "relay_feed"));
    // A further 304 within the interval is not recorded again.
    assert_eq!(pull(&h, &relay, 1).await.status, 304);
    assert_eq!(h.events("boot_policy.read").len(), 3);
    // `have` must be a decimal generation.
    for bad in ["", "?have=", "?have=x", "?gen=1"] {
        let r = h
            .req_as(
                Some(&relay),
                "GET",
                &format!("/v1/relay/boot-policy{bad}"),
                &[],
                None,
            )
            .await;
        assert_eq!(r.status, 400, "{bad}");
    }
}

/// Success adds the device's MACs to its boot service's list with a new
/// generation; a stale relay gets it; clearing removes it with another
/// generation; the old generation is refused by the relay's own check.
#[tokio::test]
async fn success_stops_and_clear() {
    let h = Harness::m3().await;
    let macs = ["02:00:00:00:02:01"];
    let rd = h.ready_device("policy", &macs).await;
    let g1 = open(&h, &pull(&h, &rd.relay, 0).await);
    assert_eq!(g1.generation, 1);
    let r = h
        .confirm(&rd.session.token, &rd.pkg, &rd.disk, &nonce())
        .await;
    let job = r.json()["job_id"].as_str().unwrap().to_owned();
    let mut seq = 1;
    for step in 1..=4u8 {
        if step > 1 {
            let r = h
                .report(
                    &rd.session.token,
                    &job,
                    serde_json::json!({"seq": seq, "step": step, "event": "step_started"}),
                )
                .await;
            assert_eq!(r.status, 200);
            seq += 1;
        }
        let r = h
            .report(
                &rd.session.token,
                &job,
                serde_json::json!({"seq": seq, "step": step, "event": "step_completed"}),
            )
            .await;
        assert_eq!(r.status, 200);
        seq += 1;
    }
    let r = h
        .report(
            &rd.session.token,
            &job,
            serde_json::json!({"seq": seq, "step": 5, "event": "succeeded"}),
        )
        .await;
    assert_eq!(r.status, 200);
    // Stale relay (have=1): the new list with the stop.
    let g2 = open(&h, &pull(&h, &rd.relay, 1).await);
    assert_eq!(g2.generation, 2);
    let mac = MacAddress::parse(macs[0]).unwrap();
    assert!(g2.stop_set().contains(&mac));
    assert_eq!(g2.stops[0].job_id.to_string(), job);
    assert_eq!(pull(&h, &rd.relay, 2).await.status, 304);
    // The operator clears the stop.
    let r = h.get(Who::Admin, "/v1/boot-stops").await;
    assert_eq!(r.status, 200);
    let stop = r.json()["stops"][0]["id"].as_str().unwrap().to_owned();
    let r = h
        .req(
            Who::Admin,
            "POST",
            &format!("/v1/boot-stops/{stop}/clear"),
            &[],
            None,
        )
        .await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert!(r.json()["cleared_at"].is_number());
    let rec = &h.events("boot_stop.cleared")[0];
    assert!(
        rec.detail.contains("\"generation\":\"3\""),
        "{}",
        rec.detail
    );
    let r = h
        .req(
            Who::Admin,
            "POST",
            &format!("/v1/boot-stops/{stop}/clear"),
            &[],
            None,
        )
        .await;
    assert_eq!(r.status, 409);
    let g3 = open(&h, &pull(&h, &rd.relay, 2).await);
    assert_eq!(g3.generation, 3);
    assert!(g3.stops.is_empty());
    // A relay that applied 3 refuses 2 (rollback, its own check).
    assert!(g2.check_for(rd.bs, Some(g3.generation)).is_err());
}

/// Only a relay certificate bound to an active boot service is served;
/// it gets only its own list; operators get 403; a relay gets 403 on
/// operator routes.
#[tokio::test]
async fn relay_authentication() {
    let h = Harness::m3().await;
    let a = h.relay_cert("relay a");
    let b = h.relay_cert("relay b");
    let unbound = h.relay_cert("relay unbound");
    let off = h.relay_cert("relay disabled");
    let bs_a = h
        .enrol_boot_service(&a, "Relay A", &["10.1.0.0/16"], BootServiceStatus::Active)
        .await;
    let bs_b = h
        .enrol_boot_service(&b, "Relay B", &["10.2.0.0/16"], BootServiceStatus::Active)
        .await;
    h.enrol_boot_service(
        &off,
        "Relay off",
        &["10.3.0.0/16"],
        BootServiceStatus::Disabled,
    )
    .await;
    assert_eq!(open(&h, &pull(&h, &a, 0).await).boot_service_id, bs_a);
    assert_eq!(open(&h, &pull(&h, &b, 0).await).boot_service_id, bs_b);
    // Not bound to any boot service.
    let r = pull(&h, &unbound, 0).await;
    assert_eq!(r.status, 401);
    assert_eq!(h.events("auth.unknown_certificate").len(), 1);
    // Bound to a disabled boot service.
    let r = pull(&h, &off, 0).await;
    assert_eq!(r.status, 401);
    assert_eq!(h.events("auth.boot_service_disabled").len(), 1);
    // An operator certificate.
    let r = h.get(Who::Admin, "/v1/relay/boot-policy?have=0").await;
    assert_eq!(r.status, 403);
    // A relay on an operator route.
    let r = h.req_as(Some(&a), "GET", "/v1/packages", &[], None).await;
    assert_eq!(r.status, 403);
    let denied = h.events("authz.denied");
    assert_eq!(denied.len(), 2);
    assert_eq!(denied[1].actor_kind, "boot_service");
    assert_eq!(
        denied[1].actor_id.as_deref(),
        Some(bs_a.to_string().as_str())
    );
}

/// A certificate bound both to an operator and to a boot service is
/// refused everywhere (fail closed).
#[tokio::test]
async fn ambiguous_certificate_refused() {
    let h = Harness::m3().await;
    let bs = h
        .enrol_boot_service(
            &h.pki.client,
            "Same cert",
            &["10.4.0.0/16"],
            BootServiceStatus::Active,
        )
        .await;
    let _ = bs;
    assert_eq!(h.get(Who::Admin, "/v1/packages").await.status, 401);
    assert_eq!(
        h.get(Who::Admin, "/v1/relay/boot-policy?have=0")
            .await
            .status,
        401
    );
    assert!(!h.events("auth.ambiguous_certificate").is_empty());
}

/// Assignment needs the derived ETag; the packages show in the view;
/// two boot services on one subnet offer nothing (ambiguous).
#[tokio::test]
async fn assignment_etag_and_ambiguity() {
    let h = Harness::m3().await;
    let relay = h.relay_cert("relay assign");
    let bs: BootServiceId = h
        .enrol_boot_service(
            &relay,
            "Assign",
            &["127.0.0.0/8"],
            BootServiceStatus::Active,
        )
        .await;
    let (pkg, _, _) = h.ready_package("assign").await;
    let path = format!("/v1/boot-services/{bs}/packages");
    let body = serde_json::to_vec(&serde_json::json!({ "package_ids": [pkg] })).unwrap();
    let r = h
        .req(Who::Admin, "PUT", &path, &[], Some(body.clone()))
        .await;
    assert_eq!(r.status, 428);
    let r = h
        .req(
            Who::Admin,
            "PUT",
            &path,
            &[("if-match", "\"bsp-0\"")],
            Some(body.clone()),
        )
        .await;
    assert_eq!(r.status, 412);
    let r = h.assign(bs, &[&pkg]).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["usable_count"], 1);
    assert!(
        r.json()
            .get("warning")
            .is_none_or(serde_json::Value::is_null)
    );
    let etag = r.header("etag").unwrap();
    assert_eq!(
        etag,
        usgp_api::assignment_etag(&[usgp_proto::PackageId::parse(&pkg).unwrap()])
    );
    // An unknown package id.
    let r = h
        .req(
            Who::Admin,
            "PUT",
            &path,
            &[("if-match", &etag)],
            Some(
                serde_json::to_vec(
                    &serde_json::json!({ "package_ids": [crate::authz_matrix::NOWHERE] }),
                )
                .unwrap(),
            ),
        )
        .await;
    assert_eq!(r.status, 422);
    assert_eq!(h.events("boot_service.packages.set").len(), 1);
    assert_eq!(h.events("boot_service.packages.refused").len(), 3);
    let r = h.get(Who::Admin, "/v1/boot-services").await;
    assert_eq!(r.json()["boot_services"].as_array().unwrap().len(), 1);
    // A second boot service on the same subnet makes the source ambiguous.
    let other = h.relay_cert("relay overlap");
    h.enrol_boot_service(
        &other,
        "Overlap",
        &["127.0.0.1/32"],
        BootServiceStatus::Active,
    )
    .await;
    let s = h.open_session(&["02:00:00:00:02:02"]).await;
    let (_, code) = h.issue_code().await;
    assert_eq!(h.submit_code(&s.token, &code).await.status, 200);
    let r = h
        .dev("GET", "/v1/device/session/packages", Some(&s.token), None)
        .await;
    assert_eq!(r.json()["packages"], serde_json::json!([]));
    let opened = &h.events("device.session.opened");
    assert!(
        opened
            .last()
            .unwrap()
            .detail
            .contains("\"boot_service_resolution\":\"ambiguous\"")
    );
}
