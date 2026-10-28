//! `usgp-cli boot-service list | show | set-packages` and
//! `usgp-cli boot-stop list | clear` (M3 plan WU-13, section 3.5;
//! REQ-TGT-001, REQ-TGT-008, REQ-BOOT-067).
//!
//! `set-packages` replaces a boot service's whole package list. It is a
//! conditional request (`If-Match`, RFC 9110 §13.1.1): with `--if-match`
//! the operator binds the change to the assignment they reviewed with
//! `show` (which prints the tag); without it, the tag is read just before
//! the change. A change in between is refused by the server (412) and
//! nothing is changed. Enrolling and disabling boot services are local
//! administrative commands of the server, not operator API calls.
//!
//! `boot-stop clear` is the minimal reversal of a boot stop (decision
//! 0021 item 3): the device is offered a boot program again after the
//! relay's next policy pull.

// COMPLIANCE MAPPING:
// - NIST 800-53: CM-3 (Configuration Change Control) - assignment changes
//   are conditional on the reviewed state; lost updates are refused.
// - NIST 800-53: AC-3 - the server enforces `boot_service.assign` and
//   `device.boot_reenable`; the CLI shows its refusal.
// - NIST 800-53: SI-10 - ids parsed and the list bounded locally; the
//   tag is sent only if it is a well-formed entity tag.
// - SPEC: specs/targeting.md#REQ-TGT-001 (packages per boot service),
//   #REQ-TGT-008 (warning when nothing is usable)
// - SPEC: specs/boot-network.md#REQ-BOOT-067 (boot stops; minimal clear)
// - RFC 9110 §8.8.3 (ETag), §13.1.1 (If-Match)

use std::io::Write;

use usgp_proto::ids::{BootServiceId, BootStopId};
use usgp_proto::ops::{
    BootServiceList, BootServiceView, BootStopList, BootStopView, SetBootServicePackagesRequest,
};

use crate::client::{ApiClient, Body, ClientError, Method, Transport, clean_etag};
use crate::cmd_content::CmdError;
use crate::cmd_image::print_reason;
use crate::display::{esc, utc};

/// Parses a boot-service id given on the command line.
///
/// # Errors
///
/// [`CmdError::Invalid`].
pub fn boot_service_id(text: &str) -> Result<BootServiceId, CmdError> {
    BootServiceId::parse(text).map_err(|e| CmdError::Invalid(format!("ID {}: {e}", esc(text))))
}

/// Parses a boot-stop id given on the command line.
///
/// # Errors
///
/// [`CmdError::Invalid`].
pub fn boot_stop_id(text: &str) -> Result<BootStopId, CmdError> {
    BootStopId::parse(text).map_err(|e| CmdError::Invalid(format!("ID {}: {e}", esc(text))))
}

/// Writes one boot service; `tag` is its assignment tag, if known.
///
/// # Errors
///
/// [`CmdError::Output`].
pub fn print_boot_service(
    out: &mut dyn Write,
    v: &BootServiceView,
    tag: Option<&str>,
) -> Result<(), CmdError> {
    writeln!(out, "boot service {}", v.id)?;
    writeln!(out, "  name:    {}", esc(v.name.as_str()))?;
    writeln!(out, "  status:  {}", v.status)?;
    let subnets: Vec<String> = v
        .served_subnets
        .as_slice()
        .iter()
        .map(ToString::to_string)
        .collect();
    writeln!(out, "  subnets: {}", subnets.join(", "))?;
    if v.packages.is_empty() {
        writeln!(out, "  packages: none")?;
    } else {
        writeln!(out, "  packages:")?;
        for p in &v.packages {
            writeln!(out, "    {} {}", p.id, esc(p.name.as_str()))?;
        }
    }
    writeln!(out, "  usable now: {}", v.usable_count)?;
    print_reason(out, "WARNING", v.warning.as_ref())?;
    if let Some(t) = tag {
        writeln!(out, "  assignment tag: {}", esc(t))?;
    }
    Ok(())
}

/// `boot-service list`.
///
/// # Errors
///
/// [`CmdError`].
pub fn list<T: Transport>(api: &mut ApiClient<T>, out: &mut dyn Write) -> Result<(), CmdError> {
    let raw = api.get("/v1/boot-services".into())?;
    let list: BootServiceList = parse_json!(raw)?;
    if list.boot_services.is_empty() {
        writeln!(out, "no boot services")?;
    }
    for v in &list.boot_services {
        print_boot_service(out, v, None)?;
    }
    Ok(())
}

fn get<T: Transport>(
    api: &mut ApiClient<T>,
    id: BootServiceId,
) -> Result<(BootServiceView, Option<String>), CmdError> {
    let raw = api.get(format!("/v1/boot-services/{id}"))?;
    let v: BootServiceView = parse_json!(raw)?;
    if v.id != id {
        return Err(
            ClientError::BadResponse("the server returned a different boot service").into(),
        );
    }
    Ok((v, raw.etag))
}

/// `boot-service show ID`.
///
/// # Errors
///
/// [`CmdError`].
pub fn show<T: Transport>(
    api: &mut ApiClient<T>,
    id: BootServiceId,
    out: &mut dyn Write,
) -> Result<(), CmdError> {
    let (v, tag) = get(api, id)?;
    print_boot_service(out, &v, tag.as_deref())
}

/// `boot-service set-packages ID (PACKAGE_ID... | --none) [--if-match TAG]`.
///
/// # Errors
///
/// [`CmdError`]; the server's 412 if the assignment changed since the tag
/// was read.
pub fn set_packages<T: Transport>(
    api: &mut ApiClient<T>,
    id: BootServiceId,
    packages: &[String],
    if_match: Option<&str>,
    out: &mut dyn Write,
) -> Result<(), CmdError> {
    let wire = SetBootServicePackagesRequest {
        package_ids: packages.to_vec(),
    };
    let ids = wire.validate().map_err(|e| CmdError::Invalid(e.message))?;
    let tag = match if_match {
        Some(t) => clean_etag(t.as_bytes()).ok_or_else(|| {
            CmdError::Invalid(format!("--if-match {}: not an entity tag", esc(t)))
        })?,
        None => get(api, id)?.1.ok_or(ClientError::BadResponse(
            "the server sent no ETag for the boot service",
        ))?,
    };
    let req = SetBootServicePackagesRequest::from(ids.as_slice());
    let raw = api.call(
        Method::Put,
        format!("/v1/boot-services/{id}/packages"),
        Some(tag),
        json_body!(&req)?,
    )?;
    let v: BootServiceView = parse_json!(raw)?;
    if v.id != id {
        return Err(
            ClientError::BadResponse("the server returned a different boot service").into(),
        );
    }
    writeln!(out, "set packages of boot service {id}")?;
    print_boot_service(out, &v, raw.etag.as_deref())
}

/// Writes one boot stop.
///
/// # Errors
///
/// [`CmdError::Output`].
pub fn print_boot_stop(out: &mut dyn Write, v: &BootStopView) -> Result<(), CmdError> {
    writeln!(out, "boot stop {}", v.id)?;
    writeln!(out, "  device:  {}", v.mac)?;
    writeln!(out, "  job:     {}", v.job_id)?;
    writeln!(out, "  boot service: {}", v.boot_service_id)?;
    writeln!(out, "  stopped: {}", utc(v.created_at.as_micros()))?;
    match (v.cleared_at, v.cleared_by) {
        (Some(at), Some(by)) => {
            writeln!(out, "  cleared: {} by operator {by}", utc(at.as_micros()))?
        }
        (Some(at), None) => writeln!(out, "  cleared: {}", utc(at.as_micros()))?,
        _ => writeln!(out, "  active: the device is not offered a boot program")?,
    }
    Ok(())
}

/// `boot-stop list` (active and cleared).
///
/// # Errors
///
/// [`CmdError`].
pub fn list_stops<T: Transport>(
    api: &mut ApiClient<T>,
    out: &mut dyn Write,
) -> Result<(), CmdError> {
    let raw = api.get("/v1/boot-stops".into())?;
    let list: BootStopList = parse_json!(raw)?;
    if list.stops.is_empty() {
        writeln!(out, "no boot stops")?;
    }
    for v in &list.stops {
        print_boot_stop(out, v)?;
    }
    Ok(())
}

/// `boot-stop clear ID`.
///
/// # Errors
///
/// [`CmdError`].
pub fn clear_stop<T: Transport>(
    api: &mut ApiClient<T>,
    id: BootStopId,
    out: &mut dyn Write,
) -> Result<(), CmdError> {
    let raw = api.call(
        Method::Post,
        format!("/v1/boot-stops/{id}/clear"),
        None,
        Body::Empty,
    )?;
    let v: BootStopView = parse_json!(raw)?;
    if v.id != id {
        return Err(ClientError::BadResponse("the server returned a different boot stop").into());
    }
    writeln!(out, "cleared boot stop {id}")?;
    print_boot_stop(out, &v)?;
    writeln!(
        out,
        "  the device is offered a boot program again after the relay's next policy pull"
    )?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::client::fake::{FakeTransport, Scripted};
    use usgp_proto::api::{ErrorBody, Message, PackageRef, Reason};
    use usgp_proto::ids::{JobId, PackageId, UnixMicros};
    use usgp_proto::names::DisplayName;
    use usgp_proto::ops::{BootServiceStatus, IpCidr, SubnetList};
    use usgp_proto::{ErrorCode, MacAddress};

    pub(crate) const BS: &str = "9a1e2f3a-4b5c-4d6e-8f70-8192a3b4c5d6";
    pub(crate) const PKG: &str = "1c9e8a70-2b3d-4e5f-9a0b-c1d2e3f40516";
    const STOP: &str = "aa1e2f3a-4b5c-4d6e-8f70-8192a3b4c5d6";
    pub(crate) const TAG: &str = "\"bsp-abc\"";

    pub(crate) fn service(packages: &[&str]) -> BootServiceView {
        let usable = u32::try_from(packages.len()).unwrap();
        BootServiceView {
            id: BootServiceId::parse(BS).unwrap(),
            name: DisplayName::new("Lab segment").unwrap(),
            served_subnets: SubnetList::new(vec![IpCidr::parse("10.20.0.0/16").unwrap()]).unwrap(),
            status: BootServiceStatus::Active,
            packages: packages
                .iter()
                .map(|p| PackageRef {
                    id: PackageId::parse(p).unwrap(),
                    name: DisplayName::new("Laptops").unwrap(),
                })
                .collect(),
            usable_count: usable,
            warning: (usable == 0).then(|| Reason {
                code: ErrorCode::new("no_usable_package").unwrap(),
                message: Message::new("this boot service has no usable package").unwrap(),
            }),
        }
    }

    fn body(v: &BootServiceView) -> Vec<u8> {
        serde_json::to_vec(v).unwrap()
    }

    #[test]
    fn set_packages_reads_tag_then_sends_if_match() {
        let mut api = ApiClient::new(
            FakeTransport::default()
                .expect(
                    Method::Get,
                    &format!("/v1/boot-services/{BS}"),
                    Scripted::bytes(200, body(&service(&[]))).with_etag(TAG),
                )
                .expect(
                    Method::Put,
                    &format!("/v1/boot-services/{BS}/packages"),
                    Scripted::bytes(200, body(&service(&[PKG]))).with_etag("\"bsp-def\""),
                ),
        );
        let mut out = Vec::new();
        set_packages(
            &mut api,
            boot_service_id(BS).unwrap(),
            &[PKG.to_owned()],
            None,
            &mut out,
        )
        .unwrap();
        let seen = &api.transport().seen;
        let put = seen.get(1).unwrap();
        assert_eq!(put.if_match.as_deref(), Some(TAG));
        let sent: SetBootServicePackagesRequest = serde_json::from_slice(&put.body).unwrap();
        assert_eq!(sent.package_ids, vec![PKG.to_owned()]);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("assignment tag: \"bsp-def\""), "{text}");
        assert!(text.contains("usable now: 1"), "{text}");
    }

    #[test]
    fn set_packages_with_reviewed_tag_skips_the_read_and_shows_412() {
        let body412 = ErrorBody::new(
            ErrorCode::new("precondition_failed").unwrap(),
            Message::new("changed").unwrap(),
        );
        let mut api = ApiClient::new(FakeTransport::default().expect(
            Method::Put,
            &format!("/v1/boot-services/{BS}/packages"),
            Scripted::bytes(412, serde_json::to_vec(&body412).unwrap()),
        ));
        let e = set_packages(
            &mut api,
            boot_service_id(BS).unwrap(),
            &[],
            Some(TAG),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(e.to_string().contains("changed since it was read"), "{e}");
        let put = api.transport().seen.first().unwrap();
        assert_eq!(put.if_match.as_deref(), Some(TAG));
        let sent: SetBootServicePackagesRequest = serde_json::from_slice(&put.body).unwrap();
        assert!(sent.package_ids.is_empty());
    }

    #[test]
    fn set_packages_refuses_bad_input_and_missing_etag() {
        let mut api = ApiClient::new(FakeTransport::default());
        let id = boot_service_id(BS).unwrap();
        for (pk, tag) in [
            (vec!["nope".to_owned()], None),
            (vec![PKG.to_owned(), PKG.to_owned()], None),
            (vec![PKG.to_owned()], Some("\"a\"\r\nX: y")),
        ] {
            let e = set_packages(&mut api, id, &pk, tag, &mut Vec::new()).unwrap_err();
            assert!(matches!(e, CmdError::Invalid(_)), "{e}");
        }
        assert!(api.transport().seen.is_empty());
        let too_many: Vec<String> = (0..=256u32)
            .map(|i| format!("1c9e8a70-2b3d-4e5f-9a0b-{i:012x}"))
            .collect();
        assert!(matches!(
            set_packages(&mut api, id, &too_many, None, &mut Vec::new()),
            Err(CmdError::Invalid(_))
        ));
        // No ETag on the read: nothing is changed.
        let mut api = ApiClient::new(FakeTransport::default().expect(
            Method::Get,
            &format!("/v1/boot-services/{BS}"),
            Scripted::bytes(200, body(&service(&[]))),
        ));
        let e = set_packages(&mut api, id, &[PKG.to_owned()], None, &mut Vec::new()).unwrap_err();
        assert!(e.to_string().contains("no ETag"), "{e}");
        assert_eq!(api.transport().seen.len(), 1);
    }

    #[test]
    fn show_prints_warning_and_tag() {
        let mut api = ApiClient::new(FakeTransport::default().expect(
            Method::Get,
            &format!("/v1/boot-services/{BS}"),
            Scripted::bytes(200, body(&service(&[]))).with_etag(TAG),
        ));
        let mut out = Vec::new();
        show(&mut api, boot_service_id(BS).unwrap(), &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("WARNING: no_usable_package"), "{text}");
        assert!(text.contains("subnets: 10.20.0.0/16"), "{text}");
        assert!(text.contains("assignment tag: \"bsp-abc\""), "{text}");
    }

    fn stop(cleared: bool) -> BootStopView {
        BootStopView {
            id: BootStopId::parse(STOP).unwrap(),
            boot_service_id: BootServiceId::parse(BS).unwrap(),
            mac: MacAddress::parse("02:00:00:00:00:01").unwrap(),
            job_id: JobId::parse("8a1e2f3a-4b5c-4d6e-8f70-8192a3b4c5d6").unwrap(),
            created_at: UnixMicros::new(0).unwrap(),
            cleared_at: cleared.then(|| UnixMicros::new(1_000_000).unwrap()),
            cleared_by: None,
        }
    }

    #[test]
    fn boot_stops_list_and_clear() {
        let list = BootStopList {
            stops: vec![stop(false)],
        };
        let mut api = ApiClient::new(
            FakeTransport::default()
                .expect(
                    Method::Get,
                    "/v1/boot-stops",
                    Scripted::bytes(200, serde_json::to_vec(&list).unwrap()),
                )
                .expect(
                    Method::Post,
                    &format!("/v1/boot-stops/{STOP}/clear"),
                    Scripted::bytes(200, serde_json::to_vec(&stop(true)).unwrap()),
                ),
        );
        let mut out = Vec::new();
        list_stops(&mut api, &mut out).unwrap();
        clear_stop(&mut api, boot_stop_id(STOP).unwrap(), &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("device:  02:00:00:00:00:01"), "{text}");
        assert!(text.contains("active: the device is not offered"), "{text}");
        assert!(
            text.contains(&format!("cleared boot stop {STOP}")),
            "{text}"
        );
        assert!(
            text.contains("cleared: 1970-01-01T00:00:01.000000Z"),
            "{text}"
        );
        assert!(api.transport().seen.get(1).unwrap().body.is_empty());
    }
}
