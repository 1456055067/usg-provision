#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::collections::BTreeMap;

use super::values::{ValueError, check_computer_name, check_tags, check_time_zone};
use super::*;

const NS: &str = "urn:schemas-microsoft-com:unattend";

fn doc(body: &str) -> String {
    format!(r#"<?xml version="1.0" encoding="utf-8"?><unattend xmlns="{NS}">{body}</unattend>"#)
}

fn good_body() -> &'static str {
    r#"<settings pass="specialize"><component name="Microsoft-Windows-Shell-Setup"><ComputerName>{{device.computer_name}}</ComputerName><TimeZone>{{time_zone}}</TimeZone></component><component name="Microsoft-Windows-UnattendedJoin"><Identification><JoinDomain>{{domain}}</JoinDomain><MachineObjectOU>{{machine_ou}}</MachineObjectOU></Identification></component></settings>"#
}

fn parse(s: &str) -> Result<Template, TemplateError> {
    Template::parse(s.as_bytes(), &Limits::default())
}

fn pv() -> PackageValues {
    PackageValues {
        computer_name: Some(ComputerNameSource::PerDevice),
        time_zone: Some("Eastern Standard Time".into()),
        domain: Some("corp.example".into()),
        machine_ou: Some(r#"OU="Lab, West",DC=corp,DC=example"#.into()),
    }
}

fn resolver() -> MapResolver {
    let mut m = BTreeMap::new();
    m.insert("device.computer_name".into(), "LAB-PC01".into());
    m.insert("time_zone".into(), "Eastern Standard Time".into());
    m.insert("domain".into(), "corp.example".into());
    m.insert(
        "machine_ou".into(),
        r#"OU="Lab, West",DC=corp,DC=example"#.into(),
    );
    MapResolver(m)
}

#[test]
fn good_template_parses_lints_clean_and_renders() {
    let t = parse(&doc(good_body())).unwrap();
    assert_eq!(
        t.references(),
        vec!["device.computer_name", "domain", "machine_ou", "time_zone"]
    );
    assert_eq!(t.lint(&pv()), vec![]);
    let r = t.render(&resolver()).unwrap();
    let s = String::from_utf8(r.bytes).unwrap();
    assert!(s.contains("<ComputerName>LAB-PC01</ComputerName>"));
    assert!(s.contains("OU=&quot;Lab, West&quot;,DC=corp"));
    assert!(!s.contains("{{"));
}

#[test]
fn refuses_doctype_and_billion_laughs() {
    let xxe = format!(
        r#"<?xml version="1.0"?><!DOCTYPE u [<!ENTITY x SYSTEM "file:///etc/passwd">]><unattend xmlns="{NS}">&x;</unattend>"#
    );
    assert_eq!(parse(&xxe), Err(TemplateError::DoctypeRefused));
    let lol = format!(
        r#"<!DOCTYPE u [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]><unattend xmlns="{NS}">&b;</unattend>"#
    );
    assert_eq!(parse(&lol), Err(TemplateError::DoctypeRefused));
}

#[test]
fn refuses_undeclared_entity_pi_and_encodings() {
    assert_eq!(parse(&doc("&foo;")), Err(TemplateError::EntityRefused));
    assert_eq!(
        parse(&doc("<?xml-stylesheet href=\"x\"?>")),
        Err(TemplateError::ProcessingInstructionRefused)
    );
    let u16 = format!(r#"<?xml version="1.0" encoding="UTF-16"?><unattend xmlns="{NS}"/>"#);
    assert_eq!(parse(&u16), Err(TemplateError::EncodingNotUtf8));
    assert_eq!(
        Template::parse(&[0xff, 0xfe, b'<', 0], &Limits::default()),
        Err(TemplateError::NotUtf8)
    );
    assert_eq!(
        Template::parse(b"<unattend \xff/>", &Limits::default()),
        Err(TemplateError::NotUtf8)
    );
}

#[test]
fn predefined_and_numeric_references_allowed() {
    let t = parse(&doc("<a b=\"&lt;&#65;\">&amp;&#x42;</a>")).unwrap();
    let s = String::from_utf8(t.render(&MapResolver::default()).unwrap().bytes).unwrap();
    assert!(s.contains("<a b=\"&lt;A\">&amp;B</a>"), "{s}");
}

#[test]
fn root_and_namespace_checked() {
    assert_eq!(parse("<other/>"), Err(TemplateError::WrongRoot));
    assert_eq!(parse("<unattend/>"), Err(TemplateError::WrongRoot));
    assert_eq!(
        parse("<unattend xmlns=\"urn:other\"/>"),
        Err(TemplateError::WrongRoot)
    );
    assert!(parse(&format!("<u:unattend xmlns:u=\"{NS}\"/>")).is_ok());
}

#[test]
fn limits_enforced() {
    let small = Limits {
        max_bytes: 10,
        ..Limits::default()
    };
    assert_eq!(
        Template::parse(doc("").as_bytes(), &small),
        Err(TemplateError::TooLarge)
    );
    let deep = doc(&"<a>".repeat(64)).replace("</unattend>", &"</a>".repeat(64));
    let deep = format!("{deep}</unattend>");
    assert_eq!(parse(&deep), Err(TemplateError::TooDeep));
    let many = doc(&"<a/>".repeat(50_000));
    assert_eq!(parse(&many), Err(TemplateError::TooManyElements));
    let long = doc(&format!("<a b=\"{}\"/>", "x".repeat(64 * 1024 + 1)));
    assert_eq!(parse(&long), Err(TemplateError::AttributeTooLong));
}

#[test]
fn not_well_formed_refused() {
    for bad in [
        "",
        "<unattend",
        &doc("<a></b>"),
        &doc("</a>"),
        &format!("{}<x/>", doc("")),
        &format!("{}text", doc("")),
        &doc("&#0;"),
    ] {
        assert!(
            matches!(parse(bad), Err(TemplateError::NotWellFormed { .. })),
            "{bad}"
        );
    }
}

#[test]
fn reference_syntax() {
    assert_eq!(
        parse(&doc("<a>{{Bad}}</a>")),
        Err(TemplateError::BadReference)
    );
    assert_eq!(parse(&doc("<a>{{x</a>")), Err(TemplateError::BadReference));
    assert_eq!(parse(&doc("<a>{{}}</a>")), Err(TemplateError::BadReference));
    let long = format!("<a>{{{{a{}}}}}</a>", "b".repeat(64));
    assert_eq!(parse(&doc(&long)), Err(TemplateError::BadReference));
    // `{{{{` is a literal `{{`.
    let t = parse(&doc("<a x=\"{{{{y}}\">{{{{z}}</a>")).unwrap();
    assert!(t.references().is_empty());
    let s = String::from_utf8(t.render(&MapResolver::default()).unwrap().bytes).unwrap();
    assert!(s.contains("<a x=\"{{y}}\">{{z}}</a>"), "{s}");
}

#[test]
fn secret_bearing_settings_refused() {
    for el in [
        "<UserAccounts><AdministratorPassword><Value>x</Value></AdministratorPassword></UserAccounts>",
        "<UserAccounts><LocalAccounts><LocalAccount><Password><Value>x</Value></Password></LocalAccount></LocalAccounts></UserAccounts>",
        "<Identification><Credentials><Password>x</Password></Credentials></Identification>",
        "<ProductKey><Key>x</Key></ProductKey>",
        "<AutoLogon><Enabled>true</Enabled></AutoLogon>",
    ] {
        let t = parse(&doc(&format!(
            "<settings pass=\"oobeSystem\">{el}</settings>"
        )))
        .unwrap();
        let f = t.lint(&PackageValues::default());
        assert_eq!(f.len(), 1, "{el}: {f:?}");
        let LintFinding::SecretBearingSetting { path } = &f[0] else {
            panic!("{f:?}")
        };
        assert!(path.starts_with("unattend/settings[oobeSystem]/"), "{path}");
        assert!(!path.contains('x'));
    }
}

#[test]
fn reference_in_command_refused() {
    let t = parse(&doc(
        "<settings pass=\"specialize\"><RunSynchronous><RunSynchronousCommand><Path>cmd {{domain}}</Path></RunSynchronousCommand></RunSynchronous></settings>",
    ))
    .unwrap();
    let f = t.lint(&pv());
    assert!(f.contains(&LintFinding::ReferenceInCommand {
        path: "unattend/settings[specialize]/RunSynchronous".into()
    }));
}

#[test]
fn unknown_and_unreferenced_values() {
    let t = parse(&doc(
        "<settings pass=\"oobeSystem\"><ComputerName>{{computer_name}}</ComputerName><x>{{nope}}</x><y>{{device.}}</y></settings>",
    ))
    .unwrap();
    let f = t.lint(&pv());
    assert!(f.contains(&LintFinding::UnknownReference {
        name: "nope".into()
    }));
    assert!(f.contains(&LintFinding::UnknownReference {
        name: "device.".into()
    }));
    // computer_name is per device, so `{{computer_name}}` is unknown.
    assert!(f.contains(&LintFinding::UnknownReference {
        name: "computer_name".into()
    }));
    // ComputerName is in oobeSystem, not specialize.
    assert!(f.contains(&LintFinding::ValueNotReferenced {
        name: "computer_name"
    }));
    assert!(f.contains(&LintFinding::ValueNotReferenced { name: "time_zone" }));
}

#[test]
fn invalid_literal_package_values() {
    let t = parse(&doc(good_body())).unwrap();
    let mut v = pv();
    v.computer_name = Some(ComputerNameSource::Value("*".into()));
    v.time_zone = Some(String::new());
    let f = t.lint(&v);
    assert!(f.contains(&LintFinding::InvalidValue {
        name: "computer_name",
        reason: ValueError::Random
    }));
    assert!(f.contains(&LintFinding::InvalidValue {
        name: "time_zone",
        reason: ValueError::Empty
    }));
}

#[test]
fn render_unresolved_and_invalid() {
    let t = parse(&doc(good_body())).unwrap();
    let mut r = resolver();
    r.0.remove("domain");
    assert_eq!(
        t.render(&r),
        Err(RenderError::Unresolved {
            name: "domain".into()
        })
    );
    let mut r = resolver();
    r.0.insert("device.computer_name".into(), "12345".into());
    assert_eq!(
        t.render(&r),
        Err(RenderError::InvalidValue {
            name: "device.computer_name".into(),
            source: ValueError::AllDigits
        })
    );
}

#[test]
fn render_escapes_markup_in_values() {
    let t = parse(&doc("<a v=\"{{device.k}}\">{{device.k}}</a>")).unwrap();
    let mut m = BTreeMap::new();
    m.insert("device.k".into(), "</a><b a='1'>&\r\t\n".into());
    let out = t.render(&MapResolver(m)).unwrap();
    let s = String::from_utf8(out.bytes.clone()).unwrap();
    assert!(!s.contains("<b"), "{s}");
    // Re-parse keeps the structure: one `a` element, no `b`.
    let back = Template::parse(&out.bytes, &Limits::default());
    assert!(back.is_ok());
}

#[test]
fn render_too_large() {
    let lim = Limits {
        max_bytes: 300,
        ..Limits::default()
    };
    let t = Template::parse(doc("<a>{{device.k}}</a>").as_bytes(), &lim).unwrap();
    let mut m = BTreeMap::new();
    m.insert("device.k".into(), "x".repeat(400));
    assert_eq!(t.render(&MapResolver(m)), Err(RenderError::TooLarge));
}

#[test]
fn computer_name_rules() {
    assert_eq!(check_computer_name("PC-01"), Ok(()));
    assert_eq!(check_computer_name(""), Err(ValueError::Empty));
    assert_eq!(check_computer_name("*"), Err(ValueError::Random));
    assert_eq!(
        check_computer_name("ABCDEFGHIJKLMNOP"),
        Err(ValueError::TooLong)
    );
    for bad in ["A B", "A.B", "A_B", "A&B", "A{B", "Ä"] {
        assert_eq!(
            check_computer_name(bad),
            Err(ValueError::ForbiddenCharacter),
            "{bad}"
        );
    }
    assert_eq!(check_computer_name("-AB"), Err(ValueError::HyphenAtEnd));
    assert_eq!(check_computer_name("1234"), Err(ValueError::AllDigits));
}

#[test]
fn time_zone_and_tags() {
    assert_eq!(check_time_zone("UTC_dstoff"), Ok(()));
    assert_eq!(check_time_zone(&"x".repeat(257)), Err(ValueError::TooLong));
    assert_eq!(check_time_zone("a\nb"), Err(ValueError::ForbiddenCharacter));
    assert_eq!(check_tags(&["a", "b"]), Ok(()));
    assert_eq!(check_tags(&vec!["a"; 65]), Err(ValueError::TooManyTags));
    assert_eq!(check_tags(&[""]), Err(ValueError::Empty));
    assert_eq!(check_tags(&["x".repeat(129)]), Err(ValueError::TooLong));
    assert_eq!(check_tags(&["a\u{7}"]), Err(ValueError::ForbiddenCharacter));
}
