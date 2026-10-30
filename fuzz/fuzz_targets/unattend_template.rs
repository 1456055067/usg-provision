//! Fuzz target `unattend_template`: answer-file template bytes
//! (`usgp-wincfg` `unattend::Template::parse`, `references`, `lint`,
//! `render`).
//!
//! Invariants:
//!
//! - no panic; `TooLarge` exactly over the byte limit;
//! - tighter limits never accept a template the defaults refuse, and an
//!   accepted template parses the same under both;
//! - `references` is sorted and unique; `lint` is deterministic and, with
//!   no package values, reports every reference not of the `device.` form
//!   as unknown;
//! - render with no values fails on the first reference in name order,
//!   or succeeds when there are none;
//! - render with a valid value for every reference (values chosen to need
//!   XML escaping) never fails its own self-check, stays within the byte
//!   limit, is deterministic, and (unless the template uses the `{{{{`
//!   escape for a literal `{{`) the result parses again as a template
//!   with no references left.

#![no_main]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), IA-5(7), CM-6, SA-11
// - SPEC: specs/configuration.md#REQ-CFG-002 to #REQ-CFG-007
// - W3C XML 1.0 (Fifth Edition)

use std::collections::BTreeMap;

use libfuzzer_sys::fuzz_target;
use usgp_wincfg::unattend::{
    Limits, LintFinding, MapResolver, PackageValues, RenderError, Template, TemplateError,
};

fn tight() -> Limits {
    Limits {
        max_bytes: 16 * 1024,
        max_depth: 8,
        max_elements: 64,
        max_attr_value_bytes: 64,
    }
}

fn value_for(name: &str) -> &'static str {
    match name {
        "computer_name" | "device.computer_name" => "LAB-PC01",
        "time_zone" => "Eastern Standard Time",
        _ => r#"OU="a&b <c>",DC='x'"#,
    }
}

fuzz_target!(|data: &[u8]| {
    let lim = Limits::default();
    let t = Template::parse(data, &lim);
    if data.len() > lim.max_bytes {
        assert_eq!(t, Err(TemplateError::TooLarge));
        return;
    }
    assert_ne!(t, Err(TemplateError::TooLarge), "too large under the limit");
    if let Ok(small) = Template::parse(data, &tight()) {
        let t = t.as_ref().expect("tight limits accept more");
        assert_eq!(
            small.references(),
            t.references(),
            "limits change the parse"
        );
    }
    let Ok(t) = t else {
        return;
    };

    let refs = t.references();
    assert!(
        refs.windows(2).all(|w| w[0] < w[1]),
        "references not sorted and unique"
    );
    let findings = t.lint(&PackageValues::default());
    assert_eq!(
        findings,
        t.lint(&PackageValues::default()),
        "lint not deterministic"
    );
    for r in &refs {
        if !r.starts_with("device.") || r.len() == "device.".len() {
            assert!(
                findings.contains(&LintFinding::UnknownReference { name: r.clone() }),
                "unknown reference not reported"
            );
        }
    }

    match (t.render(&MapResolver::default()), refs.first()) {
        (Err(RenderError::Unresolved { name }), Some(first)) => assert_eq!(&name, first),
        (Ok(_), None) => {}
        (r, f) => panic!("empty resolver: {r:?} with first reference {f:?}"),
    }

    let map: BTreeMap<String, String> = refs
        .iter()
        .map(|r| (r.clone(), value_for(r).to_owned()))
        .collect();
    let resolver = MapResolver(map);
    match t.render(&resolver) {
        Ok(out) => {
            assert!(out.bytes.len() <= lim.max_bytes, "rendered over the limit");
            assert_eq!(
                t.render(&resolver).ok(),
                Some(out.clone()),
                "render not deterministic"
            );
            // `{{{{` is the escape for a literal `{{`, which the output then
            // carries; without it, the output is a template with no references.
            if !data.windows(4).any(|w| w == b"{{{{") {
                let again = Template::parse(&out.bytes, &lim).expect("rendered output parses");
                assert!(again.references().is_empty(), "reference left after render");
            }
        }
        Err(RenderError::TooLarge) => {}
        Err(e) => panic!("render with valid values failed: {e:?}"),
    }
});
