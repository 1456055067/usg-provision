//! Fuzz target `wim_xml`: arbitrary bytes as the WIM XML data resource
//! (UTF-16LE with a byte-order mark).
//!
//! The bytes go through `parse_xml` under the default limits and under
//! tight limits; if they are also valid UTF-8 they go through
//! `parse_xml_str` as text, which lets the fuzzer mutate markup directly.
//! Invariants (plan WU-9, §10):
//!
//! - no panic, and every refusal carries a listed reason code;
//! - `parse_xml` equals `decode_utf16` followed by `parse_xml_str`, and an
//!   accepted resource starts with the BOM, has even length and
//!   re-encodes byte for byte;
//! - an accepted result keeps every limit: image count, elements per
//!   image, text length of every element; indexes are at least 1 and
//!   strictly increasing; `NAME` and `DESCRIPTION` match their leaves;
//! - tightening a limit never turns a refusal into an acceptance: what
//!   the tight limits accept, the defaults accept with the same result.

#![no_main]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), SA-11 (Developer
//   Testing and Evaluation)
// - SPEC: specs/os-images.md#REQ-IMG-037 (name and description readable),
//   #REQ-IMG-022 (each refusal names its reason)
// - SPEC: specs/standards/wim.md §6 (XML data)
// - DECISION: docs/decisions/0006-wim-format-by-black-box-test-files.md

use libfuzzer_sys::fuzz_target;
use usgp_image::wim::xml::{BOM, WimXml, decode_utf16, encode_utf16, parse_xml, parse_xml_str};
use usgp_image::{WimError, WimLimits};

const TIGHT: WimLimits = WimLimits {
    max_xml_bytes: 4096,
    max_images: 2,
    max_name_chars: 8,
    max_xml_depth: 4,
    max_xml_elements_per_image: 4,
    ..WimLimits::DEFAULT
};

fn assert_listed(e: &WimError) {
    let code = e.reason_code();
    assert!(
        WimError::REASON_CODES.contains(&code),
        "unlisted reason code {code}"
    );
    assert!(!e.operator_message().is_empty(), "empty operator message");
}

fn check_accepted(x: &WimXml, limits: &WimLimits) {
    assert!(
        x.images.len() <= limits.max_images as usize,
        "too many images"
    );
    let mut last = 0u32;
    for img in &x.images {
        assert!(img.index >= 1, "index 0 accepted");
        assert!(img.index > last, "indexes not strictly increasing");
        last = img.index;
        assert!(
            img.elements.len() <= limits.max_xml_elements_per_image,
            "too many elements"
        );
        for leaf in &img.elements {
            assert!(
                leaf.text.chars().count() <= limits.max_name_chars,
                "element text over the limit"
            );
            assert!(!leaf.text.contains('\0'), "NUL in element text");
        }
        assert!(img.name.chars().count() <= limits.max_name_chars);
        assert!(img.description.chars().count() <= limits.max_name_chars);
        assert_eq!(img.leaf("NAME"), Some(img.name.as_str()), "NAME leaf");
        if let Some(d) = img.leaf("DESCRIPTION") {
            assert_eq!(d, img.description, "DESCRIPTION leaf");
        } else {
            assert!(img.description.is_empty(), "description without a leaf");
        }
    }
}

/// Parses `bytes` under `limits` and checks the invariants.
fn run_bytes(bytes: &[u8], limits: &WimLimits) -> Result<WimXml, WimError> {
    let got = parse_xml(bytes, limits);
    let two_step = decode_utf16(bytes, limits).and_then(|t| {
        assert!(bytes.len() as u64 <= limits.max_xml_bytes, "over the limit");
        assert!(bytes.starts_with(&BOM), "decoded without a BOM");
        assert_eq!(bytes.len() % 2, 0, "decoded an odd length");
        assert_eq!(encode_utf16(&t), bytes, "UTF-16 does not re-encode");
        parse_xml_str(&t, limits)
    });
    assert_eq!(got, two_step, "parse_xml differs from decode + parse");
    match &got {
        Ok(x) => check_accepted(x, limits),
        Err(e) => assert_listed(e),
    }
    got
}

fn run_text(text: &str, limits: &WimLimits) -> Result<WimXml, WimError> {
    let got = parse_xml_str(text, limits);
    match &got {
        Ok(x) => check_accepted(x, limits),
        Err(e) => assert_listed(e),
    }
    got
}

fuzz_target!(|data: &[u8]| {
    let wide = run_bytes(data, &WimLimits::DEFAULT);
    if let Ok(tight) = run_bytes(data, &TIGHT) {
        assert_eq!(wide.as_ref().ok(), Some(&tight), "tight accepted more");
    }
    if let Ok(text) = std::str::from_utf8(data) {
        let wide = run_text(text, &WimLimits::DEFAULT);
        if let Ok(tight) = run_text(text, &TIGHT) {
            assert_eq!(wide.as_ref().ok(), Some(&tight), "tight accepted more");
        }
    }
});
