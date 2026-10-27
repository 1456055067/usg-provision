//! "Does this refused certificate chain to one of our trust anchors?"
//!
//! Used only to classify a refused client certificate for the audit
//! budget (finding SEC-012 / NIST-014): a certificate whose signature path
//! leads to a configured anchor was issued by our PKI (it may be revoked,
//! expired, of the wrong purpose, ...), while a self-made certificate or
//! one from a foreign issuer can be produced by anyone. The answer never
//! grants anything: authentication is the WebPKI verifier's job.
//!
//! The probe checks names and signatures only (issuer name equals the
//! parent's subject name, byte for byte, and the parent's key verifies
//! the child's signature) with the provider's restricted verification
//! algorithms. Validity periods, key usage, extended key usage, basic
//! constraints and revocation are deliberately not checked: those are the
//! failures we want to keep on the credential budget. Work is bounded:
//! at most [`MAX_INTERMEDIATES`] presented intermediates are considered,
//! the path is at most [`MAX_DEPTH`] certificates above the end entity,
//! and at most [`MAX_SIGNATURE_CHECKS`] signatures are verified per probe
//! (no backtracking).

// COMPLIANCE MAPPING:
// - NIST 800-53: AU-2, AU-12, AC-7 - refused certificates from our own
//   PKI keep their individual audit records on the credential budget;
//   self-made certificates cannot use it up.
// - NIST 800-53: SI-10 (Information Input Validation) - bounded DER walk
//   of attacker-supplied certificates; no panics on input.
// - NIST 800-53: SC-13 - signatures verified with the FIPS provider's
//   algorithms only.
// - RFC 5280 §4.1 (certificate structure), §6.1.3 (a)(1), (a)(4)
//   (signature and issuer name checks, subset).

use rustls::crypto::WebPkiSupportedAlgorithms;

/// Most presented intermediates considered.
pub(crate) const MAX_INTERMEDIATES: usize = 8;
/// Most certificates in the path above the end entity, anchor excluded.
pub(crate) const MAX_DEPTH: usize = 5;
/// Most signature verifications per probe.
pub(crate) const MAX_SIGNATURE_CHECKS: usize = 8;

/// The parts of a certificate the probe needs (borrowed from its DER).
#[derive(Debug, Clone, Copy)]
struct Parts<'a> {
    /// The whole tbsCertificate TLV (the signed message).
    tbs: &'a [u8],
    /// Contents of the outer signatureAlgorithm SEQUENCE.
    sig_alg: &'a [u8],
    /// The signature value (BIT STRING with no unused bits).
    signature: &'a [u8],
    /// The issuer Name TLV.
    issuer: &'a [u8],
    /// The subject Name TLV.
    subject: &'a [u8],
    /// Contents of the subjectPublicKeyInfo algorithm SEQUENCE.
    spki_alg: &'a [u8],
    /// The subjectPublicKey value.
    spki_key: &'a [u8],
}

/// A configured trust anchor's name and key (owned).
#[derive(Debug, Clone)]
pub(crate) struct Anchor {
    subject: Vec<u8>,
    spki_alg: Vec<u8>,
    spki_key: Vec<u8>,
}

impl Anchor {
    /// The anchor's subject and key from its certificate DER; `None` if it
    /// does not have the X.509 structure.
    pub(crate) fn from_der(der: &[u8]) -> Option<Self> {
        let p = parse(der)?;
        Some(Self {
            subject: p.subject.to_vec(),
            spki_alg: p.spki_alg.to_vec(),
            spki_key: p.spki_key.to_vec(),
        })
    }
}

/// True if `end_entity` (with the presented `intermediates`) has a
/// signature path to one of `anchors`. False on any parse failure.
pub(crate) fn chains_to_anchor(
    anchors: &[Anchor],
    algs: &WebPkiSupportedAlgorithms,
    end_entity: &[u8],
    intermediates: &[&[u8]],
) -> bool {
    let Some(mut current) = parse(end_entity) else {
        return false;
    };
    let candidates: Vec<Parts<'_>> = intermediates
        .iter()
        .take(MAX_INTERMEDIATES)
        .filter_map(|d| parse(d))
        .collect();
    let mut checks = 0usize;
    let mut verify = |child: &Parts<'_>, alg: &[u8], key: &[u8]| -> bool {
        if checks >= MAX_SIGNATURE_CHECKS {
            return false;
        }
        checks = checks.saturating_add(1);
        signed_by(algs, child, alg, key)
    };
    for _ in 0..=MAX_DEPTH {
        for anchor in anchors.iter().filter(|a| a.subject == current.issuer) {
            if verify(&current, &anchor.spki_alg, &anchor.spki_key) {
                return true;
            }
        }
        let next = candidates
            .iter()
            .find(|c| c.subject == current.issuer && verify(&current, c.spki_alg, c.spki_key));
        match next {
            Some(n) => current = *n,
            None => return false,
        }
    }
    false
}

/// True if `child`'s signature verifies under the key (`key_alg`, `key`)
/// with an algorithm the provider allows.
fn signed_by(
    algs: &WebPkiSupportedAlgorithms,
    child: &Parts<'_>,
    key_alg: &[u8],
    key: &[u8],
) -> bool {
    algs.all.iter().any(|alg| {
        let sig_id = alg.signature_alg_id();
        let key_id = alg.public_key_alg_id();
        let sig_id: &[u8] = &sig_id;
        let key_id: &[u8] = &key_id;
        sig_id == child.sig_alg
            && key_id == key_alg
            && alg
                .verify_signature(key, child.tbs, child.signature)
                .is_ok()
    })
}

const SEQUENCE: u8 = 0x30;
const BIT_STRING: u8 = 0x03;
const INTEGER: u8 = 0x02;
const VERSION_TAG: u8 = 0xa0;

/// One DER TLV: tag, the whole TLV, its value, and what follows.
struct Tlv<'a> {
    tag: u8,
    whole: &'a [u8],
    value: &'a [u8],
    rest: &'a [u8],
}

/// Reads one TLV with a single-octet tag and a definite length of at most
/// four length octets.
fn tlv(input: &[u8]) -> Option<Tlv<'_>> {
    let (&tag, after_tag) = input.split_first()?;
    if tag & 0x1f == 0x1f {
        return None; // high tag number form: never in a certificate
    }
    let (&first, mut after_len) = after_tag.split_first()?;
    let len = if first < 0x80 {
        usize::from(first)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return None;
        }
        let (octets, rest) = after_len.split_at_checked(n)?;
        after_len = rest;
        octets.iter().try_fold(0usize, |acc, &b| {
            acc.checked_mul(256)?.checked_add(usize::from(b))
        })?
    };
    let (value, rest) = after_len.split_at_checked(len)?;
    let header_len = input.len().checked_sub(after_len.len())?;
    let whole = input.get(..header_len.checked_add(len)?)?;
    Some(Tlv {
        tag,
        whole,
        value,
        rest,
    })
}

/// Reads one TLV that must have `tag`.
fn expect(input: &[u8], tag: u8) -> Option<Tlv<'_>> {
    tlv(input).filter(|t| t.tag == tag)
}

/// The BIT STRING contents with no unused bits.
fn bit_string_bytes(value: &[u8]) -> Option<&[u8]> {
    match value.split_first() {
        Some((0, bytes)) => Some(bytes),
        _ => None,
    }
}

/// The parts of a DER certificate (RFC 5280 §4.1), or `None`.
fn parse(der: &[u8]) -> Option<Parts<'_>> {
    let outer = expect(der, SEQUENCE)?;
    if !outer.rest.is_empty() {
        return None;
    }
    let tbs = expect(outer.value, SEQUENCE)?;
    let sig_alg = expect(tbs.rest, SEQUENCE)?;
    let sig = expect(sig_alg.rest, BIT_STRING)?;
    if !sig.rest.is_empty() {
        return None;
    }
    // tbsCertificate: [0] version OPTIONAL, serial, signature, issuer,
    // validity, subject, subjectPublicKeyInfo, ...
    let mut body = tbs.value;
    if let Some(v) = tlv(body).filter(|t| t.tag == VERSION_TAG) {
        body = v.rest;
    }
    let serial = expect(body, INTEGER)?;
    let inner_sig = expect(serial.rest, SEQUENCE)?;
    let issuer = expect(inner_sig.rest, SEQUENCE)?;
    let validity = expect(issuer.rest, SEQUENCE)?;
    let subject = expect(validity.rest, SEQUENCE)?;
    let spki = expect(subject.rest, SEQUENCE)?;
    let spki_alg = expect(spki.value, SEQUENCE)?;
    let spki_key = expect(spki_alg.rest, BIT_STRING)?;
    Some(Parts {
        tbs: tbs.whole,
        sig_alg: sig_alg.value,
        signature: bit_string_bytes(sig.value)?,
        issuer: issuer.whole,
        subject: subject.whole,
        spki_alg: spki_alg.value,
        spki_key: bit_string_bytes(spki_key.value)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlv_rejects_truncation_and_long_lengths() {
        assert!(tlv(&[]).is_none());
        assert!(tlv(&[0x30]).is_none());
        assert!(tlv(&[0x30, 0x02, 0x00]).is_none(), "value too short");
        assert!(
            tlv(&[0x30, 0x85, 1, 1, 1, 1, 1]).is_none(),
            "5 length octets"
        );
        assert!(tlv(&[0x30, 0x80]).is_none(), "indefinite length");
        assert!(tlv(&[0x1f, 0x01, 0x00]).is_none(), "high tag number");
        let t = tlv(&[0x30, 0x81, 0x01, 0xaa, 0xbb]).unwrap();
        assert_eq!(t.value, &[0xaa]);
        assert_eq!(t.whole, &[0x30, 0x81, 0x01, 0xaa]);
        assert_eq!(t.rest, &[0xbb]);
    }

    #[test]
    fn garbage_never_chains() {
        let algs = super::super::tls_provider()
            .unwrap()
            .signature_verification_algorithms;
        for input in [&b""[..], b"\x30\x00", b"\x30\x03\x30\x01\x00", &[0xff; 64]] {
            assert!(parse(input).is_none());
            assert!(!chains_to_anchor(&[], &algs, input, &[input]));
        }
    }
}
