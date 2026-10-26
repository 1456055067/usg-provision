//! Message digests through the FIPS 140-3 validated module.
//!
//! M1 needs SHA-256 only (plan section 5). The result type is
//! [`usgp_common::Sha256Digest`], a plain value type with no crypto of its
//! own, so callers can parse, compare and print digests without linking a
//! digest implementation.

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-13 (Cryptographic Protection) - SHA-256 computed only by
//   the FIPS 140-3 validated AWS-LC module (decision 0001).
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity) -
//   digest used to verify boot content before serving.
// - FIPS 180-4 §6.2 - SHA-256.
// - DECISION: docs/decisions/0001-fips-validated-crypto.md

use usgp_common::Sha256Digest;
use usgp_common::digest::SHA256_LEN;

/// Digest algorithms offered by the provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DigestAlgorithm {
    /// SHA-256 (FIPS 180-4).
    Sha256,
}

impl DigestAlgorithm {
    /// Output length in bytes.
    #[must_use]
    pub const fn output_len(self) -> usize {
        match self {
            Self::Sha256 => SHA256_LEN,
        }
    }
}

/// SHA-256 of `data` through the validated module.
pub(crate) fn sha256_fips(data: &[u8]) -> Sha256Digest {
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data);
    let mut out = [0u8; SHA256_LEN];
    // The module returns exactly 32 bytes for SHA-256; zip never panics.
    debug_assert_eq!(d.as_ref().len(), SHA256_LEN);
    for (o, i) in out.iter_mut().zip(d.as_ref()) {
        *o = *i;
    }
    Sha256Digest(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors: FIPS 180-4 / NIST CSRC "Cryptographic Standards and
    // Guidelines: Examples with Intermediate Values", SHA-256 examples
    // (SHA256.pdf): one-block message "abc" and two-block 448-bit message
    // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq". The empty
    // message digest is the published SHA-256 of the zero-length message
    // (NIST CAVP SHAVS byte-oriented short-message vectors, Len = 0).

    fn hex(d: Sha256Digest) -> String {
        d.to_hex()
    }

    #[test]
    fn fips_180_4_abc() {
        assert_eq!(
            hex(sha256_fips(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn fips_180_4_empty() {
        assert_eq!(
            hex(sha256_fips(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn fips_180_4_448_bit() {
        let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        assert_eq!(msg.len() * 8, 448);
        assert_eq!(
            hex(sha256_fips(msg)),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn one_byte_change_changes_digest() {
        let a = sha256_fips(b"payload-0");
        let b = sha256_fips(b"payload-1");
        assert_ne!(a, b);
    }

    #[test]
    fn algorithm_len() {
        assert_eq!(DigestAlgorithm::Sha256.output_len(), 32);
    }
}
