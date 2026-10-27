//! Message digests through the FIPS 140-3 validated module.
//!
//! SHA-256 is the integrity digest (content identity, chunk digests, audit
//! chain, key ids). SHA-1 exists only because the WIM format records SHA-1
//! hashes ([`LegacySha1Hasher`]); it detects accidental damage and is never
//! the basis of an SI-7 decision (plan M2 section 5.1, decision 0001).
//!
//! The SHA-256 result type is [`usgp_common::Sha256Digest`], a plain value
//! type with no crypto of its own, so callers can parse, compare and print
//! digests without linking a digest implementation.

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-13 (Cryptographic Protection) - digests computed only by
//   the FIPS 140-3 validated AWS-LC module (decision 0001).
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity) -
//   streaming SHA-256 for content verified chunk by chunk.
// - FIPS 180-4 §6.1 (SHA-1), §6.2 (SHA-256).
// - DECISION: docs/decisions/0001-fips-validated-crypto.md

use std::fmt;

use usgp_common::Sha256Digest;
use usgp_common::digest::SHA256_LEN;

/// Length of a SHA-1 digest in bytes (FIPS 180-4).
pub const SHA1_LEN: usize = 20;

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
    Sha256Digest(copy_out(d.as_ref()))
}

/// Copies a module digest into a fixed array. The module returns exactly
/// `N` bytes for the algorithms used here; `zip` never panics either way.
fn copy_out<const N: usize>(d: &[u8]) -> [u8; N] {
    debug_assert_eq!(d.len(), N);
    let mut out = [0u8; N];
    for (o, i) in out.iter_mut().zip(d) {
        *o = *i;
    }
    out
}

/// Streaming SHA-256 (FIPS 180-4).
///
/// Feeding the same bytes in any split gives the same digest as
/// [`crate::sha256`] over the concatenation.
pub struct Sha256Hasher(aws_lc_rs::digest::Context);

impl Sha256Hasher {
    /// A fresh hasher.
    #[must_use]
    pub fn new() -> Self {
        Self(aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256))
    }

    /// Adds `data` to the message.
    ///
    /// The module limits a message to 2^61 bytes; no input this product
    /// accepts comes near that (uploads are capped far below it).
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Finishes and returns the digest.
    #[must_use]
    pub fn finish(self) -> Sha256Digest {
        Sha256Digest(copy_out(self.0.finish().as_ref()))
    }
}

impl Default for Sha256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Sha256Hasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha256Hasher")
    }
}

/// A SHA-1 digest. Format compatibility only; see [`LegacySha1Hasher`].
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha1Digest(pub [u8; SHA1_LEN]);

impl Sha1Digest {
    /// Lowercase hex text form (40 characters).
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex_lower(&self.0)
    }
}

impl fmt::Debug for Sha1Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha1Digest({})", self.to_hex())
    }
}

impl fmt::Display for Sha1Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Streaming SHA-1 for formats that record SHA-1 hashes (WIM).
///
/// **Not a security control.** It detects accidental damage only
/// (REQ-IMG-051). Integrity decisions (SI-7) always use SHA-256 against a
/// signed manifest. SP 800-131A status of SHA-1 for non-signature use was
/// not read (OPEN-SB-3).
pub struct LegacySha1Hasher(aws_lc_rs::digest::Context);

impl LegacySha1Hasher {
    /// A fresh hasher.
    #[must_use]
    pub fn new() -> Self {
        Self(aws_lc_rs::digest::Context::new(
            &aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY,
        ))
    }

    /// Adds `data` to the message (module limit 2^61 bytes, as for SHA-256).
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Finishes and returns the digest.
    #[must_use]
    pub fn finish(self) -> Sha1Digest {
        Sha1Digest(copy_out(self.0.finish().as_ref()))
    }
}

impl Default for LegacySha1Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for LegacySha1Hasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LegacySha1Hasher")
    }
}

/// One-shot SHA-1 (format compatibility only; see [`LegacySha1Hasher`]).
#[must_use]
pub fn legacy_sha1(data: &[u8]) -> Sha1Digest {
    let mut h = LegacySha1Hasher::new();
    h.update(data);
    h.finish()
}

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        for nibble in [b >> 4, b & 0x0f] {
            let c = DIGITS.get(usize::from(nibble)).copied().unwrap_or(b'0');
            s.push(char::from(c));
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors: FIPS 180-4 / NIST CSRC "Cryptographic Standards and
    // Guidelines: Examples with Intermediate Values", SHA-256 and SHA-1
    // examples (SHA256.pdf, SHA1.pdf): one-block message "abc" and
    // two-block 448-bit message
    // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq". The empty
    // message digest is the published digest of the zero-length message
    // (NIST CAVP SHAVS byte-oriented short-message vectors, Len = 0).

    const MSG_448: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

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
        assert_eq!(MSG_448.len() * 8, 448);
        assert_eq!(
            hex(sha256_fips(MSG_448)),
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

    #[test]
    fn sha256_streaming_equals_one_shot_for_every_split() {
        let want = sha256_fips(MSG_448);
        for split in 0..=MSG_448.len() {
            let (a, b) = MSG_448.split_at(split);
            let mut h = Sha256Hasher::new();
            h.update(a);
            h.update(b);
            assert_eq!(h.finish(), want, "split at {split}");
        }
        // Byte at a time, and with empty updates mixed in.
        let mut h = Sha256Hasher::default();
        for byte in MSG_448 {
            h.update(&[]);
            h.update(std::slice::from_ref(byte));
        }
        assert_eq!(h.finish(), want);
    }

    #[test]
    fn sha1_fips_180_4_vectors() {
        assert_eq!(
            legacy_sha1(b"abc").to_hex(),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            legacy_sha1(MSG_448).to_hex(),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        assert_eq!(
            legacy_sha1(b"").to_hex(),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }

    #[test]
    fn sha1_streaming_equals_one_shot() {
        let want = legacy_sha1(MSG_448);
        for split in 0..=MSG_448.len() {
            let (a, b) = MSG_448.split_at(split);
            let mut h = LegacySha1Hasher::new();
            h.update(a);
            h.update(b);
            assert_eq!(h.finish(), want, "split at {split}");
        }
    }

    #[test]
    fn hex_lower_formats() {
        assert_eq!(hex_lower(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
        assert_eq!(hex_lower(&[]), "");
    }
}
