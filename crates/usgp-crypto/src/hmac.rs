//! HMAC-SHA-256 keys and tags, and constant-time comparison.
//!
//! The server stores operator-issued session codes as HMAC-SHA-256 under a
//! code key and looks them up by that value (plan M3 section 5, "Codes"),
//! so a database read never reveals a usable code. Keys live inside the
//! validated module ([`HmacKey`]); the module wipes its key state when the
//! value is dropped, and every key buffer of ours is [`Zeroizing`].
//!
//! Key length rules:
//!
//! - [`HmacKey::from_key_file`] is the production loader: exactly
//!   [`HMAC_KEY_FILE_LEN`] (32) raw bytes, the length
//!   [`HmacKey::generate_key_bytes`] produces (plan M3 section 3.9,
//!   `[codes] hmac_key`, "32 bytes").
//! - [`HmacKey::from_bytes`] accepts [`MIN_HMAC_KEY_LEN`] to
//!   [`MAX_HMAC_KEY_LEN`] bytes. The minimum is 112 bits, the smallest
//!   HMAC key length SP 800-131A Rev 2 §8 permits for generation; shorter
//!   keys are refused (fail closed).
//!
//! Tag comparison is constant time ([`HmacKey::verify`], [`ct_eq`] and
//! [`HmacTag`]'s `PartialEq`).

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-13 (Cryptographic Protection) - HMAC-SHA-256
//   (FIPS 198-1, FIPS 180-4) computed only in the FIPS 140-3 validated
//   module.
// - NIST 800-53: SC-12 (Cryptographic Key Establishment and Management) -
//   keys generated from the module DRBG; key buffers zeroized; key state
//   cleansed by the module on drop; Debug redacted.
// - NIST 800-53: IA-5 (Authenticator Management) - session codes are kept
//   only as keyed digests; comparison in constant time.
// - NIST 800-53: SI-10 (Information Input Validation) - key lengths
//   checked before use.
// - SPEC: specs/targeting.md#REQ-TGT-013; plan M3 section 5 ("Codes"),
//   section 3.9 ([codes]); decisions 0001, 0011, 0018 item 1, 0020.
// - RFC 2104 §2-3 (HMAC, key length); RFC 4231 (HMAC-SHA-256 test
//   vectors); SP 800-131A Rev 2 §8 (112-bit minimum HMAC key).

use std::fmt;

use aws_lc_rs::hmac;
use zeroize::Zeroizing;

use crate::CryptoError;

/// Length of an HMAC-SHA-256 tag in bytes.
pub const HMAC_SHA256_LEN: usize = 32;

/// Length of a key file ([`HmacKey::from_key_file`]) in bytes.
pub const HMAC_KEY_FILE_LEN: usize = 32;

/// Shortest key [`HmacKey::from_bytes`] accepts (112 bits,
/// SP 800-131A Rev 2 §8).
pub const MIN_HMAC_KEY_LEN: usize = 14;

/// Longest key [`HmacKey::from_bytes`] accepts. Keys above the SHA-256
/// block size (64 bytes) are hashed first (RFC 2104 §2); the bound only
/// stops an absurd input.
pub const MAX_HMAC_KEY_LEN: usize = 1024;

/// An HMAC-SHA-256 key held inside the validated module.
///
/// `Debug` never prints key material.
pub struct HmacKey {
    key: hmac::Key,
}

impl HmacKey {
    /// Loads a key of [`MIN_HMAC_KEY_LEN`] to [`MAX_HMAC_KEY_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// [`CryptoError::KeyRejected`] if the length is outside that range.
    /// The error never contains key bytes.
    pub fn from_bytes(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() < MIN_HMAC_KEY_LEN {
            return Err(CryptoError::KeyRejected {
                reason: "HMAC key shorter than 112 bits",
            });
        }
        if key.len() > MAX_HMAC_KEY_LEN {
            return Err(CryptoError::KeyRejected {
                reason: "HMAC key longer than the limit",
            });
        }
        // The module copies the key into its own context (inner and outer
        // pads), which it cleanses on drop.
        Ok(Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, key),
        })
    }

    /// Loads the contents of a key file: exactly [`HMAC_KEY_FILE_LEN`]
    /// raw bytes, no framing and no trailing newline.
    ///
    /// The caller reads the file under its trusted-file rules into a
    /// [`Zeroizing`] buffer.
    ///
    /// # Errors
    ///
    /// [`CryptoError::KeyRejected`] if the length is not exactly
    /// [`HMAC_KEY_FILE_LEN`].
    pub fn from_key_file(contents: &Zeroizing<Vec<u8>>) -> Result<Self, CryptoError> {
        if contents.len() != HMAC_KEY_FILE_LEN {
            return Err(CryptoError::KeyRejected {
                reason: "HMAC key file must hold exactly 32 bytes",
            });
        }
        Self::from_bytes(contents)
    }

    /// Fresh key-file contents ([`HMAC_KEY_FILE_LEN`] bytes) from the
    /// module DRBG, for `keygen`. Load them with
    /// [`Self::from_key_file`].
    ///
    /// # Errors
    ///
    /// [`CryptoError::Random`] if the DRBG fails.
    pub fn generate_key_bytes() -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let mut bytes = Zeroizing::new(vec![0u8; HMAC_KEY_FILE_LEN]);
        crate::rand::fill_random(&mut bytes)?;
        Ok(bytes)
    }

    /// HMAC-SHA-256 of `data` under this key.
    #[must_use]
    pub fn sign(&self, data: &[u8]) -> HmacTag {
        let tag = hmac::sign(&self.key, data);
        let mut out = [0u8; HMAC_SHA256_LEN];
        // The module returns exactly 32 bytes for HMAC-SHA-256; `zip`
        // never panics either way.
        for (o, i) in out.iter_mut().zip(tag.as_ref()) {
            *o = *i;
        }
        HmacTag(out)
    }

    /// Checks `tag` against HMAC-SHA-256 of `data`, in constant time with
    /// respect to the tag contents.
    ///
    /// # Errors
    ///
    /// [`CryptoError::MacInvalid`] if the tag does not match, including a
    /// tag of the wrong length. No detail is given on purpose.
    pub fn verify(&self, data: &[u8], tag: &[u8]) -> Result<(), CryptoError> {
        hmac::verify(&self.key, data, tag).map_err(|_| CryptoError::MacInvalid)
    }
}

impl fmt::Debug for HmacKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HmacKey")
            .field("alg", &"hmac-sha256")
            .field("key", &"<redacted>")
            .finish()
    }
}

/// HMAC-SHA-256 of `data` under `key` (FIPS 198-1).
#[must_use]
pub fn hmac_sha256(key: &HmacKey, data: &[u8]) -> HmacTag {
    key.sign(data)
}

/// An HMAC-SHA-256 tag.
///
/// Equality is constant time ([`ct_eq`]). A tag is a keyed digest, not a
/// secret, so it may be stored and printed (for example as a database
/// lookup value).
#[derive(Clone, Copy, Eq)]
pub struct HmacTag([u8; HMAC_SHA256_LEN]);

impl HmacTag {
    /// The tag bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; HMAC_SHA256_LEN] {
        &self.0
    }

    /// Lowercase hex text form (64 characters).
    #[must_use]
    pub fn to_hex(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(HMAC_SHA256_LEN * 2);
        for b in self.0 {
            // Writing to a String cannot fail.
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// Builds a tag from stored bytes (for example a database column).
    ///
    /// # Errors
    ///
    /// [`CryptoError::MacInvalid`] unless `bytes` is exactly
    /// [`HMAC_SHA256_LEN`] bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, CryptoError> {
        <[u8; HMAC_SHA256_LEN]>::try_from(bytes)
            .map(Self)
            .map_err(|_| CryptoError::MacInvalid)
    }
}

impl PartialEq for HmacTag {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(&self.0, &other.0)
    }
}

impl AsRef<[u8]> for HmacTag {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for HmacTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HmacTag({})", self.to_hex())
    }
}

/// Compares two byte strings in constant time with respect to their
/// contents (the module's `CRYPTO_memcmp`).
///
/// Strings of different lengths are unequal at once: lengths are treated
/// as public.
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    aws_lc_rs::constant_time::verify_slices_are_equal(a, b).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_basic() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(!ct_eq(b"", b"a"));
    }

    #[test]
    fn length_bounds() {
        assert!(HmacKey::from_bytes(&[7u8; MIN_HMAC_KEY_LEN]).is_ok());
        assert!(HmacKey::from_bytes(&[7u8; MAX_HMAC_KEY_LEN]).is_ok());
        assert!(matches!(
            HmacKey::from_bytes(&[7u8; MIN_HMAC_KEY_LEN - 1]),
            Err(CryptoError::KeyRejected { .. })
        ));
        assert!(matches!(
            HmacKey::from_bytes(&[7u8; MAX_HMAC_KEY_LEN + 1]),
            Err(CryptoError::KeyRejected { .. })
        ));
        assert!(HmacKey::from_bytes(&[]).is_err());
    }
}
