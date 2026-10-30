//! Bounded base64 byte strings and the P-384 public key form (M4 plan WU-4).
//!
//! [`B64Bytes`] is a byte string carried as padded base64 (RFC 4648 §4)
//! whose decoded length must lie in `MIN..=MAX`; the text length is checked
//! before anything is decoded. `Debug` shows only the length, so a
//! ciphertext or signature never reaches a log through `{:?}`.
//!
//! [`P384Spki`] is a P-384 public key as an X.509 SubjectPublicKeyInfo
//! (RFC 5280 §4.1.2.7) in the one DER form RFC 5480 §2 gives for an
//! uncompressed point on `secp384r1`. Only the structure is checked here;
//! this crate does no cryptography (the point is checked by `usgp-crypto`).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - length checked
//   before decoding; exact DER prefix for keys.
// - NIST 800-53: SC-12 (Cryptographic Key Establishment and Management,
//   basis) - one public key form for the job and escrow keys.
// - RFC 4648 §4 (base64), RFC 5280 §4.1.2.7 (SPKI), RFC 5480 §2
//   (ecPublicKey, secp384r1, uncompressed point)

use std::fmt;

use base64ct::{Base64, Encoding};

/// Why a base64 value was refused. The text is never echoed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum B64Error {
    /// Not padded base64.
    #[error("value is not padded base64")]
    NotBase64,
    /// The decoded length is outside the allowed range.
    #[error("decoded value must be {min} to {max} bytes")]
    BadLength {
        /// Smallest length.
        min: usize,
        /// Largest length.
        max: usize,
    },
    /// The bytes are not a P-384 SubjectPublicKeyInfo of the expected form.
    #[error("value is not a P-384 SubjectPublicKeyInfo with an uncompressed point")]
    NotP384Spki,
}

/// Longest padded base64 text for `max` bytes.
const fn max_text_len(max: usize) -> usize {
    max.div_ceil(3).saturating_mul(4)
}

fn decode_bounded(text: &str, min: usize, max: usize) -> Result<Vec<u8>, B64Error> {
    if text.len() > max_text_len(max) {
        return Err(B64Error::BadLength { min, max });
    }
    let bytes = Base64::decode_vec(text).map_err(|_| B64Error::NotBase64)?;
    if bytes.len() < min || bytes.len() > max {
        return Err(B64Error::BadLength { min, max });
    }
    Ok(bytes)
}

/// A byte string of `MIN` to `MAX` bytes, padded base64 on the wire.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct B64Bytes<const MIN: usize, const MAX: usize>(Vec<u8>);

impl<const MIN: usize, const MAX: usize> B64Bytes<MIN, MAX> {
    /// Wraps bytes.
    ///
    /// # Errors
    ///
    /// [`B64Error::BadLength`] outside `MIN..=MAX`.
    pub fn new(bytes: Vec<u8>) -> Result<Self, B64Error> {
        if bytes.len() < MIN || bytes.len() > MAX {
            return Err(B64Error::BadLength { min: MIN, max: MAX });
        }
        Ok(Self(bytes))
    }

    /// Parses padded base64.
    ///
    /// # Errors
    ///
    /// [`B64Error`].
    pub fn parse(text: &str) -> Result<Self, B64Error> {
        decode_bounded(text, MIN, MAX).map(Self)
    }

    /// The bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The bytes, owned.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl<const MIN: usize, const MAX: usize> fmt::Debug for B64Bytes<MIN, MAX> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "B64Bytes(<{} bytes>)", self.0.len())
    }
}

impl<const MIN: usize, const MAX: usize> serde::Serialize for B64Bytes<MIN, MAX> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&Base64::encode_string(&self.0))
    }
}

impl<'de, const MIN: usize, const MAX: usize> serde::Deserialize<'de> for B64Bytes<MIN, MAX> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<const A: usize, const B: usize>;

        impl<const A: usize, const B: usize> serde::de::Visitor<'_> for V<A, B> {
            type Value = B64Bytes<A, B>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("padded base64 of a bounded length")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<B64Bytes<A, B>, E> {
                B64Bytes::parse(v).map_err(E::custom)
            }
        }

        d.deserialize_str(V::<MIN, MAX>)
    }
}

/// Length of a P-384 SPKI in DER with an uncompressed point.
pub const P384_SPKI_LEN: usize = 120;

/// The fixed DER head of a P-384 SPKI (RFC 5480 §2): SEQUENCE (118) {
/// SEQUENCE (16) { OID id-ecPublicKey, OID secp384r1 }, BIT STRING (98,
/// no unused bits) } then the uncompressed point marker `0x04`.
const P384_SPKI_PREFIX: [u8; 24] = [
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04,
];

/// A P-384 public key, SPKI DER (120 bytes), padded base64 on the wire.
/// Its key id is the SHA-256 of these bytes (as for the plan key).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct P384Spki([u8; P384_SPKI_LEN]);

impl P384Spki {
    /// Checks the DER form.
    ///
    /// # Errors
    ///
    /// [`B64Error::NotP384Spki`].
    pub fn from_der(der: &[u8]) -> Result<Self, B64Error> {
        let arr: [u8; P384_SPKI_LEN] = der.try_into().map_err(|_| B64Error::NotP384Spki)?;
        if !arr.starts_with(&P384_SPKI_PREFIX) {
            return Err(B64Error::NotP384Spki);
        }
        Ok(Self(arr))
    }

    /// Parses padded base64 of the DER.
    ///
    /// # Errors
    ///
    /// [`B64Error`].
    pub fn parse(text: &str) -> Result<Self, B64Error> {
        let der = decode_bounded(text, P384_SPKI_LEN, P384_SPKI_LEN)?;
        Self::from_der(&der)
    }

    /// The DER bytes.
    #[must_use]
    pub const fn as_der(&self) -> &[u8; P384_SPKI_LEN] {
        &self.0
    }
}

impl fmt::Display for P384Spki {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&Base64::encode_string(&self.0))
    }
}

impl fmt::Debug for P384Spki {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "P384Spki({self})")
    }
}

impl serde::Serialize for P384Spki {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for P384Spki {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;

        impl serde::de::Visitor<'_> for V {
            type Value = P384Spki;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("padded base64 of a P-384 SubjectPublicKeyInfo")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<P384Spki, E> {
                P384Spki::parse(v).map_err(E::custom)
            }
        }

        d.deserialize_str(V)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A structurally valid SPKI (the point is not checked here).
    pub(crate) fn spki(fill: u8) -> P384Spki {
        let mut der = [fill; P384_SPKI_LEN];
        der[..24].copy_from_slice(&P384_SPKI_PREFIX);
        P384Spki::from_der(&der).unwrap()
    }

    #[test]
    fn bounded_bytes() {
        type T = B64Bytes<2, 4>;
        assert!(T::parse("AA==").is_err());
        assert_eq!(T::parse("AAA=").unwrap().as_bytes(), &[0, 0]);
        assert!(T::parse("AAAAAAA=").is_err());
        assert!(T::parse("AAAAAAAAAAAAAAAAAAAA").is_err());
        assert!(T::parse("!!!!").is_err());
        let v = T::new(vec![1, 2, 3]).unwrap();
        assert_eq!(format!("{v:?}"), "B64Bytes(<3 bytes>)");
        let j = serde_json::to_string(&v).unwrap();
        assert_eq!(serde_json::from_str::<T>(&j).unwrap(), v);
    }

    #[test]
    fn spki_form() {
        let k = spki(7);
        let j = serde_json::to_string(&k).unwrap();
        assert_eq!(serde_json::from_str::<P384Spki>(&j).unwrap(), k);
        let mut bad = *k.as_der();
        bad[23] = 0x02; // compressed point marker
        assert!(P384Spki::from_der(&bad).is_err());
        assert!(P384Spki::from_der(&bad[..119]).is_err());
        assert!(P384Spki::parse("AAAA").is_err());
    }
}
