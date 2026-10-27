//! Random bytes from the module's DRBG.
//!
//! Ids and nonces come from here (plan M2 section 5.1), never from an
//! operating-system or library generator outside the FIPS boundary.

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-13 (Cryptographic Protection) - random bits from the
//   validated module's DRBG (SP 800-90A inside AWS-LC FIPS).
// - DECISION: docs/decisions/0001-fips-validated-crypto.md

use crate::CryptoError;

/// Fills `buf` with random bytes from the validated module.
///
/// # Errors
///
/// [`CryptoError::Random`] if the DRBG fails. Callers must treat that as
/// fatal for the operation (fail closed).
pub fn fill_random(buf: &mut [u8]) -> Result<(), CryptoError> {
    aws_lc_rs::rand::fill(buf).map_err(|_| CryptoError::Random)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_and_differs() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill_random(&mut a).unwrap();
        fill_random(&mut b).unwrap();
        // 2^-256 chance of a false failure.
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn empty_buffer_is_ok() {
        fill_random(&mut []).unwrap();
    }
}
