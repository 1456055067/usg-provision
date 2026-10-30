//! Random bytes from the module's DRBG.
//!
//! Ids and nonces come from here (plan M2 section 5.1), never from an
//! operating-system or library generator outside the FIPS boundary.

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-13 (Cryptographic Protection) - random bits from the
//   validated module's DRBG (SP 800-90A inside AWS-LC FIPS).
// - DECISION: docs/decisions/0001-fips-validated-crypto.md

use zeroize::Zeroizing;

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

/// The 64-symbol password alphabet (plan M4 section 1.3): upper and lower
/// case letters without the look-alikes `I O l o`, digits without `0 1`,
/// and eight symbols that are not shell, command-interpreter or XML
/// specials. 64 symbols give 6 bits per character (24 characters: 144
/// bits).
pub const PASSWORD_ALPHABET: &[u8; 64] =
    b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789+-.,:=@_";

/// Shortest password [`random_password`] produces (one of each class).
pub const MIN_PASSWORD_LEN: usize = 4;
/// Longest password [`random_password`] produces.
pub const MAX_PASSWORD_LEN: usize = 256;

/// Draws before giving up on the four-class rule. For 24 characters the
/// chance a draw misses a class is under 5 %, so 64 failures in a row
/// means the DRBG is broken.
const MAX_PASSWORD_ATTEMPTS: usize = 64;

// COMPLIANCE MAPPING:
// - NIST 800-53: IA-5(1) (Password-Based Authentication) - random password
//   from the module DRBG; uniform over 64 symbols (byte & 63, no modulo
//   bias); at least one upper, lower, digit and symbol.
// - SPEC: plan M4 section 1.3, section 5 (Password).

/// A random password of `len` characters from [`PASSWORD_ALPHABET`],
/// containing at least one character of each of the four classes. Draws
/// are retried until that holds; the rejected draws are wiped.
///
/// # Errors
///
/// [`CryptoError::PasswordLength`] if `len` is outside
/// [`MIN_PASSWORD_LEN`]..=[`MAX_PASSWORD_LEN`]; [`CryptoError::Random`] if
/// the DRBG fails or never yields a draw with all four classes.
pub fn random_password(len: usize) -> Result<Zeroizing<String>, CryptoError> {
    if !(MIN_PASSWORD_LEN..=MAX_PASSWORD_LEN).contains(&len) {
        return Err(CryptoError::PasswordLength {
            min: MIN_PASSWORD_LEN,
            max: MAX_PASSWORD_LEN,
        });
    }
    let mut raw = Zeroizing::new(vec![0u8; len]);
    for _ in 0..MAX_PASSWORD_ATTEMPTS {
        fill_random(&mut raw)?;
        let mut out = Zeroizing::new(String::with_capacity(len));
        for b in raw.iter() {
            let sym = PASSWORD_ALPHABET
                .get(usize::from(b & 0x3f))
                .copied()
                .ok_or(CryptoError::Random)?;
            out.push(char::from(sym));
        }
        if has_all_classes(out.as_bytes()) {
            return Ok(out);
        }
    }
    Err(CryptoError::Random)
}

fn has_all_classes(pw: &[u8]) -> bool {
    pw.iter().any(u8::is_ascii_uppercase)
        && pw.iter().any(u8::is_ascii_lowercase)
        && pw.iter().any(u8::is_ascii_digit)
        && pw.iter().any(|b| !b.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alphabet_is_64_unique_safe_symbols() {
        let mut seen = std::collections::HashSet::new();
        for &c in PASSWORD_ALPHABET {
            assert!(seen.insert(c));
            assert!(!b"IOlo01&<>\"'`$;|*?!(){}[]~#% ^/\\".contains(&c));
        }
        assert_eq!(seen.len(), 64);
    }

    #[test]
    fn password_shape() {
        for _ in 0..200 {
            let pw = random_password(24).unwrap();
            assert_eq!(pw.len(), 24);
            assert!(pw.bytes().all(|b| PASSWORD_ALPHABET.contains(&b)));
            assert!(has_all_classes(pw.as_bytes()));
        }
        assert_ne!(*random_password(24).unwrap(), *random_password(24).unwrap());
    }

    #[test]
    fn password_length_bounds() {
        assert!(random_password(3).is_err());
        assert!(random_password(257).is_err());
        assert_eq!(random_password(4).unwrap().len(), 4);
        assert_eq!(random_password(256).unwrap().len(), 256);
    }

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
