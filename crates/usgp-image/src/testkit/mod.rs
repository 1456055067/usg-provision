//! Test support (feature `testkit`): our own XPRESS encoder and a WIM
//! builder, used only to make test files and fuzz seeds. Never used by the
//! product; release builds do not enable the feature.

// COMPLIANCE MAPPING:
// - NIST 800-53: SA-11 (Developer Testing and Evaluation)

pub mod builder;
pub mod xpress_enc;

pub use builder::{BuildInfo, ImageSpec, WimBuilder};

use std::io::Cursor;

use crate::codec::XpressDecoder;
use crate::error::WimError;
use crate::wim::reshdr::ResourceHeader;
use crate::wim::source::{NoProgress, Source};

/// Largest resource [`decode_resource`] returns (test files only).
pub const DECODE_RESOURCE_MAX: u64 = 256 * 1024 * 1024;

/// Reads resource `rh` of the in-memory file `file` through the product's
/// own resource reader (chunk table and XPRESS decoder), for tests that
/// compare decoded content with a lookup entry's SHA-1 (BOOT-004).
///
/// # Errors
///
/// As the product's reader; [`WimError::OutOfBounds`] if `rh` lies outside
/// `file`; [`WimError::LimitExceeded`] above [`DECODE_RESOURCE_MAX`].
pub fn decode_resource(file: &[u8], rh: &ResourceHeader) -> Result<Vec<u8>, WimError> {
    let len = u64::try_from(file.len()).map_err(|_| WimError::OutOfBounds { what: "resource" })?;
    rh.check_within(0, len, "resource")?;
    if rh.original_size > DECODE_RESOURCE_MAX {
        return Err(WimError::LimitExceeded { what: "resource" });
    }
    let mut cursor = Cursor::new(file);
    let mut progress = NoProgress;
    let mut src = Source::new(&mut cursor, &mut progress);
    let mut decoder = XpressDecoder::new();
    let mut out = Vec::new();
    crate::wim::resource::read_resource(&mut src, rh, Some(&mut decoder), &mut |piece| {
        out.extend_from_slice(piece);
        Ok(())
    })?;
    Ok(out)
}
