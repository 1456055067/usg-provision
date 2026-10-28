//! Test support (feature `testkit`): our own XPRESS encoder and a WIM
//! builder, used only to make test files and fuzz seeds. Never used by the
//! product; release builds do not enable the feature.

// COMPLIANCE MAPPING:
// - NIST 800-53: SA-11 (Developer Testing and Evaluation)

pub mod builder;
pub mod tree;
pub mod xpress_enc;

pub use builder::{BuildInfo, ImageSpec, WimBuilder};
pub use tree::{NodeSpec, TreeSpec};

use std::io::Cursor;
use std::sync::Arc;

use usgp_common::Sha256Digest;

use crate::chunks::{CONTENT_CHUNK_BYTES, ContentHasher};
use crate::wim::remote::{ChunkFetchError, ChunkSource};

use crate::codec::XpressDecoder;
use crate::error::WimError;
use crate::wim::reshdr::ResourceHeader;
use crate::wim::source::{NoProgress, Source};

/// Largest resource [`decode_resource`] returns (test files only).
pub const DECODE_RESOURCE_MAX: u64 = 256 * 1024 * 1024;

/// Reads resource `rh` of the in-memory file `file` through the product's
/// own resource reader (chunk table and XPRESS decoder), for tests that
/// compare decoded content with a lookup entry's SHA-1 (BOOT-004). Chunks
/// stored at 32768 bytes are taken as raw, as the apply reader does
/// (OBS-046).
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
    crate::wim::resource::read_resource(
        &mut src,
        rh,
        Some(&mut decoder),
        crate::wim::resource::RawChunks::Apply,
        &mut |piece| {
            out.extend_from_slice(piece);
            Ok(())
        },
    )?;
    Ok(out)
}

/// A [`ChunkSource`] over bytes in memory, with the reference digests
/// computed from the bytes as given (the "signed manifest" of a test).
/// [`MemoryChunks::tamper`] changes a byte afterwards, so the reader must
/// refuse that chunk.
#[derive(Debug, Clone)]
pub struct MemoryChunks {
    data: Vec<u8>,
    digests: Vec<Sha256Digest>,
    fetches: u64,
    unavailable: Option<u64>,
}

impl MemoryChunks {
    /// A source over `data`.
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        let mut h = ContentHasher::new(usgp_crypto::provider());
        h.update(&data);
        let digests = h.finish().chunks;
        Self {
            data,
            digests,
            fetches: 0,
            unavailable: None,
        }
    }

    /// Flips byte `at` after the digests were taken (no-op past the end).
    pub fn tamper(&mut self, at: usize) {
        if let Some(b) = self.data.get_mut(at) {
            *b ^= 0x5a;
        }
    }

    /// Makes chunk `n` fail to fetch.
    pub fn make_unavailable(&mut self, n: u64) {
        self.unavailable = Some(n);
    }

    /// Chunks fetched so far.
    #[must_use]
    pub fn fetches(&self) -> u64 {
        self.fetches
    }
}

impl ChunkSource for MemoryChunks {
    fn content_len(&self) -> u64 {
        u64::try_from(self.data.len()).unwrap_or(u64::MAX)
    }

    fn expected_sha256(&self, n: u64) -> Option<Sha256Digest> {
        self.digests.get(usize::try_from(n).ok()?).copied()
    }

    fn fetch(&mut self, n: u64) -> Result<Arc<[u8]>, ChunkFetchError> {
        self.fetches = self.fetches.saturating_add(1);
        if self.unavailable == Some(n) {
            return Err(ChunkFetchError::Unavailable);
        }
        let c = usize::try_from(CONTENT_CHUNK_BYTES).map_err(|_| ChunkFetchError::Unavailable)?;
        let start = usize::try_from(n)
            .ok()
            .and_then(|k| k.checked_mul(c))
            .ok_or(ChunkFetchError::Unavailable)?;
        let end = start.saturating_add(c).min(self.data.len());
        self.data
            .get(start..end)
            .map(Arc::from)
            .ok_or(ChunkFetchError::Unavailable)
    }
}
