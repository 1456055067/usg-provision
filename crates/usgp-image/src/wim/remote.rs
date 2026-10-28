//! A WIM file read from verified content chunks (M3 apply).
//!
//! The agent never holds the whole image: it fetches the content store's
//! fixed 8 MiB chunks (REQ-IMG-050) through a [`ChunkSource`]. Every chunk
//! is checked against the SHA-256 the signed content manifest gives for
//! it, through the FIPS provider, **before** any of its bytes are handed
//! to the WIM reader, so no unverified byte is decoded or written
//! (decision 0011). [`ChunkReader`] turns a source into `Read + Seek` with
//! a two-chunk cache.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity),
//   SI-7(1) (Integrity Checks) - verify-before-use of every chunk.
// - NIST 800-53: SC-13 (Cryptographic Protection) - SHA-256 through
//   usgp-crypto's FIPS provider (decision 0001).
// - NIST 800-53: SI-10 (Information Input Validation) - chunk lengths
//   checked against the content length.
// - SPEC: specs/os-images.md#REQ-IMG-050, #REQ-IMG-051
// - SPEC: specs/preinstall-env.md#REQ-PE-016
// - DECISION: docs/decisions/0011-content-integrity-and-secrets-baseline.md

use std::fmt;
use std::io::{self, Read, Seek, SeekFrom};
use std::sync::Arc;

use usgp_common::Sha256Digest;
use usgp_crypto::CryptoProvider;

use crate::chunks::CONTENT_CHUNK_BYTES;

/// Why a chunk could not be fetched (from the source's point of view).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChunkFetchError {
    /// The chunk is not available now (network, server); retrying is the
    /// source's job, so this is final for the reader.
    Unavailable,
    /// The source failed with an I/O error.
    Io(io::ErrorKind),
}

/// Content addressed by fixed-size chunks, with a reference digest per
/// chunk from a signed manifest. Implemented by the agent over its server
/// link (`usgp-deploy`), and by tests over memory.
pub trait ChunkSource {
    /// Length of the whole content in bytes.
    fn content_len(&self) -> u64;

    /// The reference SHA-256 of chunk `n` (each chunk is
    /// [`CONTENT_CHUNK_BYTES`] long, the last may be shorter), from the
    /// signed content manifest; `None` if the manifest has no such chunk.
    fn expected_sha256(&self, n: u64) -> Option<Sha256Digest>;

    /// The bytes of chunk `n`, as fetched. They are not trusted: the
    /// reader verifies them before use.
    ///
    /// # Errors
    ///
    /// [`ChunkFetchError`] if the chunk cannot be fetched.
    fn fetch(&mut self, n: u64) -> Result<Arc<[u8]>, ChunkFetchError>;
}

/// Why [`ChunkReader`] stopped. Kept by the reader, because the WIM
/// reader sees only an [`io::Error`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChunkReadError {
    /// A chunk's SHA-256 differs from the signed manifest's (SI-7).
    Integrity {
        /// 0-based chunk number.
        chunk: u64,
    },
    /// A chunk had the wrong length.
    Length {
        /// 0-based chunk number.
        chunk: u64,
    },
    /// The manifest names no digest for a chunk inside the content.
    NoDigest {
        /// 0-based chunk number.
        chunk: u64,
    },
    /// The source could not fetch a chunk.
    Fetch {
        /// 0-based chunk number.
        chunk: u64,
        /// What the source reported.
        error: ChunkFetchError,
    },
}

impl fmt::Display for ChunkReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Integrity { chunk } => write!(f, "content chunk {chunk} failed verification"),
            Self::Length { chunk } => write!(f, "content chunk {chunk} has the wrong length"),
            Self::NoDigest { chunk } => write!(f, "content chunk {chunk} has no reference digest"),
            Self::Fetch { chunk, .. } => write!(f, "content chunk {chunk} could not be fetched"),
        }
    }
}

impl std::error::Error for ChunkReadError {}

/// `Read + Seek` over a [`ChunkSource`], verifying each chunk once when it
/// is fetched and caching the last two verified chunks.
pub struct ChunkReader<'a> {
    src: &'a mut dyn ChunkSource,
    crypto: &'a dyn CryptoProvider,
    len: u64,
    pos: u64,
    cache: [Option<(u64, Arc<[u8]>)>; 2],
    next_slot: usize,
    error: Option<ChunkReadError>,
    fetched: u64,
}

impl fmt::Debug for ChunkReader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChunkReader")
            .field("len", &self.len)
            .field("pos", &self.pos)
            .field("fetched", &self.fetched)
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl<'a> ChunkReader<'a> {
    /// A reader over `src`, verifying with `crypto`'s SHA-256.
    pub fn new(src: &'a mut dyn ChunkSource, crypto: &'a dyn CryptoProvider) -> Self {
        let len = src.content_len();
        Self {
            src,
            crypto,
            len,
            pos: 0,
            cache: [None, None],
            next_slot: 0,
            error: None,
            fetched: 0,
        }
    }

    /// Length of the content.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.len
    }

    /// True for empty content.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The error that made the last read fail, if any.
    #[must_use]
    pub fn error(&self) -> Option<ChunkReadError> {
        self.error
    }

    /// Number of chunks fetched (and verified) so far.
    #[must_use]
    pub fn chunks_fetched(&self) -> u64 {
        self.fetched
    }

    fn fail(&mut self, e: ChunkReadError) -> io::Error {
        self.error = Some(e);
        io::Error::new(io::ErrorKind::InvalidData, e)
    }

    /// The verified chunk `n`.
    fn chunk(&mut self, n: u64) -> io::Result<Arc<[u8]>> {
        if let Some((_, c)) = self.cache.iter().flatten().find(|(k, _)| *k == n) {
            return Ok(Arc::clone(c));
        }
        let start = n.saturating_mul(CONTENT_CHUNK_BYTES);
        let want = self.len.saturating_sub(start).min(CONTENT_CHUNK_BYTES);
        let Some(expected) = self.src.expected_sha256(n) else {
            return Err(self.fail(ChunkReadError::NoDigest { chunk: n }));
        };
        let bytes = match self.src.fetch(n) {
            Ok(b) => b,
            Err(error) => return Err(self.fail(ChunkReadError::Fetch { chunk: n, error })),
        };
        self.fetched = self.fetched.saturating_add(1);
        if u64::try_from(bytes.len()).ok() != Some(want) {
            return Err(self.fail(ChunkReadError::Length { chunk: n }));
        }
        // SI-7: verified before any byte is used. The digests are public
        // reference values, so a plain comparison is fine.
        if self.crypto.sha256(&bytes) != expected {
            return Err(self.fail(ChunkReadError::Integrity { chunk: n }));
        }
        if let Some(slot) = self.cache.get_mut(self.next_slot) {
            *slot = Some((n, Arc::clone(&bytes)));
        }
        self.next_slot = (self.next_slot + 1) % 2;
        Ok(bytes)
    }
}

impl Read for ChunkReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(e) = self.error {
            return Err(io::Error::new(io::ErrorKind::InvalidData, e));
        }
        if self.pos >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let n = self.pos / CONTENT_CHUNK_BYTES;
        let chunk = self.chunk(n)?;
        let within = usize::try_from(self.pos % CONTENT_CHUNK_BYTES)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let avail = chunk.get(within..).unwrap_or(&[]);
        let k = avail.len().min(buf.len());
        let (dst, _) = buf.split_at_mut(k);
        dst.copy_from_slice(avail.get(..k).unwrap_or(&[]));
        self.pos = self
            .pos
            .saturating_add(u64::try_from(k).unwrap_or(u64::MAX));
        Ok(k)
    }
}

impl Seek for ChunkReader<'_> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let bad = || io::Error::from(io::ErrorKind::InvalidInput);
        let new = match to {
            SeekFrom::Start(p) => Some(p),
            SeekFrom::End(d) => self.len.checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        }
        .ok_or_else(bad)?;
        self.pos = new;
        Ok(new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunks::ContentHasher;

    struct Mem {
        data: Vec<u8>,
        digests: Vec<Sha256Digest>,
        fetches: u64,
    }

    impl Mem {
        fn new(data: Vec<u8>) -> Self {
            let mut h = ContentHasher::new(usgp_crypto::provider());
            h.update(&data);
            let digests = h.finish().chunks;
            Self {
                data,
                digests,
                fetches: 0,
            }
        }
    }

    impl ChunkSource for Mem {
        fn content_len(&self) -> u64 {
            u64::try_from(self.data.len()).unwrap_or(u64::MAX)
        }
        fn expected_sha256(&self, n: u64) -> Option<Sha256Digest> {
            self.digests.get(usize::try_from(n).ok()?).copied()
        }
        fn fetch(&mut self, n: u64) -> Result<Arc<[u8]>, ChunkFetchError> {
            self.fetches += 1;
            let c =
                usize::try_from(CONTENT_CHUNK_BYTES).map_err(|_| ChunkFetchError::Unavailable)?;
            let s = usize::try_from(n).map_err(|_| ChunkFetchError::Unavailable)? * c;
            let e = (s + c).min(self.data.len());
            Ok(Arc::from(
                self.data.get(s..e).ok_or(ChunkFetchError::Unavailable)?,
            ))
        }
    }

    #[test]
    fn reads_across_chunks_and_caches_two() {
        let c = usize::try_from(CONTENT_CHUNK_BYTES).unwrap();
        let data: Vec<u8> = (0..2 * c + 10)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let mut m = Mem::new(data.clone());
        let mut r = ChunkReader::new(&mut m, usgp_crypto::provider());
        let mut buf = vec![0u8; 20];
        r.seek(SeekFrom::Start(u64::try_from(c - 10).unwrap()))
            .unwrap();
        r.read_exact(&mut buf).unwrap();
        assert_eq!(Some(&buf[..]), data.get(c - 10..c + 10));
        r.seek(SeekFrom::Start(0)).unwrap();
        r.read_exact(&mut buf).unwrap();
        assert_eq!(r.chunks_fetched(), 2);
        let mut all = Vec::new();
        r.seek(SeekFrom::Start(0)).unwrap();
        r.read_to_end(&mut all).unwrap();
        assert_eq!(all, data);
        drop(r);
        assert_eq!(m.fetches, 3, "chunks 0 and 1 were served from the cache");
    }

    #[test]
    fn tampered_chunk_fails_before_use() {
        let mut m = Mem::new(vec![7u8; 100]);
        if let Some(b) = m.data.get_mut(50) {
            *b = 8;
        }
        let mut r = ChunkReader::new(&mut m, usgp_crypto::provider());
        let mut buf = [0u8; 4];
        assert!(r.read_exact(&mut buf).is_err());
        assert_eq!(r.error(), Some(ChunkReadError::Integrity { chunk: 0 }));
        assert_eq!(buf, [0u8; 4], "no byte handed out");
        // Sticky: later reads fail too.
        assert!(r.read(&mut buf).is_err());
    }

    #[test]
    fn missing_digest_and_short_chunk() {
        let mut m = Mem::new(vec![1u8; 10]);
        m.digests.clear();
        let mut r = ChunkReader::new(&mut m, usgp_crypto::provider());
        assert!(r.read(&mut [0u8; 1]).is_err());
        assert_eq!(r.error(), Some(ChunkReadError::NoDigest { chunk: 0 }));
        let mut m = Mem::new(vec![1u8; 10]);
        m.data.pop();
        let mut r = ChunkReader {
            len: 10,
            ..ChunkReader::new(&mut m, usgp_crypto::provider())
        };
        assert!(r.read(&mut [0u8; 1]).is_err());
        assert_eq!(r.error(), Some(ChunkReadError::Length { chunk: 0 }));
    }
}
