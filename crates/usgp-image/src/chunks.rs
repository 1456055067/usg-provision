//! Content digests for the content store: the total SHA-256 and one
//! SHA-256 per fixed 8 MiB chunk, in one pass (plan §1.1, §5.7).
//!
//! The chunk digests let every later use verify content chunk by chunk
//! before any byte of a chunk is sent or written (REQ-IMG-050), with
//! memory bounded to one chunk buffer per stream.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity),
//   SI-7(1) (Integrity Checks) - reference digests for verify-on-use.
// - NIST 800-53: SC-13 (Cryptographic Protection) - SHA-256 through the
//   FIPS-validated provider (usgp-crypto, decision 0001).
// - SPEC: specs/os-images.md#REQ-IMG-050, #REQ-IMG-051
// - FIPS 180-4 §6.2 (SHA-256)

use usgp_common::Sha256Digest;
use usgp_crypto::{CryptoProvider, Sha256Hasher};

/// Chunk size of the content store's per-chunk digests. Equal to
/// `usgp_proto::limits::CHUNK_SIZE`.
pub const CONTENT_CHUNK_BYTES: u64 = 8 * 1024 * 1024;

/// Digests of one piece of content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentDigests {
    /// Total size in bytes.
    pub size: u64,
    /// SHA-256 of the whole content.
    pub total: Sha256Digest,
    /// SHA-256 of each [`CONTENT_CHUNK_BYTES`] chunk in order; the last
    /// may be short; none for empty content.
    pub chunks: Vec<Sha256Digest>,
}

/// One-pass hasher: feed the content in any split with
/// [`ContentHasher::update`], then [`ContentHasher::finish`].
pub struct ContentHasher<'a> {
    crypto: &'a dyn CryptoProvider,
    total: Sha256Hasher,
    chunk: Sha256Hasher,
    in_chunk: u64,
    size: u64,
    chunks: Vec<Sha256Digest>,
}

impl std::fmt::Debug for ContentHasher<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContentHasher")
            .field("size", &self.size)
            .field("chunks", &self.chunks.len())
            .finish_non_exhaustive()
    }
}

impl<'a> ContentHasher<'a> {
    /// A hasher using `crypto`'s SHA-256.
    #[must_use]
    pub fn new(crypto: &'a dyn CryptoProvider) -> Self {
        Self {
            crypto,
            total: crypto.sha256_hasher(),
            chunk: crypto.sha256_hasher(),
            in_chunk: 0,
            size: 0,
            chunks: Vec::new(),
        }
    }

    /// Bytes fed so far.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Feeds the next bytes of the content.
    pub fn update(&mut self, mut data: &[u8]) {
        self.total.update(data);
        while !data.is_empty() {
            let room = CONTENT_CHUNK_BYTES.saturating_sub(self.in_chunk);
            let take = usize::try_from(room).map_or(data.len(), |r| r.min(data.len()));
            let (head, rest) = data.split_at_checked(take).unwrap_or((data, &[]));
            self.chunk.update(head);
            let n = u64::try_from(head.len()).unwrap_or(u64::MAX);
            self.in_chunk = self.in_chunk.saturating_add(n);
            self.size = self.size.saturating_add(n);
            if self.in_chunk == CONTENT_CHUNK_BYTES {
                let done = std::mem::replace(&mut self.chunk, self.crypto.sha256_hasher());
                self.chunks.push(done.finish());
                self.in_chunk = 0;
            }
            data = rest;
        }
    }

    /// Finishes and returns the digests.
    #[must_use]
    pub fn finish(mut self) -> ContentDigests {
        if self.in_chunk > 0 {
            self.chunks.push(self.chunk.finish());
        }
        ContentDigests {
            size: self.size,
            total: self.total.finish(),
            chunks: self.chunks,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digests(data: &[u8], split: usize) -> ContentDigests {
        let p = usgp_crypto::provider();
        let mut h = ContentHasher::new(p);
        for piece in data.chunks(split.max(1)) {
            h.update(piece);
        }
        h.finish()
    }

    #[test]
    fn empty() {
        let d = digests(&[], 1);
        assert_eq!(d.size, 0);
        assert!(d.chunks.is_empty());
        assert_eq!(d.total, usgp_crypto::sha256(&[]));
    }

    #[test]
    fn chunked_equals_one_shot_any_split() {
        let len = usize::try_from(CONTENT_CHUNK_BYTES).unwrap() * 2 + 5;
        let data: Vec<u8> = (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect();
        let chunk = usize::try_from(CONTENT_CHUNK_BYTES).unwrap();
        let expected: Vec<_> = data.chunks(chunk).map(usgp_crypto::sha256).collect();
        for split in [1 << 20, 4093, chunk, chunk + 1, len] {
            let d = digests(&data, split);
            assert_eq!(d.size, u64::try_from(len).unwrap());
            assert_eq!(d.total, usgp_crypto::sha256(&data));
            assert_eq!(d.chunks, expected, "split {split}");
        }
    }

    #[test]
    fn exact_multiple_has_no_empty_tail() {
        let data = vec![7u8; usize::try_from(CONTENT_CHUNK_BYTES).unwrap()];
        let d = digests(&data, 1 << 16);
        assert_eq!(d.chunks.len(), 1);
    }
}
