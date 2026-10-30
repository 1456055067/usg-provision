//! Content chunks fetched from the server and verified against the signed
//! content manifest before any use (plan section 3.3).
//!
//! [`VerifiedChunks`] fetches chunk `n` through the [`ServerLink`], checks
//! its length against the manifest and its SHA-256 (through the FIPS
//! provider) against `chunk_sha256[n]`, and only then hands it out. It
//! keeps the last two verified chunks. It implements `usgp-image`'s
//! [`ChunkSource`], whose reader verifies every chunk again before decoding
//! (two independent checks; harmless).
//!
//! Transient failures are retried by the plan's policy with growing delays
//! (REQ-JOB-007); a digest or length mismatch, "not found" and a refusal
//! are not. The first failure is kept and returned for every later call,
//! so the engine can name it (REQ-JOB-005).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7, SI-7(1) (Integrity Checks) - verify before use.
// - NIST 800-53: SC-13 (Cryptographic Protection) - SHA-256 through
//   usgp-crypto (decision 0001).
// - NIST 800-53: SI-10 (Information Input Validation) - exact chunk
//   length before hashing.
// - SPEC: specs/preinstall-env.md#REQ-PE-016; specs/progress.md#REQ-JOB-007,
//   #REQ-JOB-008, #REQ-JOB-011
// - DECISION: docs/decisions/0011, 0021 item 4

use std::fmt;
use std::sync::Arc;

use usgp_common::Sha256Digest;
use usgp_crypto::CryptoProvider;
use usgp_image::wim::remote::{ChunkFetchError, ChunkSource};
use usgp_proto::JobId;
use usgp_proto::content_manifest::{ContentManifestV1, ContentManifestV2, chunk_count};
use usgp_proto::job_plan::{RetryPolicyV1, VerifiedJobPlan};

use crate::clock::{Clock, TimeLimit, Watch, backoff};
use crate::link::{LinkError, ServerLink};

/// What went wrong with a chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChunkErrorKind {
    /// The server could not be reached, after every attempt.
    Network,
    /// The server does not have the chunk (404; not retried).
    NotFound,
    /// The server refused the request (409 or similar; not retried).
    Refused,
    /// The server reported that its own copy failed its check.
    ServerIntegrity,
    /// The server's response broke the protocol.
    Protocol,
    /// The chunk's SHA-256 differs from the signed manifest (not retried).
    Digest,
    /// The chunk has the wrong length (not retried).
    Length,
    /// The manifest names no digest for the chunk asked for.
    NoDigest,
    /// The step ran out of time.
    StepTimeout,
    /// No progress for the stall limit.
    Stalled,
}

/// A chunk failure: what, which chunk, and how many attempts were made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkError {
    /// What went wrong.
    pub kind: ChunkErrorKind,
    /// 0-based chunk number.
    pub chunk: u64,
    /// Fetch attempts made for that chunk.
    pub attempts: u32,
}

impl fmt::Display for ChunkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self.kind {
            ChunkErrorKind::Network => "could not be fetched (server not reachable)",
            ChunkErrorKind::NotFound => "is not on the server",
            ChunkErrorKind::Refused => "was refused by the server",
            ChunkErrorKind::ServerIntegrity => "failed the server's integrity check",
            ChunkErrorKind::Protocol => "came back in a bad response",
            ChunkErrorKind::Digest => "failed its integrity check",
            ChunkErrorKind::Length => "has the wrong length",
            ChunkErrorKind::NoDigest => "has no reference digest",
            ChunkErrorKind::StepTimeout => "was not fetched before the step timed out",
            ChunkErrorKind::Stalled => "was not fetched before the transfer stalled",
        };
        write!(
            f,
            "content chunk {} {what} after {} attempt(s)",
            self.chunk, self.attempts
        )
    }
}

impl std::error::Error for ChunkError {}

/// Called after each verified chunk, with the link, so the engine can send
/// a progress report while the chunk source holds the link.
pub(crate) trait FetchHook {
    fn fetched(&self, link: &mut dyn ServerLink);
}

/// The signed manifest whose chunk digests are the reference: the image
/// (v1) or a driver archive or agent package (v2; M4 plan WU-4a).
#[derive(Clone, Copy)]
enum ManifestRef<'a> {
    V1(&'a ContentManifestV1),
    V2(&'a ContentManifestV2),
}

impl ManifestRef<'_> {
    fn size(self) -> u64 {
        match self {
            Self::V1(m) => m.size,
            Self::V2(m) => m.size,
        }
    }

    fn chunk(self, n: u64) -> Option<(u64, Sha256Digest)> {
        match self {
            Self::V1(m) => m.chunk(n).map(|(l, d)| (l, *d)),
            Self::V2(m) => m.chunk(n).map(|(l, d)| (l, *d)),
        }
    }
}

/// Verified chunks of the plan's image (plan section 3.3), or of one
/// driver archive or agent package (M4 plan section 1.4).
pub struct VerifiedChunks<'a> {
    link: &'a mut dyn ServerLink,
    crypto: &'a dyn CryptoProvider,
    clock: &'a dyn Clock,
    manifest: ManifestRef<'a>,
    job: JobId,
    content: Sha256Digest,
    retry: RetryPolicyV1,
    watch: Option<&'a Watch<'a>>,
    hook: Option<&'a dyn FetchHook>,
    cache: [Option<(u64, Arc<[u8]>)>; 2],
    next_slot: usize,
    failure: Option<ChunkError>,
    fetched_bytes: u64,
}

impl fmt::Debug for VerifiedChunks<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedChunks")
            .field("job", &self.job)
            .field("content", &self.content)
            .field("failure", &self.failure)
            .field("fetched_bytes", &self.fetched_bytes)
            .finish_non_exhaustive()
    }
}

impl<'a> VerifiedChunks<'a> {
    /// Chunks of `plan`'s image, fetched over `link` for `plan`'s job.
    pub fn new(
        link: &'a mut dyn ServerLink,
        crypto: &'a dyn CryptoProvider,
        clock: &'a dyn Clock,
        plan: &'a VerifiedJobPlan,
    ) -> Self {
        let p = plan.plan();
        Self {
            link,
            crypto,
            clock,
            manifest: ManifestRef::V1(plan.content_manifest()),
            job: p.job_id,
            content: p.image.content_sha256,
            retry: p.retry,
            watch: None,
            hook: None,
            cache: [None, None],
            next_slot: 0,
            failure: None,
            fetched_bytes: 0,
        }
    }

    /// Chunks of one driver archive or agent package (`manifest`, already
    /// verified as part of a v2 plan), fetched over `link` for `job` with
    /// the plan's `retry` policy (M4 plan section 1.4: re-verified chunk
    /// by chunk at the step that uses it).
    pub fn for_archive(
        link: &'a mut dyn ServerLink,
        crypto: &'a dyn CryptoProvider,
        clock: &'a dyn Clock,
        job: JobId,
        retry: RetryPolicyV1,
        manifest: &'a ContentManifestV2,
    ) -> Self {
        Self {
            link,
            crypto,
            clock,
            manifest: ManifestRef::V2(manifest),
            job,
            content: manifest.sha256,
            retry,
            watch: None,
            hook: None,
            cache: [None, None],
            next_slot: 0,
            failure: None,
            fetched_bytes: 0,
        }
    }

    /// Fetches and verifies every chunk, in order, into one buffer, and
    /// then checks the SHA-256 of the whole content against the manifest.
    /// Content larger than `max_bytes` is refused before any fetch.
    ///
    /// # Errors
    ///
    /// [`ChunkError`]; a whole-file digest mismatch is
    /// [`ChunkErrorKind::Digest`] on the last chunk, and an oversized
    /// content is [`ChunkErrorKind::Length`] on chunk 0.
    pub fn read_all(&mut self, max_bytes: u64) -> Result<Vec<u8>, ChunkError> {
        let size = self.manifest.size();
        let Some(cap) = usize::try_from(size).ok().filter(|_| size <= max_bytes) else {
            return Err(self.fail(ChunkErrorKind::Length, 0, 0));
        };
        let mut out = Vec::with_capacity(cap);
        let n = chunk_count(size);
        for i in 0..n {
            let c = self.get(i)?;
            out.extend_from_slice(&c);
        }
        let want = match self.manifest {
            ManifestRef::V1(m) => m.sha256,
            ManifestRef::V2(m) => m.sha256,
        };
        if self.crypto.sha256(&out) != want {
            return Err(self.fail(ChunkErrorKind::Digest, n.saturating_sub(1), 1));
        }
        Ok(out)
    }

    /// Applies a step's time limits.
    pub(crate) fn with_watch(mut self, w: &'a Watch<'a>) -> Self {
        self.watch = Some(w);
        self
    }

    /// Calls `hook` after each verified chunk.
    pub(crate) fn with_hook(mut self, h: &'a dyn FetchHook) -> Self {
        self.hook = Some(h);
        self
    }

    /// The first failure, if any.
    #[must_use]
    pub fn failure(&self) -> Option<ChunkError> {
        self.failure
    }

    /// Bytes of verified chunks fetched so far.
    #[must_use]
    pub fn fetched_bytes(&self) -> u64 {
        self.fetched_bytes
    }

    /// The content's length in bytes.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.manifest.size()
    }

    /// `true` for empty content (never, for a valid manifest).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.manifest.size() == 0
    }

    fn fail(&mut self, kind: ChunkErrorKind, chunk: u64, attempts: u32) -> ChunkError {
        let e = ChunkError {
            kind,
            chunk,
            attempts,
        };
        self.failure = Some(e);
        e
    }

    fn time_kind(t: TimeLimit) -> ChunkErrorKind {
        match t {
            TimeLimit::Step => ChunkErrorKind::StepTimeout,
            TimeLimit::Stall => ChunkErrorKind::Stalled,
        }
    }

    /// Chunk `n`, verified.
    ///
    /// # Errors
    ///
    /// [`ChunkError`]; once one is returned, every later call returns it.
    pub fn get(&mut self, n: u64) -> Result<Arc<[u8]>, ChunkError> {
        if let Some(e) = self.failure {
            return Err(e);
        }
        if let Some(c) = self.cache.iter().flatten().find(|(k, _)| *k == n) {
            return Ok(Arc::clone(&c.1));
        }
        let Some((len, digest)) = self.manifest.chunk(n) else {
            return Err(self.fail(ChunkErrorKind::NoDigest, n, 0));
        };
        let mut attempts: u32 = 0;
        loop {
            if let Some(w) = self.watch
                && let Err(t) = w.check()
            {
                return Err(self.fail(Self::time_kind(t), n, attempts));
            }
            attempts = attempts.saturating_add(1);
            match self.link.fetch_chunk(self.job, &self.content, n) {
                Ok(bytes) => {
                    if u64::try_from(bytes.len()).ok() != Some(len) {
                        return Err(self.fail(ChunkErrorKind::Length, n, attempts));
                    }
                    if self.crypto.sha256(&bytes) != digest {
                        return Err(self.fail(ChunkErrorKind::Digest, n, attempts));
                    }
                    let chunk: Arc<[u8]> = Arc::from(bytes);
                    if let Some(slot) = self.cache.get_mut(self.next_slot) {
                        *slot = Some((n, Arc::clone(&chunk)));
                    }
                    self.next_slot = (self.next_slot + 1) % 2;
                    self.fetched_bytes = self.fetched_bytes.saturating_add(len);
                    if let Some(w) = self.watch {
                        w.progress();
                    }
                    if let Some(h) = self.hook {
                        h.fetched(&mut *self.link);
                    }
                    return Ok(chunk);
                }
                Err(LinkError::Transient) if attempts < self.retry.attempts => {
                    let d = backoff(self.retry.base_ms, self.retry.max_ms, attempts);
                    if let Some(w) = self.watch
                        && let Err(t) = w.check_wait(d)
                    {
                        return Err(self.fail(Self::time_kind(t), n, attempts));
                    }
                    self.clock.sleep(d);
                }
                Err(e) => {
                    let kind = match e {
                        LinkError::Transient => ChunkErrorKind::Network,
                        LinkError::NotFound => ChunkErrorKind::NotFound,
                        LinkError::Refused => ChunkErrorKind::Refused,
                        LinkError::ServerIntegrity => ChunkErrorKind::ServerIntegrity,
                        LinkError::Protocol => ChunkErrorKind::Protocol,
                    };
                    return Err(self.fail(kind, n, attempts));
                }
            }
        }
    }
}

impl ChunkSource for VerifiedChunks<'_> {
    fn content_len(&self) -> u64 {
        self.manifest.size()
    }

    fn expected_sha256(&self, n: u64) -> Option<Sha256Digest> {
        self.manifest.chunk(n).map(|(_, d)| d)
    }

    fn fetch(&mut self, n: u64) -> Result<Arc<[u8]>, ChunkFetchError> {
        self.get(n).map_err(|_| ChunkFetchError::Unavailable)
    }
}
