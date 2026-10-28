//! Boot-policy pull from the server (M3 plan WU-11, section 3.6; decision
//! 0021 item 2): the signed, generation-numbered list of devices whose
//! jobs succeeded, which the relay stops offering a boot program to
//! (REQ-BOOT-067).
//!
//! - **Transport.** `GET /v1/relay/boot-policy?have=<generation>` over
//!   HTTP/1.1 in TLS built by `usgp-crypto` on the FIPS provider, with the
//!   relay's client certificate (mTLS). The server certificate is checked
//!   against `server_feed.trust_anchors` and `server_feed.server_name`.
//!   304 means the relay already has the current generation; 200 carries a
//!   `SignedEnvelopeV1` of a `BootPolicyV1`. TCP connect and the TLS
//!   handshake are each bounded by [`CONNECT_TIMEOUT`], the whole exchange
//!   by [`FETCH_TIMEOUT`], and the body by `MAX_ENVELOPE_BYTES`.
//! - **Verification, in order** ([`BootPolicyFeed::apply_bytes`]): the
//!   envelope shape; the signature with the pinned boot-policy key, before
//!   the payload is parsed (`BootPolicyV1::open`); the boot service; the
//!   generation, which must not be below the applied one. An equal
//!   generation is the same list: identical bytes change nothing, other
//!   bytes are refused.
//! - **Apply.** The stop set is replaced atomically
//!   (`Suppression::apply_stops`) and, for a list from the server, written
//!   to the optional cache file (mode 0600, atomic rename).
//! - **Fail safe.** On any error the last good list stays in effect and
//!   `boot_policy.rejected` or `boot_policy.fetch_failed` is emitted (one
//!   event per distinct reason, then at most one per
//!   [`REPORT_INTERVAL`] with the count in between). While no list has
//!   ever been applied, no device is offered a boot program
//!   (`suppress::FeedGate::Awaiting`), so a stopped device is never served
//!   because the server could not be reached.
//! - **Cache.** At start-up a cache file, if present, is read (bounded, no
//!   symbolic link, owned by the relay or a trusted owner, not group- or
//!   world-writable) and goes through the same verification as a list
//!   from the server.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7, SI-7(6) (Software, Firmware, and Information
//   Integrity; Cryptographic Protection) - the list is applied only after
//   its signature verifies with the pinned key; verify before parse.
// - NIST 800-53: SC-23 (Session Authenticity) - generation rollback and
//   lists for another boot service are refused.
// - NIST 800-53: SC-8, SC-8(1), SC-13 - TLS from usgp-crypto (FIPS), no
//   plaintext fallback; IA-3 / IA-5(2) - the relay authenticates with its
//   enrolled client certificate and verifies the server's.
// - NIST 800-53: SC-5 - connect, exchange and body size bounds.
// - NIST 800-53: SI-17 (Fail-Safe Procedures) - last good list kept; no
//   offers before a first list.
// - NIST 800-53: AU-2 / AU-3 / AU-12 - every apply and refusal is an event
//   (what: generation, boot service, digest; outcome; where: node name).
// - SPEC: specs/boot-network.md#REQ-BOOT-067 (status note: DEC-0021),
//   #REQ-BOOT-051, #REQ-BOOT-060
// - DECISION: docs/decisions/0021 items 2 and 3; 0018 item 9
// - RFC 9110 §15.4.5 (304 Not Modified), §7.2 (Host)

// POAM: SC-23 - a process running as the relay's own uid can replace the
// cache file with an older list that was validly signed, and the relay
// applies it at its next start until the first pull from the server
// corrects it. The generation applied last is not kept in tamper-evident
// storage.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper::header::{self, HeaderValue};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout};
use usgp_common::Sha256Digest;
use usgp_common::config::TrustPolicy;
use usgp_crypto::tls::{ALPN_HTTP11, ClientAlpn, ClientTls, ClientTlsSettings, TlsMinVersion};
use usgp_crypto::{CryptoError, VerifyingKey};
use usgp_proto::envelope::{PayloadType, SignatureAlg, SignatureVerifier, SignedEnvelopeV1};
use usgp_proto::limits::MAX_ENVELOPE_BYTES;
use usgp_proto::{BootPolicyError, BootPolicyV1, SignedManifestError};

use crate::config::ServerFeedConfig;
use crate::events::{self, Outcome};
use crate::files::{
    FileError, MAX_CERT_PEM_BYTES, MAX_KEY_PEM_BYTES, read_private_key, read_trusted_public,
};
use crate::lock;
use crate::suppress::{BootStops, FeedGate, Suppression};

/// The server route (plan section 3.5).
pub const BOOT_POLICY_PATH: &str = "/v1/relay/boot-policy";
/// TCP connect timeout, and separately the TLS handshake timeout (project
/// design, CM-6).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest whole exchange, connect to last body byte (project design).
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(60);
/// At most one `boot_policy.rejected` / `boot_policy.fetch_failed` per
/// reason in this interval; repeats in between are counted.
pub const REPORT_INTERVAL: Duration = Duration::from_secs(300);
/// Largest share of the poll interval added or removed as jitter (1/8).
const JITTER_DIVISOR: u32 = 8;

/// Why the feed could not be set up at start-up (exit 78).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FeedSetupError {
    /// A configured file could not be read or breaks a trust rule.
    #[error("server_feed.{field}: {source}")]
    File {
        /// The key.
        field: &'static str,
        /// What failed.
        #[source]
        source: FileError,
    },
    /// The pinned boot-policy key is not a P-384 SPKI PEM.
    #[error("server_feed.boot_policy_key_pub: not a usable public key: {0}")]
    Key(#[source] CryptoError),
    /// The TLS client could not be built (bad anchors, certificate or
    /// key, or not FIPS).
    #[error("server_feed: TLS client configuration refused: {0}")]
    Tls(#[source] CryptoError),
}

impl FeedSetupError {
    /// The failing configuration key, for `relay.config.rejected`.
    #[must_use]
    pub fn field(&self) -> String {
        match self {
            Self::File { field, .. } => format!("server_feed.{field}"),
            Self::Key(_) => "server_feed.boot_policy_key_pub".to_owned(),
            Self::Tls(_) => "server_feed".to_owned(),
        }
    }
}

/// The pinned boot-policy key as a [`SignatureVerifier`]: only this key,
/// only ECDSA P-384/SHA-384, only a well-framed signing input.
#[derive(Debug, Clone)]
pub struct PinnedPolicyKey {
    key: VerifyingKey,
    id: Sha256Digest,
}

impl PinnedPolicyKey {
    /// Pins `key`.
    #[must_use]
    pub fn new(key: VerifyingKey) -> Self {
        let id = key.key_id().0;
        Self { key, id }
    }

    /// The key id (SHA-256 of the SPKI DER).
    #[must_use]
    pub fn key_id(&self) -> Sha256Digest {
        self.id
    }
}

impl SignatureVerifier for PinnedPolicyKey {
    fn verify(
        &self,
        key_id: &Sha256Digest,
        alg: SignatureAlg,
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        *key_id == self.id
            && alg == SignatureAlg::EcdsaP384Sha384
            && usgp_crypto::verify_signing_input(&self.key, message, signature).is_ok()
    }
}

/// The TLS client and pinned key built from `[server_feed]`.
#[derive(Debug, Clone)]
pub struct FeedMaterial {
    /// mTLS client (relay certificate, server anchors, ALPN http/1.1).
    pub tls: ClientTls,
    /// The pinned boot-policy key.
    pub key: PinnedPolicyKey,
}

/// Reads the feed's files under the trusted-file rules and builds the TLS
/// client and the pinned key. The private key is read into a wiped buffer
/// and handed to `usgp-crypto`, which keeps it in its own.
///
/// # Errors
///
/// [`FeedSetupError`].
pub fn load_material(
    cfg: &ServerFeedConfig,
    trust: &TrustPolicy,
) -> Result<FeedMaterial, FeedSetupError> {
    let public = |field: &'static str, path: &Path, max: u64| {
        read_trusted_public(path, max, trust).map_err(|e| FeedSetupError::File {
            field,
            source: FileError::File(e),
        })
    };
    let trust_anchors_pem = public("trust_anchors", &cfg.trust_anchors, MAX_CERT_PEM_BYTES)?;
    let client_cert_pem = public("client_cert", &cfg.client_cert, MAX_CERT_PEM_BYTES)?;
    let key_pem = public(
        "boot_policy_key_pub",
        &cfg.boot_policy_key_pub,
        MAX_KEY_PEM_BYTES,
    )?;
    let client_key_pem =
        read_private_key(&cfg.client_key, MAX_KEY_PEM_BYTES, trust).map_err(|source| {
            FeedSetupError::File {
                field: "client_key",
                source,
            }
        })?;
    let key = VerifyingKey::from_spki_pem(&key_pem).map_err(FeedSetupError::Key)?;
    let tls = ClientTls::new(&ClientTlsSettings {
        trust_anchors_pem,
        client_cert_chain_pem: Some(client_cert_pem),
        client_key_pem: Some(client_key_pem),
        min_version: TlsMinVersion::Tls12,
        alpn: ClientAlpn::Http11,
    })
    .map_err(FeedSetupError::Tls)?;
    Ok(FeedMaterial {
        tls,
        key: PinnedPolicyKey::new(key),
    })
}

/// Where a list came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Pulled from the server.
    Server,
    /// Read from the cache file at start-up.
    Cache,
}

impl Source {
    /// Stable label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Cache => "cache",
        }
    }
}

/// Why a list was refused. Never carries list content.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Rejection {
    /// Not a signed envelope of the expected shape or size.
    #[error("not a valid signed envelope")]
    Envelope,
    /// The signature does not verify with the pinned key, or the payload
    /// type is wrong.
    #[error("signature does not verify with the pinned boot-policy key")]
    Signature,
    /// The signed payload is not a valid v1 list.
    #[error("signed payload is not a valid boot-policy list: {0}")]
    Invalid(String),
    /// The list is for another boot service.
    #[error("list is for another boot service")]
    WrongBootService,
    /// The generation is below the applied one.
    #[error("generation {got} is below the applied generation {have}")]
    Rollback {
        /// Applied.
        have: u64,
        /// Offered.
        got: u64,
    },
    /// Same generation as the applied list, different content.
    #[error("generation {0} is already applied with different content")]
    GenerationReused(u64),
}

impl Rejection {
    /// Stable label for events and tests.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Envelope => "envelope",
            Self::Signature => "signature",
            Self::Invalid(_) => "invalid",
            Self::WrongBootService => "wrong_boot_service",
            Self::Rollback { .. } => "rollback",
            Self::GenerationReused(_) => "generation_reused",
        }
    }
}

/// Result of applying a verified list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applied {
    /// A new list is in effect.
    New {
        /// Its generation.
        generation: u64,
    },
    /// The same list was already in effect.
    Unchanged,
}

/// Why a pull failed (no list was received). Never carries secrets.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FetchError {
    /// TCP connect failed or timed out.
    #[error("connect: {0}")]
    Connect(String),
    /// TLS handshake refused or timed out.
    #[error("tls: {0}")]
    Tls(String),
    /// The HTTP exchange failed.
    #[error("http: {0}")]
    Http(String),
    /// An unexpected status.
    #[error("unexpected HTTP status {0}")]
    Status(u16),
    /// The body is larger than the envelope limit.
    #[error("response body larger than the envelope limit")]
    TooLarge,
    /// The whole exchange took longer than [`FETCH_TIMEOUT`].
    #[error("exchange timed out")]
    Timeout,
}

impl FetchError {
    /// Stable label for events and tests.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Connect(_) => "connect",
            Self::Tls(_) => "tls",
            Self::Http(_) => "http",
            Self::Status(_) => "status",
            Self::TooLarge => "too_large",
            Self::Timeout => "timeout",
        }
    }
}

/// What one pull did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollOutcome {
    /// 304: the applied generation is current.
    NotModified,
    /// A list was received and applied (or was already in effect).
    Applied(Applied),
    /// A list was received and refused; the last good list stays.
    Rejected(Rejection),
    /// No list was received; the last good list stays.
    FetchFailed(FetchError),
}

/// One rate-limited report channel.
#[derive(Debug, Default)]
struct Reporter {
    last: Option<(Instant, String)>,
    repeated: u64,
}

impl Reporter {
    /// Whether to emit now for `reason`; returns the repeats suppressed
    /// since the last event.
    fn should_emit(&mut self, reason: &str, now: Instant) -> Option<u64> {
        match &self.last {
            Some((at, last))
                if last == reason && now.saturating_duration_since(*at) < REPORT_INTERVAL =>
            {
                self.repeated = self.repeated.saturating_add(1);
                None
            }
            _ => {
                let n = self.repeated;
                self.last = Some((now, reason.to_owned()));
                self.repeated = 0;
                Some(n)
            }
        }
    }

    fn reset(&mut self) {
        self.last = None;
        self.repeated = 0;
    }
}

/// The boot-policy client of one relay.
#[derive(Debug)]
pub struct BootPolicyFeed {
    cfg: ServerFeedConfig,
    material: FeedMaterial,
    suppression: Arc<Suppression>,
    rejected: Mutex<Reporter>,
    failed: Mutex<Reporter>,
}

impl BootPolicyFeed {
    /// A feed applying lists to `suppression`. From now on no device is
    /// offered a boot program until a list is applied.
    #[must_use]
    pub fn new(
        cfg: ServerFeedConfig,
        material: FeedMaterial,
        suppression: Arc<Suppression>,
    ) -> Arc<Self> {
        suppression.require_feed();
        Arc::new(Self {
            cfg,
            material,
            suppression,
            rejected: Mutex::new(Reporter::default()),
            failed: Mutex::new(Reporter::default()),
        })
    }

    /// The configuration.
    #[must_use]
    pub fn config(&self) -> &ServerFeedConfig {
        &self.cfg
    }

    /// The boot-policy state in effect.
    #[must_use]
    pub fn gate(&self) -> FeedGate {
        self.suppression.feed()
    }

    /// Verifies and applies an envelope (module docs, in that order).
    /// Emits `boot_policy.applied` for a new list and
    /// `boot_policy.rejected` (rate-limited) for a refusal.
    ///
    /// # Errors
    ///
    /// [`Rejection`]; the last good list stays in effect.
    pub fn apply_bytes(&self, bytes: &[u8], source: Source) -> Result<Applied, Rejection> {
        match self.verify(bytes) {
            Ok((policy, digest)) => {
                let current = self.suppression.feed();
                if let FeedGate::Applied(stops) = &current
                    && stops.generation() == policy.generation
                {
                    if stops.payload_sha256() == digest {
                        lock(&self.rejected).reset();
                        return Ok(Applied::Unchanged);
                    }
                    let r = Rejection::GenerationReused(policy.generation);
                    self.report_rejected(&r, source);
                    return Err(r);
                }
                let previous = current.generation();
                let stops = BootStops::from_policy(&policy, digest);
                let count = stops.len();
                self.suppression.apply_stops(stops);
                lock(&self.rejected).reset();
                let cache = match (&self.cfg.cache_file, source) {
                    (Some(path), Source::Server) => match write_cache(path, bytes) {
                        Ok(()) => "written".to_owned(),
                        Err(e) => format!("write_failed:{:?}", e.kind()),
                    },
                    (Some(_), Source::Cache) => "read".to_owned(),
                    (None, _) => "none".to_owned(),
                };
                let detail = [
                    ("source", source.label().to_owned()),
                    ("boot_service_id", policy.boot_service_id.to_string()),
                    ("generation", policy.generation.to_string()),
                    (
                        "previous_generation",
                        previous.map_or_else(|| "none".to_owned(), |g| g.to_string()),
                    ),
                    ("stops", count.to_string()),
                    ("issued_at_us", policy.issued_at_us.as_micros().to_string()),
                    ("payload_sha256", digest.to_hex()),
                    ("key_id", self.material.key.key_id().to_hex()),
                    ("cache", cache),
                ];
                events::emit_simple(events::BOOT_POLICY_APPLIED, Outcome::Success, &detail);
                Ok(Applied::New {
                    generation: policy.generation,
                })
            }
            Err(r) => {
                self.report_rejected(&r, source);
                Err(r)
            }
        }
    }

    /// Signature, shape, boot service and rollback checks; returns the
    /// list and the SHA-256 of its signed payload.
    fn verify(&self, bytes: &[u8]) -> Result<(BootPolicyV1, Sha256Digest), Rejection> {
        let env = SignedEnvelopeV1::from_json(bytes).map_err(|_| Rejection::Envelope)?;
        let digest = env
            .verified_payload(PayloadType::BootPolicyV1, &self.material.key)
            .map(|v| usgp_crypto::sha256(v.bytes))
            .map_err(|_| Rejection::Signature)?;
        let policy = BootPolicyV1::open(&env, &self.material.key).map_err(|e| match e {
            SignedManifestError::Envelope(_) => Rejection::Signature,
            other => Rejection::Invalid(other.to_string()),
        })?;
        policy
            .check_for(
                self.cfg.boot_service_id,
                self.suppression.feed().generation(),
            )
            .map_err(|e| match e {
                BootPolicyError::WrongBootService => Rejection::WrongBootService,
                BootPolicyError::Rollback { have, got } => Rejection::Rollback { have, got },
                _ => Rejection::Invalid(e.to_string()),
            })?;
        Ok((policy, digest))
    }

    fn report_rejected(&self, r: &Rejection, source: Source) {
        let Some(repeated) = lock(&self.rejected).should_emit(&r.to_string(), Instant::now())
        else {
            return;
        };
        let gate = self.suppression.feed();
        let detail = [
            ("source", source.label().to_owned()),
            ("reason", r.label().to_owned()),
            ("error", r.to_string()),
            ("boot_service_id", self.cfg.boot_service_id.to_string()),
            ("action", "last good list kept".to_owned()),
            ("state", gate.label().to_owned()),
            (
                "generation_in_effect",
                gate.generation()
                    .map_or_else(|| "none".to_owned(), |g| g.to_string()),
            ),
            ("repeated_since_last", repeated.to_string()),
        ];
        events::emit_simple(events::BOOT_POLICY_REJECTED, Outcome::Refused, &detail);
    }

    fn report_fetch_failed(&self, e: &FetchError) {
        let Some(repeated) = lock(&self.failed).should_emit(&e.to_string(), Instant::now()) else {
            return;
        };
        let gate = self.suppression.feed();
        let detail = [
            ("reason", e.label().to_owned()),
            ("error", e.to_string()),
            ("server", self.cfg.url.authority()),
            ("boot_service_id", self.cfg.boot_service_id.to_string()),
            ("action", "last good list kept".to_owned()),
            ("state", gate.label().to_owned()),
            (
                "generation_in_effect",
                gate.generation()
                    .map_or_else(|| "none".to_owned(), |g| g.to_string()),
            ),
            ("repeated_since_last", repeated.to_string()),
        ];
        events::emit_simple(events::BOOT_POLICY_FETCH_FAILED, Outcome::Failure, &detail);
    }

    /// Reads and applies the cache file, if one is configured and present
    /// (start-up only). A missing file is normal; any other problem is a
    /// `boot_policy.rejected` and the relay stays without a list until the
    /// first pull.
    pub fn load_cache(&self) -> Option<Result<Applied, Rejection>> {
        let path = self.cfg.cache_file.as_ref()?;
        match read_cache(path) {
            Ok(None) => None,
            Ok(Some(bytes)) => Some(self.apply_bytes(&bytes, Source::Cache)),
            Err(e) => {
                let r = Rejection::Invalid(format!("cache file unusable: {e}"));
                self.report_rejected(&r, Source::Cache);
                Some(Err(r))
            }
        }
    }

    /// One pull: fetch, then verify and apply on the blocking pool.
    pub async fn poll_once(self: &Arc<Self>) -> PollOutcome {
        let have = self.suppression.feed().generation();
        match self.fetch(have).await {
            Ok(None) => {
                lock(&self.failed).reset();
                PollOutcome::NotModified
            }
            Ok(Some(bytes)) => {
                lock(&self.failed).reset();
                let me = Arc::clone(self);
                // Signature verification and parsing of a list of up to
                // 100,000 entries is CPU work: keep it off the async
                // workers.
                match tokio::task::spawn_blocking(move || me.apply_bytes(&bytes, Source::Server))
                    .await
                {
                    Ok(Ok(a)) => PollOutcome::Applied(a),
                    Ok(Err(r)) => PollOutcome::Rejected(r),
                    Err(_) => {
                        let r = Rejection::Invalid("verification task failed".to_owned());
                        self.report_rejected(&r, Source::Server);
                        PollOutcome::Rejected(r)
                    }
                }
            }
            Err(e) => {
                self.report_fetch_failed(&e);
                PollOutcome::FetchFailed(e)
            }
        }
    }

    /// Pulls now and then every `poll_interval_s` with jitter, forever
    /// (the caller aborts the task at shutdown).
    pub async fn run(self: Arc<Self>) {
        loop {
            let _ = self.poll_once().await;
            tokio::time::sleep(jittered(self.cfg.poll_interval)).await;
        }
    }

    /// `GET /v1/relay/boot-policy?have=<g>`. `Ok(None)` for 304.
    async fn fetch(&self, have: Option<u64>) -> Result<Option<Vec<u8>>, FetchError> {
        timeout(FETCH_TIMEOUT, self.fetch_inner(have))
            .await
            .map_err(|_| FetchError::Timeout)?
    }

    async fn fetch_inner(&self, have: Option<u64>) -> Result<Option<Vec<u8>>, FetchError> {
        let url = &self.cfg.url;
        let tcp = timeout(
            CONNECT_TIMEOUT,
            TcpStream::connect((url.host.as_str(), url.port)),
        )
        .await
        .map_err(|_| FetchError::Connect("timed out".to_owned()))?
        .map_err(|e| FetchError::Connect(format!("{:?}", e.kind())))?;
        let _ = tcp.set_nodelay(true);
        let tls = timeout(
            CONNECT_TIMEOUT,
            self.material.tls.connect(tcp, &self.cfg.server_name),
        )
        .await
        .map_err(|_| FetchError::Tls("handshake timed out".to_owned()))?
        .map_err(|f| FetchError::Tls(f.to_string()))?;
        if tls.alpn() != Some(ALPN_HTTP11) {
            return Err(FetchError::Tls(
                "server did not agree to http/1.1".to_owned(),
            ));
        }
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|e| FetchError::Http(e.to_string()))?;
        let conn_task = AbortOnDrop(tokio::spawn(conn));
        let host =
            HeaderValue::from_str(&url.authority()).map_err(|_| FetchError::Http("host".into()))?;
        let request = hyper::Request::get(format!("{BOOT_POLICY_PATH}?have={}", have.unwrap_or(0)))
            .header(header::HOST, host)
            .header(header::ACCEPT, "application/json")
            .body(Empty::<Bytes>::new())
            .map_err(|_| FetchError::Http("request".into()))?;
        let resp = sender
            .send_request(request)
            .await
            .map_err(|e| FetchError::Http(e.to_string()))?;
        let status = resp.status().as_u16();
        let result = match status {
            304 => Ok(None),
            200 => {
                if let Some(len) = resp.headers().get(header::CONTENT_LENGTH)
                    && content_length(len)
                        .is_none_or(|n| u64::try_from(MAX_ENVELOPE_BYTES).is_ok_and(|m| n > m))
                {
                    return Err(FetchError::TooLarge);
                }
                let mut body = resp.into_body();
                let mut out = Vec::new();
                while let Some(frame) = body.frame().await {
                    let frame = frame.map_err(|e| FetchError::Http(e.to_string()))?;
                    if let Ok(data) = frame.into_data() {
                        if out.len().saturating_add(data.len()) > MAX_ENVELOPE_BYTES {
                            return Err(FetchError::TooLarge);
                        }
                        out.extend_from_slice(&data);
                    }
                }
                Ok(Some(out))
            }
            other => Err(FetchError::Status(other)),
        };
        drop(conn_task);
        result
    }
}

/// Aborts the connection task when the exchange ends or is cancelled.
struct AbortOnDrop(tokio::task::JoinHandle<Result<(), hyper::Error>>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Parses a `Content-Length` value (digits only).
fn content_length(v: &HeaderValue) -> Option<u64> {
    let b = v.as_bytes();
    if b.is_empty() || b.len() > 20 || !b.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(b).ok()?.parse().ok()
}

/// `interval` plus or minus up to 1/8 of it, from the FIPS DRBG (no
/// jitter if the DRBG fails).
fn jittered(interval: Duration) -> Duration {
    let span = interval / JITTER_DIVISOR;
    let mut b = [0u8; 4];
    if usgp_crypto::fill_random(&mut b).is_err() || span.is_zero() {
        return interval;
    }
    let r = f64::from(u32::from_le_bytes(b)) / f64::from(u32::MAX);
    let lo = interval.saturating_sub(span);
    lo + span.mul_f64(2.0 * r)
}

/// Reads the cache file: `Ok(None)` if absent. Bounded; no symbolic link;
/// a regular file owned by the relay or a trusted owner, not group- or
/// world-writable.
fn read_cache(path: &Path) -> Result<Option<Vec<u8>>, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        let file = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("{:?}", e.kind())),
        };
        let meta = file.metadata().map_err(|e| format!("{:?}", e.kind()))?;
        if !meta.is_file() {
            return Err("not a regular file".to_owned());
        }
        if meta.mode() & 0o022 != 0 {
            return Err("group- or world-writable".to_owned());
        }
        let me = usgp_common::process::effective_uid().ok();
        if me != Some(meta.uid()) && meta.uid() != 0 {
            return Err("not owned by the relay".to_owned());
        }
        let max = u64::try_from(MAX_ENVELOPE_BYTES).unwrap_or(u64::MAX);
        if meta.len() > max {
            return Err("too large".to_owned());
        }
        let mut buf = Vec::new();
        file.take(max.saturating_add(1))
            .read_to_end(&mut buf)
            .map_err(|e| format!("{:?}", e.kind()))?;
        if u64::try_from(buf.len()).unwrap_or(u64::MAX) > max {
            return Err("too large".to_owned());
        }
        Ok(Some(buf))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(usgp_common::config::ConfigError::UnsupportedPlatform.to_string())
    }
}

/// Writes the cache atomically: a new file `<path>.tmp` with mode 0600,
/// synced, then renamed over `path`.
fn write_cache(path: &Path, bytes: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let mut tmp: PathBuf = path.to_path_buf();
        let mut name = path
            .file_name()
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?
            .to_os_string();
        name.push(".tmp");
        tmp.set_file_name(name);
        match std::fs::remove_file(&tmp) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)?;
        if let Some(dir) = path.parent()
            && let Ok(d) = std::fs::File::open(dir)
        {
            let _ = d.sync_all();
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (path, bytes);
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_stays_within_an_eighth() {
        let i = Duration::from_secs(30);
        for _ in 0..200 {
            let j = jittered(i);
            assert!(j >= i - i / 8 && j <= i + i / 8, "{j:?}");
        }
    }

    #[test]
    fn reporter_dedupes_and_counts() {
        let mut r = Reporter::default();
        let t0 = Instant::now();
        assert_eq!(r.should_emit("a", t0), Some(0));
        assert_eq!(r.should_emit("a", t0 + Duration::from_secs(1)), None);
        assert_eq!(r.should_emit("a", t0 + Duration::from_secs(2)), None);
        // Another reason: at once, with the count.
        assert_eq!(r.should_emit("b", t0 + Duration::from_secs(3)), Some(2));
        assert_eq!(r.should_emit("b", t0 + REPORT_INTERVAL * 2), Some(0));
        r.reset();
        assert_eq!(r.should_emit("b", t0), Some(0));
    }

    #[test]
    fn content_length_parse() {
        assert_eq!(content_length(&HeaderValue::from_static("12")), Some(12));
        assert_eq!(content_length(&HeaderValue::from_static("")), None);
        assert_eq!(content_length(&HeaderValue::from_static("-1")), None);
        assert_eq!(content_length(&HeaderValue::from_static("1 2")), None);
    }
}
