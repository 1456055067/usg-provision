//! Content transfer shared by images and PE kits: streaming upload and
//! verified download (plan WU-8, sections 1.1 "Upload", 5.7).
//!
//! **Upload.** The file is read twice, in fixed 1 MiB pieces: once to
//! compute its SHA-256 and size, which go in the session request, and once
//! to stream the body with `Content-Length` equal to that size. Memory
//! stays bounded whatever the file size. The second pass is hashed too;
//! if the file changed between the passes, the CLI reports it (the server
//! refuses the body with `digest_mismatch` in any case, plan section 5.7).
//!
//! **Download.** The content manifest envelope is verified against the
//! operator's pinned content public key before anything in it is parsed.
//! Then the content is streamed into `<out>.part` one 8 MiB chunk at a
//! time: each chunk is hashed and compared with the manifest's chunk
//! digest, and only then written. The total size and digest are checked
//! at the end. Only then is `<out>.part` linked to `<out>` (never
//! overwriting an existing file); on any failure `<out>.part` is deleted.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7, SI-7(1), SI-7(6) - content is verified chunk by
//   chunk against a signed manifest before it is written; the manifest
//   signature is verified with a pinned key before the manifest is
//   parsed.
// - NIST 800-53: SC-13 - SHA-256 and ECDSA P-384 only through
//   `usgp-crypto` (decision 0001).
// - NIST 800-53: SI-10 - sizes, counts and identifiers are checked; the
//   envelope is size-capped.
// - SPEC: specs/os-images.md#REQ-IMG-050, specs/preinstall-env.md
//   #REQ-PE-008 (integrity on every use)
// - SPEC: specs/os-images.md#REQ-IMG-030, #REQ-IMG-031 (streaming upload,
//   bounded memory), #REQ-IMG-033 (file names with spaces)
// - FIPS 180-4 (SHA-256), FIPS 186-5 (ECDSA)

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use usgp_common::Sha256Digest;
use usgp_crypto::{Sha256Hasher, VerifyingKey};
use usgp_proto::api::PeDeclaration;
use usgp_proto::api::{CreateUpload, CreateUploadRequest, CreateUploadResponse, UploadAccepted};
use usgp_proto::content_manifest::ContentManifestV1;
use usgp_proto::envelope::{SignatureAlg, SignatureVerifier, SignedEnvelopeV1};
use usgp_proto::ids::ContentId;
use usgp_proto::limits::{CHUNK_SIZE, MAX_ENVELOPE_BYTES};
use usgp_proto::names::{DisplayName, FileName};
use usgp_proto::status::ContentKind;
use usgp_proto::{SignedManifestError, api};

use crate::client::{ApiClient, Body, ClientError, Method, Transport};
use crate::display::esc;

/// Read size for hashing and streaming an upload.
const IO_BUF: usize = 1024 * 1024;

/// A failed content command.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CmdError {
    /// The server or the connection refused or failed.
    #[error(transparent)]
    Client(#[from] ClientError),
    /// A value given on the command line breaks a rule (nothing was sent).
    #[error("{0}")]
    Invalid(String),
    /// A local file could not be read or written.
    #[error("{}: {kind}", path.display())]
    Local {
        /// The file.
        path: PathBuf,
        /// The I/O error kind.
        kind: io::ErrorKind,
    },
    /// The output file already exists.
    #[error("{} already exists; refusing to overwrite it", .0.display())]
    OutputExists(PathBuf),
    /// The local file changed while it was being uploaded.
    #[error("{} changed while it was being uploaded; the server will refuse it", .0.display())]
    FileChanged(PathBuf),
    /// The signed manifest did not verify or does not describe this item.
    #[error("manifest not trusted: {0}")]
    Manifest(String),
    /// Downloaded bytes do not match the signed manifest.
    #[error("integrity check failed: {0}; nothing was written")]
    Integrity(String),
    /// The operator did not confirm a deletion.
    #[error("not confirmed; nothing was deleted")]
    NotConfirmed,
    /// Writing to standard output or error failed.
    #[error("cannot write output: {0}")]
    Output(io::ErrorKind),
}

impl From<io::Error> for CmdError {
    fn from(e: io::Error) -> Self {
        Self::Output(e.kind())
    }
}

/// Verifies envelope signatures with one pinned public key.
///
/// `usgp_proto` hands the verifier the full signing input of plan section
/// 5.3; `usgp-crypto` exposes verification only as `verify_typed(key,
/// type, payload, sig)`, which rebuilds that input itself. This adapter
/// splits the input back into type and payload and checks that rebuilding
/// gives the identical bytes before it verifies, so the two definitions
/// cannot silently diverge.
#[derive(Debug)]
pub struct PinnedKey {
    key: VerifyingKey,
    id: Sha256Digest,
}

impl PinnedKey {
    /// Pins `key`.
    #[must_use]
    pub fn new(key: VerifyingKey) -> Self {
        let id = key.key_id().0;
        Self { key, id }
    }

    /// The pinned key's id (SHA-256 of its SPKI DER).
    #[must_use]
    pub const fn id(&self) -> &Sha256Digest {
        &self.id
    }
}

/// Splits a plan section 5.3 signing input into (type, payload).
fn split_signing_input(message: &[u8]) -> Option<(&str, &[u8])> {
    let rest = message
        .strip_prefix(usgp_proto::envelope::SIGNATURE_DOMAIN)?
        .strip_prefix(b"\n")?;
    let nl = rest.iter().position(|&b| b == b'\n')?;
    let (ty, rest) = rest.split_at(nl);
    let rest = rest.get(1..)?;
    let nl = rest.iter().position(|&b| b == b'\n')?;
    let (len, payload) = rest.split_at(nl);
    let payload = payload.get(1..)?;
    let len: usize = std::str::from_utf8(len).ok()?.parse().ok()?;
    if len != payload.len() {
        return None;
    }
    Some((std::str::from_utf8(ty).ok()?, payload))
}

impl SignatureVerifier for PinnedKey {
    fn verify(
        &self,
        key_id: &Sha256Digest,
        alg: SignatureAlg,
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        if *key_id != self.id || alg != SignatureAlg::EcdsaP384Sha384 {
            return false;
        }
        let Some((ty, payload)) = split_signing_input(message) else {
            return false;
        };
        match usgp_crypto::envelope::signed_message(ty, payload) {
            Ok(rebuilt) if rebuilt == message => {}
            _ => return false,
        }
        usgp_crypto::verify_typed(&self.key, ty, payload, signature).is_ok()
    }
}

/// Path segment for a content kind (`images` or `pe`).
#[must_use]
pub const fn segment(kind: ContentKind) -> &'static str {
    match kind {
        ContentKind::Image => "images",
        ContentKind::Pe => "pe",
    }
}

/// Parses an identifier given on the command line.
///
/// # Errors
///
/// [`CmdError::Invalid`].
pub fn content_id(text: &str) -> Result<ContentId, CmdError> {
    ContentId::parse(text).map_err(|e| CmdError::Invalid(format!("ID {}: {e}", esc(text))))
}

fn local(path: &Path) -> impl Fn(io::Error) -> CmdError + '_ {
    move |e| CmdError::Local {
        path: path.to_path_buf(),
        kind: e.kind(),
    }
}

/// Opens a regular file for upload and returns it with its size.
fn open_upload(path: &Path) -> Result<(File, u64), CmdError> {
    let file = File::open(path).map_err(local(path))?;
    let meta = file.metadata().map_err(local(path))?;
    if !meta.is_file() {
        return Err(CmdError::Invalid(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    Ok((file, meta.len()))
}

/// SHA-256 and length of everything `r` yields, read in 1 MiB pieces.
fn hash_stream(r: &mut dyn Read) -> io::Result<(Sha256Digest, u64)> {
    let mut h = Sha256Hasher::new();
    let mut buf = vec![0u8; IO_BUF];
    let mut total = 0u64;
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        h.update(buf.get(..n).unwrap_or_default());
        total = total.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
    }
    Ok((h.finish(), total))
}

/// What the second (streaming) pass saw.
#[derive(Default)]
struct Seen {
    hasher: Option<Sha256Hasher>,
    bytes: u64,
}

/// A reader that hashes what passes through it into shared state, so the
/// caller can check it after the transport has consumed the body.
struct HashingReader<R> {
    inner: R,
    seen: Arc<Mutex<Seen>>,
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        let mut s = self
            .seen
            .lock()
            .map_err(|_| io::Error::other("upload state poisoned"))?;
        if let Some(h) = s.hasher.as_mut() {
            h.update(buf.get(..n).unwrap_or_default());
        }
        s.bytes = s.bytes.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        Ok(n)
    }
}

/// The result of an upload.
#[derive(Debug)]
pub struct Uploaded {
    /// The content item.
    pub content_id: ContentId,
    /// Its state after the body arrived (`checking`).
    pub state: usgp_proto::status::ContentState,
    /// Size sent.
    pub size: u64,
    /// SHA-256 declared and sent.
    pub sha256: Sha256Digest,
}

/// Uploads `path` as `kind` with display name `name` (and the PE
/// declaration for a PE).
///
/// # Errors
///
/// [`CmdError`]. A refused session sends no body. If the body cannot be
/// read locally, the session is cancelled (best effort).
pub fn upload<T: Transport>(
    api: &mut ApiClient<T>,
    kind: ContentKind,
    path: &Path,
    name: &str,
    pe_declaration: Option<PeDeclaration>,
) -> Result<Uploaded, CmdError> {
    let display_name =
        DisplayName::new(name).map_err(|e| CmdError::Invalid(format!("--name {e}")))?;
    let file_name_text = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| CmdError::Invalid("the file name is not valid UTF-8".into()))?;
    let file_name = FileName::new(file_name_text)
        .map_err(|e| CmdError::Invalid(format!("file name {}: {e}", esc(file_name_text))))?;

    let (mut file, size) = open_upload(path)?;
    let (sha256, hashed) = hash_stream(&mut file).map_err(local(path))?;
    if hashed != size {
        return Err(CmdError::FileChanged(path.to_path_buf()));
    }
    if size == 0 {
        return Err(CmdError::Invalid(format!(
            "{} is empty; empty files are refused",
            path.display()
        )));
    }

    let req = CreateUploadRequest::from(&CreateUpload {
        kind,
        display_name,
        file_name,
        size,
        sha256,
        pe_declaration,
    });
    // The server applies the same rules; checking here means a bad value
    // is reported without a round trip.
    req.validate().map_err(|e| CmdError::Invalid(e.message))?;
    let raw = api.call(Method::Post, "/v1/uploads".into(), None, json_body!(&req)?)?;
    let session: CreateUploadResponse = parse_json!(raw)?;

    file.seek(SeekFrom::Start(0)).map_err(local(path))?;
    let seen = Arc::new(Mutex::new(Seen {
        hasher: Some(Sha256Hasher::new()),
        bytes: 0,
    }));
    let reader = HashingReader {
        inner: file.take(size),
        seen: Arc::clone(&seen),
    };
    let put = api.call(
        Method::Put,
        format!("/v1/uploads/{}", session.upload_id),
        None,
        Body::Stream {
            len: size,
            reader: Box::new(reader),
        },
    );
    let (sent_digest, sent) = match seen.lock() {
        Ok(mut s) => (s.hasher.take().map(Sha256Hasher::finish), s.bytes),
        Err(_) => (None, 0),
    };
    let accepted: UploadAccepted = match put {
        Ok(raw) => parse_json!(raw)?,
        Err(e) => {
            if sent != size {
                // Our side stopped early: cancel so the session does not
                // linger (the server also fails it, REQ-IMG-035).
                let _ = api.delete(format!("/v1/uploads/{}", session.upload_id), None);
            }
            return Err(e.into());
        }
    };
    if sent != size || sent_digest != Some(sha256) {
        return Err(CmdError::FileChanged(path.to_path_buf()));
    }
    Ok(Uploaded {
        content_id: accepted.content_id,
        state: accepted.state,
        size,
        sha256,
    })
}

/// Prints an upload result.
///
/// # Errors
///
/// [`CmdError::Output`].
pub fn print_uploaded(
    out: &mut dyn Write,
    kind: ContentKind,
    u: &Uploaded,
) -> Result<(), CmdError> {
    writeln!(out, "uploaded {} {}", kind, u.content_id)?;
    writeln!(out, "  size:   {} bytes", u.size)?;
    writeln!(out, "  sha256: {}", u.sha256)?;
    writeln!(out, "  state:  {}", u.state)?;
    writeln!(
        out,
        "the server is checking the file; see `usgp-cli {} view {}`",
        if kind == ContentKind::Image {
            "image"
        } else {
            "pe"
        },
        u.content_id
    )?;
    Ok(())
}

/// Fetches and verifies the signed content manifest of `id`.
///
/// # Errors
///
/// [`CmdError::Client`], or [`CmdError::Manifest`] if the envelope does
/// not verify with the pinned key or describes other content.
pub fn fetch_manifest<T: Transport>(
    api: &mut ApiClient<T>,
    kind: ContentKind,
    id: ContentId,
    key: &PinnedKey,
) -> Result<ContentManifestV1, CmdError> {
    let max = u64::try_from(MAX_ENVELOPE_BYTES).unwrap_or(u64::MAX);
    let bytes = api.get_bytes(format!("/v1/{}/{id}/manifest", segment(kind)), max)?;
    let env = SignedEnvelopeV1::from_json(&bytes).map_err(|e| CmdError::Manifest(e.to_string()))?;
    let m = ContentManifestV1::open(&env, key).map_err(|e| manifest_error(&e))?;
    if m.content_id != id || m.kind != kind {
        return Err(CmdError::Manifest(format!(
            "the signed manifest describes {} {}, not {kind} {id}",
            m.kind, m.content_id
        )));
    }
    Ok(m)
}

/// Text for a manifest that did not open.
#[must_use]
pub fn manifest_error(e: &SignedManifestError) -> CmdError {
    CmdError::Manifest(e.to_string())
}

/// The result of a verified download.
#[derive(Debug)]
pub struct Downloaded {
    /// The verified manifest.
    pub manifest: ContentManifestV1,
    /// The file written.
    pub path: PathBuf,
}

/// `<out>.part`.
fn part_path(out: &Path) -> PathBuf {
    let mut s = out.as_os_str().to_owned();
    s.push(".part");
    PathBuf::from(s)
}

/// Removes the partial file when dropped unless disarmed.
struct PartGuard<'a>(Option<&'a Path>);

impl Drop for PartGuard<'_> {
    fn drop(&mut self) {
        if let Some(p) = self.0 {
            let _ = fs::remove_file(p);
        }
    }
}

/// Reads exactly `buf.len()` bytes unless the stream ends first; returns
/// the count read.
fn read_full(r: &mut dyn Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while let Some(rest) = buf.get_mut(filled..) {
        if rest.is_empty() {
            break;
        }
        match r.read(rest) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Downloads `id` to `out`, verifying it against its signed manifest.
///
/// # Errors
///
/// [`CmdError`]; on any error nothing is left at `out` or `<out>.part`.
pub fn download<T: Transport>(
    api: &mut ApiClient<T>,
    kind: ContentKind,
    id: ContentId,
    out: &Path,
    key: &PinnedKey,
) -> Result<Downloaded, CmdError> {
    if fs::symlink_metadata(out).is_ok() {
        return Err(CmdError::OutputExists(out.to_path_buf()));
    }
    let manifest = fetch_manifest(api, kind, id, key)?;

    let part = part_path(out);
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(&part).map_err(|e| match e.kind() {
        io::ErrorKind::AlreadyExists => CmdError::OutputExists(part.clone()),
        kind => CmdError::Local {
            path: part.clone(),
            kind,
        },
    })?;
    let mut guard = PartGuard(Some(&part));

    let mut resp = api.send(crate::client::Request {
        method: Method::Get,
        path: format!("/v1/content/{id}"),
        if_match: None,
        body: Body::Empty,
    })?;
    if let Some(len) = resp.content_length
        && len != manifest.size
    {
        return Err(CmdError::Integrity(format!(
            "server sends {len} bytes; the signed manifest says {}",
            manifest.size
        )));
    }
    if let Some(tag) = &resp.etag
        && *tag != api::content_etag(&manifest.sha256)
    {
        return Err(CmdError::Integrity(
            "server ETag does not name the signed digest".into(),
        ));
    }

    let chunk_cap = usize::try_from(CHUNK_SIZE).unwrap_or(usize::MAX);
    let mut buf = vec![0u8; chunk_cap];
    let mut total = Sha256Hasher::new();
    let mut i = 0u64;
    while let Some((len, want)) = manifest.chunk(i) {
        let len = usize::try_from(len).unwrap_or(usize::MAX);
        let chunk = buf
            .get_mut(..len)
            .ok_or_else(|| CmdError::Integrity("chunk larger than the chunk size".into()))?;
        let got = read_full(&mut resp.body, chunk).map_err(|e| {
            CmdError::Client(ClientError::Transport(format!(
                "download broke off: {}",
                e.kind()
            )))
        })?;
        if got != len {
            return Err(CmdError::Integrity(format!(
                "content ended early in chunk {i}"
            )));
        }
        let digest = usgp_crypto::sha256(chunk);
        if digest != *want {
            return Err(CmdError::Integrity(format!(
                "chunk {i} does not match the signed manifest"
            )));
        }
        total.update(chunk);
        file.write_all(chunk).map_err(local(&part))?;
        i = i.saturating_add(1);
    }
    let mut extra = [0u8; 1];
    if read_full(&mut resp.body, &mut extra).unwrap_or(0) != 0 {
        return Err(CmdError::Integrity(
            "server sent more bytes than the signed manifest says".into(),
        ));
    }
    if total.finish() != manifest.sha256 {
        return Err(CmdError::Integrity(
            "whole-file SHA-256 does not match the signed manifest".into(),
        ));
    }
    file.sync_all().map_err(local(&part))?;
    drop(file);
    // A hard link never replaces an existing file, unlike rename.
    fs::hard_link(&part, out).map_err(|e| match e.kind() {
        io::ErrorKind::AlreadyExists => CmdError::OutputExists(out.to_path_buf()),
        kind => CmdError::Local {
            path: out.to_path_buf(),
            kind,
        },
    })?;
    guard.0 = None;
    let _ = fs::remove_file(&part);
    Ok(Downloaded {
        manifest,
        path: out.to_path_buf(),
    })
}

/// Prints a verified download.
///
/// # Errors
///
/// [`CmdError::Output`].
pub fn print_downloaded(
    out: &mut dyn Write,
    d: &Downloaded,
    key: &PinnedKey,
) -> Result<(), CmdError> {
    let m = &d.manifest;
    writeln!(
        out,
        "downloaded {} {} to {}",
        m.kind,
        m.content_id,
        d.path.display()
    )?;
    writeln!(out, "  name:   {}", esc(m.display_name.as_str()))?;
    writeln!(out, "  file:   {}", esc(m.file_name.as_str()))?;
    writeln!(out, "  size:   {} bytes", m.size)?;
    writeln!(out, "  sha256: {}", m.sha256)?;
    writeln!(
        out,
        "  verified: {} chunks and the whole file against the manifest signed by key {}",
        m.chunk_sha256.len(),
        key.id()
    )?;
    Ok(())
}

/// Asks the operator to confirm a deletion: `warning` goes to `err`, and
/// only the exact answer `yes` on `input` confirms (REQ-IMG-014). End of
/// input is a refusal.
///
/// # Errors
///
/// [`CmdError::NotConfirmed`] or [`CmdError::Output`].
pub fn confirm(
    warning: &str,
    input: &mut dyn BufRead,
    err: &mut dyn Write,
) -> Result<(), CmdError> {
    write!(err, "{warning}\nType 'yes' to delete it: ")?;
    err.flush()?;
    let mut line = String::new();
    // A bounded read: an answer longer than this is not "yes".
    input.take(64).read_line(&mut line)?;
    if line.trim_end_matches(['\n', '\r']) == "yes" {
        Ok(())
    } else {
        Err(CmdError::NotConfirmed)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::client::fake::{FakeTransport, Scripted};
    use crate::config::tests::TempDir;
    use usgp_crypto::SigningKey;
    use usgp_proto::content_manifest::{ManifestEdition, WimSummaryV1, chunk_count};
    use usgp_proto::envelope::SignatureV1;
    use usgp_proto::ids::{UnixMicros, UploadId};
    use usgp_proto::names::{EditionIndex, WimText};
    use usgp_proto::status::{ContentState, UploadState, WimCompression};
    use usgp_proto::{Architecture, KitVersion};

    use usgp_proto::envelope::PayloadType;
    const CONTENT_MANIFEST: PayloadType = PayloadType::ContentManifestV1;

    pub(crate) const ID: &str = "0b7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e6f";
    const UPLOAD: &str = "5d1e2f3a-4b5c-4d6e-8f70-8192a3b4c5d6";

    pub(crate) fn id() -> ContentId {
        ContentId::parse(ID).unwrap()
    }

    pub(crate) fn sign(key: &SigningKey, ty: PayloadType, payload: Vec<u8>) -> Vec<u8> {
        let sig = usgp_crypto::sign_typed(key, ty.as_str(), &payload).unwrap();
        let s = SignatureV1::new(key.key_id().0, SignatureAlg::EcdsaP384Sha384, sig).unwrap();
        SignedEnvelopeV1::new(ty, payload, vec![s])
            .unwrap()
            .to_json()
            .unwrap()
    }

    fn manifest_for(key: &SigningKey, data: &[u8]) -> ContentManifestV1 {
        let size = u64::try_from(data.len()).unwrap();
        let chunk = usize::try_from(CHUNK_SIZE).unwrap();
        let chunks = data.chunks(chunk).map(usgp_crypto::sha256).collect();
        assert_eq!(
            u64::try_from(data.chunks(chunk).count()).unwrap(),
            chunk_count(size)
        );
        ContentManifestV1 {
            schema: 1,
            kind: ContentKind::Image,
            content_id: id(),
            display_name: DisplayName::new("Win 11 Ent").unwrap(),
            file_name: FileName::new("install image.wim").unwrap(),
            size,
            sha256: usgp_crypto::sha256(data),
            chunk_size: CHUNK_SIZE,
            chunk_sha256: chunks,
            wim: WimSummaryV1 {
                compression: WimCompression::Xpress,
                image_count: 1,
                boot_index: 0,
                editions: vec![ManifestEdition {
                    index: EditionIndex::new(1).unwrap(),
                    name: WimText::new("Edition\x1b[2J 1").unwrap(),
                    description: WimText::new("d").unwrap(),
                    total_bytes: None,
                }],
            },
            ready_at: UnixMicros::new(1).unwrap(),
            key_id: key.key_id().0,
        }
    }

    /// Data spanning more than one chunk.
    fn data() -> Vec<u8> {
        let n = usize::try_from(CHUNK_SIZE).unwrap() + 1000;
        (0..n).map(|i| u8::try_from(i % 251).unwrap()).collect()
    }

    fn setup(
        manifest_env: Vec<u8>,
        body: Vec<u8>,
        etag: Option<String>,
    ) -> ApiClient<FakeTransport> {
        let mut content = Scripted::bytes(200, body);
        content.etag = etag;
        ApiClient::new(
            FakeTransport::default()
                .expect(
                    Method::Get,
                    &format!("/v1/images/{ID}/manifest"),
                    Scripted::bytes(200, manifest_env),
                )
                .expect(Method::Get, &format!("/v1/content/{ID}"), content),
        )
    }

    fn no_files_left(out: &Path) {
        assert!(!out.exists(), "output left behind");
        assert!(!part_path(out).exists(), ".part left behind");
    }

    #[test]
    fn good() {
        let key = SigningKey::generate().unwrap();
        let d = data();
        let m = manifest_for(&key, &d);
        let env = sign(&key, CONTENT_MANIFEST, m.to_payload().unwrap());
        let etag = api::content_etag(&m.sha256);
        let mut api = setup(env, d.clone(), Some(etag));
        let t = TempDir::new("dl");
        let out = t.0.join("install image.wim");
        let pinned = PinnedKey::new(key.verifying_key().clone());
        let got = download(&mut api, ContentKind::Image, id(), &out, &pinned).unwrap();
        assert_eq!(fs::read(&out).unwrap(), d);
        assert!(!part_path(&out).exists());
        assert!(api.transport().done());
        let mut text = Vec::new();
        print_downloaded(&mut text, &got, &pinned).unwrap();
        let text = String::from_utf8(text).unwrap();
        assert!(text.contains("verified: 2 chunks"), "{text}");
    }

    #[test]
    fn tampered_chunk() {
        let key = SigningKey::generate().unwrap();
        let d = data();
        let m = manifest_for(&key, &d);
        let env = sign(&key, CONTENT_MANIFEST, m.to_payload().unwrap());
        for flip in [0usize, d.len() - 1] {
            let mut bad = d.clone();
            *bad.get_mut(flip).unwrap() ^= 1;
            let mut api = setup(env.clone(), bad, None);
            let t = TempDir::new("dlbad");
            let out = t.0.join("x.wim");
            let pinned = PinnedKey::new(key.verifying_key().clone());
            let e = download(&mut api, ContentKind::Image, id(), &out, &pinned).unwrap_err();
            assert!(matches!(e, CmdError::Integrity(_)), "{e}");
            no_files_left(&out);
        }
    }

    #[test]
    fn truncated_or_extended_content() {
        let key = SigningKey::generate().unwrap();
        let d = data();
        let m = manifest_for(&key, &d);
        let env = sign(&key, CONTENT_MANIFEST, m.to_payload().unwrap());
        let mut short = d.clone();
        short.pop();
        let mut long = d.clone();
        long.push(0);
        for body in [short, long, Vec::new()] {
            let mut resp_api = setup(env.clone(), body, None);
            let t = TempDir::new("dltrunc");
            let out = t.0.join("x.wim");
            let pinned = PinnedKey::new(key.verifying_key().clone());
            // Content-Length disagrees with the manifest: refused up front.
            let e = download(&mut resp_api, ContentKind::Image, id(), &out, &pinned).unwrap_err();
            assert!(matches!(e, CmdError::Integrity(_)), "{e}");
            no_files_left(&out);
        }
        // Without Content-Length, the stream itself is checked.
        let mut short = d.clone();
        short.truncate(d.len() - 10);
        let mut content = Scripted::bytes(200, short);
        content.content_length = None;
        let mut api = ApiClient::new(
            FakeTransport::default()
                .expect(
                    Method::Get,
                    &format!("/v1/images/{ID}/manifest"),
                    Scripted::bytes(200, env),
                )
                .expect(Method::Get, &format!("/v1/content/{ID}"), content),
        );
        let t = TempDir::new("dltrunc2");
        let out = t.0.join("x.wim");
        let pinned = PinnedKey::new(key.verifying_key().clone());
        let e = download(&mut api, ContentKind::Image, id(), &out, &pinned).unwrap_err();
        assert!(e.to_string().contains("ended early"), "{e}");
        no_files_left(&out);
    }

    #[test]
    fn bad_signature() {
        let key = SigningKey::generate().unwrap();
        let other = SigningKey::generate().unwrap();
        let d = data();
        // Signed by a key the operator did not pin.
        let m = manifest_for(&other, &d);
        let env = sign(&other, CONTENT_MANIFEST, m.to_payload().unwrap());
        let pinned = PinnedKey::new(key.verifying_key().clone());
        let t = TempDir::new("dlsig");
        let out = t.0.join("x.wim");
        let mut api = ApiClient::new(FakeTransport::default().expect(
            Method::Get,
            &format!("/v1/images/{ID}/manifest"),
            Scripted::bytes(200, env),
        ));
        let e = download(&mut api, ContentKind::Image, id(), &out, &pinned).unwrap_err();
        assert!(matches!(e, CmdError::Manifest(_)), "{e}");
        no_files_left(&out);
        // The content itself was never requested.
        assert_eq!(api.transport().seen.len(), 1);

        // Right key, payload altered after signing.
        let m = manifest_for(&key, &d);
        let payload = m.to_payload().unwrap();
        let sig = usgp_crypto::sign_typed(&key, CONTENT_MANIFEST.as_str(), &payload).unwrap();
        let mut altered = m.clone();
        altered.size -= 1;
        altered
            .chunk_sha256
            .truncate(usize::try_from(chunk_count(altered.size)).unwrap());
        let s = SignatureV1::new(key.key_id().0, SignatureAlg::EcdsaP384Sha384, sig).unwrap();
        let env = SignedEnvelopeV1::new(CONTENT_MANIFEST, altered.to_payload().unwrap(), vec![s])
            .unwrap()
            .to_json()
            .unwrap();
        let mut api = ApiClient::new(FakeTransport::default().expect(
            Method::Get,
            &format!("/v1/images/{ID}/manifest"),
            Scripted::bytes(200, env),
        ));
        let e = download(&mut api, ContentKind::Image, id(), &out, &pinned).unwrap_err();
        assert!(matches!(e, CmdError::Manifest(_)), "{e}");

        // A validly signed package manifest is not a content manifest.
        let env = sign(
            &key,
            PayloadType::PackageManifestV1,
            m.to_payload().unwrap(),
        );
        let mut api = ApiClient::new(FakeTransport::default().expect(
            Method::Get,
            &format!("/v1/images/{ID}/manifest"),
            Scripted::bytes(200, env),
        ));
        let e = download(&mut api, ContentKind::Image, id(), &out, &pinned).unwrap_err();
        assert!(matches!(e, CmdError::Manifest(_)), "{e}");
        no_files_left(&out);
    }

    #[test]
    fn manifest_for_other_content_refused() {
        let key = SigningKey::generate().unwrap();
        let mut m = manifest_for(&key, b"abc");
        m.content_id = ContentId::parse("1c9e8a70-2b3d-4e5f-9a0b-c1d2e3f40516").unwrap();
        let env = sign(&key, CONTENT_MANIFEST, m.to_payload().unwrap());
        let mut api = ApiClient::new(FakeTransport::default().expect(
            Method::Get,
            &format!("/v1/images/{ID}/manifest"),
            Scripted::bytes(200, env),
        ));
        let pinned = PinnedKey::new(key.verifying_key().clone());
        let e = fetch_manifest(&mut api, ContentKind::Image, id(), &pinned).unwrap_err();
        assert!(e.to_string().contains("not image"), "{e}");
    }

    #[test]
    fn wrong_etag_refused() {
        let key = SigningKey::generate().unwrap();
        let m = manifest_for(&key, b"abc");
        let env = sign(&key, CONTENT_MANIFEST, m.to_payload().unwrap());
        let mut api = setup(env, b"abc".to_vec(), Some("\"sha256:00\"".into()));
        let t = TempDir::new("dletag");
        let out = t.0.join("x.wim");
        let pinned = PinnedKey::new(key.verifying_key().clone());
        let e = download(&mut api, ContentKind::Image, id(), &out, &pinned).unwrap_err();
        assert!(matches!(e, CmdError::Integrity(_)), "{e}");
        no_files_left(&out);
    }

    #[test]
    fn existing_output_never_overwritten() {
        let key = SigningKey::generate().unwrap();
        let t = TempDir::new("dlexists");
        let out = t.put("x.wim", b"mine", 0o600);
        let mut api = ApiClient::new(FakeTransport::default());
        let pinned = PinnedKey::new(key.verifying_key().clone());
        let e = download(&mut api, ContentKind::Image, id(), &out, &pinned).unwrap_err();
        assert!(matches!(e, CmdError::OutputExists(_)));
        assert_eq!(fs::read(&out).unwrap(), b"mine");
        assert!(api.transport().seen.is_empty());
    }

    #[test]
    fn confirm_needs_exact_yes() {
        let mut err = Vec::new();
        assert!(confirm("delete X?", &mut &b"yes\n"[..], &mut err).is_ok());
        assert!(String::from_utf8(err).unwrap().contains("delete X?"));
        for answer in [&b""[..], b"y\n", b"YES\n", b"no\n", b" yes\n", b"yesyes\n"] {
            assert!(matches!(
                confirm("w", &mut &answer[..], &mut Vec::new()),
                Err(CmdError::NotConfirmed)
            ));
        }
    }

    #[test]
    fn signing_input_split_round_trips() {
        let msg = usgp_proto::signing_input(CONTENT_MANIFEST, b"{\"a\":1}\n\n");
        assert_eq!(
            split_signing_input(&msg),
            Some((CONTENT_MANIFEST.as_str(), &b"{\"a\":1}\n\n"[..]))
        );
        assert_eq!(split_signing_input(b"USGP-SIG-V1\nt\n3\nab"), None);
        assert_eq!(split_signing_input(b"OTHER\nt\n2\nab"), None);
        assert_eq!(split_signing_input(b"USGP-SIG-V1\nt"), None);
    }

    fn upload_session() -> CreateUploadResponse {
        CreateUploadResponse {
            upload_id: UploadId::parse(UPLOAD).unwrap(),
            content_id: id(),
            state: UploadState::Open,
            expires_at: UnixMicros::new(2).unwrap(),
        }
    }

    fn accepted() -> UploadAccepted {
        UploadAccepted {
            content_id: id(),
            state: ContentState::Checking,
        }
    }

    #[test]
    fn upload_streams_declared_size_and_digest() {
        let t = TempDir::new("up");
        let d = data();
        let path = t.put("install image.wim", &d, 0o600);
        let mut api = ApiClient::new(
            FakeTransport::default()
                .expect(
                    Method::Post,
                    "/v1/uploads",
                    Scripted::bytes(201, serde_json::to_vec(&upload_session()).unwrap()),
                )
                .expect(
                    Method::Put,
                    &format!("/v1/uploads/{UPLOAD}"),
                    Scripted::bytes(202, serde_json::to_vec(&accepted()).unwrap()),
                ),
        );
        let u = upload(&mut api, ContentKind::Image, &path, "Win 11", None).unwrap();
        assert_eq!(u.state, ContentState::Checking);
        let seen = &api.transport().seen;
        let (first, second) = (seen.first().unwrap(), seen.get(1).unwrap());
        let create: CreateUploadRequest = serde_json::from_slice(&first.body).unwrap();
        assert_eq!(create.kind, "image");
        assert_eq!(create.file_name, "install image.wim");
        assert_eq!(create.size, u64::try_from(d.len()).unwrap());
        assert_eq!(create.sha256, usgp_crypto::sha256(&d).to_hex());
        assert_eq!(create.pe_declaration, None);
        assert_eq!(second.stream_len, Some(create.size));
        assert_eq!(second.body, d);
    }

    #[test]
    fn pe_upload_carries_declaration() {
        let t = TempDir::new("pe");
        let path = t.put("boot.wim", b"pe-bytes", 0o600);
        let mut api = ApiClient::new(
            FakeTransport::default()
                .expect(
                    Method::Post,
                    "/v1/uploads",
                    Scripted::bytes(201, serde_json::to_vec(&upload_session()).unwrap()),
                )
                .expect(
                    Method::Put,
                    &format!("/v1/uploads/{UPLOAD}"),
                    Scripted::bytes(202, serde_json::to_vec(&accepted()).unwrap()),
                ),
        );
        let decl = PeDeclaration {
            architecture: Architecture::X64,
            kit_version: KitVersion::parse("10.1.26100.1").unwrap(),
        };
        upload(&mut api, ContentKind::Pe, &path, "PE", Some(decl)).unwrap();
        let create: CreateUploadRequest =
            serde_json::from_slice(&api.transport().seen.first().unwrap().body).unwrap();
        let d = create.pe_declaration.unwrap();
        assert_eq!(
            (d.architecture.as_str(), d.kit_version.as_str()),
            ("x64", "10.1.26100.1")
        );
    }

    #[test]
    fn upload_refusals_send_no_body() {
        let t = TempDir::new("upbad");
        let empty = t.put("empty.wim", b"", 0o600);
        let mut api = ApiClient::new(FakeTransport::default());
        assert!(upload(&mut api, ContentKind::Image, &empty, "x", None).is_err());
        let ok = t.put("a.wim", b"abc", 0o600);
        assert!(upload(&mut api, ContentKind::Image, &ok, "bad\nname", None).is_err());
        // PE without a declaration is refused locally.
        assert!(upload(&mut api, ContentKind::Pe, &ok, "x", None).is_err());
        assert!(upload(&mut api, ContentKind::Image, &t.0, "x", None).is_err());
        assert!(api.transport().seen.is_empty());

        // The server refuses the session (413 with limit): no PUT follows.
        let mut body = api::ErrorBody::new(
            usgp_proto::ErrorCode::new("too_large").unwrap(),
            api::Message::new("too large").unwrap(),
        );
        body.error.limit_bytes = Some(2);
        let mut api = ApiClient::new(FakeTransport::default().expect(
            Method::Post,
            "/v1/uploads",
            Scripted::bytes(413, serde_json::to_vec(&body).unwrap()),
        ));
        let e = upload(&mut api, ContentKind::Image, &ok, "x", None).unwrap_err();
        assert!(e.to_string().contains("limit 2 bytes"), "{e}");
        assert_eq!(api.transport().seen.len(), 1);
    }
}
