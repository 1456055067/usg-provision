//! Signing keys: generation (`usgp-server keygen`) and loading (plan M2
//! section 5.2).
//!
//! - Keys are ECDSA P-384, generated inside the FIPS module
//!   ([`SigningKey::generate`]).
//! - The private key is written as PKCS#8 PEM to a **new** file (`O_CREAT
//!   | O_EXCL`, so an existing file or a symbolic link at that path is
//!   refused), mode 0600, owned by the invoking administrator. The public
//!   key is SPKI PEM, mode 0644. The operator then sets the private key
//!   to `root:usgp-server 0640` (docs/operations/server.md).
//! - At start-up, keys are read under the trusted-file rules into wiped
//!   buffers ([`crate::files`]); the PEM is wiped once the key object is
//!   built. Keys are never logged; `SigningKey`'s `Debug` is redacted.
//! - Public keys used to verify (audit `--trusted-key`, earlier content
//!   keys) come from files, never from the database.

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-12 (Cryptographic Key Establishment and Management) -
//   keys generated in the validated module; exclusive create, 0600.
// - NIST 800-53: SC-13 - FIPS 186-5 ECDSA P-384 via usgp-crypto.
// - NIST 800-53: SC-12, SC-4 (Information in Shared System Resources) -
//   private key buffers are zeroized; key files refused if readable by
//   others or by a group other than the service's.
// - NIST 800-53: SC-28 (partial: operating-system access control only,
//   no encryption at rest) - new key files are created exclusively
//   (O_CREAT|O_EXCL, no symlink followed), mode 0600.
// - NIST 800-53: AU-12 - key generation is reported as an unpersisted
//   `key.generated` mirror event (no database is reachable; finding
//   NIST-011); a failed attempt as `key.generation.failed` (NIST-016).
// - SPEC: plan M2 section 5.2; decisions 0001, 0011
// POAM: SC-28 - private keys are plaintext PKCS#8 files protected by
// owner and mode only; no encryption at rest. Signing keys are files on
// the server host; there is no HSM
// (PKCS#11 would need a C library). A root compromise of the host can sign
// manifests and checkpoints (plan section 5.2).

use std::io::Write;
use std::path::{Path, PathBuf};

use usgp_common::config::{ConfigError, TrustPolicy};
use usgp_crypto::pem::{MAX_KEY_PEM_BYTES, MAX_PUBLIC_KEY_PEM_BYTES};
use usgp_crypto::{CryptoError, KeyId, SigningKey, VerifyingKey};

use crate::cli::KeyPurpose;
use crate::files::{PrivateKeyFileError, read_private_key};

/// Why a key could not be loaded. Names the key and file; never the
/// content.
#[derive(Debug, thiserror::Error)]
pub enum KeyLoadError {
    /// The file failed a trust rule or could not be read.
    #[error("{key}: {source}")]
    File {
        /// The configuration key or option.
        key: String,
        /// The file error.
        #[source]
        source: ConfigError,
    },
    /// A private key file is readable beyond its owner and the service's
    /// group, or failed a trust rule.
    #[error("{key}: {source}")]
    KeyFile {
        /// The configuration key or option.
        key: String,
        /// The file error.
        #[source]
        source: PrivateKeyFileError,
    },
    /// The file did not hold an acceptable key.
    #[error("{key}: {source}")]
    Key {
        /// The configuration key or option.
        key: String,
        /// The crypto error (carries no key bytes).
        #[source]
        source: CryptoError,
    },
}

impl KeyLoadError {
    /// The configuration key or option named.
    #[must_use]
    pub fn key(&self) -> &str {
        match self {
            Self::File { key, .. } | Self::KeyFile { key, .. } | Self::Key { key, .. } => key,
        }
    }
}

/// Loads a PKCS#8 PEM signing key from a trusted file.
///
/// # Errors
///
/// [`KeyLoadError`].
pub fn load_signing_key(
    key: &str,
    path: &Path,
    policy: &TrustPolicy,
) -> Result<SigningKey, KeyLoadError> {
    let pem = read_private_key(path, wide(MAX_KEY_PEM_BYTES), policy).map_err(|source| {
        KeyLoadError::KeyFile {
            key: key.to_owned(),
            source,
        }
    })?;
    // `pem` is wiped when it goes out of scope.
    SigningKey::from_pkcs8_pem(&pem).map_err(|source| KeyLoadError::Key {
        key: key.to_owned(),
        source,
    })
}

/// Loads an SPKI PEM public key from a trusted file.
///
/// # Errors
///
/// [`KeyLoadError`].
pub fn load_verifying_key(
    key: &str,
    path: &Path,
    policy: &TrustPolicy,
) -> Result<VerifyingKey, KeyLoadError> {
    let pem = crate::files::read_trusted_public(path, wide(MAX_PUBLIC_KEY_PEM_BYTES), policy)
        .map_err(|source| KeyLoadError::File {
            key: key.to_owned(),
            source,
        })?;
    VerifyingKey::from_spki_pem(&pem).map_err(|source| KeyLoadError::Key {
        key: key.to_owned(),
        source,
    })
}

fn wide(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// Why `keygen` failed.
#[derive(Debug, thiserror::Error)]
pub enum KeygenError {
    /// Generation or encoding in the module failed.
    #[error("key generation failed: {0}")]
    Crypto(#[from] CryptoError),
    /// An output file could not be created (it exists, is a link, or the
    /// directory is not writable) or written.
    #[error("cannot write {}: {kind}", path.display())]
    Write {
        /// The file.
        path: PathBuf,
        /// The I/O error kind.
        kind: std::io::ErrorKind,
    },
}

/// The result of `keygen`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Generated {
    /// Purpose label.
    pub purpose: KeyPurpose,
    /// Key id (SHA-256 of the SPKI DER).
    pub key_id: KeyId,
}

/// Generates a key and writes both files. Neither file may exist; if any
/// step fails, files this call created are removed.
///
/// # Errors
///
/// [`KeygenError`].
pub fn keygen(
    purpose: KeyPurpose,
    out_key: &Path,
    out_pub: &Path,
) -> Result<Generated, KeygenError> {
    let key = SigningKey::generate()?;
    let private_pem = key.to_pkcs8_pem()?;
    let public_pem = key.verifying_key().to_spki_pem()?;
    // Create both files first, so an existing public-key file is refused
    // before the private key is written.
    let mut priv_file = create_new(out_key, 0o600)?;
    let mut pub_file = match create_new(out_pub, 0o644) {
        Ok(f) => f,
        Err(e) => {
            drop(priv_file);
            let _ = std::fs::remove_file(out_key);
            return Err(e);
        }
    };
    let written = write_all(&mut priv_file, out_key, &private_pem)
        .and_then(|()| write_all(&mut pub_file, out_pub, public_pem.as_bytes()));
    if let Err(e) = written {
        drop(priv_file);
        drop(pub_file);
        let _ = std::fs::remove_file(out_key);
        let _ = std::fs::remove_file(out_pub);
        return Err(e);
    }
    Ok(Generated {
        purpose,
        key_id: key.key_id(),
    })
}

/// The `key.generated` event for a key `keygen` just wrote (finding
/// NIST-011): purpose, key id, the local uid and node. `keygen` has no
/// database connection, so the caller mirrors it unpersisted; the key id
/// is also printed for the administrator to record out of band.
#[must_use]
pub fn generated_draft(g: &Generated, uid: Option<u32>) -> usgp_audit::AuditDraft {
    let actor = uid.map_or_else(usgp_audit::Actor::system, |u| {
        usgp_audit::Actor::local_user(u, None)
    });
    let mut d = usgp_audit::AuditDraft::new(
        "key.generated",
        usgp_audit::Outcome::Success,
        actor,
        usgp_audit::Interface::ServerCli,
    )
    .target("signing_key", &g.key_id.to_string())
    .detail(
        usgp_audit::Detail::new()
            .with("purpose", g.purpose.as_str())
            .with("key_id", &g.key_id),
    );
    if let Some(u) = uid {
        d = d.source(&format!("uid:{u}"));
    }
    d
}

/// The `key.generation.failed` event for a `keygen` that failed (finding
/// NIST-016): purpose, the reason (`crypto_failure` or `write_failed`
/// with the I/O error kind and the file's name, not its directory), the
/// local uid. Mirrored unpersisted, like `key.generated`.
#[must_use]
pub fn generation_failed_draft(
    purpose: KeyPurpose,
    err: &KeygenError,
    uid: Option<u32>,
) -> usgp_audit::AuditDraft {
    let actor = uid.map_or_else(usgp_audit::Actor::system, |u| {
        usgp_audit::Actor::local_user(u, None)
    });
    let mut detail = usgp_audit::Detail::new().with("purpose", purpose.as_str());
    let reason = match err {
        KeygenError::Crypto(_) => "crypto_failure",
        KeygenError::Write { path, kind } => {
            let name = path
                .file_name()
                .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
            detail = detail
                .with("file", &name)
                .with("io_kind", &format!("{kind:?}"));
            "write_failed"
        }
    };
    let mut d = usgp_audit::AuditDraft::new(
        "key.generation.failed",
        usgp_audit::Outcome::Failure,
        actor,
        usgp_audit::Interface::ServerCli,
    )
    .reason(reason)
    .detail(detail);
    if let Some(u) = uid {
        d = d.source(&format!("uid:{u}"));
    }
    d
}

fn create_new(path: &Path, mode: u32) -> Result<std::fs::File, KeygenError> {
    let mut o = std::fs::OpenOptions::new();
    // `create_new` is O_CREAT | O_EXCL: an existing file, or a symbolic
    // link at the final component, is refused (never followed).
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    o.open(path).map_err(|e| KeygenError::Write {
        path: path.to_path_buf(),
        kind: e.kind(),
    })
}

fn write_all(f: &mut std::fs::File, path: &Path, bytes: &[u8]) -> Result<(), KeygenError> {
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|e| KeygenError::Write {
            path: path.to_path_buf(),
            kind: e.kind(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NIST-011: the `key.generated` event names purpose, key id, uid.
    #[test]
    fn generated_event_fields() {
        let key = SigningKey::generate().unwrap();
        let g = Generated {
            purpose: KeyPurpose::Audit,
            key_id: key.key_id(),
        };
        let d = generated_draft(&g, Some(1234));
        assert_eq!(d.event(), "key.generated");
        d.validate().unwrap();
        let chain = usgp_audit::AuditChain::new("node-a").unwrap();
        let fields = usgp_audit::mirror::unpersisted_fields(&chain, &d);
        let text = format!("{fields:?}");
        assert!(!text.contains("draft_invalid"), "{text}");
        assert!(text.contains("uid:1234"), "{text}");
        assert!(text.contains("audit"), "{text}");
        assert!(text.contains(&key.key_id().to_string()), "{text}");
        assert!(text.contains("node-a"), "{text}");
    }

    /// NIST-016: a failed keygen yields `key.generation.failed` with the
    /// reason, the file name only and the uid.
    #[test]
    fn failed_event_fields() {
        let err = KeygenError::Write {
            path: PathBuf::from("/secret/dir/audit.p8"),
            kind: std::io::ErrorKind::AlreadyExists,
        };
        let d = generation_failed_draft(KeyPurpose::Audit, &err, Some(77));
        assert_eq!(d.event(), "key.generation.failed");
        d.validate().unwrap();
        let chain = usgp_audit::AuditChain::new("node-b").unwrap();
        let text = format!("{:?}", usgp_audit::mirror::unpersisted_fields(&chain, &d));
        assert!(!text.contains("draft_invalid"), "{text}");
        assert!(text.contains("write_failed"), "{text}");
        assert!(text.contains("audit.p8"), "{text}");
        assert!(text.contains("AlreadyExists"), "{text}");
        assert!(!text.contains("/secret/dir"), "{text}");
        assert!(text.contains("uid:77"), "{text}");
        assert_eq!(d.outcome(), usgp_audit::Outcome::Failure);
    }
}
