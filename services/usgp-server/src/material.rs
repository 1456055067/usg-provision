//! Reads the TLS and database files the configuration names and builds
//! the `usgp-crypto` / `usgp-db` settings from them (plan M2 sections 5.4
//! and 5.5).
//!
//! Every file is read under the trusted-file rules ([`crate::files`]);
//! private keys must also not be readable by others (nor by the group,
//! unless it is the service's group) and land in wiped buffers; the admin
//! and owner database keys must be readable by their owner only
//! (finding SEC-011). Size limits are those of `usgp_crypto::pem`.

// COMPLIANCE MAPPING:
// - NIST 800-53: IA-2, IA-5(2) - operator trust anchors and CRLs (at
//   least one) are required; the acceptor is built only from trusted files.
// - NIST 800-53: SC-8, SC-13 - the TLS acceptor is built by usgp-crypto on
//   the FIPS provider (its `fips()` is asserted there).
// - NIST 800-53: IA-5(2), SC-13 - certificate-only database login:
//   `assert_certificate_only` (decision 0012).
// - NIST 800-53: CM-5 / SI-7 - trusted files only.
// - NIST 800-53: SC-8, SC-13 - the device listener's TLS authenticates
//   the server only (decision 0020), FIPS provider. Devices hold no
//   certificate: IA-3 for devices is partial (POAM in
//   `usgp_api::device::auth`).
// - SPEC: specs/operator-access.md#REQ-RBAC-005; plan sections 5.4, 5.5

use std::collections::BTreeMap;
use std::path::Path;

use usgp_common::Sha256Digest;
use usgp_common::config::{ConfigError, TrustPolicy};
use usgp_crypto::pem::{MAX_CERT_PEM_BYTES, MAX_CRL_BYTES, MAX_KEY_PEM_BYTES};
use usgp_crypto::tls::{
    DeviceServerTls, DeviceServerTlsSettings, ServerTls, ServerTlsSettings, TlsMinVersion,
};
use usgp_crypto::{CrlNumber, CryptoError, Sha256Hasher};
use usgp_db::DbSettings;

use crate::config::{DB_APPLICATION_NAME, DatabaseConfig, DeviceListenerConfig, TlsConfig};
use crate::files::{KeyAccess, read_private_key, read_private_key_with, read_trusted_public};

/// Why TLS or database material could not be loaded (exit 78). Names the
/// key and file; never the content.
#[derive(Debug, thiserror::Error)]
pub enum MaterialError {
    /// A file failed a trust rule or could not be read.
    #[error("{key}: {source}")]
    File {
        /// The configuration key.
        key: String,
        /// The file error.
        #[source]
        source: ConfigError,
    },
    /// The files did not form a usable TLS configuration.
    #[error("{key}: {source}")]
    Crypto {
        /// The configuration section or key.
        key: String,
        /// The crypto error (no key bytes).
        #[source]
        source: CryptoError,
    },
    /// The database settings were refused (decision 0012).
    #[error("{0}")]
    Database(#[from] usgp_db::DbError),
    /// A private key file is readable beyond its owner and the service's
    /// group (finding SEC-005), or failed a trust rule.
    #[error("{key}: {source}")]
    KeyFile {
        /// The configuration key.
        key: String,
        /// The file error.
        #[source]
        source: crate::files::PrivateKeyFileError,
    },
    /// A section the command needs is not configured.
    #[error("{key} is required for this command")]
    Missing {
        /// The configuration key.
        key: String,
    },
}

impl MaterialError {
    /// The configuration key named in the refusal record.
    #[must_use]
    pub fn key(&self) -> String {
        match self {
            Self::File { key, .. }
            | Self::Crypto { key, .. }
            | Self::KeyFile { key, .. }
            | Self::Missing { key } => key.clone(),
            Self::Database(_) => "database".to_owned(),
        }
    }
}

fn wide(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

fn key_err(key: &str) -> impl FnOnce(crate::files::PrivateKeyFileError) -> MaterialError + '_ {
    move |source| MaterialError::KeyFile {
        key: key.to_owned(),
        source,
    }
}

fn file_err(key: &str) -> impl FnOnce(ConfigError) -> MaterialError + '_ {
    move |source| MaterialError::File {
        key: key.to_owned(),
        source,
    }
}

/// The CRL files, read now, the SHA-256 of the set (to notice a change on
/// reload), and the CRL numbers per issuer (to refuse a rollback, finding
/// SEC-007).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrlSet {
    /// Each file's bytes (PEM or DER).
    pub crls: Vec<Vec<u8>>,
    /// SHA-256 over every file as `u64 BE length || bytes`, in order.
    pub digest: Sha256Digest,
    /// Per issuer (RFC 4514 text): the lowest and highest cRLNumber in
    /// the set, or `None` if one of its CRLs has no cRLNumber.
    pub numbers: BTreeMap<String, Option<(CrlNumber, CrlNumber)>>,
}

/// A reloaded CRL set that would roll an issuer's CRL back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrlRollback {
    /// The issuer.
    pub issuer: String,
    /// The highest number loaded now.
    pub loaded: CrlNumber,
    /// The lowest number offered (`None`: a CRL without a cRLNumber).
    pub offered: Option<CrlNumber>,
}

impl CrlSet {
    /// The first issuer for which `self` (the new set) has a CRL whose
    /// number is lower than the highest number in `loaded`, or has no
    /// number where `loaded` had one (RFC 5280 §5.2.3: CRL numbers only
    /// increase). Equal numbers are accepted. An issuer with no number in
    /// `loaded` cannot be compared and is accepted.
    #[must_use]
    pub fn rollback_from(&self, loaded: &Self) -> Option<CrlRollback> {
        for (issuer, offered) in &self.numbers {
            let Some(Some((_, high))) = loaded.numbers.get(issuer) else {
                continue;
            };
            match offered {
                Some((low, _)) if low >= high => {}
                _ => {
                    return Some(CrlRollback {
                        issuer: issuer.clone(),
                        loaded: high.clone(),
                        offered: offered.as_ref().map(|(low, _)| low.clone()),
                    });
                }
            }
        }
        None
    }
}

/// Reads every `tls.client_crls` file and the CRL numbers in it.
///
/// # Errors
///
/// [`MaterialError::File`]; [`MaterialError::Crypto`] if a file holds no
/// parsable CRL.
pub fn read_crls(tls: &TlsConfig, policy: &TrustPolicy) -> Result<CrlSet, MaterialError> {
    let mut crls = Vec::with_capacity(tls.client_crls.len());
    let mut numbers: BTreeMap<String, Option<(CrlNumber, CrlNumber)>> = BTreeMap::new();
    let mut h = Sha256Hasher::new();
    for (i, p) in tls.client_crls.iter().enumerate() {
        let key = format!("tls.client_crls[{i}]");
        let bytes = read_trusted_public(p, wide(MAX_CRL_BYTES), policy).map_err(file_err(&key))?;
        let facts = usgp_crypto::crl_facts(&bytes).map_err(|source| MaterialError::Crypto {
            key: key.clone(),
            source,
        })?;
        for f in facts {
            let entry = numbers
                .entry(f.issuer)
                .or_insert_with(|| f.number.clone().map(|n| (n.clone(), n)));
            *entry = match (entry.take(), f.number) {
                (Some((low, high)), Some(n)) => Some((low.min(n.clone()), high.max(n))),
                _ => None,
            };
        }
        h.update(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
        h.update(&bytes);
        crls.push(bytes);
    }
    Ok(CrlSet {
        crls,
        digest: h.finish(),
        numbers,
    })
}

/// Builds the TLS acceptor from the configured files and `crls`.
///
/// # Errors
///
/// [`MaterialError`].
pub fn build_server_tls(
    tls: &TlsConfig,
    crls: &CrlSet,
    policy: &TrustPolicy,
) -> Result<ServerTls, MaterialError> {
    let cert_chain_pem = read_trusted_public(&tls.cert_chain, wide(MAX_CERT_PEM_BYTES), policy)
        .map_err(file_err("tls.cert_chain"))?;
    let client_trust_anchors_pem =
        read_trusted_public(&tls.client_trust_anchors, wide(MAX_CERT_PEM_BYTES), policy)
            .map_err(file_err("tls.client_trust_anchors"))?;
    let private_key_pem = read_private_key(&tls.private_key, wide(MAX_KEY_PEM_BYTES), policy)
        .map_err(key_err("tls.private_key"))?;
    let settings = ServerTlsSettings {
        cert_chain_pem,
        private_key_pem,
        min_version: tls.min_version,
        client_trust_anchors_pem,
        client_crls: crls.crls.clone(),
        acceptable_policy_oids: tls.acceptable_policy_oids.clone(),
    };
    // `settings.private_key_pem` is wiped when `settings` drops.
    ServerTls::new(&settings).map_err(|source| MaterialError::Crypto {
        key: "tls".to_owned(),
        source,
    })
}

/// Builds the device listener's TLS configuration (server authentication
/// only, decision 0020; FIPS asserted by usgp-crypto) from
/// `[device_api] cert_chain` and `private_key`, read under the same rules
/// as the operator listener's files.
///
/// # Errors
///
/// [`MaterialError`].
pub fn build_device_tls(
    d: &DeviceListenerConfig,
    policy: &TrustPolicy,
) -> Result<DeviceServerTls, MaterialError> {
    let cert_chain_pem = read_trusted_public(&d.cert_chain, wide(MAX_CERT_PEM_BYTES), policy)
        .map_err(file_err("device_api.cert_chain"))?;
    let private_key_pem = read_private_key(&d.private_key, wide(MAX_KEY_PEM_BYTES), policy)
        .map_err(key_err("device_api.private_key"))?;
    let settings = DeviceServerTlsSettings {
        cert_chain_pem,
        private_key_pem,
        min_version: d.min_version,
    };
    // `settings.private_key_pem` is wiped when `settings` drops.
    DeviceServerTls::new(&settings).map_err(|source| MaterialError::Crypto {
        key: "device_api".to_owned(),
        source,
    })
}

/// Which role's client certificate the database settings use.
#[derive(Debug, Clone, Copy)]
pub enum DbRole<'a> {
    /// The application role of `[database]` (`serve`, `--check-config`).
    App,
    /// The administrative role of `[database.admin]` (`operator enrol`,
    /// `operator disable`, `audit verify`; decision 0016).
    Admin,
    /// The owner role (`migrate`), given on the command line so the
    /// service never holds owner credentials.
    Owner {
        /// Role name.
        user: &'a str,
        /// Client certificate (PEM).
        cert: &'a Path,
        /// Client key (PKCS#8 PEM).
        key: &'a Path,
    },
}

/// Builds the database settings and runs
/// [`usgp_db::assert_certificate_only`] on them (decision 0012).
///
/// # Errors
///
/// [`MaterialError`].
pub fn db_settings(
    db: &DatabaseConfig,
    role: DbRole<'_>,
    policy: &TrustPolicy,
) -> Result<DbSettings, MaterialError> {
    // SEC-011: admin and owner keys are owner-only (0600/0400), whoever
    // runs the command; only the service's own key may be 0640.
    let (user, cert, key, cert_key, key_key, access) = match role {
        DbRole::App => (
            db.user.as_str(),
            db.client_cert.as_path(),
            db.client_key.as_path(),
            "database.client_cert",
            "database.client_key",
            KeyAccess::Service,
        ),
        DbRole::Admin => {
            let a = db.admin.as_ref().ok_or_else(|| MaterialError::Missing {
                key: "database.admin".to_owned(),
            })?;
            (
                a.user.as_str(),
                a.client_cert.as_path(),
                a.client_key.as_path(),
                "database.admin.client_cert",
                "database.admin.client_key",
                KeyAccess::OwnerOnly,
            )
        }
        DbRole::Owner { user, cert, key } => (
            user,
            cert,
            key,
            "--owner-cert",
            "--owner-key",
            KeyAccess::OwnerOnly,
        ),
    };
    let server_ca_pem = read_trusted_public(&db.server_ca, wide(MAX_CERT_PEM_BYTES), policy)
        .map_err(file_err("database.server_ca"))?;
    let client_cert_pem =
        read_trusted_public(cert, wide(MAX_CERT_PEM_BYTES), policy).map_err(file_err(cert_key))?;
    let client_key_pem = read_private_key_with(key, wide(MAX_KEY_PEM_BYTES), policy, access)
        .map_err(key_err(key_key))?;
    let s = DbSettings {
        host: db.host.clone(),
        port: db.port,
        dbname: db.dbname.clone(),
        user: user.to_owned(),
        server_name: db.server_name.clone(),
        server_ca_pem,
        client_cert_pem,
        client_key_pem,
        min_tls: TlsMinVersion::Tls12,
        pool_size: db.pool_size,
        connect_timeout: db.connect_timeout,
        application_name: DB_APPLICATION_NAME.to_owned(),
    };
    usgp_db::assert_certificate_only(&s).map_err(usgp_db::DbError::from)?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(v: u8) -> CrlNumber {
        CrlNumber::from_be_bytes(&[v]).unwrap()
    }

    fn set(entries: &[(&str, Option<(u8, u8)>)]) -> CrlSet {
        CrlSet {
            crls: Vec::new(),
            digest: Sha256Digest([0; 32]),
            numbers: entries
                .iter()
                .map(|(i, r)| ((*i).to_owned(), r.map(|(lo, hi)| (n(lo), n(hi)))))
                .collect(),
        }
    }

    /// SEC-007: lower or missing numbers for a known issuer are a
    /// rollback; equal or higher numbers, and new issuers, are not.
    #[test]
    fn rollback_rules() {
        let loaded = set(&[("CN=a", Some((3, 3))), ("CN=b", None)]);
        assert_eq!(set(&[("CN=a", Some((3, 4)))]).rollback_from(&loaded), None);
        assert_eq!(set(&[("CN=a", Some((4, 4)))]).rollback_from(&loaded), None);
        assert_eq!(set(&[("CN=c", Some((1, 1)))]).rollback_from(&loaded), None);
        assert_eq!(set(&[("CN=b", Some((1, 1)))]).rollback_from(&loaded), None);
        let r = set(&[("CN=a", Some((2, 9)))])
            .rollback_from(&loaded)
            .unwrap();
        assert_eq!(r.issuer, "CN=a");
        assert_eq!(r.loaded, n(3));
        assert_eq!(r.offered, Some(n(2)));
        let r = set(&[("CN=a", None)]).rollback_from(&loaded).unwrap();
        assert_eq!(r.offered, None);
    }
}
