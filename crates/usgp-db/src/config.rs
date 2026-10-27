//! Database connection settings and the certificate-only rule (decision
//! 0012, plan section 5.5).
//!
//! [`DbSettings`] holds already-loaded PEM bytes; reading files (with the
//! trusted-file checks) is the server's job. The settings have no password
//! field, and [`assert_certificate_only`] refuses anything that could turn
//! password authentication on:
//!
//! - a missing client certificate or key;
//! - a connection-string or URL form in any field (`key=value`, `://`,
//!   `@`, `?`, whitespace);
//! - a Unix-socket host (no TLS);
//! - a password set on the built [`tokio_postgres::Config`].
//!
//! The user is always set explicitly ([`pg_config`]); the driver's default
//! (the OS user name from `whoami`) is never used.

// COMPLIANCE MAPPING:
// - NIST 800-53: IA-5(2) (PKI-Based Authentication) - certificate-only
//   database login.
// - NIST 800-53: SC-8, SC-8(1) - TLS required (`SslMode::Require` plus a
//   hook that never returns plaintext).
// - NIST 800-53: SC-13 (Cryptographic Protection) - the driver's non-FIPS
//   password code stays unreachable (decision 0012).
// - NIST 800-53: CM-6 (Configuration Settings) - refuse at start-up.
// - Decisions 0008, 0012; plan section 5.5

use std::fmt;
use std::time::Duration;

use tokio_postgres::config::{ChannelBinding, SslMode};
use usgp_crypto::tls::TlsMinVersion;
use zeroize::Zeroizing;

/// Longest accepted host, database or user name (PostgreSQL identifiers
/// are at most 63 bytes; host names at most 253).
pub const MAX_NAME_LEN: usize = 253;
/// Largest accepted pool.
pub const MAX_POOL_SIZE: usize = 256;
/// Default pool size (plan section 3.5).
pub const DEFAULT_POOL_SIZE: usize = 8;
/// Default connect timeout (plan section 3.5).
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Why a database configuration was refused. Names the field only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// No client certificate: certificate login is the only method.
    #[error("database.client_cert is required (certificate-only login, decision 0012)")]
    MissingClientCert,
    /// No client key.
    #[error("database.client_key is required (certificate-only login, decision 0012)")]
    MissingClientKey,
    /// No server CA: the server certificate must be verified.
    #[error("database.server_ca is required")]
    MissingServerCa,
    /// A field is empty.
    #[error("database.{0} must not be empty")]
    Empty(&'static str),
    /// A field looks like a connection string or URL, which could carry a
    /// password or override TLS settings.
    #[error("database.{0} must be a plain value, not a connection string or URL")]
    ConnectionStringForm(&'static str),
    /// A Unix-socket path was given as host (no TLS on sockets).
    #[error("database.host must be a TCP host name or address, not a socket path")]
    SocketHost,
    /// A field is too long.
    #[error("database.{0} is too long")]
    TooLong(&'static str),
    /// A number is out of range.
    #[error("database.{0} is out of range")]
    OutOfRange(&'static str),
    /// A password is set on the driver configuration.
    #[error("a database password is configured; only certificate login is allowed (decision 0012)")]
    PasswordSet,
    /// The driver configuration lacks an explicit user.
    #[error("database user is not set explicitly")]
    UserNotSet,
    /// The driver configuration does not require TLS.
    #[error("database TLS is not required")]
    TlsNotRequired,
}

/// Connection settings for one role.
pub struct DbSettings {
    /// TCP host name or address.
    pub host: String,
    /// TCP port.
    pub port: u16,
    /// Database name.
    pub dbname: String,
    /// Role name. Always sent explicitly.
    pub user: String,
    /// Name the server certificate must carry. Defaults to `host` when
    /// `None`.
    pub server_name: Option<String>,
    /// Trust anchors for the server certificate, PEM.
    pub server_ca_pem: Vec<u8>,
    /// Client certificate chain, PEM, end entity first.
    pub client_cert_pem: Vec<u8>,
    /// Client private key, PKCS#8 PEM. Wiped on drop; never printed.
    pub client_key_pem: Zeroizing<Vec<u8>>,
    /// Lowest TLS version.
    pub min_tls: TlsMinVersion,
    /// Pool size, 1 to [`MAX_POOL_SIZE`].
    pub pool_size: usize,
    /// Connect (TCP + TLS + login) and pool-wait timeout.
    pub connect_timeout: Duration,
    /// `application_name` reported to the server.
    pub application_name: String,
}

impl fmt::Debug for DbSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DbSettings")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("dbname", &self.dbname)
            .field("user", &self.user)
            .field("server_name", &self.server_name)
            .field("server_ca_pem_len", &self.server_ca_pem.len())
            .field("client_cert_pem_len", &self.client_cert_pem.len())
            .field("client_key_pem", &"<redacted>")
            .field("min_tls", &self.min_tls)
            .field("pool_size", &self.pool_size)
            .field("connect_timeout", &self.connect_timeout)
            .field("application_name", &self.application_name)
            .finish()
    }
}

impl DbSettings {
    /// The TLS server name to verify.
    #[must_use]
    pub fn tls_server_name(&self) -> &str {
        self.server_name.as_deref().unwrap_or(&self.host)
    }
}

/// Refuses any configuration that could enable password authentication or
/// a non-TLS connection (decision 0012, plan section 5.5). Call at start-up
/// before connecting; [`crate::pool::PgStore::connect`] calls it too.
///
/// # Errors
///
/// [`ConfigError`] naming the field.
pub fn assert_certificate_only(s: &DbSettings) -> Result<(), ConfigError> {
    if s.client_cert_pem.iter().all(u8::is_ascii_whitespace) {
        return Err(ConfigError::MissingClientCert);
    }
    if s.client_key_pem.iter().all(u8::is_ascii_whitespace) {
        return Err(ConfigError::MissingClientKey);
    }
    if s.server_ca_pem.iter().all(u8::is_ascii_whitespace) {
        return Err(ConfigError::MissingServerCa);
    }
    plain_value("host", &s.host)?;
    if s.host.starts_with('/') {
        return Err(ConfigError::SocketHost);
    }
    plain_value("dbname", &s.dbname)?;
    plain_value("user", &s.user)?;
    if let Some(n) = &s.server_name {
        plain_value("server_name", n)?;
    }
    plain_value("application_name", &s.application_name)?;
    if s.port == 0 {
        return Err(ConfigError::OutOfRange("port"));
    }
    if s.pool_size == 0 || s.pool_size > MAX_POOL_SIZE {
        return Err(ConfigError::OutOfRange("pool_size"));
    }
    if s.connect_timeout.is_zero() || s.connect_timeout > Duration::from_secs(600) {
        return Err(ConfigError::OutOfRange("connect_timeout"));
    }
    check_pg_config(&pg_config(s)?)
}

/// Builds the driver configuration: explicit user, TLS required, channel
/// binding off (no password, so nothing to bind), `search_path` pinned to
/// `public` (CVE-2018-1058 class), no password.
///
/// # Errors
///
/// [`ConfigError`] for a field that is not a plain value.
pub fn pg_config(s: &DbSettings) -> Result<tokio_postgres::Config, ConfigError> {
    plain_value("host", &s.host)?;
    plain_value("dbname", &s.dbname)?;
    plain_value("user", &s.user)?;
    let mut c = tokio_postgres::Config::new();
    c.host(&s.host)
        .port(s.port)
        .dbname(&s.dbname)
        .user(&s.user)
        .application_name(&s.application_name)
        .ssl_mode(SslMode::Require)
        .channel_binding(ChannelBinding::Disable)
        .connect_timeout(s.connect_timeout)
        .options("-c search_path=public");
    Ok(c)
}

/// Checks a built driver configuration: no password, an explicit user,
/// TLS required.
///
/// # Errors
///
/// [`ConfigError::PasswordSet`], [`ConfigError::UserNotSet`],
/// [`ConfigError::TlsNotRequired`].
pub fn check_pg_config(c: &tokio_postgres::Config) -> Result<(), ConfigError> {
    if c.get_password().is_some() {
        return Err(ConfigError::PasswordSet);
    }
    match c.get_user() {
        Some(u) if !u.is_empty() => {}
        _ => return Err(ConfigError::UserNotSet),
    }
    if c.get_ssl_mode() != SslMode::Require {
        return Err(ConfigError::TlsNotRequired);
    }
    Ok(())
}

/// A plain value: non-empty, bounded, and nothing a connection string or
/// URL parser would interpret.
fn plain_value(field: &'static str, v: &str) -> Result<(), ConfigError> {
    if v.is_empty() {
        return Err(ConfigError::Empty(field));
    }
    if v.len() > MAX_NAME_LEN {
        return Err(ConfigError::TooLong(field));
    }
    if v.contains("://")
        || v.chars().any(|c| {
            c.is_whitespace() || c.is_control() || matches!(c, '=' | '@' | '?' | '\'' | '\\')
        })
    {
        return Err(ConfigError::ConnectionStringForm(field));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn good() -> DbSettings {
        DbSettings {
            host: "db.internal".into(),
            port: 5432,
            dbname: "usgp".into(),
            user: "usgp_app".into(),
            server_name: None,
            server_ca_pem: b"-----BEGIN CERTIFICATE-----\n".to_vec(),
            client_cert_pem: b"-----BEGIN CERTIFICATE-----\n".to_vec(),
            client_key_pem: Zeroizing::new(b"-----BEGIN PRIVATE KEY-----\n".to_vec()),
            min_tls: TlsMinVersion::Tls12,
            pool_size: DEFAULT_POOL_SIZE,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            application_name: "usgp-server".into(),
        }
    }

    #[test]
    fn good_settings_pass_and_set_user_explicitly() {
        let s = good();
        assert_certificate_only(&s).unwrap();
        let c = pg_config(&s).unwrap();
        assert_eq!(c.get_user(), Some("usgp_app"));
        assert_eq!(c.get_ssl_mode(), SslMode::Require);
        assert_eq!(c.get_channel_binding(), ChannelBinding::Disable);
        assert!(c.get_password().is_none());
        assert_eq!(s.tls_server_name(), "db.internal");
    }

    #[test]
    fn missing_client_cert_refused() {
        let mut s = good();
        s.client_cert_pem = Vec::new();
        assert_eq!(
            assert_certificate_only(&s),
            Err(ConfigError::MissingClientCert)
        );
        s.client_cert_pem = b"  \n".to_vec();
        assert_eq!(
            assert_certificate_only(&s),
            Err(ConfigError::MissingClientCert)
        );
    }

    #[test]
    fn missing_client_key_refused() {
        let mut s = good();
        s.client_key_pem = Zeroizing::new(Vec::new());
        assert_eq!(
            assert_certificate_only(&s),
            Err(ConfigError::MissingClientKey)
        );
    }

    #[test]
    fn missing_server_ca_refused() {
        let mut s = good();
        s.server_ca_pem = Vec::new();
        assert_eq!(
            assert_certificate_only(&s),
            Err(ConfigError::MissingServerCa)
        );
    }

    #[test]
    fn url_and_connection_string_forms_refused() {
        for (field, value) in [
            ("host", "postgres://u:pw@db/usgp"),
            ("host", "host=db password=x"),
            ("host", "db?sslmode=disable"),
            ("dbname", "usgp password=x"),
            ("user", "usgp_app:pw@db"),
            ("user", "u=1"),
        ] {
            let mut s = good();
            match field {
                "host" => s.host = value.into(),
                "dbname" => s.dbname = value.into(),
                _ => s.user = value.into(),
            }
            assert_eq!(
                assert_certificate_only(&s),
                Err(ConfigError::ConnectionStringForm(field)),
                "{field}={value}"
            );
        }
    }

    #[test]
    fn socket_host_and_empty_user_refused() {
        let mut s = good();
        s.host = "/var/run/postgresql".into();
        assert_eq!(assert_certificate_only(&s), Err(ConfigError::SocketHost));
        let mut s = good();
        s.user = String::new();
        assert_eq!(assert_certificate_only(&s), Err(ConfigError::Empty("user")));
    }

    #[test]
    fn ranges_checked() {
        let mut s = good();
        s.pool_size = 0;
        assert_eq!(
            assert_certificate_only(&s),
            Err(ConfigError::OutOfRange("pool_size"))
        );
        let mut s = good();
        s.port = 0;
        assert_eq!(
            assert_certificate_only(&s),
            Err(ConfigError::OutOfRange("port"))
        );
        let mut s = good();
        s.connect_timeout = Duration::ZERO;
        assert_eq!(
            assert_certificate_only(&s),
            Err(ConfigError::OutOfRange("connect_timeout"))
        );
    }

    #[test]
    fn password_on_driver_config_refused() {
        let mut c = pg_config(&good()).unwrap();
        c.password("secret");
        assert_eq!(check_pg_config(&c), Err(ConfigError::PasswordSet));
    }

    #[test]
    fn parsed_connection_string_with_password_refused() {
        let c: tokio_postgres::Config = "host=db user=usgp_app password=x sslmode=require"
            .parse()
            .unwrap();
        assert_eq!(check_pg_config(&c), Err(ConfigError::PasswordSet));
    }

    #[test]
    fn driver_config_without_user_or_tls_refused() {
        let mut c = tokio_postgres::Config::new();
        c.host("db").ssl_mode(SslMode::Require);
        assert_eq!(check_pg_config(&c), Err(ConfigError::UserNotSet));
        let mut c = pg_config(&good()).unwrap();
        c.ssl_mode(SslMode::Prefer);
        assert_eq!(check_pg_config(&c), Err(ConfigError::TlsNotRequired));
    }

    #[test]
    fn debug_redacts_key() {
        let s = good();
        let d = format!("{s:?}");
        assert!(d.contains("<redacted>"));
        assert!(!d.contains("PRIVATE KEY"));
    }
}
