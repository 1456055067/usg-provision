//! PostgreSQL test harness (feature `pg-integration`).
//!
//! Reads the `USGP_TEST_PG_*` contract of `scripts/pg-test-setup.sh` (plan
//! WU-3b). A missing variable **panics**, so the test fails rather than
//! skips: CI can never pass these gates without a database.
//!
//! Each test gets its own database, created by the owner role, so tests
//! run in parallel without sharing state.

use std::time::Duration;

use tokio_postgres::Client;
use usgp_crypto::tls::TlsMinVersion;
use usgp_db::config::pg_config;
use usgp_db::{DbSettings, PgStore, PgTls};
use zeroize::Zeroizing;

fn var(name: &str) -> String {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => v,
        _ => panic!(
            "{name} is not set: pg-integration tests need PostgreSQL \
             (scripts/pg-test-setup.sh up; then load pg-test.env). \
             They fail instead of skipping."
        ),
    }
}

fn file(var_name: &str) -> Vec<u8> {
    let path = var(var_name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{var_name}: cannot read {path}: {e}"))
}

/// Login material for one role.
pub struct Role {
    /// Role name.
    pub user: String,
    /// Client certificate PEM.
    pub cert: Vec<u8>,
    /// Client key PEM.
    pub key: Zeroizing<Vec<u8>>,
}

/// The test environment.
pub struct PgEnv {
    /// Host.
    pub host: String,
    /// Port.
    pub port: u16,
    /// TLS name of the server.
    pub server_name: String,
    /// The pre-made database the owner connects to for `CREATE DATABASE`.
    pub admin_db: String,
    /// Test CA, PEM.
    pub server_ca: Vec<u8>,
    /// Migration owner.
    pub owner: Role,
    /// Application role.
    pub app: Role,
    /// Administrative role (decision 0016: operator records, audit
    /// verify).
    pub admin: Role,
    /// Role for which the server asks for SCRAM (no password exists).
    pub pwprobe_user: String,
}

/// Loads the environment; panics if anything is missing.
pub fn env() -> PgEnv {
    PgEnv {
        host: var("USGP_TEST_PG_HOST"),
        port: var("USGP_TEST_PG_PORT")
            .parse()
            .expect("USGP_TEST_PG_PORT is a port number"),
        server_name: var("USGP_TEST_PG_SERVER_NAME"),
        admin_db: var("USGP_TEST_PG_DBNAME"),
        server_ca: file("USGP_TEST_PG_SERVER_CA"),
        owner: Role {
            user: var("USGP_TEST_PG_OWNER_USER"),
            cert: file("USGP_TEST_PG_OWNER_CERT"),
            key: Zeroizing::new(file("USGP_TEST_PG_OWNER_KEY")),
        },
        app: Role {
            user: var("USGP_TEST_PG_APP_USER"),
            cert: file("USGP_TEST_PG_APP_CERT"),
            key: Zeroizing::new(file("USGP_TEST_PG_APP_KEY")),
        },
        admin: Role {
            user: var("USGP_TEST_PG_ADMIN_USER"),
            cert: file("USGP_TEST_PG_ADMIN_CERT"),
            key: Zeroizing::new(file("USGP_TEST_PG_ADMIN_KEY")),
        },
        pwprobe_user: var("USGP_TEST_PG_PWPROBE_USER"),
    }
}

impl PgEnv {
    /// Settings for `user` logging in with `role`'s certificate to `db`.
    pub fn settings_as(&self, user: &str, role: &Role, db: &str) -> DbSettings {
        DbSettings {
            host: self.host.clone(),
            port: self.port,
            dbname: db.to_owned(),
            user: user.to_owned(),
            server_name: Some(self.server_name.clone()),
            server_ca_pem: self.server_ca.clone(),
            client_cert_pem: role.cert.clone(),
            client_key_pem: role.key.clone(),
            min_tls: TlsMinVersion::Tls12,
            pool_size: 4,
            connect_timeout: Duration::from_secs(20),
            application_name: "usgp-db-test".into(),
        }
    }

    /// Owner settings for `db`.
    pub fn owner(&self, db: &str) -> DbSettings {
        self.settings_as(&self.owner.user, &self.owner, db)
    }

    /// Application settings for `db`.
    pub fn app(&self, db: &str) -> DbSettings {
        self.settings_as(&self.app.user, &self.app, db)
    }

    /// Administrative-role settings for `db`.
    pub fn admin(&self, db: &str) -> DbSettings {
        self.settings_as(&self.admin.user, &self.admin, db)
    }
}

/// A direct driver connection (for statements the repository does not
/// offer, such as tampering or privilege probes).
pub async fn raw(s: &DbSettings) -> Client {
    let cfg = pg_config(s).unwrap();
    let tls = PgTls::new(s).unwrap();
    let (client, conn) = cfg.connect(tls).await.unwrap();
    tokio::spawn(async move {
        let _closed = conn.await;
    });
    client
}

/// A fresh database for one test.
pub struct TestDb {
    /// Environment.
    pub env: PgEnv,
    /// Database name.
    pub name: String,
    /// Owner store (migrations).
    pub owner: PgStore,
    /// Application store.
    pub app: PgStore,
    /// Administrative store (operator enrol/disable; decision 0016).
    pub admin: PgStore,
}

impl TestDb {
    /// Creates an empty (unmigrated) database.
    pub async fn create() -> Self {
        let env = env();
        let name = format!(
            "usgp_t_{}",
            usgp_common::Sha256Digest(super::rand_bytes()).to_hex()
        );
        let name = name.get(..30).unwrap().to_owned();
        let admin = raw(&env.owner(&env.admin_db)).await;
        admin
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .await
            .unwrap();
        let owner = PgStore::connect(&env.owner(&name)).unwrap();
        let app = PgStore::connect(&env.app(&name)).unwrap();
        let admin = PgStore::connect(&env.admin(&name)).unwrap();
        Self {
            env,
            name,
            owner,
            app,
            admin,
        }
    }

    /// Creates a database and applies every migration as the owner.
    pub async fn migrated() -> Self {
        let db = Self::create().await;
        let r = db.owner.migrate().await.unwrap();
        assert_eq!(r.version, usgp_db::SCHEMA_VERSION);
        db
    }

    /// A raw owner connection to this database.
    pub async fn raw_owner(&self) -> Client {
        raw(&self.env.owner(&self.name)).await
    }

    /// A raw application connection to this database.
    pub async fn raw_app(&self) -> Client {
        raw(&self.env.app(&self.name)).await
    }

    /// A raw administrative-role connection to this database.
    pub async fn raw_admin(&self) -> Client {
        raw(&self.env.admin(&self.name)).await
    }

    /// Closes the pools and drops the database (best effort; the CI
    /// container is discarded anyway).
    pub async fn finish(self) {
        self.owner.close();
        self.app.close();
        self.admin.close();
        let admin = raw(&self.env.owner(&self.env.admin_db)).await;
        let _dropped = admin
            .batch_execute(&format!("DROP DATABASE IF EXISTS {}", self.name))
            .await;
    }
}

/// Asserts that `r` failed with SQLSTATE `code`.
pub fn assert_sqlstate<T: std::fmt::Debug>(
    r: Result<T, tokio_postgres::Error>,
    code: &tokio_postgres::error::SqlState,
    what: &str,
) {
    match r {
        Ok(v) => panic!("{what}: expected SQLSTATE {}, got Ok({v:?})", code.code()),
        Err(e) => assert_eq!(e.code(), Some(code), "{what}: {e:?}"),
    }
}
