//! PostgreSQL store: a connection pool over the `usgp-crypto` TLS hook,
//! and the transaction type [`PgTx`].
//!
//! Transactions are plain `BEGIN`/`COMMIT` on one pooled connection. A
//! transaction dropped without commit or rollback takes its connection
//! **out of the pool** and closes it, so the server rolls back and no
//! half-finished transaction is ever handed to another caller.

// COMPLIANCE MAPPING:
// - NIST 800-53: AU-5 - fail closed: a failed statement poisons the
//   transaction (`TxFailed`), an unaudited change cannot commit.
// - NIST 800-53: SC-8 - every pooled connection is made through `PgTls`.
// - NIST 800-53: SC-5 - bounded pool, bounded waits.
// - Decisions 0008, 0012, 0015

use deadpool_postgres::{Manager, ManagerConfig, Object, Pool, RecyclingMethod, Runtime};
use tokio_postgres::Row;
use tokio_postgres::types::ToSql;

use crate::config::{DbSettings, assert_certificate_only, pg_config};
use crate::error::{ConnectFailure, DbError, classify_connect};
use crate::tls::PgTls;

/// Parameters of one statement.
pub(crate) type Params<'a> = &'a [&'a (dyn ToSql + Sync)];

/// A PostgreSQL-backed store. Cheap to clone (shares the pool).
#[derive(Clone)]
pub struct PgStore {
    pool: Pool,
}

impl std::fmt::Debug for PgStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgStore")
            .field("status", &self.pool.status())
            .finish()
    }
}

impl PgStore {
    /// Builds the pool after [`assert_certificate_only`]. No connection is
    /// made until first use; call [`PgStore::ping`] to fail fast.
    ///
    /// # Errors
    ///
    /// [`DbError::Config`] for a refused configuration, [`DbError::Connect`]
    /// if the TLS inputs are refused.
    pub fn connect(s: &DbSettings) -> Result<Self, DbError> {
        assert_certificate_only(s)?;
        let tls = PgTls::new(s)?;
        Self::with_tls(s, tls)
    }

    /// As [`PgStore::connect`] with a prepared connector.
    ///
    /// # Errors
    ///
    /// As [`PgStore::connect`].
    pub fn with_tls(s: &DbSettings, tls: PgTls) -> Result<Self, DbError> {
        let cfg = pg_config(s)?;
        crate::config::check_pg_config(&cfg)?;
        let mc = ManagerConfig {
            recycling_method: RecyclingMethod::Verified,
        };
        let mgr = Manager::from_config(cfg, tls, mc);
        let timeout = Some(s.connect_timeout);
        let pool = Pool::builder(mgr)
            .max_size(s.pool_size)
            .runtime(Runtime::Tokio1)
            .create_timeout(timeout)
            .wait_timeout(timeout)
            .recycle_timeout(timeout)
            .build()
            .map_err(|e| DbError::Connect {
                class: ConnectFailure::Other,
                source: Some(Box::new(e)),
            })?;
        Ok(Self { pool })
    }

    /// Gets a pooled connection.
    pub(crate) async fn get(&self) -> Result<Object, DbError> {
        self.pool.get().await.map_err(|e| {
            let class = match &e {
                deadpool_postgres::PoolError::Timeout(_) => ConnectFailure::Timeout,
                deadpool_postgres::PoolError::Backend(b) => classify_connect(b),
                _ => ConnectFailure::Other,
            };
            DbError::Connect {
                class,
                source: Some(Box::new(e)),
            }
        })
    }

    /// Makes (or reuses) one connection and runs a trivial query.
    ///
    /// # Errors
    ///
    /// [`DbError::Connect`] with the failure class (for example
    /// `auth_method_refused` if the server asks for a password).
    pub async fn ping(&self) -> Result<(), DbError> {
        let obj = self.get().await?;
        obj.simple_query("SELECT 1")
            .await
            .map_err(|e| DbError::from_pg("ping", e))?;
        Ok(())
    }

    /// Checks that the schema is exactly the version this build expects
    /// and that every applied migration matches its embedded checksum
    /// (plan 3.4: `serve` refuses to start otherwise).
    ///
    /// # Errors
    ///
    /// [`DbError::Migration`] naming the mismatch.
    pub async fn check_schema(&self) -> Result<u32, DbError> {
        let obj = self.get().await?;
        crate::migrate::check_schema(&obj).await
    }

    /// Applies pending migrations on a dedicated connection (owner role).
    ///
    /// # Errors
    ///
    /// [`DbError::Migration`] or a database error; nothing partial is left
    /// (each migration is its own transaction).
    pub async fn migrate(&self) -> Result<crate::migrate::MigrateReport, DbError> {
        let obj = self.get().await?;
        // The connection holds a session advisory lock; it is closed
        // afterwards rather than returned to the pool.
        let client = Object::take(obj);
        crate::migrate::run(&client).await
    }

    /// Closes the pool; later calls fail.
    pub fn close(&self) {
        self.pool.close();
    }
}

impl crate::repo::Store for PgStore {
    type Tx = PgTx;

    async fn begin(&self) -> Result<PgTx, DbError> {
        let obj = self.get().await?;
        if let Err(e) = obj
            .batch_execute("BEGIN ISOLATION LEVEL READ COMMITTED")
            .await
        {
            drop(Object::take(obj));
            return Err(DbError::from_pg("begin", e));
        }
        Ok(PgTx {
            obj: Some(obj),
            mutated: false,
            audited: false,
            failed: false,
        })
    }
}

/// One PostgreSQL transaction. Implements [`crate::repo::RepoTx`] and
/// [`usgp_audit::AuditTx`].
pub struct PgTx {
    obj: Option<Object>,
    pub(crate) mutated: bool,
    pub(crate) audited: bool,
    failed: bool,
}

impl std::fmt::Debug for PgTx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgTx")
            .field("open", &self.obj.is_some())
            .field("mutated", &self.mutated)
            .field("audited", &self.audited)
            .field("failed", &self.failed)
            .finish()
    }
}

impl PgTx {
    fn client(&self) -> Result<&tokio_postgres::Client, DbError> {
        if self.failed {
            return Err(DbError::TxFailed);
        }
        match &self.obj {
            Some(o) => Ok(o),
            None => Err(DbError::TxFinished),
        }
    }

    fn note<T>(
        &mut self,
        ctx: &'static str,
        r: Result<T, tokio_postgres::Error>,
    ) -> Result<T, DbError> {
        r.map_err(|e| {
            self.failed = true;
            DbError::from_pg(ctx, e)
        })
    }

    /// Rows of a query.
    pub(crate) async fn query(
        &mut self,
        ctx: &'static str,
        sql: &str,
        params: Params<'_>,
    ) -> Result<Vec<Row>, DbError> {
        let r = self.client()?.query(sql, params).await;
        self.note(ctx, r)
    }

    /// At most one row.
    pub(crate) async fn query_opt(
        &mut self,
        ctx: &'static str,
        sql: &str,
        params: Params<'_>,
    ) -> Result<Option<Row>, DbError> {
        let r = self.client()?.query_opt(sql, params).await;
        self.note(ctx, r)
    }

    /// A state-changing statement; returns the affected row count.
    pub(crate) async fn execute(
        &mut self,
        ctx: &'static str,
        sql: &str,
        params: Params<'_>,
    ) -> Result<u64, DbError> {
        self.mutated = true;
        let r = self.client()?.execute(sql, params).await;
        self.note(ctx, r)
    }

    /// Marks the transaction failed (a precondition the caller cannot
    /// recover from inside it).
    pub(crate) fn poison(&mut self) {
        self.failed = true;
    }

    pub(crate) async fn finish_commit(mut self) -> Result<(), DbError> {
        let Some(obj) = self.obj.take() else {
            return Err(DbError::TxFinished);
        };
        if self.failed {
            rollback_or_discard(obj).await;
            return Err(DbError::TxFailed);
        }
        if self.mutated && !self.audited {
            rollback_or_discard(obj).await;
            return Err(DbError::Unaudited);
        }
        // COMMIT on a transaction the server already aborted answers
        // ROLLBACK without an error; `failed` above prevents relying on
        // that. A COMMIT error leaves the outcome unknown to us, so the
        // connection is discarded.
        match obj.batch_execute("COMMIT").await {
            Ok(()) => Ok(()),
            Err(e) => {
                drop(Object::take(obj));
                Err(DbError::from_pg("commit", e))
            }
        }
    }

    pub(crate) async fn finish_rollback(mut self) {
        if let Some(obj) = self.obj.take() {
            rollback_or_discard(obj).await;
        }
    }
}

async fn rollback_or_discard(obj: Object) {
    if obj.batch_execute("ROLLBACK").await.is_err() {
        drop(Object::take(obj));
    }
}

impl Drop for PgTx {
    fn drop(&mut self) {
        if let Some(obj) = self.obj.take() {
            // Not committed or rolled back: close the connection so the
            // server rolls back, and keep it out of the pool.
            drop(Object::take(obj));
        }
    }
}
