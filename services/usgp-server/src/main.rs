//! usgp-server: control plane service (plan M2 WU-7).
//!
//! Process contract: [`usgp_server::cli`]. The FIPS check is always the
//! first action; start-up order is in the library documentation.

use std::process::ExitCode;
use std::time::Duration;

use usgp_audit::AuditChain;
use usgp_common::config::TrustPolicy;
use usgp_common::telemetry::{self, Level, LogFormat};
use usgp_crypto::PeerCertificate;
use usgp_db::{OperatorRole, PgStore, SCHEMA_VERSION};
use usgp_proto::{BootServiceId, DisplayName, OperatorId};
use usgp_server::cli::{self, Command, ConfigArgs, RoleArg, USAGE};
use usgp_server::config::{self, LoadedConfig};
use usgp_server::events::{self, LocalUser};
use usgp_server::material::{self, DbRole};
use usgp_server::serve::{self, RunOptions, ServeError};
use usgp_server::{
    EXIT_CONFIG, EXIT_FAILURE, EXIT_NOPERM, EXIT_UNAVAILABLE, EXIT_USAGE, audit_cmd,
    boot_service_cmd, keys, migrate_cmd, operator,
};

/// How long shutdown waits for blocking work (a running content check)
/// before the process exits; the check is then marked Failed by restart
/// recovery at the next start.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

fn main() -> ExitCode {
    // COMPLIANCE MAPPING:
    // - NIST 800-53: SC-13 (Cryptographic Protection) - fail closed if the
    //   validated module is not in FIPS mode (docs/decisions/0001).
    // - NIST 800-53: AU-2 / AU-12 - the refusal is mirrored as
    //   server.start.refused before the process exits.
    if let Err(e) = usgp_crypto::fips_status() {
        eprintln!("usgp-server: refusing to start: {e}");
        let _ = telemetry::init(Level::INFO, LogFormat::Json);
        events::unpersisted(
            usgp_common::process::hostname().as_deref(),
            &serve::refusal_draft("fips_inactive", None),
        );
        return ExitCode::from(EXIT_FAILURE);
    }
    match cli::parse(std::env::args_os().skip(1)) {
        Err(e) => {
            eprintln!("usgp-server: {e}");
            eprintln!("{USAGE}");
            ExitCode::from(EXIT_USAGE)
        }
        Ok(Command::Help) => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Ok(Command::SelfCheck) => ExitCode::SUCCESS,
        Ok(Command::CheckConfig(args)) => check_config(&args),
        Ok(Command::Serve(args)) => serve_cmd(&args),
        Ok(Command::Migrate {
            config,
            owner_user,
            owner_cert,
            owner_key,
        }) => migrate(&config, &owner_user, &owner_cert, &owner_key),
        Ok(Command::Keygen {
            purpose,
            out_key,
            out_pub,
        }) => match keys::keygen(purpose, &out_key, out_pub.as_deref()) {
            Ok(g) => {
                // NIST-011: no database here; the event is mirrored
                // unpersisted with the local uid and node.
                let _ = telemetry::init(Level::INFO, LogFormat::Json);
                events::unpersisted(
                    usgp_common::process::hostname().as_deref(),
                    &keys::generated_draft(&g, usgp_common::process::effective_uid().ok()),
                );
                println!("purpose: {}", g.purpose.as_str());
                if let Some(id) = &g.key_id {
                    println!("key id: {id}");
                }
                println!(
                    "private key: {} (mode 0600; set owner root:<service group>, mode 0640)",
                    out_key.display()
                );
                if let Some(p) = &out_pub {
                    println!("public key: {}", p.display());
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("usgp-server: {e}");
                // NIST-016: the failed attempt is mirrored too.
                let _ = telemetry::init(Level::INFO, LogFormat::Json);
                events::unpersisted(
                    usgp_common::process::hostname().as_deref(),
                    &keys::generation_failed_draft(
                        purpose,
                        &e,
                        usgp_common::process::effective_uid().ok(),
                    ),
                );
                ExitCode::from(EXIT_FAILURE)
            }
        },
        Ok(Command::OperatorEnrol {
            config,
            cert,
            name,
            role,
        }) => operator_enrol(&config, &cert, &name, role),
        Ok(Command::OperatorDisable { config, id }) => operator_disable(&config, &id),
        Ok(Command::AuditVerify {
            config,
            trusted_keys,
            max_unsigned_records,
            max_checkpoint_age,
        }) => audit_verify(
            &config,
            &trusted_keys,
            audit_cmd::VerifyOptions {
                max_unsigned_records,
                max_checkpoint_age,
            },
        ),
        Ok(Command::BootServiceEnrol {
            config,
            cert,
            name,
            subnets,
        }) => boot_service_enrol(&config, &cert, &name, &subnets),
        Ok(Command::BootServiceDisable { config, id }) => boot_service_disable(&config, &id),
        Ok(Command::BootServiceRaiseGeneration { config, id, to }) => {
            boot_service_raise_generation(&config, &id, to)
        }
    }
}

fn runtime() -> Option<tokio::runtime::Runtime> {
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => Some(rt),
        Err(e) => {
            eprintln!("usgp-server: cannot start the async runtime: {}", e.kind());
            None
        }
    }
}

fn trust(args: &ConfigArgs) -> TrustPolicy {
    TrustPolicy {
        admin_uid: args.admin_uid,
    }
}

/// Loads the configuration. On failure prints the reason and, for
/// `serve`, mirrors `server.start.refused`; returns exit 78.
fn load(args: &ConfigArgs, for_serve: bool) -> Result<LoadedConfig, ExitCode> {
    match config::load(&args.path, &trust(args)) {
        Ok(l) => Ok(l),
        Err(e) => {
            eprintln!("usgp-server: {e}");
            let _ = telemetry::init(Level::INFO, LogFormat::Json);
            if for_serve {
                events::unpersisted(
                    usgp_common::process::hostname().as_deref(),
                    &serve::refusal_draft("config_invalid", Some(e.field())),
                );
            }
            Err(ExitCode::from(EXIT_CONFIG))
        }
    }
}

/// `--check-config`: validates the configuration and every file it names
/// (trust rules, keys, certificates, CRLs, TLS acceptor, database
/// settings); connects to nothing and binds nothing.
fn check_config(args: &ConfigArgs) -> ExitCode {
    let loaded = match load(args, false) {
        Ok(l) => l,
        Err(code) => return code,
    };
    let cfg = &loaded.config;
    let policy = trust(args);
    let prepared = match serve::prepare(cfg, &policy) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("usgp-server: {e}");
            return ExitCode::from(e.exit_code());
        }
    };
    let db = match material::db_settings(&cfg.database, DbRole::App, &policy)
        .and_then(|s| usgp_db::PgTls::new(&s).map(|_| s).map_err(Into::into))
    {
        Ok(s) => s,
        Err(e) => {
            eprintln!("usgp-server: {e}");
            return ExitCode::from(EXIT_CONFIG);
        }
    };
    println!("configuration: valid");
    println!("config sha256: {}", loaded.sha256);
    println!("node: {}", cfg.node_name);
    println!("listen: {}", cfg.listen);
    println!("content key id: {}", prepared.content_key_id);
    println!("audit key id: {}", prepared.audit_key_id);
    match &prepared.provisioning {
        Some(k) => {
            println!("plan key id: {}", k.plan_key_id());
            println!("boot-policy key id: {}", k.boot_policy_key_id());
            println!("code hmac key: loaded (32 bytes)");
        }
        None => println!("provisioning keys: not configured (device sessions and relay feed off)"),
    }
    match &cfg.device_listener {
        Some(d) => println!("device listen: {} (server-authenticated TLS)", d.listen),
        None => println!("device listen: off"),
    }
    println!("crl files: {}", prepared.crls.crls.len());
    println!(
        "database: {}:{}/{} as {} (certificate login)",
        db.host, db.port, db.dbname, db.user
    );
    match &cfg.database.admin {
        Some(a) => println!("database admin role: {} (local commands)", a.user),
        None => println!("database admin role: not configured (local commands refused)"),
    }
    ExitCode::SUCCESS
}

fn serve_cmd(args: &ConfigArgs) -> ExitCode {
    let loaded = match load(args, true) {
        Ok(l) => l,
        Err(code) => return code,
    };
    let cfg = &loaded.config;
    if let Err(e) = telemetry::init(cfg.log_level, LogFormat::Json) {
        eprintln!("usgp-server: cannot start logging: {e}");
        return ExitCode::from(EXIT_FAILURE);
    }
    let policy = trust(args);
    let service_uid = usgp_common::process::effective_uid().ok();
    // CM-5 / AC-6: never run as the administrator uid that owns the
    // trusted files unless the operator opted in.
    if let Some(reason) =
        serve::shared_admin_uid_refusal(service_uid, &policy, args.allow_shared_admin_uid)
    {
        eprintln!(
            "usgp-server: refusing to run as the --admin-uid ({reason}); \
             use --allow-shared-admin-uid to accept that risk"
        );
        serve::refuse_unpersisted(cfg, reason, Some("--admin-uid"));
        return ExitCode::from(EXIT_CONFIG);
    }
    // AC-6(1), decision 0016: the service must not be able to read the
    // administrative database key (finding SEC-011).
    if let Some(e) = serve::admin_key_refusal(cfg) {
        eprintln!(
            "usgp-server: refusing to start: the service can read \
             [database.admin] client_key; make it root-owned, mode 0600"
        );
        return refused_before_db(cfg, &e);
    }
    let prepared = match serve::prepare(cfg, &policy) {
        Ok(p) => p,
        Err(e) => return refused_before_db(cfg, &e),
    };
    let db = match material::db_settings(&cfg.database, DbRole::App, &policy) {
        Ok(s) => s,
        Err(e) => return refused_before_db(cfg, &ServeError::Material(e)),
    };
    let Some(rt) = runtime() else {
        serve::refuse_unpersisted(cfg, "runtime_failure", None);
        return ExitCode::from(EXIT_FAILURE);
    };
    let opts = RunOptions {
        trust: policy,
        allow_shared_admin_uid: args.allow_shared_admin_uid,
        service_uid,
    };
    let result = rt.block_on(async {
        let store = match PgStore::connect(&db) {
            Ok(s) => s,
            Err(source) => {
                return Err((
                    ServeError::Database {
                        stage: "database_config",
                        source,
                    },
                    false,
                ));
            }
        };
        // The client key is held by the pool's connector from here on.
        drop(db);
        let version = match check_database(&store).await {
            Ok(v) => v,
            Err(e) => return Err((e, false)),
        };
        let shutdown = match shutdown_signal() {
            Ok(f) => f,
            Err(_) => return Err((ServeError::Runtime("cannot install signal handlers"), false)),
        };
        let r = serve::run(
            store.clone(),
            &loaded,
            prepared,
            opts,
            version,
            shutdown,
            None,
        )
        .await;
        store.close();
        r.map_err(|e| (e, true))
    });
    rt.shutdown_timeout(SHUTDOWN_GRACE);
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err((e, recorded)) => {
            eprintln!("usgp-server: {e}");
            if !recorded {
                serve::refuse_unpersisted(cfg, e.reason(), e.field().as_deref());
            }
            ExitCode::from(e.exit_code())
        }
    }
}

fn refused_before_db(cfg: &config::ServerConfig, e: &ServeError) -> ExitCode {
    eprintln!("usgp-server: {e}");
    serve::refuse_unpersisted(cfg, e.reason(), e.field().as_deref());
    ExitCode::from(e.exit_code())
}

/// Ping, then the schema version must be exactly this build's (plan
/// section 3.4).
async fn check_database(store: &PgStore) -> Result<u32, ServeError> {
    store.ping().await.map_err(|source| ServeError::Database {
        stage: "database_unavailable",
        source,
    })?;
    let v = store
        .check_schema()
        .await
        .map_err(|source| ServeError::Database {
            stage: "schema_mismatch",
            source,
        })?;
    if v != SCHEMA_VERSION {
        return Err(ServeError::Database {
            stage: "schema_mismatch",
            source: usgp_db::MigrationError::SchemaBehind {
                applied: v,
                expected: SCHEMA_VERSION,
            }
            .into(),
        });
    }
    Ok(v)
}

/// Installs SIGTERM and SIGINT handlers now (so a signal during start-up
/// is not fatal) and returns the future that completes on either.
fn shutdown_signal() -> std::io::Result<impl std::future::Future<Output = &'static str>> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate())?;
        let mut int = signal(SignalKind::interrupt())?;
        Ok(async move {
            tokio::select! {
                _ = term.recv() => "SIGTERM",
                _ = int.recv() => "SIGINT",
            }
        })
    }
    #[cfg(not(unix))]
    {
        Ok(async {
            let _ = tokio::signal::ctrl_c().await;
            "SIGINT"
        })
    }
}

/// Guard for local administrative commands: root or the owner of the
/// configuration file (decisions 0015 item 3, 0016 item 3). This stops
/// mistakes; the access control is the root-only `usgp_admin` client key
/// (finding NIST-015). Returns the local user, or exit 77.
fn local_admin(policy: &TrustPolicy, config: &std::path::Path) -> Result<LocalUser, ExitCode> {
    events::local_admin(
        policy,
        events::file_owner(config),
        usgp_common::process::effective_uid(),
    )
    .map_err(|why| {
        match why {
            "not_local_admin" => {
                eprintln!(
                    "usgp-server: this command must be run as root or as the owner of the \
                     configuration file"
                );
            }
            _ => eprintln!("usgp-server: cannot determine the effective uid"),
        }
        ExitCode::from(EXIT_NOPERM)
    })
}

/// Loads the configuration for a local command, starts logging (audit
/// mirror on stdout) and checks the caller.
fn local_setup(args: &ConfigArgs) -> Result<(LoadedConfig, LocalUser), ExitCode> {
    let loaded = load(args, false)?;
    let _ = telemetry::init(loaded.config.log_level, LogFormat::Json);
    let who = local_admin(&trust(args), &args.path)?;
    Ok((loaded, who))
}

/// Connects as the administrative role (`[database.admin]`, decision
/// 0016) and checks reachability and schema. `unavailable` is the exit
/// status for a database that cannot be used.
async fn connect_admin(
    cfg: &config::ServerConfig,
    policy: &TrustPolicy,
    unavailable: u8,
) -> Result<PgStore, ExitCode> {
    let s = material::db_settings(&cfg.database, DbRole::Admin, policy).map_err(|e| {
        eprintln!("usgp-server: {e}");
        ExitCode::from(EXIT_CONFIG)
    })?;
    let store = PgStore::connect(&s).map_err(|e| {
        eprintln!("usgp-server: {e}");
        ExitCode::from(EXIT_CONFIG)
    })?;
    drop(s);
    check_database(&store).await.map_err(|e| {
        eprintln!("usgp-server: {e}");
        ExitCode::from(unavailable)
    })?;
    Ok(store)
}

fn chain_for(cfg: &config::ServerConfig) -> Result<AuditChain, ExitCode> {
    AuditChain::new(&cfg.node_name).map_err(|e| {
        eprintln!("usgp-server: {e}");
        ExitCode::from(EXIT_CONFIG)
    })
}

fn migrate(
    args: &ConfigArgs,
    owner_user: &str,
    owner_cert: &std::path::Path,
    owner_key: &std::path::Path,
) -> ExitCode {
    let (loaded, who) = match local_setup(args) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let cfg = &loaded.config;
    let policy = trust(args);
    let role = DbRole::Owner {
        user: owner_user,
        cert: owner_cert,
        key: owner_key,
    };
    let s = match material::db_settings(&cfg.database, role, &policy) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("usgp-server: {e}");
            return ExitCode::from(EXIT_CONFIG);
        }
    };
    let chain = match chain_for(cfg) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let Some(rt) = runtime() else {
        return ExitCode::from(EXIT_FAILURE);
    };
    rt.block_on(async {
        let store = match PgStore::connect(&s) {
            Ok(st) => st,
            Err(e) => {
                eprintln!("usgp-server: {e}");
                return ExitCode::from(EXIT_CONFIG);
            }
        };
        drop(s);
        let r = migrate_cmd::migrate(&store, &chain, &who).await;
        store.close();
        match r {
            Ok(report) => {
                let applied: Vec<String> = report.applied.iter().map(u32::to_string).collect();
                println!(
                    "migrations applied: {}",
                    if applied.is_empty() {
                        "none".to_owned()
                    } else {
                        applied.join(", ")
                    }
                );
                println!("schema version: {}", report.version);
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("usgp-server: {e}");
                ExitCode::from(EXIT_FAILURE)
            }
        }
    })
}

fn operator_enrol(
    args: &ConfigArgs,
    cert: &std::path::Path,
    name: &str,
    role: RoleArg,
) -> ExitCode {
    let Ok(name) = DisplayName::new(name) else {
        eprintln!("usgp-server: --name is not an acceptable display name");
        return ExitCode::from(EXIT_USAGE);
    };
    let (loaded, who) = match local_setup(args) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let cfg = &loaded.config;
    let policy = trust(args);
    // The certificate decides who becomes an operator: it is read under
    // the trusted-file rules like every other trust input (CM-5).
    let pem = match usgp_server::files::read_trusted_public(
        cert,
        u64::try_from(usgp_crypto::pem::MAX_CERT_PEM_BYTES).unwrap_or(u64::MAX),
        &policy,
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("usgp-server: --cert: {e}");
            return ExitCode::from(EXIT_CONFIG);
        }
    };
    let cert = match PeerCertificate::from_pem(&pem) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("usgp-server: --cert: {e}");
            return ExitCode::from(EXIT_CONFIG);
        }
    };
    // SEC-006: a certificate that can never log in is refused here too;
    // `operator::enrol` records the refusal.
    let audit_key_id =
        match keys::load_signing_key("signing.audit_key", &cfg.signing.audit_key, &policy) {
            Ok(k) => k.key_id(),
            Err(e) => {
                eprintln!("usgp-server: {e}");
                return ExitCode::from(EXIT_CONFIG);
            }
        };
    let chain = match chain_for(cfg) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let req = operator::Enrolment {
        cert,
        name,
        role: match role {
            RoleArg::Administrator => Some(OperatorRole::Administrator),
            RoleArg::None => None,
        },
    };
    let Some(rt) = runtime() else {
        return ExitCode::from(EXIT_FAILURE);
    };
    rt.block_on(async {
        let store = match connect_admin(cfg, &policy, EXIT_FAILURE).await {
            Ok(s) => s,
            Err(code) => return code,
        };
        let r = async {
            events::ensure_genesis(&store, &chain, &audit_key_id).await?;
            operator::enrol(&store, &chain, &who, &req).await
        }
        .await;
        store.close();
        match r {
            Ok(op) => {
                println!("operator id: {}", op.id);
                println!("certificate sha256: {}", op.cert_sha256);
                println!("role: {}", op.role.map_or("none", OperatorRole::as_str));
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("usgp-server: operator enrol: {e}");
                ExitCode::from(EXIT_FAILURE)
            }
        }
    })
}

fn operator_disable(args: &ConfigArgs, id: &str) -> ExitCode {
    let Ok(id) = OperatorId::parse(id) else {
        eprintln!("usgp-server: --id is not an operator id (hyphenated UUID)");
        return ExitCode::from(EXIT_USAGE);
    };
    let (loaded, who) = match local_setup(args) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let cfg = &loaded.config;
    let policy = trust(args);
    let chain = match chain_for(cfg) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let Some(rt) = runtime() else {
        return ExitCode::from(EXIT_FAILURE);
    };
    rt.block_on(async {
        let store = match connect_admin(cfg, &policy, EXIT_FAILURE).await {
            Ok(s) => s,
            Err(code) => return code,
        };
        let r = operator::disable(&store, &chain, &who, id).await;
        store.close();
        match r {
            Ok(operator::Disabled::Changed) => {
                println!("operator {id}: disabled");
                ExitCode::SUCCESS
            }
            Ok(operator::Disabled::AlreadyDisabled) => {
                println!("operator {id}: already disabled");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("usgp-server: operator disable: {e}");
                ExitCode::from(EXIT_FAILURE)
            }
        }
    })
}

fn audit_verify(
    args: &ConfigArgs,
    trusted_keys: &[std::path::PathBuf],
    options: audit_cmd::VerifyOptions,
) -> ExitCode {
    let (loaded, who) = match local_setup(args) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let cfg = &loaded.config;
    let chain = match chain_for(cfg) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let Ok(now_us) = chain.now_us() else {
        eprintln!("usgp-server: cannot read the clock");
        return ExitCode::from(EXIT_FAILURE);
    };
    // SEC-002, SEC-015: the checkpoint cadence the chain must show, with
    // slack for the configured writers; SEC-013: optional age limit.
    let verify_policy = match audit_cmd::verify_policy(
        &cfg.checkpoint,
        cfg.api.max_audit_writers(),
        options,
        now_us,
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("usgp-server: audit verify options: {e}");
            eprintln!("{USAGE}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let policy = trust(args);
    let mut trusted = Vec::with_capacity(trusted_keys.len());
    for p in trusted_keys {
        match keys::load_verifying_key("--trusted-key", p, &policy) {
            Ok(k) => trusted.push(k),
            Err(e) => {
                eprintln!("usgp-server: {e}");
                return ExitCode::from(EXIT_CONFIG);
            }
        }
    }
    let Some(rt) = runtime() else {
        return ExitCode::from(EXIT_UNAVAILABLE);
    };
    rt.block_on(async {
        let store = match connect_admin(cfg, &policy, EXIT_UNAVAILABLE).await {
            Ok(s) => s,
            Err(code) => return code,
        };
        let code = match audit_cmd::verify_with_policy(&store, &trusted, verify_policy).await {
            Ok(report) => {
                print!("{}", audit_cmd::render(&report));
                audit_cmd::record_result(&store, &chain, &who, &report, &trusted).await;
                ExitCode::from(audit_cmd::exit_code(&report))
            }
            Err(e) => {
                eprintln!("usgp-server: the audit chain could not be read: {e}");
                ExitCode::from(EXIT_UNAVAILABLE)
            }
        };
        store.close();
        code
    })
}

/// Reads a certificate named on the command line under the trusted-file
/// rules (CM-5): it decides who is trusted.
fn read_cert_arg(
    cert: &std::path::Path,
    policy: &TrustPolicy,
) -> Result<PeerCertificate, ExitCode> {
    let pem = usgp_server::files::read_trusted_public(
        cert,
        u64::try_from(usgp_crypto::pem::MAX_CERT_PEM_BYTES).unwrap_or(u64::MAX),
        policy,
    )
    .map_err(|e| {
        eprintln!("usgp-server: --cert: {e}");
        ExitCode::from(EXIT_CONFIG)
    })?;
    PeerCertificate::from_pem(&pem).map_err(|e| {
        eprintln!("usgp-server: --cert: {e}");
        ExitCode::from(EXIT_CONFIG)
    })
}

/// Runs one administrative boot-service command on the `usgp_admin`
/// role (decision 0016), after the genesis check.
fn run_admin<T, Fut>(
    args: &ConfigArgs,
    needs_genesis: bool,
    f: impl FnOnce(PgStore, AuditChain, LocalUser) -> Fut,
    report: impl FnOnce(Result<T, boot_service_cmd::BootServiceCmdError>) -> ExitCode,
) -> ExitCode
where
    Fut: std::future::Future<Output = (PgStore, Result<T, boot_service_cmd::BootServiceCmdError>)>,
{
    let (loaded, who) = match local_setup(args) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let cfg = &loaded.config;
    let policy = trust(args);
    let audit_key_id = if needs_genesis {
        match keys::load_signing_key("signing.audit_key", &cfg.signing.audit_key, &policy) {
            Ok(k) => Some(k.key_id()),
            Err(e) => {
                eprintln!("usgp-server: {e}");
                return ExitCode::from(EXIT_CONFIG);
            }
        }
    } else {
        None
    };
    let chain = match chain_for(cfg) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let Some(rt) = runtime() else {
        return ExitCode::from(EXIT_FAILURE);
    };
    rt.block_on(async {
        let store = match connect_admin(cfg, &policy, EXIT_FAILURE).await {
            Ok(s) => s,
            Err(code) => return code,
        };
        if let Some(k) = &audit_key_id
            && let Err(e) = events::ensure_genesis(&store, &chain, k).await
        {
            store.close();
            eprintln!("usgp-server: {e}");
            return ExitCode::from(EXIT_FAILURE);
        }
        let (store, r) = f(store, chain, who).await;
        store.close();
        report(r)
    })
}

fn boot_service_enrol(
    args: &ConfigArgs,
    cert: &std::path::Path,
    name: &str,
    subnets: &[String],
) -> ExitCode {
    let Ok(name) = DisplayName::new(name) else {
        eprintln!("usgp-server: --name is not an acceptable display name");
        return ExitCode::from(EXIT_USAGE);
    };
    let subnets = match boot_service_cmd::parse_subnets(subnets) {
        Ok(s) => s,
        Err(why) => {
            eprintln!("usgp-server: {why}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let cert = match read_cert_arg(cert, &trust(args)) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let req = boot_service_cmd::BootServiceEnrolment {
        cert,
        name,
        subnets,
    };
    run_admin(
        args,
        true,
        |store, chain, who| async move {
            let r = boot_service_cmd::enrol(&store, &chain, &who, &req).await;
            (store, r)
        },
        |r| match r {
            Ok(b) => {
                println!("boot service id: {}", b.id);
                println!("certificate sha256: {}", b.cert_sha256);
                println!("status: {}", b.status.as_str());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("usgp-server: boot-service enrol: {e}");
                ExitCode::from(EXIT_FAILURE)
            }
        },
    )
}

/// `boot-service raise-generation` (finding NIST-013).
fn boot_service_raise_generation(args: &ConfigArgs, id: &str, to: u64) -> ExitCode {
    let Ok(id) = BootServiceId::parse(id) else {
        eprintln!("usgp-server: --id is not a boot-service id (hyphenated UUID)");
        return ExitCode::from(EXIT_USAGE);
    };
    run_admin(
        args,
        false,
        |store, chain, who| async move {
            let r = boot_service_cmd::raise_generation(&store, &chain, &who, id, to).await;
            (store, r)
        },
        |r| match r {
            Ok(before) => {
                println!("boot service {id}: boot-policy generation {before} -> {to}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("usgp-server: boot-service raise-generation: {e}");
                ExitCode::from(EXIT_FAILURE)
            }
        },
    )
}

fn boot_service_disable(args: &ConfigArgs, id: &str) -> ExitCode {
    let Ok(id) = BootServiceId::parse(id) else {
        eprintln!("usgp-server: --id is not a boot-service id (hyphenated UUID)");
        return ExitCode::from(EXIT_USAGE);
    };
    run_admin(
        args,
        false,
        |store, chain, who| async move {
            let r = boot_service_cmd::disable(&store, &chain, &who, id).await;
            (store, r)
        },
        |r| match r {
            Ok(boot_service_cmd::Disabled::Changed) => {
                println!("boot service {id}: disabled");
                ExitCode::SUCCESS
            }
            Ok(boot_service_cmd::Disabled::AlreadyDisabled) => {
                println!("boot service {id}: already disabled");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("usgp-server: boot-service disable: {e}");
                ExitCode::from(EXIT_FAILURE)
            }
        },
    )
}
