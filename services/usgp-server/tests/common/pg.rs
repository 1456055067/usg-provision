//! Helpers for the PostgreSQL tests (`e2e_pg.rs`, `large_upload_pg.rs`):
//! the `USGP_TEST_PG_*` contract (WU-3b; a missing variable **fails**
//! the test, it never skips), the server binary as a child process, and
//! the local commands (`migrate`, `operator enrol`).

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use super::{DbFiles, Fixture, admin_uid, https};

/// The value of a required test variable; panics (test fails) if unset.
pub fn var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!(
            "{name} is not set: pg-integration tests need PostgreSQL \
             (scripts/pg-test-setup.sh up). They fail instead of skipping."
        )
    })
}

/// Runs `usgp-server` with `args` to completion.
pub fn server(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_usgp-server"))
        .args(args)
        .output()
        .expect("spawn usgp-server")
}

/// Bytes as text (lossy).
pub fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// The test's uid as an argument.
pub fn uid() -> String {
    admin_uid().to_string()
}

/// Copies the file named by variable `from_var` into the fixture, so the
/// trust rules see a file owned by the test uid.
pub fn copy_in(f: &Fixture, from_var: &str, name: &str, mode: u32) -> PathBuf {
    let bytes = std::fs::read(var(from_var)).unwrap();
    f.scratch.write(name, &bytes, mode)
}

/// The CI database, the owner's credentials and the written config.
pub struct PgSetup {
    /// Application-role settings in the config.
    pub db: DbFiles,
    /// Owner role.
    pub owner_user: String,
    /// Owner certificate (copied in).
    pub owner_cert: PathBuf,
    /// Owner key (copied in).
    pub owner_key: PathBuf,
    /// `server.toml`.
    pub config: PathBuf,
}

impl PgSetup {
    /// Reads the `USGP_TEST_PG_*` variables, copies the files in and
    /// writes the configuration, after `edit` has changed its text.
    pub fn new(f: &Fixture, edit: impl FnOnce(String) -> String) -> Self {
        let db = DbFiles {
            host: var("USGP_TEST_PG_HOST"),
            port: var("USGP_TEST_PG_PORT").parse().unwrap(),
            dbname: var("USGP_TEST_PG_DBNAME"),
            user: var("USGP_TEST_PG_APP_USER"),
            server_name: var("USGP_TEST_PG_SERVER_NAME"),
            server_ca: copy_in(f, "USGP_TEST_PG_SERVER_CA", "pg-ca.pem", 0o644),
            client_cert: copy_in(f, "USGP_TEST_PG_APP_CERT", "pg-app.pem", 0o644),
            client_key: copy_in(f, "USGP_TEST_PG_APP_KEY", "pg-app.key", 0o600),
            // Decision 0016: local commands log in as the admin role.
            admin: Some((
                var("USGP_TEST_PG_ADMIN_USER"),
                copy_in(f, "USGP_TEST_PG_ADMIN_CERT", "pg-admin.pem", 0o644),
                copy_in(f, "USGP_TEST_PG_ADMIN_KEY", "pg-admin.key", 0o600),
            )),
        };
        let owner_user = var("USGP_TEST_PG_OWNER_USER");
        let owner_cert = copy_in(f, "USGP_TEST_PG_OWNER_CERT", "pg-owner.pem", 0o644);
        let owner_key = copy_in(f, "USGP_TEST_PG_OWNER_KEY", "pg-owner.key", 0o600);
        let config = f.write_config(&edit(f.config_text(&db)));
        Self {
            db,
            owner_user,
            owner_cert,
            owner_key,
            config,
        }
    }

    /// The config path as text.
    pub fn cfg(&self) -> &str {
        self.config.to_str().unwrap()
    }

    /// `migrate` as the owner.
    pub fn migrate(&self) -> Output {
        server(&[
            "migrate",
            "--config",
            self.cfg(),
            "--owner-user",
            &self.owner_user,
            "--owner-cert",
            self.owner_cert.to_str().unwrap(),
            "--owner-key",
            self.owner_key.to_str().unwrap(),
            "--admin-uid",
            &uid(),
        ])
    }

    /// `migrate` must apply something: the test needs a fresh database.
    pub fn migrate_fresh(&self) {
        let out = self.migrate();
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        assert!(
            !text(&out.stdout).contains("migrations applied: none"),
            "the database was already migrated: this test needs a fresh database"
        );
    }

    /// `operator enrol` as an administrator.
    pub fn enrol(&self, cert: &str, name: &str) -> Output {
        server(&[
            "operator",
            "enrol",
            "--config",
            self.cfg(),
            "--cert",
            cert,
            "--name",
            name,
            "--role",
            "administrator",
            "--admin-uid",
            &uid(),
        ])
    }

    /// Starts `serve`. The admin key is made unreadable first: `serve`
    /// refuses to start if it can read it (finding SEC-011; deployments
    /// make it root-owned 0600, the tests run as one uid).
    pub fn serve(&self) -> Serving {
        self.admin_key_mode(0o000);
        Serving::start(self.cfg())
    }

    /// Stops `serve` and makes the admin key readable to the local
    /// commands again.
    pub fn stop(&self, s: Serving) -> (Option<i32>, Vec<String>) {
        let r = s.stop();
        self.admin_key_mode(0o600);
        r
    }

    fn admin_key_mode(&self, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        if let Some((_, _, key)) = &self.db.admin {
            std::fs::set_permissions(key, std::fs::Permissions::from_mode(mode)).unwrap();
        }
    }

    /// `audit verify` with the public key file `key`.
    pub fn audit_verify(&self, key: &str) -> Output {
        server(&[
            "audit",
            "verify",
            "--config",
            self.cfg(),
            "--trusted-key",
            key,
            "--admin-uid",
            &uid(),
        ])
    }
}

/// A running `serve` child and its stdout lines.
pub struct Serving {
    child: Child,
    lines: mpsc::Receiver<String>,
    seen: Vec<String>,
    /// The listener address.
    pub addr: SocketAddr,
}

impl Serving {
    /// Starts `serve` and waits for `server.start`.
    pub fn start(config: &str) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_usgp-server"))
            .args([
                "serve",
                "--config",
                config,
                "--admin-uid",
                &uid(),
                "--allow-shared-admin-uid",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn serve");
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(l) = line else { break };
                if tx.send(l).is_err() {
                    break;
                }
            }
        });
        let mut s = Self {
            child,
            lines: rx,
            seen: Vec::new(),
            addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        };
        let line = s.wait_for("\"event\":\"server.start\"");
        s.addr = listen_addr(&line);
        s
    }

    /// The child's process id.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Waits up to 60 s for a stdout line containing `needle`.
    pub fn wait_for(&mut self, needle: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(60);
        if let Some(l) = self.seen.iter().find(|l| l.contains(needle)) {
            return l.clone();
        }
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match self.lines.recv_timeout(left) {
                Ok(l) => {
                    self.seen.push(l.clone());
                    if l.contains(needle) {
                        return l;
                    }
                }
                Err(_) => break,
            }
        }
        panic!(
            "{needle} not seen; output so far:\n{}",
            self.seen.join("\n")
        );
    }

    /// SIGTERM, then the exit status and the stdout lines.
    pub fn stop(mut self) -> (Option<i32>, Vec<String>) {
        let pid = self.child.id().to_string();
        let st = Command::new("kill").args(["-TERM", &pid]).status().unwrap();
        assert!(st.success());
        let code = self.child.wait().unwrap().code();
        while let Ok(l) = self.lines.recv_timeout(Duration::from_secs(5)) {
            self.seen.push(l);
        }
        (code, self.seen)
    }
}

/// The listener address from the `server.start` line (its detail holds
/// `listen` = `127.0.0.1:<port>`).
pub fn listen_addr(line: &str) -> SocketAddr {
    let at = line
        .find("127.0.0.1:")
        .expect("listen address in server.start");
    let rest = &line[at + "127.0.0.1:".len()..];
    let port: u16 = rest
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .unwrap();
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// The device listener's address from the `server.start` line (its
/// detail holds `device_listen` = `127.0.0.1:<port>`).
pub fn device_addr(line: &str) -> SocketAddr {
    let at = line
        .find("device_listen")
        .expect("device_listen in server.start");
    listen_addr(&line[at..])
}

/// Polls `GET <view>` (for example `/v1/images/<id>`) every 250 ms until
/// its body shows state `want`, for at most `limit`.
pub async fn wait_state(
    addr: SocketAddr,
    f: &Fixture,
    view: &str,
    want: &str,
    limit: Duration,
) -> super::Response {
    let deadline = Instant::now() + limit;
    loop {
        let r = https(addr, &f.pki, Some(&f.pki.client), "GET", view, None)
            .await
            .unwrap();
        assert_eq!(r.status, 200, "{}", r.body);
        if r.body.contains(&format!("\"state\":\"{want}\"")) {
            return r;
        }
        assert!(
            !r.body.contains("\"state\":\"failed\""),
            "{view} failed while waiting for {want}: {}",
            r.body
        );
        assert!(
            Instant::now() < deadline,
            "{view} never reached {want}: {}",
            r.body
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
