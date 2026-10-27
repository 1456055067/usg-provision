#!/usr/bin/env bash
# PostgreSQL for the `pg-integration` tests (plan WU-3b; decisions 0008 and
# 0012). Used by the CI job `pg-integration` and, optionally, by developers.
#
# What it sets up:
# - A throwaway test PKI made in a temporary directory (never in the work
#   tree, never committed): an ECDSA P-384 CA, a server certificate for
#   localhost / 127.0.0.1 / ::1, and client certificates whose CN is the role
#   name (usgp_owner, usgp_app, usgp_admin). The CA key is deleted once the certificates
#   are issued. All validity periods are 2 days.
# - A digest-pinned postgres:16 container, published on the loopback address
#   only. It is initialised by this script (container-run) rather than by the
#   image's entrypoint, because that entrypoint requires either a superuser
#   password or `trust` host access before first start. Here no password is
#   ever set and TCP is not opened until pg_hba.conf is final.
# - postgresql.conf: ssl = on, ssl_min_protocol_version = TLSv1.2, the test
#   CA as ssl_ca_file.
# - pg_hba.conf: certificate-only login over TLS for usgp_owner, usgp_app and
#   usgp_admin (the local administrative role, decision 0016),
#   no `host` lines, no password or trust methods. The one exception is
#   usgp_pwprobe, a role with no password that pg_hba asks for SCRAM: it
#   exists only so a test can show the driver refuses password
#   authentication (plan section 5.5). `check` fails if anything else asks
#   for a password, md5, SCRAM or trust, or if any role has a password.
#
# Usage:
#   scripts/pg-test-setup.sh up      make the PKI, start, check, smoke-test
#   scripts/pg-test-setup.sh check   re-run the configuration check
#   scripts/pg-test-setup.sh status  exit 0 if the container is running
#   scripts/pg-test-setup.sh down    remove the container and the PKI dir
#   scripts/pg-test-setup.sh hba     print the pg_hba.conf this script uses
#
# After `up`, "$USGP_PG_TEST_DIR/pg-test.env" holds the USGP_TEST_PG_*
# variables (KEY=VALUE lines; append to $GITHUB_ENV, or `set -a; . file`).
#
# Environment:
#   USGP_PG_TEST_DIR    PKI and env-file directory. Default:
#                       ${RUNNER_TEMP:-${TMPDIR:-/tmp}}/usgp-pg-test. Refused
#                       if inside the repository (except under target/) or
#                       if the path contains whitespace.
#   USGP_PG_TEST_PORT   host loopback port (default 55432).
#   USGP_PG_TEST_IMAGE  image reference; must end in @sha256:<64 hex>.
#
# Requires docker and openssl on the host.
#
# COMPLIANCE MAPPING:
# - NIST 800-53: IA-2, IA-5(2) (PKI-based database login), SC-8, SC-8(1)
#   (TLS to the database), CM-6 (secure configuration, checked), CM-2
#   (digest-pinned image)
# - Decisions 0008 (PostgreSQL), 0012 (certificate-only database login)
set -euo pipefail

# postgres:16.15 (Debian trixie; same index as the 16 and 16-trixie tags on
# 2026-10-27), multi-arch OCI index digest. Update deliberately (CM-3):
# resolve the new tag's index digest, record the version here, re-run CI.
readonly PG_IMAGE_DEFAULT='docker.io/library/postgres@sha256:9e2cf6287f25c3151f4c9421ccce2b17f3e60061c111a29165e0d2cdd9ff0a97'
readonly CONTAINER=usgp-pg-test
readonly DBNAME=usgp_test
readonly OWNER_ROLE=usgp_owner
readonly APP_ROLE=usgp_app
readonly ADMIN_ROLE=usgp_admin
readonly PROBE_ROLE=usgp_pwprobe
# Paths inside the container.
readonly C_PKI=/usgp/pki
readonly C_TLS=/var/lib/postgresql/usgp-tls
readonly C_DATA=/var/lib/postgresql/data

die() {
  echo "pg-test-setup: $*" >&2
  exit 1
}

# ------------------------------------------------------------ config text --

hba_conf() {
  cat << EOF
# pg_hba.conf for the pg-integration tests (scripts/pg-test-setup.sh).
# Decision 0012: database login is by TLS client certificate only.
# TYPE   DATABASE  USER                     ADDRESS    METHOD
# Superuser: Unix socket inside the container only (docker exec), no TCP.
local    all       postgres                            peer
# Password-refusal probe (plan section 5.5): the role has no password, so
# this line can never authenticate; it makes the server ask for SCRAM.
hostssl  all       ${PROBE_ROLE}             0.0.0.0/0  scram-sha-256
hostssl  all       ${PROBE_ROLE}             ::/0       scram-sha-256
# Owner (migrations) and application roles: certificate CN = role name.
hostssl  all       ${OWNER_ROLE},${APP_ROLE},${ADMIN_ROLE}  0.0.0.0/0  cert
hostssl  all       ${OWNER_ROLE},${APP_ROLE},${ADMIN_ROLE}  ::/0       cert
EOF
}

server_conf() {
  cat << EOF

# --- scripts/pg-test-setup.sh (plan WU-3b) ---
listen_addresses = '*'
ssl = on
ssl_cert_file = '${C_TLS}/server.crt'
ssl_key_file = '${C_TLS}/server.key'
ssl_ca_file = '${C_TLS}/ca.crt'
ssl_min_protocol_version = 'TLSv1.2'
password_encryption = 'scram-sha-256'
log_connections = on
log_line_prefix = '%m [%p] %q%u@%d '
EOF
}

# The configuration check, as one query over a relation with the columns of
# pg_hba_file_rules that matter. Prints one line per violation; no output
# means the rules are acceptable.
#   $1: SQL for the rule source (pg_hba_file_rules, or test rows)
hba_violations_sql() {
  cat << EOF
WITH rules AS ($1),
classified AS (
  SELECT r.*,
    (r.user_name && ARRAY['all', '${APP_ROLE}', '${OWNER_ROLE}', '${ADMIN_ROLE}']
      OR EXISTS (SELECT 1 FROM unnest(r.user_name) u
                 WHERE u LIKE '+%' OR u LIKE '/%')) AS covers_app
  FROM rules r
)
SELECT format('line %s: %s %s %s %s %s -- %s', line_number, type,
              array_to_string(database, ','), array_to_string(user_name, ','),
              coalesce(address, '-'), coalesce(auth_method, '-'), reason)
FROM (
  SELECT c.*, CASE
    WHEN c.error IS NOT NULL THEN 'parse error: ' || c.error
    WHEN c.type <> 'local' AND c.type <> 'hostssl'
      THEN 'connection type is not hostssl (TLS not required)'
    WHEN c.auth_method IN ('password', 'md5', 'trust')
      THEN 'password, md5 or trust method'
    WHEN c.covers_app AND c.auth_method NOT IN ('cert', 'reject')
      THEN 'app or owner role can log in without a certificate'
    WHEN c.covers_app AND array_to_string(c.options, ',') LIKE '%map=%'
      THEN 'identity map on a certificate rule'
    WHEN c.auth_method = 'scram-sha-256'
         AND c.user_name IS DISTINCT FROM ARRAY['${PROBE_ROLE}']
      THEN 'scram-sha-256 for a role other than the probe role'
    WHEN c.auth_method NOT IN ('cert', 'reject', 'peer', 'scram-sha-256')
      THEN 'unexpected method'
  END AS reason
  FROM classified c
) v
WHERE reason IS NOT NULL
ORDER BY line_number;
EOF
}

# --------------------------------------------------------------- helpers --

repo_root() {
  cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P
}

pki_dir() {
  local d="${USGP_PG_TEST_DIR:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/usgp-pg-test}"
  case "$d" in
    *[[:space:]]*) die "USGP_PG_TEST_DIR must not contain whitespace: '$d'" ;;
  esac
  mkdir -p "$d"
  d="$(cd "$d" && pwd -P)"
  local root
  root="$(repo_root)"
  case "$d/" in
    "$root/target/"*) ;;
    "$root/"*)
      rmdir "$d" 2> /dev/null || true
      die "refusing a key directory inside the work tree ($d); use target/ or a temp dir"
      ;;
  esac
  echo "$d"
}

image_ref() {
  local img="${USGP_PG_TEST_IMAGE:-$PG_IMAGE_DEFAULT}"
  [[ "$img" =~ @sha256:[0-9a-f]{64}$ ]] || die "image must be pinned by digest: $img"
  echo "$img"
}

port() {
  local p="${USGP_PG_TEST_PORT:-55432}"
  if ! { [[ "$p" =~ ^[0-9]{1,5}$ ]] && [ "$p" -ge 1 ] && [ "$p" -le 65535 ]; }; then
    die "bad port: $p"
  fi
  echo "$p"
}

# psql as the superuser over the container's Unix socket (peer).
su_psql() {
  docker exec -u postgres "$CONTAINER" psql -X -q -At -v ON_ERROR_STOP=1 -d postgres "$@"
}

# psql over TCP+TLS inside the container, as a client would connect.
#   $1: libpq connection string (host, user, TLS options); rest: psql args
tcp_psql() {
  local conn=$1
  shift
  docker exec "$CONTAINER" psql -X -q -At -w -v ON_ERROR_STOP=1 \
    "host=localhost port=5432 dbname=${DBNAME} connect_timeout=5 ${conn}" "$@"
}

# ------------------------------------------------------------------- PKI --

# issue <name> <subject CN> <ext file>: key + certificate signed by the CA.
issue() {
  local dir=$1 name=$2 cn=$3 ext=$4
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$dir/$name.key" 2> /dev/null
  openssl req -new -key "$dir/$name.key" -subj "/CN=$cn" -out "$dir/$name.csr"
  openssl x509 -req -in "$dir/$name.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" \
    -set_serial "0x$(openssl rand -hex 16)" -days 2 -sha384 -extfile "$ext" \
    -out "$dir/$name.crt" 2> /dev/null
  rm -f "$dir/$name.csr"
}

make_pki() {
  local dir=$1
  (
    umask 077
    rm -f "$dir"/*.key "$dir"/*.crt "$dir"/*.ext "$dir"/*.csr "$dir/pg-test.env"
    cat > "$dir/ca.ext" << 'EOF'
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF
    cat > "$dir/server.ext" << 'EOF'
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, IP:127.0.0.1, IP:::1
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF
    cat > "$dir/client.ext" << 'EOF'
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$dir/ca.key" 2> /dev/null
    openssl req -new -key "$dir/ca.key" -subj "/CN=usgp pg-integration test CA" -out "$dir/ca.csr"
    openssl x509 -req -in "$dir/ca.csr" -signkey "$dir/ca.key" \
      -set_serial "0x$(openssl rand -hex 16)" -days 2 -sha384 -extfile "$dir/ca.ext" \
      -out "$dir/ca.crt" 2> /dev/null
    rm -f "$dir/ca.csr"
    issue "$dir" server localhost "$dir/server.ext"
    issue "$dir" "$OWNER_ROLE" "$OWNER_ROLE" "$dir/client.ext"
    issue "$dir" "$APP_ROLE" "$APP_ROLE" "$dir/client.ext"
    issue "$dir" "$ADMIN_ROLE" "$ADMIN_ROLE" "$dir/client.ext"
    # Nothing else may be issued from this CA.
    rm -f "$dir/ca.key" "$dir"/*.ext "$dir"/*.srl
    # Readable by the container's root (keys stay 0600).
    chmod 0644 "$dir"/*.crt
  )
  for c in server "$OWNER_ROLE" "$APP_ROLE" "$ADMIN_ROLE"; do
    openssl verify -CAfile "$dir/ca.crt" "$dir/$c.crt" > /dev/null \
      || die "issued certificate $c.crt does not verify"
  done
}

write_env() {
  local dir=$1 p=$2
  {
    echo "USGP_TEST_PG_HOST=127.0.0.1"
    echo "USGP_TEST_PG_PORT=$p"
    echo "USGP_TEST_PG_SERVER_NAME=localhost"
    echo "USGP_TEST_PG_DBNAME=$DBNAME"
    echo "USGP_TEST_PG_SERVER_CA=$dir/ca.crt"
    echo "USGP_TEST_PG_OWNER_USER=$OWNER_ROLE"
    echo "USGP_TEST_PG_OWNER_CERT=$dir/$OWNER_ROLE.crt"
    echo "USGP_TEST_PG_OWNER_KEY=$dir/$OWNER_ROLE.key"
    echo "USGP_TEST_PG_APP_USER=$APP_ROLE"
    echo "USGP_TEST_PG_APP_CERT=$dir/$APP_ROLE.crt"
    echo "USGP_TEST_PG_APP_KEY=$dir/$APP_ROLE.key"
    echo "USGP_TEST_PG_ADMIN_USER=$ADMIN_ROLE"
    echo "USGP_TEST_PG_ADMIN_CERT=$dir/$ADMIN_ROLE.crt"
    echo "USGP_TEST_PG_ADMIN_KEY=$dir/$ADMIN_ROLE.key"
    echo "USGP_TEST_PG_PWPROBE_USER=$PROBE_ROLE"
  } > "$dir/pg-test.env"
}

# ------------------------------------------------------ inside container --

# Runs as root inside the postgres image (entrypoint override).
container_run() {
  install -d -o postgres -g postgres -m 0700 "$C_TLS" "$C_DATA"
  install -o postgres -g postgres -m 0600 "$C_PKI/server.key" "$C_TLS/server.key"
  install -o postgres -g postgres -m 0644 "$C_PKI/server.crt" "$C_PKI/ca.crt" "$C_TLS/"
  # No -W/--pwfile: the superuser has no password. Host access starts as
  # reject; pg_hba.conf is replaced below before TCP is opened.
  gosu postgres initdb -D "$C_DATA" -U postgres -E UTF8 --no-locale \
    --auth-local=peer --auth-host=reject > /dev/null
  server_conf >> "$C_DATA/postgresql.conf"
  hba_conf > "$C_DATA/pg_hba.conf"
  chown postgres:postgres "$C_DATA/postgresql.conf" "$C_DATA/pg_hba.conf"
  chmod 0600 "$C_DATA/pg_hba.conf"
  # Socket-only start to create the roles; TCP opens on the final start.
  gosu postgres pg_ctl -D "$C_DATA" -o "-c listen_addresses=''" -w -s start
  # No PASSWORD clause anywhere: rolpassword stays NULL for every role.
  # usgp_owner gets CREATEDB so tests can make isolated databases; it is
  # not a superuser and cannot create roles. Grants on schema objects are
  # the job of migrations 0002 and 0003 (plan section 3.4, decision 0016).
  gosu postgres psql -X -q -v ON_ERROR_STOP=1 -d postgres << EOF
CREATE ROLE ${OWNER_ROLE} LOGIN NOSUPERUSER NOCREATEROLE CREATEDB NOREPLICATION NOBYPASSRLS;
CREATE ROLE ${APP_ROLE} LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
CREATE ROLE ${ADMIN_ROLE} LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
CREATE ROLE ${PROBE_ROLE} LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
CREATE DATABASE ${DBNAME} OWNER ${OWNER_ROLE};
REVOKE ALL ON DATABASE ${DBNAME} FROM PUBLIC;
GRANT CONNECT ON DATABASE ${DBNAME} TO ${APP_ROLE};
GRANT CONNECT ON DATABASE ${DBNAME} TO ${ADMIN_ROLE};
EOF
  gosu postgres pg_ctl -D "$C_DATA" -m fast -w -s stop
  exec gosu postgres postgres -D "$C_DATA"
}

# ------------------------------------------------------------ host side --

wait_ready() {
  local i
  for i in $(seq 1 60); do
    if [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2> /dev/null)" != true ]; then
      docker logs "$CONTAINER" >&2 || true
      die "container exited during start-up"
    fi
    if docker exec "$CONTAINER" pg_isready -q -h 127.0.0.1 -p 5432; then
      return 0
    fi
    [ "$i" -lt 60 ] && sleep 1
  done
  docker logs "$CONTAINER" >&2 || true
  die "PostgreSQL did not accept TCP connections within 60 s"
}

# expect_refused <label> <conn> : the TCP login must fail.
expect_refused() {
  local label=$1 conn=$2 out
  if out="$(tcp_psql "$conn" -c 'SELECT 1' 2>&1)"; then
    die "smoke: $label was accepted; it must be refused"
  fi
  echo "ok: refused: $label ($(echo "$out" | tail -n 1))"
}

check() {
  local out line bad=0
  echo "== pg_hba rules in force (pg_hba_file_rules)"
  su_psql -c "SELECT line_number, type, array_to_string(database, ','), array_to_string(user_name, ','), coalesce(address, '-'), auth_method FROM pg_hba_file_rules ORDER BY line_number" \
    | sed 's/^/  /'
  out="$(su_psql -c "$(hba_violations_sql "SELECT line_number, type, database, user_name, address, auth_method, options, error FROM pg_hba_file_rules")")"
  if [ -n "$out" ]; then
    while IFS= read -r line; do
      echo "  VIOLATION $line" >&2
    done <<< "$out"
    echo "check: pg_hba allows a non-certificate login (decision 0012)" >&2
    bad=1
  fi
  out="$(su_psql -c "SELECT rolname FROM pg_authid WHERE rolpassword IS NOT NULL ORDER BY 1")"
  if [ -n "$out" ]; then
    echo "check: roles with a password set (decision 0012): $out" >&2
    bad=1
  fi
  out="$(su_psql -c "SELECT current_setting('ssl') || ' ' || current_setting('ssl_min_protocol_version')")"
  case "$out" in
    "on TLSv1.2" | "on TLSv1.3") echo "ok: ssl and minimum protocol: $out" ;;
    *)
      echo "check: ssl settings are '$out', expected 'on TLSv1.2' or stricter" >&2
      bad=1
      ;;
  esac
  [ "$bad" -eq 0 ] || die "configuration check FAILED"
  echo "ok: certificate-only login; no password, md5, scram or trust for ${APP_ROLE}/${OWNER_ROLE}/${ADMIN_ROLE}; no role has a password"
}

# The check must catch each bad rule and pass each good one.
check_selftest() {
  local rows out expected
  rows="SELECT * FROM (VALUES
    (101, 'host',      ARRAY['all'], ARRAY['all'],        '0.0.0.0/0', 'md5',           NULL::text[], NULL::text),
    (102, 'hostssl',   ARRAY['all'], ARRAY['${APP_ROLE}'], '0.0.0.0/0', 'scram-sha-256', NULL, NULL),
    (103, 'hostssl',   ARRAY['all'], ARRAY['all'],        '0.0.0.0/0', 'trust',         NULL, NULL),
    (104, 'hostssl',   ARRAY['all'], ARRAY['+admins'],    '0.0.0.0/0', 'password',      NULL, NULL),
    (105, 'hostnossl', ARRAY['all'], ARRAY['${APP_ROLE}'], '0.0.0.0/0', 'cert',          NULL, NULL),
    (106, 'hostssl',   ARRAY['all'], ARRAY['${APP_ROLE}'], '0.0.0.0/0', 'cert',          ARRAY['map=m'], NULL),
    (107, 'local',     ARRAY['all'], ARRAY['all'],        NULL,        'trust',         NULL, NULL),
    (108, 'hostssl',   ARRAY['all'], ARRAY['/^usgp'],     '0.0.0.0/0', 'scram-sha-256', NULL, NULL),
    (109, 'hostssl',   ARRAY['all'], ARRAY['${ADMIN_ROLE}'], '0.0.0.0/0', 'ldap',        NULL, NULL),
    (110, 'hostssl',   ARRAY['all'], ARRAY['other'],      '0.0.0.0/0', 'scram-sha-256', NULL, NULL),
    (111, 'local',     ARRAY['all'], ARRAY['${APP_ROLE}'], NULL,        'peer',          NULL, NULL),
    (112, NULL,        NULL,         NULL,                NULL,        NULL,            NULL, 'syntax error'),
    (201, 'local',     ARRAY['all'], ARRAY['postgres'],   NULL,        'peer',          NULL, NULL),
    (202, 'hostssl',   ARRAY['all'], ARRAY['${PROBE_ROLE}'], '0.0.0.0/0', 'scram-sha-256', NULL, NULL),
    (203, 'hostssl',   ARRAY['all'], ARRAY['${OWNER_ROLE}','${APP_ROLE}'], '::/0', 'cert', NULL, NULL),
    (204, 'hostssl',   ARRAY['all'], ARRAY['all'],        '0.0.0.0/0', 'reject',        NULL, NULL)
  ) AS t(line_number, type, database, user_name, address, auth_method, options, error)"
  out="$(su_psql -c "$(hba_violations_sql "$rows")" | sed -n 's/^line \([0-9]*\):.*/\1/p' | tr '\n' ' ')"
  expected="101 102 103 104 105 106 107 108 109 110 111 112 "
  if [ "$out" != "$expected" ]; then
    die "check self-test: flagged lines '$out', expected '$expected' (1xx bad, 2xx good)"
  fi
  echo "ok: check self-test (12 bad rules flagged, 4 good rules passed)"
}

smoke() {
  local p="$C_PKI" got
  local verify="sslmode=verify-full sslrootcert=$p/ca.crt"
  got="$(tcp_psql "user=$APP_ROLE $verify sslcert=$p/$APP_ROLE.crt sslkey=$p/$APP_ROLE.key" \
    -c "SELECT current_user || ' ' || ssl::text || ' ' || version FROM pg_stat_ssl WHERE pid = pg_backend_pid()")"
  echo "ok: accepted: $APP_ROLE with its certificate ($got)"
  case "$got" in "$APP_ROLE true TLSv1."[23]) ;; *) die "smoke: unexpected session '$got'" ;; esac
  got="$(tcp_psql "user=$OWNER_ROLE $verify sslcert=$p/$OWNER_ROLE.crt sslkey=$p/$OWNER_ROLE.key" \
    -c "SELECT current_user")"
  [ "$got" = "$OWNER_ROLE" ] || die "smoke: owner login gave '$got'"
  echo "ok: accepted: $OWNER_ROLE with its certificate"
  got="$(tcp_psql "user=$ADMIN_ROLE $verify sslcert=$p/$ADMIN_ROLE.crt sslkey=$p/$ADMIN_ROLE.key" \
    -c "SELECT current_user")"
  [ "$got" = "$ADMIN_ROLE" ] || die "smoke: admin login gave '$got'"
  echo "ok: accepted: $ADMIN_ROLE with its certificate"
  expect_refused "plaintext connection" "user=$APP_ROLE sslmode=disable"
  expect_refused "TLS without a client certificate" "user=$APP_ROLE $verify sslcertmode=disable"
  expect_refused "$APP_ROLE with the owner's certificate (CN mismatch)" \
    "user=$APP_ROLE $verify sslcert=$p/$OWNER_ROLE.crt sslkey=$p/$OWNER_ROLE.key"
  expect_refused "$ADMIN_ROLE with the application certificate (CN mismatch)" \
    "user=$ADMIN_ROLE $verify sslcert=$p/$APP_ROLE.crt sslkey=$p/$APP_ROLE.key"
  expect_refused "$PROBE_ROLE (server asks for SCRAM; no password exists)" \
    "user=$PROBE_ROLE $verify sslcert=$p/$APP_ROLE.crt sslkey=$p/$APP_ROLE.key"
}

up() {
  command -v docker > /dev/null || die "docker not found"
  command -v openssl > /dev/null || die "openssl not found"
  local dir img p root bound
  dir="$(pki_dir)"
  img="$(image_ref)"
  p="$(port)"
  root="$(repo_root)"
  docker rm -f -v "$CONTAINER" > /dev/null 2>&1 || true
  make_pki "$dir"
  echo "ok: test PKI in $dir (CA key deleted after issuance)"
  docker pull -q "$img" > /dev/null
  echo "image: $img"
  docker image inspect -f 'image id: {{.Id}}' "$img"
  docker run -d --name "$CONTAINER" --pull never \
    -p "127.0.0.1:$p:5432" \
    -v "$dir:$C_PKI:ro" \
    -v "$root/scripts/pg-test-setup.sh:/usgp/pg-test-setup.sh:ro" \
    --entrypoint /bin/bash \
    "$img" /usgp/pg-test-setup.sh container-run > /dev/null
  wait_ready
  bound="$(docker port "$CONTAINER" 5432/tcp)"
  [ "$bound" = "127.0.0.1:$p" ] || die "port published as '$bound', expected 127.0.0.1:$p only"
  echo "ok: listening on $bound (loopback only)"
  echo "ok: $(su_psql -c 'SELECT version()')"
  check
  check_selftest
  smoke
  write_env "$dir" "$p"
  echo "env: $dir/pg-test.env"
}

down() {
  docker rm -f -v "$CONTAINER" > /dev/null 2>&1 || true
  local dir
  dir="$(pki_dir)"
  rm -f "$dir"/*.key "$dir"/*.crt "$dir/pg-test.env"
  rmdir "$dir" 2> /dev/null || true
  echo "ok: container removed, test keys deleted"
}

case "${1:-}" in
  up) up ;;
  check) check ;;
  status) [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2> /dev/null)" = true ] ;;
  down) down ;;
  hba) hba_conf ;;
  container-run) container_run ;;
  *)
    sed -n '/^# Usage:/,/^# Requires/p' "${BASH_SOURCE[0]}" >&2
    exit 2
    ;;
esac
