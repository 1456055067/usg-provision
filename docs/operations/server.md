# Operating `usgp-server` (milestones M2 and M3)

`usgp-server` is the control plane. In M2 it holds Windows images and
Windows PE kits in a content-addressed, integrity-protected store, lists
the editions of an uploaded WIM, builds deployment packages from one
edition and one PE, signs content and package manifests, and serves an
operator API over mutual TLS. Every operator action and every refusal is
written to a tamper-evident audit chain in PostgreSQL.

M3 adds a second, separate listener for pre-boot devices (the
[device listener](#device-listener)), operator-issued device codes and
console approval of waiting devices, signed job plans, job progress and
failure records, and a minimal, manual enrolment of relays as boot
services with a signed boot-policy list that tells each relay which
devices to stop booting (decision 0021).

**M3 evidence status (read first).** M3 is **not met**. The owner's lab
procedure MT-2 (steps L1 to L12, [MT-2-lab.md](../testing/MT-2-lab.md))
is NOT RUN, and so is M2's MT-1. CI on `m3/build`:

- run 40818350636 (commit 647af22): all 19 jobs passed, before the
  reviews and the review fix rounds;
- run 40876728637 (commit 349de13): boot smoke S10 (GPT-OBS-002) and S1
  to S8 passed; the Windows VHD step and S9 failed;
- run 40910029759 (commit fff029f): S9 passed, GPT-OBS-001 was
  accepted, and boot smoke passed 11 of 11; `gates` and `pg-integration`
  timed out on a test hang that was fixed afterwards;
- run 40928612312 (commit 21c1efb): conclusion
  failure. `gates`, `pg-integration`, boot smoke S1 to S10, `fuzz-smoke`
  (24 targets) and `large-upload` passed. In `windows-agent` the FIPS
  probe and the raw-disk VHD test passed (GPT-OBS-001 accepted again),
  and the BOOT-004 VHD test failed: Windows refused (error 87) to assign
  a drive letter to the new Windows partition, before any format. The
  agent's own Windows letter step may fail the same way after the wipe;
  this was fixed in fix round 4 (POAM-53, closed);
- run 40980499705 (commit 7cd5ecf, after fix rounds 4 to 7): all 35
  jobs passed, including `windows-agent` with every VHD and WinSink test.

The M3 behaviour below is tested in-process (QA run on commit 647af22,
macOS, functional evidence only) and by the review fix rounds' own
tests, which passed in CI (runs 40928612312 and 40980499705) but have
no QA re-run. See
[TEST_EVIDENCE.md](../compliance/TEST_EVIDENCE.md).

**M2 evidence status (read first).** The server's behaviour is tested
in-process on the in-memory store, on a macOS development host, which is
functional evidence only (POAM-2). The CI runs on commit 5ea03a1 on
Linux (2026-10-28 UTC; `ci` runs 40633650457 and 40633638960,
`wim-samples` runs 40633638946 and 40633653170, all successful) gave
the following results; see
[ATO_EVIDENCE.md](../compliance/ATO_EVIDENCE.md):

- **PASS:** the PostgreSQL tests (`pg-integration`, CI runs 40633650457
  and 40633638960): `migrate_pg` 9, including `newer_schema_refused`;
  `repo_pg` (role grants) 9; `audit_pg` 9; and `e2e_pg` (the end-to-end
  flow on PostgreSQL, with restart recovery and `audit verify`) 1. On
  the earlier commit d72b761 this job failed on a stale test (POAM-34,
  now closed).
- **PASS:** the 10.5 GiB upload on PostgreSQL with the 256 MiB memory
  bound (`large-upload`, CI run 40633650457). The server's peak resident
  memory was 54 MiB (51 MiB on d72b761), and `audit verify` reported the
  chain intact.
- **PASS:** 600 s fuzzing of the WIM and XPRESS parsers (`fuzz-smoke`,
  CI run 40633650457). These runs were built without ASan (POAM-37).
- **PASS:** the Linux check of our own DISM-made sample WIMs
  (`wim-samples` `verify`, runs 40633638946 and 40633653170), with the
  S11/S12 rules described under
  [WIM acceptance rules](#wim-acceptance-rules-and-reason-codes). These
  CI results are not QA results.
- **NOT RUN:** the manual procedure MT-1 with licensed Windows 11
  Enterprise media (M2 exit 1a; POAM-33). M2 is met except exit 1a
  (MT-1, owner action), so M2 is **not met**.

The example configuration and the service unit in this guide are
**examples: not shipped and not tested**. Every default below is
**project design** (CM-6), not described product behaviour.

## Contents

- [Host requirements](#host-requirements)
- [Accounts, files, ownership and modes](#accounts-files-ownership-and-modes)
- [PostgreSQL setup](#postgresql-setup)
- [Keys](#keys)
- [Command line](#command-line)
- [Configuration reference](#configuration-reference)
- [Example configuration](#example-configuration)
- [Example service unit](#example-service-unit)
- [Operators](#operators)
- [Device listener](#device-listener)
- [Device codes and approval](#device-codes-and-approval)
- [Boot services (relay enrolment)](#boot-services-relay-enrolment)
- [Jobs](#jobs)
- [Boot stops](#boot-stops)
- [TLS, CRL refresh and revocation](#tls-crl-refresh-and-revocation)
- [Audit](#audit)
- [Time synchronisation](#time-synchronisation)
- [Backup and restore](#backup-and-restore)
- [Schema migrations and upgrades](#schema-migrations-and-upgrades)
- [Supported content](#supported-content)
- [WIM acceptance rules and reason codes](#wim-acceptance-rules-and-reason-codes)
- [Other API reason codes](#other-api-reason-codes)
- [Limits](#limits)
- [Network controls](#network-controls)
- [Known gaps](#known-gaps)
- [Document Change History](#document-change-history)

## Host requirements

- A Unix host. The trusted-file and content-root checks are Unix only;
  elsewhere the server refuses to start (`unsupported_platform`). Linux
  is the release platform; macOS is development only (POAM-2).
- The FIPS module in FIPS mode. Every command checks it first and exits
  1 if it is inactive (decision 0001).
- PostgreSQL 15 or later, reachable over TLS (decision 0008).
- A filesystem for the content root large enough for the largest upload
  plus its staging copy (`content.max_upload_bytes`, default 32 GiB).
- A time synchronisation service (see
  [Time synchronisation](#time-synchronisation)).
- A host name, or `node_name` set in the configuration. The host name is
  read from Linux procfs, so on other hosts `node_name` is required.

## Accounts, files, ownership and modes

Create a dedicated service account and group, for example user
`usgp-server` in group `usgp-server`. That account must own none of the
trusted files below except the content root.

Trusted files (configuration, certificates, CRLs, keys) are read with the
same rules as the relay: a regular file, not a symbolic link, owned by
root or by the `--admin-uid`, not group- or world-writable, and every
directory above it owned by root or that uid and not group- or
world-writable unless sticky. The checks are repeated on the opened
handle. ACLs are not inspected (POAM-7): put no ACLs on these paths.

| Path (example) | Owner:group | Mode | Rule |
|----------------|-------------|------|------|
| `/etc/usgp-server/server.toml` | `root:usgp-server` | 0640 | Trusted file, at most 64 KiB |
| `/etc/usgp-server/tls/server.pem`, `operator-cas.pem`, `crl/*.crl` | `root:root` | 0644 | Trusted files |
| `/etc/usgp-server/tls/server.key` | `root:usgp-server` | 0640 | Service private key (below) |
| `/etc/usgp-server/db/ca.pem`, `app.pem` | `root:root` | 0644 | Trusted files |
| `/etc/usgp-server/db/app.key` | `root:usgp-server` | 0640 | Service private key (below) |
| `/etc/usgp-server/keys/content.p8`, `audit.p8` | `root:usgp-server` | 0640 | Service private keys (below) |
| `/etc/usgp-server/keys/plan.p8`, `boot-policy.p8`, `code-hmac.key` (M3) | `root:usgp-server` | 0640 | Service private keys (below) |
| `/etc/usgp-server/tls/device.pem` (M3) | `root:root` | 0644 | Device listener certificate chain |
| `/etc/usgp-server/tls/device.key` (M3) | `root:usgp-server` | 0640 | Device listener key; service private key (below) |
| `/etc/usgp-server/keys/*.pub` | `root:root` | 0644 | Public keys |
| `/etc/usgp-server/db/admin.pem` | `root:root` | 0644 | Trusted file |
| `/etc/usgp-server/db/admin.key` | `root:root` | **0600** | Administrative key (below) |
| `/root/usgp-owner/owner.key` (not in the configuration) | `root:root` | **0600** | Migration key (below) |
| `/var/lib/usgp-server/content` | `usgp-server:usgp-server` | **0700** | Content root |

Private key rules (SC-12, AC-6):

- **Keys the service reads** (TLS key, `[database]` client key, content
  and audit signing keys; in M3 also the device listener key, the plan
  and boot-policy signing keys and the code HMAC key) must not be
  readable by others, and may be
  group-readable only when the group is the service's own (the effective
  gid of `serve`). Use `root:<service group> 0640`, or `0600`. `serve`,
  running as the service user, applies the full rule at every start. A
  command run as root cannot know the service group, so it accepts a
  group-readable key of any group (it still refuses a world-readable
  one).
- **Administrative keys** (the `[database.admin]` client key and the
  `migrate --owner-key`) must be readable by their owner only: `0600` or
  `0400`, whoever runs the command, root included. Any group or other
  bit is refused.
- **`serve` refuses to start** (exit 78, `server.start.refused` reason
  `admin_key_readable_by_service`, field `database.admin.client_key`) if
  it can open the configured `[database.admin]` client key. This is an
  access test, so it also catches a key owned by the service account.
  Consequence: never run `serve` as root with `[database.admin]`
  configured; root can open the key and the server refuses.
- `serve` cannot check the owner key, which is never in the
  configuration; `migrate` applies the owner-only rule when it reads it
  (POAM-30).
- `--check-config` does not apply the serve-time readability check of
  the admin key.

The content root must be a directory owned by the service uid with no
group or other access (`mode & 0o077 == 0`); otherwise `serve` refuses
(`content_root_mode_not_0700`, `content_root_not_owned_by_service`,
`content_root_not_a_directory`, `content_root_unreadable`). It holds
`staging/` (uploads in progress) and `objects/` (Ready content, files
mode 0440, read-only).

The service account must not be the `--admin-uid`: `serve` refuses to
run as that uid (exit 78, `service_uid_is_admin_uid`) unless
`--allow-shared-admin-uid` is given, and records the opt-in in
`server.start`.

## PostgreSQL setup

The server logs in to PostgreSQL with TLS client certificates only. No
database password exists anywhere: the configuration has no password key,
and a `password`, `passfile`, `url`, `connection_string` or `sslmode` key
refuses start-up (decision 0012). Three roles are needed (decision 0016):

| Role | Used by | Rights |
|------|---------|--------|
| `usgp_owner` (any name; given to `migrate`) | `usgp-server migrate` only | Owns the database and schema; runs migrations |
| `usgp_app` (this exact name) | `serve` | Granted by migration 0002; since migration 0003 no INSERT, UPDATE or DELETE on operator records; no UPDATE or DELETE on audit records or checkpoints |
| `usgp_admin` (this exact name) | `operator enrol`, `operator disable`, `audit verify`; in M3 also `boot-service enrol`, `disable` and `raise-generation` | Granted by migration 0003: read, insert and update operator records (no delete); append to and read the audit chain. Migration 0004 (M3) adds read, insert and update on boot-service records and on the boot-policy generation; only this role may write boot-service records |

Steps, by the database administrator:

1. Create the three roles as `LOGIN` roles **with no password**, none of
   them superuser, `usgp_app` and `usgp_admin` without `CREATEDB` or
   `CREATEROLE`. The migrations grant to the literal names `usgp_app` and
   `usgp_admin`, so those two names are fixed.
2. **Create `usgp_admin` before migrating to schema 3.** Migration 0003
   fails if the role does not exist (as 0002 does for `usgp_app`).
3. Create the database owned by the owner role.
4. Issue one TLS client certificate per role, each with the role name as
   its common name, and give each key to its user only (see the table
   above).
5. Server settings: `ssl = on`, `ssl_min_protocol_version = 'TLSv1.2'`.
   In `pg_hba.conf`, only `hostssl ... cert` lines for these three roles;
   no `host` lines and no password methods for them.
6. Run `usgp-server migrate` as root (or the `--admin-uid`) with the
   owner role's certificate (see [Command line](#command-line)).

The server's database client always uses TLS, verifies the server
certificate against `database.server_ca` and the name in
`database.server_name` (default: `database.host`), and never falls back
to a plaintext connection. It does not check the database server
certificate for revocation (POAM-21). The client TLS minimum is 1.2 and
has no setting.

The test procedure (`scripts/pg-test-setup.sh`) is in
`docs/BUILDING.md` section 8. It is a test fixture, not a production
installer.

## Keys

Generate the two signing keys inside the FIPS module, one per purpose:

```sh
usgp-server keygen --purpose content \
  --out-key /etc/usgp-server/keys/content.p8 \
  --out-pub /etc/usgp-server/keys/content.pub
usgp-server keygen --purpose audit \
  --out-key /etc/usgp-server/keys/audit.p8 \
  --out-pub /etc/usgp-server/keys/audit.pub
chown root:usgp-server /etc/usgp-server/keys/content.p8 \
  /etc/usgp-server/keys/audit.p8
chmod 0640 /etc/usgp-server/keys/content.p8 /etc/usgp-server/keys/audit.p8
```

- Keys are ECDSA P-384. The private key is written as PKCS#8 PEM to a
  **new** file (an existing file or a symbolic link is refused), mode
  0600, owned by the invoker; the public key is SPKI PEM, mode 0644.
- `keygen` prints the purpose and the **key id** (SHA-256 of the public
  key). **Record each key id out of band** (for example in the system's
  configuration record). `keygen` has no database connection, so it
  writes only an unpersisted `key.generated` line (or
  `key.generation.failed`) to stdout; forward it to the SIEM.
- The content and audit keys must be different files and different keys
  (`audit_key_equals_content_key`); the audit key must not be listed in
  `signing.previous_content_pubs`.
- Verifiers take trusted public keys from files only, never from the
  database: `audit verify --trusted-key`, and the operator CLI's pinned
  `--content-key-pub`.
- **Rotation.** Generate a new key, point `signing.content_key` at it,
  and add the old public key to `signing.previous_content_pubs` so that
  manifests it signed still verify. Distribute the new public key to
  operators. For the audit key, keep every old public key: `audit
  verify` needs all of them (`--trusted-key` may be repeated up to 16
  times).
- Keys are plaintext files with no HSM and no encryption at rest. A
  compromise of root on the server host can sign manifests and
  checkpoints (POAM-18).

### Keys for the device listener (M3)

The device listener needs three more keys, one per purpose. They are
configured together (all three or none), each must be a file of its
own, and none may be the content or audit key file
(`must be a file of its own (one key per purpose)`). `device_api.enabled
= true` without them refuses start-up (field `device_api.enabled`).

```sh
usgp-server keygen --purpose plan \
  --out-key /etc/usgp-server/keys/plan.p8 \
  --out-pub /etc/usgp-server/keys/plan.pub
usgp-server keygen --purpose boot-policy \
  --out-key /etc/usgp-server/keys/boot-policy.p8 \
  --out-pub /etc/usgp-server/keys/boot-policy.pub
usgp-server keygen --purpose code-hmac \
  --out-key /etc/usgp-server/keys/code-hmac.key
chown root:usgp-server /etc/usgp-server/keys/plan.p8 \
  /etc/usgp-server/keys/boot-policy.p8 /etc/usgp-server/keys/code-hmac.key
chmod 0640 /etc/usgp-server/keys/plan.p8 \
  /etc/usgp-server/keys/boot-policy.p8 /etc/usgp-server/keys/code-hmac.key
```

| Key | Purpose | Public half goes to |
|-----|---------|---------------------|
| `signing.plan_key` (ECDSA P-384) | Signs each job plan given to a device | The agent's `plan.pub`, through `usgp-cli pe agent-config` ([winpe-kit.md](winpe-kit.md)) |
| `signing.content_key` (M2) | Signs content and package manifests | The agent's `content.pub`, and the operator CLI's `--content-key-pub` |
| `signing.boot_policy_key` (ECDSA P-384) | Signs the boot-policy list each relay pulls | Each relay's `server_feed.boot_policy_key_pub` ([relay.md](relay.md#server_feed-m3)) |
| `codes.hmac_key` | Keys the HMAC-SHA-256 under which device codes are stored; codes are never stored in clear | No public half and no key id. Exactly 32 raw bytes from the module's DRBG, loaded into a wiped buffer |

- The plan and content keys must differ: `pe agent-config` refuses two
  equal public keys.
- The agent and the relays pin these public keys. Rotating the plan or
  content key means building new agent configurations
  ([winpe-kit.md](winpe-kit.md)); rotating the boot-policy key means
  updating every relay's `boot_policy_key_pub`. There is no rotation
  list for the plan or boot-policy key.
- Rotating `codes.hmac_key` makes every unused code unusable.
- `server.start` records `device_listen` and the plan and boot-policy key
  ids.

## Command line

The FIPS check runs before every command.

| Command | Purpose | Exit status |
|---------|---------|-------------|
| `usgp-server --self-check` | FIPS check only | 0; 1 FIPS inactive |
| `usgp-server --check-config PATH [--admin-uid UID]` | Validate the configuration and every file it names; build the TLS acceptor and the database TLS client. Connects to nothing, binds nothing, does not check the content root or the admin-key readability rule | 0 valid; 78 invalid; 1 FIPS |
| `usgp-server serve --config PATH [--admin-uid UID] [--allow-shared-admin-uid]` | Run the server | 0 clean stop; 78 configuration, trust or key error; 1 FIPS, database, schema version, audit, bind or runtime failure |
| `usgp-server migrate --config PATH --owner-user NAME --owner-cert PEM --owner-key PEM [--admin-uid UID]` | Apply pending migrations as the owner role | 0; 78; 77 not a local administrator; 1 |
| `usgp-server keygen --purpose content\|audit\|plan\|boot-policy --out-key FILE --out-pub FILE` | Generate a signing key (`plan` and `boot-policy` are M3) | 0; 1 |
| `usgp-server keygen --purpose code-hmac --out-key FILE` | Generate the device-code HMAC key (M3; `--out-pub` is refused) | 0; 1 |
| `usgp-server operator enrol --config PATH --cert PEM --name NAME --role administrator\|none [--admin-uid UID]` | Bind one certificate to one operator | 0; 2 bad name; 78 (also if `[database.admin]` is absent); 77; 1 refused or database |
| `usgp-server operator disable --config PATH --id UUID [--admin-uid UID]` | Disable an operator (0 also if already disabled) | 0; 2 bad id; 78; 77; 1 |
| `usgp-server audit verify --config PATH --trusted-key PEM [--trusted-key PEM ...] [--max-unsigned-records N] [--max-checkpoint-age DUR] [--admin-uid UID]` | Verify the audit chain | 0 intact; 1 tampered or policy violated; 69 chain unreadable (not verified); 78; 77; 2 usage |
| `usgp-server boot-service enrol --config PATH --cert PEM --name NAME --subnet CIDR [--subnet CIDR ...] [--admin-uid UID]` | Bind one relay client certificate to a new boot service and the subnets it serves (M3, decision 0021) | 0; 78; 77; 1 refused or database |
| `usgp-server boot-service disable --config PATH --id UUID [--admin-uid UID]` | Disable a boot service (M3) | 0; 78; 77; 1 |
| `usgp-server boot-service raise-generation --config PATH --id UUID --to N [--admin-uid UID]` | Raise a boot service's boot-policy generation after a restore (M3) | 0; 78; 77; 1 |
| `usgp-server -h` / `--help` | Usage on stdout | 0 |
| no arguments, or anything else | Usage on stderr | 2 |

Exit status summary: 0 success; 1 failure (for `audit verify`, a broken
chain); 2 usage; 69 the chain could not be read; 77 a local
administrative command run by someone other than root or the owner of
the configuration file; 78 configuration, trust or key error. Note that
`scripts/gates.sh` uses 77 for NOT RUN; that is a different context.

`--admin-uid UID` names one uid, besides root, that may own the trusted
files. The local administrative commands (`migrate`, `operator`,
`audit verify`, `boot-service`) run only as root or as the owner of the
configuration
file they load (named on the command line). **That check is a guard
against mistakes, not the access control**: any local user can write a
configuration file of their own. The access control is possession of the
`usgp_admin` client key (root only, mode 0600) for `operator`, `audit
verify` and `boot-service`, and of the owner key for `migrate` (decision
0016; POAM-30). `keygen` has no restriction; it only creates new files
the invoker owns.

The certificates given to `operator enrol` and `boot-service enrol` are
read under the trusted-file rules, because they decide who becomes an
administrator and which relay may pull a boot-policy list.

## Configuration reference

`/etc/usgp-server/server.toml` is a trusted file of at most 64 KiB.
Unknown keys at any level are refused, every value is range-checked, and
paths must be absolute (1 to 4096 bytes, no NUL). Any violation refuses
start-up with exit 78 and a `server.start.refused` record naming the key
(never the value). `--check-config` applies the same rules.

### Top level

| Key | Default | Range / rule |
|-----|---------|--------------|
| `schema_version` | required | must be 1 |
| `node_name` | host name | 1 to 64 characters, no control characters; required when no host name is available. The audit "where" label (AU-3) |

### `[api]`

| Key | Default | Range / rule |
|-----|---------|--------------|
| `listen` | `127.0.0.1:8443` (loopback) | IP address and port |
| `max_connections` | 64 | 1 to 4096 |
| `max_connections_per_source` | 16 | 1 to `max_connections`. Source = IPv4 address or IPv6 /64 |
| `max_handshakes_per_source` | 8 | 1 to `max_connections_per_source` |
| `reserved_cert_connections` | `max_connections / 4` (16) | 0 to `max_connections - 1`. Slots that only connections with a validated client certificate may hold after the handshake |
| `handshake_timeout_s` | 5 | 1 to 300 |
| `header_timeout_s` | 10 | 1 to 300 |
| `idle_timeout_s` | 120 | 1 to 3600; reset by any byte in either direction, never a total deadline (REQ-IMG-032) |
| `max_connection_age_s` | 300 | 1 to 86400; afterwards the connection closes once the request in progress completes |
| `max_json_bytes` | 65536 | 1024 to 1048576 |
| `max_headers` | 64 | 8 to 256 |
| `max_header_bytes` | 16384 | 8192 to 1048576 |

### `[tls]`

| Key | Default | Range / rule |
|-----|---------|--------------|
| `cert_chain` | required | Server certificate chain (PEM) |
| `private_key` | required | Server key (PKCS#8 PEM); service private-key rule |
| `min_version` | `"1.2"` | `"1.2"` or `"1.3"` |
| `client_trust_anchors` | required | Operator CA certificates (PEM) |
| `client_crls` | required | 1 to 64 CRL files (PEM or DER) |
| `crl_reload_s` | 300 | 1 to 86400 |
| `acceptable_policy_oids` | `[]` | Up to 64 dotted OIDs; if non-empty, the operator certificate must assert one of them exactly (`anyPolicy` is not a wildcard) |

### `[database]` and `[database.admin]`

| Key | Default | Range / rule |
|-----|---------|--------------|
| `host` | required | Host name or address |
| `port` | 5432 | 1 to 65535 |
| `dbname` | required | |
| `user` | required | The application role, `usgp_app` |
| `server_ca` | required | Database server CA (PEM) |
| `server_name` | `host` | Name the server certificate must carry; not empty |
| `client_cert` | required | Application role certificate (PEM) |
| `client_key` | required | Application role key; service private-key rule |
| `pool_size` | 8 | 1 to 256 |
| `connect_timeout_s` | 10 | 1 to 300 |
| `admin.user` | none; section optional | The administrative role, `usgp_admin`; must differ from `user` |
| `admin.client_cert` | required in the section | Must differ from `client_cert` |
| `admin.client_key` | required in the section | Must differ from `client_key`; administrative key rule (0600 or 0400) |

Without `[database.admin]`, `operator enrol`, `operator disable` and
`audit verify` exit 78 (`database.admin is required for this command`).
There is no password key in either section.

### `[content]`

| Key | Default | Range / rule |
|-----|---------|--------------|
| `root` | required | Content root; service-owned, 0700 |
| `max_upload_bytes` | 34359738368 (32 GiB) | 1 to 1099511627776 (1 TiB); stated by `GET /v1/limits` (REQ-IMG-031) |
| `max_open_uploads` | 4 | 1 to 1024 |
| `max_open_uploads_per_operator` | 2 | 1 to `max_open_uploads` |
| `upload_idle_timeout_s` | 300 | 1 to 3600; longest pause between body bytes |
| `upload_session_ttl_s` | 86400 | 60 to 604800; how long a session waits for its body |
| `check_concurrency` | 1 | 1 to 64 |
| `check_stall_timeout_s` | 600 | 1 to 86400; a check with no progress this long fails (REQ-IMG-021) |

### `[signing]`

| Key | Default | Range / rule |
|-----|---------|--------------|
| `content_key` | required | Content and package manifest signing key (PKCS#8 PEM) |
| `audit_key` | required | Audit checkpoint signing key; a different file and key from `content_key` |
| `previous_content_pubs` | `[]` | Up to 64 SPKI PEM files of earlier content keys |
| `plan_key` (M3) | none | Job plan signing key. With `boot_policy_key` and `codes.hmac_key`: all three or none, each its own file; required when `device_api.enabled = true` |
| `boot_policy_key` (M3) | none | Boot-policy list signing key; same rules as `plan_key` |

### `[device_api]` (M3)

The device listener ([Device listener](#device-listener)). The
listener is **off** unless `enabled = true`. Every value below is
project design (CM-6); OPEN-TGT-1 and OPEN-JOB-4 leave the spec values
open, so the defaults fail closed. "Source" means an IPv4 address or an
IPv6 /64.

| Key | Default | Range / rule |
|-----|---------|--------------|
| `enabled` | `false` | When true, `listen`, `cert_chain`, `private_key` and the three M3 keys are required |
| `listen` | `127.0.0.1:8444` | IP address and port; must differ from `api.listen`. Choose an address the boot segments can reach |
| `cert_chain` | none | Device listener certificate chain (PEM); required when enabled; the path is checked even when disabled |
| `private_key` | none | Device listener key; service private-key rule; required when enabled |
| `min_version` | `"1.2"` | `"1.2"` or `"1.3"` |
| `max_connections` | 256 | 1 to 4096 |
| `max_connections_per_source` | 16 | 1 to `max_connections` |
| `max_handshakes_per_source` | 8 | 1 to `max_connections_per_source` |
| `max_connections_per_boot_service` | 64 | 1 to `max_connections`; connections from the sources one boot service serves |
| `boot_service_refresh_s` | 30 | 1 to 600; how often the listener reloads its table of served subnets |
| `handshake_timeout_s` | 10 | 1 to 300 |
| `header_timeout_s` | 10 | 1 to 300 |
| `idle_timeout_s` | 120 | 1 to 3600 |
| `max_json_bytes` | 65536 | 1024 to 65536 |
| `max_headers` | 64 | 8 to 256 |
| `max_header_bytes` | 16384 | 8192 to 1048576 |
| `pending_session_ttl_s` | 3600 | 60 to 86400; lifetime of a session before its wipe confirmation |
| `max_pending_sessions` | 64 | 1 to 100000, in total |
| `max_pending_sessions_per_ip` | 4 | 1 to `max_pending_sessions`, per source |
| `max_pending_sessions_per_boot_service` | 32 | 1 to `max_pending_sessions` |
| `unauthorised_idle_timeout_s` | 120 | 30 to `pending_session_ttl_s`, and at least 5 poll intervals; a session never authorised and not heard from this long expires early |
| `session_opens_per_ip_per_min` | 10 | 1 to 1000 |
| `session_opens_per_boot_service_per_min` | 60 | 1 to 100000 |
| `session_opens_per_min` | 600 | 1 to 100000, all sources together |
| `code_attempts_per_session` | 5 | 1 to 20; failed code attempts before the session is refused |
| `code_attempts_per_ip_per_min` | 10 | 1 to 1000 |
| `poll_ms` | 2000 | 500 to 60000; poll interval suggested to the agent |
| `progress_min_interval_ms` | 2000 | 100 to 60000; `progress` reports recorded at most this often per job |
| `max_chunk_requests_per_job` | 2 | 1 to 16 concurrent chunk requests |

### `[codes]` (M3)

| Key | Default | Range / rule |
|-----|---------|--------------|
| `hmac_key` | none | The code HMAC key (32 raw bytes); see [Keys](#keys-for-the-device-listener-m3) |
| `default_ttl_s` | 900 | 60 to `max_ttl_s`; a code's lifetime when the operator names none |
| `max_ttl_s` | 3600 | 60 to 86400 |

The code length is fixed: 10 symbols of Crockford's base32 (50 bits from
the DRBG), shown as `XXXXX-XXXXX`.

### `[jobs]` (M3)

Written into every signed plan. OPEN-JOB-4 leaves the values open; these
are project design.

| Key | Default | Range / rule |
|-----|---------|--------------|
| `lost_after_s` | 900 | 60 to 86400; a running job not heard from this long becomes `lost` |
| `retry_attempts` | 5 | 1 to 100; device retries of a transient failure |
| `retry_base_ms`, `retry_max_ms` | 2000, 60000 | 1 <= base <= max <= 3600000 |
| `stall_timeout_s` | 1800 | 1 to 604800; no progress this long fails the job |
| `timeout_verify_s`, `timeout_disk_s`, `timeout_apply_s`, `timeout_boot_s`, `timeout_report_s` | 21600, 1800, 21600, 1800, 600 | 1 to 604800 each; steps 1 to 5 |
| `report_interval_s` | 30 | 1 to 3600 |

Fixed, not configurable (REQ-DISK-004, REQ-DISK-006): the minimum disk
size (64 x 10^9 bytes, or more for a large image), the separate wipe
confirmation, and the refusal of removable, USB and boot-media disks.
There is no setting that skips TLS or signature checks.

### `[audit]`

| Key | Default | Range / rule |
|-----|---------|--------------|
| `checkpoint_every_records` | 100 | 1 to 1000000 |
| `checkpoint_every_s` | 60 | 1 to 86400; checkpoint when new records exist |
| `checkpoint_heartbeat_s` | 900 | 60 to 86400; checkpoint even with no new record |
| `unauth_records_per_source_per_min` | 10 | 1 to 10000; anonymous refusals (no certificate, TLS protocol failure, handshake timeout, certificate that does not chain to an anchor) |
| `unauth_records_global_per_min` | 300 | 1 to 100000 |
| `credential_failure_records_per_source_per_min` | 60 | 1 to 10000; refusals of certificates that chain to a configured anchor, unknown certificates and disabled operators |
| `credential_failure_records_global_per_min` | 600 | 1 to 100000 |

Refusals over a cap are still refused; they are counted and summarised
every 60 s (and before `server.stop`) as `auth.unauthenticated.summary`.
The caps cannot be set to 0.

### `[pe]`

| Key | Default | Range / rule |
|-----|---------|--------------|
| `known_bad_kit_versions` | `[]` | Up to 256 kit versions (2 to 4 dot-separated decimal parts, each at most 65535). A PE with a listed version is shown with a warning and the warning is audited (REQ-PE-009). No source names a known-bad kit, so the default is empty |

### `[wim]`

Each value may only **lower** the built-in limit (1 to the default).

| Key | Default |
|-----|---------|
| `max_xml_bytes` | 16777216 (16 MiB) |
| `max_images` | 1024 |
| `max_lookup_bytes` | 67108864 (64 MiB) |
| `max_metadata_bytes` | 1073741824 (1 GiB) per image |
| `max_metadata_total_bytes` | 4294967296 (4 GiB) in total |
| `max_name_chars` | 1024 |
| `max_xml_depth` | 32 |
| `max_xml_elements_per_image` | 1024 |
| `max_integrity_bytes` | 16777216 (16 MiB) |

The total metadata of a file is also limited to 32 times the file size
(fixed, not configurable).

### `[log]`

| Key | Default | Range / rule |
|-----|---------|--------------|
| `level` | `info` | `error`, `warn`, `info` or `debug`. The audit mirror is never filtered by level |

## Example configuration

**Example, not shipped, not tested as a file.** Every key is written out
with its default or a safe example value. The key set was checked against
`services/usgp-server/src/config.rs` (every section refuses unknown keys)
and against the test fixtures
`services/usgp-server/tests/fixtures/server-v1.toml` and (M3 sections)
`server-m3.toml`. Paths are examples. The M3 device listener is shown
switched off; to switch it on, set `enabled = true` and give it an
address the boot segments can reach.

```toml
# usgp-server example configuration: every key, defaults unless noted.
# Example only: not shipped, not tested as a file.
schema_version = 1
# AU-3 "where" label; the host name if omitted.
node_name = "ctl-01"

[api]
# CM-7: loopback by default. Expose deliberately and filter in the network.
listen = "127.0.0.1:8443"
# SC-5: connection and handshake caps (source = IPv4 address or IPv6 /64).
max_connections = 64
max_connections_per_source = 16
max_handshakes_per_source = 8
reserved_cert_connections = 16
handshake_timeout_s = 5
# SC-10 / SC-5: progress-based timeouts, never a total deadline.
header_timeout_s = 10
idle_timeout_s = 120
# AC-12 / SC-23: every operator reconnects and is re-checked against CRLs.
max_connection_age_s = 300
# SI-10: request size bounds.
max_json_bytes = 65536
max_headers = 64
max_header_bytes = 16384

[tls]
# SC-8 / SC-13: TLS 1.2 or 1.3 on the FIPS provider.
cert_chain = "/etc/usgp-server/tls/server.pem"
private_key = "/etc/usgp-server/tls/server.key"
min_version = "1.2"
# IA-2 / IA-5(2): operator certificates validated against these anchors.
client_trust_anchors = "/etc/usgp-server/tls/operator-cas.pem"
# IA-5(2): at least one CRL; a stale CRL refuses every certificate of its CA.
client_crls = ["/etc/usgp-server/tls/crl/agency.crl"]
crl_reload_s = 300
# IA-5(2): exact policy match when non-empty.
acceptable_policy_oids = []

[database]
# SC-8 / IA-5(2): TLS with a client certificate; no password key exists.
host = "db.internal"
port = 5432
dbname = "usgp"
user = "usgp_app"
server_ca = "/etc/usgp-server/db/ca.pem"
server_name = "db.internal"
client_cert = "/etc/usgp-server/db/app.pem"
client_key = "/etc/usgp-server/db/app.key"
pool_size = 8
connect_timeout_s = 10

[database.admin]
# AC-6(1), decision 0016: local administrative commands only.
# The key must be root-owned 0600; serve refuses to start if it can read it.
user = "usgp_admin"
client_cert = "/etc/usgp-server/db/admin.pem"
client_key = "/etc/usgp-server/db/admin.key"

[content]
# SC-28 (access control only) / SI-7: service-owned 0700 root.
root = "/var/lib/usgp-server/content"
# REQ-IMG-031: stated by GET /v1/limits.
max_upload_bytes = 34359738368
# SC-5: upload and check caps.
max_open_uploads = 4
max_open_uploads_per_operator = 2
upload_idle_timeout_s = 300
upload_session_ttl_s = 86400
check_concurrency = 1
# REQ-IMG-021: a stalled check fails.
check_stall_timeout_s = 600

[signing]
# SC-12 / SI-7(6): one key per purpose.
content_key = "/etc/usgp-server/keys/content.p8"
audit_key = "/etc/usgp-server/keys/audit.p8"
previous_content_pubs = []
# M3, SC-12: job plans and boot-policy lists; one key per purpose.
plan_key = "/etc/usgp-server/keys/plan.p8"
boot_policy_key = "/etc/usgp-server/keys/boot-policy.p8"

[audit]
# AU-9(3): signed checkpoints by count, by time and by heartbeat.
checkpoint_every_records = 100
checkpoint_every_s = 60
checkpoint_heartbeat_s = 900
# AU-4 / AU-12 / SC-5: per-source and global caps on refusal records.
unauth_records_per_source_per_min = 10
unauth_records_global_per_min = 300
credential_failure_records_per_source_per_min = 60
credential_failure_records_global_per_min = 600

[pe]
# REQ-PE-009: no known-bad kit is named by any source.
known_bad_kit_versions = []

[wim]
# SI-10 / SC-5: parser limits; values may only be lowered.
max_xml_bytes = 16777216
max_images = 1024
max_lookup_bytes = 67108864
max_metadata_bytes = 1073741824
max_metadata_total_bytes = 4294967296
max_name_chars = 1024
max_xml_depth = 32
max_xml_elements_per_image = 1024
max_integrity_bytes = 16777216

[log]
level = "info"

[device_api]
# CM-7: off unless configured; a separate listener from [api].
enabled = false
listen = "127.0.0.1:8444"
cert_chain = "/etc/usgp-server/tls/device.pem"
private_key = "/etc/usgp-server/tls/device.key"
min_version = "1.2"
# SC-5: connection caps; a source outside every served subnet is closed.
max_connections = 256
max_connections_per_source = 16
max_handshakes_per_source = 8
max_connections_per_boot_service = 64
boot_service_refresh_s = 30
handshake_timeout_s = 10
header_timeout_s = 10
idle_timeout_s = 120
max_json_bytes = 65536
max_headers = 64
max_header_bytes = 16384
# AC-12 / SC-5: pending sessions expire and are capped.
pending_session_ttl_s = 3600
max_pending_sessions = 64
max_pending_sessions_per_ip = 4
max_pending_sessions_per_boot_service = 32
unauthorised_idle_timeout_s = 120
session_opens_per_ip_per_min = 10
session_opens_per_boot_service_per_min = 60
session_opens_per_min = 600
# AC-7: code attempts.
code_attempts_per_session = 5
code_attempts_per_ip_per_min = 10
poll_ms = 2000
progress_min_interval_ms = 2000
max_chunk_requests_per_job = 2

[codes]
# IA-5: codes are stored only as HMAC-SHA-256 values under this key.
hmac_key = "/etc/usgp-server/keys/code-hmac.key"
default_ttl_s = 900
max_ttl_s = 3600

[jobs]
# REQ-JOB-007, REQ-JOB-011: written into every signed plan.
lost_after_s = 900
retry_attempts = 5
retry_base_ms = 2000
retry_max_ms = 60000
stall_timeout_s = 1800
timeout_verify_s = 21600
timeout_disk_s = 1800
timeout_apply_s = 21600
timeout_boot_s = 1800
timeout_report_s = 600
report_interval_s = 30
```

## Example service unit

**Example, not shipped, not tested.** The server needs no capability:
its default port (8443) is above 1024. Add `CAP_NET_BIND_SERVICE` only if
`api.listen` names a port below 1024.

```ini
[Unit]
Description=usg-provision control plane
Wants=network-online.target time-sync.target
After=network-online.target time-sync.target postgresql.service
# Stop retrying after 5 failed starts in 10 minutes, so a failing
# ExecStartPre cannot restart-loop.
StartLimitIntervalSec=600
StartLimitBurst=5

[Service]
Type=simple
User=usgp-server
Group=usgp-server
ExecStartPre=/usr/bin/usgp-server --check-config /etc/usgp-server/server.toml
ExecStart=/usr/bin/usgp-server serve --config /etc/usgp-server/server.toml
# No capabilities (port 8443). For a port below 1024 use instead:
#   AmbientCapabilities=CAP_NET_BIND_SERVICE
#   CapabilityBoundingSet=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=
AmbientCapabilities=
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadOnlyPaths=/etc/usgp-server
ReadWritePaths=/var/lib/usgp-server/content
UMask=0077
Restart=on-failure
RestartSec=10
RestartPreventExitStatus=2 78
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Notes:

- With root-owned files no `--admin-uid` is needed. If an administrator
  account owns them, add `--admin-uid <uid>` to both commands; that uid
  must not be `User=`.
- `serve` refuses to start if it can open the `[database.admin]` key, so
  the unit must not run as root and the admin key must be root-owned
  0600.
- `RestartPreventExitStatus=2 78` applies to `ExecStart` only. A failed
  `ExecStartPre` is retried under `Restart=on-failure` until the
  `StartLimit` settings stop it, as for the relay
  ([relay.md](relay.md#running-without-root)).
- Exit 1 can mean the database is unreachable or at the wrong schema
  version; the unit retries.
- On SIGTERM or SIGINT the server stops accepting, records `server.stop`,
  signs a final checkpoint and gives blocking work 10 s. Connections in
  progress are not drained; an interrupted upload or check is marked
  Failed (`interrupted_by_restart`) at the next start.

## Operators

- One certificate maps to one operator by the SHA-256 of the end-entity
  certificate (decision 0007). Renewal means enrolling the new
  certificate.
- `operator enrol` refuses a certificate with no extendedKeyUsage
  extension or without `id-kp-clientAuth` (`operator.enrol.refused`,
  reason `certificate_eku`), and a certificate already enrolled
  (`certificate_already_enrolled`). It does not check the certificate's
  validity or chain; the handshake does that on every connection.
- Roles: `administrator` holds every permission (REQ-RBAC-004); `none`
  gets 403 on every route (REQ-RBAC-003). There are no other roles in M2.
- `operator disable` takes effect on the operator's next request (401,
  `auth.operator_disabled`). An open connection keeps its current request.
  Operators are disabled, never deleted.
- Enrolment creates the audit chain's genesis record if `serve` has not
  run yet, so operators can be enrolled before the first start.
- There is no list or review command for operators in M2 (AC-2 gap).
- M3 adds the permissions `auth_code.issue`, `auth_code.view`,
  `auth_code.revoke`, `device_session.view`, `device_session.approve`,
  `job.view`, `job.acknowledge`, `job.fail`, `boot_service.view`,
  `boot_service.assign`, `boot_stop.view` and `device.boot_reenable`.
  `administrator` holds all of them; there is still no other role, so
  one role holds every M3 permission (AC-5 is not claimed).

## Device listener

The device listener serves the pre-boot agent
([winpe-kit.md](winpe-kit.md)). It is a separate listener from the
operator API (`[api]`), with its own address, certificate and limits.

- **Off by default.** It runs only with `device_api.enabled = true`, and
  then needs its certificate and key and the three M3 keys
  ([Keys](#keys-for-the-device-listener-m3)).
- **TLS, server-authenticated only.** TLS 1.2 or 1.3 on the FIPS
  provider. No client certificate is requested: a pre-boot device holds
  no secret (decision 0020). The agent checks the server certificate
  against the trust anchors in its `agent.toml`. Use a certificate whose
  name matches `server_name` in the agent configuration.
- **Admission by served subnet.** At accept time the listener closes a
  connection whose source address is not inside a subnet of an active
  boot service, and audits `device.connection.refused` (capped per
  source). It keeps a cached table of active boot services and their
  subnets, loaded when the listener starts (nothing is admitted until
  the first load succeeds), reloaded every
  `device_api.boot_service_refresh_s` (30 s), and reloaded on a refused
  source at most once a second.
- **After enrolling or re-enabling a boot service on a running server,**
  its devices can be refused for up to `boot_service_refresh_s` (30 s by
  default), or until a refused connection more than 1 s after the last
  load triggers a reload. Wait for the refresh before booting devices on
  a newly enrolled subnet. After a `boot-service disable`, the table
  drops the service at its next load.
- **Connection caps.** In total (`max_connections`), per source, per
  boot service (`max_connections_per_boot_service`), and handshakes per
  source.
- **Session opens** are refused (403 `forbidden`, a capped
  `device.session.open_refused` with reason `no_boot_service`) when no
  active boot service serves the source, or more than one does. That
  check runs before any rate limit counts the request. Then come the
  per-source, per-boot-service and global open ceilings and the pending
  session caps (429 `rate_limited`).
- **Bearer token.** An opened session gets a 32-byte token from the
  DRBG; the server keeps only its SHA-256. Every later request carries
  it as `Authorization: Bearer`. The token is **bound to the source
  network** it was issued to: the same IPv4 address or IPv6 /64
  (decision 0023 item 1). A request from another source network gets
  401 `invalid_token` and a capped `auth.unauthenticated` record with
  reason `token_source_mismatch`. A device whose IPv4 address changes
  after the wipe therefore loses its session, and its job becomes `lost`
  (POAM-39).
- **Expiry.** A pending session expires after `pending_session_ttl_s`,
  or sooner (`unauthorised_idle_timeout_s`) if it was never authorised
  and stops polling. A confirmed session's token stops working at the
  job's last contact plus twice `jobs.lost_after_s` while the job is
  unfinished, and at finish plus `jobs.lost_after_s` once it has
  finished (decision 0023 item 1, as clarified 2026-10-29; 403
  `session_ended`).
- **Fail closed on audit.** Every state-changing device route writes its
  record in the same transaction as the change. If the record cannot be
  written, the route answers 503 `audit_unavailable` and nothing
  changes. In particular, the wipe confirmation creates no job and no
  plan unless `disk.wipe.authorised` commits (REQ-DISK-006).
- **Errors** use the M2 shape `{"error":{"code","message"}}`. A
  malformed body gets a fixed 400 message with the line and column, never
  the parser's text. Wrong, expired, used and revoked codes get the same
  answer.

Device routes, for reference (the agent is the only intended client):

| Method, path | Purpose | Audit (success / refusal) |
|--------------|---------|---------------------------|
| POST `/v1/device/sessions` | Open a session (no token yet) | `device.session.opened` / `device.session.open_refused` |
| GET `/v1/device/session` | Poll the session state | none / `device.session.status_refused` |
| POST `/v1/device/session/code` | Enter an operator code | `auth_code.used`, `device.session.authorised` / `device.session.code_refused` |
| GET `/v1/device/session/packages` | Packages offered to this device | `device.session.packages.read` (and `boot_service.no_usable_package` when empty) / `device.session.packages_refused` |
| POST `/v1/device/session/package` | Choose a package | `device.session.package_chosen` / `device.session.package_refused` |
| POST `/v1/device/session/disk` | Choose a disk (a descriptor, never disk content) | `device.session.disk_chosen` / `device.session.disk_refused` |
| POST `/v1/device/session/confirm` | The separate wipe confirmation: creates the job and returns the signed plan | `job.created`, `disk.wipe.authorised`, `job.plan.issued` / `device.session.confirm_refused` |
| POST `/v1/device/session/cancel` | Cancel before the confirmation only | `device.session.cancelled` / `device.session.cancel_refused` |
| POST `/v1/device/session/end` | End the session (nothing to offer, no disk, firmware, agent error) | `device.session.ended` / `device.session.end_refused` |
| GET `/v1/device/jobs/{job}/content/{sha256}/chunks/{n}` | One verified content chunk | `job.content.read` (once per job, content and pass) / `job.content.refused` |
| POST `/v1/device/jobs/{job}/progress` | Progress and step changes | `job.step.*`, `job.failed`, `job.succeeded`, `boot_stop.added` / `job.progress.refused` |

## Device codes and approval

A device session gets no package list, no plan and no content until it
is authorised (decision 0018 item 1, decision 0020). There are two ways.

**A code entered at the device.**

```sh
usgp-cli code issue [--ttl SECONDS] [--note TEXT]
usgp-cli code list
usgp-cli code revoke ID
```

- `code issue` prints the code **once**, on stdout only (`Cache-Control:
  no-store`). The server stores only its HMAC-SHA-256 under
  `codes.hmac_key`; the value is never logged, never audited and never
  shown again. `code list` shows ids, states and times, never values.
- A code is single-use and expires after `--ttl` (default
  `codes.default_ttl_s`, at most `codes.max_ttl_s`). Revoke an unused code
  you no longer need.
- The technician types the code at the device with echo off. After
  `device_api.code_attempts_per_session` (5) failures the session is
  refused; each source gets `code_attempts_per_ip_per_min` (10) attempts
  a minute.
- Records: `auth_code.issued`, `auth_code.revoked`, `auth_code.used`,
  `device.session.authorised` (method `code`), and
  `device.session.code_refused` for a failure (never the value).

**Approval in the console.**

```sh
usgp-cli session list [--state awaiting_authorisation]
usgp-cli session show ID
usgp-cli session approve --display-code CODE [ID]
usgp-cli session refuse ID [--note TEXT]
```

- The device shows a **display code** (`XXX-XXX`). It is not a secret;
  it binds the approval to the screen in front of the technician. Read
  it from the device, and check the session's MACs, source address,
  firmware, architecture, Secure Boot state and memory with `session
  show` before approving. These device facts are **claimed** by the
  device, not verified (POAM-38).
- `approve` refuses a display code that does not match
  (`device.session.approve_refused`). `refuse` ends the session; the
  device then shows a persistent "refused" screen.
- **Neither way authenticates the device itself** (POAM-38). Approve
  only a device you can see. Under decision 0020 a copied PE gains
  nothing without a fresh authorisation, and M3 delivers no secret to
  any session. **M4 must not deliver a secret to a session authorised
  only by a code or an approval** (security review, M3).

## Boot services (relay enrolment)

M3 brings forward a minimal, manual part of M5's relay enrolment
(decision 0021). A **boot service** is one relay's client certificate,
bound by its SHA-256 to a record with a name and the subnets it serves.
It decides which packages a device on those subnets is offered
(REQ-TGT-001), and which boot-policy list the relay pulls
(REQ-BOOT-067).

```sh
usgp-server boot-service enrol --config /etc/usgp-server/server.toml \
  --cert /root/relay-a.pem --name relay-site-a --subnet 10.20.1.0/24
usgp-server boot-service disable --config /etc/usgp-server/server.toml \
  --id UUID
usgp-cli boot-service list
usgp-cli boot-service show ID
usgp-cli boot-service set-packages ID PACKAGE_ID... --if-match TAG
```

- `enrol` is a local administrative command (`usgp_admin` key). It
  refuses a certificate without the TLS client purpose, a certificate
  already bound to an operator or to another boot service, and a name in
  use (`boot_service.enrol.refused`). It prints the boot service id; put
  that id in the relay's `server_feed.boot_service_id`.
- The relay's certificate must chain to `tls.client_trust_anchors` and
  pass the same CRL checks as an operator's, because the relay pulls its
  list from the operator listener (`GET /v1/relay/boot-policy`, a route
  only a boot service may use). A certificate bound to both an operator
  and a boot service is refused (`auth.ambiguous_certificate`).
- **Disable** makes the relay's certificate get 401
  (`auth.boot_service_disabled`), and its devices are offered nothing.
- **No rotation.** A renewed relay certificate means disabling the boot
  service and enrolling a new one (new id, packages assigned again).
  `cert_not_after` is recorded but not enforced ahead of time (POAM-44).
- `set-packages` replaces the package list; pass the assignment tag that
  `show` prints with `--if-match`. A boot service with no usable package
  is shown with a warning, and its devices see "nothing to offer"
  (REQ-TGT-008).
- **Overlapping subnets.** A device whose source address two active boot
  services serve cannot open a session (403). Do not enrol overlapping
  subnets.
- After enrolling, allow for the listener's admission refresh
  ([Device listener](#device-listener)).

**Boot-policy generation.** Each boot service has a generation number
that rises by one each time its stop list changes. A relay refuses a
list whose generation is below the one it holds. After a database
restore, raise it:

```sh
usgp-server boot-service raise-generation --config \
  /etc/usgp-server/server.toml --id UUID --to N
```

`N` must be above the current value and above the generation every
relay of that boot service holds (each relay reports it in
`relay.start` and `boot_policy.applied`). Records:
`boot_policy.generation.raised` or `.raise.refused`. The generation
never goes down (migration 0004 guard). See
[Backup and restore](#backup-and-restore).

## Jobs

A job is created by the wipe confirmation at the device, in the same
transaction as `job.created` and `disk.wipe.authorised`. The
`disk.wipe.authorised` record names how the session was authorised
(`auth_method`, and `auth_code_id` or `approved_by_operator`) and the
MACs the device claimed. The plan is signed after the commit. The person
who confirms at the device is not individually identified (AU-10 basis
only).

```sh
usgp-cli job list [--state S]
usgp-cli job show ID
usgp-cli job ack ID
```

- **States**: `running`, `lost`, `failed`, `succeeded`. Steps: 1
  download and verify all content, 2 partition and format, 3 apply the
  image, 4 make the disk bootable, 5 report success and restart. Every
  step change and every state change is one audit record. `failed` and
  `succeeded` are final. There is no cancelled state: a job cannot be
  cancelled after the wipe confirmation (REQ-TGT-011).
- `job show` gives the job's steps, bytes and percentage, disk, the
  partition layout the device reported, and any persistent error (step,
  category, code, the files that failed, attempts), the same fields the
  device shows. It also links a new job to an earlier failed or lost job
  of the same MACs (`previous_job_id`).
- **Lost.** A running job not heard from for `jobs.lost_after_s` becomes
  `lost` (`job.lost`). The device's next report moves it back to
  `running` (`job.resumed`).
- **Server-enforced time limits.** The plan's step and stall timeouts are
  stored with the job. A running job whose current step runs past its
  timeout, or that sends no accepted report within the stall timeout, is
  failed by the server: category `timeout`, reason `step_timeout` or
  `stall_timeout`, `job.failed` with `failed_by=server`. A late report
  from such a job gets 409 `job_not_running` and the job is failed in
  the same transaction.
- **Acknowledge.** `job ack` (permission `job.acknowledge`) clears the
  attention flag of a failed job; the job stays `failed`
  (`job.failure.acknowledged`).
- **Fail a job (operator).** The API route `POST /v1/jobs/{id}/fail`
  with the body `{"reason": "..."}` (1 to 200 printable characters;
  permission `job.fail`) fails a `running` or `lost` job: category
  `refused`, code `operator_failed`, and `job.failed` with
  `failed_by=operator` and the reason as a note. A finished job gets 409
  and `job.fail_refused`. `usgp-cli` has no command for it in M3. Use it
  for a job that holds a device's MACs (a confirmation for those MACs is
  refused with 409 `in_use` while another session's job is running)
  and whose device will not report again.
- **After the wipe**, the device carries on even when the server answers
  503; a step whose report was refused is recorded only when a later
  report succeeds (POAM-41). The final `job.succeeded` or `job.failed`
  record carries the server's step history.

## Boot stops

When a job succeeds, the server adds a **boot stop** for each MAC the
device claimed, on every active boot service whose subnets contain the
device's source address, and raises each one's generation in the same
transaction (`boot_stop.added`, marked `claimed=<mac>`,
`mac_basis=agent_claim`; decision 0023 item 2). The relays then stop
offering a boot program to those MACs (REQ-BOOT-067).

```sh
usgp-cli boot-stop list
usgp-cli boot-stop clear ID
```

- `clear` (permission `device.boot_reenable`) is the only way to make a
  stopped device network-bootable again in M3 (decision 0021 item 3;
  REQ-BOOT-062 is OPEN). It raises the generation (`boot_stop.cleared`).
- The MACs are the device's own claim, shown to the technician on the
  wipe screen. A MAC that already has a live stop, or a running job in
  another session, is refused at the confirmation. Stops by the MAC the
  relay observed, or by the SMBIOS UUID, are not built (POAM-42, M5).

## TLS, CRL refresh and revocation

- TLS 1.2 and 1.3 only, FIPS provider, AES-GCM suites, groups secp384r1
  and secp256r1, no session tickets or resumption, no 0-RTT, ALPN
  `http/1.1` only. Every connection re-validates the client certificate.
- A connection without a certificate reaches HTTP and gets 401 with
  `WWW-Authenticate: usgp-client-cert realm="usg-provision"` and
  `Connection: close`, and an audit record. A presented certificate that
  fails validation fails the handshake; that is audited as
  `auth.tls.failed` with a class (`untrusted`, `expired`,
  `not_yet_valid`, `revoked`, `revocation_unknown`, `crl_stale`,
  `bad_eku`, `unknown_critical_ext`, `policy`, `bad_certificate`,
  `protocol`, or `handshake_timeout` from the acceptor) and the
  presented certificate's facts as a claim.
- **CRL refresh is an operator duty.** Revocation uses the CRL files in
  `tls.client_crls` only: no OCSP, no CRL distribution-point fetching
  (POAM-20). Replace each CRL file before its `nextUpdate`. A CRL past
  `nextUpdate`, or an issuer with no CRL, makes every certificate of that
  CA fail (`crl_stale`, `revocation_unknown`): fail closed.
- The server re-reads the CRL files every `tls.crl_reload_s`. When the
  set changed, it rebuilds the TLS acceptor, records
  `auth.tls.crl_reloaded`, and closes every older connection after its
  request in progress. Revocation therefore takes effect within
  `crl_reload_s` for new connections; a long transfer in progress (for
  example a large download) still completes. `api.max_connection_age_s`
  bounds how long any connection lives.
- If a reload fails (unreadable or invalid file), the previous acceptor
  stays and `auth.tls.crl_reloaded` is recorded with outcome failure,
  reason `crl_reload_failed`.
- **Rollback refusal.** Publish CRLs with an increasing `cRLNumber`. A
  reload in which any issuer's CRL has a lower number than the highest
  loaded, or no number where one was loaded, is refused: the previous
  CRL set stays in force and `auth.tls.crl_reloaded` is recorded with
  outcome failure, reason `crl_number_rollback`, and the issuer and both
  numbers. Equal numbers are accepted. The comparison is made before the
  CRL signature is checked, and the high-water mark is held in memory
  only: it is forgotten when an issuer's CRL is removed and at restart
  (POAM-29). If CRL files are fetched automatically, the fetcher must
  never install an older CRL.
- The server's own database client and the operator CLI do not check
  the revocation of the certificates *they* are shown (POAM-21).

## Audit

### The chain

Every operator action, every protected read and every authentication or
authorization refusal is an audit record (decision 0010). Records carry
who (`actor_kind`, `actor_id`, `actor_label` with the operator's name and
certificate SHA-256), what (`event`, target), when (`ts_us`, UTC
microseconds), where (`interface` `api`, `server-cli` or `system`, and
`node`), source (peer `ip:port`, or `uid:<n>` for local commands),
outcome, reason, and `initiating_seq` for later state changes.

- Each record's hash covers the previous record's hash, so the records
  form a SHA-256 chain in PostgreSQL. The application and admin roles
  cannot UPDATE or DELETE audit rows, and triggers refuse it. CI run
  40633650457 tests the application role and the triggers (`audit_pg`)
  and the admin role's UPDATE (`repo_pg`); a DELETE by the admin role
  is not tested.
- A mutation and its audit record commit in one transaction. If the
  record cannot be written, the action is refused with 500
  `audit_unavailable` and nothing changes (decision 0015 item 1). The
  same applies to protected reads and to `server.start`.
- **Checkpoints**: the server signs `(seq, record_hash, signed_at)` with
  the audit key every `checkpoint_every_records` records, every
  `checkpoint_every_s` seconds when new records exist, every
  `checkpoint_heartbeat_s` seconds even when idle (96 a day at the
  default), and at clean shutdown. Each checkpoint is itself a record
  (`audit.checkpoint`). A checkpoint that cannot be signed or stored
  emits an unpersisted `audit.checkpoint.failed` line (reason
  `begin_failed`, `sign_or_write_failed` or `commit_failed`), at most
  once per 60 s with a count of suppressed failures.
- There is no audit-reading API (decision 0015 item 3); records are read
  only by the local `audit verify` command.

### The stdout mirror and SIEM forwarding

Every record is also written as one JSON line on stdout (the M1 shape,
with `seq`, `ts_us`, `record_hash`, `prev_hash` and `persisted` in
`detail`). Records that could not be stored are mirrored with
`persisted=false`. Diagnostics go to stderr.

- **Forward stdout off the host** (journald to the site's SIEM or log
  store). The forwarded `audit.checkpoint` lines are the only external
  anchor of the chain (AU-9(2)); without them, deleting or rewriting
  records after the newest checkpoint cannot be detected (POAM-25).
- Write errors on stdout are dropped without an alert (POAM-5). Alert on
  forwarder errors, dropped messages, and a server that writes no
  `audit.checkpoint` line for longer than `checkpoint_heartbeat_s`.
- **Alert on**: `audit.checkpoint.failed`, `server.start.refused`,
  `key.generated`, `key.generation.failed`, `auth.tls.crl_reloaded` with
  outcome failure, `auth.tls.failed` with reason `revoked`,
  `auth.operator_disabled`, sustained `auth.unauthenticated.summary`
  counts, `content.integrity.failed`, `content.orphan.found`,
  `operator.enrolled`, `operator.disabled` and `audit.verify` with
  outcome failure. From M3 also: `maintenance.sweep.failed`,
  `boot_service.enrolled`, `boot_service.disabled`,
  `boot_policy.generation.raised`, `boot_stop.cleared`, `job.failed`,
  `device.session.approved`, `auth_code.issued`, sustained
  `device.session.code_refused` or `device.connection.refused` counts,
  and `auth.unauthenticated` with reason `token_source_mismatch`.
- No product tool verifies the chain from the forwarded lines; the
  comparison below is manual.

### Event catalogue (server)

| Event | When |
|-------|------|
| `audit.chain.genesis`, `audit.checkpoint`, `audit.checkpoint.failed` | Chain start; each checkpoint; checkpoint failure (unpersisted) |
| `server.start`, `server.stop`, `server.start.refused`, `server.migrate` | Lifecycle (start records version, config SHA-256, listener, key ids, schema version, TLS minimum, CRL set SHA-256, service uid) |
| `key.generated`, `key.generation.failed` | `keygen` (unpersisted) |
| `auth.unauthenticated`, `auth.unknown_certificate`, `auth.operator_disabled`, `auth.tls.failed`, `auth.unauthenticated.summary` | Authentication refusals (`auth.tls.failed` detail `trust_anchor: chained\|not_chained` is a classification, never an authentication result) |
| `auth.tls.crl_reloaded` | CRL reload, success or failure (`crl_reload_failed`, `crl_number_rollback`) |
| `authz.denied` | 403 (route and permission) |
| `api.limits.read`, `api.request.refused`, `api.request.failed` | Limits read; unknown route or method; internal failure before routing |
| `content.upload.created`, `.refused`, `.started`, `.received`, `.failed`, `.cancelled` | Upload session and body |
| `content.check.started`, `content.ready`, `content.failed`, `content.manifest.signed` | Content state changes (`initiating_seq` = the upload record) |
| `image.read`, `image.list.read`, `pe.read`, `pe.list.read`, `content.manifest.read`, `content.download`, `content.download.completed`, `content.download.aborted` | Protected reads |
| `content.integrity.failed`, `content.orphan.found` | Verification failure on use; orphaned object found at start (never deleted automatically) |
| `edition.declared`, `edition.declaration.refused`, `pe.declared` | Declared facts (decision 0013) |
| `image.deleted`, `image.delete.refused`, `pe.deleted`, `pe.delete.refused` | Deletes |
| `package.created`, `.edited`, `.cloned`, `.deleted`, `.refused`, `package.status.changed`, `package.manifest.signed`, `package.read`, `package.list.read`, `package.manifest.read`, `os_support.refused` | Packages |
| `operator.enrolled`, `operator.enrol.refused`, `operator.disabled`, `operator.disable.refused`, `audit.verify` | Local administrative commands (actor: local uid, claimed) |
| `boot_service.enrolled`, `boot_service.enrol.refused`, `boot_service.disabled`, `boot_service.disable.refused`, `boot_policy.generation.raised`, `boot_policy.generation.raise.refused` | M3 local administrative commands (actor: local uid, claimed) |
| `auth_code.issued`, `auth_code.refused`, `auth_code.list.read`, `auth_code.revoked`, `auth_code.revoke_refused` | M3 operator code actions (never the code value) |
| `device_session.list.read`, `device.session.approved`, `device.session.approve_refused`, `device.session.refused`, `device.session.refuse_refused` | M3 operator session actions |
| `device.connection.refused`, `device.session.opened`, `device.session.open_refused`, `device.session.no_boot_service`, `auth_code.used`, `device.session.authorised`, `device.session.code_refused`, `device.session.packages.read`, `boot_service.no_usable_package`, `device.session.package_chosen`, `device.session.disk_chosen`, `device.session.cancelled`, `device.session.expired`, `device.session.ended`, and the `*_refused` event of each device route | M3 device sessions (actor kind `device_session`, label with the claimed MACs and source; interface `device_api`) |
| `disk.wipe.authorised`, `job.created`, `job.plan.issued` | M3 wipe confirmation (one transaction; plan signed after the commit) |
| `job.step.started`, `job.step.completed`, `job.failed`, `job.succeeded`, `job.lost`, `job.resumed`, `job.content.read`, `job.content.refused`, `job.progress.refused` | M3 job state changes and content access |
| `job.list.read`, `job.read`, `job.failure.acknowledged`, `job.acknowledge_refused`, `job.fail_refused` | M3 operator job actions (`job.failed` with `failed_by=operator` for the fail route) |
| `boot_service.read`, `boot_service.packages.set`, `boot_service.packages.refused`, `boot_stop.list.read`, `boot_stop.added`, `boot_stop.cleared`, `boot_stop.clear_refused` | M3 boot services and stops |
| `boot_policy.read`, `boot_policy.refused`, `boot_policy.generation.initialised`, `auth.boot_service_disabled`, `auth.ambiguous_certificate` | M3 relay pulls (actor kind `boot_service`) |
| `maintenance.sweep.failed` | M3 maintenance sweep (lost jobs, expiry, time limits) could not run; unpersisted, at most once per 300 s per sweep |

### Verifying the chain

```sh
usgp-server audit verify --config /etc/usgp-server/server.toml \
  --trusted-key /etc/usgp-server/keys/audit.pub \
  --max-checkpoint-age 30m
```

The verifier reads the chain as `usgp_admin` and checks: seq starts at 1
and is contiguous; each record links to the previous hash; each record
hash recomputes; each checkpoint signature verifies with a trusted key
and matches the record at its seq; no record lies beyond the stored head;
and the cadence policy below. It records `audit.verify` with the result.

- `--max-unsigned-records N`: the longest run of records allowed without
  a matched signed checkpoint (between checkpoints, before the first and
  after the last). The default is derived from the configuration:
  `checkpoint_every_records + 1 + slack`, where slack =
  `min(writers, 10000) x 2 + 16` and writers = `api.max_connections +
  content.check_concurrency + 2`. At the defaults: `100 + 1 + (67 x 2 +
  16) = 251`. The slack avoids false alarms from appends queued while a
  checkpoint is taken; the cost is that up to that many records after the
  newest checkpoint can be rewritten undetected by the chain (POAM-25).
  Lower `api.max_connections`, or pass a smaller `N`, for a tighter
  bound.
- `--max-checkpoint-age DUR` (`N` followed by `s`, `m`, `h` or `d`, 1 s to
  366 d; opt-in): the newest matched checkpoint must be no older than
  `DUR`, measured against the verifier's clock and against the last
  record. Use about twice `checkpoint_heartbeat_s` (30 minutes at the
  default) while the server runs; use a longer value, or omit it, across
  planned downtime, since a stopped server signs no heartbeat.
- Findings (exit 1): `seq_not_contiguous`, `genesis_invalid`,
  `prev_hash_mismatch`, `record_hash_mismatch`, `unencodable`,
  `checkpoint_untrusted_key`, `checkpoint_bad_signature`,
  `checkpoint_hash_mismatch`, `checkpoint_beyond_chain`,
  `checkpoint_record_missing`, `checkpoint_record_unmatched`,
  `head_mismatch`, `record_beyond_head`, `checkpoint_gap_too_long`,
  `unsigned_tail_too_long`, `no_checkpoint`, `checkpoint_stale`.
- `checkpoint_stale` means the newest trusted checkpoint is older than
  the limit (or none matched). Check whether the server was stopped or
  its checkpointer failed (`audit.checkpoint.failed`); otherwise treat it
  as possible truncation and compare with the forwarded mirror.
- `checkpoint_gap_too_long` or `unsigned_tail_too_long` can also follow
  a checkpointer failure or many local commands while the server was
  stopped (16 records of slack); investigate before overriding the limit.
- Notice `timestamp_backwards` (not a finding): a record's time is
  earlier than the previous one's, which points to a clock step (AU-8).
- After every verification, compare the reported last seq and head hash
  with the newest `audit.checkpoint` line in the SIEM. A database that
  ends before a checkpoint the SIEM holds has been truncated or
  restored.

The audit key's holder can forge checkpoints after the last externally
forwarded one (POAM-18).

## Time synchronisation

Audit timestamps are UTC microseconds from the host's system clock
(AU-8); the server does not check the clock. Run a time synchronisation
service against the site's authoritative sources and monitor it. A
backward clock step shows up as `timestamp_backwards` notices in `audit
verify`. `--max-checkpoint-age` also depends on the verifying host's
clock.

## Backup and restore

Back up, together and on the same schedule (CP-9; procedure only, not
tested):

1. **PostgreSQL**, by standard PostgreSQL practice (for example base
   backups with archived WAL), protected and stored off the host.
2. **The content root** (`objects/`; `staging/` need not be kept). Take
   it after the database backup; objects are immutable once Ready, and
   an object without a database row is reported as `content.orphan.found`
   and never deleted automatically.
3. **Keys and configuration**: `/etc/usgp-server/` including the signing
   keys, the TLS key and the three database client keys, stored
   encrypted and under the same access rules as the originals. Keep
   every old audit public key.
4. **Externally**: the forwarded audit mirror in the SIEM is part of the
   record and is retained under the site's audit policy.

**Restore** (CP-10). Restoring a PostgreSQL backup rolls the audit chain
back to the backup's head. Records written after the backup (and already
forwarded to the SIEM) are no longer in the database, and new records
will reuse their seq numbers, so the database and the SIEM then hold two
different records for the same seq. `audit verify` on the restored
database reports intact. The product has no restore event (POAM-36).
Until it does:

1. Before restoring, note from the SIEM the newest `audit.checkpoint`
   line (seq and record hash) and the last mirrored seq.
2. Stop the server; restore PostgreSQL, then the content root, then keys
   if needed. Do not start `serve` yet.
3. Run `audit verify` with every trusted audit key. Record its last seq
   and head hash.
4. Record the restore out of band (change record, signed by the
   administrator): restored head seq and hash, the last forwarded
   checkpoint and last mirrored seq from step 1, the range of seq numbers
   that will be reused, and the reason.
5. Start `serve`. Keep the pre-restore mirror lines; they are the only
   copy of the lost records.
6. Content restored without its database row (or the reverse) shows up
   as `content.orphan.found` or as an integrity failure on use; review
   both before returning the system to service.
7. **Boot-policy generation (M3).** The restored database holds an
   older boot-policy generation than the relays, so every relay refuses
   the server's lists as a rollback until the generation passes theirs
   (POAM-36). Before devices are booted again, for each boot service:
   read the generation each relay holds (from its last `relay.start` or
   `boot_policy.applied` record), run `usgp-server boot-service
   raise-generation --id UUID --to N` with `N` above all of them, and
   check that each relay then logs `boot_policy.applied`.
8. **Boot stops (M3).** Stops added after the backup are not in the
   restored database. A relay keeps its last list until the raised
   generation replaces it, so those devices become network-bootable
   again then. Compare `boot_stop.added` records in the SIEM after the
   backup's time with `usgp-cli boot-stop list`, and review the affected
   devices before returning the system to service.

## Schema migrations and upgrades

- Migrations are compiled into the binary, numbered from 1, ordered, and
  checksummed. `migrate` takes an advisory lock and applies each pending
  migration in its own transaction. It refuses if an applied migration is
  unknown to the binary (a newer database) or its checksum differs.
- `serve` and the administrative commands refuse unless the applied
  version is exactly the binary's (schema 3 in M2, schema 4 in M3) with
  matching checksums (exit 1 for `serve`). Migration 0004 adds the
  device session, code, job, boot-service and boot-stop tables, the
  guard triggers (including the deferred `job_wipe_authorised` trigger:
  a job cannot commit without its `disk.wipe.authorised` record), and
  the `usgp_app` and `usgp_admin` grants.
- **Migrations are forward-only.** There are no down migrations. The
  rollback path is **restore from backup**: back up PostgreSQL before
  every `migrate`, and if an upgrade must be undone, reinstall the old
  binary and restore the pre-migration backup, following the audit-chain
  restore procedure above.
- Upgrade order: back up; stop `serve`; install the new binary; run
  `migrate` with the owner key; run `--check-config`; start `serve`; run
  `audit verify`.
- The server never writes its configuration. A configuration with
  `schema_version = 1` stays valid.

## Supported content

This is project scope (decisions 0009, 0013, 0014), not a statement about
any other product (REQ-OS-006 is OPEN).

- **Images**: WIM files, uncompressed or XPRESS. A package can be Ready
  only for an edition declared `windows-11` / `enterprise` / `x64`.
  Windows 10, `enterprise-ltsc`, `iot-enterprise`, `education`, `pro`,
  `home`, `other`, and `x86`, `arm64`, `arm` are refused when chosen for
  a package (`os_scope`, `os_support.refused`).
- **PE kits**: x64 only, declared at upload with a kit version
  (`pe_architecture_not_supported:<arch>` otherwise). A PE file must hold
  one image, or name its usable image by boot index.
- **Declared versus verified.** The operator declares each edition's
  release, edition and architecture (`PUT
  /v1/images/{id}/editions/{index}/declaration`) and the PE's
  architecture and kit version. The product would refuse a declaration
  that contradicts a fact the WIM's documented XML states, but no
  documented XML element states these facts today, so every fact is
  recorded, shown and signed as `declared`, never `verified` (POAM-23).
  An undeclared edition is `unknown` and its package stays `not_usable`
  (`os_support_unknown`). Declarations are audited with the operator's
  identity, and cannot be changed while a package uses the edition
  (409 `in_use`).
- Package and content manifests are signed with the content key. The
  operator CLI verifies them against the pinned `--content-key-pub`.

## WIM acceptance rules and reason codes

An upload is checked after its body arrives, in a bounded background
worker. The first failure stops the check; the content becomes Failed
with the reason code and an operator message, and `content.failed` is
recorded. Rules marked *project rule* are our fail-closed choices (some
are in decision 0017); they are not Microsoft text.

| Code | Meaning | Remedy |
|------|---------|--------|
| `wim_not_wim` | No WIM signature | Upload a `.wim` file |
| `wim_truncated` | File ends inside the header | Re-copy the file; check the source |
| `wim_header_size` | Header size field is not 208 (*project rule*, decision 0017) | Re-export the image with DISM |
| `wim_out_of_bounds` | A structure lies outside the file | File is damaged; re-copy or re-create |
| `wim_malformed` | A field is invalid (for example the chunk size field of an XPRESS file is not 32768, *project rule*, decision 0017; impossible split-part fields; a non-zero boot header with boot index 0; a bad chunk table) | File is damaged or of an unsupported layout; re-export with DISM |
| `wim_limit_exceeded` | A `[wim]` limit, the 32x metadata expansion limit, or the total metadata limit was exceeded | Split content across files, or have the administrator review `[wim]` (values can only be lowered) |
| `wim_no_images` | File holds no images | Upload a file with at least one image |
| `wim_image_count_mismatch` | Header, XML and metadata counts disagree | File is damaged; re-create |
| `wim_xml_invalid` | Image information XML is invalid (encoding, DOCTYPE, depth, missing NAME, bad index) | Re-export with DISM |
| `wim_xml_too_large` | XML is above `max_xml_bytes` | As for `wim_limit_exceeded` |
| `wim_duplicate_index` | An index appears twice | Re-export with DISM |
| `wim_boot_index_invalid` | Boot index names no image, or the boot header does not locate that image's metadata (*project rule*, derived, unconfirmed) | Re-export with DISM; for a PE, see POAM-35 |
| `wim_integrity_mismatch` | The file's integrity table disagrees with its content | File is damaged; re-copy |
| `wim_metadata_hash_mismatch` | An image's metadata does not match its hash | File is damaged; re-copy |
| `wim_lzx_not_supported` | LZX ("maximum") compression (decision 0014) | Re-export with `/Compress:fast` (XPRESS) or `/Compress:none` |
| `wim_compression_not_supported` | LZMS, recovery (`.esd`) or unknown compression, including resource flag 0x10 | Export to a `.wim` with XPRESS or no compression |
| `wim_header_flags_not_supported` | Header flags the product does not accept | Re-export with DISM |
| `wim_raw_chunk_not_supported` | A compressed metadata resource holds an uncompressed chunk (*project rule*, OPEN-WIM-5; POAM-26) | Re-export with `/Compress:none` |
| `wim_split_not_supported` | Split part (`.swm`) | Merge the set into one `.wim` first |
| `wim_resource_only_not_supported` | Resource-only WIM | Not supported |
| `wim_metadata_only_not_supported` | Metadata-only WIM | Not supported |
| `wim_resource_overlap` | Two resources occupy the same bytes (*project rule*). One exception is accepted: two adjacent lookup entries that are equal in all 50 bytes are one shared metadata resource, read and verified once. This is the layout DISM writes for two identical images (OBS-018). Still refused: a third equal entry, a repeat that is not directly after its twin, and any other sharing (other size, hash, flags or count, a partial overlap, or a metadata entry on a file range) | File is damaged or of an unobserved layout; re-create, or export each image to a new file |
| `wim_duplicate_resource` | Two **file** resources have the same hash (*project rule*; metadata entries are not subject to it) | Re-create the file with DISM |
| `wim_metadata_order_not_supported` | Image metadata is not stored in rising offset order in the lookup table (*project rule*). One serviced layout is accepted: the first metadata entry (index 1) lies after every other entry and ends exactly where the lookup table starts. This is what DISM writes after a commit of index 1 (OBS-021), and lookup order still gives the index there, from one sample. Still refused: any other order, including a moved entry that is not the first, and a moved entry together with a shared one | Export each image to a new file and upload that file |
| `wim_decode_failed` | Compressed data is invalid | File is damaged; re-copy |
| `wim_read_error` | The stored file could not be read | Storage fault on the server; check the host |
| `wim_check_stalled` | The check made no progress for `check_stall_timeout_s` | Retry; check server load and storage |
| `pe_no_usable_image` | A PE file holds several images and names none as bootable | Upload a single-image PE, or one with a boot index |

Raw-sized chunks inside compressed **file** resources are counted, not
refused, in M2 (images are not applied until M3).

## Other API reason codes

Errors use `{"error": {"code": "...", "message": "..."}}`. Messages never
contain internal paths or file content.

| Code | Status | Meaning |
|------|--------|---------|
| `unauthenticated` | 401 | No certificate, unknown certificate, or disabled operator |
| `forbidden` | 403 | Missing permission; does not reveal whether the item exists |
| `not_found`, `method_not_allowed` | 404, 405 (`Allow`) | Route or item |
| `invalid_json`, `bad_request` | 400 | Malformed body, path or header |
| `body_too_large`, `unsupported_media_type` | 413, 415 | JSON body limits |
| `empty:<f>`, `too_long:<f>`, `invalid_character:<f>`, `invalid_value:<f>`, `out_of_range:<f>`, `required:<f>`, `not_allowed:<f>` | 422 | Field validation |
| `empty_file`, `too_large` | 422, 413 | Declared size 0; above `max_upload_bytes` (refused before any body) |
| `duplicate` | 409 | Content with this digest exists (id given) |
| `quota` | 429 | Too many open uploads |
| `length_required`, `size_mismatch` | 411, 400 | `Content-Length` missing or chunked; differs from the declared size |
| `digest_mismatch`, `interrupted`, `interrupted_by_restart`, `storage_error`, `cancelled` | content Failed | Upload outcomes (staging removed) |
| `pe_architecture_not_supported:<arch>` | 422 | Non-x64 PE |
| `not_ready`, `not_ready_content`, `package_not_ready`, `in_use` | 409 | State conflicts; `in_use` names the dependent packages |
| `precondition_required`, `precondition_failed` | 428, 412 | `If-Match` missing or stale |
| `declaration_contradicts_file:<fact>`, `os_scope` | 422 | Declared facts (decision 0013) |
| `os_support_unknown`, `release_not_supported:<r>`, `edition_not_supported:<e>`, `architecture_not_supported:<a>` | package reason | Why a package is `not_usable` |
| `kit_version_known_bad` | warning | PE kit on `pe.known_bad_kit_versions` |
| `integrity_failed`, `integrity_failed_on_use` | 500 or aborted stream; content Failed | A chunk or manifest failed verification on use; dependent packages become `not_usable` |
| `storage_error` | 503 or aborted stream | Object could not be read; content stays Ready |
| `audit_unavailable` | 500 | Audit record could not be written; nothing changed |
| `unavailable`, `internal` | 503, 500 | At a limit; internal error ("the outcome may be unknown, check before retrying" when a commit failed) |

M3 codes, mostly on the device listener (where `audit_unavailable` is
503, not 500):

| Code | Status | Meaning |
|------|--------|---------|
| `forbidden` | 403 | At session open: no active boot service, or more than one, serves the source |
| `invalid_token` | 401 | Bearer token unknown, or used from another source network |
| `rate_limited` | 429 | A session-open, pending-session or code-attempt limit |
| `not_authorised` | 403 | The session is not authorised yet |
| `code_not_accepted` | 422 | The code was wrong, expired, used or revoked (one answer for all) |
| `session_refused`, `session_ended` | 403 (`session_ended` is 409 on one state conflict) | Refused by an operator or by too many code attempts; expired, ended or lapsed |
| `wrong_state`, `job_started` | 409 | The request does not fit the session's state; cancel after the wipe confirmation |
| `in_use` | 409 | At confirmation: a claimed MAC has a live boot stop or a running job in another session |
| `package_not_offered`, `disk_too_small` | 422 | The package is not offered to this device; the disk is below the package's minimum |
| `display_code_mismatch` | 422 | Approval with a display code that is not the session's |
| `job_not_running` | 409 | A chunk or report for a job that is not running (including one the server just failed for a time limit) |
| `progress_out_of_order` | 409 | A report out of step order |
| `integrity_failed` | 500 | A content chunk failed its server-side check; not retried by the agent |

## Limits

All defaults are project design, listed in the
[Configuration reference](#configuration-reference). Fixed limits: total
WIM metadata at most 32 times the file size; one chunk buffer per
download (8 MiB chunks, each verified before it is sent); 16
`--trusted-key` options; checkpoint slack as in
[Verifying the chain](#verifying-the-chain). The server's resident memory
during a 10.5 GiB upload is designed to stay under 256 MiB. That bound is
asserted only by the CI `large-upload` job. It passed in CI run
40601242085 on commit d72b761, with a peak of 51 MiB, and in CI run
40633650457 on commit 5ea03a1, with a peak of 54 MiB (synthetic content
both times). Real media (MT-1) is NOT RUN.

## Network controls

- Keep `api.listen` on loopback unless operators connect remotely. When
  exposed, allow the API port only from operator networks (firewall or
  source allow-list). Before authentication every connection holds a
  global slot for up to `handshake_timeout_s`; a few addresses together
  can fill them (SC-5, POAM-27). Per-source caps bound one address or
  IPv6 /64.
- Refusal records are capped. An attacker with many sources can use up
  the credential refusal budget with public certificates (a CA
  certificate or a copied operator certificate), so a revoked operator's
  attempt in that minute is only counted in
  `auth.unauthenticated.summary` (POAM-28). Network filtering is the
  mitigation.
- Allow the server to reach PostgreSQL only; allow PostgreSQL to accept
  only `hostssl` from the server host.
- **Device listener (M3).** Expose `device_api.listen` only to the boot
  segments that enrolled boot services serve; the listener itself also
  closes connections from sources outside every served subnet. Relays
  pull their boot-policy lists from the operator listener (`api.listen`),
  so allow each enrolled relay host to reach it.
- A host inside a served subnet can still hold that boot service's
  connection and pending-session slots, within the per-source and
  per-boot-service caps. Port security and DHCP snooping on the boot
  segment are the network mitigation.

## Known gaps

See [POAM.md](../compliance/POAM.md): POAM-4 (relay; the server half's CI
condition is met), POAM-5 (relay; the server's stdout mirror drops write
errors), POAM-14, POAM-18 to POAM-33, and POAM-35 to POAM-37. In short: keys in
files with no HSM; no RFC 5280 policy-tree processing; CRL files only;
clients do not check server-certificate revocation; CLI software keys
only; operator-declared facts; non-FIPS password code linked but
unreachable; audit truncation and unsigned-tail residual; raw-chunk
refusal; pre-authentication slots; credential refusal budget; CRL number
high-water mark not persisted; owner-key and local-admin guard limits;
key buffer reallocation; serviced WIM layouts with few observations;
MT-1 NOT RUN; Linux fuzzing without ASan;
OPEN-PE-LIC with counsel; no restore event.

M3 adds POAM-38 to POAM-60 and extends POAM-1, 6, 11, 16, 18, 21, 31
and 36 (all pending owner acceptance). In short: the device has no
credential of its own and its facts are claimed; the token is bound to
the source network, not the TLS channel; secret buffers inside the HTTP
stack are not wiped; post-wipe audit scope; boot stops keyed by claimed
MACs; no SMBIOS identifier; no relay certificate rotation; a substituted
PE on the boot network; FIPS in Windows PE unconfirmed; MT-2 NOT RUN.

## Document Change History

| Date | Change |
|------|--------|
| 2026-10-29 | Evidence status: CI run 40980499705 (all 35 jobs green); POAM-53 closed. M3 still not met. |
| 2026-10-29 | Evidence status: CI run 40928612312 recorded (failure in `windows-agent` only: BOOT-004 VHD test, error 87 before any format; open defect POAM-53; everything else named passed). M3 still not met. |
| 2026-10-29 | M3 (WU-16; `m3/build` at 21c1efb). Title and M3 evidence status (M3 not met; MT-2 and MT-1 NOT RUN; CI runs 40818350636, 40876728637, 40910029759 as recorded; 40928612312 pending). New files and modes (device TLS key, plan, boot-policy and code HMAC keys); `usgp_admin` grants of migration 0004; keys for the device listener and their purposes; `keygen` purposes and `boot-service enrol`, `disable` and `raise-generation` commands; configuration reference for `[signing]` additions, `[device_api]` (every key, including `max_pending_sessions_per_boot_service`, `unauthorised_idle_timeout_s`, `session_opens_per_min`, `session_opens_per_boot_service_per_min`, `max_connections_per_boot_service`, `boot_service_refresh_s`), `[codes]` and `[jobs]`; example configuration extended (checked against `server-m3.toml`). New sections: Device listener (admission by served subnet and the 30 s refresh after enrolment, token bound to the source network, expiry and lapse, fail-closed audit, device routes), Device codes and approval, Boot services (relay enrolment, disable, no rotation, raise-generation), Jobs (states, server time limits, acknowledge, the operator fail route), Boot stops. M3 events, alerts, M3 reason codes, restore steps 7 and 8 (raise the generation; review lost stops), schema 4, device-listener network controls, M3 known gaps. |
| 2026-10-28 | CI on commit 5ea03a1. Rewrote the evidence status: `pg-integration` PASS (`migrate_pg`, `repo_pg`, `audit_pg` 9 each, `e2e_pg` 1); `large-upload` PASS (peak 54 MiB); `fuzz-smoke` and `wim-samples` `verify` PASS with the S11/S12 rules; MT-1 NOT RUN; M2 met except exit 1a (MT-1, owner action), so not met. Audit-row protection now cites `audit_pg` and `repo_pg`, with what each tests. Limits note records both large-upload peaks. Known gaps: POAM-34 closed; `repo_pg` and `e2e_pg` removed from the NOT RUN list. |
| 2026-10-27 | First M2 CI evidence (commit d72b761) and the S11/S12 WIM rules. Rewrote the evidence status: `large-upload`, `fuzz-smoke` and the `wim-samples` `verify` job PASS; `pg-integration` not fully passed (`repo_pg` and `e2e_pg` NOT RUN); MT-1 NOT RUN. Updated the 256 MiB note under Limits. `wim_resource_overlap` and `wim_metadata_order_not_supported` now describe the S11/S12 rules (OBS-018, OBS-021), matching the working tree, which is not yet committed. Known gaps now go up to POAM-37. |
| 2026-10-27 | First version for milestone M2 (WU-11): deployment with three certificate-only database roles, key modes and the `serve` admin-key refusal, command line and exit codes, full configuration reference including round-1 and round-2 keys, example configuration and example service unit (not shipped, not tested; REL-M2-P6-003), TLS and CRL refresh with rollback refusal, audit chain, checkpoints, heartbeat, SIEM forwarding and `audit verify` (`--max-unsigned-records` default 251, `--max-checkpoint-age`), time synchronisation, backup and restore with the audit-chain procedure (NIST-012), forward-only migrations with restore from backup as rollback (REL-M2-P6-004), WIM reason codes with remedies, API reason codes, limits, network controls and NOT RUN caveats. |
