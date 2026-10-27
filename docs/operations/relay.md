# Operating `usgp-relay` (milestone M1)

`usgp-relay` is the per-segment boot service. It answers UEFI x86-64 PXE
clients over IPv4 as a ProxyDHCP responder, and serves verified boot files
over read-only TFTP. It never assigns addresses (decision 0003). This
guide covers the M1 release: a static, file-based configuration on a
Linux host.

M1 evidence status: the relay's behaviour is tested in-process, and the
live boot scenarios (boot smoke S1 to S8) passed in CI run 40438138720
on 2026-10-27, in one lab topology with OVMF firmware (see
`docs/compliance/TEST_EVIDENCE.md`). The service unit below is an
example: it has not been tested, and none is shipped yet.

## Contents

- [Host requirements](#host-requirements)
- [Files, ownership and modes](#files-ownership-and-modes)
- [Command line](#command-line)
- [Configuration reference](#configuration-reference)
- [Running without root](#running-without-root)
- [Network requirements](#network-requirements)
- [What the boot network may carry](#what-the-boot-network-may-carry)
- [Suppressing a device](#suppressing-a-device)
- [Time synchronisation](#time-synchronisation)
- [Log collection and monitoring](#log-collection-and-monitoring)
- [Denial-of-service mitigations in the network](#denial-of-service-mitigations-in-the-network)
- [Audit event catalogue](#audit-event-catalogue)
- [Large boot files and the handshake deadline](#large-boot-files-and-the-handshake-deadline)
- [Upgrades](#upgrades)
- [Test lab note](#test-lab-note)
- [Document Change History](#document-change-history)

## Host requirements

- Linux. The relay binds every socket to its interface with
  `SO_BINDTODEVICE`. On any other operating system it refuses to start
  (exit 1).
- One or more interfaces on the boot segments, each with a unicast IPv4
  address.
- The FIPS crypto module in FIPS mode. The relay checks this first and
  exits 1 if it is not active (decision 0001).

## Files, ownership and modes

The relay reads these files and never writes them:

| File | Configured by | Notes |
|------|---------------|-------|
| Configuration, for example `/etc/usgp-relay/relay.toml` | `--config PATH` | At most 64 KiB |
| Boot manifest | `boot.manifest` | Written by `usgp-cli boot-manifest create`; at most 1 MiB and 256 files |
| Boot root directory | `boot.root` | Holds the published boot files |
| Suppression file (optional) | `suppression.file` | At most 1 MiB and 10,000 entries |

The relay refuses to start (exit 78) unless each of these passes its
trust rules (CM-5, SI-7):

- The configuration, manifest and suppression files are regular files.
  The path must name the real file: a symbolic link as the last path
  component is refused. Links in the directory part are resolved, and
  every directory they lead through is checked.
- Each file is owned by root (uid 0) or by the `--admin-uid`, and is not
  group-writable or world-writable.
- Every directory from the file's parent up to `/` is owned by root or the
  `--admin-uid`. None of them may be group-writable or world-writable,
  unless it has the sticky bit.
- The boot root follows the same directory rules, and must not itself be
  group-writable or world-writable. It is resolved once at start-up; every
  boot file is read below that resolved directory.
- Below the boot root, no directory on a published file's path may be a
  symbolic link. The file itself may not be a symbolic link, a FIFO or a
  device.

The suppression file is checked again on every reload. If it fails, the
previous list stays in force.

Recommended layout:

| Path | Owner | Mode |
|------|-------|------|
| `/etc/usgp-relay/` | root:root | 0755 |
| `/etc/usgp-relay/relay.toml` | root:root | 0644 |
| `/etc/usgp-relay/boot-manifest.toml` | root:root | 0644 |
| `/etc/usgp-relay/suppress.toml` | root:root | 0644 |
| `/srv/usgp-relay/boot/` (boot root) | root:root | 0755 |
| boot files | root:root | 0644 |

Do not set ACLs on these files or directories. The relay does not inspect
ACLs (POAM-7).

If a non-root administrator must own these files, pass that account's uid
as `--admin-uid`. The relay's own service account must be a different uid
(see [Command line](#command-line)).

The manifest is not signed in M1 (POAM-6). Anyone who can act as root or
as the `--admin-uid` can replace the manifest and the boot files together.

## Command line

| Command | Behaviour | Exit status |
|---------|-----------|-------------|
| `usgp-relay --config PATH [--admin-uid UID] [--allow-shared-admin-uid]` | Run until SIGTERM or SIGINT | 0 clean stop; 78 configuration, trust or content error; 1 FIPS inactive, bind failure, non-Linux host or other runtime failure |
| `usgp-relay --check-config PATH [--admin-uid UID]` | FIPS check, configuration and trust checks, verify every published file and the suppression file; binds nothing; prints the state | 0 running; 3 missing or tampered content; 78 invalid; 1 FIPS inactive |
| `usgp-relay --self-check` | FIPS check only | 0, or 1 if FIPS is inactive |
| `usgp-relay -h` or `--help` | Usage on stdout | 0 |
| `usgp-relay` with no arguments, or anything else | Usage on stderr | 2 |

Options:

- `--admin-uid UID` (decimal) names one uid that may own the trusted files
  and directories besides root. Without it, only root-owned files are
  trusted. It is a command-line option, not a configuration key, because
  the configuration file itself is checked against it. Set it in the
  service unit, which only root can change.
- `--allow-shared-admin-uid` (with `--config` only). Without this flag,
  the relay refuses to start (exit 78, `relay.config.rejected` with field
  `--admin-uid`) when its effective uid is a non-zero `--admin-uid`, or when
  its effective uid cannot be determined. A relay running as the account
  that owns its trust anchors could rewrite them. Use the flag only if
  you accept that risk; `relay.start` records it as
  `allow_shared_admin_uid=true`.
- The options after PATH may come in either order, each at most once.

`--check-config` writes the same audit events as a real start. Its status
report goes to stdout: `configuration: valid`, `state: …`, one line per
file, and the suppression entry count.

## Configuration reference

Every numeric limit and default below is **project design (OPEN-BOOT-L1),
not product behaviour**. No public source gives these numbers; they were
chosen for this project and can be changed. Unknown keys are refused, and
every value is range-checked. Any violation refuses start-up with exit 78
and a `relay.config.rejected` event that names the key.

Example (all limits at their defaults, so they are omitted):

```toml
schema_version = 1

[[interface]]
name = "boot0"
address = "10.20.1.2"
# prefix_len = 24   # optional; see below

[boot]
manifest = "/etc/usgp-relay/boot-manifest.toml"
root = "/srv/usgp-relay/boot"
uefi_x64_program = "usgp-test-payload.efi"

[suppression]
file = "/etc/usgp-relay/suppress.toml"

[log]
node_name = "relay-site-a-1"
```

### Top level and interfaces

| Key | Default | Range or rule | Notes |
|-----|---------|---------------|-------|
| `schema_version` | required | `1` | Kept across updates (REQ-BOOT-053) |
| `[[interface]] name` | required | 1 to 15 characters of `[A-Za-z0-9._-]`, not `.` or `..`; unique; 1 to 16 entries | No wildcard. Every socket is bound to it |
| `[[interface]] address` | required | Unicast IPv4; not 0/8, 127/8, 169.254/16, 224/4, 240/4 or 255.255.255.255; unique | Sent to devices as the boot server address (`siaddr`, option 54); must be reachable from every client subnet (REQ-BOOT-022) |
| `[[interface]] prefix_len` | derived | 8 to 31 | The subnet that counts as "same segment". If absent, it is taken at start-up from the interface's connected route (a route on that interface with no gateway that contains `address`). If neither exists, start-up is refused (exit 78, field `interface[i].prefix_len`). `relay.start` reports the result in `interface_prefixes` |

### `[boot]`

| Key | Default | Range or rule | Notes |
|-----|---------|---------------|-------|
| `boot.manifest` | required | Absolute path, 1 to 4096 bytes | See trust rules |
| `boot.root` | required | Absolute path to a directory | Resolved once at start-up |
| `boot.uefi_x64_program` | required | A boot file name present in the manifest | Offered to architecture 7 (UEFI x86-64) only (decision 0004) |

Boot file names are 1 to 127 bytes of `[A-Za-z0-9._-]` and `/`, with no
leading `/`, no empty component and no `.` or `..` component.

### `[limits]`

| Key | Default | Range | Meaning |
|-----|---------|-------|---------|
| `dhcp_client_burst` | 8 | 1 to 100 | Replies per claimed client hardware address: bucket size |
| `dhcp_client_refill_ms` | 2000 | 100 to 60000 | Refill interval for the bucket above |
| `dhcp_relay_burst` | 200 | 1 to 10000 | Replies per routed source address: bucket size |
| `dhcp_relay_per_sec` | 50 | 1 to 10000 | Refill per second for the bucket above |
| `dhcp_global_per_sec` | 200 | 1 to 10000 | Replies per second to same-segment requests (source 0.0.0.0 or inside the interface subnet, no `giaddr`), all interfaces together |
| `dhcp_relayed_global_per_sec` | 200 | 1 to 10000 | Replies per second to routed requests (relayed, or from another subnet), all sources together |
| `tracked_clients` | 4096 | 64 to 65536 | Size of each per-key bucket table |
| `tftp_max_transfers` | 64 | 1 to 1024 | Established TFTP transfers |
| `tftp_max_pending` | 256 | 1 to 4096 | TFTP transfers waiting for the first ACK, all interfaces together |
| `tftp_per_client_transfers` | 4 | 1 to 64 | TFTP transfers per source address |
| `tftp_rrq_burst` | 8 | 1 to 100 | TFTP requests per source address: bucket size |
| `tftp_rrq_refill_ms` | 1000 | 100 to 60000 | Refill interval for the bucket above |
| `tftp_rrq_global_per_sec` | 50 | 1 to 10000 | TFTP read requests admitted per second **on each interface** |
| `tftp_rrq_global_burst` | 100 | 1 to 10000 | TFTP read requests admitted at once on each interface before the rate applies |
| `tftp_error_per_sec` | 20 | 1 to 1000 | TFTP ERROR packets sent per second |
| `verify_concurrency` | 2 | 1 to 16 | File reads and hashes at once |

### `[tftp]`

| Key | Default | Range or rule | Meaning |
|-----|---------|---------------|---------|
| `max_block_size` | 1468 | 8 to 65464 | Largest block size granted |
| `initial_timeout_ms` | 1000 | 100 to 60000; at least `min_timeout_ms`, at most `max_timeout_ms` | Initial retransmission timeout |
| `min_timeout_ms` | 250 | 100 to 60000 | Retransmission timeout floor |
| `max_timeout_ms` | 8000 | 100 to 60000 | Retransmission timeout ceiling |
| `max_retries` | 5 | 1 to 10 | Resends per packet after the first ACK |
| `handshake_retries` | 1 | 1 to 10 | Resends of the first packet |
| `handshake_timeout_ms` | 2000 | 100 to 60000; at most `max_transfer_secs` | Time from request arrival to the first ACK. It also covers file verification (see [Large boot files](#large-boot-files-and-the-handshake-deadline)) |
| `max_transfer_secs` | 600 | 10 to 3600 | Hard limit on one transfer |
| `max_file_size_bytes` | 67108864 | 1 to 4294967295 | Largest file served. A manifest entry larger than this refuses start-up |

### `[content]`, `[suppression]`, `[log]`

| Key | Default | Range or rule | Meaning |
|-----|---------|---------------|---------|
| `content.recheck_interval_secs` | 60 | 5 to 3600 | Seconds between re-checks of every published file |
| `suppression.file` | none | Absolute path | Optional suppression file |
| `suppression.reload_interval_secs` | 2 | 1 to 300 | Seconds between checks of the suppression file |
| `log.level` | `info` | `error`, `warn`, `info`, `debug` | Diagnostic level. Audit events are written at any level |
| `log.node_name` | host name | 1 to 64 characters, no control characters | The "where" label on every audit event. If unset, the Linux host name is used |

Fixed, not configurable: UDP ports 67, 4011 and 69; DHCP requests of 300
to 1472 octets with at most 16 hops; TFTP octet mode only, requests of at
most 512 octets.

## Running without root

The relay is designed to need only two capabilities: `CAP_NET_BIND_SERVICE`
for ports below 1024, and `CAP_NET_RAW` for `SO_BINDTODEVICE`. It does not
drop privileges itself, and it does not refuse to run as root. When it
runs as root it reports `warning=running_as_root` in `relay.start`. Least
privilege therefore depends on the service unit (AC-6, POAM-13).

Run it under a dedicated account that owns none of its files, for example
`usgp-relay`. Example unit (not shipped, not yet tested):

```ini
[Unit]
Description=usg-provision boot relay (ProxyDHCP and read-only TFTP)
Wants=network-online.target time-sync.target
After=network-online.target time-sync.target
# Stop retrying after 5 failed starts in 10 minutes, so a failing
# ExecStartPre cannot restart-loop.
StartLimitIntervalSec=600
StartLimitBurst=5

[Service]
Type=simple
User=usgp-relay
Group=usgp-relay
ExecStartPre=/usr/bin/usgp-relay --check-config /etc/usgp-relay/relay.toml
ExecStart=/usr/bin/usgp-relay --config /etc/usgp-relay/relay.toml
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadOnlyPaths=/etc/usgp-relay /srv/usgp-relay
Restart=on-failure
RestartSec=10
RestartPreventExitStatus=2 78
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Notes:

- With root-owned files, no `--admin-uid` is needed. If an administrator
  account owns the files, add `--admin-uid <that uid>` to both commands.
  That uid must not be the `User=` of this unit.
- `ExecStartPre` exits 3 when content is missing or tampered, and 78
  when the configuration or files are invalid; either fails the start.
  Remove it if the relay should start anyway: it then runs in the
  `running_missing_content` state and makes no offers until the content
  verifies.
- `RestartPreventExitStatus=2 78` applies to the main process
  (`ExecStart`) only. A failed `ExecStartPre` still counts as a failed
  start and is retried under `Restart=on-failure`. `StartLimitIntervalSec`
  and `StartLimitBurst` stop those retries after 5 failed starts in 10
  minutes; the unit then stays failed until an operator fixes the cause
  and runs a reset and start. An alternative is a separate one-shot
  check unit that this unit requires.
- Exit 78 from the main process means the configuration or files must be
  fixed. Restarting does not help, so the unit does not restart on it.

## Network requirements

### Same segment

The relay must have an address on the boot segment. Devices find it by
broadcast; no change to the site DHCP server is needed (REQ-BOOT-011). If
the site DHCP server already sends PXE boot settings (for example a boot
server, a boot file name or a vendor class for PXE clients), those
settings may conflict with the relay. Devices may then boot from the other
source. Remove them, or keep the relay off that segment.

### Other subnets (REQ-BOOT-023)

For devices on a subnet other than the relay's, the network must provide:

1. **Relay agent forwarding.** The DHCP relay agent on the device's
   subnet must forward DHCP to the relay's interface address, in
   addition to the site DHCP server.
2. **Routed path to the relay.** The routed path must carry the device's
   later unicast traffic to the relay's interface address: PXE boot
   server requests on UDP 4011 (and possibly 67), and TFTP on UDP 69 and
   the relay's ephemeral transfer ports.
3. **Return route through the boot interface.** Every relay socket is
   bound to its configured interface. Replies to the relay agent
   (`giaddr`, UDP 67), unicast replies to routed clients, and TFTP data
   all leave through that interface. The relay host therefore needs a
   route to each client subnet **via the boot interface**. On a
   multi-homed host whose default route uses another interface, add
   explicit routes. Requests that arrive on another interface are not
   seen by the relay.
4. **Reachable server address.** The interface `address` is what devices
   use; it must be reachable from every client subnet (REQ-BOOT-022).

Any relay agent is accepted. Relayed requests are answered no matter
which relay agent forwarded them, and M1 has no allow list (owner answer
Q-1). Restrict relay agents in the network instead; see
[Denial-of-service mitigations](#denial-of-service-mitigations-in-the-network).

### Same segment or routed: the interface prefix

The relay sorts each DHCP request into one of two classes, which use
separate rate budgets:

- **Same segment**: no `giaddr`, from 0.0.0.0 or from inside the
  interface's subnet.
- **Routed**: everything else.

The subnet is `interface[i].prefix_len`, or else the connected route of
the configured address. A request on port 67 with no `giaddr`, from
outside that subnet, is dropped (`off_segment_source`). The one exception
is when its `ciaddr` equals its source address: it is then answered by
unicast to that address on port 68, charged to the routed budget.

**Secondary subnets on the boot segment.** If the site DHCP server hands
out addresses from more than one subnet on the same segment, the derived
prefix covers only the subnet of the relay's configured address. Clients
in a secondary subnet are treated as routed. Their DISCOVER from 0.0.0.0
is still answered. A later request from their new address on port 67 is
answered only if its `ciaddr` equals the source; otherwise it is dropped
as `off_segment_source`. Either set `interface[i].prefix_len` to a prefix
that covers every subnet on the segment, or expect these drops; they show
in `dhcp.drop.summary`.

## What the boot network may carry

**No secrets in the boot root (REQ-BOOT-043).** DHCP and TFTP are
cleartext and unauthenticated (POAM-8). Any host on the path can read or
change what they carry, and anyone on the network can request any
published file. The boot root, the boot files and DHCP options must
therefore contain no credentials, keys, passwords, domain-join material
or device-specific secrets. Anything that needs such material must come
later, over a separately protected channel. The relay's configuration has
no secret keys.

What the relay's checks do and do not cover:

- **At the relay**: the relay verifies each file against the manifest
  before it serves it (SI-7). Only bytes whose size and SHA-256 match the
  manifest are sent. A file changed on the relay's disk is refused.
- **In transit**: nothing protects the file. TFTP is cleartext and
  unauthenticated, so an on-path host can change the bytes after they
  leave the relay, and the relay cannot detect that (SC-8, POAM-8).
- **On the device**: whether the device's firmware detects a changed
  program depends on its Secure Boot check. How the product relies on
  Secure Boot is an open spec question (OPEN-BOOT-SB). The M1 evidence is
  narrow: in scenario S5 (CI run 40438138720) OVMF firmware with Secure
  Boot enabled refused an unsigned test program served by the relay. That
  shows the relay does not weaken the firmware check; it says nothing
  about other firmware or about signed boot chains. Keeping Secure Boot
  enabled on devices is recommended.

The network controls in
[Denial-of-service mitigations](#denial-of-service-mitigations-in-the-network)
also limit which hosts can sit on the boot path.

## Suppressing a device

The suppression file stops the relay from offering a boot program to the
devices it lists. A suppressed device gets no reply at all, so its
firmware moves on to its next boot option (REQ-BOOT-050, REQ-BOOT-051):

```toml
schema_version = 1

[[device]]
mac = "52:54:00:12:34:56"
note = "provisioned 2026-10-26"   # optional, at most 200 characters

[[device]]
guid = "00112233-4455-6677-8899-aabbccddeeff"
```

Each entry has exactly one `mac` or `guid`. Multicast and all-zero MAC
addresses, and the nil GUID, are refused. GUID text is case-insensitive.
Changes take effect within `suppression.reload_interval_secs`, without a
restart. A file that fails to parse or fails the trust rules is refused,
and the previous list stays in force (`suppression.rejected`).

**Suppression is a convenience, not access control (REQ-BOOT-045).**
Hardware addresses and machine identifiers on the boot network are
claimed by the device and are not authenticated. A hostile device can
claim any identity, or none, and can request boot files over TFTP
directly. Do not use suppression to keep a device away from boot files.
The protection for boot content is that it contains nothing secret
(REQ-BOOT-043).

M1 does not suppress devices automatically after provisioning
(REQ-BOOT-060, POAM-16).

## Time synchronisation

Audit timestamps are UTC (RFC 3339) from the host's system clock (AU-8).
The relay does not check the clock. Run a time synchronisation service
on the relay host against the site's authoritative time sources, and
monitor it. Events from relays with unsynchronised clocks cannot be
correlated reliably.

## Log collection and monitoring

The relay writes one JSON line per audit event to stdout, on the tracing
target `audit`. Diagnostics go to stderr.

- **Collect stdout persistently**, for example in a persistent system
  journal, and forward it to the site's central log store. M1 has no
  tamper-evident audit store of its own (AU-9, POAM-4). Protection of
  collected records depends on the collection system.
- **Monitor for audit failures** (AU-5, POAM-5). The relay ignores write
  errors on stdout and keeps serving, with no alert. Alert on: the
  service stopping or restarting; journal or forwarder errors and dropped
  messages; and the log store running short of space. Treat a period with
  no relay records while devices are booting as a possible audit failure.
- **Retain** records according to the site's audit retention policy.
- **Alert on** `boot.file.integrity_failed`, `boot.file.missing`,
  `relay.state.changed` to `running_missing_content`,
  `relay.config.rejected`, `suppression.rejected`,
  `boot.file.verify_slow`, `relay.start` with a `warning`, and sustained
  `limits.shed` counts.
- Set `log.node_name` to a unique name per relay so that records from
  different sites can be told apart.

M1 has no live status query. The state is visible only through these
events and `--check-config` (REQ-BOOT-052; owner answer Q-4; POAM-12).

## Denial-of-service mitigations in the network

The relay limits its own work (see `[limits]`), but it cannot see Ethernet
source addresses, and DHCP and TFTP identities are claimed. These residual
risks need network controls (SC-5; POAM-9, POAM-10):

| Residual | Network mitigation |
|----------|--------------------|
| A host on the boot segment that rotates its claimed hardware address can use up the same-segment DHCP budget while it floods | DHCP snooping and port security on the boot segment |
| A host on the boot segment can claim a `giaddr`, use up the routed budget and have replies sent to that address | DHCP snooping (untrusted ports must not send relayed messages) |
| A spoofed source address inside the boot subnet counts as same-segment | IP source guard on the boot segment; reverse-path filtering upstream |
| Off-segment senders rotating source addresses can use up the routed budget | ACLs on UDP 67 and 4011 toward the relay that admit only known relay agents (and routed clients' follow-up traffic) |
| Spoofed TFTP requests above `tftp_rrq_global_per_sec` on one interface shed genuine requests on that segment; several interfaces flooded at once can fill the shared pending cap | IP source guard and DHCP snooping on the boot segment; ACLs on UDP 69 |

Service recovers when the flood stops.

## Audit event catalogue

Every event has these fields: `timestamp` (UTC RFC 3339), `event`,
`component` (`usgp-relay` or `usgp-cli`), `node_name`, `outcome`
(`success`, `failure`, `refused` or `dropped`), and `detail`. Where they
apply it also has `interface`, `local_addr`, `peer`, `claimed_mac` and
`claimed_guid`. MAC and GUID are always marked as claimed: they are not
authenticated.

| Event | When | Key detail |
|-------|------|------------|
| `relay.start` | Start-up finished (success), or failed before serving (failure) | `version`, `config_sha256`, `manifest_sha256`, `interfaces`, `interface_prefixes` (for example `boot0=10.20.1.0/24(interface)`), `state`, `node_name`, `node_name_source` (`config`, `hostname`, `unset`), `service_uid`, `admin_uid`, `allow_shared_admin_uid`, `warning` (`running_as_root`, `service_uid_owns_trusted_files`, `service_uid_unknown`). Failure: `reason` (for example `fips_inactive`, `async runtime unavailable`, a bind error) |
| `relay.stop` | Process stop after a signal, or an error after start | `reason` |
| `relay.config.rejected` | Configuration, trust or content refusal at start-up or in `--check-config` | `field` (a config key, `--admin-uid` or `interface[i].prefix_len`), `reason` (trust rules: world-writable, group-writable, owner, writable directory, replaced, unresolvable, symbolic link; or `service_uid_is_admin_uid`, `service_uid_unknown`) |
| `relay.state.changed` | Change between `running` and `running_missing_content` | `from`, `to`, `cause`, `files_not_verified` |
| `boot.manifest.loaded` | Start-up | `manifest_sha256`, `file_count`, `uefi_x64_program` |
| `boot.file.verified` | Start-up and each re-check | `file`, `size`, `sha256` |
| `boot.file.integrity_failed` | A published file does not match the manifest (start-up, re-check or request) | `file`, `expected_sha256`, `actual_sha256` (when read), `expected_size`, `actual_size`, `reason`, `cause` |
| `boot.file.missing` | A published file is not in the boot root | `file`, `cause` |
| `boot.file.verify_slow` | A TFTP request was dropped because verifying the file did not finish before the handshake deadline; at most once per file per 60 s (project design) | outcome `dropped`; `file`, `size`, `elapsed_ms` (about equal to `limit_ms`), `limit_ms`, `suppressed_since_last` (timeouts since the last event for this file) |
| `suppression.loaded` | Each load of the suppression file | `entries`, `file_sha256` |
| `suppression.rejected` | Suppression file refused (once per distinct content or error) | `error`, `action` (previous list kept) |
| `dhcp.offer.sent`, `dhcp.ack.sent` | Each ProxyDHCP reply (bounded by the rate limits) | `xid`, `arch`, `file`, `yiaddr` (read from the reply bytes; always 0.0.0.0), `destination` (`relay_agent`, `unicast`, `broadcast`), `destination_addr`, `listen_port`, `origin` (same segment or routed), `giaddr`, `relay_info_echoed` |
| `dhcp.suppressed` | A suppressed device was seen; at most once per device per 60 s | claimed MAC and GUID |
| `dhcp.drop.summary` | Every 60 s, if non-zero | counts per drop reason (for example `malformed`, `short_message`, `not_pxe_client`, `unsupported_arch`, `suppressed`, `missing_content`, `off_segment_source`, `bad_source`) |
| `tftp.drop.summary` | Every 60 s, if non-zero | counts per drop reason (for example `malformed`, `bad_source`) |
| `limits.shed` | Every 60 s, if a budget or cap shed requests | counts per limit (`dhcp_client`, `dhcp_relay_source`, `dhcp_global`, `dhcp_relayed_global`, `tftp_request_source`, `tftp_rrq_global`, `tftp_per_client`, `tftp_pending`, `tftp_transfers`, `tftp_error`, `tftp_verify_timeout`) |
| `tftp.transfer.started` | A read transfer begins | `file`, `sha256`, `verified_sha256=true`, `tsize`, `oack`, `blksize` |
| `tftp.transfer.completed` | The client acknowledged the last block | `file`, `sha256`, `size`, `last_block`, `retries`, `duration_ms` |
| `tftp.transfer.failed` | The server gave up | `file`, `sha256`, `reason` (`retry_cap`, `max_duration`, `handshake_timeout`, `established_cap`, `tid_open_failed`, and others) |
| `tftp.transfer.aborted_by_client` | The client sent an ERROR | `file`, `sha256`, `client_error_code` |
| `tftp.request.refused` | A request got a TFTP ERROR (rate-limited) | `reason`, `code_sent` (1 not published, 2 write request, 3 too large, 4 mode) |
| `boot_manifest.created`, `boot_manifest.verify` (cli) | `usgp-cli boot-manifest create` and `verify` | `effective_uid`, `real_uid` (Linux), `env_user_claimed`, root, files, manifest SHA-256, outcome |

Per-packet drops are counted, not logged one by one, so log volume stays
bounded under floods.

## Large boot files and the handshake deadline

For every TFTP read request, the relay reads and hashes the whole file
again before it sends anything (SI-7), with at most `verify_concurrency`
reads at once. That verification, any wait for a free read slot, and the
client's first ACK must all fit within `tftp.handshake_timeout_ms`
(default 2000 ms), measured from the request's arrival.

If verification does not finish in time, the request is dropped silently:
no TFTP ERROR is sent and nothing wrong is served. The relay stays
`running`, and `boot.file.verify_slow` names the file. A file whose read
and hash always take longer than the deadline on the host's storage is
**never served**. Clients retrying such a file also keep the read slots
busy, which can delay other files.

The relay does not compare file sizes with the deadline at start-up. Until
a separate verification bound exists (POAM-15):

- Keep boot files small enough to read and hash well within the deadline
  on the relay's storage, on local disk.
- After publishing a new file, watch for `boot.file.verify_slow` and
  `tftp_verify_timeout` in `limits.shed`.
- If needed, raise `tftp.handshake_timeout_ms`. Each pending transfer then
  lives longer, so the pending cap fills sooner under a flood: about
  interfaces × `tftp_rrq_global_per_sec` × deadline must stay below
  `tftp_max_pending`.

## Upgrades

The relay never writes its configuration, manifest or suppression file
(REQ-BOOT-053). Keep `/etc/usgp-relay/` and the boot root across package
updates. A configuration with `schema_version = 1` stays valid. No package
or conffile handling is shipped in M1.

## Test lab note

The boot smoke harness (`scripts/boot-smoke.sh`, run under `sudo -E`)
creates its lab directory under `/tmp` (`/tmp/usgp-boot-smoke.XXXXXX`),
not under `$TMPDIR`. The lab's configuration, manifest and boot root must
pass the trust checks above, and a user-owned `$TMPDIR` would fail them
(exit 78).

## Document Change History

| Date | Change |
|------|--------|
| 2026-10-27 | Evidence status: boot smoke S1 to S8 passed in CI run 40438138720; the Secure Boot note now cites S5 and states its limits. |
| 2026-10-26 | M1 final pass: corrected what the manifest check and Secure Boot protect (QA-004); example unit no longer restart-loops on a failed `--check-config` (REL-M1-010). |
| 2026-10-26 | First version for milestone M1: configuration reference, command line, file ownership, running without root, network requirements (REQ-BOOT-023), secrets (REQ-BOOT-043), suppression (REQ-BOOT-045), time, logging, network mitigations, audit event catalogue, large-file note. |
