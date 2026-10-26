# usg-provision roadmap

Baseline from the bootstrap run (2026-10-25), derived from `specs/INDEX.md`
only. Scope: **Windows 10/11 Enterprise client first** (P1 capabilities).
Windows Server, Linux, and ARM come later.

Rules for every milestone:

- A milestone cannot start until its **spec gate** is met: each listed
  capability has an `AUDITED` spec in `specs/`, and each listed standards
  topic has a summary in `specs/standards/` with section citations.
- Exit criteria are met only by passing gates recorded in a run's
  `qa-report.md`. A gate that is NOT RUN (missing QEMU, OVMF, Windows media,
  root) does not count toward exit.
- Every milestone updates `docs/compliance/*`.

Standards topic numbers refer to the list at the end of `specs/INDEX.md`.
Topics 18 to 21 are new requests from this roadmap (section 4).

## 1. Release R1 definition

R1 = one Windows 10/11 Enterprise client, UEFI x86-64, provisioned bare-metal
over the network end to end through a segment boot service with local cache.
P1 IDs: BOOT-1, BOOT-2, BOOT-5, PE-1, IMG-1, IMG-2, DRV-1, DISK-1, CFG-1,
CFG-2, SEQ-1, AGT-1, TGT-1, RELAY-1, RELAY-2, JOB-1, OS-1. R1 = M1 to M5.

Change from the suggested spine: relays and caching (RELAY-1/2) are P1, while
full RBAC (RBAC-1) is P2. So relays come before the full control plane
(M5 vs M6). To keep "every privileged path has authorisation" true from the
start, a minimal authenticated operator API with audit arrives in M2.

## 2. Milestones

### M0: Workspace scaffold (this run)

- Work: Cargo workspace with stub crates, FIPS crypto dependency wired into
  `usgp-crypto`, CI, `deny.toml`, fuzz skeleton, compliance seeds.
- Exit: fmt, clippy, test, pure-Rust script, name check, cargo deny, cargo
  audit, markdownlint all pass locally; CI workflow present. `usgp-crypto`
  test confirms FIPS mode on the build host.
- Spec gate: none.
- Decisions: D-0 (amend 0001; fuzz exception 0002).

### M1: Network boot to a test payload

- Capabilities: BOOT-1, BOOT-2 (UEFI x86-64, IPv4). BOOT-5 hook only: the
  relay can be told not to offer a boot program to a given client.
- Work: sans-IO DHCP/PXE parsing and ProxyDHCP responder (`usgp-dhcp`),
  read-only TFTP (`usgp-tftp`), relay binary with a static file-based config
  (`usgp-relay`), boot files verified against a SHA-256 manifest before they
  are served, our own minimal UEFI test payload (pure Rust, separate
  workspace under `testing/`), and a QEMU + OVMF harness.
- Exit:
  1. QEMU x86-64 with OVMF PXE-boots from `usgp-relay` and runs the test
     payload, which prints a marker on serial. Works both with relay on the
     client's segment and with a DHCP relay agent forwarding (cross-subnet,
     BOOT-1).
  2. Changing one byte of a served file makes the relay refuse to serve it.
  3. Fuzz targets `dhcp_packet` and `tftp_packet` run 10 minutes with no
     crash; negative tests for every RFC length and option limit.
  4. The relay binds only configured interfaces, drops malformed packets
     without panicking, rate-limits per client, and never offers an address.
  5. With OVMF Secure Boot firmware, the unsigned test payload is refused by
     the firmware (proves we do not disable or work around the check).
- Spec gate: BOOT-1, BOOT-2 (`specs/boot-network.md`). Standards 1, 3
  (RFC 1350 base; 2347/2348/2349 for the options we choose), 2 (ProxyDHCP,
  needed once D-1 is decided), 5 (background for the BOOT-5 hook).
- Decisions before start: D-1.
- Build order: `usgp-common` → `usgp-crypto` (digest) → `usgp-dhcp` ∥
  `usgp-tftp` → `usgp-relay` → test payload + harness.

### M2: Content store, integrity, minimal operator API

- Capabilities: IMG-1, IMG-2; the parts of OS-1 that concern Windows 10/11
  WIM editions.
- Work: WIM header, lookup table, and XML metadata parsing (list editions,
  select one), streaming chunked upload of multi-GB files, content-addressed
  store, signed content manifests, deployment package records with versions
  (create, clone, view, edit, delete), PE boot kit import (`usgp-cli pe
  import`). Minimal operator API with authentication, a single
  administrator role, and an audit event for every mutation. Tamper-evident
  audit log. Database with migrations.
- Exit:
  1. Upload a Windows 11 Enterprise multi-edition WIM over 10 GB; editions
     listed; one selected into a package; manifest signed; re-download
     verifies.
  2. Truncated, oversized-field, and wrong-magic WIM inputs are rejected
     (fuzz target `wim_header` and `wim_xml`, 10 minutes each).
  3. Every API mutation produces an audit event; the audit chain verifier
     detects a modified, deleted, or reordered record.
  4. Unauthenticated calls get 401 and an audit event.
- Spec gate: IMG-1, IMG-2, OS-1 (`specs/os-images.md`, `specs/os-support.md`),
  PE-1 (`specs/preinstall-env.md`, boot kit import part). Standards 9 (WIM, incl.
  compression codecs, see topic 21), 11 (WinPE redistribution constraints),
  17 (HTTP/TLS), 20 (security baseline).
- Decisions before start: D-6 (operator authentication), D-7 (database).
- Build order: `usgp-crypto` (sign, verify, AEAD, TLS) → `usgp-audit` ∥
  `usgp-db` ∥ `usgp-proto` → `usgp-image` → `usgp-api` → `usgp-server` →
  `usgp-cli`.

### M3: Pre-boot agent, disk layout, image apply

- Capabilities: PE-1, TGT-1, DISK-1, BOOT-5, JOB-1 (per-step progress and
  persistent error).
- Work: agent for the Windows PE target; provisioning session with server
  authentication and device authorisation (D-3); package and disk selection
  at the device; disk inventory and GPT layout for UEFI per Microsoft's
  recommended layout; signed job plan; chunk fetch from the server with
  verification before write; WIM edition apply; boot entry for the installed
  OS; relay stops offering a boot program once the job completes.
- Exit:
  1. In a QEMU/OVMF lab with an operator-built WinPE and a Windows 11
     Enterprise WIM: device boots from the relay, technician authorises,
     selects package and a virtual disk, image is applied, device reboots to
     disk and enters Windows setup, not network boot.
  2. Disk-layout tests run against loopback image files only, never a real
     block device; plan tests cover disk too small, disk with existing
     partitions, removable disk carrying the boot environment (refused).
  3. A wipe never starts unless `disk.wipe.authorised` was durably recorded;
     tested by failing the audit write.
  4. Tampered chunk or plan signature → job fails before any disk write,
     with a persistent error shown at the device and in the job status.
- Spec gate: PE-1, TGT-1, DISK-1, BOOT-5, JOB-1 (`specs/preinstall-env.md`,
  `specs/targeting.md`, `specs/disk.md`, `specs/boot-network.md`,
  `specs/progress.md`). Standards 5, 8, 11, 18 (WinPE network boot and boot
  entry creation).
- Decisions before start: D-2, D-3, D-4, D-5.
- Build order: `usgp-disk` ∥ `usgp-proto` (session, plan) → `usgp-deploy` →
  `usgp-image` (apply) → `usgp-preboot-agent`; `usgp-relay` BOOT-5 policy.

### M4: Configuration, drivers, workflow, management hand-off

- Capabilities: CFG-1, CFG-2, DRV-1, SEQ-1, AGT-1, OS-1 (Windows 10 and 11).
- Work: unattend template validation and per-device substitution, computer
  name, time zone, local administrator password, descriptive tags, domain/OU
  value carried as configuration (join mechanism is M8); driver package
  ingest (ZIP/CAB) with digesting and staged offline injection; ordered
  workflow with long step timeouts; management agent install step; secret
  delivery and scrubbing (D-8).
- Exit:
  1. Lab install of Windows 10 and Windows 11 Enterprise reaches logon-ready
     with the configured name, time zone, and tags, drivers present, and the
     management agent installed and reporting.
  2. Local administrator password is never in server logs, audit records,
     relay cache, or on the target disk after setup completes (test scans
     the applied disk image).
  3. Fuzz targets `unattend_template`, `zip_archive`, `cab_archive`.
- Spec gate: CFG-1, CFG-2, DRV-1, SEQ-1, AGT-1, OS-1
  (`specs/configuration.md`, `specs/drivers.md`, `specs/workflow.md`,
  `specs/agent-handoff.md`, `specs/os-support.md`). Standards 10, 12, 19
  (ZIP and CAB formats).
- Decisions before start: D-8, D-9.
- Build order: `usgp-wincfg` → `usgp-deploy` steps → `usgp-preboot-agent` →
  `usgp-server` secret service.

### M5: Relay enrolment and caching (R1 complete)

- Capabilities: RELAY-1, RELAY-2.
- Work: operator assigns the boot-service role to an enrolled host; relay
  identity certificate issuance and revocation; relay pulls config and
  signed manifests; verified chunk cache with fallback to the server;
  agent content fetch through the relay.
- Exit:
  1. Two segments, each with a relay; devices on both provision; second
     device on a segment pulls content from the relay cache (measured) and a
     cache miss falls back to the server.
  2. A revoked relay stops answering PXE within the configured interval.
  3. A corrupted cache entry is detected, evicted, and refetched.
  4. Full R1 end-to-end run recorded as ATO test evidence.
- Spec gate: RELAY-1, RELAY-2 (`specs/relay.md`). Standards 17, 20.
- Decisions before start: D-5 for any Windows relay host; RELAY-1 host OS
  answer (Unconfirmed) or a recorded product decision.
- Build order: `usgp-cache` → `usgp-httpboot` (content) → `usgp-api` /
  `usgp-server` enrolment → `usgp-relay`.

### M6: Fleet control plane (P2)

- Capabilities: RBAC-1, AUD-1, TGT-2, TGT-3, TGT-4, JOB-2, JOB-3, JOB-4,
  RELAY-3, IMG-3, IMG-4, CFG-3, CFG-4, SEQ-2, SEQ-3, SEQ-4.
- Exit: role matrix tests for every route (positive and negative); audit
  export verified; log collection; event forwarding; cache management and
  health reporting; device-side prompts and confirmation code.
- Spec gate: those capabilities. Standards 14 (SMBIOS serial, chassis).

### M7: Boot media, BIOS, HTTP boot, PE usability, wipe (P2)

- Capabilities: MEDIA-1, MEDIA-2, MEDIA-3, BOOT-3, BOOT-4, PE-2, PE-3,
  DRV-2, RET-1.
- Exit: USB and ISO boot in QEMU (UEFI and BIOS); encrypted offline
  content (AES-256-GCM via `usgp-crypto`); firmware HTTP Boot in OVMF;
  wipe with 1 to 25 passes verified on loopback images, gated by an audited
  job.
- Spec gate: those capabilities. Standards 4, 7, 15, 16.

### M8: Refresh and directory join (P2)

- Capabilities: RFR-1, DOM-1, DOM-2, DOM-3, RELAY-4, AGT-2.
- Exit: re-image of a managed endpoint with no technician; offline domain
  join with no join credentials in the answer file; existing computer
  account reused.
- Spec gate: those capabilities. Standards 13.
- Note: RFR-1 needs an agent already on managed endpoints. Whether that is
  a new `services/usgp-endpoint-agent` is decided in the M8 plan.

### M9 and later (P3)

BOOT-6, MEDIA-4, PE-4, IMG-5, IMG-6, DRV-3, DISK-2, DOM-4, RFR-2, RFR-3,
RET-2, OS-2, OS-3, Windows Server.

## 3. Crate build order (summary)

| Milestone | Crates (in order; ∥ = parallel) |
|-----------|---------------------------------|
| M0 | all stubs |
| M1 | common → crypto → dhcp ∥ tftp → relay; `testing/uefi-payload` |
| M2 | crypto → audit ∥ db ∥ proto → image → api → server → cli |
| M3 | disk ∥ proto → deploy → image → preboot-agent; relay |
| M4 | wincfg → deploy → preboot-agent → server |
| M5 | cache → httpboot → api/server → relay |
| M6+ | per plan |

## 4. Spec and standards requests from this roadmap

New standards topics (not in the index list) needed by the design:

- **18.** Windows PE network boot and boot configuration: how the Microsoft
  boot program loads WinPE over TFTP from a PE boot kit, the boot
  configuration store it reads, and creating the installed OS's boot entry
  from WinPE (Microsoft Learn). For M3 (BOOT-5, PE-1).
- **19.** ZIP (PKWARE APPNOTE) and Microsoft Cabinet format, bounds and
  compression methods. For M4 (DRV-1).
- **20.** Security baseline references: NIST SP 800-52 Rev 2 (TLS), FIPS
  186-5 (signatures), RFC 5280 (X.509 for relay identity), NIST SP 800-57
  (key management). For M2 and M5. Not product behaviour.
- **21.** WIM compression codecs as publicly documented by Microsoft
  (XPRESS, LZX, LZMS) as part of topic 9. For M2 and M3.

## 5. Unconfirmed index items: effect on the plan

| Unconfirmed item | Affects | Safe to proceed without it? |
|------------------|---------|-----------------------------|
| Secure Boot behaviour | M1, M3, M7 | Yes. The design never disables or bypasses Secure Boot and uses the operator's Microsoft boot files (D-2). M1 only checks that an unsigned payload is refused. Any signing work waits for a source or decision. |
| IPv6 network boot | M1 | Yes. IPv4 only; nothing built for v6. |
| Pre-registering devices by MAC/UUID | M3 | Yes. TGT-1 selection at the device is the only path. Session records keep MACs for audit, not for automatic targeting. |
| Zero-touch bare metal | M3 | Yes, and it reinforces D-3: without it, a technician is present and can enter an authorisation code. |
| Multicast delivery | M5 | Yes. Unicast HTTPS from relay cache only. |
| DHCP coexistence / proxy behaviour | **M1 (blocks)** | Only after decision D-1. ProxyDHCP is background only in the index, so building it needs a recorded product decision. |
| BitLocker / TPM | M4 | Yes, but the hand-off must not prevent later encryption. Gap recorded as a POAM (SC-28 on the installed OS is the endpoint's responsibility). |
| Windows Server target | M9 | Yes; out of R1. |
| General operator API | M2, M6 | Yes. We need an API for our own CLI and UI regardless. Exposing it as a supported third-party interface is a later product decision. |
| General audit trail beyond retirement | M2 | Yes. AU-2/AU-12 require it for the ATO whatever the product does; it is a project requirement, not a copied behaviour. |
| Approval workflows before deploy or wipe | M3, M7 | Partly. D-3 operator approval of a device session is a security design choice, not a claim about product behaviour. A general approval workflow waits for a source. |
| User-state migration details | M9 | Yes (RFR-2 is P3). |
| Domain-join material on the device | M8 | Yes for R1 (domain join is M8). Topic 13 summary required before M8. |
| Relay host operating systems | **M5 (influences)** | Partly. The relay is written to run on Linux and Windows hosts; R1 tests on Linux. Windows hosts also depend on D-5. |

## 6. Open decisions

Product-behaviour questions go to the spec-researcher as spec requests;
others are project decisions for the owner, recorded in `docs/decisions/`.

| ID | Needed before | Question | Type | Proposed default |
|----|---------------|----------|------|------------------|
| D-0 | M0 close | Amend 0001: the FIPS build also compiles `aws-lc-sys` (not linked) and needs `bindgen`/`clang-sys`/`cmake`/`cc`; accept them as build-only under `usgp-crypto`. Accept libFuzzer (C++) in the separate `fuzz/` workspace (proposed 0002). | Project | Accept both, enforced by `deny.toml` and the pure-Rust script. |
| D-1 | M1 | DHCP coexistence: the boot service never leases addresses; it answers only as ProxyDHCP (and supports a mode where the site's DHCP carries boot options and the relay runs no DHCP listener). | Product (spec request: Unconfirmed item) | ProxyDHCP + no-DHCP mode; never a full DHCP server. |
| D-2 | M3 | Boot chain for WinPE: Microsoft boot program from the operator's PE boot kit, no third-party chain-loader by default. | Project | As stated. |
| D-3 | M3 | How a bare-metal device session is authorised before it may see packages or receive secrets. | Product (spec request: does the product require a credential at the device for bare metal? PE-3/SEQ-4 are P2) | Technician enters a short-lived operator-issued code; operator approval in the console as an alternative; on by default. |
| D-4 | M3 | WIM apply: our own pure-Rust reader writing files through Windows APIs in WinPE, or a WinPE-native tool fed verified content. | Project | Decide in the M3 plan after the topic 9/21 summaries. |
| D-5 | M3 / M5 | Do Windows PE and Windows relay hosts fall within the FIPS module's validated operational environments? If not, what crypto does the agent use there? | Project / ATO | Check the certificate; POAM if not covered. |
| D-6 | M2 | Operator authentication mechanism (PIV/CAC client certificates via mTLS, OIDC to an enterprise IdP, or both). | Project | mTLS client certs first. |
| D-7 | M2 | Database: embedded pure-Rust store vs PostgreSQL with a pure-Rust driver whose TLS goes through `usgp-crypto`. (SQLite via `rusqlite` is excluded: C.) | Project | Decide in the M2 plan. |
| D-8 | M4 | Local administrator password: in the answer file and scrubbed after setup, or set by a post-setup step so it never lands in the answer file. | Project | Post-setup step; answer file carries no secret. |
| D-9 | M4 | AGT-1: which management agent is installed? | Product (spec request) | Operator-supplied installer package + enrolment config, run as a workflow step. |
| D-10 | before first release | Project license. | Project | Owner decides. |
