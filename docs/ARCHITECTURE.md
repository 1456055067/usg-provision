# usg-provision architecture

Status: baseline from the bootstrap run (2026-10-25). Derived only from
`specs/INDEX.md` (all capabilities `NOT SPECCED`), open standards, and
decision [0001](decisions/0001-fips-validated-crypto.md). Every mechanism
here is our own design. Where the index is silent or a behaviour is listed
as Unconfirmed, this document says so and either picks the most
conservative design or defers the choice to a named milestone.

## 1. What the system does

From the index, three end-to-end outcomes:

1. A bare-metal device boots from the network (or from media, later), gets a
   Windows 10/11 Enterprise image with drivers and configuration, and ends
   as a managed endpoint (OS-1, BOOT-1/2/5, IMG-1/2, DRV-1, DISK-1,
   CFG-1/2, SEQ-1, AGT-1, TGT-1, JOB-1).
2. An already-managed endpoint is re-imaged on demand (RFR-1, P2).
3. Bootable USB/ISO media for devices that cannot network-boot (MEDIA-*, P2).

Plus secure wipe and retirement (RET-*, P2/P3).

The first release (R1) covers outcome 1 for Windows client on UEFI x86-64,
served by a per-segment boot service (RELAY-1/2).

## 2. Components

```text
                operator (browser / usgp-cli)
                         |  HTTPS (TLS 1.3, FIPS provider), operator authn
                         v
  +-----------------------------------------------------+
  | usgp-server  (control plane)                        |
  |  usgp-api: REST/JSON routes, authn, RBAC (AC-3)     |
  |  usgp-audit: hash-chained, signed audit log (AU-9)  |
  |  usgp-db: packages, devices, jobs, relays           |
  |  usgp-image: WIM ingest, chunk + digest, manifests  |
  |  usgp-wincfg: unattend templates, driver packages   |
  |  content store (content-addressed by SHA-256)       |
  +-----------------------------------------------------+
        ^  mTLS (relay identity issued at enrolment)
        |  config, signed manifests, content, events
        v
  +-----------------------------------------------------+
  | usgp-relay  (one per L2 segment; on a managed host) |
  |  usgp-dhcp: ProxyDHCP responder (no IP leases)      |
  |  usgp-tftp: read-only TFTP of verified boot files   |
  |  usgp-httpboot: HTTP(S) boot artifact + content     |
  |  usgp-cache: verified chunk cache, fallback to srv  |
  +-----------------------------------------------------+
        ^  L2 broadcast DHCP/PXE, TFTP   (UNAUTHENTICATED)
        |  HTTPS to relay or server      (server-authenticated TLS)
        v
  +-----------------------------------------------------+
  | target device                                       |
  |  firmware PXE (UEFI) -> boot program -> WinPE       |
  |  usgp-preboot-agent (runs inside operator's WinPE)  |
  |   usgp-deploy: executes the signed job plan         |
  |   usgp-disk: computes + applies the disk layout     |
  |   usgp-image: verifies + applies WIM edition        |
  |   usgp-wincfg: renders unattend, stages drivers     |
  +-----------------------------------------------------+
```

| Component | Runs on | Role |
|-----------|---------|------|
| `usgp-server` | hardened server (Linux first) | Source of truth for packages, devices, jobs, relays, audit. Signs content manifests and job plans. |
| `usgp-relay` | an operator-assigned, enrolled host on each boot segment (RELAY-1; host OS is OPEN) | Answers PXE, serves verified boot files, caches verified content, forwards progress. Holds no long-lived secrets except its own identity key. |
| `usgp-preboot-agent` | target device, inside operator-built Windows PE (PE-1) | Authenticates the server, opens a provisioning session, asks the technician for package and disk (TGT-1, DISK-1), executes the plan, reports progress (JOB-1). |
| `usgp-cli` | operator workstation | Imports PE boot kits, images, driver packages; manages packages and jobs; later builds media (MEDIA-1). |

### Windows PE and Microsoft components

PE-1 says operators build WinPE themselves from Microsoft's deployment kit;
we never ship Microsoft components. Consequences for the design:

- A **PE boot kit** is an operator-imported, digest-pinned set of boot files
  (boot program per firmware architecture, its configuration, the WinPE
  `.wim`) plus our agent binary injected by the operator's build step.
  `usgp-cli pe import` records digests; the server signs a manifest over them.
- In WinPE the agent may call Windows-native facilities that the operator's
  WinPE contains (disk IOCTLs, volume format, offline servicing tools). The
  pure-Rust rule governs what we build and link, not tools present on the
  target at run time. Each such call is wrapped behind a trait in
  `usgp-disk` / `usgp-deploy` so the plan logic stays pure and testable.
  Whether WIM apply uses our own reader or a WinPE-native tool is decided in
  the M3 plan (see ROADMAP open decision D-4).

## 3. Trust boundaries

| # | Boundary | Authentication | Untrusted inputs | Fail-secure rule |
|---|----------|----------------|------------------|------------------|
| TB-1 | Target firmware ↔ relay (DHCP/PXE, TFTP; L2) | None possible (open standards provide none). Secure Boot, where the device has it on, is the only integrity check the firmware makes; we never weaken it. | Every DHCP/TFTP packet (RFC 2131/2132/4578, RFC 1350/2347-2349). | Malformed or unexpected packet → drop, rate-limited log. Unknown architecture → no offer. Device whose job is complete → no offer (BOOT-5). |
| TB-2 | Pre-boot agent ↔ relay/server (HTTPS) | Server authenticated by TLS against a provisioning trust anchor baked into the PE boot kit. The device is unauthenticated until the session is authorised (technician code or operator approval, design D-3). | Hardware facts, selections, progress events, logs from the device. | No authorised session → no package list, no plan, no secret. Plan signature or content digest mismatch → stop before any disk write. |
| TB-3 | Relay ↔ server (mTLS) | Mutual TLS; relay certificate issued by the server's internal CA at operator-approved enrolment (RELAY-1 "assigned to that role"). | Relay health, cache inventory, forwarded events. | Revoked or expired relay cert → relay stops answering PXE. Lost server link → relay serves only content it already verified; never invents plans. |
| TB-4 | Operator ↔ API (HTTPS) | Operator authentication (mechanism decided at M2; PIV/CAC-capable mTLS is the target, D-6) + RBAC on every route. | All request bodies, uploads (multi-GB WIM, ZIP/CAB driver packages, unattend templates). | Unauthenticated or unauthorised → 401/403 + audit event. Upload fails validation → quarantined, never published. |
| TB-5 | Server ↔ its storage | OS file permissions; integrity via signed manifests. | Content read back from disk. | Digest mismatch on read → content marked bad, not served. |
| TB-6 | Build/supply chain | `cargo deny`, `cargo audit`, pinned toolchain, lockfile. | Third-party crates; the FIPS C module (decision 0001). | Any gate failure blocks release. |

Destructive operations (disk wipe at DISK-1, RET-1) happen only inside an
authorised session, against a disk identified by stable attributes the
technician confirmed, after the server has durably recorded the
authorisation audit event. If the audit write fails, the agent does not wipe.

## 4. Data flows (R1, bare-metal Windows over the network)

1. **Content ingest (operator → server).** `usgp-cli` uploads a WIM in
   chunks over HTTPS. The server streams it through SHA-256, splits it into
   fixed chunks (content-addressed), parses the WIM header and XML metadata
   to list editions (IMG-2), and stores a content manifest. Driver packages
   (DRV-1) and the unattend template (CFG-1) go through the same pipeline.
   A deployment package (IMG-1) is a versioned record that references
   manifest digests plus configuration; publishing a version signs it.
2. **Relay sync (server → relay).** The relay pulls its config and the
   signed manifests for packages offered on its segment, then pulls chunks
   on demand or by pre-stage (RELAY-3, P2), verifying each chunk digest
   before it enters the cache.
3. **Network boot (device ↔ relay).** UEFI PXE broadcast → relay answers
   as ProxyDHCP (boot server + boot file only, no address; decision D-1)
   → device TFTPs the boot program and WinPE files the relay has verified
   against the PE boot kit manifest.
4. **Session (agent ↔ relay/server).** The agent starts in WinPE, gathers
   hardware facts (MACs, firmware type, architecture, disks), opens a TLS
   session to the relay (proxying to the server) and is authorised (D-3).
   The server returns the packages the device may choose (TGT-1).
5. **Selection and plan.** The technician picks a package and target disk.
   The server records the selection, emits `job.created` and
   `disk.wipe.authorised`, and returns a signed job plan: ordered steps
   (SEQ-1), digests of all content, per-device values (CFG-1/2).
6. **Execution.** The agent verifies the plan signature, partitions the disk
   (`usgp-disk`, GPT layout for UEFI), fetches chunks from the relay cache or
   server (RELAY-2) verifying each before write, applies the selected WIM
   edition, stages drivers (DRV-1), renders the unattend file with
   per-device values, retrieves secrets one-shot for the step that needs
   them, installs the management agent hand-off step (AGT-1), sets the boot
   entry for the installed OS, and reports progress per step (JOB-1).
7. **Completion.** The server marks the job complete; the relay stops
   offering a boot program to that device (BOOT-5) and the firmware boot
   order points at the installed OS.

## 5. Crypto boundary (decision 0001)

- `usgp-crypto` is the only crate that depends on `aws-lc-rs` (feature
  `fips`), `rustls` (feature `fips`), and, from M1, `tokio-rustls`. It
  exports:
  - `CryptoProvider` trait: digest (SHA-256/384/512), HMAC, signature
    verify/sign (ECDSA P-256/P-384, and RSA-PSS/PKCS#1 v1.5 verify where an
    open format needs it), AEAD (AES-256-GCM), HKDF, DRBG output.
  - A separately named legacy-digest entry point for SHA-1 that open formats
    require (WIM resource hashes). It is documented as non-security and is
    never used for SI-7 decisions.
  - TLS: `server_config()` / `client_config()` builders and accept/connect
    wrappers, so no other crate names `rustls` types.
  - `fips_status()`; every service calls it first in `main` and exits non-zero
    if the module is not in FIPS mode.
- Enforcement: `deny.toml` bans `ring`, `openssl*`, and restricts
  `aws-lc-rs`, `aws-lc-fips-sys`, `aws-lc-sys`, `rustls`, `tokio-rustls` to
  their wrappers; `scripts/check-pure-rust.sh` fails on any `-sys` crate or
  C/C++ build helper (`cc`, `bindgen`, `cmake`, `pkg-config`, `vcpkg`, and
  similar) in a normal, build, or dev tree outside `usgp-crypto` that is not
  on the pure-Rust-bindings allowlist (empty today).
- Observed in the bootstrap probe (aws-lc-rs 1.18.2, rustls 0.23.46):
  `rustls/fips` also enables the non-FIPS `aws-lc-sys` build. It compiles
  but is not linked into binaries that use the FIPS provider. Decision 0001
  names only `aws-lc-fips-sys`, so it needs an amendment (ROADMAP D-0).
- Validated operational environment: macOS build hosts can compile and
  self-test the FIPS module but are not evidence of a validated
  environment. The authoritative FIPS build is CI on Linux. Whether the
  pre-boot agent (Windows PE) and Windows relay hosts fall inside the
  module's validated operational environments must be checked against the
  certificate before M3 (ROADMAP D-5).

## 6. Crate map

```text
crates/
  usgp-common/       config loading + validation, error base, ids, time, tracing init
  usgp-crypto/       CryptoProvider, FIPS status, TLS config (only C dependency)
  usgp-audit/        audit event types, hash chain, signed checkpoints, export
  usgp-db/           repository traits + migrations (engine chosen at M2)
  usgp-proto/        NEW: wire types shared by server, relay, agent, cli (serde)
  usgp-dhcp/         sans-IO DHCP/PXE parser + ProxyDHCP responder logic
  usgp-tftp/         sans-IO TFTP read-only server state machine
  usgp-httpboot/     HTTP boot artifact + content serving (relay side)
  usgp-image/        WIM header/XML/lookup parsing, chunking, digests, manifests
  usgp-disk/         disk inventory model, GPT/MBR layout plans, layout executor trait
  usgp-wincfg/       NEW: unattend template model/render, driver package ingest (ZIP/CAB)
  usgp-deploy/       job plan model + step engine (OS-neutral)
  usgp-cache/        verified chunk cache, eviction, upstream fetch
  usgp-api/          server REST routes, authn, RBAC
services/
  usgp-server/       control plane binary
  usgp-relay/        per-segment boot + cache binary
  usgp-preboot-agent/ agent binary (Windows PE target first)
tools/
  usgp-cli/          operator CLI
fuzz/                separate cargo workspace (cargo-fuzz targets)
```

Refinements to the CLAUDE.md layout, and why:

1. **`usgp-proto` (new).** The agent runs in WinPE and must not link the
   server's HTTP stack, database, or RBAC. Shared wire types (session,
   plan, progress events, relay config) need one home that all four
   binaries can depend on. It holds types and validation only, and it is a
   fuzz target.
2. **`usgp-wincfg` (new).** Unattend files (XML), driver packages (ZIP/CAB),
   and later offline domain join data are Windows-specific, each with its
   own untrusted-input parser. Keeping them out of `usgp-deploy` keeps the
   engine OS-neutral for later Linux work (OS-2) and gives each parser its
   own fuzz target.
3. **Sans-IO protocol crates.** `usgp-dhcp` and `usgp-tftp` expose pure
   `handle(packet, ctx) -> Vec<Reply>` state machines with no sockets. The
   relay owns the sockets. Benefits: fuzzable, unit-testable without root,
   and the QEMU smoke harness can drive them over a user-space network.
4. **`usgp-httpboot` scope.** It serves verified artifacts and content over
   HTTP(S). Firmware HTTP Boot (BOOT-4) is P2 with a single source, so it is
   a later feature of this crate; no chain-loader is assumed.

Layering (enforced by Cargo dependencies, checked in review):

```text
common <- crypto <- audit, image, cache, api
common <- dhcp, tftp, httpboot, disk, wincfg, db, proto   (no crypto in parsers)
deploy  -> common, proto, disk, image, wincfg
server  -> api, audit, db, image, wincfg, proto, crypto, common
relay   -> dhcp, tftp, httpboot, cache, proto, crypto, common
agent   -> deploy, proto, crypto, common
cli     -> proto, crypto, common
```

## 7. Wire protocols (our design)

- All agent↔server, relay↔server, and cli↔server traffic is HTTPS with JSON
  bodies under versioned paths (`/v1/...`), defined in `usgp-proto`.
  gRPC was rejected because it needs `protoc` (a C++ binary) or extra
  codegen, plus a second TLS integration, for no gain at this scale.
- Bulk content is `GET /v1/content/{sha256}/{chunk}` from relay or server;
  the client verifies chunk digests from the signed manifest, so the
  transport does not have to be trusted for integrity. TLS still provides
  confidentiality.
- Signatures: ECDSA P-384 with SHA-384 over a canonical byte encoding of
  manifests and plans (encoding defined in `usgp-proto` at M2).

## 8. Cross-cutting rules

- Config (CM-6): every key has a secure default; services refuse to start
  on unknown keys or values that fail validation.
- Audit (AU-2/AU-12): every operator action and job state change produces
  an event (who, what, when, where, outcome) before the change is
  acknowledged.
- Secrets: `zeroize` types; never logged; delivered only inside an
  authorised TLS session, one-shot per step; cleartext copies on the target
  are scrubbed at the end of setup (design detail at M4).
- Parsers: bounds-checked, no panics, fuzz target each.
- IPv4 only until IPv6 boot is confirmed (Unconfirmed list); packet types
  are not designed to preclude a later v6 path.
