# Drivers (DRV-1)

Status: AUDITED (spec run M4, 2026-10-29; clean-room audit 2026-10-29, OPEN
items remain OPEN). REQ
range in use: `REQ-DRV-001` to `REQ-DRV-011`. DRV-2 (storage drivers in
the preinstall environment) and DRV-3 (settings by chassis type) are not
specced.

## Purpose

Windows images do not hold every device driver. Operators add driver
packages to a deployment so that the installed Windows works on the
target hardware from its first start.

## Actors and roles

- **Operator**: uploads driver archives and attaches them to packages.
- **Product**: stores, verifies and delivers the drivers, and puts them
  into the installed Windows before it first starts.

## Requirements

### REQ-DRV-001: Driver archives in ZIP or CAB form

An operator can upload driver content as a ZIP archive or a Microsoft
cabinet (CAB) archive.

- Priority: MUST
- Source: SRC-004 (CAB driver files accepted as well as ZIP)
- Standards: `specs/standards/zip-cab.md`
- Status: AUDITED. Which compression methods inside them are accepted is
  OPEN-DRV-1.

### REQ-DRV-002: Drivers are optional parts of a package

An operator can attach any number of driver archives to a deployment
package, including none, and detach them again.

- Priority: MUST
- Source: SRC-001 (drivers are an optional part of a package)
- Standards: none
- Status: AUDITED

### REQ-DRV-003: One archive, many packages

One uploaded driver archive can be attached to several packages. Uploading
a file again under the same identity does not detach it from the other
packages that use it.

- Priority: MUST
- Source: SRC-004 (re-uploading a driver file no longer removes it from
  other packages that use it)
- Standards: none
- Status: AUDITED. Whether such an update changes packages that are
  already ready is OPEN-DRV-2.

### REQ-DRV-004: Applied on bare-metal installs

During a bare-metal install, the drivers in every archive attached to
the package are added to the installed Windows before it first starts,
so that Windows can use them when it detects its devices.

- Priority: MUST
- Source: SRC-001 (outcome only: drivers are part of the package the
  install applies). SRC-004 does not say when drivers are applied
  on bare metal, so it is not cited here
- Standards: `specs/standards/offline-drivers.md` §6
- Status: AUDITED. "Before it first starts" is a project reading of the
  open mechanism (offline addition, topic 12), not a vendor statement.

### REQ-DRV-005: Applied on refresh

The same drivers are applied when the package is used to refresh a
managed device.

- Priority: MUST
- Source: SRC-004 (driver files were not used during refresh; fixed)
- Standards: `specs/standards/offline-drivers.md`
- Status: AUDITED (refresh itself is RFR-1, not specced)

### REQ-DRV-006: Only valid driver packages are applied

The product applies only the INF-based driver packages found in an
archive. An archive that holds no INF-based driver package is reported
to the operator when it is uploaded. Installers inside an archive are
not run.

- Priority: SHOULD
- Source: none
- Basis: project reading of Microsoft's offline method, which accepts
  only INF packages (`offline-drivers.md` §3)
- Standards: `specs/standards/offline-drivers.md` §1, §3
- Status: OPEN (No product source says what happens to archives without
  INF packages or with installers.)

### REQ-DRV-007: Signatures

The product does not weaken Windows' driver signature requirement on
the installed system.

- Priority: MUST
- Source: none
- Basis: project rule (Secure Boot and boot chains are never weakened,
  DEC-0018 item 5; CLAUDE.md)
- Standards: `specs/standards/offline-drivers.md` §2
- Status: OPEN (Whether unsigned packages are refused at upload, skipped
  with a warning at install, or fail the install. No product source.)

### REQ-DRV-008: Integrity

Driver archives are integrity-checked when uploaded and again before
their content is used on a device, like other package content.

- Priority: MUST
- Source: SRC-004 (downloaded files are hash-checked before imaging
  continues)
- Basis: DEC-0011, DEC-0021 item 4 (verify before use; nothing written
  before verified), project rules
- Standards: none
- Status: AUDITED

### REQ-DRV-009: Bounded, safe archive reading

The product reads archives with fixed bounds and refuses an archive
whose entries would land outside the extraction area, whose sizes are
inconsistent, or that it cannot read in full. A refused archive is not
partly applied.

- Priority: MUST
- Source: none
- Basis: project rule (every parser bounded and never panics; CLAUDE.md)
- Standards: `specs/standards/zip-cab.md` A.6, B.8
- Status: AUDITED

### REQ-DRV-010: Driver failure during install

If adding the package's drivers fails on a device, the operator sees a
persistent error naming the driver step (`specs/progress.md`).

- Priority: MUST
- Source: SRC-004 (outcome only: a clear persistent error when a step
  fails)
- Standards: none
- Status: OPEN (Is a failed driver a stop for the whole install, or a
  warning? No source.)

### REQ-DRV-011: Audit

Uploading, replacing, attaching, detaching and deleting driver archives
are recorded for audit.

- Priority: MUST
- Source: none
- Basis: DEC-0010 (project rule)
- Standards: none
- Status: AUDITED

## States and transitions

A driver archive is *being processed*, *ready* or *refused* (with a
reason), like other content (`specs/os-images.md`). Only a ready archive
can be part of a ready package.

## Limits

Not stated publicly (OPEN-DRV-3).

## Error behaviour

Refused archive: reason shown, not attachable (REQ-DRV-009). Driver step
failure on a device: persistent error (REQ-DRV-010).

## Security expectations

Integrity as for all content (REQ-DRV-008); signatures never weakened
(REQ-DRV-007); bounded readers (REQ-DRV-009).

## Standards relied on

`specs/standards/offline-drivers.md` (topic 12), `specs/standards/zip-cab.md`
(topic 25).

## Out of scope / unknown

- DRV-2, DRV-3.
- **OPEN-DRV-1**: accepted compression methods (`zip-cab.md` OPEN-ARC-2).
- **OPEN-DRV-2**: effect of replacing a shared archive on ready packages.
- **OPEN-DRV-3**: size and count limits.
- **OPEN-DRV-4**: whether drivers are filtered by architecture or
  hardware before use (Windows itself chooses among staged drivers,
  `offline-drivers.md` §5).
- REQ-DRV-006, 007, 010: see Status lines.
