# Preinstallation environment (PE-1, import part for milestone M2)

Status: AUDITED, partial (spec run M2, 2026-10-26; re-audit round 1
approved). OPEN: REQ-PE-005, 010. REQ range in use: `REQ-PE-001` to
`REQ-PE-010`. Booting the environment on a device is
milestone M3 and has no REQs here (see "Later sections").

## Purpose

Windows installs run from Windows PE, a small Windows system that
Microsoft provides for deployment and recovery. The product does not ship
Windows PE. The operator builds it with Microsoft's deployment kit and
brings it into the product, where it becomes part of deployment packages
(`specs/os-images.md` REQ-IMG-001). This spec covers what the operator
imports, what the product checks, and what the operator sees.

## Actors and roles

- **Operator**: downloads Microsoft's Windows Assessment and Deployment
  Kit (ADK) and its Windows PE add-on, builds and optionally customises a
  Windows PE image on their own Windows machine, and imports it.
- **Product**: checks, stores, versions and shows imported environments.

## Definitions

- **Preinstall environment** ("PE"): a Windows PE boot image, which is a
  WIM file (`specs/standards/wim.md`) produced by Microsoft's kit
  (`specs/standards/winpe.md` §3), possibly customised by the operator
  with drivers, optional components and updates (`winpe.md` §4).
- **Import**: the operator's action of giving a PE to the product.

## Requirements

### REQ-PE-001: Microsoft components come from the operator

The product's own distribution contains no Windows PE image, no part of
Microsoft's ADK or its Windows PE add-on, and no file taken from them.
The operator obtains these from Microsoft and builds the environment on a
Windows machine they control.

- Priority: MUST
- Source: SRC-004 (the environment is produced with Microsoft's kit on
  the operator's side); SRC-057, SRC-058 (Windows PE is an ADK add-on the
  user downloads from Microsoft); SRC-063 [secondary] (redistribution in
  a third-party product is said not to be allowed)
- Basis: the MUST is a cautious project stance taken pending counsel's
  answer to OPEN-PE-LIC. The only source on redistribution is secondary
  (SRC-063), and the licence terms were not read.
- Standards: `specs/standards/winpe.md` §2, §7
- Status: AUDITED (the licensing questions in OPEN-PE-LIC remain open)

### REQ-PE-002: Import a Windows PE image

An operator can import a Windows PE boot image into the product. The
image is the one Microsoft's kit produces for a working set (the boot
image in the media folder), with or without the operator's own drivers,
optional components and updates. Once checked (REQ-PE-004) it can be
chosen for packages.

- Priority: MUST
- Source: SRC-004 (outcome only: the product uses an environment the
  operator prepares); SRC-060, SRC-061 (what the kit produces and how it
  is customised)
- Standards: `specs/standards/winpe.md` §3, §4
- Status: AUDITED (anything else that network boot needs, such as boot
  manager files, is OPEN-PE-2)

### REQ-PE-003: Preparation on non-English Windows

If the product supplies a helper that the operator runs on their own
Windows machine to prepare the environment, the helper works whatever the
display language of that machine.

- Priority: SHOULD
- Source: SRC-004
- Standards: none
- Status: AUDITED (whether usg-provision supplies such a helper at all is a
  clean-side decision, limited by OPEN-PE-LIC)

### REQ-PE-004: Check an imported environment

Before an imported PE is ready, the product checks it as a well-formed
WIM file (`specs/os-images.md` REQ-IMG-037, REQ-IMG-038) and checks that
it holds a single image, or names one bootable image, that can be used as
the environment. A PE that fails is refused with a reason, as in
REQ-IMG-022, and nothing becomes ready from it.

- Priority: MUST
- Source: SRC-047 (boot index in the header), SRC-048 (only Windows PE
  images can be marked bootable; one per file); SRC-005 (failed uploads
  must give an error)
- Standards: `specs/standards/wim.md` §2, §11
- Status: AUDITED

### REQ-PE-005: Identify the environment's architecture and version

The product determines, and shows, the processor architecture of an
imported PE and the Windows PE (kit) version it comes from. In M2 only an
x64 (amd64) PE is accepted, because M2 packages hold only Windows 11
Enterprise x64 images (`specs/os-support.md`) and a 32-bit PE cannot
deploy Windows 11. A PE for any other architecture is refused with a
reason that names the architecture, and the refusal is audited
(`specs/operator-access.md` REQ-AUD-001).

- Priority: MUST (architecture check); SHOULD (version shown)
- Source: SRC-004, SRC-008 (the kit release matters: one release did not
  work with the product); SRC-058 (32-bit WinPE cannot deploy Windows
  11); SRC-060 (kit architectures amd64, x86, arm, arm64)
- Basis: DEC-0009 (M2 image scope is Windows 11 Enterprise x64; refusals
  are clear and audited). Accepting only an x64 PE follows from that
  scope (project design, not described product behaviour)
- Standards: `specs/standards/winpe.md` §2, §3
- Status: OPEN (How does the product learn a PE's architecture and kit
  version? The image metadata that records them is not publicly
  documented (`wim.md` OPEN-WIM-8). Read from the file by a documented
  means, or declared by the operator at import?)

### REQ-PE-006: What the operator sees

For each imported PE the operator can see a name they give it, its
architecture and version (REQ-PE-005), when it was imported, its status
(as in REQ-IMG-020), its digest, and which packages use it.

- Priority: SHOULD
- Source: SRC-001 (each package includes PE content); SRC-004
- Basis: derived for the list of items shown
- Standards: none
- Status: AUDITED

### REQ-PE-007: Several environments, chosen per package

The product keeps more than one imported PE at a time. Each package
refers to one of them, and an operator can switch a package to another
(an edit, `specs/os-images.md` REQ-IMG-012).

- Priority: SHOULD
- Source: SRC-001 (PE content is part of each package)
- Basis: derived for keeping several at once
- Standards: none
- Status: AUDITED

### REQ-PE-008: Integrity

An imported PE is content under `specs/os-images.md` REQ-IMG-050 to
REQ-IMG-052: a digest is recorded when it becomes ready and checked
before every use, and it never changes in place.

- Priority: MUST
- Source: SRC-004
- Standards: `specs/standards/security-baseline.md`
- Status: AUDITED

### REQ-PE-009: Known-bad kit releases

When a Microsoft kit release is known not to work with the product, the
product tells operators which release to use instead, and warns when an
imported PE comes from the known-bad release.

- Priority: SHOULD
- Source: SRC-004, SRC-008 (operators were told to stay on an earlier
  kit release)
- Basis: the warning at import is derived (project design, not described
  product behaviour); the sources describe only the advice to operators
- Standards: none
- Status: AUDITED (the warning depends on REQ-PE-005)

### REQ-PE-010: Changes the product makes to the environment

Whether the product adds its own files to an imported PE (for example a
start-up program that contacts the product, or drivers from a package)
before serving it, and when, is not settled.

- Priority: SHOULD
- Source: SRC-004 (operator-defined scripts can run inside Windows PE)
- Standards: `specs/standards/winpe.md` §4, §5
- Status: OPEN (Does the product change the operator's PE, or must the
  operator's preparation include everything? Limited by OPEN-PE-LIC. M3.)

## States and transitions

As for an image file in `specs/os-images.md`: *Receiving*, *Checking*,
*Ready*, *Failed* (with reason), *Deleted*. Deleting a PE that packages
use follows REQ-IMG-015 (OPEN).

## Limits

- Microsoft's limits on Windows PE that later milestones must respect
  (`specs/standards/winpe.md` §6): automatic restart after 240 hours, no
  persistence across restarts, 512 MB minimum memory, RAM boot needs room
  for the whole image, no domain join inside WinPE.
- Size limits: OPEN-IMG-L1 in `specs/os-images.md`.

## Error behaviour

- Not a WIM, damaged, or unsupported variant: refused with a reason
  (REQ-PE-004).
- Wrong architecture: refused with a reason (REQ-PE-005).
- Known-bad kit release: warning (REQ-PE-009).
- Digest mismatch later: not used; reported (REQ-PE-008).

## Security expectations

- Imported files are untrusted input; checks are bounded (REQ-PE-004).
- Integrity is verified on every use (REQ-PE-008).
- Import happens over the protected, authenticated channel in
  `specs/os-images.md` REQ-IMG-053 and `specs/operator-access.md`.
- Microsoft lists security fixes for older Windows PE add-ons
  (`winpe.md` §2). Whether the product checks or reminds operators about
  them is OPEN-PE-3.

## Standards relied on

- Microsoft Windows PE and ADK documentation: `specs/standards/winpe.md`.
- Microsoft WIM format: `specs/standards/wim.md`.

## Later sections (no REQs in M2)

- **Booting the environment** on a device over the network (M3), after
  the boot program of `specs/boot-network.md`. Needs the boot manager and
  boot configuration files from the kit (OPEN-PE-2) and a choice between
  boot media signed under the 2011 and 2023 Microsoft UEFI CAs
  (`winpe.md` §3; `uefi-secure-boot.md`).
- **Windows 11 Setup inside WinPE** needs the WMI and secure-startup
  optional components (`winpe.md` §4), if the install uses Setup.
- **PE-2** usability at the device (network choice, on-screen keyboard,
  command shell on error, branding); **PE-3** passwords for the shell;
  **PE-4** a Linux-based environment.

## Out of scope / unknown

- **OPEN-PE-LIC** (for counsel; `winpe.md` §7): may a product-supplied
  helper run Microsoft's kit tools on the operator's machine; may the
  product store an operator's PE and serve it to that operator's own
  devices; may the product add its own files to it; what may be done
  with uploaded Windows images; and do the ADK and DISM licence terms
  limit creating test WIM files with DISM and analysing them for
  interoperability (the method of DEC-0006)? The ADK licence terms were
  not read (click-through). REQ-PE-001's MUST is a cautious project
  stance until counsel answers; its redistribution source is secondary
  (SRC-063).
- **OPEN-PE-2**: which files besides the boot image (boot manager, boot
  configuration, RAM-disk support files) the operator imports or the
  product needs for network boot of WinPE. M3.
- **OPEN-PE-3**: whether the product checks that an imported PE has
  Microsoft's security updates applied.
- REQ-PE-005, REQ-PE-010: see each Status line.
