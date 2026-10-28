# Preinstallation environment (PE-1: import part M2, boot and apply part M3)

Status: AUDITED, partial (spec run M2, 2026-10-26; re-audit round 1
approved). REQ-PE-005 (M2) AUDITED 2026-10-27 after the decisions
0012-0015 check. OPEN: REQ-PE-010; the post-M2 part of 005
(`specs/os-images.md` OPEN-IMG-F1).
M3 part (spec run M3, 2026-10-27; fix rounds 1 and 2, 2026-10-28,
CR-003, CR-011 and DEC-0018): REQ-PE-011 to REQ-PE-020 AUDITED
2026-10-28 after re-audit round 1; REQ-PE-001 to 010 are unchanged.
REQ range in use: `REQ-PE-001` to `REQ-PE-020`.

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

In M2 the product learns these facts as for an image edition
(`specs/os-images.md` REQ-IMG-043):

1. At import the operator declares the PE's processor architecture and
   kit version.
2. The product reads the same facts from the image information inside
   the file, as far as Microsoft documents where that information
   records them (`specs/standards/wim.md` §7, OPEN-WIM-8). If a declared
   fact contradicts a fact read from the file, the import, or the choice
   of the PE for a package, is refused with a reason that names the
   fact, and the refusal is audited.
3. A fact the file does not state is taken from the declaration and is
   shown and recorded as declared, not verified.
4. Each declaration is audited with the operator's identity.

The x64 rule above applies to the declared and the read architecture
alike. After M2, whether these facts are read from the file without a
declaration is `specs/os-images.md` OPEN-IMG-F1.

- Priority: MUST (architecture check; items 1 to 4); SHOULD (version
  shown)
- Source: SRC-004, SRC-008 (the kit release matters: one release did not
  work with the product); SRC-058 (32-bit WinPE cannot deploy Windows
  11); SRC-060 (kit architectures amd64, x86, arm, arm64)
- Basis: DEC-0009 (M2 image scope is Windows 11 Enterprise x64; refusals
  are clear and audited). Accepting only an x64 PE follows from that
  scope. Items 1 to 4 and the x64 rule's use of declared facts are
  DEC-0013 items 1 to 4. Project design, not described product
  behaviour.
- Standards: `specs/standards/winpe.md` §2, §3; `specs/standards/wim.md`
  §7
- Status: AUDITED (M2; the rule after M2 is OPEN-IMG-F1)

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

## Requirements, M3: booting the environment and applying the image

These cover what happens on the device between the boot program
(`specs/boot-network.md`) and the restart into the installed Windows.
The device-side choices are in `specs/targeting.md`, the disk in
`specs/disk.md`, progress and errors in `specs/progress.md`.

### REQ-PE-011: Boot the operator's environment over the network

A UEFI x64 device that network boots from a boot service, and that the
boot service serves (`specs/boot-network.md` REQ-BOOT-063), starts the
Windows PE environment chosen for that boot service from the network,
with no local media. The environment runs from memory and does not
change any disk until the person at the device has confirmed a wipe
(`specs/disk.md` REQ-DISK-006).

- Priority: MUST
- Source: SRC-004, SRC-005 (installs start by network boot into the
  provisioning environment; outcome only); SRC-091, SRC-092 (how Windows
  PE boots over the network into a RAM disk)
- Standards: `specs/standards/winpe-network-boot.md` §2 to §4
- Status: AUDITED (2026-10-28; which environment a boot service serves when several
  packages with different environments are offered is OPEN-PE-5)

### REQ-PE-012: Network-boot files come from the operator's kit

Besides the WinPE image, network boot needs Microsoft's boot manager
and the other boot files from the same kit, and a boot configuration
that tells the boot manager to start that image from a RAM disk. These
come from the operator's own kit and environment, like the image itself
(REQ-PE-001). [project rule] The operator builds the boot configuration
with Microsoft's tool as part of the environment's boot kit and imports
it with the other boot files; the product never generates or edits a
boot configuration. The product checks that the set is complete and
matches the imported environment's architecture before the boot service
offers it; an incomplete or mismatched set is refused with a reason, and
the boot service treats it as missing content (`specs/boot-network.md`
REQ-BOOT-052).

- Priority: MUST
- Source: SRC-004 (outcome only: the operator prepares the environment
  with Microsoft's kit); SRC-091 (files and boot configuration for
  network boot of WinPE)
- Basis: DEC-0018 item 3 (operator builds the boot configuration; the
  product imports and verifies it and never generates it; project rule,
  not described product behaviour); the completeness check is project
  design
- Standards: `specs/standards/winpe-network-boot.md` §2, §5, §6
- Status: AUDITED (2026-10-28; what "verifies" can check in an
  undocumented format is limited to completeness, presence and
  integrity, OPEN-PE-7; licensing of storing and serving the kit files
  stays with OPEN-PE-LIC)

### REQ-PE-013: The product's program starts by itself

When the environment has started on the device, the product's program in
it starts automatically, with nothing typed at the device, and shows its
own screen (`specs/targeting.md`). If it cannot start, the device does
not sit at a blank prompt with no explanation.

- Priority: MUST
- Source: SRC-001 (after boot, the person goes straight to choosing a
  package and disk; outcome only); SRC-062, SRC-095 (Microsoft's
  documented ways to run a program automatically when WinPE starts)
- Standards: `specs/standards/winpe.md` §5, §5.1
- Status: AUDITED (2026-10-28; how the program gets into the operator's
  environment is REQ-PE-010, OPEN)

### REQ-PE-014: Bring up the network

The environment starts wired networking and gets its address from the
site DHCP server before the product's program tries to reach the product.
The program waits for the network with a bounded wait. If no usable
network comes up, the device shows a persistent error that says so
(`specs/progress.md` REQ-JOB-005) and suggests that a network driver may
be missing from the environment.

- Priority: MUST
- Source: SRC-004 (outcome only: connection failures are reported at
  the device); SRC-096, SRC-097 (WinPE starts networking at
  boot, can wait for an address, and needs a driver for adapters it does
  not cover)
- Standards: `specs/standards/winpe.md` §5.2
- Status: AUDITED (2026-10-28; wait length: `specs/progress.md`
  OPEN-JOB-4; Wi-Fi is PE-2, not M3)

### REQ-PE-015: Connect back over a protected, authenticated channel

The product's program connects back to the product (its boot service or
the central server) over TLS. It accepts the product only if the
product's certificate chains to a trust anchor the program already holds
and names the server it meant to reach. The product authenticates the
session as `specs/targeting.md` REQ-TGT-012 requires. Everything after
the PXE phase (package list, content, secrets, progress reports) goes
over this channel. A failure to connect or to authenticate is shown at
the device and nothing is installed.

- Priority: MUST
- Source: SRC-004 (outcome only: the device's environment and the
  product authenticate each other)
- Basis: DEC-0011 (secrets only over protected channels); REQ-BOOT-043;
  TLS, the trust-anchor check and the server-name check are project
  design
- Standards: `specs/standards/http-tls.md` §6;
  `specs/standards/security-baseline.md` §2
- Status: AUDITED (2026-10-28; how the trust anchor and the session credential reach
  the environment, given that the PXE phase carries no secrets, is
  OPEN-PE-6)

### REQ-PE-016: Download and verify content before use

The program downloads all the content the chosen package needs and
verifies each item's integrity against the digest the product recorded
(`specs/os-images.md` REQ-IMG-050) before using it. Content that fails
the check is not used, and the job fails (`specs/progress.md`
REQ-JOB-008).

- Priority: MUST
- Source: SRC-004 (outcome only: content is integrity-checked before
  use); SRC-009 (outcome only: content is downloaded before the install
  runs)
- Standards: `specs/standards/security-baseline.md`
- Status: AUDITED (2026-10-28; where content is held while waiting, and whether
  download comes before partitioning, is `specs/progress.md` OPEN-JOB-3)

### REQ-PE-017: Apply the chosen image

After the disk has been partitioned (`specs/disk.md` REQ-DISK-008), the
environment applies the chosen edition of the package's Windows image to
the Windows partition, so that the result is what Microsoft's documented
apply of that image index gives. Only the chosen edition is applied.
[project rule] The product applies the image itself; it does not call
Microsoft's imaging tool to do so.

- Priority: MUST
- Source: SRC-001 (outcome only: a package's image is installed on the
  chosen disk); SRC-088, SRC-048 (Microsoft's apply flow: partition,
  apply the image index to the Windows partition, then set up boot
  files)
- Basis: DEC-0018 item 4 (the product applies the image with its own
  reader; implementation choice, project rule, not described product
  behaviour)
- Standards: `specs/standards/wim.md` §7, §11; `specs/standards/gpt.md`
  §10
- Status: AUDITED (2026-10-28; compression scope follows `specs/os-images.md`
  REQ-IMG-038)

### REQ-PE-018: Enough memory

Before the environment is offered for network boot, the product tells
the operator how much memory a device needs to start it (the base
requirement plus the size of the image, which is held in memory). If the
environment starts but memory runs short, the device shows an error
rather than continuing.

- Priority: SHOULD
- Source: SRC-057 (512 MB base; RAM boot needs contiguous memory for the
  whole image)
- Basis: derived
- Standards: `specs/standards/winpe.md` §6, §9;
  `specs/standards/winpe-network-boot.md` §4
- Status: AUDITED (2026-10-28)

### REQ-PE-019: Restart into the installed system

When the image has been applied and the disk made bootable
(`specs/boot-network.md` REQ-BOOT-065, REQ-BOOT-066), the program
reports success to the product (`specs/progress.md` REQ-JOB-013) and
restarts the device, which then starts the installed Windows. Nothing
the environment wrote to its own RAM disk is needed after the restart.

- Priority: MUST
- Source: SRC-004 (after network boot, the next boot does not return to
  network boot; outcome only)
- Basis: the restart itself is derived
- Standards: `specs/standards/winpe.md` §5.2 (WinPE can restart itself),
  §9
- Status: AUDITED (2026-10-28)

### REQ-PE-020: Firmware mode and architecture of the running environment

The program checks, when it starts, that the environment booted in UEFI
mode on x64. If not, it shows a persistent error and installs nothing
(`specs/disk.md` REQ-DISK-011).

- Priority: MUST
- Source: SRC-057 (WinPE must boot in the firmware mode the installed
  Windows will use); SRC-096 (WinPE reports its firmware mode)
- Basis: M3 scope (DEC-0004, DEC-0009)
- Standards: `specs/standards/winpe.md` §5.3, §6
- Status: AUDITED (2026-10-28)

## States and transitions

As for an image file in `specs/os-images.md`: *Receiving*, *Checking*,
*Ready*, *Failed* (with reason), *Deleted*. In M2, deleting a PE that
packages use is refused, naming those packages (`specs/os-images.md`
REQ-IMG-015).

**On the device (M3).** *Network booting* (REQ-PE-011) → *Starting*
(REQ-PE-013, REQ-PE-020) → *Network up* (REQ-PE-014) → *Connected*
(REQ-PE-015) → device session (`specs/targeting.md`) → job
(`specs/progress.md`: download and verify, disk, apply, boot setup) →
*Restarting* (REQ-PE-019). A failure at any point shows a persistent
error and installs nothing further.

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
- Declared architecture or kit version contradicts the file: refused
  with a reason naming the fact; audited (REQ-PE-005).
- Deleting a PE that packages use: refused in M2, naming them
  (REQ-IMG-015).
- Known-bad kit release: warning (REQ-PE-009).
- Digest mismatch later: not used; reported (REQ-PE-008).
- M3, on the device: network does not come up (REQ-PE-014); the product
  cannot be reached or authenticated (REQ-PE-015); content fails its
  check (REQ-PE-016); wrong firmware mode (REQ-PE-020); not enough memory
  (REQ-PE-018). Each shows a persistent error at the device
  (`specs/progress.md` REQ-JOB-005) and installs nothing further.
- M3, boot files incomplete or mismatched: refused; the boot service
  reports missing content (REQ-PE-012).

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
- Windows PE network boot and boot configuration (M3):
  `specs/standards/winpe-network-boot.md`.
- GPT and the Windows layout (M3): `specs/standards/gpt.md`.
- TLS and certificates (M3): `specs/standards/http-tls.md`,
  `specs/standards/security-baseline.md`.

## Later sections

- **Booting the environment** (M3) is now REQ-PE-011 to REQ-PE-020. The
  choice between boot files signed under the 2011 and 2023 Microsoft
  UEFI CAs (`winpe.md` §3; `uefi-secure-boot.md`) stays with
  OPEN-BOOT-SB.
- **Windows 11 Setup inside WinPE** needs the WMI and secure-startup
  optional components (`winpe.md` §4), if the install uses Setup. The M3
  flow applies the image directly (REQ-PE-017) and does not run Setup in
  WinPE.
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
  product needs for network boot of WinPE. M3: the file set is now known
  (`winpe-network-boot.md` §2) and is REQ-PE-012; the operator produces
  the boot configuration (DEC-0018 item 3, project rule).
- **OPEN-PE-7** (M3): beyond completeness, presence and integrity, what
  can the product check in an imported boot configuration whose format
  is not public? (No public format exists to parse against.)
- **OPEN-PE-3**: whether the product checks that an imported PE has
  Microsoft's security updates applied.
- **OPEN-PE-5** (M3): when one boot service offers packages that use
  different environments, which environment does a device boot before
  the person has chosen a package? (One environment per boot service,
  or a boot-time menu, or a restart after the choice.)
- **OPEN-PE-6** (M3): how the environment gets the trust anchor and the
  credential it needs for REQ-PE-015, given that nothing secret may be
  sent over PXE or TFTP (REQ-BOOT-043). Linked to REQ-PE-010 and D-3.
- **OPEN-WINPE-1** (`winpe.md` §5.1): whether `wpeinit` still runs when a
  replacement shell is configured.
- REQ-PE-010: see its Status line. REQ-PE-005 after M2:
  `specs/os-images.md` OPEN-IMG-F1.
