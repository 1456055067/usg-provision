# Supported operating systems (OS-1, image-content part for milestone M2)

Status: AUDITED, partial (spec run M2, 2026-10-26; re-audit round 1
approved; CR-511 applied in finalisation). REQ-OS-004 and REQ-OS-005
(M2) AUDITED 2026-10-27 after the decisions 0012-0015 check.
REQ-OS-011 (CR-516) AUDITED 2026-10-27 after the diff check, text
unchanged. OPEN: REQ-OS-003, 006, 010 (in part). REQ range in use:
`REQ-OS-001` to `REQ-OS-013`. Spec run M4 (2026-10-29) added
REQ-OS-012 (vendor text OPEN; project note AUDITED 2026-10-29, decision 0024:
Windows 11 only) and 013 (AUDITED 2026-10-29) for the install and refresh part.

## Purpose

The public sources describe a product that installs Windows 10 and
Windows 11 client operating systems. For M2 the question is narrower:
which Windows images the product accepts as package content, and how it
tells the operator when an image is not accepted.

By project decision DEC-0009 (owner, 2026-10-26; project design, not
described product behaviour), M2 accepts **Windows 11 Enterprise x64**
images only. Windows 10 images, other editions and other architectures
are refused with a clear reason, and the refusal is audited. Wider
support is a later decision.

## Actors and roles

- **Operator**: uploads images and builds packages (`specs/os-images.md`)
  and needs to know whether the image they chose can be deployed.
- **Product**: decides whether an image is in scope and says so.

## Facts from Microsoft relied on

From Microsoft's release-information pages (read 2026-10-26; SRC-064,
SRC-065), the ADK page (SRC-058), the Setup supported-platforms page
(SRC-066) and the processor architecture values (SRC-067):

- **Windows 11** current versions: 26H2 (available 2026-09-29), 26H1
  (2026-02-10; only for new devices, not offered as an in-place update),
  25H2 (2025-09-30), 24H2 (2024-10-01), 23H2 (2023-10-31). Feature updates
  get 36 months of support for Enterprise and Education editions and 24
  months for Home and Pro. Enterprise LTSC 2024 (version 24H2) has
  mainstream support to 2029-10-09. IoT Enterprise is not supported on
  26H1.
- **Windows 10** reached end of support on 2025-10-14. Paid Extended
  Security Updates exist for enrolled devices. Windows 10 Enterprise LTSC
  2021 has mainstream support to 2027-01-12, and LTSC 2019 extended
  support to 2029-01-09.
- **Architectures**: Windows 11 has no 32-bit version (ADK page). Windows
  11 26H1 is for Arm64 devices (ADK page). Image metadata identifies
  32-bit and 64-bit images with the values 0 and 9 (Setup supported
  platforms); Microsoft's processor architecture values are 0 x86, 9 x64,
  12 Arm64 (`specs/standards/wim.md` §7).
- A 32-bit Windows PE cannot deploy Windows 11 (`specs/standards/winpe.md`
  §2).

## Requirements

### REQ-OS-001: Windows 11 only in M2

In M2 the product accepts Windows 11 client installation images as
package content. It refuses Windows 10 images, and images of any other
Windows release, with a reason that says the release is not supported
(REQ-OS-005).

- Priority: MUST
- Source: SRC-004, SRC-005 (outcome only: the product targets Windows
  client operating systems)
- Basis: DEC-0009 (project decision, not described product behaviour)
- Standards: none
- Status: AUDITED

### REQ-OS-002: x64 only in M2

In M2 the product accepts only x64 Windows images. Images for any other
processor architecture are refused with a reason that names the
architecture (REQ-OS-005).

- Priority: MUST
- Source: none
- Basis: DEC-0009 (project decision, not described product behaviour)
- Standards: Microsoft processor architecture values
  (`specs/standards/wim.md` §7)
- Status: AUDITED

### REQ-OS-003: Other architectures in later milestones

Whether later milestones accept Arm64 Windows images is not settled.
In M2 they are refused (REQ-OS-002).

- Priority: SHOULD
- Source: SRC-004 (Arm support was added, without saying for which
  operating systems)
- Standards: none
- Status: OPEN (Are Arm64 Windows images in scope after M2, and when?
  Arm devices are INDEX BOOT-6, P3.)

### REQ-OS-004: Enterprise edition only in M2

In M2 the product accepts only the Windows 11 Enterprise edition. Images
of other editions (for example Home, Pro or Education) are refused with
a reason that names the edition (REQ-OS-005). In M2 only the plain
Enterprise edition counts: variants such as Enterprise LTSC and IoT
Enterprise are refused in the same way.

- Priority: MUST
- Source: none
- Basis: DEC-0009; the M2 refusal of Enterprise variants is DEC-0013
  item 3 (project decisions, not described product behaviour)
- Standards: none
- Status: AUDITED (whether Enterprise variants are accepted after M2
  is OPEN-OS-2)

### REQ-OS-005: Refuse out-of-scope images clearly

When the operator chooses an image (REQ-IMG-041) whose Windows release,
edition or architecture is outside REQ-OS-001, REQ-OS-002 and REQ-OS-004,
the product refuses the choice at that point, says plainly which of the
three is the problem, and does not let a package using the image become
ready. The refusal is recorded for audit (`specs/operator-access.md`
REQ-AUD-001).

In M2 the rule applies to the facts established under
`specs/os-images.md` REQ-IMG-043, whether they were read from the file
(verified) or only declared by the operator. Either kind can cause a
refusal, and only an image whose facts, declared and read, are all
within scope can make a package ready.

- Priority: MUST
- Source: SRC-004 (incompatible files are blocked when added, rather than
  failing later)
- Basis: DEC-0009 (refusal with a clear, audited error); DEC-0013 item 3
  (the scope applies to declared and read facts); project decisions, not
  described product behaviour; derived from REQ-IMG-022
- Standards: none
- Status: AUDITED (M2; how facts are learned after M2 is
  `specs/os-images.md` OPEN-IMG-F1)

### REQ-OS-006: Show what is supported

The operator can find out which Windows releases, editions and
architectures the product supports, without trial and error.

- Priority: SHOULD
- Source: none
- Standards: none
- Status: OPEN (How is the supported list presented, for example in
  documentation or in the operator interface? No public source says.)

### REQ-OS-007: Windows 10 is refused in M2

Windows 10 is past Microsoft's end of support, apart from LTSC releases
and devices enrolled in Extended Security Updates (SRC-065). In M2 every
Windows 10 image is refused, including LTSC images and images meant for
devices under Extended Security Updates (REQ-OS-001).

- Priority: MUST
- Source: SRC-065 (Windows 10 end of support, for context only)
- Basis: DEC-0009 (project decision, not described product behaviour)
- Standards: none
- Status: AUDITED (whether any Windows 10 image is accepted after M2 is a
  later decision)

### REQ-OS-008: No rule based on feature update

Within the scope of REQ-OS-001, REQ-OS-002 and REQ-OS-004, the product
does not accept or refuse an image because of which Windows 11 feature
update it holds. Images of older and newer feature updates are handled
on the same terms.

- Priority: SHOULD
- Source: SRC-064 (names and dates of Windows 11 releases only)
- Basis: project design, not described product behaviour: DEC-0009 sets
  the M2 scope by release family, edition and architecture, not by
  feature update
- Standards: none
- Status: AUDITED

### REQ-OS-009: Unknown support status blocks readiness in M2

In M2, when the product cannot tell whether an image is a Windows 11
Enterprise x64 image (REQ-IMG-043), it treats the image as not yet
supported: a package using that image cannot become ready. Only an
image known to be within REQ-OS-001, REQ-OS-002 and REQ-OS-004 can make
a package ready.

- Priority: MUST
- Source: none
- Basis: DEC-0009 (project decision, not described product behaviour:
  M2 accepts only images known to be Windows 11 Enterprise x64)
- Standards: none
- Status: AUDITED

### REQ-OS-010: Preinstall environment must suit the image

A package must not pair a Windows 11 image with a 32-bit preinstall
environment. The product warns the operator when a package's preinstall
environment comes from a Microsoft deployment kit older than the Windows
release in its image.

- Priority: MUST (32-bit pairing refused); SHOULD (age warning)
- Source: SRC-058 (32-bit WinPE cannot deploy Windows 11; use the kit
  matching the newest Windows version deployed)
- Standards: `specs/standards/winpe.md` §2
- Status: OPEN for the second sentence (for M2, REQ-PE-005 now says how
  the kit version is learned: declared and cross-checked, DEC-0013; not
  yet settled is whether a declared-only version is enough to warn on,
  and how kit versions are compared with Windows releases). In M2 the
  first sentence is also met by REQ-PE-005, which accepts only an x64
  PE.

### REQ-OS-011: When a fact counts as unknown in M2

In M2 a Windows release, edition or architecture fact of an image
counts as unknown for REQ-OS-009 only if the operator did not declare
it and the product did not read it from the file (`specs/os-images.md`
REQ-IMG-043). A fact that was declared but not read is not unknown; it
is judged against REQ-OS-001, REQ-OS-002 and REQ-OS-004 like a read
fact (REQ-OS-005).

- Priority: MUST
- Source: none
- Basis: derived from DEC-0013 items 1 to 3 (project decision, not
  described product behaviour)
- Standards: none
- Status: AUDITED (M2; how facts are learned after M2 is
  `specs/os-images.md` OPEN-IMG-F1)

### REQ-OS-012: Windows 10 and Windows 11 installs

The product installs both Windows 10 and Windows 11 client systems on
bare metal, and refreshes devices running them.

- Priority: MUST (product capability)
- Source: SRC-004 (bare-metal provisioning for Windows 10 and Windows
  11, with refresh, from the first cloud release in 2022)
- Standards: none
- Status: OPEN (for usg-provision: DEC-0009, REQ-OS-001 and REQ-OS-007
  still refuse Windows 10 images. Whether M4 accepts Windows 10, which
  Microsoft no longer supports except LTSC and Extended Security Updates
  (SRC-065), needs an owner decision.)
- Project note [project decision 0024] (AUDITED, owner 2026-10-30): the
  owner has decided. DEC-0009 stands: usg-provision installs and
  refreshes Windows 11 Enterprise x64 only, and Windows 10 images are
  still refused (REQ-OS-001, REQ-OS-007). The M4 lab exit covers
  Windows 11 only. The paragraph above remains the record of the
  product's public capability. For this project, only the Windows 11
  part applies.

### REQ-OS-013: One package, both install paths

A package that installs Windows on bare metal can also be used to
refresh a managed device, with the same drivers and configuration
(`specs/drivers.md` REQ-DRV-005, `specs/configuration.md` REQ-CFG-012).

- Priority: SHOULD
- Source: SRC-004 (packages can be deployed as refreshes; drivers and
  administrator password applied on refresh after fixes)
- Standards: none
- Status: AUDITED (refresh itself is RFR-1, P2, not specced; user-state
  migration during refresh is RFR-2)

## Later sections

- **Bare-metal install** (OS-1, install part): specced in M3 and M4 in
  `specs/disk.md`, `specs/preinstall-env.md`, `specs/workflow.md`,
  `specs/configuration.md`, `specs/drivers.md` and
  `specs/agent-handoff.md`.
- **Refresh of a managed Windows device** (RFR-1): not specced; see
  REQ-OS-013.
- **Windows 10, other editions and other architectures**: after M2, by
  later decision (DEC-0009).
- **Linux** (OS-2) and **cloud-hosted VMs** (OS-3).
- **Windows Server** (INDEX Unconfirmed).

## States and transitions

An image's support status is one of: *supported*, *not supported (with a
reason)*, or *unknown* (the product could not tell; REQ-IMG-043; what
counts as unknown in M2 is REQ-OS-011). A
not-supported image is refused (REQ-OS-005). An unknown image is held
back from readiness (REQ-OS-009). Only a supported image can make a
package ready.

## Limits

None beyond `specs/os-images.md`.

## Error behaviour

- Windows 10 or another release, another edition, or another
  architecture: refused when the image is chosen, with a reason naming
  the problem; the refusal is audited; the package cannot become ready
  (REQ-OS-005).
- 32-bit preinstall environment with a Windows 11 image: refused
  (REQ-OS-010).

## Security expectations

No security requirements specific to this area. Content integrity is in
`specs/os-images.md`. Refusals are audited (`specs/operator-access.md`).

## Standards relied on

- Microsoft Windows 10 and 11 release information (SRC-064, SRC-065).
- Microsoft Setup supported platforms and processor architecture values:
  `specs/standards/wim.md` §7.
- Microsoft ADK and WinPE: `specs/standards/winpe.md`.

## Out of scope / unknown

- REQ-OS-003, 006, 010: see each Status line.
- **OPEN-OS-1**: whether support after M2 is tied to Microsoft's
  servicing dates and is updated as Microsoft releases new Windows
  versions, and who decides.
- **OPEN-OS-2**: settled for M2 by DEC-0013 item 3: Windows 11
  Enterprise LTSC and IoT Enterprise images are refused (REQ-OS-004).
  Still open: whether they are accepted after M2.
