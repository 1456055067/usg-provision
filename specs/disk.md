# Target disk handling (DISK-1 for milestone M3)

Status: AUDITED (spec run M3, 2026-10-27; fix round 1, 2026-10-28;
re-audit rounds 1 and 2 approved with comments). AUDITED
2026-10-28: REQ-DISK-001 to 016 (002, 005, 006 and 016 settled by
DEC-0018 items 7 and 8, project rules; re-audit round 2). No REQ is
OPEN; OPEN-DISK-1 to 4 remain.
REQ range in use: `REQ-DISK-001` to `REQ-DISK-016`. DISK-2 (eMMC) is not
specced; numbers from `REQ-DISK-030` are kept for it and for legacy BIOS
layouts (BOOT-3).

## Purpose

During a bare-metal install the person at the device chooses the disk
Windows goes on. The product then removes everything on that disk and
writes a fresh partition layout suitable for Windows on UEFI firmware,
ready for the image to be applied (`specs/preinstall-env.md`
REQ-PE-017). This spec covers which disks may be chosen, what is
refused, what is shown and confirmed before the wipe, the wipe itself,
and the layout written.

M3 scope: UEFI firmware, GPT, Windows 11 Enterprise x64, one target disk.

## Actors and roles

- **Person at the device**: chooses the disk and confirms the wipe
  (`specs/targeting.md` REQ-TGT-005).
- **Provisioning environment**: lists disks, refuses unsuitable ones,
  wipes and partitions the chosen disk.
- **Operator**: sees which disk was chosen and the outcome
  (`specs/progress.md`).

## Definitions

- **Disk**: a whole storage device the provisioning environment can see
  as a block device (not a partition or volume).
- **Eligible disk**: a disk that may be offered for choice
  (REQ-DISK-002 to REQ-DISK-005).
- **Wipe**: removing all existing partitions and partition tables from
  the chosen disk so that no earlier volume is recognised afterwards
  (REQ-DISK-007).
- **Windows layout**: the partition layout in REQ-DISK-008.

## Requirements

### Choosing the disk

### REQ-DISK-001: List the disks and let the person choose

The device lists every eligible disk and the person chooses one. Each
entry shows enough to tell disks apart and recognise them: at least the
capacity, the model or product name the disk reports, the bus or
connection type, and whether it holds existing partitions. Ineligible
disks are not choosable; they are either left out or shown with the
reason they cannot be used.

- Priority: MUST (choice); SHOULD (items shown)
- Source: SRC-001 (the person at the device selects the disk)
- Basis: the items shown are derived
- Standards: none
- Status: AUDITED (2026-10-28)

### REQ-DISK-002: One or several eligible disks [project rule]

When there are several eligible disks the device preselects none of
them; the person must pick one. When exactly one is eligible, it is
still shown to the person, who must confirm it; it is never used
without that confirmation (REQ-DISK-006).

- Priority: MUST
- Source: SRC-001 (the person selects the disk)
- Basis: DEC-0018 item 8 (a single eligible disk is still shown for
  confirmation; project rule, not described product behaviour); "no
  preselection with several disks" is project design
- Standards: none
- Status: AUDITED (2026-10-28; settled by DEC-0018 item 8)

### REQ-DISK-003: No eligible disk

If no disk is eligible, the device says so, says whether disks were seen
but refused (with each reason) or none were seen at all, notes that a
storage driver may be missing from the environment, changes nothing,
and reports the failure to the operator (`specs/progress.md`
REQ-JOB-006).

- Priority: MUST
- Source: SRC-004, SRC-006 (outcome only: some storage needs a driver
  before its disks are visible)
- Basis: the message content is derived
- Standards: `specs/standards/winpe.md` §4 (drivers are added to the
  environment image)
- Status: AUDITED (2026-10-28)

### REQ-DISK-004: Disk too small

A disk smaller than the minimum is not eligible. The minimum is at least
Microsoft's stated minimum storage for the target Windows (64 GB for
Windows 11) and never less than the size of the Windows layout
(REQ-DISK-008) plus the expanded size of the chosen image. The device
shows the disk's size and the minimum.

- Priority: MUST
- Source: SRC-099 (Windows 11 needs 64 GB of storage); SRC-084 (Windows
  partition at least 20 GB for 64-bit, plus system, reserved and
  recovery partitions)
- Basis: refusing is derived from Microsoft's minimums; no vendor source
  describes the refusal
- Standards: `specs/standards/gpt.md` §10, §13
- Status: AUDITED (2026-10-28; whether an operator may lower the minimum is
  OPEN-DISK-1)

### REQ-DISK-005: Removable disks and the boot media disk [project rule]

A disk the environment reports as removable media, and any disk that
carries the boot environment itself, are not eligible. They are refused
with the reason shown (REQ-DISK-001).

- Priority: MUST
- Source: none (no public source describes this refusal)
- Basis: DEC-0018 item 8 (removable disks and the disk carrying the boot
  environment are refused; project rule, not described product
  behaviour); showing the reason is project design; Microsoft
  distinguishes removable media from fixed disks (SRC-085) and WinPE
  reports where it booted from (SRC-096)
- Standards: `specs/standards/gpt.md` §11, §12; `specs/standards/
  winpe.md` §5.3
- Status: AUDITED (2026-10-28; settled by DEC-0018 item 8.
  Whether a USB-attached disk that reports itself as fixed is eligible
  is OPEN-DISK-4. For network boot the second clause rarely applies; it
  matters for boot media, MEDIA-1.)

### Before the wipe

### REQ-DISK-006: Show and confirm before wiping [project rule]

Before anything is written to the chosen disk, the device shows: the
disk's identity as in REQ-DISK-001; that every partition and all data on
it will be destroyed; and the existing partitions it holds, with their
sizes and any volume labels it can read. The wipe starts only after the
person explicitly confirms, with an action distinct from the one used to
choose the disk. In release R1 no mode skips this confirmation.
Declining returns to the disk choice or cancels (`specs/targeting.md`
REQ-TGT-010). The person's authorisation of the wipe is durably
recorded as an audit record before anything is written to the disk; if
it cannot be recorded, nothing is written.

- Priority: MUST
- Source: SRC-087 (Microsoft's reference deployment flow warns that all
  data on the disk will be deleted and asks for confirmation before
  erasing)
- Basis: DEC-0018 item 7 (explicit wipe confirmation, mandatory and
  separate from disk selection, never skipped in release R1, durably
  recorded before any write; project rule, not described product
  behaviour); no vendor source describes the confirmation screen
- Standards: `specs/standards/gpt.md` §10
- Status: AUDITED (2026-10-28; settled by DEC-0018 item 7)

### REQ-DISK-007: Wipe the chosen disk

After confirmation the environment removes all partitions on the chosen
disk and wipes them so that no earlier partition table or volume is
recognised afterwards: both copies of any earlier GPT and any earlier
MBR are destroyed before the new layout is written, and the new volumes
are formatted fresh. Only the chosen disk is touched.

- Priority: MUST
- Source: SRC-004 (outcome only: existing partitions are wiped);
  SRC-087 (Microsoft's sample clears the disk before creating
  partitions)
- Standards: `specs/standards/gpt.md` §2, §7, §10
- Status: AUDITED (2026-10-28; how much of the old data is overwritten is
  OPEN-DISK-2; a secure multi-pass wipe is RET-1, not part of install)

### The layout written (UEFI)

### REQ-DISK-008: Windows layout on UEFI

The chosen disk gets a GPT with a protective MBR and, in this order:

1. an EFI system partition, FAT32, 200 MB on disks with 512-byte logical
   sectors (native or emulated) and 300 MB on 4K-native disks;
2. a Microsoft reserved partition of 16 MB, unformatted;
3. the Windows partition, NTFS, taking the remaining space less the
   recovery partition;
4. a recovery partition immediately after the Windows partition, NTFS,
   with the Microsoft recovery type and the platform-required and
   no-drive-letter attributes, sized for the recovery image of the chosen
   Windows plus at least 250 MB free (Microsoft recommends at least
   990 MB in total for this way of partitioning).

Each partition has the type Microsoft documents for it. No other
partitions are created.

- Priority: MUST (items 1 to 3); SHOULD (item 4)
- Source: SRC-084, SRC-085, SRC-086, SRC-087 (Microsoft's recommended
  layout, types, sizes, attributes); SRC-004, SRC-001 (outcome only: the
  product partitions the chosen disk)
- Basis: the vendor sources do not say which layout the product writes;
  this is Microsoft's recommended default
- Standards: `specs/standards/gpt.md` §9, §10, §11
- Status: AUDITED (2026-10-28; whether the recovery environment is also
  configured is OPEN-DISK-3)

### REQ-DISK-009: GPT written correctly

The GPT written has valid primary and backup headers and partition entry
arrays with correct CRCs, a protective MBR as UEFI defines it, a new
random disk GUID, a new random GUID for every partition, all partitions
inside the usable range and not overlapping, and an entry array of at
least 16,384 bytes. After writing, the environment reads the table back
and checks it before formatting.

- Priority: MUST
- Source: SRC-080 (UEFI GPT rules); SRC-085 (GUIDs must be unique; never
  copy them)
- Basis: the read-back check before formatting is project design
- Standards: `specs/standards/gpt.md` §3 to §7
- Status: AUDITED (2026-10-28; CRC parameters: OPEN-GPT-1 in `gpt.md`)

### REQ-DISK-010: Alignment

Every partition starts on a 1 MiB boundary.

- Priority: MUST
- Source: SRC-080 (UEFI recommends 1 MiB alignment to avoid detecting
  physical block and transfer sizes)
- Standards: `specs/standards/gpt.md` §8
- Status: AUDITED (2026-10-28)

### REQ-DISK-011: UEFI mode only

The disk is partitioned only if the environment booted in UEFI mode. If
it booted in legacy BIOS mode, the device refuses before the wipe, says
that the firmware must boot in UEFI mode for this package, and reports
it to the operator.

- Priority: MUST
- Source: SRC-057 (WinPE must boot in the mode the installed Windows
  will use); SRC-084 (UEFI devices need GPT for the Windows drive);
  SRC-096 (WinPE reports its firmware mode)
- Basis: M3 scope (UEFI only) from DEC-0004 and DEC-0009; BIOS layouts
  are BOOT-3
- Standards: `specs/standards/winpe.md` §5.3, §6; `specs/standards/
  gpt.md` §10
- Status: AUDITED (2026-10-28)

### During and after partitioning

### REQ-DISK-012: Partitioning does not depend on the network

Wiping and partitioning work with local operations only. A loss of
network connection while they run does not by itself make them fail; the
step completes and the job then reports or retries the network problem
(`specs/progress.md` REQ-JOB-007).

- Priority: SHOULD
- Source: SRC-004, SRC-006 (outcome only: a network drop during
  partitioning does not fail the install)
- Standards: none
- Status: AUDITED (2026-10-28)

### REQ-DISK-013: Failure while partitioning

If the wipe, partitioning or formatting fails, the job stops, the device
shows a persistent error naming the step and the disk
(`specs/progress.md` REQ-JOB-005), and the operator sees it. The device
does not go on to apply the image.

- Priority: MUST
- Source: SRC-004 (download-error behaviour only)
- Basis: derived by analogy; project design
- Standards: none
- Status: AUDITED (2026-10-28)

### REQ-DISK-014: Disk choice is reported

The operator view of the job shows the disk chosen (identity as in
REQ-DISK-001) and the layout written.

- Priority: SHOULD
- Source: SRC-002 (outcome only: deployments can be tracked)
- Basis: items shown are derived
- Standards: none
- Status: AUDITED (2026-10-28)

### REQ-DISK-015: Only one disk is changed

No disk other than the chosen one is written to at any point of the
install, including disks that hold earlier operating systems or data.

- Priority: MUST
- Source: SRC-001 (the person selects the disk to install to; outcome)
- Basis: derived
- Standards: none
- Status: AUDITED (2026-10-28)

### REQ-DISK-016: Existing contents are not read out [project rule]

The environment reads only what it needs to describe the disk
(REQ-DISK-001, REQ-DISK-006). It does not copy or send any file content
from existing partitions to the product.

- Priority: MUST
- Source: none (project security requirement; no vendor source)
- Basis: DEC-0018 item 8 (the product never reads out existing disk
  contents; project rule, not described product behaviour)
- Standards: none
- Status: AUDITED (2026-10-28; settled by DEC-0018 item 8)

## States and transitions (target disk)

*Listed* (REQ-DISK-001) → *Chosen* → *Confirmed* (REQ-DISK-006) →
*Wiping* (REQ-DISK-007) → *Partitioning* (REQ-DISK-008 to 010) →
*Formatted* → handed to image apply (`specs/preinstall-env.md`
REQ-PE-017). Any failure goes to *Failed* (REQ-DISK-013). Before
*Confirmed* the person can go back or cancel; after *Wiping* starts the
disk's earlier contents are gone.

## Limits

- Minimum disk size: REQ-DISK-004 (at least 64 GB for Windows 11).
- At most 128 partitions on a GPT disk in Windows; the layout uses four
  (`gpt.md` §10).
- ESP 200 MB (300 MB on 4K-native); MSR 16 MB; recovery at least the
  recovery image plus 250 MB (990 MB recommended).
- One target disk per install.

## Error behaviour

- No eligible disk: REQ-DISK-003.
- Too small, removable, boot media: not eligible, reason shown
  (REQ-DISK-004, REQ-DISK-005).
- Booted in BIOS mode: refused before the wipe (REQ-DISK-011).
- Wipe, partition or format fails: REQ-DISK-013.
- Read-back check of the GPT fails: as REQ-DISK-013.

## Security expectations

- Destructive action needs an explicit, separate confirmation at the
  device, recorded before any write (REQ-DISK-006), and touches only the
  chosen disk (REQ-DISK-015).
- Existing data is not exfiltrated (REQ-DISK-016).
- Disk-level encryption of the new install (BitLocker) and secure
  sanitisation are out of scope (INDEX Unconfirmed; RET-1).

## Standards relied on

- UEFI 2.10 chapter 5 and Microsoft's UEFI/GPT partition guidance:
  `specs/standards/gpt.md`.
- WinPE firmware mode and drivers: `specs/standards/winpe.md`.

## Out of scope / unknown

- DISK-2 (eMMC targets), legacy BIOS/MBR layouts (BOOT-3), multi-disk or
  RAID layouts, data partitions, BitLocker.
- **OPEN-DISK-1**: may an operator set a different minimum disk size (for
  example per package)?
- **OPEN-DISK-2**: how much of the old disk is overwritten during the
  install wipe (partition structures only, or more)? The public source
  says only that partitions are wiped, not just removed.
- **OPEN-DISK-3**: is the Windows recovery environment placed in and
  registered for the recovery partition (Microsoft's samples do this
  from the applied Windows), or is the partition only created?
- **OPEN-DISK-4**: is a USB-attached disk that reports itself as fixed
  (not removable) eligible? DEC-0018 item 8 covers removable disks and
  the boot-environment disk only.
- REQ-DISK-002, 005, 006 and 016 are settled by DEC-0018 items 7 and 8
  (project rules).
