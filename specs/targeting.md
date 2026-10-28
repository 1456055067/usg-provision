# Targeting at the device (TGT-1 for milestone M3)

Status: AUDITED, partial (spec run M3, 2026-10-27; fix rounds 1 and 2,
2026-10-28; re-audit rounds 1 and 2 approved with comments). AUDITED
2026-10-28: REQ-TGT-001 to 006, 008 to 016 (006, 010, 011 and 016
settled by DEC-0018 items 7 and 10, project rules). OPEN: 007.
REQ range in use: `REQ-TGT-001` to `REQ-TGT-016`. TGT-2 to TGT-4
(refresh targeting, serial number, targeting restrictions) are not
specced; numbers from `REQ-TGT-020` are kept for them.

## Purpose

A bare-metal device has no record in the product before it boots. For
such devices the operator decides **which deployment packages a boot
service may offer**, and the person standing at the device chooses one
of them and the disk to install to. This spec covers what that person
sees and chooses after the provisioning environment has started on the
device, which packages are offered, what happens when there is nothing
to offer, cancelling, and whether the device's session must be
authorised before packages are shown or secrets are sent.

It starts when the provisioning environment on the device has connected
back to the product (`specs/preinstall-env.md` REQ-PE-015) and ends when
the person has confirmed a package and a disk and the install begins.
Disk choice details are in `specs/disk.md`; progress in
`specs/progress.md`.

M3 scope: one wired, network-booted UEFI x64 device; Windows 11
Enterprise x64 packages (`specs/os-support.md`, DEC-0009).

## Actors and roles

- **Operator**: makes deployment packages available on a boot service and
  sets any secret that the device session needs.
- **Person at the device** (technician): has physical access, starts the
  network boot (`specs/boot-network.md` "Actors"), and makes the choices
  below. Not assumed to be an authenticated operator of the product.
- **Provisioning environment**: the operator's Windows PE with the
  product's program running in it (`specs/preinstall-env.md`).
- **Boot service** and **product**: as in `specs/boot-network.md`.

## Definitions

- **Offered package**: a deployment package (`specs/os-images.md`
  REQ-IMG-001) that the operator has made available on the boot service
  that answered the device, and that is ready (REQ-IMG-020).
- **Device session**: one run of the provisioning environment on one
  device, from connect-back until the install starts, is cancelled, or
  fails.

## Requirements

### Which packages are offered

### REQ-TGT-001: Operator makes packages available per boot service

An operator chooses which deployment packages each boot service makes
available to devices it boots. A device booted from that boot service is
offered only those packages, never packages made available only on other
boot services.

- Priority: MUST
- Source: SRC-001 (outcome only: packages are made available to a boot
  service in advance); SRC-004 (outcome only: the operator is told when
  a boot service lacks packages)
- Standards: none
- Status: AUDITED (2026-10-28)

### REQ-TGT-002: Only usable packages are offered

A package is offered only while it is ready and all the content it needs
is ready and passes its integrity check (`specs/os-images.md`
REQ-IMG-020, REQ-IMG-050). A package that is being processed, failed,
or refers to missing or damaged content is not offered.

- Priority: MUST
- Source: SRC-004 (outcome only: content is integrity-checked before
  use)
- Basis: derived from REQ-IMG-020 and REQ-IMG-050 (project design for
  the filtering)
- Standards: none
- Status: AUDITED (2026-10-28)

### REQ-TGT-003: Only packages the device can run are offered

A package is offered only if it matches the device's firmware mode and
processor architecture as the provisioning environment reports them. In
M3 that means UEFI on x64 only, matching the M3 image and environment
scope.

- Priority: MUST
- Source: SRC-057 (WinPE must boot in the firmware mode the installed
  Windows will use; via `winpe.md` §6)
- Basis: project design derived from DEC-0009 and REQ-BOOT-003,
  REQ-PE-005; not described product behaviour
- Standards: `specs/standards/winpe.md` §5.3, §6
- Status: AUDITED (2026-10-28)

### What the person at the device sees and chooses

### REQ-TGT-004: Choose one package

The device shows the list of offered packages and the person picks
exactly one. For each package the list shows at least the name and
description the operator gave it (`specs/os-images.md` REQ-IMG-010) and
the operating system it installs, so that packages can be told apart.

- Priority: MUST (choice); SHOULD (items shown)
- Source: SRC-001 (the person at the device selects a package)
- Basis: the items shown are derived
- Standards: none
- Status: AUDITED (2026-10-28)

### REQ-TGT-005: Choose the target disk

After choosing a package, the person chooses the disk to install to, as
`specs/disk.md` REQ-DISK-001 to REQ-DISK-006 describe.

- Priority: MUST
- Source: SRC-001 (the person at the device selects a disk)
- Standards: `specs/standards/gpt.md`
- Status: AUDITED (2026-10-28)

### REQ-TGT-006: Review before starting [project rule]

Before anything on the disk is changed, the device shows a summary of the
choices (package, operating system, target disk) and the install starts
only when the person confirms it. This summary is shown with the
mandatory wipe confirmation of `specs/disk.md` REQ-DISK-006, which is
separate from choosing the disk and which, in release R1, no mode skips.

- Priority: MUST (shown with the mandatory wipe confirmation)
- Source: SRC-087 (Microsoft's reference deployment flow warns and asks
  for confirmation before erasing)
- Basis: DEC-0018 item 7 (mandatory, separate wipe confirmation; project
  rule, not described product behaviour); the summary's content
  (package, operating system, disk) is project design; no vendor source
  describes a review step
- Standards: `specs/standards/gpt.md` §10
- Status: AUDITED (2026-10-28; settled by DEC-0018 item 7)

### REQ-TGT-007: Exactly one package offered

When exactly one package is offered, whether the device still asks the
person to choose it or proceeds with it is not settled.

- Priority: SHOULD
- Source: SRC-004 (outcome only: an operator-configurable mode needing no
  input at the device exists; not publicly defined)
- Standards: none
- Status: OPEN (Is the single package chosen automatically? Relates to
  installs needing no input at the device, INDEX Unconfirmed.
  Authorisation still applies, REQ-TGT-013, REQ-TGT-014, and in release
  R1 the wipe confirmation is never skipped, `specs/disk.md`
  REQ-DISK-006, DEC-0018 item 7.)

### When nothing can be offered

### REQ-TGT-008: No package offered

If the boot service has no offered package for the device, the device
shows a clear message that no deployment is available from this boot
service, changes nothing on any disk, and lets the person restart or
shut down the device. The operator is told that the boot service has no
usable package, as for missing content in `specs/boot-network.md`
REQ-BOOT-052.

- Priority: MUST
- Source: SRC-004 (outcome only: the operator is told when a boot service
  lacks packages it needs)
- Basis: the device-side message is derived
- Standards: none
- Status: AUDITED (2026-10-28)

### REQ-TGT-009: No usable disk

If the device has no disk that may be chosen (`specs/disk.md`
REQ-DISK-003), the device says so before any package is applied,
changes nothing, and lets the person restart or shut down.

- Priority: MUST
- Source: SRC-004, SRC-006 (outcome only: some storage needs a driver
  before the environment can see it)
- Basis: derived
- Standards: none
- Status: AUDITED (2026-10-28)

### Cancelling

### REQ-TGT-010: Cancel before anything is written [project rule]

Until the person confirms the wipe (`specs/disk.md` REQ-DISK-006), they
can cancel at any point. Cancelling changes nothing on any disk, ends
the device session, is recorded as a cancelled session (an audit record,
REQ-TGT-016), and lets the person restart or shut down.

- Priority: MUST
- Source: none (no public source describes cancelling)
- Basis: DEC-0018 item 10 (cancel allowed at any point before the wipe
  confirmation; project rule, not described product behaviour)
- Standards: none
- Status: AUDITED (2026-10-28; settled by DEC-0018 item 10)

### REQ-TGT-011: No cancelling after the wipe confirmation [project rule]

Once the person has confirmed the wipe, the install cannot be cancelled,
from the device or from the operator view. The job runs until it
succeeds or stops with a persistent error (`specs/progress.md`
REQ-JOB-005, REQ-JOB-006).

- Priority: MUST
- Source: none
- Basis: DEC-0018 item 10 (after the wipe the job runs to success or a
  persistent error; project rule, not described product behaviour)
- Standards: none
- Status: AUDITED (2026-10-28; settled by DEC-0018 item 10)

### Authorising the device session (DEC-0018 item 1)

### REQ-TGT-012: Mutual authentication before any choice

Before the device shows any package or receives any configuration, the
provisioning environment and the product authenticate each other over
the protected channel of `specs/preinstall-env.md` REQ-PE-015. The
device checks the product's identity against trust anchors it already
holds; the product accepts only sessions that authenticate as a
provisioning environment it trusts. A session that fails either check
gets nothing and is recorded.

- Priority: MUST
- Source: SRC-004 (outcome only: the device's environment and the
  product authenticate each other)
- Basis: the trust-anchor check and recording are project design
- Standards: `specs/standards/http-tls.md` §6; `specs/standards/
  security-baseline.md` §2
- Status: AUDITED (2026-10-28; what credential the environment presents is a
  clean-side design; the PXE phase itself carries no secrets,
  REQ-BOOT-043)

### REQ-TGT-013: Session authorised by operator-issued code [project rule]

A bare-metal device session goes no further than REQ-TGT-012 until it is
authorised. One way to authorise it is for the person at the device to
enter a short-lived, single-use code that an operator has issued.
Authorisation is required by default: either this code or the operator
approval in REQ-TGT-014 must succeed before packages are listed or any
secret is sent (REQ-TGT-015). A wrong, expired or already-used code is
refused. Issuing a code, using it, approving a device and refusing a
device or a code are each audit records, without the code value
(`specs/operator-access.md` REQ-AUD-001). Wider auditing of device-side
choices stays OPEN in REQ-TGT-016.

- Priority: MUST
- Source: SRC-004, SRC-006 (outcome only: operator-set secrets and an
  optional code entered at the device exist; where each is entered is
  not stated)
- Basis: DEC-0018 item 1 (short-lived, single-use code or operator
  approval; on by default; issue, use, approval and refusal audited;
  project rule, not described product behaviour)
- Standards: `specs/standards/security-baseline.md` §4.2
- Status: AUDITED (2026-10-28; code length, lifetime and the limit on
  failed attempts are clean-side design, OPEN-TGT-2)

### REQ-TGT-014: Device session authorised by operator approval [project rule]

The other way to authorise a session is for an operator to approve the
waiting device in the product, after seeing its identity (as recorded
in REQ-TGT-016). Until an operator approves it, the device shows that it
is waiting for approval and lists no packages. An operator can also
refuse it.

- Priority: MUST
- Source: none (no public source describes operator approval)
- Basis: DEC-0018 item 1 (project rule, not described product
  behaviour)
- Standards: none
- Status: AUDITED (2026-10-28; how long a device may wait is
  OPEN-TGT-1)

### REQ-TGT-015: No secrets before the session is authorised

No secret that a package carries (for example a local administrator
password or directory-join material) is sent to the device until the
session has passed REQ-TGT-012 and the required authorisation, an
operator-issued code or operator approval (REQ-TGT-013, REQ-TGT-014).
Secrets are then sent only over the protected channel, only for the
package chosen, and are never shown on
the device's screen.

- Priority: MUST
- Source: SRC-004 (outcome only: secrets for a deployment are
  protected); SRC-009 (outcome only: no join credentials are typed at
  the device)
- Basis: DEC-0011 (secrets over protected channels); REQ-BOOT-043
- Standards: `specs/standards/http-tls.md` §6
- Status: AUDITED (2026-10-28)

### Record

### REQ-TGT-016: Device-session choices are audit records [project rule]

The product records, as audit records (`specs/operator-access.md`
REQ-AUD-001), for each device session: the boot service, the device's
network hardware address and machine identifier
(`specs/boot-network.md` REQ-BOOT-007), whether authentication and the
required authorisation succeeded, the package and disk chosen, the wipe
confirmation, and the outcome (started, cancelled, failed). Failed code
attempts are recorded without the value entered. Job state changes are
audit records too (`specs/progress.md` REQ-JOB-012).

- Priority: MUST
- Source: none (no public source for a record of device-side choices)
- Basis: DEC-0018 item 10 (device-side choices and every job state
  change are audit records) and item 7 (the wipe confirmation is
  durably recorded before any write); project rules, not described
  product behaviour
- Standards: none
- Status: AUDITED (2026-10-28; settled by DEC-0018 items 7 and 10)

## States and transitions (device session)

1. *Connecting*: the environment has started and is reaching the
   product (REQ-PE-014, REQ-PE-015). Failure goes to *Failed*.
2. *Authenticating*: REQ-TGT-012, then the required authorisation, an
   operator-issued code or operator approval (REQ-TGT-013,
   REQ-TGT-014). Failure goes to *Refused*.
3. *Choosing package*: REQ-TGT-004. With no offered package, goes to
   *Nothing to offer* (REQ-TGT-008).
4. *Choosing disk*: REQ-TGT-005. With no usable disk, goes to *No disk*
   (REQ-TGT-009).
5. *Confirming*: REQ-TGT-006, REQ-DISK-006. Confirm goes to *Started*
   and the job of `specs/progress.md` begins.
6. Before the wipe is confirmed the person can cancel: *Cancelled*
   (REQ-TGT-010). After it, no cancel (REQ-TGT-011).

*Refused*, *Nothing to offer*, *No disk*, *Cancelled* and *Failed* end
the session with nothing written to disk.

## Limits

- The public sources give no limit on how many packages a boot service
  may offer or how many device sessions may run at once
  (`specs/boot-network.md` OPEN-BOOT-L1 covers the boot phase).
- No timeout for a device left waiting at a choice is stated
  (OPEN-TGT-1).

## Error behaviour

- Product unreachable: shown at the device (`specs/progress.md`
  REQ-JOB-005).
- Authentication fails: nothing is shown or sent; the device says it
  could not establish a trusted session; recorded (REQ-TGT-012,
  REQ-TGT-016).
- Wrong, expired or used operator-issued code, or approval refused:
  refused; audited without the code value (REQ-TGT-013, REQ-TGT-014).
- Nothing to offer, no disk: REQ-TGT-008, REQ-TGT-009.

## Security expectations

- The boot network is unauthenticated (`specs/boot-network.md`
  REQ-BOOT-043, REQ-BOOT-045). Anyone on the segment can boot the
  environment. The authorisation gate is therefore REQ-TGT-012 plus an
  operator-issued code or operator approval (REQ-TGT-013, REQ-TGT-014;
  DEC-0018 item 1, project rule).
- Physical access to the device alone is not enough to obtain a
  package's secrets (REQ-TGT-013 to REQ-TGT-015).
- The device shows no secret values (REQ-TGT-015).

## Standards relied on

- `specs/standards/http-tls.md`, `specs/standards/security-baseline.md`
  (protected channel and authentication).
- `specs/standards/winpe.md` §5.3, §6 (firmware mode).
- `specs/standards/gpt.md` §10 (Microsoft's confirm-before-erase
  practice).

## Out of scope / unknown

- TGT-2 (refresh targeting), TGT-3 (serial number in device identity),
  TGT-4 (targeting restrictions): not specced.
- Pre-registering devices and installs needing no input at the device
  (INDEX Unconfirmed; REQ-TGT-007).
- Per-device prompts for computer name and other values (CFG-3, CFG-4).
- Wi-Fi and network choice at the device (PE-2, MEDIA-2).
- D-3 is settled by DEC-0018 item 1 (REQ-TGT-013, REQ-TGT-014; project
  rule).
- **OPEN-TGT-1**: does a device left at a choice screen, or waiting for
  approval, time out, and what happens then?
- **OPEN-TGT-2**: length and lifetime of the operator-issued code and the
  limit on failed attempts (clean-side design).
- REQ-TGT-007: see its Status line. REQ-TGT-006, 010, 011 and 016 are
  settled by DEC-0018 items 7 and 10 (project rules).
