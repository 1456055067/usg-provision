# Install workflow (SEQ-1)

Status: AUDITED (spec run M4, 2026-10-29; clean-room audit 2026-10-29, OPEN items remain OPEN). REQ
range in use: `REQ-SEQ-001` to `REQ-SEQ-008`. SEQ-2 (custom scripts),
SEQ-3 (optional reboots, web-service calls) and SEQ-4 (confirmation code)
are not specced.

## Purpose

Once the person at the device has chosen a package and a disk
(`specs/targeting.md`), the install runs by itself, in a fixed order,
until Windows is ready for its user to log on and the device is a
managed endpoint.

## Actors and roles

- **Person at the device**: starts the install; after that, no input.
- **Operator**: watches progress (`specs/progress.md`).
- **Product**: runs the steps in order and enforces time limits.

## Requirements

### REQ-SEQ-001: Automatic from choice to logon-ready

After the package and disk are chosen and confirmed, the install runs
to the end without further input at the device.

- Priority: MUST
- Source: SRC-001 (boot, pick package and disk, let the build finish,
  device ready to use), SRC-009 (the rest runs automatically)
- Standards: none
- Status: AUDITED

### REQ-SEQ-002: Order of steps

The install runs these steps in this order. Each starts only after the
one before it succeeded:

1. download and verify all content for the package
   (`specs/preinstall-env.md` REQ-PE-016);
2. prepare the disk (`specs/disk.md`);
3. apply the image (REQ-PE-017);
4. add the package's drivers to the installed Windows
   (`specs/drivers.md` REQ-DRV-004);
5. place the resolved configuration for Windows to use
   (`specs/configuration.md` REQ-CFG-003);
6. make the installed Windows the next boot target and restart into it
   (`specs/boot-network.md` REQ-BOOT-065);
7. Windows completes its own first-start configuration
   (`specs/standards/unattend.md` §1.1);
8. install the management agent (`specs/agent-handoff.md`);
9. report the device ready (logon-ready, REQ-SEQ-006).

- Priority: MUST
- Source: SRC-009 (all content downloaded first, the rest runs from the
  local copy; domain join and agent install are part of the process),
  SRC-001 (outcome only: the order boot, choose, build, ready)
- Basis: steps 2 to 7 follow the open Windows mechanism (topics 10 and
  12) and the M3 specs; the exact order within steps 4 to 8 is project
  design, not a vendor statement
- Standards: `specs/standards/unattend.md` §1, `offline-drivers.md` §6
- Status: AUDITED

### REQ-SEQ-003: Tolerates join and account setup finishing early

The install does not fail when domain join or local administrator
account setup finishes before the management agent is installed.

- Priority: MUST
- Source: SRC-004, SRC-006 (a fix for installs that failed in that case)
- Standards: none
- Status: AUDITED

### REQ-SEQ-004: Every step has a time limit

Each step has a time limit. A step that runs past it stops the install
with a persistent error naming the step (`specs/progress.md`).

- Priority: MUST
- Source: SRC-004, SRC-006 (install time limits exist and were raised
  for stability)
- Standards: none
- Status: AUDITED. Values are OPEN-SEQ-1.

### REQ-SEQ-005: Generous limits

Time limits allow for long-running steps lasting hours. For commands run
during a refresh the default limit is 3 hours.

- Priority: MUST
- Source: SRC-004 (refresh command default raised from 1 to 3 hours;
  long-running steps), SRC-006 (install time limits raised)
- Standards: none
- Status: AUDITED. Bare-metal step limits are OPEN-SEQ-1.

### REQ-SEQ-006: What logon-ready means

The install is complete when the installed Windows has finished its
first-start configuration and shows its logon screen, and the
management agent is installed (REQ-AGT-001). Only then is the job
reported successful.

- Priority: MUST
- Source: SRC-001 (device ready to use at the end), SRC-009 (fully
  managed at the end)
- Basis: the observable test (logon screen reached) is project design
- Standards: `specs/standards/unattend.md` §1.1, §5
- Status: AUDITED. How the product observes this is OPEN-SEQ-2.

### REQ-SEQ-007: Progress and audit of steps

Each step's start, end and outcome are reported as progress and recorded
for audit.

- Priority: MUST
- Source: SRC-002 (operators track deployment status; outcome only)
- Basis: DEC-0018 item 10 (every job state change audited), project rule
- Standards: none
- Status: AUDITED

### REQ-SEQ-008: Stop on error

When a step fails, later steps do not run. The device is not reported
ready.

- Priority: MUST
- Source: SRC-004 (imaging stops after a download error; outcome
  extended to all steps)
- Basis: extension to all steps is project design
- Standards: none
- Status: AUDITED

## States and transitions

Steps are *waiting*, *running*, *succeeded*, *failed* or *timed out*. A
failed or timed-out step ends the job with a persistent error
(`specs/progress.md`, REQ-JOB-012). Cancelling follows DEC-0018 item 10
(only before the wipe confirmation).

## Limits

Step limits: OPEN-SEQ-1; refresh commands 3 hours by default
(REQ-SEQ-005).

## Error behaviour

REQ-SEQ-004, REQ-SEQ-008.

## Security expectations

No secret appears in progress or step reports (DEC-0011).

## Standards relied on

`specs/standards/unattend.md`, `specs/standards/offline-drivers.md`.

## Out of scope / unknown

- SEQ-2 to SEQ-4.
- **OPEN-SEQ-1**: time limit values per step for bare-metal installs.
- **OPEN-SEQ-2**: how the product learns the device reached logon-ready
  (after the restart, the preinstall agent is no longer running).
