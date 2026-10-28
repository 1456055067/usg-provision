# Deployment progress and errors (JOB-1 for milestone M3)

Status: AUDITED, partial (spec run M3, 2026-10-27; fix round 1,
2026-10-28; re-audit round 1 approved with comments). AUDITED
2026-10-28: REQ-JOB-001 to 009, 011 to 015. OPEN: 010.
REQ range in use: `REQ-JOB-001` to `REQ-JOB-015`. JOB-2 to JOB-4
(overview metrics, log collection, event forwarding) are not specced;
numbers from `REQ-JOB-020` are kept for them.

## Purpose

Once the person at a device has started an install
(`specs/targeting.md`), the operator and the person at the device both
need to know how it is going: which step it is on, how far a download
has got, and, if something fails, exactly what failed, in a way that
does not disappear. This spec covers what each of them sees, how
failures are presented and how long they persist, and retry behaviour.

M3 scope: one bare-metal network-booted install at a time per device.

## Actors and roles

- **Operator**: watches jobs in the product.
- **Person at the device**: watches the device's screen.
- **Provisioning environment** and **product**: report and record
  progress.

## Definitions

- **Job**: one install on one device, from the confirmed start
  (`specs/targeting.md` REQ-TGT-006, `specs/disk.md` REQ-DISK-006) to
  success or failure.
- **Step**: one stage of a job. In M3 the steps, in order, are:
  1. download and verify content (REQ-PE-016);
  2. wipe and partition the disk (`specs/disk.md`);
  3. apply the image (REQ-PE-017);
  4. make the disk bootable (`specs/boot-network.md` REQ-BOOT-065);
  5. restart into the installed system (REQ-PE-019).
  The order of steps 1 and 2 is a clean-side decision (OPEN-JOB-3).
  Later milestones add steps (drivers, configuration, agent).
- **Transient failure**: a failure that may succeed if repeated, such as
  a dropped connection or timeout.

## Requirements

### What the operator sees

### REQ-JOB-001: Per-device job record

For each job the operator can see: the device's identity (as recorded in
`specs/targeting.md` REQ-TGT-016), the boot service, the package, the
disk chosen, when the job started, the current step, the job's state
(REQ-JOB-012), and when it last reported.

- Priority: MUST
- Source: SRC-002 (outcome only: operators can track installs and their
  status); SRC-004 (outcome only: progress is reported)
- Basis: the list of items is derived
- Standards: none
- Status: AUDITED (2026-10-28)

### REQ-JOB-002: Step progress

The operator view and the device's screen both show the list of steps,
which are done, which is running, and which remain.

- Priority: SHOULD
- Source: SRC-004, SRC-009 (outcome only: progress is visible during the
  install)
- Basis: derived
- Standards: none
- Status: AUDITED (2026-10-28)

### REQ-JOB-003: Download progress

While content downloads, the device's screen shows progress for the
download as a whole and for the file being fetched: bytes done, total
bytes, and the file's name or role. The operator view shows at least the
overall percentage for the download step.

- Priority: MUST (device); SHOULD (operator)
- Source: SRC-004, SRC-006 (outcome only: download progress is shown;
  where is not stated)
- Basis: placement at the device and in the operator view is derived
- Standards: none
- Status: AUDITED (2026-10-28; how often the operator view refreshes is OPEN-JOB-1)

### What the person at the device sees

### REQ-JOB-004: Device shows the job

From the start of the job until the restart into the installed system,
the device's screen shows the package being installed, the current step
(REQ-JOB-002) and, during downloads, REQ-JOB-003. It never shows
completion unless every step has succeeded.

- Priority: MUST
- Source: SRC-004 (outcome only: completion is not shown after a
  failure)
- Standards: none
- Status: AUDITED (2026-10-28)

### Failures

### REQ-JOB-005: Clear, persistent error at the device

When a step fails, the device stops and shows an error that:

1. names the step that failed;
2. for download failures, names each file that failed (or its role in
   the package) and says how many failed;
3. says whether the failure was a network problem, an integrity-check
   failure, a refusal by the product, or a local problem (disk, memory);
4. stays on screen until the person acts. The device does not restart,
   clear the error, or move on by itself.

- Priority: MUST
- Source: SRC-004 (outcome only: download failures give a persistent
  error that identifies the failed files; the device does not restart
  by itself during troubleshooting)
- Basis: item 3 is derived
- Standards: none
- Status: AUDITED (2026-10-28; what the person can then do is REQ-JOB-009, REQ-JOB-010)

### REQ-JOB-006: Failure shown to the operator

When a job fails, the operator view shows the job as failed with the same
information as REQ-JOB-005 items 1 to 3, the time of failure, and the
attempts made (REQ-JOB-007). The failed state stays in the operator view
until an operator acts on it or the device starts a new job; it is not
cleared by the passage of time alone.

- Priority: MUST
- Source: SRC-002 (outcome only: deployment status can be reported);
  SRC-004 (outcome only: errors persist)
- Basis: the persistence rule in the operator view is derived
- Standards: none
- Status: AUDITED (2026-10-28; how long finished and failed jobs are kept is
  OPEN-JOB-2)

### REQ-JOB-007: Automatic retry of transient failures

Transient failures while fetching content or talking to the product are
retried automatically a bounded number of times, spaced out (values:
OPEN-JOB-4), before the step is declared failed. Progress already made
in a file need not be kept. A failure that is not transient
(integrity-check failure, refusal, file not found) is not retried.

- Priority: MUST
- Source: SRC-004 (outcome only: transient failures, including transient
  errors while retrieving what to download, are retried)
- Basis: the bound and "not for non-transient failures" are project
  design
- Standards: `specs/standards/http-tls.md` (status codes)
- Status: AUDITED (2026-10-28; retry count and delays are OPEN-JOB-4)

### REQ-JOB-008: Nothing is applied after a failed download

If any content the job needs has not been downloaded completely and
verified (`specs/preinstall-env.md` REQ-PE-016), the job does not go on
to apply the image or change boot settings. It fails with REQ-JOB-005.

- Priority: MUST
- Source: SRC-004 (outcome only: imaging does not proceed unless all
  content downloaded and passed its integrity check)
- Standards: `specs/standards/security-baseline.md`
- Status: AUDITED (2026-10-28)

### REQ-JOB-009: Starting again after a failure

After a failure, the person at the device can restart the device and
network boot again, which starts a new device session and, once
confirmed, a new job from the beginning. The product links the new job
to the failed one for the same device.

- Priority: SHOULD
- Source: SRC-004 (outcome only: a device can be imaged again)
- Basis: project design (starting from the beginning and linking the
  jobs)
- Standards: none
- Status: AUDITED (2026-10-28; whether a failed job can instead resume from the
  failed step is OPEN-JOB-5)

### REQ-JOB-010: Troubleshooting shell after an error

After an error, a command shell can be opened at the device for
troubleshooting, protected by an operator-set secret.

- Priority: SHOULD
- Source: SRC-004 (outcome only: a troubleshooting shell is available at
  the device after errors; two separate operator-set secrets exist, one
  gating the install and one gating troubleshooting access at the
  device; an operator can disable the troubleshooting shell)
- Standards: none
- Status: OPEN (PE-2 and PE-3 are P2. Is the shell part of M3, and how
  is its secret issued?)

### REQ-JOB-011: Step timeouts

Every step has a timeout long enough for slow networks and large images
(hours, not minutes). A step that exceeds it fails with REQ-JOB-005,
naming the timeout.

- Priority: SHOULD
- Source: SRC-004, SRC-006 (outcome only: install steps may take hours)
- Standards: none
- Status: AUDITED (2026-10-28; values are OPEN-JOB-4)

### Job states

### REQ-JOB-012: Job states

A job is in exactly one of: *Running* (with its current step),
*Succeeded*, *Failed* (with reason), *Cancelled*, or *Lost* (the product
has not heard from the device for longer than an allowed interval). Every
change of state is recorded with its time.

- Priority: MUST
- Source: SRC-002 (outcome only: deployment status can be reported)
- Basis: the state set is derived; *Lost* is project design
- Standards: none
- Status: AUDITED (2026-10-28; the interval for *Lost* is OPEN-JOB-4; whether state
  changes are audit records is `specs/targeting.md` REQ-TGT-016, D-M3-8)

### REQ-JOB-013: Success

A job is *Succeeded* only after the image has been applied, the disk has
been made bootable, and the device has reported this before restarting
(REQ-PE-019). Whether the product also waits to hear from the installed
system is a later milestone (AGT-1).

- Priority: MUST
- Source: SRC-004 (outcome only: completion is not shown after a
  failure)
- Basis: derived
- Standards: none
- Status: AUDITED (2026-10-28)

### Content of messages

### REQ-JOB-014: No secrets in progress or errors

Progress, error messages, the operator view and records never contain
secret values (passwords, keys, tokens, directory-join material), on the
device's screen or in the product.

- Priority: MUST
- Source: SRC-004 (outcome only: packages carry secrets)
- Basis: DEC-0011
- Standards: none
- Status: AUDITED (2026-10-28)

### REQ-JOB-015: Messages in the operator's language

Error messages shown to operators are readable in the language of the
product's interface.

- Priority: MAY
- Source: SRC-006 (outcome only: operator-facing error messages are
  localised)
- Standards: none
- Status: AUDITED (2026-10-28)

## States and transitions

```text
Running(step 1) -> Running(step 2) -> ... -> Running(step 5) -> Succeeded
Running(any) -> Failed(reason)          (REQ-JOB-005, REQ-JOB-006)
Running(any) -> Cancelled               (if allowed, targeting REQ-TGT-011)
Running(any) -> Lost                    (no report within the interval)
Lost -> Running | Failed | Succeeded    (when the device reports again)
```

A failed job is never restarted in place in M3; a new job starts
(REQ-JOB-009).

## Limits

- Retry counts, delays, step timeouts, the *Lost* interval and the
  operator view's refresh rate are not in any public source
  (OPEN-JOB-1, OPEN-JOB-4).
- WinPE restarts by itself after 240 hours of use (`winpe.md` §6); any
  step timeout is far shorter.

## Error behaviour

Summary of the failures and where they surface:

| Failure | Device | Operator |
|---------|--------|----------|
| Product unreachable at start | persistent error (REQ-JOB-005) | nothing until the device reports; see OPEN-JOB-6 |
| Download fails after retries | persistent error naming files and count | Failed with same detail |
| Integrity check fails | persistent error; not retried | Failed |
| Disk step fails | `specs/disk.md` REQ-DISK-013 | Failed |
| Image apply fails | persistent error naming the step | Failed |
| Boot setup fails | persistent error naming the step | Failed |
| Device stops reporting | n/a | Lost |

## Security expectations

- No secrets in any message (REQ-JOB-014).
- Reports from the device travel over the protected channel
  (`specs/preinstall-env.md` REQ-PE-015) and are accepted only from the
  session they belong to.

## Standards relied on

- `specs/standards/http-tls.md` (status codes; transport).
- `specs/standards/security-baseline.md` (integrity).
- `specs/standards/winpe.md` §6 (WinPE time limit).

## Out of scope / unknown

- JOB-2 (overview metrics), JOB-3 (logs on the device and central
  collection), JOB-4 (event forwarding).
- **OPEN-JOB-1**: how fresh the operator's view of progress must be.
- **OPEN-JOB-2**: how long finished and failed job records are kept.
- **OPEN-JOB-3**: does content download (step 1) happen before or after
  the disk is wiped? A public source says the device downloads all
  content to its local disk first and then installs from that copy,
  which implies partitioning comes first; downloading into memory is
  limited by the RAM disk (`winpe.md` §9).
- **OPEN-JOB-4**: retry count and delays, step timeouts, the *Lost*
  interval.
- **OPEN-JOB-5**: can a failed job resume from the failed step?
- **OPEN-JOB-6**: when the device cannot reach the product at all, how
  does the operator learn of it? (REQ-BOOT-054 is the related OPEN for
  the boot phase.)
- REQ-JOB-010: see its Status line.
