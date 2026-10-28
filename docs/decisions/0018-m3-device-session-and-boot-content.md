# 0018: M3 Device Session, Boot Content and Install Defaults

- Status: Accepted (owner, 2026-10-28). Items 1–4 and items 5–10 were
  accepted in two steps on the same day.
- Date: 2026-10-28
- Decider: project owner
- Refines: decisions 0004 (boot scope), 0006 (WIM by black-box samples), 0010
  (audit every operator action)
- Resolves: roadmap decisions D-2, D-3, D-4 and D-5; spec run M3 questions
  D-M3-2 to D-M3-8

## Context

Milestone M3 boots an operator-prepared Windows PE from the relay, lets a
technician pick a package and disk, and applies the image. The audited
public sources leave several behaviours open: device-side authorisation,
the wipe confirmation, cancelling, and how the boot order changes. A
Windows PE image is also larger than default-size TFTP blocks can carry
without block-number wraparound.

## Decision

Items 1–4 were accepted by the owner on 2026-10-28.

- **1. Device session authorisation (D-3).** A bare-metal device session
  gets no package list and no secret until it is authorised. There are two
  ways to authorise it: a short-lived, single-use code that an operator
  issues and the technician enters at the device, or an operator approving
  the waiting device in the console. Authorisation is required by default.
  Every issue, use, approval and refusal is audited.
- **2. Large boot files over TFTP (D-M3-3).** The boot service supports
  block-number wraparound and negotiates large block sizes (RFC 2348) when
  the client asks. The QEMU lab tests whether Microsoft's boot program
  accepts wraparound, and the result is recorded as an observation.
- **3. WinPE boot configuration (D-M3-2).** The operator builds the boot
  configuration store with Microsoft's tool as part of the PE boot kit.
  The product imports it, verifies its integrity and serves it, but never
  generates or edits it.
- **4. Image apply (D-4).** The project's own pure-Rust WIM reader, which
  extends the M2 checker, runs inside WinPE. It writes files through
  Windows APIs and verifies content before every write. Microsoft's
  servicing tool is not used to apply images.

Items 5–10 were proposed as defaults and accepted by the owner on
2026-10-28.

- **5. Boot chain (D-2).** WinPE boots through Microsoft's boot program from
  the operator's PE boot kit. No third-party chain-loader is used, and
  Secure Boot is never weakened.
- **6. FIPS operating environment (D-5).** Check whether the FIPS module's
  validated operational environments include Windows PE on x64. Record a
  POA&M item if they do not. M3 does not wait for the answer.
- **7. Wipe confirmation (D-M3-4).** An explicit wipe confirmation at the
  device is mandatory and separate from disk selection. No mode skips it
  in R1. `disk.wipe.authorised` is durably recorded before any write.
- **8. Disk choice (D-M3-5).** A single eligible disk is still shown for
  confirmation. Removable disks and the disk carrying the boot environment
  are refused. The product never reads out existing disk contents (project
  rule).
- **9. Completion (D-M3-6).** At the end of the install, the installed OS's
  boot entry is made first in the boot order, and the change lasts. The
  boot service stops offering a boot program to that device once its job
  has succeeded.
- **10. Cancelling and device audit (D-M3-7, D-M3-8).** A session can be
  cancelled at any point before the wipe confirmation. After the wipe the
  job runs to success or a persistent error. Device-side choices and every
  job state change are audit records, extending decision 0010 from
  operator actions to device sessions.

## Consequences

- M3 needs a session-authorisation API, a code issuer, and a console
  approval route, each audited.
- The relay TFTP service gains wraparound support and a lab observation of
  how Microsoft's boot program behaves with it.
- PE boot kits carry an operator-built boot configuration store, imported
  under the same integrity rules as other boot content.
- `usgp-image` gains an extraction path that writes files and is fuzzed
  like the checker.
