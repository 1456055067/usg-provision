# 0024: M4 Administrator Password, Management Agent, OS Scope and Drivers

- Status: Accepted (owner, 2026-10-30)
- Date: 2026-10-30
- Decider: project owner
- Resolves: roadmap D-8 and D-9; REQ-OS-012; the DRV-1 injection method;
  the M4 part of POAM-38
- Specs: `specs/configuration.md` REQ-CFG-010, `specs/agent-handoff.md`
  REQ-AGT-003/004, `specs/os-support.md` REQ-OS-012, `specs/drivers.md`;
  standards topics 10 (`unattend.md`) and 12 (`offline-drivers.md`)

## Context

The M3 security review set a constraint (decision 0018 item 1, POAM-38). A
device session is authorised only by an operator code or approval, and a
rogue Windows PE can relay a code that a technician types. So no secret may
be delivered to such a session.

The M4 spec pass found three things:

- Windows caches the answer file on the installed disk, and Microsoft's
  "hide" option for passwords is only an encoding (topic 10).
- Public sources do not say how the product delivers the local
  administrator password or the agent's enrolment material (OPEN-CFG-4,
  OPEN-AGT-1 to 3).
- Windows 10 reached end of support on 2025-10-14.

## Decision

1. **Local administrator password (D-8).** No password is delivered to the
   device and none is placed in an answer file.
   - A post-setup workflow step generates a random password on the device.
   - The step sets the password on the account.
   - It sends the password back to the server encrypted to a
     server-held public key, so only the server can recover it.
   - Operators retrieve it through an audited, permission-gated server
     route.
   - REQ-CFG-010 is satisfied by construction: the answer file and its
     cached copies hold no secret.
2. **Management agent (D-9).** The operator uploads a signed package
   holding the agent installer and a non-secret enrolment configuration.
   A workflow step runs it. The enrolment configuration carries no secret.
   The management side decides whether to approve the device's enrolment.
   No enrolment secret reaches a device session.
3. **Windows 10 (REQ-OS-012).** Decision 0009 stands: Windows 11
   Enterprise x64 only. The M4 lab exit covers Windows 11 only.
4. **Drivers (DRV-1).** After the image is applied, the agent runs the
   DISM in Windows PE to add the driver packages to the offline image
   (topic 12). Driver packages are digest-verified before they are written
   (SI-7). DISM's output and exit status are checked, and nothing is cached
   on the target.

## Consequences

- M4 needs no stronger device authorisation, because nothing secret is
  delivered. POAM-38 stays open for later secret-bearing features, such as
  domain join in M8.
- New server state: escrowed administrator passwords (SC-28 at rest, AU-2
  on retrieval) and the server key that decrypts them (SC-12).
- The roadmap's M4 exit 1 drops Windows 10. Exit 2 (no password on the
  disk, in logs or in caches) is tested by scanning the applied disk image
  and the server stores.
- DISM's exit-status gaps (OPEN-DRVS-2 and 3) shape the plan's checks.
