# Management agent hand-off (AGT-1)

Status: AUDITED (spec run M4, 2026-10-29; clean-room audit 2026-10-29, OPEN
items remain OPEN). REQ
range in use: `REQ-AGT-001` to `REQ-AGT-006`. AGT-2 (patches,
applications, policies) is not specced.

## Purpose

The install ends with the device under central management, so that it
needs no separate enrolment step afterwards. This answers roadmap D-9 as
far as public sources allow.

## Actors and roles

- **Operator**: supplies what the device needs to join management.
- **Product**: installs the agent during the build.
- **Management system**: the system the agent reports to.

## What the public sources say (D-9)

- The build installs the management agent, and the device is ready to
  use, and fully managed, at the end (SRC-001, SRC-009).
- Afterwards operators can hand the device over to wider management;
  patching, software installs and policy may be part of the build
  (SRC-002; AGT-2).
- Domain join and local administrator setup may finish before the agent
  install, and the install must not fail when they do (SRC-004,
  SRC-006; `specs/workflow.md` REQ-SEQ-003).
- Managed endpoints can later be refreshed, and content can then come
  through the agent (SRC-004; RFR-1).
- Package tags are applied to the provisioned endpoint (SRC-004;
  `specs/configuration.md` REQ-CFG-009).
- **Not stated anywhere read**: what the product installs (which agent
  build or version), how the installer and its enrolment configuration
  are supplied to the product or delivered to the device, and how they
  are protected. These are OPEN-AGT-1 and OPEN-AGT-3.

## Requirements

### REQ-AGT-001: Agent installed during the build

Every successful install leaves the management agent installed and
running on the device.

- Priority: MUST
- Source: SRC-001, SRC-009
- Standards: none
- Status: AUDITED

### REQ-AGT-002: Managed endpoint, observably

At the end of the install the device is a managed endpoint: it appears
to the management system as a device under management, carries the
package's tags (REQ-CFG-009), and can be targeted for later actions
such as a refresh.

- Priority: MUST
- Source: SRC-001, SRC-009 (managed at the end), SRC-004 (tags applied;
  refresh of managed endpoints), SRC-002 (hand-over to wider management)
- Standards: none
- Status: AUDITED. What "appears to the management system" consists of
  is OPEN-AGT-2.

### REQ-AGT-003: Supplying the agent and its enrolment configuration

The operator supplies the agent installer and the configuration it needs
to join management, and the product uses them in every build that
installs the agent.

- Priority: MUST
- Source: none
- Standards: none
- Status: OPEN (D-9: no public source says how the installer and its
  configuration reach the product or the device, whether they are part
  of each package or set once, or whether the product updates them.)

### REQ-AGT-004: Enrolment configuration treated as a secret

Any part of the enrolment configuration that would let a device join
management is handled as a secret: protected at rest, delivered only
over an authenticated, encrypted channel, never shown or logged.

- Priority: MUST
- Source: none
- Basis: DEC-0011 (secrets baseline), project rule
- Standards: none
- Status: OPEN (Which parts are secret is not public. Under the M3
  security review no secret may reach a device session authorised only by
  an operator code or approval (DEC-0018 item 1; POAM-38), so delivery
  is blocked until a stronger device authorisation is decided.)

### REQ-AGT-005: Agent install failure

If the agent cannot be installed, the job ends with a persistent error
naming the step, and the device is not reported ready.

- Priority: MUST
- Source: none
- Basis: derived from REQ-SEQ-006 and REQ-SEQ-008 (project design)
- Standards: none
- Status: AUDITED

### REQ-AGT-006: Order relative to Windows setup

The agent is installed after Windows has completed its first-start
configuration on the installed disk (`specs/workflow.md` REQ-SEQ-002
step 8).

- Priority: SHOULD
- Source: SRC-009 (agent install is part of the process; order not
  stated)
- Basis: project design; Windows offers a system-context script after
  setup (`specs/standards/unattend.md` §5), but whether the product uses
  it is not known
- Standards: `specs/standards/unattend.md` §5
- Status: AUDITED

## States and transitions

The hand-off is *pending*, *agent installed*, or *failed*. Only *agent
installed* lets the job succeed (REQ-SEQ-006).

## Limits

None stated.

## Error behaviour

REQ-AGT-005.

## Security expectations

REQ-AGT-004. No public source describes how the product protects the
enrolment configuration; nothing is inferred.

## Standards relied on

`specs/standards/unattend.md` §5.

## Out of scope / unknown

- AGT-2.
- **OPEN-AGT-1** (D-9): which agent is installed and how the installer is
  supplied and kept current.
- **OPEN-AGT-2**: what registration with the management system consists
  of, and how the product confirms it happened.
- **OPEN-AGT-3** (D-9, POAM-38): which parts of the enrolment
  configuration are secret, and how they reach the device.
- REQ-AGT-003, 004: see Status lines.
