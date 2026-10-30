# Configuration and answer files (CFG-1, CFG-2)

Status: AUDITED (spec run M4, 2026-10-29; clean-room audit 2026-10-29, OPEN items remain OPEN). REQ
range in use: `REQ-CFG-001` to `REQ-CFG-012`. CFG-3 (name templates and
names entered at the device) and CFG-4 (prompts answered at the device)
are not specced.

## Purpose

A deployment package carries the configuration that turns a generic
Windows image into a particular device's installation: a Windows answer
file, plus a small set of values the operator sets on the package
(computer name, domain and OU, time zone, local administrator password,
descriptive tags). Some values differ per device and are filled in when
that device installs.

## Actors and roles

- **Operator**: writes or supplies the answer file and sets the package
  values (`specs/operator-access.md` for permissions).
- **Device**: receives its resolved configuration during the install.
- **Product**: stores the configuration, resolves per-device values,
  checks them, and delivers them.

## Requirements

### REQ-CFG-001: A package carries an answer file

Every deployment package carries one Windows unattended-setup answer
file. A package without one cannot become ready.

- Priority: MUST
- Source: SRC-001 (the answer file is a required part of a package)
- Standards: `specs/standards/unattend.md` §1, §2
- Status: AUDITED

### REQ-CFG-002: Checking the answer file

When the operator adds or changes the answer file, the product checks
it before the package can become ready and tells the operator what is
wrong if it cannot be used.

- Priority: SHOULD
- Source: none
- Standards: `specs/standards/unattend.md` §1.2 (Microsoft recommends
  validating answer files with its own tool)
- Status: OPEN (What checks does the product make: well-formed XML only,
  or settings valid for their configuration pass? No public source
  says.)

### REQ-CFG-003: Per-device values substituted at install time

The answer file may refer to per-device values. When a device installs,
the product replaces each reference with that device's value before the
answer file reaches Windows. The computer name is one such value. The
same package can therefore serve many devices.

- Priority: MUST
- Source: SRC-004 (answer files can reference variables such as the
  computer name)
- Standards: none
- Status: AUDITED. How a reference is written in the answer file is for
  the clean side to design; no public format exists and none may be
  copied (OPEN-CFG-1).

### REQ-CFG-004: Unresolved references

If a reference in the answer file has no value for the device being
installed, the install does not continue with the reference left in
place.

- Priority: MUST
- Source: none
- Standards: none
- Status: OPEN (Does the product stop with a persistent error, ask at the
  device, or use a default? No public source says. Project design until
  decided: stop with a persistent error naming the value, before the
  disk is wiped, `specs/progress.md`.)

### REQ-CFG-005: Computer name

The package sets the computer name, directly or as a per-device value
(REQ-CFG-003). The product refuses a name that Windows would not accept,
before it reaches the device, and says why. Windows' rules are in the
standards summary.

- Priority: MUST
- Source: SRC-004 (invalid computer names are caught instead of
  breaking naming or domain join), SRC-001 (computer name is a package
  value)
- Standards: `specs/standards/unattend.md` §3.1
- Status: AUDITED. When the check runs for a per-device name (at package
  save, or when the device's value is known) is OPEN-CFG-2.

### REQ-CFG-006: Domain and OU as carried values

The package can name an Active Directory domain and the OU in which the
device's computer account is placed. In M4 the product carries both
values to the device's configuration unchanged. An OU name with a
distinguished name longer than 64 characters, and an OU name containing
quotation marks, are carried correctly.

- Priority: MUST
- Source: SRC-001 (domain and OU are package values; both offline and
  online joins exist), SRC-004 (long OU names work; a failure caused by a
  quoted OU path is logged clearly)
- Standards: `specs/standards/unattend.md` §3.4
- Status: AUDITED. The join itself (offline or online, DOM-1, DOM-2) is
  not specced; in M4 no join credential is part of the package (see
  "Security expectations").

### REQ-CFG-007: Time zone

The package can set the device's time zone as text. The product accepts
any time zone name the operator types rather than only names from a
fixed list.

- Priority: MUST
- Source: SRC-004 (time zone values accept free text), SRC-001 (time
  zone is a package value)
- Standards: `specs/standards/unattend.md` §3.2
- Status: AUDITED. Whether the product warns about names Windows does not
  know is OPEN-CFG-3 (and `unattend.md` OPEN-UNATT-2).

### REQ-CFG-008: Local administrator password

The package can hold a password for the device's local administrator
account, which the install sets. The password is kept when the package
is cloned, and the cloned package can be deployed. It is set on
bare-metal installs and on refreshes.

- Priority: MUST
- Source: SRC-004 (clones keep the password, and a later fix makes such
  clones usable; a fix for setting it during refresh)
- Standards: `specs/standards/unattend.md` §3.3, §4
- Status: AUDITED. How it is protected is OPEN-CFG-4 (see "Security
  expectations"). Refresh is RFR-1 (not specced).

### REQ-CFG-009: Descriptive tags

The package can carry descriptive tags. After the install, the tags are
attached to the device as a managed endpoint, so that operators can see
and use them there.

- Priority: MUST
- Source: SRC-001 (tags are package values), SRC-004 (package tags are
  applied to provisioned endpoints)
- Standards: none (Windows has no answer-file setting for them)
- Status: AUDITED. Where tags appear and how they are used depends on the
  management hand-off (`specs/agent-handoff.md`, OPEN-AGT-2) and is
  OPEN-CFG-5.

### REQ-CFG-010: No secret left in clear on the installed disk

After a successful install, the installed disk holds no copy of the
local administrator password or of any other secret from the package in
clear or merely encoded form, in an answer file or elsewhere the product
placed it.

- Priority: MUST
- Source: none
- Basis: project rule from DEC-0011 (secrets handling baseline); Windows'
  own behaviour, which does not ensure this, is in
  `specs/standards/unattend.md` §4
- Standards: `specs/standards/unattend.md` §2.1, §4
- Status: OPEN (roadmap D-8: no public source says how the product
  handles this; the owner must decide the mechanism, for example
  removing Windows' cached answer file after the passes that need it.)

### REQ-CFG-011: Changes are audited without secrets

Every change to a package's answer file or values is recorded for audit:
who, what, when, outcome. Secret values are never written to the audit
record, logs or progress display, and are never shown back to an
operator.

- Priority: MUST
- Source: none
- Basis: DEC-0010 (every operator action audited) and DEC-0011 (secrets
  never shown), project rules
- Standards: none
- Status: AUDITED

### REQ-CFG-012: Same configuration on every install path

The answer file and package values apply in the same way whether the
package is used for a bare-metal install or a refresh.

- Priority: SHOULD
- Source: SRC-004 (packages can be deployed as refreshes; settings fixed
  for refresh)
- Standards: none
- Status: AUDITED (refresh itself is RFR-1, not specced)

## States and transitions

A package's configuration is *incomplete* (no answer file, REQ-CFG-001,
or a check failed, REQ-CFG-002) or *complete*. Only a complete
configuration lets a package become ready (`specs/os-images.md`). At
install time the configuration is *resolved* for one device
(REQ-CFG-003); resolution either succeeds or the install stops
(REQ-CFG-004).

## Limits

- Computer name: Windows' 15-byte limit and character rules
  (`unattend.md` §3.1).
- Time zone: Windows accepts up to 256 characters (`unattend.md` §3.2).
- OU: no 64-character limit (REQ-CFG-006). Other product limits are not
  stated publicly (OPEN-CFG-6).

## Error behaviour

- Invalid computer name: refused with a reason before use (REQ-CFG-005).
- Unresolved reference: the install does not continue (REQ-CFG-004).
- Answer file that cannot be used: package not ready (REQ-CFG-002).

## Security expectations

- Outcome only: join passwords are kept out of the answer file
  (SRC-004, SRC-009). No public source says how the administrator
  password is protected (OPEN-CFG-4).
- Project constraints (not product behaviour): secrets are delivered
  only over an authenticated, encrypted channel and never shown
  (DEC-0011). Under the M3 security review, no secret is delivered to a
  device session authorised only by an operator-issued code or approval
  (DEC-0018 item 1 with the review finding the request cites as
  POAM-38). So the administrator password cannot reach a device in M4
  until a stronger device authorisation is decided: OPEN-CFG-4.
- Windows itself only "hides" local account passwords by encoding, with
  no security benefit, and keeps a cached answer file on disk
  (`unattend.md` §4).

## Standards relied on

- `specs/standards/unattend.md` (topic 10).

## Out of scope / unknown

- CFG-3, CFG-4; domain join itself (DOM-1 to DOM-4).
- **OPEN-CFG-1**: the reference syntax for per-device values (clean-side
  design) and the set of per-device values besides the computer name.
- **OPEN-CFG-2**: when a per-device computer name is checked.
- **OPEN-CFG-3**: warning on unknown time zone names.
- **OPEN-CFG-4** (D-8, POAM-38): how the administrator password is
  protected at rest, delivered to the device, and kept off the installed
  disk, given that M3 device sessions may not receive secrets.
- **OPEN-CFG-5**: how tags are represented on the managed endpoint.
- **OPEN-CFG-6**: size limits on the answer file and on values.
- REQ-CFG-002, 004, 010: see their Status lines.
