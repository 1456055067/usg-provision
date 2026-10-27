# Operator access and audit for content management (milestone M2)

Status: AUDITED, partial (spec run M2, 2026-10-26; re-audit round 1
approved). OPEN: REQ-RBAC-002, REQ-AUD-004. REQ ranges in use:
`REQ-RBAC-001` to `REQ-RBAC-006` and `REQ-AUD-001` to `REQ-AUD-005`.
Numbers up to 019 in each range are reserved for this file; INDEX rows
RBAC-1 and AUD-1 (device retirement, P2) will use later numbers.

## Purpose

Operators manage images, preinstall environments and deployment packages
(`specs/os-images.md`, `specs/preinstall-env.md`). This spec states who
may do those things and what record is kept of them. The public sources
describe roles and audit only for other product areas, so most of this
spec rests on project decisions, which are marked as such.

## What the public sources say

- The product gates actions with roles and permissions. Public release
  notes mention an administrator right to create local boot services,
  built-in roles that lacked a permission they needed, and separate
  administrator and view-only roles for device retirement. (SRC-004,
  SRC-006)
- Retirement actions are logged with operator notes, and that log can be
  exported. No public source describes an audit record of other operator
  actions. (SRC-004; INDEX Unconfirmed)
- No public source describes a general operator API; one is mentioned
  only for retirement. (INDEX Unconfirmed)

## Project decisions this spec relies on

These are project decisions accepted by the owner on 2026-10-26. They are
not described product behaviour.

- **DEC-0007**: operators authenticate with TLS client certificates
  (PIV/CAC or agency-issued); one certificate maps to one operator; no
  shared or anonymous accounts; unauthenticated requests are refused and
  audited.
- **DEC-0010**: every operator action that reads protected content or
  changes state, and every authentication or authorisation failure, is
  audited (successes and failures), in a tamper-evident audit log.
- **DEC-0011**: secrets are never logged, are protected at rest, and
  travel only over authenticated, encrypted channels; operator channels
  use TLS per NIST SP 800-52 Rev. 2.

## Actors and roles

- **Operator**: an individual person using the operator interface.
- **Administrator**: an operator whose role lets them assign roles.
- **Auditor**: anyone allowed to read audit records (OPEN-ACC-2).

## Requirements

### Access

### REQ-RBAC-001: Content actions need a permission

Each content action needs a permission that the operator's role grants:
viewing, creating, editing, cloning and deleting packages; uploading,
viewing and deleting image files; importing, viewing and deleting
preinstall environments. An operator without the permission cannot
perform the action.

- Priority: MUST
- Source: SRC-004, SRC-006 (outcome only: product actions are gated by
  role permissions; content permissions are not described)
- Standards: none
- Status: AUDITED (the permission set and default roles are OPEN-ACC-2)

### REQ-RBAC-002: View without change

A role can allow an operator to view content and its status without
allowing any change.

- Priority: SHOULD
- Source: SRC-004 (a view-only role exists for another area)
- Standards: none
- Status: OPEN (Which roles exist by default for content management? No
  public source says.)

### REQ-RBAC-003: Refused actions change nothing

When an operator attempts an action their role does not allow, nothing
changes, and the operator is told the action is not permitted, without
being shown content they may not see. The refused attempt is audited
(REQ-AUD-001).

- Priority: MUST
- Source: none
- Basis: project design, not described product behaviour: derived from
  REQ-RBAC-001; auditing of the refusal from DEC-0010
- Standards: RFC 9110 §15.5.4 (403) where HTTP is used
- Status: AUDITED

### REQ-RBAC-004: Built-in roles work as intended

Any role the product supplies ready-made holds every permission needed
for the tasks it is meant for, so operators do not hit missing
permissions in normal use.

- Priority: SHOULD
- Source: SRC-004
- Standards: none
- Status: AUDITED

### REQ-RBAC-005: Individual operators, authenticated by certificate

Every content action is performed by an individually identified operator
who has authenticated to the product with a TLS client certificate (for
example from a PIV or CAC card, or another agency-issued certificate).
The product validates the certificate path against trust anchors that
an administrator configures, and maps each accepted certificate to
exactly one operator. There is no anonymous or shared operator access. A
request that is not authenticated is refused, changes nothing, and is
audited (REQ-AUD-001). How revocation is checked and how certificates
map to operators is for the clean-side design.

- Priority: MUST
- Source: none
- Basis: DEC-0007 (project decision, not described product behaviour)
- Standards: RFC 5280 path validation
  (`specs/standards/security-baseline.md` §2); RFC 8446 / RFC 9846
  client authentication (`specs/standards/http-tls.md` §6.3); FIPS
  201-3 and NIST SP 800-63B as background (`security-baseline.md` §4);
  RFC 9110 §15.5.2 (401) where HTTP is used
- Status: AUDITED

### REQ-RBAC-006: Secret values stay hidden

No role lets an operator read back a secret value stored in a package
(`specs/os-images.md` REQ-IMG-054).

- Priority: MUST
- Source: SRC-004 (packages hold administrator passwords)
- Basis: DEC-0011 item 2 (project requirement, not described product
  behaviour)
- Standards: none
- Status: AUDITED

### Audit

### REQ-AUD-001: Record every operator action and every refusal

An audit record is produced for each of these:

- every content action in REQ-RBAC-001 that changes something;
- every content action that reads content the product protects;
- every attempt refused under REQ-RBAC-003;
- every failed or missing authentication under REQ-RBAC-005;
- every refusal of out-of-scope content (`specs/os-support.md`
  REQ-OS-005, `specs/preinstall-env.md` REQ-PE-005).

Each record states who (the operator, or "unauthenticated" with what
the product could learn of the requester), what (the action and the
item acted on), when (date and time in UTC), where (the interface used),
source (the network origin), and the outcome (success, or failure with
its reason). Successes and failures are both recorded.

- Priority: MUST
- Source: none (SRC-004 describes an audit log only for retirement)
- Basis: DEC-0010 (project requirement, not described product
  behaviour); the refusal cases from DEC-0007 and DEC-0009
- Standards: none read (NIST SP 800-53 Rev. 5 could not be read)
- Status: AUDITED

### REQ-AUD-002: Record content state changes

When an image file, preinstall environment or package becomes ready,
fails (with its reason) or is deleted, an audit record is produced. A
change that completes later than the operator action that started it
(for example a check that finishes after an upload) is recorded when it
happens and names the action that started it.

- Priority: MUST
- Source: none
- Basis: DEC-0010 (state changes are audited; the outcome of an
  operator action is part of that action's record), project
  requirement, not described product behaviour
- Standards: none
- Status: AUDITED

### REQ-AUD-003: No secrets in audit records

Audit records never contain secret values, such as passwords held in
packages, in any recoverable form.

- Priority: MUST
- Source: SRC-004 (packages hold administrator passwords)
- Basis: DEC-0011 item 2 (secrets are never logged), project
  requirement, not described product behaviour; see also
  `specs/os-images.md` REQ-IMG-054
- Standards: none
- Status: AUDITED

### REQ-AUD-004: Export audit records

An operator with permission can export audit records for review outside
the product.

- Priority: SHOULD
- Source: SRC-004 (outcome only: the retirement log can be exported)
- Standards: none
- Status: OPEN (Is export provided for all audit records, in what form,
  and who may export? No public source covers content actions.)

### REQ-AUD-005: Audit records show tampering

Audit records are kept so that any change to, removal of, or insertion
among existing records can be detected.

- Priority: MUST
- Source: none
- Basis: DEC-0010 (tamper-evident audit log), project requirement, not
  described product behaviour
- Standards: none
- Status: AUDITED (how long records are kept is OPEN-AUD-L1; behaviour when
  a record cannot be written is OPEN-AUD-1)

## States and transitions

None of its own. Audit records are produced by the actions and state
changes in `specs/os-images.md`, `specs/preinstall-env.md` and
`specs/os-support.md`.

## Limits

- **OPEN-AUD-L1**: how long audit records are kept and how much space
  they may use.

## Error behaviour

- Not authenticated: refused, nothing changed, audited (REQ-RBAC-005,
  REQ-AUD-001).
- Action not permitted: refused, nothing changed, operator told
  (REQ-RBAC-003), and an audit record made (REQ-AUD-001).
- Audit record cannot be written: OPEN-AUD-1 (must the action then be
  refused?).

## Security expectations

- Access decisions are made by the product for each action, not by the
  operator interface alone (REQ-RBAC-001).
- Operators authenticate with client certificates over TLS
  (REQ-RBAC-005); sessions use TLS per NIST SP 800-52 Rev. 2
  (`specs/os-images.md` REQ-IMG-053).
- Audit records hold no secrets (REQ-AUD-003) and show tampering
  (REQ-AUD-005).

## Standards relied on

- RFC 5280, RFC 8446 / RFC 9846 (client certificates):
  `specs/standards/security-baseline.md` §2,
  `specs/standards/http-tls.md` §6.3.
- NIST SP 800-63B, FIPS 201-3, SP 800-73-5 (operator authentication
  background): `specs/standards/security-baseline.md` §4.

## Out of scope / unknown

- **OPEN-ACC-1**: settled for M2 by DEC-0007 (client certificates over
  TLS; REQ-RBAC-005). Still open: the revocation-checking method and the
  certificate-to-operator mapping (clean-side design), and whether
  another method is added later.
- **OPEN-ACC-2**: the permission set, the default roles, and who may read
  audit records.
- **OPEN-ACC-3**: the form of the operator interface (web console, API,
  command-line tool). No public source describes a general operator API.
  DEC-0007 speaks of an operator API for M2; whether other forms are
  offered is not settled.
- **OPEN-AUD-1**: behaviour when an audit record cannot be written.
- **OPEN-AUD-2**: tamper evidence is settled by DEC-0010 (REQ-AUD-005).
  Still open: who, if anyone, may delete records, and when.
- RBAC-1 and AUD-1 in the INDEX (device retirement roles and log): later.
- Restricting which devices an operator may target (TGT-4): later.
