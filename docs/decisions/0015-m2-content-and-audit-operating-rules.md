# 0015: M2 Content and Audit Operating Rules

- Status: Accepted (owner, 2026-10-27)
- Date: 2026-10-27
- Decider: project owner
- Basis: project design / requirement; not described product behaviour
- Resolves for M2: REQ-IMG-015 (in-use delete), OPEN-AUD-1, OPEN-ACC-2

## Decision

1. Audit failure: if an audit record cannot be written, the action it
   records is refused (fail closed). Refusals remain refusals.
2. In-use deletion: deleting an image, PE kit or package that another
   object depends on is refused, naming the dependants.
3. Audit access: M2 has no audit-reading API. Audit records are read and
   the chain verified only with a local administrative command on the
   server host. A viewer role is a later decision.
