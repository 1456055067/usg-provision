# 0010: Every Operator Action Is Audited

- Status: Accepted (owner, 2026-10-26)
- Date: 2026-10-26
- Decider: project owner
- Basis: project requirement (NIST SP 800-53 AU-2, AU-3, AU-12); not
  described product behaviour

## Decision

Every operator action that reads protected content or changes state, and
every authentication or authorization failure, produces an audit record
with who, what, when, where, source and outcome, written to the
tamper-evident audit log. Failures are audited as well as successes.
