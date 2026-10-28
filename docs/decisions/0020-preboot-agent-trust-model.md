# 0020: Pre-boot Agent Trust Model

- Status: Accepted (owner, 2026-10-28)
- Date: 2026-10-28
- Decider: project owner
- Refines: decision 0018 item 1
- Resolves: M3 plan question Q1; OPEN-PE-6

## Context

The operator builds Windows PE from Microsoft's kit. The product does not
ship or modify Microsoft components. Anything placed inside that
environment is served over TFTP to any device that asks, so it cannot hold
a secret.

## Decision

1. The operator adds the project's agent binary and a public configuration
   file to their own Windows PE. The configuration holds the server
   address and the server trust anchor. The product never modifies the
   PE.
2. The device carries no secret. The agent authenticates the server
   through TLS with the configured trust anchor.
3. The server accepts a device session as "a provisioning environment it
   trusts" (REQ-TGT-012) only after the mandatory authorisation of
   decision 0018 item 1. That authorisation is a single-use,
   operator-issued code entered at the device, or an operator approving
   the device, bound to a display code shown on the device's screen. The
   authorisation is the device credential.
4. The server cannot tell the project's PE from a copy, and this is
   accepted. A copied PE gains nothing without a fresh authorisation.
5. REQ-PE-010 (a secret embedded in the environment) is not built.

## Consequences

- Every package listing, plan and content download needs an authorised
  session token, which is bound to the TLS session and expires.
- A device that is never authorised sees nothing.
