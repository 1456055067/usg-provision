# 0011: Content Integrity and Secrets Handling Baseline

- Status: Accepted (owner, 2026-10-26)
- Date: 2026-10-26
- Decider: project owner (records the engineering rules in CLAUDE.md)
- Basis: project requirement (NIST SP 800-53 SI-7, SC-8, SC-28, IA-5);
  not described product behaviour

## Decision

1. Every stored or served artifact (images, PE boot kits, packages, boot
   files) is integrity-verified against a recorded digest or signature
   before it is served, applied or written, and on every use.
2. Secrets (domain-join credentials, local administrator passwords,
   enrollment tokens, private keys) are never logged, are protected at rest,
   and are delivered only over an authenticated, encrypted channel.
3. Operator and service channels use TLS through `usgp-crypto`
   (decision 0001), configured per NIST SP 800-52 Rev 2.
