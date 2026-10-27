# 0013: Operator-Declared Image Facts, Cross-Checked by the Product

- Status: Accepted (owner, 2026-10-27)
- Date: 2026-10-27
- Decider: project owner
- Basis: project design; not described product behaviour
- Resolves for M2: REQ-IMG-043, REQ-PE-005 (how image and PE facts are
  learned); interacts with REQ-OS-009 and decision 0009

## Decision

1. When an operator uploads an image, they declare, per edition used, the
   Windows release, edition and architecture; for a PE kit, its
   architecture and kit version.
2. The product reads whatever the WIM's Microsoft-documented XML metadata
   states for the same facts and refuses the upload or selection, with an
   audited reason, if a declared fact contradicts a fact read from the file.
   Facts the file does not state are taken from the declaration and marked
   "declared" (not "verified") wherever they are shown or recorded.
3. Decision 0009 applies to the declared and read facts: only Windows 11
   Enterprise x64 (and an x64 PE) can make a package Ready in M2. Edition
   names other than plain Enterprise (for example LTSC or IoT Enterprise)
   are refused in M2.
4. Declarations are audited with the operator's identity (decision 0010).
