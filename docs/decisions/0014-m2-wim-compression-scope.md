# 0014: M2 WIM Compression Scope

- Status: Accepted (owner, 2026-10-27)
- Date: 2026-10-27
- Decider: project owner
- Refines: decision 0006

## Decision

In M2 the product accepts WIM files whose resources are uncompressed or
XPRESS-compressed, decoded by our own implementation of Microsoft's
published XPRESS format (MS-XCA). LZX-compressed WIMs are refused with a
named reason until a later decision. LZMS (solid), `.esd`, split (`.swm`),
resource-only and metadata-only files are refused.
