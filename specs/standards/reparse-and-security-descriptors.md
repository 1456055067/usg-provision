# Standards summary: reparse data and security descriptors

Topic 24 of the standards reading list (spec request SR-6, M3,
2026-10-28). **Status: AUDITED 2026-10-28** (all sections; audit
fixes CR-SR6-001 to 008 applied). The OPEN items stay open, except
OPEN-RPSD-2 and 3, which the R4 fold (2026-10-28, AUDITED
2026-10-28) marks settled for the drive-letter form. Text added in
that fold is marked "R4".

Background for PE-1 image apply (REQ-PE-017): a WIM image stores
Windows symbolic links, junctions (mount points) and security
descriptors (`specs/standards/wim.md` §6 and §6.1). This file
summarises Microsoft's published formats for those items. It is not a
design. How the product applies them is the clean side's choice, except
where a REQ or a project decision says otherwise.

Sources:

- **[MS-FSCC]**: Microsoft Open Specifications, "File System Control
  Codes", protocol revision 60.0 of 2025-11-21 (HTML edition on
  Microsoft Learn). Sections read: Reparse Tags; REPARSE_DATA_BUFFER;
  Symbolic Link Reparse Data Buffer (§2.1.2.4); Mount Point Reparse
  Data Buffer (§2.1.2.5); Pathname (§2.1.5); Dot Directory Names
  (§2.1.5.1). The section numbers are the ones the pages give in their
  cross-references; the other two pages show no number and are cited
  by heading.
- **[MS-DTYP]**: Microsoft Open Specifications, "Windows Data Types",
  protocol revision 42.0 of 2024-11-19 (HTML edition). Sections read:
  SID (§2.4.2); SID packet representation (§2.4.2.2);
  SID_IDENTIFIER_AUTHORITY; ACL; ACE_HEADER (§2.4.4.1);
  SECURITY_DESCRIPTOR (§2.4.6, numbered from its subsection 2.4.6.1).
- Microsoft Learn driver and Win32 reference pages, as background:
  REPARSE_DATA_BUFFER (ntifs.h), SECURITY_DESCRIPTOR_CONTROL (driver
  docs), FSCTL_SET_REPARSE_POINT.

Both Open Specifications documents carry Microsoft's notice that
copies may be made to build implementations, and that Microsoft claims
no trade secrets in them. Field names, sizes, constants and tag values
below are Microsoft's; the wording is ours. No prose or sample code
was copied.

Labels (same meaning as in `wim.md`):

- **[derived]**: computed from facts the sources state (for example an
  offset from field order and sizes). Not stated by Microsoft.
- **[reading]**: our interpretation where a source is silent or
  ambiguous.
- **[WIM]**: a link to an observation already recorded in `wim.md`
  §6.1 and in the project's observation record (OBS-036 to OBS-038;
  R4: also OBS-049 to OBS-054). This file adds no new
  observations.
- **[project rule, DEC-0022]** (R4): the project's rule for
  applying reparse points, stated in full in `wim.md` §13.

All integers below are unsigned. Byte order: the SECURITY_DESCRIPTOR
section says a self-relative descriptor travels little-endian with no
padding. [MS-FSCC]'s reparse pages do not state a byte order
**[reading: little-endian, as for the descriptor]**; `wim.md` §9
records the byte order seen in the project's own WIM files. Offsets
are from the start of the structure.

## 1. Reparse tags ([MS-FSCC] "Reparse Tags")

A reparse tag is a 32-bit value that names the owner of a reparse
point. Its bits, from the most significant:

| Mask | Name | Meaning |
|------|------|---------|
| 0x80000000 | M | tag owned by Microsoft; others must clear it |
| 0x40000000 | R | reserved; must be zero in non-Microsoft tags |
| 0x20000000 | N | name surrogate: the entry stands for another name |
| 0x10000000 | D | directory may have children; never with N |
| 0x0FFF0000 | (reserved) | should be zero, ignored on receipt |
| 0x0000FFFF | Value | the tag number |

The masks are **[derived]** from the bit diagram's order and checked
against the listed tag values (both tags below have M and N set).

Tags this project meets:

| Tag | Value | Use |
|-----|-------|-----|
| `IO_REPARSE_TAG_MOUNT_POINT` | 0xA0000003 | mount point / junction (§3) |
| `IO_REPARSE_TAG_SYMLINK` | 0xA000000C | symbolic link (§4) |

The section lists many more Microsoft tags (deduplication, overlay
and WIM-backed files, cloud placeholders, Linux-subsystem special
files and others). It says that the listed tags, except the symbolic
link tag, are processed on the server side and not by a client after
they cross the wire, and that clients should treat their data as
opaque. Many entries add that their meaning is server-side only. It
also says third parties must request a reserved tag value so that
tags do not collide.
**[reading]** "Junction" is the common name for a directory mount
point whose target is another directory; [MS-FSCC] itself uses only
"mount point".

## 2. Generic reparse buffer ([MS-FSCC] "REPARSE_DATA_BUFFER")

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| 0 | 4 | `ReparseTag` | §1 |
| 4 | 2 | `ReparseDataLength` | bytes in `DataBuffer` |
| 6 | 2 | `Reserved` | should be 0; must be ignored |
| 8 | var | `DataBuffer` | owner-defined bytes |

- This form is only for tags with the M bit set. (The driver page adds
  that third parties use a different, GUID-carrying buffer, which is
  out of scope here.)
- The common header is 8 bytes **[derived]**. Because the length is a
  16-bit field, reparse data is at most 65 535 bytes **[derived]**.
  None of the pages read states a smaller system limit (OPEN-RPSD-1).

**WIM relevance [WIM, OBS-036, OBS-037].** A WIM image keeps the tag
in the directory entry (+88) and stores the reparse data "without the
tag and the data length" as a resource (`wim.md` §6.1). In the
symbolic-link resources recorded in OBS-037, the stored bytes begin
with the substitute-name offset field, so the `Reserved` field is not
stored either. So, when an image is applied, the stored resource is
the `DataBuffer`, its size is the `ReparseDataLength`, and the 8-byte
header is rebuilt from the entry's tag with `Reserved` set to zero
**[derived]**.

## 3. Mount point buffer ([MS-FSCC] §2.1.2.5)

Tag must be 0xA0000003.

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | `ReparseTag` |
| 4 | 2 | `ReparseDataLength` |
| 6 | 2 | `Reserved` |
| 8 | 2 | `SubstituteNameOffset` |
| 10 | 2 | `SubstituteNameLength` |
| 12 | 2 | `PrintNameOffset` |
| 14 | 2 | `PrintNameLength` |
| 16 | var | `PathBuffer` |

- `ReparseDataLength` counts from `SubstituteNameOffset` to the end:
  the size of `PathBuffer` plus 8.
- There is **no flags field**. Mount-point names may not contain dot
  directory names (§5).

## 4. Symbolic link buffer ([MS-FSCC] §2.1.2.4)

Tag must be 0xA000000C.

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | `ReparseTag` |
| 4 | 2 | `ReparseDataLength` |
| 6 | 2 | `Reserved` |
| 8 | 2 | `SubstituteNameOffset` |
| 10 | 2 | `SubstituteNameLength` |
| 12 | 2 | `PrintNameOffset` |
| 14 | 2 | `PrintNameLength` |
| 16 | 4 | `Flags` |
| 20 | var | `PathBuffer` |

- `ReparseDataLength` is the size of `PathBuffer` plus 12.
- `Flags` holds one of two values:
  - 0x00000000: the substitute name is a full (absolute) path;
  - `SYMLINK_FLAG_RELATIVE` = 0x00000001: the substitute name is
    relative to the directory that holds the link.
- Symbolic-link names may contain dot directory names (§5).

## 5. Names in the path buffer (§2.1.2.4, §2.1.2.5, §2.1.5)

These rules are the same for both buffer types.

- `PathBuffer` is an array of 16-bit Unicode characters holding two
  strings: the **substitute name** and the **print name**, in either
  order.
- Each offset is in bytes from the first byte of `PathBuffer` (not
  from the start of the structure). Halving it gives the character
  index.
- Each length is in bytes and does **not** include a terminating null,
  if one is present. Whether a null is present is not fixed.
- The **substitute name** is the target the system actually follows.
  The **print name** is meant for display; it should also identify the
  target but is informative only.
- **[derived]** For each name, offset + length must lie within
  `PathBuffer`, and both values should be even. `PathBuffer`'s size is
  `ReparseDataLength` minus 8 (mount point) or minus 12 (symbolic
  link). A buffer that breaks these bounds is malformed.
- Pathnames (§2.1.5): components are separated by a backslash; a
  leading backslash makes the path absolute (evaluated from the root),
  and no leading backslash makes it relative. A pathname is at most
  32 760 characters.
- Dot directory names (§2.1.5.1): "." is the current component and ".."
  the parent. They are allowed in symbolic-link names, not in
  mount-point names.
- The pages do not say which form a full-path substitute name takes
  on a local volume (for example whether it carries a drive or volume
  prefix). That is OPEN-RPSD-2.
- **[WIM, OBS-049] (R4)**: in the project's samples, a
  full-path substitute name on a lettered volume had the form
  `\??\L:\path` and its print name `L:\path`. This settles OPEN-RPSD-2
  for the drive-letter form only; volume-name and other prefixes were
  not sampled.

**WIM relevance, header flag 0x80 (`FLAG_HEADER_RP_FIX`)
[WIM, OBS-036, OBS-037].**

- Points that apply when the flag is set:
  - A symbolic link with `Flags` = 0 and a mount point both carry a
    full-path substitute name, so both are candidates for the capture
    fix-up **[reading]**.
  - A symbolic link with `SYMLINK_FLAG_RELATIVE` set is resolved from
    the link's own directory, so it does not depend on the capture or
    apply root **[reading]**. The samples stored relative targets
    unchanged.
  - The fix-up removes the capture-root part of an absolute target
    that lay inside the captured tree; the stored target is still a
    full path, now without the capture root [WIM, OBS-037]. Which of
    the two names was rewritten, and whether both offsets and lengths
    changed, was not recorded in `wim.md` after R3 (OPEN-RPSD-3).
  - **(R4) [WIM, OBS-049]**: both names are rewritten, the
    drive letter is kept, the offsets and lengths are rewritten to
    match, and the stored layout is substitute name first at offset 0,
    a 2-byte zero, the print name and a 2-byte zero. This settles
    OPEN-RPSD-3 for the drive-letter form.
  - The print name has no effect on what the link resolves to; the
    substitute name does (§5 above).
- A separate point, about the WIM directory entry and not the reparse
  buffer: the 4 bytes at +92 of the directory entry were zero for the
  absolute links and the junction and non-zero for the two relative
  links [WIM, OBS-036]. They lie outside the stored reparse data and
  are not the symbolic-link `Flags` field of §4. Their meaning is
  still open (OPEN-WIM-7, M-13); this file does not settle it.
  - **(R4) [WIM, OBS-052, corrected]**: read as a 32-bit value, +92
    is zero exactly on symbolic links with `Flags` 0 and mount points
    whose target lies inside the captured tree, with
    `FLAG_HEADER_RP_FIX` on, and 0x00010000 otherwise. It does not
    mean the data were changed (a volume-root capture stored such
    entries with nothing stripped). That it marks the targets DISM's
    apply re-bases is a [reading].
- Points that do not depend on the flag: the buffer layouts in §2 to
  §4, the bounds rules above, and the tag values.
- How the product applies rewritten absolute targets to a different
  root or drive letter is product behaviour. (R4) It is now the
  **[project rule, DEC-0022]** in `wim.md` §13 (formerly OPEN-WIM-12):
  - entries with +92 equal to 0x00010000 are written unchanged;
  - entries with +92 zero, in a file with the flag set, in the exact
    observed layout with a drive-letter target, are re-based onto the
    apply root;
  - everything else is refused with a named reason.

  Copied and re-based data must meet this file's §3 to §5 bounds.
  (R5, AUDITED 2026-10-28) The volume-root capture case (OPEN-WIM-13)
  is now
  answered for this DISM build: DISM re-based it exactly as the rule
  predicts [WIM, OBS-059].

## 6. Setting a reparse point (FSCTL_SET_REPARSE_POINT, background)

- The control code takes a reparse buffer (§2 to §4) as input and is
  sent to a handle on the file or directory.
- The page says the calling process must hold the privilege
  `SE_CREATE_SYMBOLIC_LINK_NAME`.
- It states no size limit and no rule about the target's current
  contents. See OPEN-RPSD-1.

## 7. SID ([MS-DTYP] §2.4.2, §2.4.2.2, SID_IDENTIFIER_AUTHORITY)

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| 0 | 1 | `Revision` | must be 0x01 |
| 1 | 1 | `SubAuthorityCount` | at most 15 |
| 2 | 6 | `IdentifierAuthority` | six bytes |
| 8 | 4 × n | `SubAuthority` | n = `SubAuthorityCount` |

- Size is 8 + 4 × `SubAuthorityCount` bytes, so at most 68 bytes
  **[derived]**, always a multiple of 4.
- §2.4.2.2 leaves the byte order of multi-byte fields to the protocol
  using it; for a self-relative descriptor that is little-endian (§9),
  so each `SubAuthority` is little-endian **[derived]**.
- `IdentifierAuthority` is a byte array, not an integer. The listed
  well-known authorities put the significant byte last (for example
  the NT authority is five zero bytes then 0x05) **[reading: it reads
  as a big-endian 48-bit number]**.
- The text form is "S-1-" then the authority, then each sub-authority,
  joined by hyphens. The last sub-authority is the relative
  identifier. Consumers should rely only on the structure being well
  formed.

## 8. ACL and ACE header ([MS-DTYP] "ACL", §2.4.4.1)

ACL header, 8 bytes **[derived]**:

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| 0 | 1 | `AclRevision` | 0x02 or 0x04 |
| 1 | 1 | `Sbz1` | must be 0 |
| 2 | 2 | `AclSize` | whole ACL in bytes, ACEs included |
| 4 | 2 | `AceCount` | number of ACEs |
| 6 | 2 | `Sbz2` | must be 0 |

- `ACL_REVISION` (0x02) allows ACE types 0x00 to 0x03 and 0x11 to
  0x13. `ACL_REVISION_DS` (0x04) allows types 0x05 to 0x08 and 0x11,
  and is for directory-service objects. **[reading]** File-system
  descriptors therefore normally use 0x02.
- ACEs follow the header back to back. A reader walks them using
  `AclSize`, `AceCount` and each ACE's own size.
- A DACL controls access; a SACL holds audit entries and at most one
  mandatory-label entry. Each list must hold only its own ACE types.

ACE header, 4 bytes, at the start of every ACE:

| Offset | Size | Field |
|--------|------|-------|
| 0 | 1 | `AceType` |
| 1 | 1 | `AceFlags` |
| 2 | 2 | `AceSize` |

- `AceSize` is the size of the whole ACE in bytes, header included
  **[reading]**. It must be a multiple of 4 and may exceed the sum of
  the fields; extra bytes are ignored except in callback ACEs.
- `AceType` values are 0x00 to 0x13. The common ones: 0x00 access
  allowed, 0x01 access denied, 0x02 system audit, 0x11 mandatory label.
  Several values are reserved.
- `AceFlags`: 0x01 object inherit, 0x02 container inherit, 0x04 no
  propagate, 0x08 inherit only, 0x10 inherited, 0x40 audit success,
  0x80 audit failure.
- **[derived]** An ACL is well formed when `AclSize` is at least 8,
  the `AceCount` ACEs fit inside `AclSize`, and each `AceSize` is at
  least 4 and a multiple of 4.

## 9. Self-relative security descriptor ([MS-DTYP] §2.4.6)

Fixed part, 20 bytes **[derived]**:

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| 0 | 1 | `Revision` | must be 1 |
| 1 | 1 | `Sbz1` | resource-manager bits only if RM set |
| 2 | 2 | `Control` | flags below |
| 4 | 4 | `OffsetOwner` | 0 = no owner SID |
| 8 | 4 | `OffsetGroup` | 0 = no group SID |
| 12 | 4 | `OffsetSacl` | 0 = no SACL |
| 16 | 4 | `OffsetDacl` | 0 = no DACL |

- **Self-relative** means the whole descriptor is one contiguous block
  and every reference is an offset from its first byte. The owner SID,
  group SID, SACL and DACL may appear in **any order** after the fixed
  part; only the offsets locate them. The **absolute** form holds
  pointers, so it cannot be sent as an opaque structure; it is the RPC
  representation (§2.4.6.1, not summarised).
- The self-relative form is required for transmission over a wire and
  for storage on secondary media. When transmitted, it is sent
  little-endian with no padding. **[reading]** Stored copies use the
  same byte order; the section states it for transmission only.
- The SR flag must be set in a self-relative descriptor.
- `OffsetSacl` must be valid if SP is set and must be zero if SP is
  clear. `OffsetDacl` follows the same rule with DP.
- `OffsetOwner` must be valid unless OD is set; `OffsetGroup` likewise
  with GD. A zero offset means that part is absent.
- Each SID or ACL that is present has a length that is a multiple of 4.
  (The section's text says "SID" under the SACL and DACL entries and
  "GroupOwner" for the group offset; **[reading]** these mean the ACL
  and `OffsetGroup`.)

`Control` flags. Masks are from the driver page; the MS-DTYP diagram
gives the same order, SR at the top:

| Mask | MS-DTYP | Driver-page name | Meaning |
|------|---------|------------------|---------|
| 0x8000 | SR | `SE_SELF_RELATIVE` | self-relative form |
| 0x4000 | RM | `SE_RM_CONTROL_VALID` | `Sbz1` is meaningful |
| 0x2000 | PS | `SE_SACL_PROTECTED` | SACL not inherited into |
| 0x1000 | PD | `SE_DACL_PROTECTED` | DACL not inherited into |
| 0x0800 | SI | `SE_SACL_AUTO_INHERITED` | SACL made by inheritance |
| 0x0400 | DI | `SE_DACL_AUTO_INHERITED` | DACL made by inheritance |
| 0x0200 | SC | `SE_SACL_AUTO_INHERIT_REQ` | SACL to be computed |
| 0x0100 | DC | `SE_DACL_AUTO_INHERIT_REQ` | DACL to be computed |
| 0x0080 | SS | `SE_SERVER_SECURITY` | server ACL requested |
| 0x0040 | DT | `SE_DACL_UNTRUSTED` | see note |
| 0x0020 | SD | `SE_SACL_DEFAULTED` | SACL set by default |
| 0x0010 | SP | `SE_SACL_PRESENT` | SACL present |
| 0x0008 | DD | `SE_DACL_DEFAULTED` | DACL set by default |
| 0x0004 | DP | `SE_DACL_PRESENT` | DACL present |
| 0x0002 | GD | `SE_GROUP_DEFAULTED` | group set by default |
| 0x0001 | OD | `SE_OWNER_DEFAULTED` | owner set by default |

- Note on 0x0040: MS-DTYP names it "DACL trusted" and the driver page
  "DACL untrusted". The two descriptions differ. **[reading]** Only
  the mask matters for storing and restoring a descriptor.
- When SC and SI are both set, the result keeps SI only; DC and DI
  likewise.

**[derived]** A self-relative descriptor is well formed when it is at
least 20 bytes, `Revision` is 1, SR is set, each non-zero offset is at
least 20 and leaves room inside the block for a well-formed SID (§7)
or ACL (§8), the SACL and DACL offsets agree with SP and DP as above,
and no part runs past the block's end. [MS-DTYP] does not say whether
the parts may overlap (OPEN-RPSD-4).

**WIM relevance [WIM, OBS-038].**

- A WIM image stores each distinct descriptor once and has entries
  refer to it by index (`wim.md` §6, §6.1).
- After DISM's apply, descriptors matched the source when compared as
  SDDL text. The descriptors of the 5 reparse points were not
  compared (the sample manifests hold no SDDL for them).
- Whether the stored bytes are exactly the self-relative form above,
  with SR set, was **open** after R3 (OPEN-WIM-7, M-14, sample S13D).
  This section is the reference that sample should be checked against.
- **(R4) [WIM, OBS-054, corrected]**: every stored descriptor seen
  has `Revision` 1 and SR set, `OffsetSacl` 0 with SP clear, and
  owner, group and DACL inside the block, so it is the self-relative
  form above. Several stored descriptors set PS although SP is clear;
  the well-formedness rule
  above does not forbid that. Byte equality with what Windows itself
  returns is still **open**: R4 compared only with .NET's
  re-serialisation (S13D, narrowed).
- **(R4) [WIM, OBS-053, corrected]**: DISM's apply wrote the
  stored descriptor faithfully on every reparse point. Seven file
  links that had their own explicit DACL in the source were stored at
  capture with the descriptor shared by ordinary files, so they lost
  that DACL at capture.
- These points do not depend on `FLAG_HEADER_RP_FIX`.

## 10. Security notes (for the clean side)

- **[reading]** Reparse data and descriptors in an image are input
  from the image, not trusted structure. §2, §5, §8 and §9 give the
  bounds a conforming buffer meets.
- The driver page says a descriptor whose DACL is absent, or present
  but null, gives everyone full access. **[reading]** An applied file
  without a DACL is therefore unprotected; a descriptor that lacks one
  is a security-relevant difference, not a formatting detail.
- **[reading]** An absolute symbolic link or mount point in an image
  can point outside the applied tree. Under `FLAG_HEADER_RP_FIX`,
  targets outside the captured tree are a separate case (OPEN-WIM-7,
  S13C). (R4) DISM stores and applies those unchanged
  [WIM, OBS-051], and the product's handling is the
  [project rule, DEC-0022] in `wim.md` §13: copied as stored, re-based
  only in the observed rewritten form, otherwise refused. The rule
  never invents a target beyond re-basing a stored one onto the apply
  root. An applied
  absolute target can still name a path outside the applied tree.

## 11. Open questions

- **OPEN-RPSD-1**: is there a system limit on reparse data size below
  the 65 535 bytes the 16-bit field allows? None of the pages read
  states one.
- **OPEN-RPSD-2**: which form does a full-path substitute name take on
  a local NTFS volume (drive-letter, volume-name or another prefix),
  and how does the print name differ? [MS-FSCC] §2.1.5 has an absolute
  pathname start at the root directory and says nothing of drive or
  volume prefixes. To be settled from the project's own samples (S13B,
  S13C), not from product material. **(R4) Settled for the
  drive-letter form** (OBS-049, §5); other prefixes not sampled.
- **OPEN-RPSD-3**: under `FLAG_HEADER_RP_FIX`, does the fix-up change
  the substitute name, the print name or both, and are the offsets and
  lengths rewritten to match? Same samples. **(R4) Settled for
  the drive-letter form**: both names, with offsets and lengths
  (OBS-049, §5).
- **OPEN-RPSD-4**: may the parts of a self-relative descriptor overlap,
  or share bytes? [MS-DTYP] is silent.
- Related, not settled here: OPEN-WIM-7 (M-13, M-14) and OPEN-WIM-12
  in `wim.md` §13. (R4) OPEN-WIM-12 is now settled for the
  project by DEC-0022; OPEN-WIM-13 (volume-root capture) is closed
  for the project (R5, AUDITED 2026-10-28; OBS-059).

## 12. Not summarised

- The other reparse buffers: NFS, Linux-subsystem symbolic link, and
  the GUID-carrying third-party form.
- The body layouts of individual ACE types (access mask, object and
  callback ACEs, conditional expressions, resource attributes).
- SDDL text syntax and the RPC (absolute) form of the descriptor.
