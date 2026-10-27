# OS images and deployment packages (IMG-1, IMG-2 for milestone M2)

Status: AUDITED, partial (spec run M2, 2026-10-26; re-audit round 1
approved). OPEN: REQ-IMG-002, 015, 016, 018, 034, 036, 039, 043, 044.
REQ range in use: `REQ-IMG-001` to `REQ-IMG-054`. Numbers
are grouped by topic in tens, so some numbers are unused.

## Purpose

An operator must be able to bring a Windows installation image into the
product and combine it with everything else a device needs into a named
**deployment package**. Later milestones use the package to install a
device. This spec covers what a package is, what an operator can do with
packages, and how Windows images in WIM format are uploaded, checked,
stored and shown.

M2 covers three things: storing content and keeping it intact; packages
built from one uploaded image edition and one imported preinstall
environment (`specs/preinstall-env.md`); and what operators can do with
both. Anything else a package will later carry is defined in the area
spec that needs it (CFG, DRV, AGT, SEQ), not here.

## Actors and roles

- **Operator**: a person who manages content through the product's
  operator interface. What each operator may do is governed by
  `specs/operator-access.md`.
- **Product**: the central service that receives, checks, stores and
  serves content.
- **Device**: the machine that is later installed from a package. Not an
  actor in M2.

## Definitions

- **Deployment package** ("package"): a named, operator-defined set of
  content and settings used to install one operating system on a device.
- **Image file**: a file in Microsoft's Windows Imaging (WIM) format
  (`specs/standards/wim.md`).
- **Edition**: one of the images inside an image file, identified by its
  index (numbered from 1), with a name and description from the file's
  metadata. One image file can hold several Windows editions
  (`specs/standards/wim.md` §1, §7).
- **Content**: any file the product stores for later delivery to devices
  (image files, preinstall environments, package files).
- **Ready**: content that has been received in full, checked and recorded
  (REQ-IMG-020), and so may be used.

Standards background: `specs/standards/wim.md`,
`specs/standards/wim-compression.md`, `specs/standards/http-tls.md`,
`specs/standards/security-baseline.md`.

## Requirements

### Package contents

### REQ-IMG-001: Minimum content of a package, and room to grow

1. **M2 minimum.** A package is usable only when it names exactly one
   image edition (REQ-IMG-041) and exactly one preinstall environment
   (`specs/preinstall-env.md`), and both are ready (REQ-IMG-020).
2. **Later content.** The package is also where later areas attach the
   other content and settings a device install needs. Each such item is
   defined, with its own sources, in the spec of the area that owns it
   (CFG, DRV, AGT, SEQ). When an area is built, its items join the
   package without changing the rules in this spec. This spec does not
   list them.

- Priority: MUST
- Source: SRC-001, SRC-004 (outcome only: a package pairs an OS image
  with what is needed to install it, including the preinstall
  environment)
- Basis: project design for the M2 minimum in item 1 and the split of
  content between area specs in item 2 (not described product
  behaviour)
- Standards: none
- Status: AUDITED

### REQ-IMG-002: Name and description

Every package has a name and may have a description. The product
enforces maximum lengths for both and tells the operator when a value is
too long, rather than cutting it short silently.

- Priority: SHOULD
- Source: SRC-004 (length limits are enforced for another kind of
  operator-defined object; values not given)
- Standards: none
- Status: OPEN (What are the maximum lengths, and must names be unique?
  No public source gives values.)

### REQ-IMG-003: Packages with many files

A package can hold more than 100 files. Creating, uploading to, editing,
cloning and deleting such a package all work.

- Priority: MUST
- Source: SRC-004, SRC-007 (creating, uploading to, editing and
  deleting a package of that size)
- Basis: cloning is derived from REQ-IMG-013 (a clone holds every file
  of the original)
- Standards: none
- Status: AUDITED

### REQ-IMG-004: Empty files are refused

The product refuses to add a zero-length file to a package and tells the
operator why.

- Priority: MUST
- Source: SRC-004, SRC-007
- Standards: none
- Status: AUDITED

### REQ-IMG-005: Files must suit their purpose

When an operator adds a file to a package for a particular purpose, the
product checks that the file is of a kind that purpose accepts and
refuses it otherwise, when the file is added rather than at install
time. For example, Windows update packages are expected as Microsoft
update (`.msu`) files, and driver packages as ZIP or CAB archives. The
accepted kinds for each purpose are set in the spec for that purpose.

- Priority: SHOULD
- Source: SRC-004
- Standards: none
- Status: AUDITED

### REQ-IMG-006: Adding a file that is already present

If an operator adds a file to a package that already holds a file of the
same name for the same purpose, the edit does not fail and the package
does not end up broken or holding two conflicting copies. The operator is
told what happened.

- Priority: SHOULD
- Source: SRC-004
- Standards: none
- Status: AUDITED

### Operator actions on packages

### REQ-IMG-010: Create a package

An operator can create a new package by giving it a name, choosing an
image edition (REQ-IMG-041) and a preinstall environment, and adding any
other content and settings it needs.

- Priority: MUST
- Source: SRC-001, SRC-004
- Standards: none
- Status: AUDITED

### REQ-IMG-011: View packages

An operator can list the packages and open any one to see its name,
description, the image file and edition it uses (index and name), its
preinstall environment, the files and settings it holds, and its status
(REQ-IMG-020). Values the product treats as secret are not shown
(REQ-IMG-054).

- Priority: MUST
- Source: SRC-001, SRC-004
- Standards: none
- Status: AUDITED

### REQ-IMG-012: Edit a package

An operator can change a package's name, description, image edition,
preinstall environment, files and settings. After a successful edit the
package is complete and usable. A failed edit leaves the package as it
was before the edit and tells the operator why.

- Priority: MUST
- Source: SRC-004 (edits must work, including for large packages); last
  two sentences derived from REQ-IMG-021
- Standards: none
- Status: AUDITED

### REQ-IMG-013: Clone a package

An operator can make a copy of a package under a new name. The copy holds
every file and setting of the original, including values the product
treats as secret, and is usable at once. Cloning does not change the
original.

- Priority: MUST
- Source: SRC-004
- Standards: none
- Status: AUDITED

### REQ-IMG-014: Delete a package

An operator can delete a package. Before deleting, the product warns the
operator and asks for confirmation. Deletion works for large packages.

- Priority: MUST
- Source: SRC-004
- Standards: none
- Status: AUDITED

### REQ-IMG-015: Deleting content that is in use

What happens when an operator deletes a package that a device is being
installed from, or an image file or preinstall environment that one or
more packages use, is not settled. Whatever the rule, a deletion must not
leave a package that refers to content that no longer exists without the
operator being told.

- Priority: MUST (the last sentence)
- Source: none (derived from REQ-IMG-020)
- Standards: none
- Status: OPEN (Is deletion of in-use content refused, deferred until no
  longer used, or allowed with the dependent packages marked unusable? No
  public source covers this.)

### REQ-IMG-016: Package versions

Whether packages keep a history of versions that an operator can view or
return to is not settled.

- Priority: SHOULD
- Source: none
- Standards: none
- Status: OPEN (Are packages versioned? Does an edit create a new version
  while devices already being installed keep the old one? No public source
  mentions versioning.)

### REQ-IMG-017: Remove several files from a package at once

When editing a package, an operator can select several of its files and
remove them in one action. The rules of REQ-IMG-012 apply: either all
the selected files are removed and the package stays usable, or nothing
changes and the operator is told why.

- Priority: SHOULD
- Source: SRC-004 (removing several files from one package)
- Basis: the all-or-nothing rule is derived from REQ-IMG-012
- Standards: none
- Status: AUDITED

### REQ-IMG-018: Delete several packages at once

Whether an operator can delete several packages in one action is not
settled.

- Priority: MAY
- Source: none
- Standards: none
- Status: OPEN (Is bulk deletion of packages offered? No public source
  read describes it.)

### Status and failure

### REQ-IMG-020: Status is visible

For each uploaded image file, and for each package, the operator can see
whether it is still being received or processed, is ready for use, or has
failed. Only ready content can be used in an install, and a package is
usable only when all content it refers to is ready.

- Priority: MUST
- Source: SRC-004, SRC-005 (processing states exist and can fail); the
  last sentence is derived from REQ-IMG-050
- Standards: none
- Status: AUDITED

### REQ-IMG-021: Nothing stays stuck in progress

Processing of an upload, a package creation or a package edit always ends
in either ready or failed, within a bounded time. Content that cannot be
finished is marked failed with a reason. The operator never has to clean
up content left half-processed by hand.

- Priority: MUST
- Source: SRC-004, SRC-005
- Standards: none
- Status: AUDITED (the time bound is part of OPEN-IMG-L1)

### REQ-IMG-022: Clear failure reasons

When an upload, check or package change fails, the operator is told what
failed and why, in terms they can act on (for example: not a WIM file,
file damaged, compression method not supported, file empty, name too
long).

- Priority: MUST
- Source: SRC-004, SRC-005
- Standards: none
- Status: AUDITED

### Uploading Windows images

### REQ-IMG-030: Upload a WIM image file

An operator can upload a Windows installation image in WIM format to the
product. Once checked (REQ-IMG-037) it becomes available for use in
packages.

- Priority: MUST
- Source: SRC-001, SRC-004
- Standards: Microsoft WIM paper (SRC-047); `specs/standards/wim.md`
- Status: AUDITED

### REQ-IMG-031: Multi-gigabyte files

Uploads of image files larger than 10 GB succeed. The product has no
built-in upload limit below that. Any larger limit the product sets is
stated to the operator, and a file over it is refused with that reason
before or at the start of the upload, not after the whole file has been
sent.

- Priority: MUST
- Source: SRC-004 (uploads over 1 GB and over 10 GB must work); the
  limit statement is derived from REQ-IMG-022
- Standards: RFC 9110 §15.5.14 (413) if HTTP is used
- Status: AUDITED (the maximum size is OPEN-IMG-L1)

### REQ-IMG-032: Large files do not time out after upload

The checks and processing that follow the upload of a very large image
file complete without the operation timing out or being abandoned while
it is still making progress.

- Priority: MUST
- Source: SRC-004
- Standards: none
- Status: AUDITED

### REQ-IMG-033: File names with spaces

Image files whose names contain spaces upload, store and are later
delivered to devices correctly.

- Priority: MUST
- Source: SRC-004
- Standards: none
- Status: AUDITED

### REQ-IMG-034: Upload progress

While a large file uploads, the operator can see how much has been sent.

- Priority: SHOULD
- Source: none
- Standards: none
- Status: OPEN (Is upload progress shown? No public source says so.)

### REQ-IMG-035: Interrupted uploads leave nothing usable

If an upload stops before the whole file has arrived (connection lost,
operator cancels, product restarts), no image becomes ready from it. The
operator can see that the upload did not complete, and the partial data
is removed or is reused only by a resume that completes the file and
passes the full check (REQ-IMG-036, REQ-IMG-037).

- Priority: MUST
- Source: none
- Basis: project requirement, not described product behaviour: DEC-0011
  item 1 (only verified content is used), through REQ-IMG-050
- Standards: none
- Status: AUDITED

### REQ-IMG-036: Resume an interrupted upload

An operator can resume an interrupted upload from where it stopped rather
than send the whole file again.

- Priority: MAY
- Source: none
- Standards: RFC 9110 §14 (conditional; `specs/standards/http-tls.md` §5)
- Status: OPEN (Must uploads be resumable? No public source covers
  resuming.)

### REQ-IMG-037: Check the image file before it is ready

Before an uploaded image file becomes ready, the product checks that it
is a well-formed WIM file and refuses it, with a reason (REQ-IMG-022), if
it is not. At least:

- the file is recognised as a WIM file (signature and header);
- every location and size the file declares lies within the file;
- the number of images the file declares agrees with the images it
  describes, and each image's index, name and description can be read;
- if the file carries an integrity table, every hash in it matches;
- the file uses a compression method the product supports
  (REQ-IMG-038).

A damaged or hostile file must not crash the product, stall other work,
or use unbounded memory or time; the check simply fails.

- Priority: MUST
- Source: SRC-005 (failed uploads must give an error); SRC-047, SRC-048
  (the format and Microsoft's own integrity check, which stops an apply
  of a damaged file)
- Standards: `specs/standards/wim.md` §2 to §8, §12, §14
- Status: AUDITED

### REQ-IMG-038: Image files the product cannot handle

An image file that the product cannot handle is refused with a reason
that names the problem. This covers at least: a compression method the
product does not support, one part of a split (spanned) set, a file that
holds only file data or only metadata, and files in Microsoft's
recovery (`.esd`) compression. Image files that use LZMS ("solid")
compression are refused in M2. Which of the others the product will
later accept is not settled.

- Priority: MUST
- Source: SRC-047 (header flags), SRC-048, SRC-049 (split sets and
  recovery compression), SRC-056 (LZMS has no published format)
- Basis: DEC-0006 item 4 for refusing LZMS in M2 (project decision, not
  described product behaviour)
- Standards: `specs/standards/wim.md` §2, §10;
  `specs/standards/wim-compression.md` §5, §7
- Status: AUDITED (which compression methods M2 supports is OPEN-IMG-C1)

### REQ-IMG-039: Split image sets

An operator can upload a split image set (all its parts) and use it like
a single image file.

- Priority: MAY
- Source: SRC-049 (Microsoft splits images for FAT32 and DVD limits)
- Standards: `specs/standards/wim.md` §10
- Status: OPEN (Must split sets be accepted? No public source says the
  product accepts them.)

### Editions

### REQ-IMG-040: Show the editions in an image file

For each ready image file the operator can see every image it contains,
each with its index, name, description and size, as recorded in the
file.

- Priority: MUST
- Source: SRC-004 (images with many indexes); SRC-050 (the per-image
  information Microsoft's tools report)
- Standards: `specs/standards/wim.md` §7
- Status: AUDITED

### REQ-IMG-041: Choose one edition per package

When an operator puts an image file into a package, they choose exactly
one of its images (by index; name and description are shown to help).
The package then installs only that image. The choice is shown wherever
the package is shown (REQ-IMG-011).

- Priority: MUST
- Source: SRC-004 (outcome only: image files with several indexes are
  supported); SRC-051 (Setup selects one image by index, name or
  description)
- Basis: "exactly one" is project design, derived from the definition
  of a package (it installs one operating system) and REQ-IMG-001
- Standards: Microsoft Setup image selection by index, name or
  description (SRC-051); `specs/standards/wim.md` §11
- Status: AUDITED

### REQ-IMG-042: Image files with many editions

Image files containing more than 10 images work, and any of their images
can be chosen.

- Priority: MUST
- Source: SRC-004
- Standards: none
- Status: AUDITED

### REQ-IMG-043: Show what an edition contains

For the chosen image the operator can see which Windows release, edition,
processor architecture and languages it holds, so that they can tell
whether it is supported (`specs/os-support.md`).

- Priority: SHOULD
- Source: SRC-050 (Microsoft's tools report these per image)
- Standards: `specs/standards/wim.md` §7
- Status: OPEN (Where does this information come from? Microsoft does not
  publish the layout of the image metadata that holds it (OPEN-WIM-8). Is
  it read from the file by a documented means, or entered and confirmed
  by the operator?)

### REQ-IMG-044: One image file in several packages

One uploaded image file can be used by several packages, including with
different editions chosen, without being uploaded again.

- Priority: MAY
- Source: none
- Standards: none
- Status: OPEN (Is an image file shared between packages, or does each
  package hold its own copy? No public source says.)

### Integrity and protection

### REQ-IMG-050: Content is verified before every use

When content becomes ready, the product records a cryptographic digest of
it. Every time the content is used afterwards (served to a device, copied
to a local cache, or read for an install) it is checked against that
digest first. Content that does not match is not used, and the failure is
reported to the operator.

- Priority: MUST
- Source: SRC-004 (all files are hash-checked before imaging proceeds)
- Basis: project requirement, not described product behaviour, for the
  "when ready" and "every use" points: DEC-0011 item 1
- Standards: `specs/standards/security-baseline.md` (choice of hash is a
  clean-side decision)
- Status: AUDITED

### REQ-IMG-051: The format's own hashes are not trusted

The SHA-1 hashes inside a WIM file are used only to detect damage
(REQ-IMG-037). They are not treated as proof that the file is the one the
operator intended, because anyone who can change the file can recompute
them. The product's own digest (REQ-IMG-050) is the integrity control.

- Priority: MUST
- Source: SRC-047
- Standards: `specs/standards/wim.md` §14
- Status: AUDITED

### REQ-IMG-052: Ready content does not change

Once content is ready, its bytes are never changed in place. A change an
operator makes produces new content with its own digest.

- Priority: SHOULD
- Source: none
- Basis: project requirement, not described product behaviour: DEC-0011
  item 1, through REQ-IMG-050
- Standards: none
- Status: AUDITED

### REQ-IMG-053: Protected upload channel

Uploads, and all operator sessions that manage content, run over TLS
configured as NIST SP 800-52 Rev. 2 requires for U.S. Government systems,
and only for an authenticated operator allowed to perform the action
(`specs/operator-access.md` REQ-RBAC-001, REQ-RBAC-005).

- Priority: MUST
- Source: none
- Basis: project requirement, not described product behaviour: DEC-0007
  (operator TLS with client certificates) and DEC-0011 item 3 (TLS per
  SP 800-52 Rev. 2)
- Standards: RFC 8446 (now RFC 9846); NIST SP 800-52 Rev. 2 [primary not
  read]; `specs/standards/http-tls.md` §6, §7
- Status: AUDITED (the TLS settings themselves depend on OPEN-TLS-1 in
  `specs/standards/http-tls.md`)

### REQ-IMG-054: Secret values in packages

Packages can hold secret values (for example a local administrator
password). The product never displays such a value back after it is
entered, never writes it to logs or audit records, and stores it
protected. A clone (REQ-IMG-013) carries the protected value without
revealing it.

- Priority: MUST
- Source: SRC-004 (packages hold administrator passwords, and clones
  must keep them)
- Basis: project requirement, not described product behaviour, for the
  protection points: DEC-0011 item 2
- Standards: none
- Status: AUDITED

## States and transitions

**Image file.** *Receiving*: the upload is in progress (REQ-IMG-034).
*Checking*: the whole file has arrived and is being checked
(REQ-IMG-037). *Ready*: checked and recorded with its digest
(REQ-IMG-050); its editions can be listed and chosen. *Failed*: the
upload was interrupted (REQ-IMG-035) or the check failed; a reason is
shown (REQ-IMG-022). *Deleted*: removed by an operator (rules for content
in use are OPEN, REQ-IMG-015). Receiving and Checking always end in Ready
or Failed (REQ-IMG-021).

**Package.** *Being created or edited*: changes are being applied.
*Ready*: all content it refers to is ready (REQ-IMG-020). *Failed*: a
change could not be applied; the package keeps its previous contents
(REQ-IMG-012). *Not usable*: content it refers to is missing or failed
(REQ-IMG-015). *Deleted*.

## Limits

- More than 100 files per package (REQ-IMG-003); no maximum is known.
- Image files over 10 GB (REQ-IMG-031); no maximum is known.
- More than 10 editions per image file (REQ-IMG-042).
- Format limits (32 KB chunks, 64-bit offsets, part numbers, SHA-1
  hashes): `specs/standards/wim.md` §12.
- **OPEN-IMG-L1**: maximum image file size, maximum package size and file
  count, name and description lengths, and time bounds for processing.

## Error behaviour (as the operator observes it)

- **Not a WIM file, or damaged**: refused after upload with a reason
  (REQ-IMG-037, REQ-IMG-022). Nothing becomes ready.
- **Unsupported variant** (compression, split part, `.esd`): refused with
  a reason that names the variant (REQ-IMG-038).
- **Upload interrupted**: shown as not completed; nothing becomes ready
  (REQ-IMG-035).
- **Too large**: refused at or before the start, with the limit stated
  (REQ-IMG-031).
- **Empty or wrong kind of file in a package**: refused when added
  (REQ-IMG-004, REQ-IMG-005).
- **Content fails its digest check later**: not used; reported
  (REQ-IMG-050).
- **Processing fails**: the item is marked failed with a reason and is
  never left stuck (REQ-IMG-021).

## Security expectations (summary)

- Uploaded files are untrusted input. Checking them must be bounded in
  memory and time and must not crash the product (REQ-IMG-037).
- Only complete, checked content with a recorded digest is used, and the
  digest is checked again on every use (REQ-IMG-050, REQ-IMG-035).
- The WIM format's own hashes are not a trust mechanism (REQ-IMG-051).
- Uploads and content management happen only over TLS, by authenticated
  and authorised operators (REQ-IMG-053, `specs/operator-access.md`).
- Secret values in packages are never shown, logged or audited in clear
  (REQ-IMG-054).

## Standards relied on

- Microsoft WIM format paper and Microsoft Learn DISM and Setup pages:
  `specs/standards/wim.md`.
- [MS-XCA], Microsoft Cabinet LZX format, [MS-PATCH], Compression API:
  `specs/standards/wim-compression.md`.
- RFC 9110, RFC 8446 / RFC 9846, NIST SP 800-52 Rev. 2:
  `specs/standards/http-tls.md`.
- FIPS 186-5, RFC 5280, NIST SP 800-57 Part 1:
  `specs/standards/security-baseline.md`.

## Out of scope / unknown

Out of scope for M2 (see `specs/INDEX.md`):

- **IMG-3**: downloading Microsoft OS media directly into the product
  (P2).
- **IMG-4**: capturing a reference device as a new image (P2).
- **IMG-5**: reusing WIM files exported from other imaging systems (P3).
  Any well-formed WIM the product supports is accepted by REQ-IMG-030
  regardless of origin; IMG-5 covers anything beyond that.
- **IMG-6**: bulk updates of packages by script (P3).
- What answer files, drivers, agent installers, scripts and update
  packages do: CFG, DRV, AGT, SEQ.
- Linux images (OS-2).
- How content reaches local caches near devices (RELAY-2, RELAY-3).

Unknown (OPEN):

- **OPEN-IMG-L1**: see Limits.
- **OPEN-IMG-C1**: which WIM compression methods the product supports in
  M2. Microsoft publishes the XPRESS Huffman and Cabinet LZX formats, but
  not how WIM applies them (`specs/standards/wim-compression.md`
  OPEN-WIMC-1, OPEN-WIMC-2), and LZMS is not published at all. LZMS is
  refused in M2 (DEC-0006 item 4, REQ-IMG-038). Gaps in the published
  formats are filled only by observing WIM files the project makes with
  Microsoft's own tools (DEC-0006). Which of XPRESS and LZX M2 supports
  still needs a product decision.
- REQ-IMG-002, 015, 016, 018, 034, 036, 039, 043, 044: see the question
  in each Status line.
- Whether the product's operator interface is a web console, an API, a
  command-line tool, or several (`specs/operator-access.md` OPEN-ACC-3).
