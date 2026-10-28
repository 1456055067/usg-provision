# Standards summary: Windows Imaging (WIM) file format

Topic 9 of the standards reading list. This is our summary of Microsoft's
public description of the WIM format, for IMG-2 (upload and validation),
IMG-4 and IMG-5 (later), and PE-1 (the Windows PE boot image is itself a
WIM file).

Sources:

- **WIM paper**: Microsoft, "Windows Imaging File Format (WIM)", a public
  white paper on the Microsoft Download Center (listing version 1.1,
  2024; document body written 2007, last revised 2017). The paper says
  its content may be used to build WIM creation or extraction tools. Its
  headings are not numbered, so this file cites them by heading name.
- Microsoft Learn: the WIM overview (Windows 7 archive), the DISM image
  management options, splitting a WIM, taking inventory of an image, the
  unattend `MetaData` key, the `WIMSetImageInformation` API page, Windows
  Setup supported platforms, and the `SYSTEM_INFO` structure.
- **Observation record (clean side, not Microsoft text)**:
  `docs/formats/wim-observed.md`, records OBS-001 to OBS-058, made under
  project decision 0006 from WIM files the project built itself with
  Microsoft's DISM. Records come from four runs: **R1** (OBS-001 to
  OBS-017; workflow run 40535666995, commit ba23bed), **R2**
  (OBS-018 to OBS-023; workflow run 40599556702, commit 5d3c8c7),
  **R3** (OBS-024 to OBS-048; workflow run 40754869824, commit
  27f7237) and **R4** (OBS-049 to OBS-058; workflow run 40766748266,
  commit 4ba76cd). All four runs used DISM file version
  10.0.26100.32860 on Windows build 26100.33650. The M3
  boot-protocol review of R4 (findings BOOT-R4-001 to 008) led to
  corrections of some R4 records, committed at d38b584; this file
  cites the corrected records, marked "(OBS-0nn, corrected)".

Labels: **[derived]** means we computed it from facts the sources state
(for example, offsets from field order and sizes). **[reading]** means our
interpretation where the source is silent or ambiguous. Neither is stated
by Microsoft. Each has an OPEN item in §13 where it matters.

Two further labels were added in M2 fix round 1 (drift):

- **[observed]** marks what was seen in the R1 to R4 files, cited
  by record (OBS-nnn). It is evidence about those files only, not a
  statement by Microsoft, and says nothing about other DISM builds or
  other tools. The R2 notes were added after run R2 (2026-10-27). The
  R3 notes were added after run R3 and audited (2026-10-28). The R4
  notes (marked R4) were added after run R4 and audited (2026-10-28).
  An observation can confirm or contradict a [derived] or [reading]
  point, or the paper itself; each note below says which.
- **[project rule]** marks a rule the product applies that neither
  Microsoft nor an observation states as a format fact. Each names the
  decision it rests on, and says "pending owner acceptance" while that
  decision is still Proposed.

The product also applies further fail-closed rules to WIM input. They
are recorded in project decisions and the observation record, not here.

## 1. Model (WIM paper, introduction and "WIM File Structure")

- A WIM is a file-based image format. One WIM file can hold one or more
  images (a captured volume each).
- Identical file content is stored once and shared by every image that
  contains it. DISM's append operation stores only one copy of each unique
  file (DISM image management, `/Append-Image`).
- A WIM file has one compression type for all its resources. Images can be
  appended only with the same compression type (DISM, `/Append-Image`).
- A WIM file contains up to six kinds of part: the **header**, **file
  resources** (captured file data), one **metadata resource** per image
  (directory tree, attributes, security), the **lookup table** (where each
  resource is), **XML data** (descriptive information), and an optional
  **integrity table** (hashes for checking the file).
- Capture, as the paper describes it: write a header with initial values,
  scan the source into an in-memory metadata resource, write file data in
  32 KB chunks while recording each chunk's location, then write the
  metadata resource, lookup table and XML data, and finally update the
  header.
- Apply: read the header, load the image's metadata resource, use the
  lookup table to find file resources, create the directory tree, then
  write files and apply their attributes.

## 2. Header (WIM paper, "WIM Header")

The paper gives the header as a packed structure. It lists field order,
types and meanings but not offsets. The offsets below are **[derived]**
from the field order and type sizes with no padding, which the structure's
"packed" name suggests.

| Offset | Size | Field | Meaning (paper) |
|--------|------|-------|-----------------|
| 0 | 8 | `ImageTag` | Signature. The C string `"MSWIM\0\0"`: the five ASCII letters `MSWIM` followed by zero bytes to fill 8 bytes **[reading]** |
| 8 | 4 | `cbSize` | Size of the header in bytes |
| 12 | 4 | `dwVersion` | Format version. It increases if the format changes. The paper gives no value (OPEN-WIM-2) |
| 16 | 4 | `dwFlags` | Header flags (table below) |
| 20 | 4 | `dwCompressionSize` | The paper describes this as the size of the compressed file in bytes; R1 files contradict this (OBS-004, see below; OPEN-WIM-3) |
| 24 | 16 | `gWIMGuid` | A unique identifier |
| 40 | 2 | `usPartNumber` | This file's part number in a split set; 1 unless split (§10) |
| 42 | 2 | `usTotalParts` | Number of parts in the split set |
| 44 | 4 | `dwImageCount` | Number of images in the file |
| 48 | 24 | `rhOffsetTable` | Resource header (§3) locating the lookup table |
| 72 | 24 | `rhXmlData` | Resource header locating the XML data |
| 96 | 24 | `rhBootMetadata` | Resource header locating the metadata resource of the bootable image |
| 120 | 4 | `dwBootIndex` | Index of the bootable image; 0 means no image is bootable |
| 124 | 24 | `rhIntegrity` | Resource header locating the integrity table |
| 148 | 60 | `bUnused` | Reserved for future fields |

Total: 208 bytes **[derived]**. This summary first advised readers to
use `cbSize` and the resource headers rather than assume 208. That
advice was our own **[reading]**, not Microsoft text; the product's rule
is now the [project rule] on `cbSize` below.

**Header flags** (`dwFlags`):

| Value | Name in the paper | Meaning |
|-------|-------------------|---------|
| 0x00000001 | `FLAG_HEADER_RESERVED` | reserved |
| 0x00000002 | `FLAG_HEADER_COMPRESSION` | file and metadata resources are compressed |
| 0x00000004 | `FLAG_HEADER_READONLY` | the contents should not be changed |
| 0x00000008 | `FLAG_HEADER_SPANNED` | resource data for the images may be in another WIM (split set, §10) |
| 0x00000010 | `FLAG_HEADER_RESOURCE_ONLY` | file resources only, no metadata |
| 0x00000020 | `FLAG_HEADER_METADATA_ONLY` | metadata only |
| 0x00000040 | `FLAG_HEADER_WRITE_IN_PROGRESS` | limits the file to one writer in a shared-write mode |
| 0x00000080 | `FLAG_HEADER_RP_FIX` | reparse point fix-up was applied |
| 0x00010000 | `FLAG_HEADER_COMPRESS_RESERVED` | reserved; valid only with 0x2 set |
| 0x00020000 | `FLAG_HEADER_COMPRESS_XPRESS` | XPRESS compression; valid only with 0x2 set |
| 0x00040000 | `FLAG_HEADER_COMPRESS_LZX` | LZX compression; valid only with 0x2 set |

The paper defines no other compression flag. A file that says it is
compressed but carries none of the defined compression flags, or carries
an undefined one, uses a method this paper does not describe
(`wim-compression.md` §5; OPEN-WIM-4).

**Observations on the header (R1).**

- **[observed]** Every R1 file starts with the ASCII letters `MSWIM`
  and three zero bytes, has `cbSize` 208, has data starting at offset
  208, and has zero bytes from 148 to 207 (OBS-001). This **confirms**,
  for R1, the [reading] of the signature and the [derived] size 208.
- **[observed]** Version: 0x00010D00 in every `.wim` and `.swm` file,
  whatever the compression; 0x00000E00 in the `.esd` file (OBS-003).
  Which values a reader should accept is **still open** (OPEN-WIM-2).
- **[observed]** The field at offset 20 is **not** the file size,
  which **contradicts** the paper's description: it is 0 in the
  uncompressed file, 32768 in every XPRESS and LZX file and 131072 in
  the `.esd` file, and equals no file size or stored size (OBS-004).
  That it holds the chunk size is a [reading]; its meaning stays
  OPEN-WIM-3.
- **[observed]** Header flags (OBS-005): `none` wrote 0x00000080,
  `fast` 0x00020082 and `max` 0x00040082. The LZX flag DISM writes is
  0x00040000, as the paper defines (**confirmed**). Flag 0x80
  (`FLAG_HEADER_RP_FIX`) is set in every R1 file, so a reader must
  accept it. Asking for an integrity table set no extra header flag.
- **[observed]** The `.esd` file has flags 0x00080082: 0x00080000 is a
  bit the paper does not define, and no defined compression flag is set
  (OBS-006). Split parts add 0x08 to the source file's flags (OBS-017).
- **[observed]** The boot metadata header and the boot index are zero
  in every R1 file (OBS-001). No bootable image has been observed, so
  §11's boot fields are **not yet confirmed** by any sample.

**Project rules on the header** (not Microsoft text):

- **[project rule, decision 0017 (accepted 2026-10-27)]** The product
  accepts a file only when `cbSize` is 208 and refuses any other value
  with a named reason. Basis: OBS-001.
- **[project rule, decision 0017 (accepted 2026-10-27)]** For a file
  whose header says XPRESS, the product requires the field at offset 20
  to be 32768 and refuses any other value with a named reason. Basis:
  OBS-004.

## 3. Resource header (WIM paper, "WIM File Resource")

Every resource location (in the header and in each lookup table entry) is
a 24-byte resource header:

| Offset | Size | Content |
|--------|------|---------|
| 0 | 7 | stored (compressed) size of the resource |
| 7 | 1 | resource flags |
| 8 | 8 | offset of the resource from the start of the file |
| 16 | 8 | original (uncompressed) size |

The paper defines the first 8 bytes as a union of a 64-bit size with "7
size bytes and 1 flag byte". The stored size is therefore a 56-bit value
**[reading]**.

**Resource flags**:

| Value | Name in the paper | Meaning |
|-------|-------------------|---------|
| 0x01 | `RESHDR_FLAG_FREE` | free (unused) space |
| 0x02 | `RESHDR_FLAG_METADATA` | this is a metadata resource |
| 0x04 | `RESHDR_FLAG_COMPRESSED` | this resource is compressed |
| 0x08 | `RESHDR_FLAG_SPANNED` | spanned (split set) |

**Observations on resource headers (R1).**

- **[observed]** The three resource headers in the file header (lookup
  table at 48, XML at 72, integrity table at 124) have the layout above
  and a 7-byte little-endian stored size (OBS-007, OBS-002). This
  **confirms** the layout and the 56-bit [reading] for those headers.
- **[observed]** The lookup-table and XML headers carry flag 0x02 in
  every R1 file; the integrity header carries 0x00 (OBS-007). Flag 0x02
  in these header slots does **not** mean an image's metadata, so a
  reader must not count them as images. DISM stored the lookup table and
  the XML uncompressed (stored size equal to original size) even in
  XPRESS files, with the XML directly after the lookup table.
- **[observed]** In the `.esd` file, 18 lookup entries carry resource
  flag 0x10, which the paper does not define (OBS-006).
- **[observed]** No split part has any entry with flag 0x08; the only
  resource flags seen in split parts are 0x00, 0x04 and 0x06 (OBS-017).
- **[observed]** Unused space (recorded from R2; also present in R1's
  12-image file): files changed after their first
  capture (append, export into an existing file, commit, delete) hold
  byte ranges that neither the file header nor any lookup entry names
  (OBS-020, OBS-022, OBS-023). See
  §5 for what those ranges held.

**Observations on resource headers (R3, AUDITED 2026-10-28).**

- **[observed]** Sizes and offsets above 2^32 (OBS-047): one R3 file
  holds a resource of 4831838208 bytes, stored uncompressed, whose
  7-byte stored size uses its fifth byte, and a metadata resource at
  an offset above 2^32. Both read correctly as the little-endian
  56-bit size and 64-bit offset above. This **confirms**, for that
  file, the 56-bit [reading] for values that need more than 32 bits.
- **[observed]** Metadata entries carry resource flags 0x06 when the
  metadata is compressed and 0x02 when it is stored as-is (OBS-043,
  OBS-047).

## 4. File resources and chunking (WIM paper, "WIM File Resource")

- Captured data is cut into **32 KB chunks**, and each chunk is compressed
  on its own. The paper's chunk-count formula uses 32768.
- A compressed resource starts with a **chunk table**, followed by the
  compressed chunks in order.
- Number of chunk table entries: `ceil(original_size / 32768) - 1`. The
  first chunk has no entry **[reading: it starts right after the table]**.
- Each entry gives the offset at which the *next* chunk starts, so the
  difference between consecutive entries is a chunk's compressed size. The
  paper's example: entries 0x4000, 0x6000, 0x12000 mean chunk 1 compressed
  to 0x4000 bytes, chunk 2 to 0x2000, and chunk 3 to 0x6000. Offsets are
  relative to the end of the chunk table **[reading, from the example]**.
- Entry width: 8 bytes if the original size is over 4 GB, otherwise 4
  bytes. The paper does not say whether "4GB" means 2^32 bytes
  (OPEN-WIM-10).
- Every chunk except the last expands to exactly 32768 bytes. The last
  expands to whatever remains of the original size.
- The decompressor is chosen by the header's compression flag (§2).
- The last chunk's compressed size is the resource's stored size minus the
  chunk table size minus the last table entry **[derived]**.
- The paper does not say how a chunk that would not shrink is stored
  (OPEN-WIM-5).
- A resource without the compressed flag is stored as-is.

**Observations on chunking (R1).**

- **[observed]** For resources under 2^32 bytes, the readings above
  hold (OBS-011): the table has `ceil(original_size / 32768) - 1`
  entries of 4 bytes; entry i is the end of chunk i, counted from the
  end of the table; chunk 0 starts right after the table; the last
  chunk runs to the end of the stored size; a one-chunk resource has no
  table. Read this way, every compressed resource in R1 (83 resources,
  369 chunk instances) decodes to the SHA-1 of its lookup entry. These
  [reading] and [derived] points are **confirmed** for R1.
- **[observed]** The 8-byte entry width was never seen in R1. R4 saw
  it (OBS-058, below); the exact threshold stays **open**
  (OPEN-WIM-10).
- **[observed]** Resource level of OPEN-WIM-5 (OBS-010): inside an
  XPRESS file, a whole resource that did not shrink (pseudorandom data,
  and every file of 59 bytes or less) is stored as plain bytes, with
  flag 0x04 clear and no chunk table. Whether a resource is compressed
  is therefore decided per resource, by its own flag, not by the header.
- **Not seen in R1**: a compressed resource in which one chunk did not
  shrink. No R1 chunk has a stored size equal to its expanded size
  (OBS-010, OBS-012). R3 supplied that case (below).
- **Impact note** (from the M2 boot-protocol review): if a reader
  refuses a chunk whose stored size equals its expanded size, then in
  M2 this affects only metadata. Once images are applied (M3), it would
  affect file data as well. The R3 note below shows such chunks occur.

**Observations on chunking (R3, AUDITED 2026-10-28).**

- **[observed]** Raw chunks (OBS-046): in an XPRESS file, two 65536-byte
  files, each half compressible text and half pseudorandom bytes (in
  opposite orders), were each stored as one compressed resource with a
  one-entry chunk table. In each, the pseudorandom chunk occupies
  exactly 32768 stored bytes and is the chunk's plain bytes; the other
  chunk is XPRESS-coded. Read that way, both resources give the SHA-1
  of their lookup entries. It held whether the raw chunk was first or
  last. This settles the chunk level of OPEN-WIM-5 for R3: a chunk
  whose stored size equals its expanded size (32768) is stored
  uncompressed.
- **[observed, AUDITED 2026-10-28]** Position (OBS-046 as corrected,
  with S14): a chunk stored at full size (32768) is raw at any
  position in the resource, including several consecutive raw chunks,
  not only first or last.
- **Not seen in R3**: a final chunk shorter than 32768 bytes that did
  not shrink. Whether the same equal-size rule marks it was **open**
  after R3 **[reading: the same rule applies, by analogy only]**. R4
  settles it (below).
- **[observed]** Compressed metadata (OBS-043): an XPRESS file's
  metadata resource of 496936 bytes (16 chunks) decodes, through the
  chunk table as read above, to exactly the bytes of the uncompressed
  capture of the same tree.
- **[observed]** No chunk table over 4 GiB (OBS-047): the R3 sample
  over 4 GiB was pseudorandom, so DISM stored it uncompressed with no
  chunk table (as OBS-010 for small files). The 8-byte entry width
  stayed **open** (OPEN-WIM-10) after R3; see R4 below.

**Observations on chunking (R4, AUDITED 2026-10-28).**

- **[observed]** Short final raw chunk (OBS-057): three XPRESS
  resources, each 32768 bytes of text followed by 100, 5000 or 32767
  pseudorandom bytes, had a one-entry chunk table. The text chunk was
  coded; the last chunk's stored size equalled its expanded size, and
  read as plain bytes each resource gave its lookup SHA-1. This
  **confirms** the [reading] above for R4 and settles OPEN-WIM-5 for
  the forms seen: a chunk is raw exactly when its stored size equals
  its expanded size (32768, or the remainder for the last chunk), at
  any position.
- **[observed]** 8-byte table entries (OBS-058; evidence from a dump
  only, because the file was not kept and its chunks were not
  decoded): one XPRESS resource with an original size of 4831838208
  (above 2^32) and a stored size of 897896440 (below 2^32). Read with
  8-byte entries, its 147455-entry table increases, the first chunk
  after the table starts with a complete Huffman table at exactly that
  offset, and the chunks fill the stored size. Read with 4-byte
  entries, the table does not increase. Every entry value was below
  2^32. So the width followed the original size, not the stored size
  or the entry values, as the paper says.
- **Still open** (OPEN-WIM-10): whether the width changes at exactly
  2^32 or only above it, and LZX resources over 4 GiB (none seen).

## 5. Lookup table (WIM paper, "Lookup Table")

- An array of entries, one per resource. Each entry holds, in order:
  - the resource header (§3), 24 bytes;
  - the part number in a split set, 2 bytes;
  - a reference count, 4 bytes: how many times this resource is used
    across all images in the file;
  - the SHA-1 hash of the uncompressed data, 20 bytes.

  Entry size 50 bytes and entry count = table size / 50 **[derived;
  packing not stated, OPEN-WIM-6]**.
- Images are found by searching the table for entries with the metadata
  flag (0x02) set. The paper does not say how a metadata entry maps to an
  image index (OPEN-WIM-6).
- File data is found from the metadata resource by matching a directory
  entry's hash to an entry's hash (§6).

**Observations on the lookup table (R1).**

- **[observed]** Packing (OBS-008): every lookup table size is a
  multiple of 50; entries are 50 bytes, packed, with the fields in the
  order above. The hash is the SHA-1 of the uncompressed content; the
  reference count counts uses across all images in the file; identical
  content is stored once; an empty file has no entry; resources follow
  each other with no gap or alignment. The packing part of OPEN-WIM-6
  is **confirmed** for R1. The "no gap" point holds only for files
  made in one step; OBS-020 (below) **contradicts** it for files
  changed later, including R1's own 12-image file, which was built by
  appends. The reference-count point is **qualified** by
  OBS-019, below.
- **[observed]** Metadata entries come first in the table in every
  single-file `.wim` of R1 and in split part 1 (OBS-009). In the
  12-image file, the k-th entry
  with the metadata flag is the metadata of image index k. In that file
  lookup order, file-offset order and index order are the same.

**Observations on the lookup table (R2).** Files changed after their
first capture.

- **[observed]** Identical metadata (OBS-018): when two images have
  identical metadata (the same tree appended twice, or the same index
  exported twice into one file), the table holds two adjacent entries
  with the metadata flag that are equal in all 50 bytes, each with
  reference count 1, and both name one stored copy of the metadata.
  The XML and DISM's own listing still show two images, index 1 and 2.
  So two lookup entries can name the same byte range, and a file can
  hold fewer metadata copies than images. DISM refused neither step.
- **[observed]** Reference counts (OBS-019): a resource used once by
  each of two images has count 2, but a resource used several times
  per image had counts that follow no stable rule (the same capture
  command gave different counts in R1 and R2). This **qualifies** the
  paper's description of the count above: in these files it is not a
  reliable count of uses.
- **[observed]** Superseded tables (OBS-020): each append, export into
  an existing file, commit and delete writes a new lookup table and
  new XML and leaves the previous ones in the file, named by nothing.
  The file then has unnamed gaps between resources. Files made by a
  single capture have none. This **contradicts**, for changed files,
  the "no gap" point of OBS-008.
- **[observed]** Commit (OBS-021, OBS-022): committing a change to
  image index 1 of the 12-image file kept every earlier byte except
  the header, and appended the new file data, the image's new
  metadata, a new lookup table and new XML. The replaced metadata
  stays where it was, named by nothing. The new metadata lies after
  every other resource, but its entry is still the first metadata
  entry in the table. In that file lookup order and file-offset order
  of metadata **differ**, and the k-th metadata entry in lookup order
  is image index k. So lookup order, not file-offset order, gives the
  index there.
- **[observed]** Delete then append (OBS-023): deleting index 1 of the
  12-image file and appending the same tree again renumbered the
  remaining images 1 to 11 and added the appended image as 12. Its
  metadata was written again at the end of the file, at a new offset,
  although an identical copy was still stored, unnamed, at the old
  offset. The stored file data was reused. In that file lookup order,
  file-offset order and index order of metadata agree.
- What is settled and what is not is in §13 under OPEN-WIM-6.

**Observations on the lookup table (R3, AUDITED 2026-10-28).** How
directory
entries name lookup entries.

- **[observed]** Every non-zero hash in a directory entry or stream
  entry of the R3 files examined names a lookup entry; empty content
  has an all-zero hash and no lookup entry (OBS-031). This agrees with
  the R1 "empty file has no entry" point (OBS-008).
- **[observed]** All names of one hard-linked file carry the same hash,
  and the content has one lookup entry (OBS-035).
- **[observed]** Reparse data is stored as a resource of its own,
  named by a hash like file data (OBS-036; §6).

## 6. Metadata resource (WIM paper, "WIM Metadata Resource")

Needed to apply an image (M3). One per image. It holds security data,
then the directory tree. The bullets below are the paper's description;
the R3 observations after them correct one [derived] point.

- **Security block** first: total length (4 bytes), number of entries
  (4 bytes; the paper's text calls them directory entries, but in context
  they count security descriptors **[reading]**), then one 8-byte length
  per descriptor, then the descriptors. Security descriptors are stored
  once per image.
- The **root directory entry** follows at the next 8-byte-aligned offset
  after the security data.
- **Directory entry** fields, in order: entry length (8), file attributes
  (4), security index (4; −1 means none), offset of the children from the
  start of the metadata (8), two reserved (8 each), creation, last access,
  and last write times (8 each), content hash (20, SHA-1), then 8 bytes
  that hold either a reparse tag and a reserved value (when the attribute
  value 0x400 is set) or a hard-link group identifier (otherwise), then
  the count of alternate streams (2), short name length in bytes (2), file
  name length in bytes (2), and the relative file name (UTF-16
  **[reading]**). Fixed part 98 bytes **[derived]**, from these sizes
  with no padding.
- **[observed]** The [derived] 98 is **contradicted by OBS-026** for
  the R3 files examined (including S01, rebuilt in R3 with the R1
  command): there the fixed part is 102 bytes (§6.1). The field order
  above is unchanged by the observation; the paper lists four bytes
  fewer than the files hold.
- **Alternate stream entries** follow a directory entry when it has
  alternate streams: length (8), reserved (8), SHA-1 hash (20), stream
  name length (2), stream name.
- Each directory (not each entry) ends with a 64-bit zero. Each entry is
  aligned (the paper states four-byte alignment here and quad alignment
  for the root; OPEN-WIM-7).
- The full path of a file is rebuilt by walking up through its parents.
- Where the short name is stored is not stated (OPEN-WIM-7).

### 6.1 Observations on the metadata resource (R3, AUDITED 2026-10-28)

Scope: the R3 files examined (including S01, rebuilt in R3 with the R1
command). That is S01, captured from a small tree, and three files
captured from a purpose-built tree with about 3000 entries
(uncompressed, XPRESS, and from a volume root), plus DISM's apply of
the uncompressed one (OBS-024 to OBS-045, OBS-048). Offsets below are
from the start of an entry unless stated. Everything here holds for
those files only.

**Security block** (OBS-024).

- **[observed]** The first 4-byte field is the length of the whole
  block, including its own 8-byte header. The second is the number of
  descriptors, which **confirms** the [reading] above. Each
  descriptor length is an 8-byte value. The descriptors follow the
  length list with no padding between them.
- **[observed]** The root entry starts at the next multiple of 8 after
  the block's length, and the bytes in between are zero.

**Directory entry: fixed part** (OBS-026). **[observed]** positions:

| Offset | Size | Content seen |
|--------|------|--------------|
| 0 | 8 | entry length |
| 8 | 4 | attributes |
| 12 | 4 | security index |
| 16 | 8 | children offset |
| 24 | 8 | zero in every entry |
| 32 | 8 | zero in every entry |
| 40 | 8 | creation time |
| 48 | 8 | last access time |
| 56 | 8 | last write time |
| 64 | 20 | content hash |
| 84 | 4 | zero in every entry |
| 88 | 8 | reparse tag and 4 further bytes, or hard-link value |
| 96 | 2 | stream entry count |
| 98 | 2 | short name length in bytes |
| 100 | 2 | name length in bytes |
| 102 | var. | name |

- **[observed]** A walker built from the 98-byte [derived] layout read
  every name as empty and failed at the first stream entry; read with
  the positions above, every entry in the files examined fits
  (OBS-026).
- **[observed]** The fields at +24 and +32 match the paper's two
  reserved fields by position. They and the bytes at +84 were zero in
  every entry; what they hold when not zero is **open** (OPEN-WIM-7).
- **[derived]** The bytes show four zero bytes at +84, and the reparse
  tag at +88 (OBS-036). Reading the paper's 8-byte union as starting
  at +88, so that the tag is its first half as the paper orders it,
  places the four extra bytes between the hash and the union. That
  placement is derived from the paper's order and the observed tag
  position; not seen directly. Microsoft's paper does not list these
  four bytes at all.

**Root entry** (OBS-025, OBS-044).

- **[observed]** The root is a single entry with the same layout as any
  other and a zero-length name, not part of a list. Its children
  offset points at the top-level list.
- **[observed]** No entry holds its parent's offset. A reader keeps the
  parent path itself while it walks, as the paper's "walking" bullet
  implies.
- **[observed]** When a volume root was captured, the root entry held
  the root directory's own attributes, descriptor and times, and the
  volume's system-information folder was left out of the image
  (OBS-044). Handling of a recycle-bin folder was not shown.

**Names and short names** (OBS-027, OBS-028).

- **[observed]** Names are UTF-16LE, which **confirms** the [reading].
  The length field counts bytes without a terminator. A 2-byte zero
  terminator follows the name. Characters outside the Basic
  Multilingual Plane are stored as surrogate pairs.
- **[observed]** The short-name length is at +98, in bytes, without a
  terminator. A non-empty short name is stored right after the name's
  terminator, also UTF-16LE, and is followed by its own 2-byte zero
  terminator. Explicitly set and generated short names are stored the
  same way. A name that needs no short name, and every name captured
  from a volume without short names, has 0 at +98 and nothing after
  the name's terminator but padding. This settles the short-name
  placement part of OPEN-WIM-7 for R3.
- **[observed]** Each entry holds one path component, never a full
  path, so paths longer than 260 UTF-16 units need nothing special in
  the metadata (OBS-041). A reader builds the full path itself and
  must handle its length.

**Length, alignment and padding** (OBS-029).

- **[observed]** An entry's length field equals its used size (fixed
  part, name, terminator, and the short name with its terminator when
  present) rounded up to a multiple of 8, with zero padding. Stream
  entries follow the same rule. Every entry therefore starts at a
  multiple of 8. This is stricter than, and consistent with, the
  paper's four-byte alignment.
- **[observed, AUDITED 2026-10-28]** In short: entries and stream
  entries are
  aligned to 8 bytes through their length field, where the paper
  says 4 (OBS-029).
- **[observed] Sparse exception** (OBS-029, OBS-039): the entry of the
  one sparse file sampled has a length 24 bytes larger than the rule
  gives, and those 24 bytes are not zero. Their last 16 bytes hold the
  start and end of the file's deallocated range as 8-byte values. The
  meaning of the first 8 bytes, and the block's form for other ranges,
  were **open** after R3 (OPEN-WIM-7, sample S13E); R4 below.
- **[observed, R4, AUDITED 2026-10-28] Sparse block** (OBS-055,
  corrected): six sparse files with known holes. The block follows
  the entry's used bytes, padded to 8, and the entry length includes
  it. It holds a 4-byte value 3 (the same in every file; meaning not
  shown), then a 4-byte value equal to 16 times the number of pairs,
  then one pair of 8-byte values per range: start, and end
  (exclusive). Ranges appear merged (three adjacent holes gave one
  pair) and in descending order. A file with the sparse attribute but
  no hole has no block. That the pairs describe the holes is a
  [reading] from equal values. Whether DISM's apply re-creates the
  holes was not measured; the resource holds the full expanded content
  either way.
- **[observed]** Stream entries start at the entry's offset plus its
  length field, and the next sibling starts where the last stream entry
  ends. A reader must advance by the length field, not by a size it
  computes, because of the sparse case.

**Lists and children** (OBS-030, OBS-042).

- **[observed]** A non-zero children offset is the offset, from the
  start of the metadata resource, of the first entry of that
  directory's list. Every list ends with 8 zero bytes where the next
  length would be, which **confirms** the paper's end marker. An empty
  directory has a non-zero children offset that points straight at
  that zero. Files, symbolic links and junctions have offset 0.
- **[observed]** Siblings appeared with childless entries first, then
  the rest, each group sorted by a case-folded name. The folding rule
  was compared on these names only; a reader must not depend on the
  order (OBS-042).

**Stream entries** (OBS-031, OBS-032).

- **[observed]** A stream entry has: length (8), 8 bytes that were
  zero in every one, SHA-1 hash (20), name length in bytes (2), then
  the UTF-16LE name, a 2-byte zero terminator and zero padding to the
  length. The order and sizes **confirm** the paper's list (38 bytes
  before the name).
- **[observed]** A file with named streams has, first, a stream entry
  with an empty name that carries the main data's hash; the entry's own
  hash is then zero, and the stream count includes the unnamed entry.
  A file with no named streams has count 0 and keeps its data hash in
  the entry.
- **[observed]** A directory with a named stream has only the named
  entry, no unnamed one.
- **[observed, AUDITED 2026-10-28]** Unnamed stream entries therefore
  occur in the
  stream list and must be read like named ones: one per file with
  named streams, and two on a file reparse point (see "Reparse
  points"; OBS-032, OBS-036).
- **[observed]** Empty content, main or named, has an all-zero hash
  and no lookup entry (OBS-031).
- **[observed]** The order of named streams was not their creation
  order in the one case with two; the rule was **open** after R3
  (OPEN-WIM-7, sample S13F); R4 below.
- **[observed, R4, AUDITED 2026-10-28]** Stream order (OBS-056,
  corrected): in every file seen, named streams follow the unnamed
  entry in descending name order, whatever order they were written in
  and whatever their sizes. All names sampled were lower case, so
  whether the sort folds case is not shown. A reader must not depend
  on the order.

**Attributes and times** (OBS-033, OBS-034).

- **[observed]** The 4 bytes at +8 hold the file attribute value the
  file system reported at capture, unchanged, for every entry. That
  includes the read-only, hidden, system, directory, archive,
  not-content-indexed, sparse, compressed, encrypted and reparse bits,
  and the value 0x80 reported when none of the others is set.
- **[observed]** +40 is creation, +48 last access and +56 last write,
  each a 64-bit count of 100-ns units since 1601-01-01 UTC, equal to
  what Windows reported to the 100-ns unit. This **confirms** the
  paper's order.

**Hard links** (OBS-035).

- **[observed]** Each name of a hard-linked file is a complete entry
  with its own name, short name and the same content hash. The names
  of one file share one non-zero 8-byte value at +88. Entries without
  the reparse bit that have a single name hold zero there. What the
  value is derived from is not shown, so a reader can only group names
  by equality of the value.

**Reparse points** (OBS-036, OBS-037).

- **[observed]** With attribute bit 0x400 set, the first 4 bytes at +88
  hold the reparse tag as Windows reports it (junction and symbolic
  link tags were seen).
- **[observed]** The next 4 bytes were zero for absolute links and the
  junction, and non-zero for the two relative links. Their meaning is
  **open** (OPEN-WIM-7).
- **[observed, AUDITED 2026-10-28]** So the second half of the 8-byte
  union (+92)
  is not always zero: it was non-zero for relative links and, as part
  of the shared value, for hard-link names (OBS-035, OBS-036). A
  reader must not require it to be zero.
- **[observed, AUDITED 2026-10-28]** +92 on reparse points (OBS-052,
  corrected): in every file seen, read as a 32-bit value, it is zero
  exactly on symbolic links with `Flags` 0 and mount points whose
  target lies inside the captured tree, with header flag 0x80 on, and
  0x00010000 otherwise (relative links, absolute targets outside the
  tree, and every entry of a file captured without the flag). It does
  **not** mean that the data were changed: in a volume-root capture
  with the flag, entries with zero were stored with nothing stripped
  (the junction byte-identical, the links only re-laid out). That it
  marks the targets DISM's apply re-bases is a [reading]; no source
  names the field.
- **[observed]** The reparse data bytes, without the tag and the data
  length (which Windows reports separately), are stored as a resource
  named by a hash. For a directory reparse point, the entry's own hash
  names it and the stream count is 0. For a file symbolic link, the
  entry hash is zero and there are two unnamed stream entries: the
  first names the reparse data, the second has a zero hash.
- **[observed]** With header flag 0x80 (`FLAG_HEADER_RP_FIX`) set,
  DISM rewrote absolute targets that lay inside the captured directory
  by removing the capture-root part of the path; relative targets were
  stored unchanged. This **adds** detail to the paper's description
  of the flag (§2).
- **[observed, R4, AUDITED 2026-10-28]** What capture with the flag
  stores (OBS-049, corrected): for three absolute symbolic
  links and one junction whose targets lay inside the captured
  directory, DISM rewrote **both** the substitute name and the print
  name by removing the capture directory and keeping the drive letter,
  and rewrote their offsets and lengths to match. The stored names
  have the form `\??\L:\path` (substitute) and `L:\path` (print). The
  stored layout puts the substitute name first at offset 0, then a
  2-byte zero, the print name and a 2-byte zero. That layout was new
  only for the symbolic links; the source junction already had it.
  The stored length is the new path buffer plus 12 (link) or 8
  (junction), as topic 24 §3 and §4 give.
- **[observed, AUDITED 2026-10-28]** On apply (S16), the applied
  reparse data
  equalled the stored bytes. Source and target were both the root of
  a volume lettered `R:`, so this cannot show whether DISM copies the
  stored targets or re-bases them onto the target root (OBS-037). It
  stayed **open** with sample S13B; R4 answered it (below).
- **[observed, R4, AUDITED 2026-10-28] Re-base on apply** (OBS-050):
  DISM applied
  the image of the previous bullet to the root of another drive
  letter, and to a subdirectory two levels down on a third letter.
  For the four rewritten entries, it replaced the stored drive letter
  by the apply root (a letter, or a letter and a directory path) in
  both names, recomputed the offsets and lengths, and kept the
  layout. Each applied target named the applied copy of its target.
- **[observed, R4, AUDITED 2026-10-28] Copy on apply** (OBS-051):
  every other
  reparse point was stored equal to its source and applied unchanged,
  byte for byte: absolute targets outside the captured tree (including
  one on another drive letter), relative links, and all entries
  of an image captured with DISM's no-fix option. With that option
  DISM cleared header flag 0x80 and stored in-tree absolute targets
  unchanged too, so after apply they still name the capture-time
  paths.
- **Answered in R4** (OPEN-WIM-7, M-13) by samples S13B and S13C,
  for the drive-letter and subdirectory forms above. What the
  product does is the [project rule, DEC-0022] in §13 (formerly
  OPEN-WIM-12). A volume-root capture with rewritten entries was never
  applied (OPEN-WIM-13).
- **See also (SR-6, AUDITED 2026-10-28)**: Microsoft's published
  layouts of the
  reparse buffers (tags, substitute and print names, the relative
  flag) are summarised in `reparse-and-security-descriptors.md`
  (topic 24) §1 to §5, which also marks the points that matter when
  `FLAG_HEADER_RP_FIX` is set. Topic 24 settles neither OPEN-WIM-7
  nor OPEN-WIM-12. (R4, AUDITED 2026-10-28: topic 24's OPEN-RPSD-2
  and 3 are now
  settled for the drive-letter form from OBS-049.)

**Security descriptors** (OBS-038).

- **[observed]** Identical descriptors are stored once, and entries
  refer to them by the index at +12. Different indexes held different
  descriptors. After DISM's apply, every path had the same descriptor
  as the source, compared as SDDL text. The descriptors of the 5
  reparse points were not compared (no SDDL was captured for them;
  correction added in SR-6, AUDITED 2026-10-28).
- **Open** (OPEN-WIM-7, sample S13D): whether the stored bytes are
  exactly the self-relative descriptor Windows returns (no binary
  reference was captured), and what an index of −1 looks like (never
  seen in any file). R4 narrows the first point (below).
- **[observed, AUDITED 2026-10-28] Form** (OBS-054, corrected): every
  stored descriptor has `Revision` 1 and SR set,
  a SACL offset of 0 (SP clear), and owner, group and DACL offsets
  inside the descriptor: the self-relative form of topic 24 §9.
  Several stored descriptors set PS although SP is clear. The only
  binary comparison available was .NET's re-serialisation of each
  file's descriptor, not the bytes Windows returns. Of the rows
  compared (3052 in one file, 20 in another; reparse points have no
  such row), most stored copies differed from it only by the PS bit, a
  few whose stored copy has no PS were equal, and one differed in
  length. Whether Windows' own bytes carry PS is still **open**.
- **[observed, AUDITED 2026-10-28] Reparse-point descriptors**
  (OBS-053, corrected): DISM's apply wrote the
  stored descriptor faithfully on every reparse point (12 of 12 in each
  of three applies). One file link whose DACL had been set on the link
  itself kept its own stored descriptor. Seven other file links had
  an explicit, protected DACL in the source, but at capture DISM
  stored them with the descriptor shared by ordinary files
  (inherited entries), so they lost their own DACL at capture, not at
  apply. Why is not shown. Directory reparse points kept theirs.
  Whether the product should warn about this is a product decision
  (open).
- **See also (SR-6, AUDITED 2026-10-28)**: the self-relative
  descriptor, SID and
  ACL layouts from [MS-DTYP] are in topic 24 §7 to §9, the reference
  for checking sample S13D.

**Sparse, compressed and encrypted files** (OBS-039, OBS-040).

- **[observed]** A sparse file and an NTFS-compressed file kept their
  attribute values, and their resources hold the full expanded content
  as read through the file system (zeros included). The sparse entry's
  extra block is described under "Length, alignment and padding".
- **[observed]** An EFS-encrypted file was stored as a resource that is
  not its plaintext, in a form our sources do not describe; DISM's own
  apply turned it back into an encrypted file that could not be read on
  another machine.
- **[project rule, DEC-0006; fail closed]** Because that stored form is
  undocumented, the product refuses EFS entries.

**XPRESS-compressed metadata** (OBS-043). **[observed]** It decodes
to the same bytes as the uncompressed capture of the same tree (§4).

**DISM's apply compared with its source** (OBS-045).

- **[observed]** DISM applied the uncompressed R3 image to another
  volume. Against the source tree, every path matched in type, the
  three times, length, named streams, descriptor (as SDDL), hard-link
  names, reparse tag and short name, and every readable file matched
  in content.
- **[observed]** The differences:
  - files captured without the archive attribute had it set after
    apply;
  - the target volume's root kept its own attributes instead of the
    captured root's;
  - in-tree absolute link targets differed, as described under
    "Reparse points";
  - the EFS file could not be read.
- These are observations of DISM's behaviour, not format facts.
  Whether the product's apply matches DISM on them is for project
  design.

## 7. XML data (WIM paper, "XML Data"; Learn pages)

- An **uncompressed**, clear-text XML document stored after the lookup
  table. It begins with the Unicode byte-order mark 0xFEFF (UTF-16
  **[reading]**).
- The paper's default structure: a root `WIM` element with `TOTALBYTES`,
  and one `IMAGE` element per image carrying an `INDEX` attribute (the
  first image is index 1), with `DIRCOUNT`, `FILECOUNT`, `TOTALBYTES`,
  `CREATIONTIME` and `LASTMODIFICATIONTIME`. Each time is given as
  `HIGHPART` and `LOWPART` in hexadecimal (the two 32-bit halves of a
  64-bit time **[reading]**).
- Imaging tools also store `NAME`, `FLAGS`, `DESCRIPTION`, and a `WINDOWS`
  element used by Windows Setup. The paper does not define their content
  (OPEN-WIM-8).
- The `WIMSetImageInformation` API page: image information is a Unicode
  XML document, enclosed in `WIM` tags for a whole file or `IMAGE` tags
  for one image. Setting it replaces any custom data.
- DISM's image inventory reports index, name, description, and size for
  each image in a file, and more detail (languages, architecture, edition)
  for one image chosen by index or name.
- Windows Setup chooses an image by metadata key `/IMAGE/INDEX`,
  `/IMAGE/NAME` or `/IMAGE/DESCRIPTION` (keys in upper case; no empty
  values). When one file holds 32-bit and 64-bit images, an image can also
  be chosen by architecture metadata: 0 for 32-bit and 9 for 64-bit
  (Setup supported platforms). These match the documented processor
  architecture values 0 (x86), 9 (x64), 12 (Arm64) and 5 (ARM)
  (`SYSTEM_INFO`) **[reading: same value set]**.

**Observations on the XML data (R1).** All from OBS-014.

- **[observed]** Encoding: every XML resource starts with the bytes
  `FF FE` and is UTF-16LE, with no XML declaration, no line breaks and
  no trailing zero unit; it ends with the closing `WIM` tag. This
  **confirms** the UTF-16 [reading] (little-endian, with byte-order
  mark).
- **[observed]** Element set: only `WIM`, `TOTALBYTES`, `IMAGE` (with
  `INDEX`), `DIRCOUNT`, `FILECOUNT`, `HARDLINKBYTES`, `CREATIONTIME`,
  `LASTMODIFICATIONTIME`, `HIGHPART`, `LOWPART`, `WIMBOOT`, `NAME` and
  `DESCRIPTION`. `INDEX` runs from 1 to N in order. `NAME` and
  `DESCRIPTION` hold exactly what was given at capture.
- **[observed]** No `FLAGS` and no `WINDOWS` element appear for content
  that is not a Windows installation. R1 files therefore state no
  edition, architecture, version or language, and DISM reports those
  as undefined. Where a Windows image records them stays **open**
  (OPEN-WIM-8); the project's samples cannot show it, and under decision
  0013 those facts are declared by the operator and cross-checked.
- **[observed]** Times are written as `0x` and eight upper-case hex
  digits; read as the two halves of a 100 ns count since 1601-01-01
  they match the capture time. This **supports** the [reading] above.
- **[observed]** The image-level `TOTALBYTES` equals the size of the
  captured tree. The top-level `TOTALBYTES` is **not one fixed
  quantity**: it equals the XML's own offset in single-file `.wim`
  files, the file length in the `.esd` file, and the source file's
  value in every split part. A reader must not rely on it.

**Observation on the XML counts (R3, AUDITED 2026-10-28).** From
OBS-048.

- **[observed]** Against the directory entries of three files,
  `DIRCOUNT` counted directories other than the root and other than
  reparse points. `FILECOUNT` counted every other entry except the
  root, reparse points included, with each hard-link name counted
  separately. Stream entries were not counted. `HARDLINKBYTES` added
  the file's size once for each extra hard-link name.

## 8. Integrity table (WIM paper, "Integrity Table")

- **Optional.** Created only when the capture asks for an integrity check.
- Layout: total size of the table in bytes (4), number of entries (4),
  chunk size in bytes (4), then the entries. Each entry is a 20-byte SHA-1
  hash.
- The hashed range starts at the end of the header and ends at the end of
  the lookup table.
- The paper says the chunk size is fixed at "10MB". Use the stored chunk
  size field; the paper's "MB" is not defined (OPEN-WIM-11).
- Entry count = `ceil(hashed_length / chunk_size)` **[derived]**.
- DISM's integrity option records the table during capture, export,
  commit and unmount, and stops an apply or mount if it finds the file is
  corrupt (DISM image management).
- **[observed]** (OBS-015, one file): the chunk size field is 10485760
  (10 × 2^20), so the paper's "10MB" is 10 MiB there. The hashed range
  starts at byte 208 (the end of the header) and ends at the end of the
  lookup table; the XML is not hashed. This **confirms** the paper's
  range for R1. The integrity resource header has flag 0x00 (OBS-007).
- **Never observed**: an integrity table with more than one entry. How
  a range longer than one chunk is split, and the last chunk's size,
  stay **open** (OPEN-WIM-11).

## 9. Byte order

The paper does not state the byte order of multi-byte fields
(OPEN-WIM-1). **[reading]**: little-endian, the native order of the
Windows structures the paper uses. Confirm with files made by Microsoft's
own DISM before relying on it.

**[observed]** (OBS-002): every 16-, 32- and 64-bit field checked in R1,
and the 7-byte stored size, is little-endian; big-endian readings give
values that fit none of the files. The [reading] is **confirmed** for
R1, and OPEN-WIM-1 is settled for those files.

## 10. Split (spanned) WIM files

- A WIM can be split into parts with the `.swm` extension (WIM paper,
  "Split (Spanned) WIM"; DISM `/Split-Image`).
- The **first part** always holds a copy of the header and **all
  metadata resources**. Later parts hold the rest: file resources, lookup
  table, XML data and integrity table (WIM paper).
- The header's part number and total parts, the spanned header flag
  (0x08), the spanned resource flag (0x08) and each lookup entry's part
  number tie resources to parts. The paper does not say how parts of one
  set are recognised as belonging together (OPEN-WIM-9).
- DISM names parts `name.swm`, `name2.swm`, `name3.swm` and so on. Its
  size option is the maximum part size in MB, but a part grows beyond it
  when a single file is larger.
- Split parts are read-only and cannot be modified. Applying them works
  only when all parts are in the same folder (split-a-WIM page).
- Reasons Microsoft gives for splitting: FAT32 has a 4 GB maximum file
  size (FAT32 is needed to boot many UEFI PCs from USB), and a
  single-sided DVD holds 4.7 GB.

**Observations on split sets (R1, one seven-part set).** These
**contradict** the paper's description in the second bullet above
(OBS-016, OBS-017):

- **[observed]** Every part, including part 1, has its own lookup table
  and its own XML. The XML is byte-identical in every part and to the
  source file's XML.
- **[observed]** Each part's lookup table lists only the resources
  stored in that part, each with that part's number. Together the
  parts' tables equal the source file's table with no hash repeated.
- **[observed]** Part 1 holds all metadata resources (from offset 208),
  as the paper says, and also file resources.
- **[observed]** Every part sets header flag 0x08. No resource in any
  part has flag 0x08 (see §3). A split part is therefore recognisable
  from the header alone.
- **[observed]** All parts share one GUID at offset 24, new for the set
  and different from the source file's; part numbers 1 to N are at
  offset 40 and the total N at offset 42. How DISM itself decides that
  files belong together cannot be observed; the shared GUID with part
  number and total is what the files offer (OPEN-WIM-9, partly
  settled).
- **[project rule, decision 0014]** The M2 product refuses split
  parts, so none of this is needed to accept a file in M2.

## 11. Image selection and bootable images

- Images are numbered from 1 (`INDEX` attribute). Tools select by index
  or name; Windows Setup also by description (§7).
- DISM's bootable option marks a volume image as bootable. It is available
  only for Windows PE images, and only one image per file can be bootable
  (DISM image management). The header's boot index records it, 0 meaning
  none (§2).

## 12. Limits

| Item | Limit | Source |
|------|-------|--------|
| Chunk size (file resources) | 32768 bytes | WIM paper |
| Chunk table entry | 4 bytes, or 8 if original size over 4 GB | WIM paper |
| Stored resource size | 56 bits **[reading]** | WIM paper |
| Resource offset, original size | 64 bits | WIM paper |
| Images per file | 32-bit count | WIM paper |
| Parts in a split set | 16-bit part numbers | WIM paper |
| Lookup and integrity hashes | SHA-1, 20 bytes | WIM paper |
| Integrity chunk | "10MB" (use the stored field); 10485760 in R1 | WIM paper; OBS-015 |
| FAT32 file size | 4 GB | split-a-WIM page |

Any of these can be larger than memory or than the actual file. A reader
must check every size and offset against the real file length and its
own limits before using it.

## 13. Open questions (standards)

- **OPEN-WIM-1**: byte order of all multi-byte fields (§9).
- **OPEN-WIM-2**: valid values of the version field (§2).
- **OPEN-WIM-3**: what the field at offset 20 really holds; the paper's
  description (size of the compressed file) does not fit its name (§2).
- **OPEN-WIM-4**: files that use a compression method the paper does not
  describe, such as the "recovery" compression DISM writes to `.esd`
  files (`wim-compression.md` §5).
- **OPEN-WIM-5**: how an incompressible chunk is stored (§4).
  - Settled for R3 (S17, OBS-046): a full-size chunk that does not
    shrink is stored as its 32768 plain bytes, marked only by a stored
    size equal to its expanded size, first or last. **[observed,
    AUDITED 2026-10-28]** At any position, including consecutive raw
    chunks (OBS-046 as corrected, with S14).
  - Open after R3: a final chunk shorter than 32768 bytes that does
    not shrink (not seen then).
  - **Answered for the forms seen (R4, AUDITED 2026-10-28; S17B,
    OBS-057)**: a short
    final chunk that does not shrink is stored as its plain bytes,
    marked by a stored size equal to its expanded size. So a chunk is
    raw exactly when its stored size equals its expanded size, at any
    position. Other DISM builds and other tools are not covered.
- **OPEN-WIM-6**: lookup entry packing, and how metadata entries map to
  image indexes (§5).
  - Settled for the R1 and R2 files: packing (OBS-008); and the k-th
    entry with the metadata flag, in lookup order, is the metadata of
    image index k. This held in every file seen, including one where
    file-offset order differs from lookup order (OBS-021) and ones
    where two entries name one shared copy (OBS-018), so lookup order,
    not file-offset order, gives the index in those files.
  - Still open: whether this holds after a commit of an index other
    than 1 (S12C) or after several commits (S12D); whether three or
    more identical images, or identical images that are not adjacent
    in index order, also share one copy through adjacent equal entries
    (S11C, S11D); whether lookup order can ever differ from index order
    (never seen); and whether other DISM builds or other tools write
    files the same way.
- **OPEN-WIM-7**: directory entry alignment and short-name placement
  (§6). In M3 it also covers the rest of the metadata layout.
  - Settled for the R3 files examined (including S01, rebuilt in R3
    with the R1 command; §6.1; OBS-024 to OBS-045, OBS-048): the
    security block; the root entry; field positions of
    the fixed part, which is 102 bytes and contradicts the [derived] 98
    (OBS-026); names and short names; alignment to 8 by the length
    field; list end marker and empty directories; empty content;
    stream entry layout and the unnamed entry; attribute and time
    fields; hard-link grouping by an equal value; where reparse tags
    and data are stored; descriptors stored once and shared by index.
  - Partly open (M-13, reparse points): the meaning of the second 4
    bytes of the union (+92; not always zero); whether DISM's apply
    copies or re-bases absolute targets when applying to another drive
    letter or a subdirectory (S16 applied `R:` to `R:`, so it cannot
    show this; S13B; AUDITED 2026-10-28); absolute targets outside the
    capture
    root, with and without the no-fix option (S13C).
  - Partly open (M-14, descriptors): byte equality with the
    self-relative descriptor Windows returns, and security index −1
    (S13D).
  - Partly open (M-15, special files): the first 8 bytes and the
    general form of the sparse entry's extra block (S13E). EFS stays
    undocumented and is refused ([project rule, DEC-0006]).
  - Also open: what +24, +32 and +84 hold when not zero; the order of
    named streams (S13F); the placement of the four extra bytes before
    the union is [derived] from the paper's order and the observed tag
    position, not seen directly; recycle-bin handling in
    a volume-root capture; whether other DISM builds or tools agree.
  - **After R4 (AUDITED 2026-10-28; §6.1 R4 notes, OBS-049 to
    OBS-056):**
    - M-13 answered for the drive-letter and subdirectory forms:
      - what capture with the flag stores (OBS-049);
      - re-base on apply for rewritten entries (OBS-050);
      - copy for every other entry (OBS-051);
      - +92 is zero exactly on in-tree absolute targets with the flag
        set (OBS-052, corrected); its meaning remains a [reading].
    - M-14 narrowed: stored descriptors are self-relative with SR set,
      and DISM's apply writes the stored descriptor faithfully
      (OBS-053, corrected; OBS-054). Still open: whether Windows' own
      bytes carry PS; security index −1 (never seen).
    - M-15 sparse block answered: a 4-byte 3, a value equal to 16 ×
      the number of pairs, then merged (start, end) pairs in
      descending order (OBS-055). The
      meaning of the 3 stays open. EFS stays refused.
    - M-09 stream order: descending name order in every file seen;
      case folding not shown; not to be relied on (OBS-056).
    - Product questions raised by R4, not format questions: whether
      the product warns that file links lose their own DACL at capture
      (open); how the product treats the volume-root capture form
      (OPEN-WIM-13).
- **OPEN-WIM-8**: the content of `NAME`, `DESCRIPTION`, `FLAGS` and
  `WINDOWS` in the XML data, in particular where edition, architecture,
  version and languages are recorded (§7).
- **OPEN-WIM-9**: how the parts of one split set are matched (§10).
- **OPEN-WIM-10**: whether the 4 GB chunk-table threshold is 2^32 bytes
  and whether it is "over" or "at least" (§4). Still open after R3
  (M-22): the sample over 4 GiB was stored uncompressed, so it has no
  chunk table (OBS-047). Needs S08B.
  - **Answered for the form seen (R4, AUDITED 2026-10-28; S08B,
    OBS-058, dump
    only)**: an XPRESS resource with an original size above 2^32 has
    8-byte entries, even though its stored size and every entry value
    are below 2^32. The width follows the original size.
  - Still open: whether the switch is at exactly 2^32 or only above
    it, and LZX resources over 4 GiB (never seen).
- **OPEN-WIM-11**: the integrity chunk size unit (§8).
- **OPEN-WIM-12** (product behaviour, not a format question).
  **No longer OPEN (R4, AUDITED 2026-10-28): settled for the project
  by DEC-0022**
  (accepted 2026-10-28). The question was: how does the product handle
  absolute reparse targets that were rewritten at capture (header flag
  0x80) when it applies an image to a different root or drive letter
  than the one captured? No public source on the product describes
  this. The earlier interim rule ([project rule, pending decision]:
  refuse such targets) is replaced by the rule below.
  - See also (SR-6, AUDITED 2026-10-28): topic 24
    (`reparse-and-security-descriptors.md`) §5 and OPEN-RPSD-2 and 3
    summarise the published buffer formats this question concerns.

**[project rule, DEC-0022] Applying reparse points (AUDITED
2026-10-28).** The
product applies link and junction targets as the R4 samples show DISM
does (OBS-050, OBS-051), accepts only the combinations those samples
show, and refuses anything else with a named reason (fail closed). The
rule rests on the observed combination of header flag, +92 value and
stored name form, not on a documented field. What +92 means remains a
[reading] (OBS-052).

Inputs, for one reparse-point entry:

| Symbol | Meaning |
|--------|---------|
| H | the header flags (§2) |
| T | the reparse tag, the 32-bit value at entry +88 |
| M | the 32-bit value at entry +92 |
| B | the stored reparse data (topic 24 buffer without its 8-byte header) |
| A | the apply root chosen for this apply |

1. **Copy**, when M is 0x00010000, whatever H is. Write B unchanged.
   Rebuild the 8-byte header from T, with the data length equal to
   the size of B and the reserved field 0. B must meet topic 24's
   bounds (§3 to §5), and a symbolic link's `Flags` must be 0 or 1.
2. **Re-base**, when M is 0 and all of these hold:
   - H has 0x80 (`FLAG_HEADER_RP_FIX`) set;
   - T is the mount-point tag 0xA0000003, or T is the symbolic-link
     tag 0xA000000C with `Flags` 0;
   - B has exactly the observed layout: substitute name at offset 0;
     print name at the substitute length plus 2; a 2-byte zero after
     each name; path buffer exactly substitute length + 2 + print
     length + 2;
   - the substitute name is `\??\` followed by D, a colon and R, and
     the print name is D, a colon and R, with the same D and R, where
     D is one upper-case letter `A` to `Z`; R starts with a backslash
     and is not a lone backslash; and R has no empty, `.` or `..`
     component and no NUL character.

   The product then writes new data:
   - A is normalised to `L:` for a volume root, or to `L:\c1\...\cn`
     with no trailing backslash for a directory;
   - the new substitute name is `\??\` + A + R, and the new print
     name is A + R; the stored letter D is discarded;
   - the layout is the one required above, and `Flags` stays 0;
   - the data length is the path buffer size plus 12 for a symbolic
     link, or plus 8 for a mount point;
   - the entry is refused if the new data would exceed 65535 bytes,
     or a name would exceed 32760 characters.
3. **Refuse** with a named reason in every other case.

How well R4 supports the rule:

- The records show 8 re-based cases (four entries, each applied to
  another drive letter and to a subdirectory) whose applied data DISM
  wrote byte for byte as the rule gives (OBS-050 to OBS-052).
- The M3 boot-protocol review of R4 (not a record) reports that,
  across 34 reparse entries, M = 0 coincided exactly with "symbolic
  link with `Flags` 0 or mount point, target inside the captured
  tree, H set", with no conflicts.

Never seen, and therefore refused under the rule:

- M = 0 with H clear; any M other than 0 or 0x00010000;
- M = 0 together with: a relative `Flags` value or another tag; any
  other layout; a substitute name that is not a drive-letter path; a
  lower-case letter; a print name that differs from the substitute;
  R equal to a lone backslash; dot components;
- apply roots given as a UNC path, a `\\?\` path, a volume GUID path
  or a mounted folder;
- a hard-linked reparse point;
- any tag other than 0xA000000C or 0xA0000003.

DEC-0022 also names an owner lab run (MT-2), on a real Windows 11
image, that is to confirm junctions resolve after first boot.

- **OPEN-WIM-13** (R4; wording AUDITED 2026-10-28; still OPEN): what
  applying a **volume-root
  capture** with header flag 0x80 should produce. In such a capture
  (S15) entries with M = 0 were stored with nothing stripped (§6.1),
  and no such image was ever applied, so the re-base rule's result for
  it is untested. Needs a sample: apply S15 to another letter and to a
  subdirectory.

**Status after R1 to R4** (R1 in M2 fix round 1, drift; R2 added
2026-10-27; R3 added and audited 2026-10-28; R4 added and audited
2026-10-28). An observation settles a point for the files of its run only;
other DISM builds are not covered.

| Item | Status after R1 to R4 | Records |
|------|-----------------------|---------|
| OPEN-WIM-1 | Settled for R1: little-endian | OBS-002 |
| OPEN-WIM-2 | Partly: values written are known; which to accept is open | OBS-003 |
| OPEN-WIM-3 | Partly: not the file size (paper contradicted); meaning is a [reading] | OBS-004 |
| OPEN-WIM-4 | Partly: `.esd` flags recorded; its compression is undocumented | OBS-006 |
| OPEN-WIM-5 | Answered for forms seen (R4) | OBS-010, 046, 057 |
| OPEN-WIM-6 | Packing settled; metadata first; lookup order gives the index in every file seen, including when offset order differs (R2); other cases open (see above) | OBS-008, OBS-009, OBS-018, OBS-021, OBS-023 |
| OPEN-WIM-7 | Partly (R3, R4): see above | OBS-024 to 045, 048 to 056 |
| OPEN-WIM-8 | Partly: encoding and element set for non-Windows content; edition, architecture, version not observable (decision 0013) | OBS-014 |
| OPEN-WIM-9 | Partly: shared GUID, part and total | OBS-016 |
| OPEN-WIM-10 | Answered for form seen; threshold open | OBS-011, 047, 058 |
| OPEN-WIM-11 | Partly: unit is 10 MiB; range confirmed; multi-entry open | OBS-015 |
| OPEN-WIM-12 | Settled: [project rule, DEC-0022] | OBS-049 to 052 |
| OPEN-WIM-13 | Open (volume-root capture never applied) | none |

**Never observed in R1 to R4** (the 8-byte chunk-table entry and the
short raw final chunk, listed here after R3, were seen in R4: OBS-058,
OBS-057): an integrity table with more than one entry; a
bootable image (non-zero boot index); a file whose lookup order
differs from its index order (file-offset order does differ in
OBS-021); a commit of any index other than 1; more than two images
sharing one metadata copy; a security index of −1; a non-zero value at
directory entry offsets +24, +32 or +84; a compressed resource of
exactly 2^32 bytes; an LZX resource over 4 GiB; an apply of a
volume-root capture.

**Samples recorded in R2** (asked for by the M2 boot-protocol review
as S11 and S12):

- **S11** (two images with identical metadata), as S11A (same tree
  appended) and S11B (same index exported twice): recorded, OBS-018,
  OBS-019, OBS-020.
- **S12A** (mount and commit of index 1): recorded, OBS-020, OBS-021,
  OBS-022.
- **S12B** (delete index 1, then append): recorded, OBS-020, OBS-023.

**Samples recorded in R3** (asked for by the M3 plan, questions M-01
to M-23):

- **S13** (uncompressed capture of a metadata test tree), **S14** (the
  same tree, XPRESS) and **S15** (its volume root): recorded, OBS-024
  to OBS-044, OBS-048.
- **S16** (DISM's apply of S13, compared with the source): recorded,
  OBS-037, OBS-038, OBS-040, OBS-041, OBS-045.
- **S17** (compressible and pseudorandom halves in one file): recorded,
  OBS-046. It replaces the "mixed file" request.
- **S08** (a file over 4 GiB): recorded, OBS-047, but stored
  uncompressed, so it did not answer OPEN-WIM-10.

**Samples recorded in R4** (AUDITED 2026-10-28; asked for after R3):

- **S13B** (a second metadata tree with in-tree and out-of-tree
  absolute links, relative links, sparse files with several holes and
  files with several named streams, captured with the fix) and
  **S13C** (the same tree with DISM's no-fix option): recorded,
  OBS-049 to OBS-056.
- **S16B**, **S16C** and **S16D** (applies to another drive letter, to
  a subdirectory, and of S13C): recorded, OBS-050, OBS-051, OBS-053,
  OBS-054.
- **S17B** (short pseudorandom final chunks): recorded, OBS-057.
- **S08B** (a compressible file over 4 GiB): recorded, OBS-058 (dump
  only).
- S13D was not run as such: R4 compared descriptors with .NET's
  re-serialisation only, so its byte-equality part is still needed.

**Samples still needed** (from the M2 boot-protocol review and runs R2
to R4):

- a tree with long runs (for example 32 KiB of zero bytes and a
  repeated 300-byte pattern), to exercise long matches and many-chunk
  tables;
- a bootable Windows PE image, once OPEN-PE-LIC allows it, for the boot
  index and boot metadata header (§2, §11); no R1 file has a non-zero
  boot index, so these fields have no sample at all;
- an export of a multi-image file in reverse index order (OPEN-WIM-6);
- **S12C**: a commit of index 5 of a multi-image file, to see whether
  lookup order still gives the index when the moved metadata is not
  the first (§5, OPEN-WIM-6);
- **S12D**: a commit of index 1 and then of index 3 in the same file,
  to see the order after two commits (§5, OPEN-WIM-6);
- **S11C**: the same tree appended three times, to see whether three
  identical images share one copy through three adjacent equal entries
  (§5, OPEN-WIM-6);
- **S11D**: images A, B, then A again by export, to see what happens
  when identical images are not adjacent in index order (§5,
  OPEN-WIM-6);
- an integrity sample over 10 MiB (OPEN-WIM-11);
- **S13D** (narrowed after R4): a binary dump of the descriptors
  Windows itself returns for the tree, not a .NET re-serialisation,
  and any entry with security index −1 if DISM can be made to write
  one (M-14, OPEN-WIM-7);
- an apply of the volume-root capture S15 to another drive letter and
  to a subdirectory (OPEN-WIM-13);
- a compressible resource of exactly 2^32 bytes, and an LZX resource
  over 4 GiB (OPEN-WIM-10);
- stream names that differ only in case (M-09 case folding).
- Recorded in R4 and no longer needed: S08B, S13B, S13C, S13E (as
  part of S13B), S13F (as part of S13B) and the short final chunk
  (S17B).

Any [reading] or OPEN point can be settled by testing against files made
with Microsoft's DISM. That is interoperability testing with Microsoft's
public tool, not use of any provisioning vendor's material. How that
testing is done and recorded, and what may not be consulted, is set by
project decision 0006
(`docs/decisions/0006-wim-format-by-black-box-test-files.md`). The
results so far are the [observed] notes in this file, from
`docs/formats/wim-observed.md`.

## 14. Security notes

- The format's hashes (lookup table, integrity table, directory entries)
  are SHA-1 and unkeyed. There is no signature. Anyone who can change the
  file can recompute them. They detect accidental corruption only.
- Proof that an image is the one the operator intended must come from
  outside the format (see `security-baseline.md`).
- All sizes, offsets, counts and the XML text come from the file. A reader
  must treat them as untrusted input.
- **[observed]** Deleting or changing an image with DISM did not remove
  the old data from the file: replaced and deleted metadata, and old
  lookup tables and XML, stayed in place, named by nothing (OBS-020,
  OBS-022, OBS-023).
- **[derived]** From that observation: content that an operator
  believes was removed from a WIM may still be present in its bytes.
