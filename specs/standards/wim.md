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
  `docs/formats/wim-observed.md`, records OBS-001 to OBS-017, made under
  project decision 0006 from WIM files the project built itself with
  Microsoft's DISM. All records so far come from one run, **R1**
  (workflow run 40535666995, commit ba23bed; DISM file version
  10.0.26100.32860 on Windows build 26100.33650).

Labels: **[derived]** means we computed it from facts the sources state
(for example, offsets from field order and sizes). **[reading]** means our
interpretation where the source is silent or ambiguous. Neither is stated
by Microsoft. Each has an OPEN item in §13 where it matters.

Two further labels were added in M2 fix round 1 (drift):

- **[observed]** marks what was seen in the R1 files, cited by record
  (OBS-nnn). It is evidence about those files only, not a statement by
  Microsoft, and says nothing about other DISM builds or other tools.
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
- **[observed]** The 8-byte entry width was never seen; the threshold
  stays **open** (OPEN-WIM-10) until a sample over 4 GiB exists.
- **[observed]** Resource level of OPEN-WIM-5 (OBS-010): inside an
  XPRESS file, a whole resource that did not shrink (pseudorandom data,
  and every file of 59 bytes or less) is stored as plain bytes, with
  flag 0x04 clear and no chunk table. Whether a resource is compressed
  is therefore decided per resource, by its own flag, not by the header.
- **Never observed**: a compressed resource in which one chunk did not
  shrink. No R1 chunk has a stored size equal to its expanded size
  (OBS-010, OBS-012). How such a chunk is stored stays **open**
  (OPEN-WIM-5, chunk level).
- **Impact note** (from the M2 boot-protocol review): if a reader
  refuses a chunk whose stored size equals its expanded size, then in
  M2 this affects only metadata. Once images are applied (M3), it would
  affect file data as well.

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
  is **confirmed** for R1.
- **[observed]** Metadata entries come first in the table in every
  single-file `.wim` of R1 and in split part 1 (OBS-009). In the
  12-image file, the k-th entry
  with the metadata flag is the metadata of image index k. In that file
  lookup order, file-offset order and index order are the same, so
  which of them a reader should use is **still open** (OPEN-WIM-6,
  mapping part). A sample whose orders differ is needed.

## 6. Metadata resource (WIM paper, "WIM Metadata Resource")

Needed to apply an image (a later milestone), and summarised here for
completeness. One per image. It holds security data, then the directory
tree.

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
  **[reading]**). Fixed part 98 bytes **[derived]**.
- **Alternate stream entries** follow a directory entry when it has
  alternate streams: length (8), reserved (8), SHA-1 hash (20), stream
  name length (2), stream name.
- Each directory (not each entry) ends with a 64-bit zero. Each entry is
  aligned (the paper states four-byte alignment here and quad alignment
  for the root; OPEN-WIM-7).
- The full path of a file is rebuilt by walking up through its parents.
- Where the short name is stored is not stated (OPEN-WIM-7).

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
- **OPEN-WIM-6**: lookup entry packing, and how metadata entries map to
  image indexes (§5).
- **OPEN-WIM-7**: directory entry alignment and short-name placement
  (§6).
- **OPEN-WIM-8**: the content of `NAME`, `DESCRIPTION`, `FLAGS` and
  `WINDOWS` in the XML data, in particular where edition, architecture,
  version and languages are recorded (§7).
- **OPEN-WIM-9**: how the parts of one split set are matched (§10).
- **OPEN-WIM-10**: whether the 4 GB chunk-table threshold is 2^32 bytes
  and whether it is "over" or "at least" (§4).
- **OPEN-WIM-11**: the integrity chunk size unit (§8).

**Status after R1** (M2 fix round 1, drift). An observation settles a
point for the R1 files only; other DISM builds are not covered.

| Item | Status after R1 | Records |
|------|-----------------|---------|
| OPEN-WIM-1 | Settled for R1: little-endian | OBS-002 |
| OPEN-WIM-2 | Partly: values written are known; which to accept is open | OBS-003 |
| OPEN-WIM-3 | Partly: not the file size (paper contradicted); meaning is a [reading] | OBS-004 |
| OPEN-WIM-4 | Partly: `.esd` flags recorded; its compression is undocumented | OBS-006 |
| OPEN-WIM-5 | Resource level settled; chunk level open | OBS-010 |
| OPEN-WIM-6 | Packing settled; metadata first; index mapping partly settled | OBS-008, OBS-009 |
| OPEN-WIM-7 | Open (not examined; not needed in M2) | none |
| OPEN-WIM-8 | Partly: encoding and element set for non-Windows content; edition, architecture, version not observable (decision 0013) | OBS-014 |
| OPEN-WIM-9 | Partly: shared GUID, part and total | OBS-016 |
| OPEN-WIM-10 | Width 4 below 2^32 confirmed; threshold open | OBS-011 |
| OPEN-WIM-11 | Partly: unit is 10 MiB; range confirmed; multi-entry open | OBS-015 |

**Never observed in R1**: an 8-byte chunk-table entry; a raw chunk
inside a compressed resource; an integrity table with more than one
entry; a bootable image (non-zero boot index); a file whose lookup
order differs from its index order.

**Samples still needed** (from the M2 boot-protocol review):

- a tree with long runs (for example 32 KiB of zero bytes and a
  repeated 300-byte pattern), to exercise long matches and many-chunk
  tables;
- a bootable Windows PE image, once OPEN-PE-LIC allows it, for the boot
  index and boot metadata header (§2, §11); no R1 file has a non-zero
  boot index, so these fields have no sample at all;
- an export of a multi-image file in reverse index order (OPEN-WIM-6);
- **S11**: a file with two images whose metadata is identical, such as
  the same index exported twice into one file, to see whether the two
  images share one metadata entry or keep two, and how each index then
  finds its metadata (§5, OPEN-WIM-6);
- **S12**: a multi-image file changed after capture, first by mount
  and commit and then by deleting an image and appending another, to
  see whether lookup order, file-offset order and index order can
  differ, and whether unused space is left in the file (§3, §5,
  OPEN-WIM-6);
- a mixed file (compressible then pseudorandom data) for the chunk-level
  case of OPEN-WIM-5;
- the large sample over 4 GiB (OPEN-WIM-10), and an integrity sample
  over 10 MiB (OPEN-WIM-11).

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
