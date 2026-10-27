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

Labels: **[derived]** means we computed it from facts the sources state
(for example, offsets from field order and sizes). **[reading]** means our
interpretation where the source is silent or ambiguous. Neither is stated
by Microsoft. Each has an OPEN item in §13 where it matters.

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
| 20 | 4 | `dwCompressionSize` | The paper describes this as the size of the compressed file in bytes (OPEN-WIM-3) |
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

Total: 208 bytes **[derived]**. Readers should still use `cbSize` and the
resource headers rather than assume 208.

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

## 9. Byte order

The paper does not state the byte order of multi-byte fields
(OPEN-WIM-1). **[reading]**: little-endian, the native order of the
Windows structures the paper uses. Confirm with files made by Microsoft's
own DISM before relying on it.

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
| Integrity chunk | "10MB" (use the stored field) | WIM paper |
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

Any [reading] or OPEN point can be settled by testing against files made
with Microsoft's DISM. That is interoperability testing with Microsoft's
public tool, not use of any provisioning vendor's material. How that
testing is done and recorded, and what may not be consulted, is set by
project decision 0006
(`docs/decisions/0006-wim-format-by-black-box-test-files.md`).

## 14. Security notes

- The format's hashes (lookup table, integrity table, directory entries)
  are SHA-1 and unkeyed. There is no signature. Anyone who can change the
  file can recompute them. They detect accidental corruption only.
- Proof that an image is the one the operator intended must come from
  outside the format (see `security-baseline.md`).
- All sizes, offsets, counts and the XML text come from the file. A reader
  must treat them as untrusted input.
