# Standards summary: GPT disks and the Windows UEFI partition layout

Status: AUDITED (M3, 2026-10-28; re-audit round 1).

Topic 8 of the standards reading list. For DISK-1 (`specs/disk.md`) and
BOOT-5 (`specs/boot-network.md`). This is our own summary of:

- UEFI Specification 2.10, chapter 5 (GUID Partition Table format), with
  §1.9.1 (byte order), §4.2.1 (CRC algorithm) and §13.3 (file system and
  partition discovery);
- Microsoft Learn: "UEFI/GPT-based hard drive partitions", "Windows and
  GPT FAQ", "PARTITION_INFORMATION_GPT structure", "Deployment lab sample
  scripts", "Windows 11 requirements".

Constants, field names, offsets and GUIDs below come from those
standards. Which optional parts usg-provision uses is a clean-side
decision. On-disk NTFS and FAT32 structures are deliberately not
summarised (§9 gives only what Microsoft states at summary level).

## 1. Conventions (UEFI §1.9.1, §2.3.1)

- All UEFI data structures are **little-endian**: the low-order byte of a
  multi-byte value is at the lowest address (§1.9.1).
- Bit 0 of a bit field is its least significant bit (§2.3.1).
- LBA means logical block address; a logical block is the device's
  reported block size (commonly 512 or 4096 bytes).

## 2. Overall disk layout (UEFI §5.3.1)

In LBA order:

1. LBA 0: protective MBR (§3).
2. LBA 1: primary GPT header (§4).
3. Primary partition entry array, after the primary header and ending
   before `FirstUsableLBA`.
4. Usable area: `FirstUsableLBA` to `LastUsableLBA` inclusive. All
   partitions lie here.
5. Backup partition entry array, after `LastUsableLBA` and ending before
   the backup header.
6. Last LBA of the device: backup GPT header.

The entry array must reserve at least **16,384 bytes**. With 512-byte
blocks that makes `FirstUsableLBA` at least 34; with 4096-byte blocks at
least 6 (§5.3.2).

## 3. Protective MBR at LBA 0 (UEFI §5.2.3, §5.2.2)

A bootable GPT disk carries a protective MBR so that tools which know
only MBR see one partition covering the disk rather than free space.

- Boot code area: unused by UEFI. Disk signature and the unknown field
  (offsets 440 and 444) are zero.
- Partition record 1 (at offset 446, 16 bytes):
  - BootIndicator `0x00`;
  - StartingCHS `0x000200`;
  - OSType `0xEE` (GPT protective);
  - EndingCHS: CHS of the last block, or `0xFFFFFF` if not
    representable;
  - StartingLBA `1`;
  - SizeInLBA: size of the disk minus one, or `0xFFFFFFFF` if that does
    not fit in 32 bits.
- Records 2 to 4: all zero.
- Signature at offset 510: `0xAA55`. The rest of the block is zero.
- OSType `0xEF` marks a UEFI system partition in a **legacy** MBR. Windows
  does not support UEFI boot from MBR disks or from `0xEF` partitions
  (Windows and GPT FAQ).

## 4. GPT header (UEFI §5.3.2, Table 5.5)

| Offset | Length | Field | Rule |
|--------|--------|-------|------|
| 0 | 8 | Signature | ASCII `EFI PART` (`0x5452415020494645` read as a little-endian 64-bit value) |
| 8 | 4 | Revision | `0x00010000` (1.0) |
| 12 | 4 | HeaderSize | At least 92 and at most the logical block size |
| 16 | 4 | HeaderCRC32 | CRC of the header (§6) |
| 20 | 4 | Reserved | Zero |
| 24 | 8 | MyLBA | LBA holding this header |
| 32 | 8 | AlternateLBA | LBA of the other header |
| 40 | 8 | FirstUsableLBA | First LBA a partition may use |
| 48 | 8 | LastUsableLBA | Last LBA a partition may use |
| 56 | 16 | DiskGUID | Unique identifier of the disk |
| 72 | 8 | PartitionEntryLBA | Start of this header's entry array |
| 80 | 4 | NumberOfPartitionEntries | Number of entries in the array |
| 84 | 4 | SizeOfPartitionEntry | 128 × 2^n, n ≥ 0 (earlier spec versions allowed any multiple of 8) |
| 88 | 4 | PartitionEntryArrayCRC32 | CRC of the entry array (§6) |
| 92 | block size − 92 | Reserved | Zero |

The backup header mirrors the primary, with `MyLBA` and `AlternateLBA`
swapped and `PartitionEntryLBA` pointing at the backup array.

## 5. Partition entry (UEFI §5.3.3, Tables 5.6 to 5.8)

| Offset | Length | Field |
|--------|--------|-------|
| 0 | 16 | PartitionTypeGUID (all zero = unused entry) |
| 16 | 16 | UniquePartitionGUID |
| 32 | 8 | StartingLBA |
| 40 | 8 | EndingLBA (**inclusive**) |
| 48 | 8 | Attributes |
| 56 | 72 | PartitionName: 36 UTF-16 code units, null-terminated |
| 128 | SizeOfPartitionEntry − 128 | Reserved, zero |

Attribute bits (UEFI Table 5.8):

- Bit 0, **Required Partition**: the platform may not work if the
  partition is removed.
- Bit 1, **No Block IO Protocol**: firmware must not expose the partition
  as a block device (and so will not treat it as a system partition,
  §13.3.3).
- Bit 2, **Legacy BIOS Bootable**: ignored by the UEFI boot manager.
- Bits 3 to 47: undefined, must be zero.
- Bits 48 to 63: defined by the owner of the partition type.

Every new partition gets a **new** UniquePartitionGUID; a copy of a disk
or partition must get new GUIDs (§5.3.3). Microsoft says never to make a
sector-by-sector copy of a whole GPT disk for the same reason (Windows
and GPT FAQ).

## 6. CRC32 (UEFI §4.2.1, §5.3.2)

- UEFI uses the standard CCITT32 CRC with polynomial `0x04C11DB7` unless
  another algorithm is stated (§4.2.1). The fetched pages do not state
  initial value, reflection or final XOR (**OPEN-GPT-1**: confirm the
  full parameter set, for example against a known-good disk image made
  by Microsoft's tools, before relying on it).
- **HeaderCRC32**: set the field to zero, then compute over `HeaderSize`
  bytes of the header (§5.3.2).
- **PartitionEntryArrayCRC32**: computed over
  `NumberOfPartitionEntries × SizeOfPartitionEntry` bytes from
  `PartitionEntryLBA`; unused space at the end of the last block is not
  included.
- Because the array CRC sits in the header, changing any entry changes
  the header CRC too.

## 7. Validation and update rules (UEFI §5.3.1, §5.3.2)

A header is valid only if:

1. the signature matches;
2. HeaderCRC32 is correct;
3. `MyLBA` equals the LBA it was read from;
4. PartitionEntryArrayCRC32 is correct;
5. for the primary, `AlternateLBA` points to a valid backup header.

Recovery and update:

- If the primary is invalid, use the backup at the last LBA. Software
  should restore the primary if policy allows and must report that it
  did.
- If the primary is valid and the backup is not, restore the backup.
- If both are invalid, the disk has no valid GPT.
- Software that changes the GPT **updates the backup first**, then the
  primary, so that an interrupted update still leaves a findable backup.
- Each partition lies within `FirstUsableLBA`..`LastUsableLBA` and does
  not overlap any other. Only partitioning structures may lie outside
  that range.

## 8. Alignment (UEFI §5.3.1)

- Partitions should start on a multiple of the larger of the physical
  block size and the optimal transfer-length granularity. Example: 512-
  byte logical blocks on 4096-byte physical blocks means multiples of 8
  LBAs.
- To avoid detecting those values, use multiples of **2,048 LBAs (1 MiB
  for 512-byte blocks)**.

## 9. Partition types and attributes Windows uses

From "PARTITION_INFORMATION_GPT" and "Windows and GPT FAQ" (GUIDs shown
in the usual text form, `uefi-guid-text.md` §1):

| Partition | Type GUID |
|-----------|-----------|
| Unused entry | `00000000-0000-0000-0000-000000000000` |
| EFI system partition (ESP) | `C12A7328-F81F-11D2-BA4B-00A0C93EC93B` |
| Microsoft reserved (MSR) | `E3C9E316-0B5C-4DB8-817D-F92DF00215AE` |
| Basic data (Windows volumes) | `EBD0A0A2-B9E5-4433-87C0-68B6B72699C7` |
| Microsoft recovery | `DE94BBA4-06D1-4D40-A16A-BFD50179D6AC` |
| LDM metadata (dynamic disks) | `5808C8AA-7E8F-42E0-85D2-E1E90434CFB3` |
| LDM data (dynamic disks) | `AF9B60A0-1431-4F62-BC68-3311714A69AD` |
| Partition holding a legacy MBR (UEFI) | `024DEE41-33E7-11D3-9D69-0008C781F39F` |

Attribute values Microsoft documents (64-bit value, bit 0 shared with
UEFI's Required Partition):

| Value | Meaning |
|-------|---------|
| `0x0000000000000001` | Platform required (UEFI bit 0); Windows treats it as an OEM/utility partition |
| `0x8000000000000000` | No drive letter by default |
| `0x4000000000000000` | Hidden from the mount manager (no letter, no volume path) |
| `0x2000000000000000` | Shadow copy (used by VSS) |
| `0x1000000000000000` | Read-only (not for dynamic disks) |

Only basic data partitions get drive letters or volume paths in Windows.

## 10. Microsoft's recommended UEFI layout for Windows

From "UEFI/GPT-based hard drive partitions" (updated 2026-09-09) and the
UEFI sample in "Deployment lab sample scripts", unless marked otherwise.

- The drive that holds the Windows partition **must be GPT** when Windows
  is deployed to a UEFI device. A GPT drive may have up to **128**
  partitions in Windows (also the FAQ).
- **Default order**: (1) system partition (ESP), (2) MSR, (3) Windows,
  (4) recovery. This order lets BitLocker work both from Windows and from
  the recovery environment.

| # | Partition | Type | File system | Size | Attributes and notes |
|---|-----------|------|-------------|------|----------------------|
| 1 | ESP | ESP GUID | FAT32 | Minimum 200 MB on 512-byte native or 512e drives; minimum 300 MB on 4K-native drives | Managed by the OS; holds only boot files, not recovery tools. Microsoft's sample uses exactly 200 MB (300 MB for 4Kn). |
| 2 | MSR | MSR GUID | none | **16 MB** | No file system, no drive letter, no user data. |
| 3 | Windows | Basic data GUID | NTFS | At least 20 GB for 64-bit (16 GB for 32-bit); must keep 16 GB free after first-run setup and maintenance | Takes the rest of the disk less the recovery partition. |
| 4 | Recovery | Recovery GUID | NTFS | Size of the recovery image (`winre.wim` from the image being deployed) plus any customisations plus **250 MB** free for servicing. For a custom partitioning script Microsoft recommends at least **990 MB** with at least 250 MB free. The sample shrinks the Windows partition by 500 MB to make room. | Must be **immediately after** the Windows partition so Windows can grow it later. Sample sets attributes `0x8000000000000001` (platform required + no drive letter). |

Further rules:

- Utility partitions not managed by Windows go **before** the Windows,
  data and recovery partitions and should carry the platform-required
  attribute. Data partitions, if any, go after the recovery partition.
- The FAQ adds: the ESP should be first on the disk; an OEM partition goes
  after the ESP and before the MSR; the MSR must be created when the disk
  is first partitioned and before any basic data partition; only one ESP
  per system.
- **Inconsistency to note**: the FAQ (dated 2017) says the MSR is 32 MB
  on drives under 16 GB and 128 MB otherwise, and that the ESP is about
  100 MB. The current partition guidance (2026) says 16 MB and 200/300 MB.
  The newer page and the sample script agree on 16 MB and 200/300 MB.
- During deployment from WinPE, Microsoft's samples give the partitions
  temporary drive letters and avoid `X:`, which WinPE uses for itself.
  After first boot Windows takes `C:` and the other partitions have no
  letter.
- Microsoft's sample "cleans" the disk (removes all partition
  information), converts it to GPT, creates the four partitions in order,
  formats them, and sets the recovery type and attributes. Its
  interactive wrapper first checks that WinPE booted in UEFI mode, warns
  that all data on the disk will be deleted, and asks for confirmation
  before erasing. (Sample practice, not a requirement of the standard.)

## 11. File systems at summary level

- **ESP**: FAT32 (Microsoft partition guidance). UEFI firmware must
  support FAT12, FAT16 and FAT32; a system partition uses FAT32, and
  removable media may use FAT12/16 (UEFI §13.3, §13.3.1.1). On fixed
  media the ESP has an `\EFI` directory with one subdirectory per vendor;
  each vendor directory holds at most one executable image per
  architecture; `\EFI\BOOT` is optional on fixed media and required on
  removable media (§13.3.1.3).
- **Windows and recovery partitions**: NTFS. Windows Setup and Disk
  Management offer only NTFS for basic data partitions; Windows file
  systems are limited to 256 TB each (Windows and GPT FAQ).
- **FAT32 limits** Microsoft states for WinPE media: 4 GB maximum file
  size, 32 GB maximum drive size (`winpe.md` §6). The 200 to 300 MB ESP
  is far below the volume limit.

## 12. Firmware discovery of partitions (UEFI §13.3.2, §13.3.3)

- Firmware looks for, in order: a valid GPT, ISO 9660, El Torito, and a
  legacy MBR; it stops at the first that validates.
- It exposes a block device for each GPT entry without attribute bit 1.
- It finds system partitions by the ESP type GUID and a conforming FAT
  file system. UEFI does not limit the number or location of ESPs.

## 13. Windows 11 minimums relevant to disk choice ("Windows 11 requirements", 2026-07-14)

- Storage: **64 GB** or more available.
- Firmware: UEFI, Secure Boot capable. TPM 2.0. Memory 4 GB.
- Virtual machines: generation 2, 64 GB disk.

## Open points

- **OPEN-GPT-1**: full CRC-32 parameter set (initial value, reflection,
  final XOR); only the polynomial and the "CCITT32" name are stated.
- **OPEN-GPT-2**: the MSR and ESP size conflict between the 2017 FAQ and
  the 2026 partition guidance (§10). This summary follows the newer page.
