# Standards summary: Windows disk, volume and firmware-variable APIs

Topic 23 of the standards reading list (SR-3, M3 build requests,
2026-10-28; AUDITED 2026-10-28, spec pass). Background for DISK-1
(`specs/disk.md`) and BOOT-5 (`specs/boot-network.md` REQ-BOOT-065),
for a program running in Windows PE. This is a semantics-only summary
of Microsoft Learn reference pages: what each function or control code
does, what it needs and how it reports failure. It is not a design.
Which calls the product uses, and how it binds to them, is the clean
side's choice (DEC-0019 records the binding choice; it adds no spec
text). The follow-up request SR-3b (2026-10-28) added §13 to §19 and
OPEN-WAPI-4 to 6 (AUDITED 2026-10-28; the OPEN items stay open).

Sources: Microsoft Learn Win32 and driver reference pages, one page
per function, structure or control code, named in each section below.
Microsoft's sample code on those pages was not copied. Function,
structure, constant and field names are Microsoft's; the wording is
ours. Pages give no section numbers, so they are cited by title.

Markers:

- **[reading]**: our inference from the cited text, not stated outright.
- **[enum]**: the page lists the enumeration in order and gives only
  some values explicitly; the other values follow from the order (each
  is one more than the one before). The clean side should confirm them
  against Microsoft's published API metadata or headers before use.

## 1. Common pattern for control codes ("DeviceIoControl" usage on each page)

- Each control code (IOCTL) is sent with `DeviceIoControl` to a handle
  opened on a disk, partition or volume. Each page says which input and
  output buffer it takes.
- The pages give the control-code names but not their numeric values
  (**OPEN-WAPI-1**).
- Variable-length outputs are sized in two steps: ask with a small
  buffer, read the size the call reports, then ask again with a buffer
  that large (§3, §8, §2).

## 2. Finding the disks (SetupAPI device interfaces)

Pages: "SetupDiGetClassDevsW function", "SetupDiGetDeviceInterfaceDetailW
function", "GUID_DEVINTERFACE_DISK".

- `GUID_DEVINTERFACE_DISK` is the device interface class for hard-disk
  storage devices: `{53F56307-B6BF-11D0-94F2-00A0C91EFB8B}`. The
  system's storage class drivers register one instance per disk.
- `SetupDiGetClassDevs` with that GUID and the flags
  `DIGCF_DEVICEINTERFACE` (devices exposing the given interface class)
  and `DIGCF_PRESENT` (only devices present now) returns a device
  information set of the disks. On failure it returns
  `INVALID_HANDLE_VALUE` and the error comes from `GetLastError`. The
  set must be released with `SetupDiDestroyDeviceInfoList`.
- The interfaces in the set are walked with
  `SetupDiEnumDeviceInterfaces`. For each,
  `SetupDiGetDeviceInterfaceDetail` returns the **device path**, a
  string that can be passed to `CreateFile` to open the disk.
  - Two-step use: first call with no output buffer; it fails with
    `ERROR_INSUFFICIENT_BUFFER` and reports the size needed. Then call
    with a buffer of that size.
  - The caller sets the structure's `cbSize` to the size of the fixed
    part only, not including the path string.
  - The device path must not be parsed. It can be reused across
    restarts.

## 3. What kind of disk it is (`IOCTL_STORAGE_QUERY_PROPERTY`)

Pages: "IOCTL_STORAGE_QUERY_PROPERTY", "STORAGE_PROPERTY_QUERY",
"STORAGE_PROPERTY_ID", "STORAGE_DEVICE_DESCRIPTOR", "STORAGE_BUS_TYPE",
"STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR".

- Input: a property query with `PropertyId` (which descriptor) and
  `QueryType` (`PropertyStandardQuery` = 0 returns the descriptor;
  `PropertyExistsQuery` = 1 only says whether it is supported and
  returns nothing).
- `PropertyId` values used here: `StorageDeviceProperty` = 0 (device
  descriptor); `StorageAccessAlignmentProperty` = 6 [enum] (access
  alignment descriptor, Windows Vista and later).
- Sizing: first ask with an output buffer that holds only the common
  descriptor header; its `Size` gives the full length to allocate.

### 3.1 Device descriptor (`STORAGE_DEVICE_DESCRIPTOR`)

- `RemovableMedia`: true when the device's media is removable; to be
  ignored if the device has no media.
- `BusType`: the bus the device is attached to (§3.2).
- `VendorIdOffset`, `ProductIdOffset`, `ProductRevisionOffset`,
  `SerialNumberOffset`: byte offsets from the start of the descriptor
  to null-terminated ASCII strings; **zero means the string is
  absent**.
- `DeviceType` and `DeviceTypeModifier` follow SCSI definitions.
- `Size` is the whole descriptor including the appended strings and any
  bus-specific bytes (`RawPropertiesLength`).

### 3.2 Bus types (`STORAGE_BUS_TYPE`)

Listed in this order; only `BusTypeUnknown` = `0x00` and
`BusTypeMaxReserved` = `0x7F` are given explicitly, the rest are
[enum]:

| Value | Name | Value | Name |
|-------|------|-------|------|
| 0 | `BusTypeUnknown` | 11 | `BusTypeSata` |
| 1 | `BusTypeScsi` | 12 | `BusTypeSd` |
| 2 | `BusTypeAtapi` | 13 | `BusTypeMmc` |
| 3 | `BusTypeAta` | 14 | `BusTypeVirtual` |
| 4 | `BusType1394` | 15 | `BusTypeFileBackedVirtual` |
| 5 | `BusTypeSsa` | 16 | `BusTypeSpaces` |
| 6 | `BusTypeFibre` | 17 | `BusTypeNvme` |
| 7 | `BusTypeUsb` | 18 | `BusTypeSCM` |
| 8 | `BusTypeRAID` | 19 | `BusTypeUfs` |
| 9 | `BusTypeiScsi` | 20 | `BusTypeNvmeof` |
| 10 | `BusTypeSas` | 21 | `BusTypeMax` |

The page describes only some of them (USB, SATA, SAS and so on); it
gives no description for `Sd`, `Mmc`, `Virtual`, `FileBackedVirtual`,
`Spaces`, `Nvme`, `SCM`, `Ufs` or `Nvmeof` beyond the name.
`BusTypeNvmeof` appears in the declaration but not in the constants
table.

### 3.3 Sector sizes (`STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR`)

- `BytesPerLogicalSector` and `BytesPerPhysicalSector`; also the cache
  line size and the alignment offsets of the first logical sector.
- Windows sector-size support ("Support policy for 4K sector hard
  drives", Microsoft Learn support article, dated 2026-02-12): 512
  logical / 512 physical (512n) and 512 logical / 4096 physical (512e)
  are supported; 4096 / 4096 (4Kn) is supported from Windows 8, and
  Windows can be installed to and boot from a 4Kn disk. Drives whose
  sector sizes are neither 512 nor 4096 bytes are **not supported**.

## 4. Size and geometry

Pages: "IOCTL_DISK_GET_DRIVE_GEOMETRY_EX", "DISK_GEOMETRY_EX",
"DISK_GEOMETRY", "MEDIA_TYPE", "IOCTL_DISK_GET_LENGTH_INFO".

- `IOCTL_DISK_GET_DRIVE_GEOMETRY_EX`: no input. Output is a
  variable-length structure: a geometry block, then `DiskSize` (bytes,
  64-bit), then partition and detection information whose position is
  not fixed. It does not report the partitions themselves (use the
  drive-layout query for that).
- The geometry block: `Cylinders`, `MediaType`, `TracksPerCylinder`,
  `SectorsPerTrack`, `BytesPerSector`.
- `MediaType` values used here: `Unknown` = 0 (explicit),
  `RemovableMedia` = 11 [enum] ("removable media other than floppy"),
  `FixedMedia` = 12 [enum] ("fixed hard disk media"). The other values
  are floppy formats.
- `IOCTL_DISK_GET_LENGTH_INFO`: no input; returns the length in bytes
  of the disk, volume or partition the handle refers to. For a volume
  handle, the last few sectors are not reachable without an extra
  file-system control call.

## 5. Writing a partition table

Pages: "IOCTL_DISK_CREATE_DISK", "IOCTL_DISK_SET_DRIVE_LAYOUT_EX",
"DRIVE_LAYOUT_INFORMATION_EX", "IOCTL_DISK_UPDATE_PROPERTIES".

- `IOCTL_DISK_CREATE_DISK`: initialises the disk and its partition
  table from a `CREATE_DISK` input: the partition style and, for GPT,
  `CREATE_DISK_GPT` with `DiskId` (the new disk GUID) and
  `MaxPartitionCount` (entries allowed without repartitioning; a value
  below 128 is raised to 128, in line with the EFI rules). After
  creating a GPT disk, the caller should
  wait until the system reports the arrival of the Microsoft reserved
  partition before sending the layout call.
- `IOCTL_DISK_SET_DRIVE_LAYOUT_EX`: partitions the disk to match the
  layout given. The caller must have write access to the drive.
- Layout input (`DRIVE_LAYOUT_INFORMATION_EX`): `PartitionStyle`
  (`PARTITION_STYLE_MBR` = 0, `PARTITION_STYLE_GPT` = 1,
  `PARTITION_STYLE_RAW` = 2, all explicit), `PartitionCount`, a
  style-specific header, then one `PARTITION_INFORMATION_EX` entry per
  partition. On MBR disks the count is always a multiple of 4 and
  unused slots have type 0.
- GPT header (`DRIVE_LAYOUT_INFORMATION_GPT`): `DiskId` (disk GUID),
  `StartingUsableOffset` (byte offset of the first usable block),
  `UsableLength` (bytes), `MaxPartitionCount`.
- Each entry (`PARTITION_INFORMATION_EX`): `PartitionStyle`,
  `StartingOffset` and `PartitionLength` (**bytes**, not blocks),
  `PartitionNumber` (1-based), `RewritePartition` (Microsoft says to
  set it to true), `IsServicePartition` and `PartitionOrdinal` (no
  description on the page), then the style-specific part
  (`PARTITION_INFORMATION_GPT`, `gpt.md` §9).
- `IOCTL_DISK_UPDATE_PROPERTIES`: no input or output. It discards the
  system's cached partition table and re-enumerates the disk. Microsoft
  says to send it when the partition table has been changed directly,
  so that the system's view matches the disk. The volume need not be
  locked for it.

## 6. Is the disk writable (`IOCTL_DISK_IS_WRITABLE`)

Page: "IOCTL_DISK_IS_WRITABLE".

- No input or output; it determines whether the disk is writable. The
  page does not say how "not writable" is reported (which error code)
  (**OPEN-WAPI-2**). **[reading]** The answer is carried by whether the
  call succeeds.

## 7. Which disk is which (`IOCTL_STORAGE_GET_DEVICE_NUMBER`)

Pages: "IOCTL_STORAGE_GET_DEVICE_NUMBER", "STORAGE_DEVICE_NUMBER".

- Returns `DeviceType`, `DeviceNumber` and `PartitionNumber`.
  `PartitionNumber` is −1 when the device cannot be partitioned.
- The values hold only until the device is removed or the system
  restarts. They are **not** stable across restarts, so they must not
  be stored as a lasting disk identity.
- **[reading]** A volume's extents (§8) carry only a disk number, not a
  device type. Comparing a disk handle's `DeviceNumber` with the disk
  numbers in a volume's extents tells whether the volume lies on that
  disk.

## 8. Volumes, their disks and mount points

Pages: "FindFirstVolumeW function", "IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS",
"VOLUME_DISK_EXTENTS", "SetVolumeMountPointW function", "Naming a
Volume".

- Volume names: the system names each volume with a volume GUID path
  of the form `\\?\Volume{GUID}\`. A volume can have more than one such
  path. The system assigns it when the volume is first installed and
  when it is formatted.
- Trailing backslash: the volume and mounted-folder functions expect a
  volume GUID path that ends in a backslash, and the paths they return
  end in one. `CreateFile` is the exception: without the final
  backslash it opens the volume device; with it, the root directory of
  the volume.
- `FindFirstVolume` starts a scan and returns the first volume GUID
  path; `FindNextVolume` continues; `FindVolumeClose` ends the scan.
  Failure to find any volume returns `INVALID_HANDLE_VALUE`. The order
  has no relation to drive letters or disk order.
- `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS`: no input. Returns the number
  of extents and, for each (`DISK_EXTENT`), the disk number (the same
  number as in the disk's `PhysicalDriveN` name), the byte offset from
  the start of the disk, and the length in bytes. A volume can span
  several disks. If there is more than one extent and the buffer holds
  only one, the call fails with `ERROR_MORE_DATA`; call again with room
  for the reported count.
- `SetVolumeMountPoint(mount point, volume GUID path)`: gives a volume a
  drive letter (`X:\`) or mounts it on an empty folder of another
  volume. Both strings must end with a backslash. The target folder
  must be completely empty (hidden and system entries count too), or
  the call fails. Returns nonzero on success and zero on failure, with the
  reason from `GetLastError`. `GetVolumeNameForVolumeMountPoint` gives
  the volume GUID path for a mount point.

## 9. Firmware variables

Pages: "GetFirmwareEnvironmentVariableExW function",
"SetFirmwareEnvironmentVariableExW function". Both: Windows 8 and
later; Kernel32.

- Arguments: the variable name (for example `BootOrder`); the namespace
  GUID as a string in braces, `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`
  (for the boot variables, the `EFI_GLOBAL_VARIABLE` GUID of
  `uefi-boot-manager.md` §10.3); a buffer and its size in bytes; the
  attributes.
- Attributes (Microsoft's `VARIABLE_ATTRIBUTE_*` names; the same bit
  values as UEFI's, `uefi-boot-manager.md` §10.3):
  `NON_VOLATILE` `0x01`, `BOOTSERVICE_ACCESS` `0x02`, `RUNTIME_ACCESS`
  `0x04` (needs `BOOTSERVICE_ACCESS` too), `HARDWARE_ERROR_RECORD`
  `0x08`, `AUTHENTICATED_WRITE_ACCESS` `0x10`,
  `TIME_BASED_AUTHENTICATED_WRITE_ACCESS` `0x20`, `APPEND_WRITE`
  `0x40`.
- Get: returns the number of bytes stored, or zero on failure (reason
  from `GetLastError`), and can also return the variable's attributes.
- Set: returns nonzero on success. A size of zero deletes the variable
  (unless an append or authenticated-write attribute is given). To
  change a variable's attributes, delete it and create it again.
- Privilege: **both reading and writing** need the caller to hold
  `SE_SYSTEM_ENVIRONMENT_NAME` (§10).
- Legacy BIOS: both functions always fail on a legacy BIOS system, or
  when Windows was installed in legacy BIOS mode on a dual-mode
  machine. Microsoft's documented test: call Get with an empty name and
  the all-zero GUID. It fails with `ERROR_INVALID_FUNCTION` on legacy
  BIOS, and with a firmware-specific error such as `ERROR_NOACCESS` on
  UEFI (the namespace does not exist). `winpe.md` §5.3 gives another
  way to tell how WinPE booted.

## 10. Privileges

Pages: "Privilege Constants (Winnt.h)", "AdjustTokenPrivileges
function".

- `SE_SYSTEM_ENVIRONMENT_NAME` is the string `SeSystemEnvironmentPrivilege`.
  It is needed to change non-volatile configuration memory (user
  right: modify firmware environment values).
- Privileges are identified in a token by a locally unique identifier
  (LUID). `LookupPrivilegeValue` turns the privilege name into the
  LUID on the local system.
- `AdjustTokenPrivileges` enables or disables privileges the token
  already holds (attribute `SE_PRIVILEGE_ENABLED` to enable). It cannot
  add a privilege the token lacks. The token handle needs
  `TOKEN_ADJUST_PRIVILEGES` access, and `TOKEN_QUERY` too if the
  previous state is asked for.
- **Success does not mean the privilege was enabled.** On a nonzero
  return, `GetLastError` is `ERROR_SUCCESS` if every privilege asked
  for was adjusted, or `ERROR_NOT_ALL_ASSIGNED` if the token lacks one
  or more of them (possibly none was adjusted). A zero return is a
  failure.

## 11. Facts relevant to which disks may be targets

Background for `specs/disk.md` OPEN-DISK-4 and OPEN-DISK-5. These are
Microsoft facts, not product behaviour.

- A disk reports its bus (§3.2), whether its media is removable (§3.1,
  and `MediaType`, §4), and its logical sector size (§3.3).
- The pages read do not say that a USB disk always reports removable
  media. **[reading]** Bus type and the removable flag are separate
  fields, so a check on one does not cover the other.
- `BusTypeSd`, `BusTypeMmc` and `BusTypeFileBackedVirtual` exist as
  distinct bus types (§3.2); their meanings are not described.
- Windows does not support logical sector sizes other than 512 and
  4096 bytes (§3.3).
- Whether a disk is writable can be asked directly (§6).

## 12. Open points

- **OPEN-WAPI-1**: the numeric values of the control codes (§1) and of
  the [enum] values are not given on the pages read. Where they come
  from is clean-side design (DEC-0019).
- **OPEN-WAPI-2**: which error `IOCTL_DISK_IS_WRITABLE` reports for a
  write-protected disk (§6) is not stated.
- **OPEN-WAPI-3**: `IsServicePartition` and `PartitionOrdinal` in a
  partition entry (§5) have no description on Microsoft's page; what
  to put in them when writing a layout is not stated.
- **OPEN-WAPI-4** (SR-3b, AUDITED): which error
  `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS` returns for a volume that is
  not backed by a disk (RAM disk, CD/DVD, network or other virtual
  volume). No Microsoft page read states it (§13). The Win32 page's
  Remarks say only that the request is not supported over SMB 3.0,
  which does not settle the code. Only an observation on Windows PE
  itself can settle it; that is clean-side work.
- **OPEN-WAPI-5** (SR-3b, AUDITED): which errors `FSCTL_LOCK_VOLUME` and
  `FSCTL_DISMOUNT_VOLUME` return when the volume is in use, is a system
  or page-file volume, or is locked by another process. The pages state
  the conditions but name no error codes (§14).
- **OPEN-WAPI-6** (SR-3b, AUDITED): the form of the link names that
  `FindFirstFileNameW` and `FindNextFileNameW` return (for example
  whether they include the drive) is not stated (§19).

## 13. Volumes not backed by a disk (SR-3b item 3; AUDITED)

Pages: "IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS" (Win32, and the
driver-reference page for the same request in ntddvol.h),
"VOLUME_DISK_EXTENTS", "GetDriveTypeW function",
"STORAGE_DEVICE_NUMBER". Background: `winpe.md` §9 (Windows PE runs
from a RAM disk as drive `X:`).

- **What Microsoft documents for the extents request.** The Win32 page
  lists no error codes. The driver-reference page gives only the
  buffer cases:
  - output buffer smaller than the fixed structure: the request fails
    with `STATUS_INVALID_PARAMETER` and returns no data;
  - large enough for the fixed structure but not for every extent:
    `STATUS_BUFFER_OVERFLOW`, with the fixed part (including the extent
    count) filled in. The `VOLUME_DISK_EXTENTS` structure page reports
    this case to Win32 callers as `ERROR_MORE_DATA` (§8);
  - large enough: success, with every extent.
  The driver page also says the request was first available only for
  volumes on fixed disks, and for removable media from Windows 2000
  SP4 and Windows XP SP1. The Win32 page's Remarks say the request is
  not supported over SMB 3.0 (background only; it names no error
  code).
- **What it does not document.** No page read says what the request
  returns for a RAM disk, an optical disc, a network volume or another
  virtual volume. A search of Microsoft Learn found no statement
  either, and no Microsoft page read confirms how the driver status
  codes above map to Win32 error codes beyond `ERROR_MORE_DATA`
  (**OPEN-WAPI-4**).
- **Documented ways to classify a volume first.**
  - `GetDriveType(root path)` (the root path needs a trailing
    backslash) returns: `DRIVE_UNKNOWN` 0, `DRIVE_NO_ROOT_DIR` 1 (no
    volume mounted there), `DRIVE_REMOVABLE` 2, `DRIVE_FIXED` 3,
    `DRIVE_REMOTE` 4 (network), `DRIVE_CDROM` 5, `DRIVE_RAMDISK` 6. All
    values are explicit on the page.
  - `IOCTL_STORAGE_GET_DEVICE_NUMBER` (§7) reports a `DeviceType`.
    Microsoft's list includes `FILE_DEVICE_DISK`, `FILE_DEVICE_CD_ROM`,
    `FILE_DEVICE_DVD` and `FILE_DEVICE_VIRTUAL_DISK`; the page gives
    the names but not their numbers (OPEN-WAPI-1).
- **[reading]** From the documented behaviour alone, a failed extents
  request cannot be told apart from "this volume is not on a disk" by
  its error code. The documented classifications above answer the
  question directly. How the agent combines them is clean-side
  design.
- **[project rule]** Whatever the combination, it fails closed: if
  the checks cannot establish that a disk is eligible under
  REQ-DISK-005 (in particular, that it does not carry the boot
  environment), that disk is refused. Basis: `specs/disk.md`
  REQ-DISK-005 and REQ-DISK-015; DEC-0018 item 8.

## 14. Locking and dismounting a volume (SR-3b item 2; AUDITED)

Pages: "FSCTL_LOCK_VOLUME", "FSCTL_DISMOUNT_VOLUME".

- Both take a handle to the volume opened for direct access (the
  pages show the `\\.\X:` form for a drive letter) with both
  `FILE_SHARE_READ` and `FILE_SHARE_WRITE` sharing. No input or output
  buffer.
- **Lock.**
  - It succeeds only if the volume is not in use: if any file on the
    volume is open, it fails. A success means no files were open.
  - It always fails on a system volume or one that holds a page file.
  - Before locking, the system writes all cached data to the volume.
  - Afterwards, the volume can be used only through the handle that
    locked it.
  - The lock lasts until `FSCTL_UNLOCK_VOLUME` is sent or that handle
    is closed, including when the process ends.
  - NTFS treats a locked volume as dismounted.
- **Dismount.**
  - It does **not** need a lock and does not check for open files. It
    dismounts even a volume that is in use, which can harm processes
    that do not hold a lock.
  - It fails if another process holds the lock, and on a system or
    page-file volume.
  - After it, no files are open, but the system still sees the volume
    and mounts it again as soon as anything accesses it. Without a
    lock held, any process may cause that at any time.
  - Microsoft's example order for changing a volume's file system:
    open the volume, lock, do the work, dismount, unlock, close.
- Error codes: neither page names the errors for "in use", "system or
  page-file volume" or "locked by another process"
  (**OPEN-WAPI-5**). The lock page says only that failures carry an
  NT status.

## 15. Volume paths and volume information (SR-3b item 1; AUDITED)

Pages: "GetVolumePathNamesForVolumeNameW function",
"DeleteVolumeMountPointW function", "GetVolumeInformationW function".

- **`GetVolumePathNamesForVolumeName(volume GUID path, ...)`.**
  - Returns every drive letter and mounted-folder path of the volume.
  - The input must be a volume GUID path, `\\?\Volume{...}\`.
  - The output is a list of null-terminated strings, ended by one more
    null. The buffer length is in 16-bit characters and counts every
    null.
  - On success, the length output is the number of characters copied.
    If the buffer is too small, the call fails with `ERROR_MORE_DATA`,
    the length output gives the size needed, and the buffer holds as
    much of the list as fits.
  - **[reading]** A volume with no drive letter and no mounted folder
    gives an empty list: just the closing null.
- **`DeleteVolumeMountPoint(mount point)`.**
  - Removes a drive letter or mounted folder. The argument needs a
    trailing backslash.
  - The folder itself is not deleted. Given a folder that is not a
    mount point, it does nothing.
  - Nonzero on success; zero on failure, with the reason from
    `GetLastError`.
- **`GetVolumeInformation(root path, ...)`.**
  - The root path needs a trailing backslash. It returns the volume
    label, the volume serial number, the longest name component, the
    file-system flags and the file-system name (for example NTFS or
    FAT).
  - The label and name buffers are at most `MAX_PATH` + 1 characters.
  - The serial number is the one the system assigns when the volume is
    formatted, **not** the disk maker's hardware serial.
  - Among the flags: `FILE_READ_ONLY_VOLUME` `0x00080000`,
    `FILE_NAMED_STREAMS` `0x00040000`, `FILE_PERSISTENT_ACLS`
    `0x00000008`, `FILE_SUPPORTS_HARD_LINKS` `0x00400000`.
  - Returns nonzero only if **all** the requested information was
    retrieved.
  - For a floppy or CD drive with no medium, the system may show a
    prompt unless critical-error prompts are turned off with
    `SetErrorMode` (`SEM_FAILCRITICALERRORS`).

## 16. Processor, memory, system directory (SR-3b items 4, 5; AUDITED)

Pages: "GetNativeSystemInfo function", "SYSTEM_INFO",
"GlobalMemoryStatusEx function", "MEMORYSTATUSEX",
"GetSystemDirectoryW function".

- **`GetNativeSystemInfo`** fills a `SYSTEM_INFO` and returns nothing.
  - From a 64-bit program it is the same as `GetSystemInfo`.
  - An x86 or x64 program emulated on a different 64-bit processor
    (such as ARM64) sees the emulated architecture.
  - `wProcessorArchitecture` values, all explicit:
    `PROCESSOR_ARCHITECTURE_INTEL` 0 (x86), `_ARM` 5, `_IA64` 6,
    `_AMD64` 9 (x64), `_ARM64` 12, `_UNKNOWN` `0xFFFF`.
  - `dwNumberOfProcessors` counts the logical processors in the
    current group.
- **`GlobalMemoryStatusEx`** fills a `MEMORYSTATUSEX`.
  - The caller **must set `dwLength`** to the structure's size before
    the call.
  - The call returns nonzero on success.
  - `ullTotalPhys` is the physical memory in bytes. `ullAvailPhys` is
    the physical memory that can be reused at once, in bytes.
  - `dwMemoryLoad` is the percentage of memory in use, 0 to 100.
  - The values change from call to call.
- **`GetSystemDirectory(buffer, size in characters)`.**
  - On success it returns the length copied, **not** counting the
    terminating null.
  - If the buffer is too small, it returns the size **needed,
    including** the null.
  - On failure it returns zero, with the reason from `GetLastError`.
  - **[reading]** So a return value greater than or equal to the
    buffer size means "too small". A return value smaller than the
    buffer size means success.
  - The path has no trailing backslash unless it is a root directory.

## 17. Network adapters (SR-3b item 6; AUDITED)

Pages: "GetAdaptersAddresses function", "IP_ADAPTER_ADDRESSES_LH",
"IP_ADAPTER_UNICAST_ADDRESS_LH", "SOCKET_ADDRESS".

- **Arguments.**
  - Address family: `AF_UNSPEC` 0 (both), `AF_INET` 2 or `AF_INET6`
    23.
  - Flags: for example `GAA_FLAG_SKIP_ANYCAST` `0x2`,
    `GAA_FLAG_SKIP_MULTICAST` `0x4`, `GAA_FLAG_SKIP_DNS_SERVER` `0x8`.
    Zero returns unicast, anycast and multicast addresses.
  - A reserved argument, which must be null.
  - A caller-allocated buffer, and its size in bytes (in and out).
- **Results.**
  - The call returns the error code **directly**, not through
    `GetLastError`.
  - `ERROR_SUCCESS` (same as `NO_ERROR`) on success.
  - `ERROR_BUFFER_OVERFLOW` if the buffer is too small or null; the
    size argument then holds the size needed.
  - `ERROR_NO_DATA` if no addresses match.
  - `ERROR_INVALID_PARAMETER`, `ERROR_NOT_ENOUGH_MEMORY` and
    `ERROR_ADDRESS_NOT_ASSOCIATED` are also listed.
- **Sizing.**
  - Microsoft recommends starting with a 15 KB buffer. That makes a
    retry rare.
  - Asking for the size with a small buffer first is discouraged,
    because the size needed can change between calls when addresses
    are added or removed.
  - **[reading]** So after `ERROR_BUFFER_OVERFLOW` the buffer may need
    to grow to the reported size and the call be retried.
- **Layout.**
  - The buffer holds a linked list of adapter records, joined by
    `Next`. The list ends at a null `Next`.
  - Each record's `Length` gives its own size; the size grew in later
    Windows versions.
  - The order of adapters follows the route metric (Windows 10 and
    later).
- **Fields used per adapter.**
  - `AdapterName`: a permanent name that the user cannot change. Byte
    characters, unlike `FriendlyName`.
  - `PhysicalAddress` and `PhysicalAddressLength`: the hardware (MAC)
    address and its length in bytes. The length is zero for interfaces
    with no data-link layer. The array size constant
    `MAX_ADAPTER_ADDRESS_LENGTH` is not given a number on the page.
  - `Flags`: `IP_ADAPTER_DHCP_ENABLED` `0x0004` means DHCP is enabled.
    Other flags: `IP_ADAPTER_IPV4_ENABLED` `0x0080`,
    `IP_ADAPTER_IPV6_ENABLED` `0x0100`.
  - `IfType` (IANA interface types): `IF_TYPE_OTHER` 1,
    `IF_TYPE_ETHERNET_CSMACD` 6, `IF_TYPE_PPP` 23,
    `IF_TYPE_SOFTWARE_LOOPBACK` 24, `IF_TYPE_IEEE80211` 71 (Wi-Fi),
    `IF_TYPE_TUNNEL` 131, and others.
  - `OperStatus` (RFC 2863): `IfOperStatusUp` 1, `Down` 2, `Testing`
    3, `Unknown` 4, `Dormant` 5, `NotPresent` 6, `LowerLayerDown` 7.
  - `Dhcpv4Server`: the DHCP server's address, for an adapter
    configured by DHCP.
  - `IfIndex` and `Ipv6IfIndex` may change when an adapter is
    re-enabled. They are not lasting identities.
- **Unicast addresses.**
  - `FirstUnicastAddress` starts a second linked list, also joined by
    `Next`.
  - Each entry's `Address` is a pointer to a socket address plus its
    length in bytes. The address family is the first field of the
    socket address and tells IPv4 from IPv6.
  - `OnLinkPrefixLength` gives the prefix length in bits; 255 is
    commonly used to mean "not valid".
  - The order of the list is not the order in which the addresses were
    added. Duplicate addresses may appear (see `DadState`).
  - The `Length` field again gives the entry's size.

## 18. Console input without echo (SR-3b item 7; AUDITED)

Pages: "GetStdHandle function", "GetConsoleMode function",
"SetConsoleMode function".

- **`GetStdHandle`.**
  - Arguments: `STD_INPUT_HANDLE` (−10 as a 32-bit unsigned value,
    4294967286), `STD_OUTPUT_HANDLE` (−11) and `STD_ERROR_HANDLE`
    (−12).
  - Returns `INVALID_HANDLE_VALUE` on failure. Returns **null** if the
    process has no such standard handle.
  - The handle may be a redirected file or pipe rather than the
    console (`GetFileType` tells which).
  - It need not be closed. Closing it closes it for the whole process.
- **`GetConsoleMode` and `SetConsoleMode`.**
  - Both need a console input or screen-buffer handle with
    `GENERIC_READ` access, and return nonzero on success.
  - **[reading]** On a redirected (non-console) handle they fail. The
    pages say only that the handle must be a console buffer.
- **Input mode flags.**
  - `ENABLE_PROCESSED_INPUT` `0x0001`, `ENABLE_LINE_INPUT` `0x0002`,
    `ENABLE_ECHO_INPUT` `0x0004`.
  - **Echo works only together with line input.**
  - All input modes except window and virtual-terminal input are on
    when a console is created.
- Echo and line input affect only `ReadFile` and `ReadConsole` reads.
  `GetConsoleMode` reports the current mode and `SetConsoleMode`
  replaces it.

## 19. Streams, hard links, security (SR-3b item 8; AUDITED)

Pages: "FindFirstStreamW function", "FindNextStreamW function",
"WIN32_FIND_STREAM_DATA", "FindFirstFileNameW function",
"FindNextFileNameW function", "GetFileSecurityW",
"ConvertSecurityDescriptorToStringSecurityDescriptorW function",
"GetFileInformationByHandleEx function", "FILE_ATTRIBUTE_TAG_INFO".

- **Data streams.**
  - `FindFirstStreamW(full file name, FindStreamInfoStandard (0),
    output, 0)` returns a search handle and the first `$DATA` stream.
    For a file, that is always the unnamed default stream `::$DATA`.
    A directory has no unnamed stream but may have named ones.
  - Each result holds the stream size in bytes and its name, in the
    form `:name:$type`, so a named data stream is `:name:$DATA`. The
    name buffer is `MAX_PATH` + 36 characters.
  - No streams: the call fails with `ERROR_HANDLE_EOF` (38).
  - File system without streams: the call fails with
    `ERROR_INVALID_PARAMETER` (87).
  - `FindNextStreamW` returns nonzero for each further stream. The
    **end of the list** is a failure with `ERROR_HANDLE_EOF` (38).
  - Close the handle with `FindClose`.
- **Hard links.**
  - `FindFirstFileNameW(file name, 0, length in/out, buffer)` returns a
    search handle and the first of the file's link names.
    `FindNextFileNameW` returns the rest.
  - The length is in characters. If the buffer is too small, the call
    fails with `ERROR_MORE_DATA` (234) and the length output is the
    size needed.
  - The end of the list is a failure with `ERROR_HANDLE_EOF`.
  - Close the handle with `FindClose`.
  - The pages do not say the form of the names returned
    (**OPEN-WAPI-6**).
- **`GetFileSecurityW(name, requested parts, buffer, size, size
  needed)`.**
  - Returns the file's security descriptor in self-relative form.
  - If the size needed is larger than the buffer, **nothing** is
    returned and the size-needed output gives the size. **[reading]**
    The caller then retries with that size; the page does not name the
    error code for this case.
  - Reading the owner, group or DACL needs `READ_CONTROL` granted by
    the DACL, or the caller must be the owner.
  - Reading the SACL needs the `SE_SECURITY_NAME` privilege to be
    enabled (§10).
- **`ConvertSecurityDescriptorToStringSecurityDescriptorW`.**
  - Arguments: the descriptor (absolute or self-relative form),
    revision `SDDL_REVISION_1`, the parts to include, an output string
    pointer and an optional length output.
  - The output string is null-terminated and **must be freed with
    `LocalFree`**.
  - The length output is the size of the returned buffer in 16-bit
    characters, **not** the number of characters in the string.
    **[reading]** It may include the terminating null; use the string
    up to its null.
  - Listed errors: `ERROR_INVALID_PARAMETER`,
    `ERROR_UNKNOWN_REVISION`, `ERROR_NONE_MAPPED` (an account could
    not be looked up) and `ERROR_INVALID_ACL`. A null DACL with the
    "DACL present" control bit set fails.
  - `BACKUP_SECURITY_INFORMATION` is not applicable: with it, the call
    reports success but returns a null string.
- **`GetFileInformationByHandleEx(handle, class, buffer, size in
  bytes)`.**
  - Returns nonzero on success. The handle must not be a pipe.
  - Class `FileAttributeTagInfo` (9, explicit) fills
    `FILE_ATTRIBUTE_TAG_INFO`: `FileAttributes` and `ReparseTag`. The
    structure page describes the members only as the attributes and
    the reparse tag.
  - **[reading]** The reparse tag is meaningful when the attributes
    include the reparse-point attribute.
