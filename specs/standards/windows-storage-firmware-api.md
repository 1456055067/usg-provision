# Standards summary: Windows disk, volume and firmware-variable APIs

Topic 23 of the standards reading list (SR-3, M3 build requests,
2026-10-28; AUDITED 2026-10-28, spec pass). Background for DISK-1
(`specs/disk.md`) and BOOT-5 (`specs/boot-network.md` REQ-BOOT-065),
for a program running in Windows PE. This is a semantics-only summary
of Microsoft Learn reference pages: what each function or control code
does, what it needs and how it reports failure. It is not a design.
Which calls the product uses, and how it binds to them, is the clean
side's choice (DEC-0019 records the binding choice; it adds no spec
text).

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
