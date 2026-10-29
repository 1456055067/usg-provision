# Standards summary: UEFI boot manager, boot options and fall-through

Topic 5 of the standards reading list, background for BOOT-5 in
`specs/boot-network.md`. This is our summary of UEFI Specification 2.10
chapter 3 (Boot Manager), with supporting points from §7.4 (image services)
and §24.3 (PXE Base Code). It describes what the standard provides. Which
of these mechanisms usg-provision uses is a clean-side decision. Where
behaviour is still OPEN, `specs/boot-network.md` REQ-BOOT-061 says so.
M3 added §9: how Microsoft's BCDBoot tool, run from Windows PE, creates
the installed Windows boot entry and where it puts it in the boot order
(AUDITED 2026-10-28, M3 re-audit round 1). M3 build requests (SR-1,
2026-10-28) added §10: the byte layouts of a load option, the global
variable namespace and attributes, and the device path nodes needed to
write a `Boot####` variable for a file on a GPT partition (AUDITED
2026-10-28, spec pass).

## 1. Boot options (§3.1.1, §3.1.3)

- Each boot option is a firmware variable named `Boot####`, where `####`
  is four hexadecimal digits. Each holds:
  - attributes;
  - a description;
  - a device path list, whose first element says where the image is: a
    disk partition and file, a network device, and so on;
  - optional data that is passed to the image when it starts.
- Attributes:
  - **ACTIVE**: the boot manager tries the option during normal boot.
    Clearing it disables the option without deleting it.
  - **HIDDEN**: the option is not shown in the firmware's boot menu.
  - **CATEGORY**: *boot* options take part in normal boot; *application*
    options are run only from a menu or hot key. Reserved values are
    ignored.
- The firmware should not delete a valid `Boot####` that `BootOrder` or
  `BootNext` refers to, except during direct interaction with a user
  (§3.1.1).

## 2. BootOrder (§3.1.1, §3.3)

- `BootOrder` is an ordered list of `Boot####` numbers. Normal boot tries
  them in that order.
- The firmware may add options (for example for new devices) or remove
  invalid ones.
- Changes are guaranteed to take effect from the next boot, and may take
  effect sooner.

## 3. BootNext and BootCurrent (§3.1.2, §3.3)

- `BootNext` names one boot option to try **first, on the next boot
  only**. The boot manager deletes `BootNext` before passing control to
  that option, so it cannot cause a loop. After that one attempt, normal
  `BootOrder` processing takes over. If the `BootNext` option fails, the
  device simply continues through `BootOrder`.
- `BootCurrent` is set by the firmware to the option chosen for the current
  boot. The OS can read it but not write it.

## 4. Variable attributes and who may change them (§3.3)

- `Boot####`, `BootOrder` and `BootNext` are non-volatile and accessible
  both before and after the OS takes over (NV + BS + RT). An operating
  system or a preinstallation environment can therefore change them at run
  time through the firmware's variable service.
- `BootCurrent`, `BootOptionSupport` and `PlatformRecovery####` are
  controlled by the firmware and read-only to the OS.
- Secure Boot policy variables (PK, KEK and the recovery-order variables)
  need authenticated writes once the platform has left setup mode (§3.3).
  Changing them is outside this topic.

## 5. What happens when a boot option fails (§3.1.2, §3.4)

- If an option fails to load, or its image returns control to the boot
  manager, the boot manager **tries the next entry in `BootOrder`**
  (§3.1.2).
- Before starting an image, the boot manager arms a **5-minute watchdog
  timer**. It disarms the timer if the image returns (§3.1.2).
- When `BootOrder` is exhausted, boot option recovery runs. OS-defined
  recovery is tried first, then normal boot is retried, then
  platform-defined recovery (§3.4).
- The platform's default behaviour applies when `BootOrder` is missing,
  points only at options that do not exist, or nothing in it succeeds. The
  firmware should provide a platform-recovery entry for the default
  removable-media path (§3.4.3).

### 5.1 Network boot as one boot option

- A network boot option points at a network device. That device offers no
  file system, so the boot manager loads the image through the device's
  **Load File** protocol. For network devices, Load File is implemented by
  the PXE Base Code, which runs DHCP and TFTP to fetch the boot program
  (§3.5.2, §3.5.2.1; §7.4.1). The IPv4 and IPv6 PXE instances sit on
  separate child handles of the network device (§24.3), so a firmware may
  list them as separate boot options.
- If the PXE client gets no valid PXE offer, its DHCP step fails with "no
  response" or a timeout, which can take at least 31 seconds (§24.3.8). A
  TFTP error or timeout fails the download (§24.3.10). Either way the load
  fails, and **the boot manager moves on to the next option in
  `BootOrder`** (§3.1.2).
- So a device whose network boot option comes before its disk option will
  wait through the PXE retry schedule and then boot from disk if nobody
  answers it. `pxe-dhcp.md` §8 gives the schedule.

## 6. Default file names on removable and fixed media (§3.5.1.1, Table 3.2)

If a boot option's path names a device but no file, the firmware appends an
architecture-specific default under `\EFI\BOOT\`, for example
`BOOTX64.EFI` for x64 and `BOOTAA64.EFI` for AArch64 (Table 3.2 lists the
rest). This matters for
installed disks and media, not for network boot.

## 7. Short-form boot options (§3.1.2)

Short-form device paths (hard drive, file path, URI, USB class or WWID) are
matched against devices that are present when the option is processed.
Options generated automatically for removable and fixed media are not
stored in non-volatile memory and are not added to `BootOrder`.

## 8. Ways the standard lets a system avoid a network-boot loop

Background for BOOT-5.

These are the standard means available. Choosing among them is not done
here.

1. **Change `BootOrder`** so that the installed system's boot option comes
   before the network boot option. This lasts until changed again (§2).
2. **Set `BootNext`** to the installed system's option. This affects one
   boot only (§3).
3. **Leave the order alone and let network boot fall through**: if no boot
   service answers the device, its network option fails and the next
   option, such as the disk, is tried (§5.1). `specs/boot-network.md`
   REQ-BOOT-050 and REQ-BOOT-051 rely on this behaviour.
4. **Clear the ACTIVE attribute** on the network boot option, so it is
   skipped in normal boot without being deleted (§1).

Option 3 needs no change on the device but costs the PXE timeout on every
boot. Options 1, 2 and 4 need something running on the device (the
installer or the installed OS) to write firmware variables (§4).

## 9. Creating the installed Windows boot entry from Windows PE (M3)

Sources: Microsoft Learn "BCDBoot Command-Line Options" (updated
2026-03-23), "BCD System Store Settings for UEFI", "Capture and Apply
Windows using a WIM file", and the UEFI sample in "Deployment lab sample
scripts". These are Microsoft tools, not part of the UEFI standard; they
are summarised because Microsoft documents them as the way to make an
applied Windows image bootable.

### 9.1 What BCDBoot does

- BCDBoot is in the Windows image itself (`%WINDIR%\System32`), in WinPE,
  and in the ADK. Microsoft's documented deployment flow is: boot WinPE,
  partition the disk, apply the Windows image with DISM, then run the
  BCDBoot **from the applied Windows** against the applied Windows
  directory, naming the ESP.
- It copies a small set of boot files from the applied Windows into the
  system partition (on UEFI, into `\EFI\Microsoft\Boot` on the ESP) and
  creates a new BCD store there from a template in the applied image.
  The Windows boot manager on UEFI is `\EFI\Microsoft\Boot\bootmgfw.efi`
  and the Windows loader is `\Windows\System32\winload.efi` ("BCD System
  Store Settings for UEFI").
- If a boot entry for that Windows partition already exists, BCDBoot
  replaces it by default (an option keeps the old values). By default it
  puts the new entry at the top of the Windows Boot Manager's own menu
  (an option keeps the existing default).
- With the firmware-type option it can lay down UEFI files, BIOS files,
  or both.

### 9.2 Effect on the firmware boot entries and boot order

- On UEFI, BCDBoot by default **adds a firmware boot option** (a
  `Boot####` variable, §1) pointing at Windows Boot Manager on the ESP,
  and places it **first in `BootOrder`** (§2).
- Two options change that: one **keeps the existing position** of the
  Windows Boot Manager entry in `BootOrder` (and adds it first if there
  is none); the other **adds it last**. They cannot be combined.
- **Exception**: when the system partition is named explicitly by drive
  letter (the system-partition option), BCDBoot **does not create the
  firmware entry**. It then relies on the firmware's default behaviour,
  which per UEFI opens the removable-media default path
  `\EFI\BOOT\BOOTX64.EFI` on the ESP (§6). Microsoft's own deployment
  samples do name the system partition this way.
  - Consequence: whether a deployment run from WinPE leaves a firmware
    boot option for Windows depends on how BCDBoot is invoked, and on the
    firmware creating options for fixed media by itself (§7). This
    matters for `boot-network.md` REQ-BOOT-065 (**OPEN-UBM-1**).
- On UEFI 2023 CA media and revocation: BCDBoot has an option to install
  boot files signed under the newer Windows UEFI CA 2023
  (`uefi-secure-boot.md`; `winpe.md` §3). A newer offline-servicing option
  (Windows 11 24H2/25H2 build 26100.8037 onward) forces the file
  selection.
- "BCD System Store Settings for UEFI" also advises making Windows Boot
  Manager the first item in the firmware display order. That is the same
  effect as §8 item 1 (change `BootOrder`).

### 9.3 Relation to the network-boot loop

- If Windows Boot Manager ends up first in `BootOrder`, later restarts go
  to the installed Windows without trying network boot (§8 item 1). This
  lasts until something changes `BootOrder` again.
- If it is added last, or not added, the network boot option may still
  come first, and the device relies on the boot service not answering
  (§8 item 3; `boot-network.md` REQ-BOOT-051).
- Firmware may itself reorder or add options (§2), so a lasting order is
  not guaranteed on every platform.

### 9.4 Invocation forms (SR-7; AUDITED 2026-10-29)

Sources: "BCDBoot Command-Line Options" (updated 2026-03-23) and the
UEFI sample in "Deployment lab sample scripts" (facts only).

- **Form:** `bcdboot <source> [/l <locale>] [/s <volume letter> [/f
  <firmware type>]] …` plus the other options in §9.1 and §9.2.
- **`<source>`** (required, first): the Windows directory to copy the
  boot files from, given as a path such as `<drive>:\Windows` (for an
  applied image, the `\Windows` folder on the Windows partition).
- **`/s <volume letter>`**: the volume letter of the system partition,
  written with a colon (for example `S:`). Microsoft says it should not
  be used in typical deployments and is meant for a disk that will boot
  on another computer. On UEFI, BCDBoot copies the boot files and
  creates the BCD store on that partition, and **does not create the
  firmware (NVRAM) entry**; the device then relies on the firmware
  default path (§9.2, OPEN-UBM-1). Microsoft's own UEFI deployment
  sample nevertheless passes `/s` with the system partition's letter.
- **`/f <UEFI|BIOS|ALL>`**: allowed only together with `/s`. When
  omitted the default is `UEFI` on UEFI/GPT systems (boot files go to
  `\Efi\Microsoft\Boot`) and `BIOS` on BIOS/MBR systems (`\Boot`).
  **[reading]** "UEFI/GPT system" means the system BCDBoot runs on, so
  in WinPE booted in UEFI mode (`winpe.md` §5.3) the default is UEFI.
- **`/l`**: locale; default `en-us`.
- **Which bcdboot.exe:** the tool is in `%WINDIR%\System32` of Windows
  and of WinPE, and in the ADK. Microsoft's apply flow (§9.1) and its
  UEFI sample run the copy **from the applied image**, that is
  `\Windows\System32\bcdboot.exe` on the Windows partition, with that
  partition's `\Windows` as `<source>`.

### Open point

- **OPEN-UBM-1**: on a device prepared from WinPE with the system
  partition named explicitly, does the device get a lasting firmware
  boot option for Windows, or does it boot only through the default
  removable-media path or firmware-generated options? Microsoft's page
  says no NVRAM entry is created in that mode; what the firmware then
  does varies by platform.

## 10. Layouts for writing a boot option (M3 build, SR-1; AUDITED)

Sources: UEFI 2.10 chapter 3 (§3.1.1, §3.1.2, §3.1.3, §3.3), chapter 8
(§8.2.1, §8.2.3), chapter 10 (§10.2, §10.3.1, §10.3.5.1, §10.3.5.4,
§10.4.5) and §1.9.1. Constants, field names and the GUID are as UEFI
defines them; the wording is ours. Markers: **[reading]** is our
inference from the cited text, not stated outright. In this section a
bare "§10.n" means a subsection of this file; UEFI chapter 10 sections
are written "UEFI §10.n".

### 10.1 Byte order and packing

- All UEFI data structures are little-endian (§1.9.1; `gpt.md` §1).
- A load option and a device path are byte-packed. Nodes may start at
  any byte offset, so every field must be read and written as unaligned
  (§3.1.3, UEFI §10.3.1).

### 10.2 The load option (`EFI_LOAD_OPTION`, §3.1.3)

The value of a `Boot####` variable is one load option. Its fields, in
order, with no padding:

| Field | Size | Content |
|-------|------|---------|
| `Attributes` | 4 bytes (UINT32) | Flags, below |
| `FilePathListLength` | 2 bytes (UINT16) | Length in bytes of `FilePathList` |
| `Description` | variable | Human-readable label: a string of 16-bit characters ending in a 16-bit null (the size rule uses `StrSize`, which counts the terminator) |
| `FilePathList` | `FilePathListLength` bytes | One or more device paths, packed; each ends with an End node (§10.4) |
| `OptionalData` | the rest | Bytes passed unchanged to the started image; empty means the image gets no data |

- `OptionalData` starts at 4 + 2 + (size of `Description` including its
  terminator) + `FilePathListLength`. Its length is the variable's
  total size minus that offset.
- Element 0 of `FilePathList` says which device and file to start. For
  a `Boot####` option it must name a UEFI application. Further elements
  are optional and their use is OS-specific.
- Unused attribute bits must be zero when an option is created and must
  be kept unchanged when an option is updated.

Attribute values:

| Name | Value | Meaning |
|------|-------|---------|
| `LOAD_OPTION_ACTIVE` | `0x00000001` | Tried in normal boot (§1) |
| `LOAD_OPTION_FORCE_RECONNECT` | `0x00000002` | For driver options only |
| `LOAD_OPTION_HIDDEN` | `0x00000008` | Not shown in the firmware boot menu |
| `LOAD_OPTION_CATEGORY` | `0x00001F00` | Mask for the category field |
| `LOAD_OPTION_CATEGORY_BOOT` | `0x00000000` | Normal boot option |
| `LOAD_OPTION_CATEGORY_APP` | `0x00000100` | Application, run from a menu only |

Category values `0x00000200` to `0x00001F00` are reserved; options with
a reserved category are ignored (§3.1.3).

### 10.3 Variable names, namespace and attributes (§3.1.1, §3.3, §8.2)

- Every variable in §1 to §3 lives in the global namespace
  `EFI_GLOBAL_VARIABLE`, GUID
  `{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}` (§3.3; given there as the
  C initialiser `0x8BE4DF61, 0x93CA, 0x11d2, 0xAA, 0x0D, 0x00, 0xE0,
  0x98, 0x03, 0x2B, 0x8C`).
- `Boot####`: `####` is exactly four hexadecimal digits with leading
  zeros, using `0`-`9` and upper-case `A`-`F`, no prefix (`Boot0001`,
  `Boot0A02`; §3.1.1).
- `BootOrder`: an array of UINT16 option numbers, first tried first.
  `BootNext` and `BootCurrent` each hold one UINT16 (§3.3).
- Attributes from §3.3, with the bit values from §8.2.1:

  | Variable | Attributes | Value |
  |----------|------------|-------|
  | `Boot####` | NV, BS, RT | `0x00000007` |
  | `BootOrder` | NV, BS, RT | `0x00000007` |
  | `BootNext` | NV, BS, RT | `0x00000007` |
  | `BootCurrent` | BS, RT (read-only to the OS) | `0x00000006` |

  `EFI_VARIABLE_NON_VOLATILE` = `0x1`,
  `EFI_VARIABLE_BOOTSERVICE_ACCESS` = `0x2`,
  `EFI_VARIABLE_RUNTIME_ACCESS` = `0x4` (§8.2.1).
- Secure Boot state (SR-3b, AUDITED 2026-10-28; UEFI §3.3, Table 3.1).
  These are in
  the same `EFI_GLOBAL_VARIABLE` namespace. Each holds one byte (an
  8-bit unsigned value). Their attributes are BS and RT (`0x00000006`),
  not NV:
  - `SecureBoot`: 1 means the firmware checks the signatures of
    drivers and boot programs on this boot; 0 means it does not. It
    must be 0 if the platform started in Setup or Audit Mode.
    Read-only after initialisation.
  - `SetupMode`: 1 means Secure Boot policy variables can be written
    without authentication; 0 means writes need authentication. The
    platform is in Setup Mode when `SetupMode` is 1 and `AuditMode`
    and `DeployedMode` are both 0. Read-only.
  - `AuditMode`: 1 means Audit Mode, 0 not; other values reserved.
    Read-only once the OS has taken over.
  - `DeployedMode`: 1 means Deployed Mode, 0 not; other values
    reserved. Read-only once the OS has taken over.

  **[reading]** From Windows these are read with
  `GetFirmwareEnvironmentVariableEx` (topic 23 §9) as one-byte values.
- Rules for writing (§8.2.3):
  - RT requires BS as well.
  - Writing an existing variable with different attributes fails with
    `EFI_INVALID_PARAMETER` and leaves it unchanged. To change
    attributes, delete and recreate.
  - Writing zero bytes deletes an ordinary variable.
  - After the OS has taken over, only variables that are both NV and RT
    can be written.

### 10.4 Device path node header and End node (UEFI §10.2, §10.3.1)

Every node starts with a 4-byte header:

| Offset | Size | Field |
|--------|------|-------|
| 0 | 1 | `Type` |
| 1 | 1 | `SubType` |
| 2 | 2 | `Length`: the whole node in bytes, header included |

- Types: `0x01` hardware, `0x02` ACPI, `0x03` messaging, `0x04` media,
  `0x05` BIOS boot specification, `0x7F` end. Other values are reserved.
  A reader can skip a node of unknown type by its `Length`.
- End node: `Type` `0x7F`, `Length` 4. `SubType` `0xFF` ends the whole
  device path (every path must end this way); `SubType` `0x01` ends one
  instance of a multi-instance path and starts the next.

### 10.5 Hard Drive media node (UEFI §10.3.5.1, Table 10.54)

`Type` `0x04`, `SubType` `0x01`, `Length` 42:

| Offset | Size | Field | Content |
|--------|------|-------|---------|
| 0 | 4 | header | as §10.4 |
| 4 | 4 | Partition Number | 1-based entry number; 0 means the whole disk. GPT: 1 to the number of partition entries |
| 8 | 8 | Partition Start | First LBA of the partition, in logical blocks |
| 16 | 8 | Partition Size | Size in logical blocks |
| 24 | 16 | Partition Signature | Type 0: all zero. Type 1: MBR signature in the first 4 bytes, rest zero. Type 2: a 16-byte GUID |
| 40 | 1 | Partition Format | `0x01` MBR, `0x02` GPT |
| 41 | 1 | Signature Type | `0x00` none, `0x01` 32-bit MBR signature, `0x02` GUID |

- For a GPT disk the boot manager compares the GUID in this node with
  the partition entry's `UniquePartitionGUID` (§3.1.2; `gpt.md` §5).
  **[reading]** It is therefore stored in the same UEFI byte order as
  that GPT field (`uefi-guid-text.md` §1.2). Table 10.54 itself says
  only "16-byte signature".
- If more than one partition matches, the boot manager may pick any of
  them, so the OS must keep partition GUIDs unique (§3.1.2).
- In text form the node is shown as `HD(...)` with the GUID in the
  usual 8-4-4-4-12 form (UEFI §10.6, device path text form).

### 10.6 File Path media node (UEFI §10.3.5.4, Table 10.57)

`Type` `0x04`, `SubType` `0x04`, `Length` 4 + n:

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | header (§10.4) |
| 4 | n | Path name: a null-terminated string of directory and file names |

- Several File Path nodes in a row are joined into one path. The
  joining must not leave a doubled separator and must insert one if
  neither side has it. A single node with no directory part is taken
  as relative to the root of the device (UEFI §10.3.5.4).
- **[reading]** The string is 16-bit characters with a 16-bit null, as
  for `Description` (§10.2). Table 10.57 does not state the character
  type in the parts read (**OPEN-UBM-2**). The separator in UEFI paths
  is the backslash, as in `\EFI\BOOT\BOOTX64.EFI` (§6).

### 10.7 Short-form paths starting with a Hard Drive node (§3.1.2)

- The boot manager must accept a device path whose first node is a Hard
  Drive media node. It finds the partition by the signature and
  partition number in that node (GUID against `UniquePartitionGUID` on
  GPT), wherever the disk is attached, and then carries on as if the
  full hardware path had been given.
- **[reading]** So a `Boot####` option for a file on a GPT partition can
  be written as: Hard Drive node (§10.5), File Path node (§10.6), End
  node with `SubType` `0xFF` (§10.4). §3.1.2 does not say in words how
  the File Path node after the Hard Drive node is used.
- A full path instead puts the disk's hardware and messaging nodes
  first and appends the media node (UEFI §10.4.5). Which form to write
  is a clean-side choice.

### 10.8 Open points

- **OPEN-UBM-2**: Table 10.57 does not state the character type of the
  File Path node's string in the text read. The reading in §10.6
  should be checked against a firmware-created Windows boot option on
  a test device.
