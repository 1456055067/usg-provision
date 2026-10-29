# Standards summary: Windows PE (WinPE)

Topic 11 of the standards reading list. This is our summary of
Microsoft's public documentation on Windows PE: what it is, how it is
obtained and built, how it is customised and starts, and its use and
redistribution limits. For PE-1 (`specs/preinstall-env.md`). Booting
WinPE over the network is summarised in topic 22,
`specs/standards/winpe-network-boot.md` (§8). M3 added §5.1 to §5.3
(automatic start, networking, boot information), §8 (pointer) and §9
(RAM disk); these were AUDITED on 2026-10-28 (M3 re-audit round 1).
The M3 build requests (SR-2, 2026-10-28) added §10, the PE/COFF
`Machine` field used to check a boot program's architecture (AUDITED
2026-10-28, spec pass). SR-7 (AUDITED 2026-10-29) added `wpeutil`
Reboot and Shutdown to §5.2, and §11 (DiskPart scripted commands),
with OPEN-WINPE-2 to 4, which stay open; the old §11 is now §12.

Sources (all Microsoft Learn unless noted): "Windows PE (WinPE)",
"Download and install the Windows ADK", "WinPE: Create bootable media",
"Copype command-line options", "WinPE: Mount and Customize", "Wpeinit and
Startnet.cmd", "Windows Setup Supported Platforms and Cross-Platform
Deployments", and one Microsoft Q&A answer marked **[secondary]** in §7.
M3 added: "Winpeshl.ini Reference", "Wpeutil Command-Line Options",
"WinPE Network Drivers: Initializing and adding drivers", "WinPE:
Install on a Hard Drive (Flat Boot or Non-RAM)".
Microsoft's pages have headings but no section numbers, so this file
cites them by page and heading.

## 1. What Windows PE is ("Windows PE (WinPE)")

- A small operating system used to install, deploy and repair Windows
  desktop editions, Windows Server and other Windows systems. From it one
  can prepare disks, install Windows from a network or local drive,
  capture and apply images, change an offline Windows installation, run
  recovery tools, and run a custom shell or GUI that automates these.
- It runs the Windows command line and supports batch files and scripts
  (optionally PowerShell), Win32 applications, a generic set of network,
  graphics and storage drivers, DISM, TCP/IP networking to file servers,
  NTFS, DiskPart and BCDBoot, and optionally BitLocker, TPM and Secure
  Boot tools. It can run under Hyper-V.

## 2. Getting it ("Download and install the Windows ADK")

- WinPE is an **add-on** to the Windows Assessment and Deployment Kit
  (ADK). Both are downloaded from Microsoft. Before Windows 10, version
  1809, WinPE was part of the ADK itself.
- Current downloads listed (page updated 2026-10-23):
  - ADK 10.1.26100.9457 (September 2026) and its WinPE add-on: support
    Windows 11 versions 26H2, 25H2, 24H2 and all earlier supported Windows
    10 and 11 versions, plus Windows Server 2025 and 2022.
  - ADK 10.1.28000.1 (November 2025) and its WinPE add-on: support
    Windows 11 version 26H1 on Arm64.
- **32-bit WinPE** is no longer included from the ADK for Windows 11,
  version 22H2 onward. The last one is in the WinPE add-on for Windows 10,
  version 2004. 32-bit WinPE for Windows 11 is not supported and cannot be
  used to deploy Windows 11.
- Use the ADK that matches the newest Windows version being deployed.
  WinPE can deploy older Windows versions. Optional components must match
  the WinPE version they are added to.
- Microsoft lists security fixes that should be applied to older WinPE
  add-ons (for example the April 2024 and May 2023 Windows security
  updates), recommends the latest ADK because of a vulnerability in the
  kit's build tooling (fixed from ADK 10.1.26100.2454, December 2024), and
  asks users to apply the ADK servicing patch for CVE-2026-25166.

## 3. Building a WinPE working set ("WinPE: Create bootable media"; "Copype")

- `copype <architecture> <working directory>` creates a working set.
  Architecture values: `amd64`, `x86`, `arm`, `arm64`.
- It creates `<working directory>\media` and `<working directory>\mount`,
  and copies the boot files and the base image `winpe.wim` into
  `media\sources`, renaming the image to `boot.wim`.
- The amd64 WinPE boots 64-bit UEFI and 64-bit BIOS PCs. The x86 WinPE
  boots 32-bit UEFI, 32-bit BIOS and 64-bit BIOS PCs. Arm WinPE boots Arm
  PCs of its own architecture.
- `MakeWinPEMedia` turns the working set into a bootable USB drive
  (`/UFD`, formatted FAT32), an ISO (`/ISO`) or a VHD.
- With ADK 10.1.26100.2454 (December 2024) and later, the `/bootex`
  option makes boot media signed under the "Windows UEFI 2023 CA". Without
  it, the media use boot managers signed under the 2011 CA. Which to use
  depends on whether the target devices have revoked the 2011-signed boot
  managers (Microsoft KB5025885). See also `uefi-secure-boot.md`.
- Updates can be applied once to the WinPE add-on's own image so that all
  later media include them.

## 4. Customising ("WinPE: Mount and Customize")

- WinPE ships as a WIM file and is customised like any Windows image:
  mount `media\sources\boot.wim` (index 1) with DISM, change it, then
  unmount with commit.
- **Drivers**: added with DISM's add-driver option from `.inf` packages.
  Microsoft suggests adding them one at a time for easier troubleshooting.
- **Optional components** (`.cab` packages, for example scripting,
  PowerShell, WMI): added with DISM's add-package option, each **with its
  matching language pack**.
- **Windows 11 Setup** launched from WinPE needs the WinPE-WMI and
  WinPE-SecureStartup optional components, or Setup may wrongly report
  that the PC does not meet minimum hardware requirements.
- **Files** copied into the mounted image appear on drive `X:` when WinPE
  runs. Too many files slow WinPE and use up RAM-disk memory.
- **Scratch space** (temporary writable RAM storage): 32, 64, 128, 256 or
  512 MB. The default is 512 MB on PCs with more than 1 GB of RAM,
  otherwise 32 MB.
- **Updates**: WinPE updates come inside the cumulative update for the
  matching Windows version (`.msu`), followed by a component clean-up.
- Background image, power scheme and some answer-file settings can also
  be set.

## 5. Start-up ("Wpeinit and Startnet.cmd"; "Mount and Customize")

- `Startnet.cmd` in `%SYSTEMROOT%\System32` runs at start. By default it
  runs `wpeinit`. Custom commands can be added to it.
- `wpeinit` installs Plug and Play devices, processes `Unattend.xml`
  settings and starts networking. It logs to `wpeinit.log` in
  `system32`. It accepts `-unattend:<path>` to name an answer file.
- Answer-file settings WinPE supports at start: display, firewall, network
  enable, log path, page file, restart, and synchronous or asynchronous
  commands (components under `Microsoft-Windows-Setup`).
- A `Winpeshl.ini` file can name a shell or application to launch instead
  of the default command prompt.

### 5.1 Starting a program automatically (M3 addition)

Sources: "Wpeinit and Startnet.cmd", "Winpeshl.ini Reference",
"Configure a PXE server to load Windows PE", "WinPE: Install on a Hard
Drive (Flat Boot or Non-RAM)".

- At start, WinPE opens a command window and runs `wpeinit`
  automatically; on slower hardware this can take a few minutes.
- Microsoft documents two ways to run something automatically, both by
  changing files **inside** the WinPE image before it is booted (mount,
  change, commit; §4):
  1. **Startup script**: add commands to `Startnet.cmd` in
     `%SYSTEMROOT%\System32`. The default script runs `wpeinit`; custom
     commands follow it.
  2. **Replacement shell**: a `Winpeshl.ini` file in
     `%SYSTEMROOT%\System32` replaces the default command prompt with one
     or more programs:
     - a single-program section takes one program path, no command-line
       options, at most 250 characters;
     - a multi-program section lists programs, each optionally with
       options after a comma, each line at most 250 characters; it runs
       programs, not scripting commands;
     - programs from both sections run one after another in file order;
       each starts only after the previous one has ended.
  Whether `wpeinit` still runs automatically when `Winpeshl.ini` replaces
  the shell is not stated on the pages read (**OPEN-WINPE-1**).
- An answer file given to `wpeinit` can also run commands at start
  (synchronous or asynchronous commands; list in §5 above).
- Nothing can be added at run time that survives a restart (§6). A
  program that must start on every boot must be in the image.

### 5.2 Networking at start (M3 addition)

Sources: "Wpeinit and Startnet.cmd", "Wpeutil Command-Line Options"
(updated 2023-08-15), "WinPE Network Drivers: Initializing and adding
drivers".

- By default `wpeinit` starts networking as soon as WinPE boots. The
  answer-file network setting (§5) can turn that off.
- `wpeutil InitializeNetwork` starts network components and drivers and
  gives the machine a random name. Without its no-wait option WinPE waits
  to get an IP address (by DHCP) before the session finishes loading;
  the no-wait option skips that wait, for networks without DHCP.
- `wpeutil WaitForNetwork` waits until the network card is initialised;
  Microsoft suggests it in scripts that need the network.
- `wpeutil` can also enable or disable the WinPE firewall, restart or
  shut down WinPE, wait for removable storage, and report how WinPE
  booted (§5.3).
- Restart and shut down (SR-7; AUDITED 2026-10-29): the command form
  is `wpeutil <command> [argument]`, one command per invocation.
  `wpeutil Reboot` restarts the current WinPE session. `wpeutil
  Shutdown` shuts it down; Microsoft notes that closing the command
  window or typing `exit` at it also does so. Neither command takes
  an argument.
- Case (CR-SR7-001; AUDITED 2026-10-29): the page does **not** say
  whether command names are case-insensitive. Its examples spell the
  tool name both `Wpeutil` and `wpeutil`, but always write the command
  names in the documented capitalisation (`Reboot`, `Shutdown`).
- WinPE includes generic drivers for many common network adapters. If a
  device's adapter is not covered, the driver is added to the image with
  DISM (recommended), or loaded at run time with `drvload` (lost at
  restart).
- Limits: only TCP/IP and NetBIOS over TCP/IP to file servers; general
  wireless networking is not supported; reaching an IPv4 network from
  WinPE on an IPv6 network is not supported; SMB1 is off by default from
  version 1709; WinPE cannot join a domain or act as a server. Wired
  802.1X needs the 802.1X optional component and a LAN profile.

### 5.3 Telling how WinPE booted ("Wpeutil", UpdateBootInfo)

`wpeutil UpdateBootInfo` writes registry values that say how WinPE
started: the boot type (flat, remote, RAM disk from a known or unknown
source, RAM disk from optical media, or error), the source drive letter
when known, and the **firmware mode** (1 = BIOS, 2 = UEFI). Microsoft's
deployment samples use the firmware value to choose between the BIOS/MBR
and UEFI/GPT partition layouts (`gpt.md` §10).

## 6. Limits and hardware ("Windows PE (WinPE)")

- **Use restriction**: WinPE is not a general-purpose operating system.
  It may be used only for deployment and recovery, not for hardware
  validation, as a thin client, or as an embedded OS.
- **Automatic restart**: WinPE stops its shell and restarts after a fixed
  period of continuous use: 240 hours from Windows 10, version 1803 (72
  hours up to version 1709). The period cannot be changed.
- **Nothing persists**: every change made while it runs (drivers, drive
  letters, registry) is lost at restart.
- **FAT32 media**: 4 GB maximum file size and 32 GB maximum drive size.
- **Not supported**: file or terminal server use, NIC teaming, **joining a
  domain**, reaching an IPv4 network from WinPE on an IPv6 network, Remote
  Desktop, `.msi` installers, booting from a path with non-English
  characters, running applications built for another architecture, and
  adding bundled app packages.
- **Memory**: the base image needs 512 MB. Booting from RAM needs a
  contiguous block of memory large enough for the whole WinPE WIM.
- **Firmware mode**: on PCs that support UEFI and legacy BIOS, WinPE must
  be booted in the mode the installed Windows will use.
- A 32-bit WinPE can deploy 64-bit Windows with 32-bit Setup or DISM
  apply, but 64-bit Setup does not run on 32-bit WinPE ("Windows Setup
  Supported Platforms").

## 7. Licensing and redistribution

What Microsoft's public pages say:

- The use restriction in §6: deployment and recovery only.
- WinPE and the ADK are downloaded by the user from Microsoft (§2).

What was **not** read, on purpose: the ADK licence terms. They are shown
as a click-through during installation, so under the clean-room rules
they are not a permitted source for the researcher.

One public secondary source **[secondary]**: a Microsoft Q&A answer
(2026-07-01) by a contributor labelled "Microsoft External Staff" says
the ADK licence does not allow WinPE to be redistributed as part of a
third-party product. It suggests that the customer build WinPE on their
own machine from an ADK they download themselves, so that the customer
accepts Microsoft's licence. The answer quotes no licence text, gives no
disclaimer, and makes some unsourced claims. Treat it as a pointer only.

Consequences for the product (see `specs/preinstall-env.md`):

- The product does not ship WinPE, the ADK, or any file taken from them.
  The operator obtains them from Microsoft.
- Open for counsel (OPEN-PE-LIC):
  - May a product-supplied tool run Microsoft's kit tools on the
    operator's machine to build or customise WinPE?
  - May the product store an operator's WinPE and serve it to that
    operator's own devices?
  - May the product add its own files to the operator's WinPE?
  - What may be done with Windows installation images (an operator's
    licensed content) once uploaded? No public source on this was read.
  - Do the ADK and DISM licence terms limit creating test WIM files with
    DISM and analysing them for interoperability? Project decision 0006
    (`docs/decisions/0006-wim-format-by-black-box-test-files.md`) relies
    on that method.
- Until counsel answers, the rule that the product ships nothing from
  the kit is a cautious project stance; its redistribution source is
  secondary.

## 8. Network boot

Summarised separately in M3: `specs/standards/winpe-network-boot.md`
(topic 22): files needed, boot configuration data, RAM disk, TFTP size
limits.

## 9. RAM-disk behaviour (M3 addition)

Sources: "Windows PE (WinPE)", "WinPE: Mount and Customize", "WinPE:
Install on a Hard Drive (Flat Boot or Non-RAM)", and the archived
"How Booting into a Boot Image Works" (via topic 22).

- When booted from network, USB or ISO media in the usual way, WinPE runs
  from a RAM disk and uses drive `X:`. Files added to the image appear on
  `X:`.
- RAM boot needs a contiguous block of memory large enough for the whole
  WIM, on top of the 512 MB the base image needs. Large images and many
  added files use up that memory and slow WinPE (§4, §6).
- Scratch space (writable temporary storage in RAM) is 32 to 512 MB
  (§4).
- Everything written while WinPE runs is lost at restart (§6). Anything
  the deployment must keep (downloaded content, logs) has to be written
  to a disk or sent over the network before WinPE restarts.
- The alternative "flat" boot from a hard drive, which avoids the RAM
  disk, is a local-disk setup, not a network boot.

## 10. Boot program architecture: the PE/COFF Machine field (SR-2; AUDITED)

Sources: Microsoft Learn "PE Format" (its parts on the MS-DOS stub,
the signature, the "COFF File Header (Object and Image)" section with
its "Machine Types" table, and the optional header); UEFI 2.10 §2.1.1
(UEFI images) and §1.9.1 (byte order). Background for REQ-PE-012's
architecture check. Field and constant names are Microsoft's and
UEFI's; the wording is ours.

- **Finding the header.** An image file starts with an MS-DOS stub. At
  file offset `0x3C` the stub holds the file offset of the PE
  signature. The signature is 4 bytes: `P`, `E`, `0x00`, `0x00`.
- **COFF file header.** 20 bytes, straight after the signature. Its
  first field, at offset 0 of the header (signature offset + 4 in the
  file), is `Machine`, 2 bytes. Then `NumberOfSections` (2),
  `TimeDateStamp` (4), `PointerToSymbolTable` (4), `NumberOfSymbols`
  (4), `SizeOfOptionalHeader` (2), `Characteristics` (2).
- **Machine values** ("Machine Types"; UEFI §2.1.1 gives the same
  numbers for UEFI images):

  | Constant | Value | CPU |
  |----------|-------|-----|
  | `IMAGE_FILE_MACHINE_UNKNOWN` | `0x0` | any machine |
  | `IMAGE_FILE_MACHINE_I386` | `0x14C` | x86 (32-bit) |
  | `IMAGE_FILE_MACHINE_AMD64` | `0x8664` | **x64** (UEFI: `EFI_IMAGE_MACHINE_x64`) |
  | `IMAGE_FILE_MACHINE_ARM64` | `0xAA64` | ARM64 (UEFI: `EFI_IMAGE_MACHINE_AARCH64`) |
  | `IMAGE_FILE_MACHINE_ARMNT` | `0x1C4` | ARM Thumb-2 |

  An image runs only on the machine it names or on one that emulates
  it ("Machine Types"). A UEFI platform must support its own native
  type; others are optional (UEFI §2.1.1).
- **Byte order.** Microsoft's page does not state the byte order of
  the header fields. UEFI images are PE32+ files (§2.1.1) and UEFI data
  structures are little-endian (§1.9.1). **[reading]** `Machine` is
  little-endian, so x64 appears in the file as the bytes `64 86`.
- **Optional header, for a fuller check.** Its first field, `Magic`, is
  `0x10B` for PE32 and `0x20B` for PE32+. `Subsystem` is at offset 68
  of the optional header in both forms; `10` means a UEFI application
  (`IMAGE_SUBSYSTEM_EFI_APPLICATION`), `11` a boot-service driver, `12`
  a runtime driver.
- **[reading]** A UEFI x64 network boot program from the operator's kit
  should therefore show the `PE\0\0` signature, `Machine` `0x8664`,
  `Magic` `0x20B` and `Subsystem` `10`. Which of these the product
  checks is a clean-side choice (REQ-PE-012).

## 11. DiskPart scripted commands (SR-7; AUDITED 2026-10-29)

Sources: Microsoft Learn Windows Commands pages "diskpart", "select
volume", "create partition primary", "convert gpt", "assign", "attach
vdisk", "detach vdisk"; the archived DiskPart pages "Format" and
"Create vdisk" (Windows Server 2012 R2 docs, [archive]); "Deployment
lab sample scripts" (facts only, no script text copied). Semantics and
argument forms only.

- **Running it.** DiskPart is run from an elevated prompt (local
  Administrators or equivalent). Its commands act on the object that
  has **focus**: list, then select a disk, partition, volume or
  virtual disk. Focus stays until another object is selected; some
  commands move it (creating a partition moves focus to the new
  partition). Selecting a volume that maps to one partition also gives
  focus to that partition and its disk. Microsoft's deployment samples
  run a command file with `diskpart /s <file>`; the "diskpart" page
  itself shows only `diskpart <parameter>` and does not describe `/s`
  (**OPEN-WINPE-2**).
- **Errors in scripts.** Most commands take `noerr`, "for scripting
  only": with it, DiskPart carries on after an error; without it, an
  error makes DiskPart exit with an error code. The pages do not list
  the exit-code values (**OPEN-WINPE-3**).
- **`select volume={<n>|<d>}`.** `<n>` is a volume number from
  `list volume`; `<d>` is a drive letter or a mount-point path. With no
  argument it shows which volume has focus. The page shows the `=`
  form (`select volume=2`, `select volume=c`); whether the space form
  is accepted is not stated there.
- **`format`** (DiskPart; archived page): formats the partition or
  volume with focus, which must be selected first. Arguments:
  `fs=<ntfs|fat|fat32>` (UDF also listed; default file system if
  omitted), `label=<label>` (quoted when it holds spaces), `quick`,
  and others (`unit=`, `compress`, `override` to force a dismount,
  `nowait`, `noerr`). The standalone `format.exe` is a different tool
  with `/FS:`, `/V:`, `/Q` options.
- **`create vdisk`** (archived page): `create vdisk file=<path>
  [type=<fixed|expandable>] [maximum=<n>]` among others (`parent=`,
  `source=`, `sd=`, `noerr`). `maximum` is in megabytes. Without
  `type`, `parent` or `source` a **fixed** VHD is made. A new VHD is
  like an uninitialised disk. The page does not say whether the new
  VHD gets focus; [reading] it must be selected before it is attached.
- **`attach vdisk [readonly] [sd=<SDDL>|usefilesd] [noerr]`**: makes
  the selected, detached VHD appear as a local disk; if it already
  holds a formatted volume, that volume gets a drive letter.
- **`detach vdisk [noerr]`**: stops the selected VHD appearing as a
  local disk.
- **`convert gpt [noerr]`**: converts the selected **empty** basic MBR
  disk to GPT; all partitions and volumes must be deleted first; the
  disk must be at least 128 MB.
- **`create partition primary [size=<n>] [offset=<n>] [id=…]
  [align=<n>] [noerr]`**: on the selected basic disk. `size` is in MB;
  without it the partition fills the rest of the free region.
  `offset` and `align` are in KB. On a GPT disk without `id` it makes
  a basic data partition (type `ebd0a0a2-b9e5-4433-87c0-68b6b72699c7`);
  Microsoft says to use `create partition efi` and `create partition
  msr` for those types rather than `id`. Focus moves to the new
  partition.
- **`assign [letter=<d>|mount=<path>] [noerr]`**: gives the selected
  volume a drive letter or mount point; with neither, the next free
  letter. A letter already in use is an error. The page says letters
  cannot be given to system, boot or page-file volumes, or to a GPT
  partition other than a basic data partition. **[reading]** This
  conflicts with Microsoft's own deployment sample, which assigns a
  letter to the EFI system partition it has just created
  (**OPEN-WINPE-4**).
- **Microsoft's sample letters and labels** (SRC-087; facts only). In
  the UEFI/GPT sample, the system (EFI) partition is formatted FAT32
  with label "System" and letter S; the Windows partition NTFS, label
  "Windows", letter W; the recovery partition NTFS, label "Recovery",
  letter R. The MSR gets no letter. The sample says the letters are
  temporary and that W is used to avoid clashes; after restart Windows
  becomes C and the others get no letter. (The BIOS sample labels its
  recovery partition "Recovery image".) Any use of these values in the
  product is a project choice, not a Microsoft requirement.

## 12. Not summarised

- The full optional-component list and language packs.
