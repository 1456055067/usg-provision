# Standards summary: Windows PE network boot and its boot configuration

Status: AUDITED (M3, 2026-10-28; re-audit round 1). The DEC-0018 notes
are [project rule], not Microsoft text.

Topic 22 of the standards reading list (new in M3). For PE-1
(`specs/preinstall-env.md` REQ-PE-011 onward) and BOOT-1/BOOT-5
(`specs/boot-network.md` REQ-BOOT-063 onward). This is our own summary of
public Microsoft documentation:

- "Configure a PXE server to load Windows PE" (Windows 10 page, dated
  2022-11-23, updated 2025-06-04);
- archived Windows Server 2008 pages "How Booting into a Boot Image Works"
  and "How to Modify the BCD Store Using Bcdedit" (Windows Deployment
  Services era; old, marked **[archive]** below);
- the Microsoft support article "PXE boot in Configuration Manager" (2026),
  used **only** for its generic description of Microsoft's network boot
  programs, marked **[support article]**;
- "BCD System Store Settings for UEFI".

Microsoft's pages have headings but no section numbers; they are cited by
page and heading. Nothing here describes the on-disk format of a BCD
store: Microsoft publishes no such format, and the clean side must not
derive one (§6).

## 1. Parts involved ("Configure a PXE server", Prerequisites)

- A deployment computer with the ADK and its WinPE add-on (the operator's
  Windows machine; `winpe.md` §2, §3).
- A DHCP server, or a DHCP proxy, that answers PXE clients
  (`proxy-dhcp.md`).
- A TFTP server holding the WinPE boot files (`tftp.md`).
- Optionally a file server holding the images to install. Microsoft's
  walkthrough uses an SMB share; any delivery method the product chooses
  is a clean-side decision.

All roles may be on one machine or separate machines.

## 2. Files the boot needs ("Configure a PXE server", Step 1)

Taken from the operator's WinPE working set (`copype`, `winpe.md` §3) and
from the WinPE image mounted with DISM:

| File | Where it comes from | Role |
|------|--------------------|------|
| PXE boot programs | the `Windows\Boot\PXE` folder inside the mounted WinPE image | network boot program(s) and boot manager (§3) |
| `boot.sdi` | the working set's `media\Boot` folder | RAM-disk image file (§4) |
| `boot.wim` | the working set's `media\sources` folder | the WinPE image itself |
| Fonts (optional) | the working set's `media\Boot\Fonts` folder | boot-manager text display |
| `BCD` | created by the operator with `bcdedit` (§5) | boot configuration data |

Microsoft's walkthrough places all of them under a `Boot` folder at the
TFTP root. It says the BCD store must be in that `\Boot` folder and must
be named `BCD`; if the boot manager reports that boot configuration data
is missing, the folder is in the wrong place.

These are Microsoft files from the operator's kit. Whether the product
may store and serve them is part of OPEN-PE-LIC (`winpe.md` §7).

## 3. Boot programs, BIOS and UEFI

- BIOS flow ("Configure a PXE server", PXE boot process summary): the
  DHCP or proxy reply names a boot file; the client downloads a small
  network boot program by TFTP; that program downloads the boot manager
  and the `BCD` file by TFTP; the boot manager reads the BCD, downloads
  `boot.sdi` and `boot.wim`, and starts WinPE's loader inside the WIM.
- UEFI flow **[archive]** ("How Booting into a Boot Image Works"): for
  EFI clients the separate loader step is skipped; the program the
  firmware downloads is itself the loader, which then fetches the BCD,
  the SDI file, the boot WIM and fonts by TFTP.
- **[support article]** Microsoft describes its UEFI boot manager,
  `bootmgfw.efi`, as the x64 UEFI network boot program that combines the
  roles of the BIOS programs (prompt or no prompt, abort to next device,
  and boot manager). On UEFI, whether to network boot at all is decided
  by the firmware, not by this program. Microsoft's Windows Deployment
  Services also has its own UEFI program, which is out of scope here.
- So for UEFI x64 the boot program offered in the PXE reply is Microsoft's
  UEFI boot manager from the operator's kit. Microsoft's pages fetched do
  not state its exact path inside the WinPE image for UEFI
  (**OPEN-WPXE-1**).
- **[archive]** The boot manager runs its own TFTP client, over the
  firmware's UDP stack, and shows a progress bar while it downloads.

## 4. RAM disk ("How Booting into a Boot Image Works" [archive]; "Windows PE (WinPE)")

- Network boot of WinPE always uses a **RAM disk**. Booting from a flat
  directory over the network is not available.
- The RAM disk is built from two things: the `.sdi` file, an NTFS-
  formatted disk image that is placed in memory and treated as a disk,
  and the boot WIM, which is appended to it. The loader mounts the volume
  and finds the WIM.
- The WIM image used must be marked bootable. Only one image in a WIM can
  be marked bootable for RAM-disk boot (`wim.md` §2, §11).
- WinPE then runs from memory as drive `X:`. Nothing written there
  survives a restart (`winpe.md` §6).
- Memory: the base WinPE image needs 512 MB, and RAM boot needs a
  contiguous block of memory large enough for the whole WIM ("Windows PE
  (WinPE)", `winpe.md` §6).

## 5. Boot configuration data the operator prepares

From "Configure a PXE server", Step 2.

Microsoft's documented way to prepare the BCD for network boot is to run
`bcdedit` on the operator's Windows machine against a new store file.
The resulting store holds three objects:

1. **RAM-disk options** (well-known identifier `{ramdiskoptions}`):
   - SDI device: `boot` (the device the boot manager was loaded from);
   - SDI path: `\Boot\boot.sdi`.
2. **WinPE loader entry** (a new GUID that `bcdedit` returns):
   - device and OS device both `ramdisk=[boot]\Boot\boot.wim,{ramdiskoptions}`;
   - loader path `\windows\system32\winload.exe` in Microsoft's (BIOS)
     walkthrough; for UEFI the Windows loader is `winload.efi`
     ("BCD System Store Settings for UEFI") (**OPEN-WPXE-1**);
   - system root `\windows`;
   - HAL detection on;
   - WinPE mode on.
3. **Boot manager** (`{bootmgr}`): a menu timeout and a display order
   containing the WinPE entry. The walkthrough uses a 30-second timeout
   and puts the WinPE entry last in the display order; these are
   walkthrough example values, not required.

The SDI and WIM paths in items 1 and 2 are also the walkthrough's
example layout (a `Boot` folder at the TFTP root); they must match
wherever the files are actually published.

The store is then copied to `\Boot\BCD` at the TFTP root.

Other boot-manager settings Microsoft documents for this case
**[archive]** ("How to Modify the BCD Store Using Bcdedit", Windows
Deployment Services):

- **RAM-disk TFTP block size** element: default **1432** bytes; Microsoft
  recommends raising it in steps (4096, 8192, 16384) and **not above
  16384**.
- **RAM-disk TFTP window size** element: default **4**.
- These are set on the RAM-disk options object. Whether and how the boot
  manager signals them to the server as TFTP options (RFC 2348 `blksize`,
  RFC 7440 `windowsize`) is not stated in the pages read
  (**OPEN-WPXE-2**). The [support article] shows a Microsoft TFTP server
  answering a read request with `tsize` and `blksize` (1456 bytes in its
  example).

## 6. What is not public

- **The BCD store's file format.** Microsoft documents BCD only through
  its tools (`bcdedit`, `BCDBoot`) and a WMI programming interface. No
  public format specification was found. The product therefore treats a
  BCD store as an opaque file that the operator (or a Microsoft tool run
  on Windows) produces. Generating or editing one without Microsoft's
  tools would need format knowledge this project does not have from a
  public source. (**OPEN-WPXE-3**; settled for the project by
  DEC-0018 item 3, [project rule]: the operator builds the store with
  Microsoft's tool, and the product imports and verifies it and never
  generates it; `preinstall-env.md` REQ-PE-012.)
- The exact UEFI file names and loader paths (OPEN-WPXE-1).

## 7. Size consequence for TFTP (derived from `tftp.md` §8 and §5 above)

A WinPE `boot.wim` is typically hundreds of megabytes. TFTP block numbers
are 16 bits, so one transfer can carry at most 65,535 full blocks:

| Block size | Largest file without block-number wrap |
|-----------:|---------------------------------------:|
| 512 | about 32 MiB |
| 1432 | about 89 MiB |
| 4096 | about 256 MiB |
| 16384 | about 1 GiB |

So delivering WinPE by TFTP to Microsoft's boot manager needs either a
large negotiated block size or block-number wrap-around, which RFC 1350
does not standardise. Which one Microsoft's boot manager supports is not
stated in the pages read. **OPEN-WPXE-4**; settled for the project by
DEC-0018 item 2, [project rule]: the boot service supports block-number
wrap-around and negotiates large block sizes (RFC 2348) when asked
(`boot-network.md` REQ-BOOT-035, REQ-BOOT-064). Whether Microsoft's boot
manager relies on wrap-around or on large blocks is still not stated in
any public source.

## 8. After WinPE starts

- WinPE loads, a command prompt opens and `wpeinit` runs to initialise
  devices and networking ("Configure a PXE server", PXE boot process
  summary step 8). Start-up order and auto-start are in `winpe.md` §5.
- Microsoft's walkthrough then uses tools in WinPE (DiskPart, DISM,
  BCDBoot) to partition, apply the image and make the disk bootable
  (`gpt.md` §10, `uefi-boot-manager.md` §9).

## Open points

- **OPEN-WPXE-1**: the UEFI boot manager's path inside the operator's
  WinPE image, and the UEFI loader path to put in the WinPE entry. The
  Windows 10 walkthrough is written for BIOS.
- **OPEN-WPXE-2**: whether the boot manager asks for its configured block
  size and window size through standard TFTP options.
- **OPEN-WPXE-3**: settled for the project by DEC-0018 item 3 (§6,
  [project rule]). Licensing of storing and serving kit files is still
  OPEN-PE-LIC.
- **OPEN-WPXE-4**: settled for the project by DEC-0018 item 2 (§7,
  [project rule]); Microsoft's actual client behaviour is still not
  stated publicly.
