# Standards summary: Windows PE (WinPE)

Topic 11 of the standards reading list. This is our summary of
Microsoft's public documentation on Windows PE: what it is, how it is
obtained and built, how it is customised and starts, and its use and
redistribution limits. For PE-1 (`specs/preinstall-env.md`). Booting
WinPE over the network belongs to milestone M3 and is not summarised here
(§8).

Sources (all Microsoft Learn unless noted): "Windows PE (WinPE)",
"Download and install the Windows ADK", "WinPE: Create bootable media",
"Copype command-line options", "WinPE: Mount and Customize", "Wpeinit and
Startnet.cmd", "Windows Setup Supported Platforms and Cross-Platform
Deployments", and one Microsoft Q&A answer marked **[secondary]** in §7.
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

## 8. Not summarised

- Network boot of WinPE (UEFI PXE files, boot configuration data, RAM
  disk options). A Microsoft page on preparing a PXE server for UEFI boot
  returned "not found" during this run. Needed for M3.
- The full optional-component list and language packs.
