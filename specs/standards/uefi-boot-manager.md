# Standards summary: UEFI boot manager, boot options and fall-through

Topic 5 of the standards reading list, background for BOOT-5 in
`specs/boot-network.md`. This is our summary of UEFI Specification 2.10
chapter 3 (Boot Manager), with supporting points from §7.4 (image services)
and §24.3 (PXE Base Code). It describes what the standard provides. Which
of these mechanisms usg-provision uses is a clean-side decision. Where
behaviour is still OPEN, `specs/boot-network.md` REQ-BOOT-061 says so.

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
