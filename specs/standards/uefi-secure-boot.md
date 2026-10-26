# Standards summary: UEFI Secure Boot (background only)

Topic 6 of the standards reading list. This is **conditional background
only**. Whether usg-provision must boot devices with Secure Boot enabled
is OPEN (INDEX Unconfirmed; `specs/boot-network.md` OPEN-BOOT-SB). This
file contains no signing design. Sources: UEFI Specification 2.10 chapter
32 (Secure Boot and Driver Signing), §7.4.1 and §7.4.2 (LoadImage,
StartImage), §3.1.1 and §3.3; and Microsoft Learn's public OEM Secure Boot
guidance.

## 1. What Secure Boot is

When Secure Boot is on, the firmware checks every image in the boot path
before running it: UEFI drivers (including option ROMs), UEFI applications,
and OS loaders. An image runs only if its signature or hash is trusted
under the platform's policy (UEFI §32.2, §32.6; Microsoft OEM Secure Boot
guidance). Secure Boot also changes how the boot manager behaves (UEFI
§3.1.1).

## 2. Keys and databases (UEFI §32.3, §32.6)

| Item | Role |
|------|------|
| PK (platform key) | the platform owner's key. It authorises changes to KEK, can hand over ownership, and can be used to turn Secure Boot off |
| KEK (key exchange keys) | keys allowed to update `db` and `dbx`, typically enrolled for the OS vendor and selected third parties |
| `db` (allowed) | signer certificates and image hashes that may run |
| `dbx` (forbidden) | revoked signers and image hashes. **`dbx` takes precedence over `db`** |
| `dbt` | timestamp authorities, used to judge revocations by time where supported |
| `dbr` | keys for OS recovery entries |

Microsoft's guidance says that Windows PCs ship with keys in `db` that let
Windows boot, and that Microsoft requires a KEK entry of its own so it can
later add allowed or revoked items. Firmware storage of these variables must
resist undetected change by the running OS.

## 3. Platform modes (UEFI §32.3)

- **Setup mode**: no PK is enrolled. Key variables can be changed without
  authentication.
- **User mode**: a PK is enrolled. Changes must be signed by PK or by an
  enrolled KEK, and signature checks are enforced.
- **Audit mode**: no enforcement. Every image runs and the results are
  logged.
- **Deployed mode**: the most locked-down mode. Setup and audit modes are
  forced off and made read-only.

Moving into user or deployed mode takes effect immediately. Moving into
setup or audit mode may need a reset. Microsoft's guidance says a platform
ready for Windows must report Secure Boot as on and setup mode as off, with
`db` provisioned.

## 4. What the firmware checks before running an image (UEFI §32.2, §32.6.3.3)

1. It computes the image digest using the Authenticode method over the
   PE/COFF image (§32.2.3). Signatures live in the image's certificate
   table (§32.2.2).
2. The image passes if `db` holds a matching hash, or a certificate that
   verifies one of the image's signatures. It must not match anything in
   `dbx`. One matching `db` entry is enough when an image has several
   signatures, as long as none is revoked.
3. The firmware may also approve images under its own platform policy
   (§32.6.3.2).
4. Whether images from networks, removable media, or other sources are
   checked is left to the system provider's policy (§32.2). The standard
   does not single out network-loaded images. Microsoft's guidance for
   Windows platforms requires verification of every image in the boot
   sequence, up to the Windows boot manager.

A network-loaded boot program reaches the boot manager through LoadImage,
via Load File and PXE (see `uefi-boot-manager.md` §5.1). It is then subject
to the same verification as any other image under that platform's policy.

## 5. What happens to an image that fails the checks

- **LoadImage** (UEFI §7.4.1):
  - returns *security violation* when the image was loaded but policy says
    it must not be started; the image still gets a handle;
  - returns *access denied* when policy forbids loading it at all; no
    handle is returned.
- **StartImage** (UEFI §7.4.2): refuses to start an image that policy
  rejected, and reports a security violation.
- The failure is recorded in the **Image Execution Information Table**,
  with reasons such as authentication failed, signature not found, found
  in `dbx`, policy failed, or untested (UEFI §32.4.2, §32.5).
- For an OS loader, the **boot manager moves on to the next boot option**
  (UEFI §32.6.1). For a network boot this means an unsigned or untrusted
  boot program is never run, and the device falls through as in
  `uefi-boot-manager.md` §5.
- A platform may let a physically present user approve and enrol a
  rejected image, reject it, or defer it (UEFI §32.6.3.3). Implementations
  need not support every part of that process.
- In audit mode, images that fail are still run, and the result is logged
  (UEFI §32.3.3, §32.4.2).

## 6. Secure Boot off

Chapter 32 does not state what happens to unsigned images when Secure Boot
is off. Microsoft's guidance notes that the PK can be used to turn Secure
Boot off. With enforcement off, the signature gate described in §4 and §5
does not apply.

## 7. Relevance to the boot service

This is background, not a requirement. If Secure Boot support is later
decided, every image the device's firmware runs during network boot would
have to verify against keys in that device's `db` and not be revoked in
`dbx`. Choosing an image's signing authority is a separate decision that
this file does not make. TFTP and DHCP themselves add no integrity
protection (`tftp.md` §9, `pxe-dhcp.md` §10). Secure Boot is the firmware's
only built-in check on the network-loaded program.
