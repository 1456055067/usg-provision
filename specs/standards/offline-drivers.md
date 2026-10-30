# Offline driver injection (standards topic 12)

Status: AUDITED (spec run M4, 2026-10-29; clean-room audit 2026-10-29, OPEN items remain OPEN).

Summary of Microsoft's public documentation of Windows driver packages
and adding them to an offline Windows image, in the researcher's own
words. Tool and option names are Microsoft's. No command example is
copied.

Sources: SRC-178 (adding and removing driver packages offline), SRC-179
(DISM driver servicing options), SRC-180 (components of a driver
package), SRC-181 (device driver packages and deployment), SRC-171
(configuration passes), SRC-182 (DISM unattended servicing).
**[reading]** marks the researcher's inference.

## 1. What a driver package is (SRC-180)

A driver package is a set of files that together support a device:

- **INF file** (required): a text file, ASCII or UTF-16, that is not a
  script but a description: supported Windows versions, device setup
  class, version, the driver files with their source and destination,
  the hardware and compatible IDs the package applies to, the name of the
  catalog file, and how its services load.
- **Catalog file** (`.cat`): holds a cryptographic hash of each file in
  the package, so Windows can tell whether the package changed after
  publication. The catalog itself must carry a digital signature the
  system trusts. The INF names it in its Version section.
- **Driver files**: usually `.sys` binaries; long names are allowed
  except for boot-start drivers.
- **Other files**: settings, services, icons, libraries.

## 2. Signing (SRC-181, SRC-179)

- Driver packages installed in a Windows image must be digitally signed.
  A signed catalog is enough for most Plug and Play packages.
- Boot-start driver binaries (for example storage drivers needed to
  reach the boot disk) must carry **embedded** signatures.
- DISM has a force-unsigned option that overrides the x64 signature
  requirement; Microsoft describes it as for testing.
- Adding drivers offline must be done from Windows 10 or later, Windows
  Server 2016 or later, or **Windows PE for Windows 10 or later**;
  otherwise signature verification may fail (SRC-178).

## 3. Offline addition with DISM (SRC-178, SRC-179)

- DISM services only INF-style driver packages. Windows Installer
  packages and executable installers are not supported.
- Packages distributed as `.cab` files must be **expanded** before DISM
  can add them (SRC-181).
- Drivers packaged inside an installer can be installed only on a
  running Windows; Microsoft discourages this and suggests extracting
  the INF package instead.
- DISM can add one INF, or every INF in a folder, optionally recursing
  into subfolders. When pointed at a folder, INF files that are not
  valid driver packages are skipped with a console message and a log
  warning, **not an error**.
- Recursing can bloat the image: each INF is expanded into its own
  folder with its own copy of shared files. Microsoft recommends one
  source folder per package to avoid name clashes.
- Drivers are added in the order given.
- Added packages go into the image's **driver store** and are renamed
  to a published name of the form `oem<number>.inf`. When the image
  boots, Plug and Play matches the stored packages to the devices
  present.
- DISM can list, inspect, remove (by published name) and export
  third-party drivers. Inbox drivers cannot be removed (apart from some
  network drivers). Removing a boot-critical driver can make the image
  unbootable.

## 4. Through an answer file (SRC-171, SRC-178, SRC-182)

- A driver path in the offlineServicing pass of an answer file adds
  every INF package in that folder and its subfolders. Network paths can
  carry credentials in the answer file.
- Boot-critical drivers (needed to see the disk or network from Windows
  PE) belong in the windowsPE pass; all drivers are staged in the driver
  store but only boot-critical ones are also installed into the offline
  image and Windows PE.
- Applying driver settings with DISM's answer-file option works only
  against an offline image.

## 5. Which driver Windows uses (SRC-181)

Being in the driver store does not mean being used: after boot, Plug and
Play may pick a better-ranked driver. The ranking, most important
first: signature, ID match, driver date, driver version. A signed
package with a weaker ID match beats an unsigned one with a better
match.

## 6. What "offline install into an applied image" requires

[reading], from §1 to §4:

1. The package must be in INF form (CAB expanded, installers excluded).
2. The packages must be put into the applied image's driver store by a
   servicing tool that runs on Windows 10 or later, or Windows PE for
   Windows 10 or later, before the image first boots.
3. Signatures are checked when the package is added (x64).
4. Selection happens later, at first boot, by Plug and Play.

The format of the driver store and the steps DISM takes to stage a
package are not described in any public source read (OPEN-DRVS-1).

## 7. Open items

- **OPEN-DRVS-1**: no public description of the driver store or of
  staging a package without Microsoft's servicing tools.
- **OPEN-DRVS-2**: DISM's exit status when some INFs in a folder fail to
  add, other than invalid INFs being skipped with a warning.
- **OPEN-DRVS-3**: whether DISM checks a package's architecture against
  the image and refuses a mismatch; the pages read do not say.
