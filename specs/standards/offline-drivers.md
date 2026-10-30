# Offline driver injection (standards topic 12)

Status: AUDITED (spec run M4, 2026-10-29; clean-room audit 2026-10-29, OPEN
items remain OPEN). §7 and OPEN-DRVS-4 to 6 AUDITED 2026-10-29 (M4 build run,
SR-1).

Summary of Microsoft's public documentation of Windows driver packages
and adding them to an offline Windows image, in the researcher's own
words. Tool and option names are Microsoft's. No command example is
copied.

Sources: SRC-178 (adding and removing driver packages offline), SRC-179
(DISM driver servicing options), SRC-180 (components of a driver
package), SRC-181 (device driver packages and deployment), SRC-171
(configuration passes), SRC-182 (DISM unattended servicing), SRC-187
(DISM global options), SRC-188 (taking inventory with DISM).
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

## 7. Adding a folder recursively and listing drivers (SR-1)

Status: AUDITED (M4 build run, 2026-10-29). Sources: SRC-179 (driver
servicing options), SRC-187 (DISM global options), SRC-188 (taking
inventory of an image). Option names and listing labels are Microsoft's
and are given only so the clean side can run and read the tool.

### 7.1 Adding drivers with recursion (SRC-179)

- The add-driver option works on an **offline** image only. The listing
  option works offline or on a running system.
- The driver argument is either one INF file or a folder. With a folder
  and the recurse option, every subfolder is searched for packages too.
- The driver argument can be repeated; packages are added in the order
  given (see §3).
- Invalid INFs in a searched folder: see §3 (console note, log warning,
  no error).
- The force-unsigned option exists for testing only (see §2).

### 7.2 Exit status (OPEN)

None of the pages read (SRC-179, SRC-187, SRC-188) gives DISM's process
exit codes, what value means success, or what is returned when some
packages in a folder are added and others fail. Only the skipped-INF case
in §3 is described, and only as no error on the console. See
OPEN-DRVS-2.

**[reading]** Until this is answered, a caller cannot treat a zero exit
alone as proof that every package was added; it would have to confirm
the result another way, for example by listing the drivers afterwards
(§7.3).

### 7.3 The driver listing (SRC-179, SRC-188)

- By default only third-party packages are listed; an "all" argument
  adds the inbox ones.
- Output can be asked for as a **table** or a **list** (a format option,
  also a global option, SRC-187).
- On an image, the listing shows which packages are present and whether
  each is installed or only staged (SRC-179).
- SRC-188 names these fields for each listed package:
  - **Published Name**: the store name given on adding (the
    `oem<number>.inf` form, §3);
  - **Original File Name**: the INF's own file name;
  - **Inbox**: yes for an inbox driver, no for third-party;
  - **Class Name**: the device class's friendly name;
  - **Provider Name**: the provider or signer of the package;
  - **Date**: the INF's driver date, **formatted for the locale**;
  - **Version**: the version from the INF's driver-version entry.
- The installed-or-staged state named in SRC-179 is not one of the
  fields SRC-188 lists; where it appears in the output is not described
  (OPEN-DRVS-5).
- No page gives the exact text layout of either format (separators,
  headers, ordering). **[reading]** A parser should key on the field
  labels and tolerate extra fields and spacing.

### 7.4 English output (SRC-187)

A global option makes DISM's console output English. Microsoft notes
that **some resources cannot be shown in English** even with it, and
that the option is not supported with the help command. **[reading]**
Because of that note, and because the date field is locale-formatted
(§7.3), the English option alone does not guarantee fixed field labels
or a fixed date format (OPEN-DRVS-4).

### 7.5 Log file (SRC-187)

- The log path option sets the full path and name of the log. Without
  it, the log goes to `%WINDIR%\Logs\Dism\dism.log`. **[reading]** This
  is the Windows directory of the system running DISM (in Windows PE,
  Windows PE's own), not of the image being serviced.
- **In Windows PE the default location is on the RAM-disk scratch
  space, which can be as small as 32 MB.** **[reading]** A long or
  verbose run in Windows PE should set the log path to real storage.
- When the log is archived, a `.bak` copy is kept and overwritten at
  each archive, and a new log is started. When archiving happens is
  not stated.
- The log level option takes 1 (errors) to 4 (errors, warnings,
  information and debug); the default is 3.
- A quiet option suppresses everything except errors on the console;
  Microsoft says not to use it with the listing commands, which would
  then show nothing.
- The log's format is not described (OPEN-DRVS-6).

## 8. Open items

- **OPEN-DRVS-1**: no public description of the driver store or of
  staging a package without Microsoft's servicing tools.
- **OPEN-DRVS-2**: DISM's process exit codes are not published on the
  pages read: neither the success value nor the result when some
  packages in a folder or recursive add fail while others succeed
  (§7.2). Only skipped invalid INFs are described (warning, no error).
- **OPEN-DRVS-3**: whether DISM checks a package's architecture against
  the image and refuses a mismatch; the pages read do not say.
- **OPEN-DRVS-4**: whether the English option fixes the
  listing's field labels and date format; Microsoft says some resources
  cannot be shown in English, and does not say which.
- **OPEN-DRVS-5**: where the installed-or-staged state appears
  in the listing, and the exact layout of the table and list formats.
- **OPEN-DRVS-6**: the log file's format and when it is
  archived.
