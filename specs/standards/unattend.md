# Windows answer files and configuration passes (standards topic 10)

Status: AUDITED (spec run M4, 2026-10-29; clean-room audit 2026-10-29, OPEN
items remain OPEN).

Summary of Microsoft's public documentation of Windows unattended setup,
in the researcher's own words. Setting and path names are Microsoft's
public names, used for interoperability. No sample answer file is copied.

Sources: SRC-170 (Windows Setup automation overview), SRC-171 (how
configuration passes work), SRC-172 (hiding sensitive data), SRC-173
(ComputerName), SRC-174 (TimeZone), SRC-175 (AdministratorPassword and
its PlainText child), SRC-176 (JoinDomain and MachineObjectOU), SRC-177
(custom scripts in Setup), SRC-182 (DISM unattended servicing). Labels:
**[reading]** marks the researcher's inference from the text, not a
Microsoft statement.

## 1. Configuration passes (SRC-171)

An answer file groups settings by configuration pass. Each setting is
valid only in the passes its reference page lists (§3). The passes:

| Pass | When it runs | Typical use |
|------|--------------|-------------|
| windowsPE | When Setup starts from its media or from an earlier Windows | Setup and Windows PE options: which image, disk layout; boot-critical drivers |
| offlineServicing | After the image is laid on disk, before the first restart; also when DISM is given an answer file for an offline image | Drivers, updates, language packs added to the offline image |
| specialize | On the image's first boot (and the first boot after a generalize) | Machine-specific settings: unique security IDs are created here; network, international and domain settings |
| generalize | When Sysprep is run with generalize | Removes machine-specific data so the image can be captured |
| auditSystem, auditUser | Only when the machine is set to boot into audit mode | Extra drivers, custom commands (system and user context) |
| oobeSystem | Before the Windows welcome experience starts | Shell options, user accounts, language and locale |

Microsoft notes that most Setup settings can go in either specialize or
oobeSystem.

### 1.1 Deploying an already-captured image without Setup

Microsoft's "deploy by script" example (SRC-171): the image is applied
with DISM's apply operation, the machine boots it, **specialize** runs,
the machine restarts, **oobeSystem** runs, then the welcome experience
starts. [reading] In this path the windowsPE pass of the answer file is
not processed by Setup, because Setup is not run from Windows PE; any
offlineServicing settings are processed only if a tool applies them to
the offline image (§1.2).

### 1.2 Applying an answer file to an offline image with DISM (SRC-182)

DISM can apply an answer file to an offline (or running) image. Only the
offlineServicing pass is processed. Driver updates through an answer
file must be applied to an offline image. Only one answer file per
command. An answer file applied this way is **not cached** on the target.
Microsoft recommends authoring and validating answer files with its
System Image Manager tool.

## 2. Where Windows looks for, and keeps, the answer file (SRC-170)

At the start of each configuration pass, Setup looks for an answer file
in a fixed order of precedence ("implicit search") and uses the
highest-precedence one that holds settings for that pass:

1. a registry value pointing to an answer file (any name);
2. `%WINDIR%\Panther\Unattend` (named Unattend.xml or Autounattend.xml;
   searched only for upgrades from an earlier Windows, **not** when Setup
   starts from Windows PE);
3. `%WINDIR%\Panther` (Setup's own cached copy, §2.1);
4. root of removable writable media, by drive letter (Autounattend.xml);
5. root of removable read-only media, by drive letter (Autounattend.xml);
6. in windowsPE and offlineServicing: the `\Sources` folder of the
   Windows distribution (Autounattend.xml); in all other passes:
   `%WINDIR%\System32\Sysprep` (Unattend.xml);
7. the root of `%SYSTEMDRIVE%` (Unattend.xml or Autounattend.xml);
8. the root of the drive Setup runs from.

An answer file named explicitly to Setup or Sysprep replaces the cached
copy.

### 2.1 The cached copy

- Setup validates the chosen answer file and caches it: during the
  windowsPE and offlineServicing passes to a Setup working folder, and,
  once Windows is on the disk, to `%WINDIR%\Panther`. The cached copy
  persists across restarts so later passes can use it.
- After each pass, Setup marks that pass as processed in the cached
  copy, and does not process it again unless the file is replaced.
- Microsoft says not to reuse or edit the cached copy: Setup annotates
  it.
- To place an answer file into an offline image so that the image uses
  it at first boot without being told, Microsoft's procedure puts it at
  `\Windows\Panther\unattend.xml` inside the image. If the image already
  holds an answer file with unprocessed settings, Microsoft advises
  editing rather than replacing it.

## 3. Settings that carry the M4 values

| Value | Setting (Microsoft name) | Valid passes | Notes |
|-------|-------------------------|--------------|-------|
| Computer name | Microsoft-Windows-Shell-Setup / ComputerName (SRC-173) | offlineServicing, specialize | §3.1 |
| Time zone | Microsoft-Windows-Shell-Setup / TimeZone (SRC-174) | specialize, oobeSystem, auditSystem | §3.2 |
| Local administrator password | Microsoft-Windows-Shell-Setup / UserAccounts / AdministratorPassword, with children Value and PlainText (SRC-175) | oobeSystem, auditSystem | §3.3 |
| Domain to join | Microsoft-Windows-UnattendedJoin / Identification / JoinDomain (SRC-176) | specialize | §3.4 |
| OU for the computer account | Microsoft-Windows-UnattendedJoin / Identification / MachineObjectOU (SRC-176) | specialize | §3.4 |

Descriptive tags have no Windows answer-file setting in the sources read.

### 3.1 Computer name (SRC-173)

- At most 15 bytes of content; ASCII counts one byte per character,
  multi-byte characters count their bytes.
- No spaces, and none of the punctuation characters the page lists
  (braces, bar, tilde, square brackets, backslash, caret, apostrophe,
  colon, semicolon, angle brackets, equals, question mark, at sign,
  exclamation mark, double quote, hash, dollar, percent, backtick,
  parentheses, plus, slash, full stop, comma, asterisk, ampersand); no
  emoji or similar non-standard characters.
- The name must pass Windows' DNS name validation; for example a name
  made only of digits is not allowed.
- If the setting is absent, Windows generates a random name. If it is an
  asterisk or empty, Windows generates a random 15-character name.
- On Windows 10 and later, users cannot type a name during the welcome
  experience; the name is generated unless the answer file sets it.

### 3.2 Time zone (SRC-174)

- A string of up to 256 characters naming a Windows time zone. The list
  of valid names comes from Windows itself (Microsoft points to the
  `tzutil /l` command). A suffix form that turns off daylight saving is
  shown in Microsoft's example.
- If unset, Windows picks a default from the language and region in the
  answer file.
- The page does not say what Windows does with an unknown name
  (OPEN-UNATT-2).

### 3.3 Local administrator password (SRC-175)

- The built-in Administrator account is disabled by default on clean
  installs. If no administrator password is set, and automatic logon is
  not set to the Administrator user, the account stays disabled.
- Setting automatic logon to the Administrator user enables the account
  even without a password. Microsoft calls a blank password a security
  risk.
- The value has a PlainText flag: true (the default) means the password
  appears in clear in the answer file; false means it is "hidden" (§4).
  The flag cannot be set by hand in Microsoft's tool; the tool's hide
  option sets it.
- How the hidden form is computed is not stated on the pages read
  (OPEN-UNATT-1). Microsoft's examples show an encoded string.

### 3.4 Domain and OU (SRC-176)

- JoinDomain: the DNS or NetBIOS name of the domain. If both a domain
  and a workgroup are given, the domain wins. Empty values are not
  allowed.
- MachineObjectOU: optional; the full LDAP distinguished name of the OU
  in which the computer account is created. Empty values are not
  allowed. No length limit is stated.
- Microsoft's example places join credentials (domain, user name,
  password) next to JoinDomain in the same answer-file element.
  [reading] An online join from the answer file therefore puts a domain
  password into the answer file. The offline join alternative is
  standards topic 13 (not summarised yet).

## 4. Secrets in answer files (SRC-170, SRC-172, SRC-175)

What Microsoft documents:

1. Setup removes sensitive data from the **cached** answer file at the
   end of each configuration pass.
2. Even so, Microsoft says the cached answer file in `%WINDIR%\Panther`
   persists across restarts and must be deleted before the computer is
   handed to its user, because domain passwords, product keys and other
   sensitive data may be a security problem.
3. If an answer file is embedded at a higher-precedence location than
   the cached copy (§2), it can be re-cached at the start of a later
   pass, and sensitive data for passes already processed is then not
   cleared again. Microsoft advises embedding at a lower-precedence
   location unless the cached copy must be overridden.
4. If oobeSystem settings remain to run at the user's first start,
   Microsoft suggests removing the sections already processed, or using
   a separate answer file holding only oobeSystem settings.
5. A command in the post-setup script (§5) can delete cached or embedded
   answer files.
6. "Hiding" a password only hides it; it gives **no encryption or other
   security benefit**. Only local account passwords (administrator
   password, local account passwords, automatic logon password) can be
   hidden. Domain passwords, product keys and other sensitive values stay
   in clear text. Microsoft says to treat answer files as sensitive data
   and control access to them.
7. An answer file applied with DISM is not cached on the target (§1.2).

[reading] The documents do not promise that a secret in an answer file
is ever absent from the disk: Setup's clearing applies to its cached
copy, not to other copies such as one placed in the image (§2.1) or on
removable media, and freed disk blocks are not discussed
(OPEN-UNATT-3).

## 5. Scripts Setup runs (SRC-177)

- **SetupComplete**: a command script at a fixed path under
  `%WINDIR%\Setup\Scripts` that Setup runs with local system rights after
  Windows is installed. The page says both that it runs before the logon
  screen appears and that it starts right after the user sees the
  desktop (OPEN-UNATT-4). Setup logs that it ran it but does not check
  its exit code. It must not restart the machine (that leaves the system
  in a bad state). If the machine joined a domain during setup, domain
  Group Policy is applied only after the script finishes. It is disabled
  when an OEM product key is used, **except on Enterprise editions** and
  Windows Server.
- **ErrorHandler**: a script at the same place that Setup runs, with
  local system rights, when it hits a fatal error; it may run more than
  once.
- Answer-file command settings also exist: synchronous and asynchronous
  commands at Setup start, in audit mode, and first-logon commands that
  run after the welcome experience but before the desktop. Microsoft
  advises keeping them short.

## 6. Drivers through the answer file (SRC-171)

Boot-critical drivers go in the windowsPE pass; other drivers can go in
offlineServicing. Driver servicing itself is topic 12
(`specs/standards/offline-drivers.md`).

## 7. Open items

- **OPEN-UNATT-1**: the hidden-password encoding. Microsoft's pages say
  only that it is not encryption. If the product ever writes a hidden
  password, the encoding needs a public Microsoft source.
- **OPEN-UNATT-2**: what Windows does with a time zone name it does not
  know (error, default, or ignore).
- **OPEN-UNATT-3**: whether any public Microsoft text says when, or
  whether, the cleared sensitive data is removed from other answer-file
  copies and from the disk.
- **OPEN-UNATT-4**: SetupComplete timing: before the logon screen, or
  after the desktop appears (the page says both).
