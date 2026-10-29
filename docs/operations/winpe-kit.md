# Pre-boot agent and the Windows PE boot kit (milestone M3)

This guide is for the operator who builds the Windows PE that devices
network-boot, and who places the project's pre-boot agent in it. The
product never ships, generates or modifies a Microsoft component
(REQ-PE-001; decisions 0018 items 3 and 5, and 0020). Everything in the
PE is the operator's own build, from Microsoft's kit, under the
operator's licence.

**Evidence status (read first).** No step of this guide has been run
with a real Windows PE. The agent's logic is tested in CI and on the
development host with a simulated platform; its Windows code is
type-checked and partly tested on a Windows Server CI runner. Booting a
real Windows PE from the relay, the agent starting automatically, the
FIPS self-test inside Windows PE, and a real Windows 11 install are the
owner's lab procedure MT-2, which is **NOT RUN**
([MT-2-lab.md](../testing/MT-2-lab.md)). The agent artifact is not
signed (POAM-60).

## Contents

- [What the device carries](#what-the-device-carries)
- [What you need](#what-you-need)
- [1. Get and check the agent pair](#1-get-and-check-the-agent-pair)
- [2. Write the agent configuration](#2-write-the-agent-configuration)
- [3. Build Windows PE with the agent](#3-build-windows-pe-with-the-agent)
- [4. Placing the FIPS module (DLL rule)](#4-placing-the-fips-module-dll-rule)
- [5. Build the boot configuration](#5-build-the-boot-configuration)
- [6. Import the PE and publish the kit](#6-import-the-pe-and-publish-the-kit)
- [At the device](#at-the-device)
- [Exit codes](#exit-codes)
- [Persistent errors](#persistent-errors)
- [Limits](#limits)
- [Document Change History](#document-change-history)

## What the device carries

The device carries **no secret** (decision 0020). The PE holds the agent
and four public files: the server address, the server's TLS trust
anchors, and the two public keys that verify the signed job plan and the
signed content manifest. Anything in the PE is served over cleartext
TFTP to any device that asks (POAM-8), so nothing else may go in it.

- The agent authenticates the **server** by TLS against the trust
  anchors. The server does not authenticate the **device**: a session is
  authorised only by an operator-issued code typed at the device or by an
  operator approving it in the console (decision 0018 item 1; POAM-38).
- A PE substituted on the boot network can carry other anchors and keys,
  and so point the device at another server (POAM-45). Compensations in
  M3: `pe agent-config` records the SHA-256 of `agent.toml` and of the
  anchors, so a kit can be compared with the record; nothing is written
  to a disk until a person at the device confirms the disk and the wipe;
  and the device has no secret to give away.

## What you need

- A Windows machine with Microsoft's Assessment and Deployment Kit and
  its Windows PE add-on (`winpe.md` §2), under your licence.
- The **agent pair** from the CI `windows-agent` job's artifact
  `usgp-preboot-agent-<sha12>-x86_64-pc-windows-msvc/`: the agent
  executable, the FIPS module DLL (`aws_lc_fips_0_14_3_crypto.dll` for
  the pinned module), `SHA256SUMS` and `PAIR.sha256`.
- `usgp-cli` with an operator certificate, and the server's public keys
  `plan.pub` and `content.pub` and its device-listener trust anchors
  ([server.md](server.md#keys-for-the-device-listener-m3)).
- The device listener switched on, and the relay enrolled as a boot
  service with an enabled `[server_feed]` ([server.md](server.md),
  [relay.md](relay.md)).

## 1. Get and check the agent pair

1. Check each file against `SHA256SUMS`, and `SHA256SUMS` against
   `PAIR.sha256`. The `PAIR.sha256` digest names the pair.
2. Record that digest in the kit record (SI-7), with the commit it was
   built from.
3. Never replace the DLL alone, or pair an executable with a DLL from
   another build. Both files come from one build.

The CI step that makes the pair checks that the executable imports that
DLL and no other AWS-LC DLL, that neither file imports a dynamic C
runtime, and that `--self-test` passes from a directory holding only the
pair. It is not signed and its build is not checked for reproducibility
(POAM-60).

## 2. Write the agent configuration

```sh
usgp-cli pe agent-config --out ./agent-kit \
  --server-url https://provision.example.gov:8444 \
  --server-name provision.example.gov \
  --trust-anchors device-listener-cas.pem \
  --plan-key-pub plan.pub --content-key-pub content.pub
```

It writes a **new** directory (it never overwrites) holding exactly
four public files:

| File | Content |
|------|---------|
| `agent.toml` | `server_url`, optional `server_name`, the three file names below, `network_wait_s` (default 120, 10 to 600), `connect_timeout_s` (default 15, 1 to 120) |
| `trust-anchors.pem` | The server trust anchors, each `CERTIFICATE` block decoded and written back fresh; text between blocks dropped |
| `plan.pub` | The plan public key (P-384), re-encoded |
| `content.pub` | The content public key (P-384), re-encoded |

- It checks every value as the agent will: `https` only, the host name,
  the ranges, the anchors (by building the agent's TLS client from them)
  and the keys (two different P-384 public keys).
- It refuses any input holding a `PRIVATE KEY` block, any other PEM label,
  an unclosed block, no certificate, or more than 64.
- It contacts no server and never opens or modifies a PE.
- It emits one `pe.agent_config.created` audit event with the SHA-256 of
  what it wrote. Keep that record: it is how a substituted kit is found
  (POAM-45).
- `agent.toml` is at most 64 KiB; unknown keys refuse start-up. There is
  no setting that skips TLS or signature checks.

## 3. Build Windows PE with the agent

Follow Microsoft's procedure; the step numbers refer to the repo
summaries in `specs/standards/`.

1. Make a working set with `copype amd64 <dir>` (`winpe.md` §3). The
   amd64 Windows PE is the one this product supports (REQ-PE-020: UEFI
   x64 only).
2. Mount `media\sources\boot.wim` index 1 with DISM (`winpe.md` §4).
3. Create one directory in the mounted image, for example `\usgp\` (it is
   `X:\usgp\` when Windows PE runs), and copy into it the agent pair and
   the four files from step 2, following the
   [DLL rule](#4-placing-the-fips-module-dll-rule).
4. Add any network and storage drivers the devices need with DISM
   (`winpe.md` §4, §5.2). A device whose adapter or disk controller has
   no driver shows a persistent error.
5. Make the agent start automatically: add `Winpeshl.ini` in
   `%SYSTEMROOT%\System32` with a multi-program section that runs
   `%SYSTEMROOT%\System32\wpeinit.exe` first and then the agent by its
   full path, for example `X:\usgp\usgp-preboot-agent.exe` (`winpe.md`
   §5.1). Running `wpeinit` explicitly side-steps OPEN-WINPE-1 (whether
   `wpeinit` still runs when `Winpeshl.ini` replaces the shell).
6. Unmount with commit (`winpe.md` §4).

Secure Boot: the boot manager in the kit is Microsoft's, signed by
Microsoft. Which certificate authority it is signed under depends on the
ADK and the `/bootex` choice (`winpe.md` §3); choose to match what your
devices trust. The product never changes Secure Boot settings (decision
0018 item 5).

## 4. Placing the FIPS module (DLL rule)

The agent uses the FIPS 140-3 module through a DLL that the executable
imports at load time (decision 0001). Which copy of that DLL Windows
loads decides whether the validated module runs. The rule below rests on
the standards summary `windows-storage-firmware-api.md` (topic 23) §28,
"DLL search order and how to limit it":

- Before any folder is searched, Windows applies DLL redirection, API
  sets, side-by-side redirection, the modules already loaded (a module
  of the same name is reused, wherever it came from) and the known-DLL
  list. Then, with safe DLL search mode on (the default), the
  application's own folder is searched **first**, before the system
  folders, the current folder and `PATH` (§28).
- A DLL the executable imports directly is resolved when the process
  starts, before the agent's code runs, so a search restriction the agent
  could set while running (`SetDefaultDllDirectories`) cannot protect it.
  This is a **[reading]** of §28: Microsoft's pages do not state it
  outright (**OPEN-WAPI-15**). Placement and write protection are what
  protect the import.

The rule:

1. **One directory.** The agent executable, its FIPS DLL, `agent.toml`
   and its three public files are in one directory of the PE image (for
   example `X:\usgp\`). Start the agent from that directory by its full
   path.
2. **No other copy.** No other directory in the image holds a file with
   the DLL's name: not the system folders and not any `PATH` entry.
3. **Only you write it.** Only the operator who builds the kit may write
   that directory, on the build machine and in the mounted image.
4. **Keep safe DLL search mode on** (the default; §28). Do not set the
   `SafeDllSearchMode` registry value to 0 in the image.
5. **One build.** The executable and the DLL come from the same pair,
   checked as in [step 1](#1-get-and-check-the-agent-pair).
6. **Check it in Windows PE.** Lab step L5 runs `usgp-preboot-agent
   --self-test` inside the built PE and records its output: `fips mode:
   active`, the `fips module` line, `sha-256 known answer: pass`, `drbg:
   pass` and `result: PASS`. Run it on every new kit.

Whether Windows PE x64 is inside the module's validated operational
environments is not confirmed (POAM-1; decision 0018 item 6). The agent
checks FIPS mode first at every start and refuses to run if it is
inactive, before it reads its configuration.

## 5. Build the boot configuration

Build the boot configuration store (BCD) yourself with `bcdedit`, as in
Microsoft's network-boot walkthrough (`winpe-network-boot.md` §5): a
RAM-disk options object with the SDI path, a Windows PE loader entry
whose device is the RAM disk of `boot.wim`, and the boot manager's
display order. For UEFI the loader path is `winload.efi`; the boot
manager's path inside the kit and the exact UEFI loader path are not
confirmed for UEFI by Microsoft's walkthrough (OPEN-WPXE-1); lab step L1
records what worked. The product imports, hashes and serves the BCD but
never generates or edits it (decision 0018 item 3).

The boot manager's TFTP block size and window size elements, if you set
them, are your choice; whether the boot manager sends them as TFTP
options is OPEN-WPXE-2, recorded by lab step L4.

## 6. Import the PE and publish the kit

1. Import the committed `boot.wim`:
   `usgp-cli pe import boot.wim --name NAME --arch x64 --kit-version V`,
   and wait until it is Ready (`usgp-cli pe view ID`).
2. Create or edit the package to use that PE (`usgp-cli package create`
   or `edit --pe ID`), and assign the package to the boot service
   (`usgp-cli boot-service set-packages`).
3. Copy the kit files to the relay's boot root (for example
   `bootmgfw.efi`, `Boot/BCD`, `Boot/boot.sdi`, `Boot/boot.wim`, fonts),
   and write the manifest:

   ```sh
   usgp-cli boot-manifest create --pe-kit --root /srv/usgp-relay/boot \
     --out /etc/usgp-relay/boot-manifest.toml --pe PE_ID \
     --boot-program bootmgfw.efi --bcd Boot/BCD --sdi Boot/boot.sdi \
     --wim Boot/boot.wim [--font NAME]...
   ```

   It checks that the boot program is a UEFI x64 application, that the
   WIM is the Ready x64 PE `PE_ID` on the server, and prints the memory
   a device needs: 512 MiB plus the WIM's size (REQ-PE-018).
4. Set `boot.uefi_x64_program` to the boot program, enable
   `[server_feed]`, and run `usgp-relay --check-config`
   ([relay.md](relay.md#windows-pe-boot-kit-pe_kit-m3)).

## At the device

The agent's screens, in order (one language, REQ-JOB-015):

1. **Starting**, then **Waiting for the network** (at most
   `network_wait_s`), then **Connecting**.
2. **Authorise this device**: a display code (`XXX-XXX`) and the boot
   service's name. The technician types the operator's code (not echoed,
   never shown), or an operator approves the session that shows this
   display code. `C` cancels.
3. **Choose what to install**: the packages offered, with name,
   description, Windows release, edition, architecture, image size and
   the minimum disk size.
4. **Choose the disk to install to**: eligible disks are numbered; disks
   that cannot be used are listed with every reason (removable, USB,
   boot media, too small, read-only, indistinguishable twins without a
   serial, and others). A single eligible disk must still be chosen.
   `B` goes back.
5. **Confirm: erase the disk and install**: the package, the disk, its
   existing partitions and labels (never file content), and the network
   adapter addresses that will be stopped from network boot after a
   successful install. Only typing `WIPE` confirms. After `WIPE` the
   install cannot be cancelled.
6. The **job screen**: the five steps (download and verify all content;
   partition and format; apply the image; make the disk bootable; report
   success and restart), with bytes and the current file. Completion is
   shown only after the server has recorded success; then the device
   restarts into the installed Windows.

The agent never wipes or restarts on its own. Any screen waits at most
2 hours for the person; when that runs out, or console input ends,
the agent cancels (before the wipe confirmation) or ends with no restart
or shutdown (at a persistent screen).

`usgp-preboot-agent --version` prints the version, and `--self-test`
runs the FIPS check without a configuration (exit 0 only in FIPS mode).

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | The job succeeded and the server recorded it |
| 1 | Start-up failed (usage, `agent.toml`, console, FIPS, platform, device facts) |
| 2 | Stopped before the confirmation: nothing to offer, no usable disk, not UEFI x64, session refused or ended, or no boot service for this network |
| 3 | The wipe confirmation was not accepted (including 409 `in_use`); nothing written |
| 4 | The job failed before any disk write (for example a tampered plan or chunk) |
| 5 | The job failed after a disk write |
| 6 | Cancelled by the person; nothing written |
| 7 | The server could not be reached or authenticated |

## Persistent errors

A persistent error screen stays until the person types `R` (restart) or
`S` (shut down), within the 2-hour limit above (REQ-JOB-005). Each says
whether anything was written to a disk. A job failure shows the failed
step, the cause (network, integrity check, refusal, time limit, or a
local problem), the reason and its code, the files that failed, and the
attempts; the operator sees the same fields in `usgp-cli job show`.

| Screen | Typical cause |
|--------|---------------|
| Cannot start | FIPS mode inactive; the platform could not be prepared; the trust anchors could not be used |
| No network | No address from DHCP within `network_wait_s`; a network driver may be missing |
| Cannot reach the provisioning server | Connection or TLS failure; wrong anchor or server name; the listener refused the source |
| This boot service is not set up for this device | No active boot service, or more than one, serves this network (403 at session open) |
| This device cannot be installed | Not booted in UEFI mode, or not x64 (REQ-PE-020) |
| This device was refused | An operator refused it, or too many wrong codes |
| The session has ended | It expired or ended on the server |
| No deployment is available | The boot service offers no usable package (REQ-TGT-008) |
| No disk can be used | Every disk was refused; reasons listed; a storage driver may be missing |
| The install did not start | The server could not durably record the wipe authorisation; a network adapter is already in a job or stopped from network boot (`in_use`); or the confirmation failed |
| INSTALL FAILED (job screen) | A step failed; see the failure fields |
| The server no longer accepts this device's session | A 401 during the job: the device's network address changed, or the session lapsed (POAM-39); the job becomes `lost` |
| INTERNAL ERROR | An internal fault; the message stays up to 600 s |

## Limits

- UEFI x64 only; BIOS and other architectures are refused before any
  disk screen (REQ-PE-020, REQ-DISK-011).
- Memory: 512 MiB plus the PE's WIM size, printed by `boot-manifest
  create --pe-kit`. A device short of memory is not detected by the agent
  (REQ-PE-018 is partial).
- Removable disks, USB disks (including a USB disk that reports itself as
  fixed, OPEN-DISK-4) and the disk holding the boot environment are
  refused. The disk must be at least 64 x 10^9 bytes, or more for a large
  image (REQ-DISK-004; decision 0023 item 3).
- The wipe destroys the old partition tables and the first 1 MiB of each
  old volume; it is **not** a sanitisation (OPEN-DISK-2; MP-6 not
  claimed; POAM-47).
- Images must be WIM, uncompressed or XPRESS. LZX or `.esd` media must be
  re-exported with DISM `/Compress:fast` before upload (decision 0014).
  Image features the project has not observed in its own DISM samples
  are refused with a named reason (decision 0006; POAM-57).

## Document Change History

| Date | Change |
|------|--------|
| 2026-10-29 | First version (M3 WU-16): trust model, the agent pair and its checks, `pe agent-config` output (public keys only, decision 0020), building Windows PE with `Winpeshl.ini`, the FIPS DLL placement rule (topic 23 §28, OPEN-WAPI-15 as a reading), the BCD, import and the `--pe-kit` manifest, device screens, exit codes, persistent errors and limits. Nothing here has run in a real Windows PE (MT-2 NOT RUN). |
