# MT-2: owner lab procedure for milestone M3

MT-2 is the manual procedure for M3 exit criterion 1: a device boots
the operator's Windows PE from the relay, a technician authorises it and
picks a package and a disk, the image is applied, and the device
restarts into Windows setup, not network boot. It needs licensed
Microsoft media and the Assessment and Deployment Kit, so only the owner
runs it (OPEN-PE-LIC). It is defined in the M3 plan, section 10.4.

**Status: NOT RUN.** Until the owner runs it and the results are
recorded, every item below stays NOT RUN, and M3 is **not met**. A step
that could not be run is recorded as NOT RUN, never as PASS.

What CI already shows without Microsoft binaries (do not repeat it
here): the agent and server against a synthetic WIM on a simulated
platform, our GPT on a loopback file and under OVMF (S10, GPT-OBS-002),
a DiskPart-written GPT read by our parser (GPT-OBS-001), the relay's
BOOT-5 stop with OVMF and a test payload (S9), and TFTP wraparound
in-process. See
[TEST_EVIDENCE.md](../compliance/TEST_EVIDENCE.md).

## Lab

- QEMU with OVMF **Secure Boot** firmware and the Microsoft-key variable
  store (`OVMF_VARS_4M.ms.fd`), one guest with an NVMe disk and a SATA
  disk (virtual disks of at least 70 GB each), and a second, removable
  (USB) virtual disk for the refusal check.
- `usgp-relay` and `usgp-server` (with PostgreSQL) on the lab network;
  the relay enrolled as a boot service for the guest's subnet.
- A Windows machine with the ADK and its Windows PE add-on.
- Licensed Windows 11 Enterprise x64 media.
- A second virtual disk and DISM for the comparison apply in L8.

## Evidence to keep for every step

- The date, the commit of every binary (`usgp-relay`, `usgp-server`,
  `usgp-cli`, the agent pair digest from `PAIR.sha256`), the ADK version,
  the QEMU and OVMF versions and the SHA-256 of the OVMF files.
- The relay's and the server's audit lines for the step (stdout mirror),
  and the guest's serial or screen capture.
- Whether each check passed, failed or was NOT RUN, and why.
- No code value, token or private key in any evidence file. Write codes
  only to a file readable by you and delete it after use.

Lab observations about Microsoft's components (LAB-OBS-nnn) go to
`docs/formats/winpe-boot-observed.md` (to be created with the first
observation), each with the step, the evidence file and its SHA-256.
Results go to the compliance scribe for
[TEST_EVIDENCE.md](../compliance/TEST_EVIDENCE.md).

## Steps

| Step | Action | Pass when | Evidence to capture | Covers |
|------|--------|-----------|---------------------|--------|
| L1 | Build Windows PE with the ADK, add the agent pair and the `pe agent-config` output, add `Winpeshl.ini`, build the BCD ([winpe-kit.md](../operations/winpe-kit.md)); import the PE; build the relay manifest with `boot-manifest create --pe-kit` | Import Ready; manifest written; memory printed | ADK version; `Winpeshl.ini` text; the `bcdedit` commands used and the UEFI loader path that worked (OPEN-WPXE-1); `pe.agent_config.created` record; `pe import` digest; manifest SHA-256; printed memory | REQ-PE-011, 012, 018 |
| L2 | Prepare the Windows 11 Enterprise x64 image. If it is LZX or `.esd`, re-export it with DISM `/Compress:fast`. Upload, declare (`windows-11` / `enterprise` / `x64`), package, wait for Ready; assign the package to the boot service | Package Ready and assigned | `dism /Get-WimInfo` output; upload digest; the declaration; package id; `boot_service.packages.set` record | REQ-IMG-001, 041 (M2 path with real media) |
| L3 | Enrol the relay as a boot service; enable `[server_feed]`; start the relay | `boot_policy.applied` (generation 1 or more) | Enrolment output and record; `relay.start` line (`boot_policy`, `boot_service_id`) | Decision 0021 |
| L4 | PXE-boot the guest with Secure Boot on | Windows PE starts from the relay | Every `tftp.transfer.*` line: names requested, `blksize`, `windowsize`, `block_wrap`, `wraps`; any `boot.file.verify_slow` or `tftp_verify_timeout` (the `.wim` is re-hashed on every request; raise `tftp.handshake_timeout_ms` if needed and record it). Record as LAB-OBS-001 (names), LAB-OBS-002 (block and window size; OPEN-WPXE-2) and LAB-OBS-003 (whether wraparound works, and which mode; OPEN-WPXE-4) | REQ-PE-011, REQ-BOOT-063, 064; decision 0018 item 2 |
| L5 | Let the agent start. Then run `X:\usgp\usgp-preboot-agent.exe --self-test` in the same Windows PE build (how a prompt is reached in the lab build is your choice; record it) | The agent starts by itself after `wpeinit`; the network wait ends; self-test `result: PASS` | Screen captures; the full self-test output (`fips mode`, `fips module`, `sha-256 known answer`, `drbg`, `result`); firmware mode and architecture as the agent reports them | REQ-PE-013, 014, 020; decision 0018 item 6; POAM-1 |
| L6 | Authorise with a code; on a second run, authorise by console approval using the display code. Choose the package and the NVMe disk; check the USB disk is listed as refused; confirm with `WIPE` | Code and approval both work; the USB disk is refused with its reason; the wipe screen lists partitions and the claimed MACs | Screen captures; `device.session.*`, `auth_code.used`, `device.session.approved`, `disk.wipe.authorised`, `job.created`, `job.plan.issued` records (no code value) | REQ-TGT-004 to 006, 012 to 016; REQ-DISK-001 to 006 |
| L7 | Steps 1 and 2 of the job: verify all content, then partition and format | Steps complete | The job's layout report (`usgp-cli job show`); after first boot, Windows' own view of the disk (partition order, types, sizes, alignment); whether DiskPart formatted the recovery partition after its type was set (BOOT-004, POAM-53); the ESP as FAT32 | REQ-DISK-008 to 010; GPT on real firmware |
| L8 | Step 3: apply the image | Applied; no named refusal | Apply the same index with DISM to the second virtual disk and compare the two trees with the `tree_manifest` example of `usgp-winapi`; record every difference. Any named refusal becomes a WIM sample request (POAM-57). After first boot, check that re-based links and junctions resolve (decision 0022 item 4). Free space left on the Windows volume, to check the file-system overhead estimate (POAM-48) | REQ-PE-017; decision 0022 |
| L9 | Step 4 and the restart: BCDBoot, the boot option, success reported, restart | The device restarts into Windows setup, not network boot | `job.succeeded` and `boot_stop.added` records; the device's last screens; the first screen of Windows setup | REQ-PE-019, REQ-BOOT-065, 066 |
| L10 | Open the firmware boot menu; then force a network boot | Windows Boot Manager is first and stays first after restarts; the forced network boot gets no relay reply (`boot.device.stopped`); after `usgp-cli boot-stop clear`, a network boot works again | Boot menu captures; `BootOrder` before and after; relay `boot.device.stopped` and `boot_policy.applied` lines; `boot_stop.cleared` record | REQ-BOOT-061, 067 |
| L11 | Negative: (a) corrupt one object in the server's content store; (b) put a wrong `plan.pub` in a copy of the kit. Run a job with each | Each gives a persistent error at the device and in `job show`, and **no disk write** | Screens; `job show` failure fields; hash of the target disk's first and last 4 MiB before and after, and its allocated size | REQ-JOB-005, 008; REQ-PE-016; M3 exit 4 |
| L12 | Throughout: Secure Boot stays on | No Secure Boot variable changes | SHA-256 of the `db`, `dbx`, `KEK` and `PK` variables before L4 and after L10 | Decision 0018 item 5 |

## Not covered by MT-2

- Real hardware other than OVMF: if available, repeat L4 to L10 on one
  physical UEFI x64 device and record the firmware vendor and version.
- Drivers and unattend configuration (M4), relay caching (M5), BIOS and
  HTTP boot (M7).

## Document Change History

| Date | Change |
|------|--------|
| 2026-10-29 | First version (M3 WU-16): lab, evidence rules, L1 to L12 from M3 plan section 10.4 with pass criteria and the evidence to capture, LAB-OBS-001 to 003, and the review items only this lab can confirm. Status NOT RUN. |
