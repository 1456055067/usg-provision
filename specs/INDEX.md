# Capability index

Survey baseline, 2026-10-25. Each area reserves the REQ ID range
`REQ-<AREA>-001` to `REQ-<AREA>-099`. Capabilities are `NOT SPECCED`
unless the table says otherwise. Spec run M1 network boot (2026-10-25/26)
moved BOOT-1, BOOT-2 and BOOT-5 to `DRAFT`, then to `AUDITED` after the
clean-room audit and owner acceptance of DEC-0004 (2026-10-26). BOOT-1 and
BOOT-5 are partly `AUDITED`: their OPEN REQs stay open. Spec run M2
(content store, integrity, operator access; 2026-10-26) moved IMG-1,
IMG-2, the image-content part of OS-1 and the import part of PE-1 to
`DRAFT`, and added RBAC-2 and AUD-2 (`specs/operator-access.md`). M2 fix
round 1 (CR-501 to CR-510) applied the owner's decisions DEC-0006,
DEC-0007, DEC-0009, DEC-0010 and DEC-0011. After the re-audit (round 1,
approved, 2026-10-26) these rows are `AUDITED`, partly where OPEN REQs
remain; OPEN REQs stay open. The M2 standards summaries (topics 9, 11,
17, 20 and 21) are audited. On 2026-10-27 the owner's decisions
DEC-0013, DEC-0014 and DEC-0015 settled the M2 parts of several OPEN
REQs (project design, not described product behaviour). After the
decisions 0012-0015 check (2026-10-27) their M2 parts, and the new
REQ-AUD-006 and 007, are `AUDITED`; their post-M2 questions stay OPEN.
REQ-OS-011 (CR-516) passed its diff check and is `AUDITED` (2026-10-27,
text unchanged). DEC-0012 (database login) is recorded but no spec
relies on it. M2 fix round 1 (drift, 2026-10-27) added the project's own
DISM observations (OBS-001 to OBS-017, run R1) to the topic 9 and 20
summaries as [observed] notes, kept apart from Microsoft text; those
notes were audited in re-verify round 1 (2026-10-27). M2 fix round 2
(2026-10-27) cites DEC-0017 (accepted 2026-10-27) for
the two WIM header rules and adds the [MS-XCA] refill rule to topic 20.
After DISM sample run R2 (2026-10-27), OBS-018 to OBS-023 were added
to the topic 9 summary as [observed] notes (audited 2026-10-27).
Spec run M3 (2026-10-27) moved TGT-1, DISK-1 and JOB-1 to `DRAFT`
(`specs/targeting.md`, `specs/disk.md`, `specs/progress.md`), added the
boot-and-apply part of PE-1 (REQ-PE-011 to 020) and the M3 part of
BOOT-5 (REQ-BOOT-063 to 067), summarised topics 8 and 22, and extended
topics 5 and 11. All M3 additions are `DRAFT` pending the clean-room
audit; earlier audited text is unchanged. M3 fix round 1 (2026-10-28)
applied the audit findings CR-001 to CR-007 and the owner's decision
DEC-0018 (device-session authorisation, TFTP wrap-around and large
blocks, operator-built boot configuration, the product's own image
apply), all labelled as project rules. After re-audit round 1 (approve
with comments; CR-008 to CR-011 applied), the M3 REQs that are not OPEN
and the M3 standards text (topics 8 and 22, topic 11 §5.1 to §5.3, §8,
§9, topic 5 §9) are `AUDITED` (2026-10-28). Still OPEN: REQ-TGT-006,
007, 010, 011, 016; REQ-DISK-002, 005, 006, 016; REQ-JOB-010;
REQ-BOOT-067. The remaining owner decisions, D-M3-4 to D-M3-8, are
listed in the M3 spec report.

Priority is for a **Windows client (10/11 Enterprise) first** release.
For M2, DEC-0009 narrows image content to Windows 11 Enterprise x64
(`specs/os-support.md`).

- **P1**: needed to provision one Windows client over the network end to end.
- **P2**: needed for production fleet use.
- **P3**: later, or other operating systems.

Sources are IDs in the provenance log (dirty side only). `DEC-nnnn` IDs
are project decisions, not product behaviour.

## End-to-end outcomes (survey answer)

The product delivers three outcomes: (a) a bare-metal or blank device is
network- or media-booted, has an OS image laid down with drivers and
configuration, and finishes as a managed endpoint running the management
agent (optionally domain-joined, with apps and patches applied); (b) an
already-managed endpoint is re-imaged ("refreshed") on demand, locally or over
the internet; (c) bootable USB/ISO media can be produced for devices that
cannot network-boot. It also covers secure wipe and retirement of devices.
(SRC-001, SRC-002, SRC-003, SRC-004, SRC-005)

## Capabilities

### BOOT — Network boot

REQ IDs in use: `REQ-BOOT-001` to `REQ-BOOT-070`, grouped by topic in
tens with gaps. BOOT-3, BOOT-4 and BOOT-6 have no REQs yet. In the REQ
column, "OPEN" lists requirements whose behaviour still needs a source or
a decision.

| ID | Capability (behavioural) | Spec file | Priority | Status | REQ IDs | Sources |
|----|--------------------------|-----------|----------|--------|---------|---------|
| BOOT-1 | A device on the local network can boot over the network (PXE) and be served the provisioning environment by a boot service on that segment, including when the boot service answers across subnets. The boot service never assigns addresses and works beside the site's DHCP server (project decision, M1). | `specs/boot-network.md` | P1 | AUDITED (partial; OPEN: 013, 014, 054). 035 AUDITED 2026-10-28 (was OPEN; settled by DEC-0018 item 2, project rule) | REQ-BOOT-001, 002, 004 to 007, 010 to 014, 020 to 023, 030 to 035, 040 to 045, 052 to 054, 070 (OPEN: 013, 014, 054) | SRC-003, SRC-004, SRC-005, SRC-006, SRC-007, SRC-009, DEC-0003, DEC-0018 |
| BOOT-2 | Network boot works on UEFI firmware (M1 scope by project decision: x86-64, IPv4). | `specs/boot-network.md` | P1 | AUDITED | REQ-BOOT-003, 005 | SRC-004 (indirect), DEC-0004 |
| BOOT-3 | Network boot also works on legacy BIOS firmware, including first-generation virtual machines, with working video output. | `specs/boot-network.md` | P2 | NOT SPECCED | none | SRC-004, SRC-006, SRC-007 |
| BOOT-4 | UEFI devices can use HTTP boot instead of TFTP-based PXE, for faster transfer. *Single source (SRC-009, dated 2022); the public release notes do not mention it. Any requirement derived from this row is capped at SHOULD, or marked `OPEN`, until a second public source confirms it.* | `specs/boot-network.md` | P2 | NOT SPECCED | none | SRC-009 |
| BOOT-5 | After a network-booted install, the device's next boot goes to the installed disk rather than looping back into network boot. For M1, an operator can tell the boot service not to offer a boot program to a device, so that the device falls through to its next boot option (project decision, M1). M3: the boot service serves the Windows PE boot files, and the install leaves the installed Windows first in the firmware boot order. | `specs/boot-network.md` | P1 | AUDITED (partial; AUDITED: 050, 051, 060; OPEN: 061, 062). M3: AUDITED 2026-10-28, 063 to 066 (064 by DEC-0018 item 2, project rule); OPEN 067 | REQ-BOOT-050, 051, 060 to 067 (OPEN: 061, 062, 067) | SRC-004, SRC-021, SRC-088, SRC-089, SRC-091 to SRC-094, DEC-0004, DEC-0018 |
| BOOT-6 | ARM-architecture devices can be provisioned. | `specs/boot-network.md` | P3 | NOT SPECCED | none | SRC-004, SRC-007 |

### MEDIA — Boot media

| ID | Capability (behavioural) | Spec file | Priority | Status | Sources |
|----|--------------------------|-----------|----------|--------|---------|
| MEDIA-1 | An operator can produce bootable USB media and an ISO image that start the provisioning environment on a device that cannot network-boot. | `specs/boot-media.md` | P2 | NOT SPECCED | SRC-001, SRC-003, SRC-004, SRC-005 |
| MEDIA-2 | Media-booted devices connected only to the internet (wired or Wi-Fi, with network credentials entered at boot) fetch all content from the central server. | `specs/boot-media.md` | P2 | NOT SPECCED | SRC-003, SRC-009 |
| MEDIA-3 | Media can optionally carry the full deployment content for isolated devices, and that content can be encrypted on the media. | `specs/boot-media.md` | P2 | NOT SPECCED | SRC-004, SRC-005, SRC-007 |
| MEDIA-4 | Media can be created without a local boot service, and large (over 32 GB) USB drives are supported. | `specs/boot-media.md` | P3 | NOT SPECCED | SRC-004 |

### PE — Preinstallation environment

| ID | Capability (behavioural) | Spec file | Priority | Status | Sources |
|----|--------------------------|-----------|----------|--------|---------|
| PE-1 | Windows installs run from a Windows PE environment that the operator prepares from Microsoft's deployment kit (the product does not ship Microsoft components). M3: the device network boots that environment, which connects back over a protected channel, downloads and verifies content, and applies the image. | `specs/preinstall-env.md` | P1 | AUDITED (partial; import part, M2: REQ-PE-001 to 010; 005 AUDITED for M2 (DEC-0013; post-M2 OPEN-IMG-F1); OPEN: 010). M3 boot-and-apply part: AUDITED 2026-10-28, REQ-PE-011 to 020 (012 and 017 carry DEC-0018 items 3 and 4 as project rules) | SRC-001, SRC-004, SRC-005, SRC-008, SRC-009, SRC-047, SRC-048, SRC-057, SRC-058, SRC-060, SRC-061, SRC-062, SRC-063, SRC-088, SRC-091, SRC-092, SRC-095 to SRC-097, DEC-0004, DEC-0009, DEC-0011, DEC-0013, DEC-0015, DEC-0018 |
| PE-2 | The environment is usable at the device: network/Wi-Fi selection, on-screen keyboard, a command shell on error, and optional company branding. | `specs/preinstall-env.md` | P2 | NOT SPECCED | SRC-004, SRC-005, SRC-006 |
| PE-3 | Access to the environment's shell and administrative functions is protected by operator-set passwords. | `specs/preinstall-env.md` | P2 | NOT SPECCED | SRC-004 |
| PE-4 | A Linux-based environment is used for Linux installs and Linux image capture. | `specs/preinstall-env.md` | P3 | NOT SPECCED | SRC-004, SRC-006 |

### IMG — OS images and deployment packages

| ID | Capability (behavioural) | Spec file | Priority | Status | Sources |
|----|--------------------------|-----------|----------|--------|---------|
| IMG-1 | An operator defines a deployment package that combines an OS image with its configuration, and can create, clone, view, edit, and delete packages. | `specs/os-images.md` | P1 | AUDITED (partial; REQ-IMG-001 to 006, 010 to 018, 020 to 022, 052, 054; 015 AUDITED for items 1 and 2 (M2 rule, DEC-0015; post-M2 OPEN-IMG-D1); OPEN: 002, 016, 018) | SRC-001, SRC-004, SRC-005, SRC-007, DEC-0010, DEC-0011, DEC-0015 |
| IMG-2 | Windows images in WIM format can be uploaded (including multi-gigabyte files and images containing many editions, where one edition is selected). | `specs/os-images.md` | P1 | AUDITED (partial; REQ-IMG-030 to 044, 050, 051, 053; 038 AUDITED (M2 compression scope, DEC-0014; post-M2 OPEN-IMG-C1); 043 AUDITED for M2 items 1 to 4 (DEC-0013; item 5 and post-M2 OPEN-IMG-F1); OPEN: 034, 036, 039, 044) | SRC-001, SRC-004, SRC-005, SRC-047, SRC-048, SRC-049, SRC-050, SRC-051, SRC-056, DEC-0006, DEC-0007, DEC-0010, DEC-0011, DEC-0013, DEC-0014 |
| IMG-3 | Microsoft OS media can be downloaded directly into the product instead of uploaded. | `specs/os-images.md` | P2 | NOT SPECCED | SRC-004 |
| IMG-4 | A reference device's OS can be captured as a new custom image. | `specs/os-images.md` | P2 | NOT SPECCED | SRC-004, SRC-007 |
| IMG-5 | Images exported from another imaging system in WIM format can be reused. | `specs/os-images.md` | P3 | NOT SPECCED | SRC-004 |
| IMG-6 | Packages can be updated in bulk by script. | `specs/os-images.md` | P3 | NOT SPECCED | SRC-004 |

### DRV — Drivers

| ID | Capability (behavioural) | Spec file | Priority | Status | Sources |
|----|--------------------------|-----------|----------|--------|---------|
| DRV-1 | Driver packages (ZIP or CAB archives) can be attached to a deployment and are applied during both bare-metal installs and refreshes. | `specs/drivers.md` | P1 | NOT SPECCED | SRC-003, SRC-004 |
| DRV-2 | Storage controller (e.g. RAID) drivers can be loaded in the preinstallation environment so that disks become visible. | `specs/drivers.md` | P2 | NOT SPECCED | SRC-004, SRC-006 |
| DRV-3 | Settings can vary by device chassis type. | `specs/drivers.md` | P3 | NOT SPECCED | SRC-007 |

### DISK — Target disk handling

| ID | Capability (behavioural) | Spec file | Priority | Status | Sources |
|----|--------------------------|-----------|----------|--------|---------|
| DISK-1 | The installer selects the target disk at boot; existing partitions are wiped and the disk is partitioned for the OS. | `specs/disk.md` | P1 | AUDITED (partial, M3, 2026-10-28; REQ-DISK-001 to 016; OPEN: 002, 005, 006, 016) | SRC-001, SRC-002, SRC-004, SRC-006, SRC-057, SRC-080, SRC-084 to SRC-087, SRC-096, SRC-099, DEC-0004, DEC-0009 |
| DISK-2 | eMMC storage is supported as a target. | `specs/disk.md` | P3 | NOT SPECCED | SRC-006 |

### CFG — Configuration and answer files

| ID | Capability (behavioural) | Spec file | Priority | Status | Sources |
|----|--------------------------|-----------|----------|--------|---------|
| CFG-1 | A deployment carries a Windows unattended-setup answer file, into which per-device values (such as computer name) are substituted at install time. | `specs/configuration.md` | P1 | NOT SPECCED | SRC-001, SRC-004 |
| CFG-2 | A deployment sets computer name, domain/OU, time zone, local administrator password, and descriptive tags. | `specs/configuration.md` | P1 | NOT SPECCED | SRC-001, SRC-004 |
| CFG-3 | Computer names come from operator-defined templates (including substrings such as the last N characters of a device value) or are entered at the device within operator-set restrictions. | `specs/configuration.md` | P2 | NOT SPECCED | SRC-004, SRC-006, SRC-007 |
| CFG-4 | Operators can define extra key/value prompts answered at the device during install. | `specs/configuration.md` | P2 | NOT SPECCED | SRC-006, SRC-007 |

### DOM — Directory join

| ID | Capability (behavioural) | Spec file | Priority | Status | Sources |
|----|--------------------------|-----------|----------|--------|---------|
| DOM-1 | Devices can be joined to Active Directory during install by offline domain join, so the Windows answer file does not have to contain domain-join credentials. | `specs/domain-join.md` | P2 | NOT SPECCED | SRC-001, SRC-003, SRC-004, SRC-005 |
| DOM-2 | Devices can alternatively join online during install. | `specs/domain-join.md` | P2 | NOT SPECCED | SRC-001 |
| DOM-3 | After a re-image, the device keeps the directory computer account it already had; an operator does not have to remove that account before the device joins again. | `specs/domain-join.md` | P2 | NOT SPECCED | SRC-004, SRC-010 |
| DOM-4 | Devices can join a cloud directory (Microsoft Entra ID) instead. | `specs/domain-join.md` | P3 | NOT SPECCED | SRC-004 |

### SEQ — Install workflow and custom steps

| ID | Capability (behavioural) | Spec file | Priority | Status | Sources |
|----|--------------------------|-----------|----------|--------|---------|
| SEQ-1 | The install proceeds as an ordered, automated workflow from boot to first OS logon-ready state, with generous step timeouts. | `specs/workflow.md` | P1 | NOT SPECCED | SRC-001, SRC-004, SRC-006 |
| SEQ-2 | Operators can add custom scripts (including PowerShell) that run in the preinstallation environment or the installed OS, with their output logged. | `specs/workflow.md` | P2 | NOT SPECCED | SRC-001, SRC-004, SRC-006, SRC-007 |
| SEQ-3 | Operators can insert optional reboots and calls to external web services into the workflow. | `specs/workflow.md` | P2 | NOT SPECCED | SRC-004, SRC-007 |
| SEQ-4 | Provisioning can require a confirmation code entered at the device before it proceeds. | `specs/workflow.md` | P2 | NOT SPECCED | SRC-004, SRC-006 |

### AGT — Post-install management handoff

| ID | Capability (behavioural) | Spec file | Priority | Status | Sources |
|----|--------------------------|-----------|----------|--------|---------|
| AGT-1 | The management agent is installed as part of the build, so the device finishes as a managed endpoint. | `specs/agent-handoff.md` | P1 | NOT SPECCED | SRC-001, SRC-002 |
| AGT-2 | Patches, applications, and policies are applied as part of, or immediately after, the build. | `specs/agent-handoff.md` | P2 | NOT SPECCED | SRC-001, SRC-002, SRC-010 |

### TGT — Target identification and selection

| ID | Capability (behavioural) | Spec file | Priority | Status | Sources |
|----|--------------------------|-----------|----------|--------|---------|
| TGT-1 | For bare metal, operators make deployment packages available on a boot service; the person at the device picks the package and target disk at boot. | `specs/targeting.md` | P1 | AUDITED (partial, M3, 2026-10-28; REQ-TGT-001 to 016; 013, 014 are DEC-0018 project rules; OPEN: 006, 007, 010, 011, 016) | SRC-001, SRC-004, SRC-006, SRC-009, SRC-057, SRC-087, DEC-0009, DEC-0011, DEC-0018 |
| TGT-2 | For refreshes, operators target existing managed endpoints individually by name or as an operator-defined set of devices, and can schedule ongoing refreshes. | `specs/targeting.md` | P2 | NOT SPECCED | SRC-004, SRC-007 |
| TGT-3 | Device identity reported during provisioning includes the hardware serial number (including on virtual machines). | `specs/targeting.md` | P2 | NOT SPECCED | SRC-004 |
| TGT-4 | An administrator can restrict which endpoints may be targeted, and refresh targeting honours the operator's rights. | `specs/targeting.md` | P2 | NOT SPECCED | SRC-004 |

### RFR — OS refresh (re-image of a managed endpoint)

| ID | Capability (behavioural) | Spec file | Priority | Status | Sources |
|----|--------------------------|-----------|----------|--------|---------|
| RFR-1 | An operator can re-image a running managed endpoint over the network with no technician or media present; content may be pulled through the existing agent. | `specs/os-refresh.md` | P2 | NOT SPECCED | SRC-002, SRC-004, SRC-005 |
| RFR-2 | A refresh can preserve user state across the re-image. | `specs/os-refresh.md` | P3 | NOT SPECCED | SRC-005 |
| RFR-3 | A refresh can switch a device between operating systems (e.g. Windows to Linux) even with limited free disk. | `specs/os-refresh.md` | P3 | NOT SPECCED | SRC-006 |

### RELAY — Local boot and cache service

| ID | Capability (behavioural) | Spec file | Priority | Status | Sources |
|----|--------------------------|-----------|----------|--------|---------|
| RELAY-1 | A device that network-boots is answered by a boot service hosted on an ordinary endpoint that is already under management in the same segment and that an operator has assigned to that role. This lessens, but does not remove, the need for purpose-built boot servers. Which host operating systems may hold the role is `OPEN`. | `specs/relay.md` | P1 | NOT SPECCED | SRC-002, SRC-003, SRC-009 |
| RELAY-2 | When a booting device needs image or driver content, it gets that content from its segment's boot service if a local copy is held there, and otherwise from the central server. | `specs/relay.md` | P1 | NOT SPECCED | SRC-003, SRC-004 |
| RELAY-3 | Cache contents are managed automatically, can be pre-staged, survive service removal, and the service reports disk space, cached content, and health. | `specs/relay.md` | P2 | NOT SPECCED | SRC-003, SRC-004, SRC-006, SRC-007 |
| RELAY-4 | The same local service can broker offline domain join for devices it boots. | `specs/relay.md` | P2 | NOT SPECCED | SRC-003, SRC-004, SRC-007 |

### JOB — Progress, status, and logs

| ID | Capability (behavioural) | Spec file | Priority | Status | Sources |
|----|--------------------------|-----------|----------|--------|---------|
| JOB-1 | Operators can see per-device deployment progress, including download progress, and a clear persistent error when a step or download fails. | `specs/progress.md` | P1 | AUDITED (partial, M3, 2026-10-28; REQ-JOB-001 to 015; OPEN: 010) | SRC-002, SRC-004, SRC-006, SRC-009, DEC-0011 |
| JOB-2 | An overview shows fleet metrics, recent deployments, and boot-service health. | `specs/progress.md` | P2 | NOT SPECCED | SRC-004 |
| JOB-3 | Provisioning logs are kept on the device and can be collected centrally. | `specs/progress.md` | P2 | NOT SPECCED | SRC-004 |
| JOB-4 | Provisioning events can be forwarded to external systems. | `specs/progress.md` | P2 | NOT SPECCED | SRC-004 |

### RBAC — Roles and permissions

| ID | Capability (behavioural) | Spec file | Priority | Status | Sources |
|----|--------------------------|-----------|----------|--------|---------|
| RBAC-1 | Operator capabilities are gated by roles, including separate administrator and read-only roles for device retirement and an administrator right to create boot services. | `specs/rbac.md` | P2 | NOT SPECCED (REQ-RBAC-020 onward reserved) | SRC-004, SRC-006 |
| RBAC-2 | Managing images, preinstall environments and packages needs role permissions; operators are individually authenticated (M2). | `specs/operator-access.md` | P1 | AUDITED (partial; REQ-RBAC-001 to 006; OPEN: 002; OPEN-ACC-2 open except who reads audit records in M2, settled by DEC-0015 in REQ-AUD-007) | SRC-004, SRC-006, DEC-0007, DEC-0010, DEC-0011, DEC-0015 |

### AUD — Audit

| ID | Capability (behavioural) | Spec file | Priority | Status | Sources |
|----|--------------------------|-----------|----------|--------|---------|
| AUD-1 | Retirement actions are logged with operator notes and the log can be exported. | `specs/audit.md` | P2 | NOT SPECCED (REQ-AUD-020 onward reserved) | SRC-004 |
| AUD-2 | Content-management actions, refusals and content state changes are recorded for audit in a tamper-evident way, without secrets (M2; project requirement, not described product behaviour). | `specs/operator-access.md` | P1 | AUDITED (partial; REQ-AUD-001 to 007; 006 (fail closed, DEC-0015) and 007 (M2 audit reading, DEC-0015) AUDITED; OPEN: 004) | SRC-004, DEC-0007, DEC-0009, DEC-0010, DEC-0011, DEC-0015 |

### RET — Wipe and retirement

| ID | Capability (behavioural) | Spec file | Priority | Status | Sources |
|----|--------------------------|-----------|----------|--------|---------|
| RET-1 | A drive can be securely wiped with a configurable number of overwrite passes (1 to 25), ending in shutdown or a summary screen. | `specs/retirement.md` | P2 | NOT SPECCED | SRC-001, SRC-004 |
| RET-2 | Lost, stolen, or decommissioned managed devices can be retired remotely (data wiped). | `specs/retirement.md` | P3 | NOT SPECCED | SRC-001, SRC-004, SRC-008 |

### OS — Supported target operating systems

| ID | Capability (behavioural) | Spec file | Priority | Status | Sources |
|----|--------------------------|-----------|----------|--------|---------|
| OS-1 | Windows 10 and Windows 11 can be installed on bare metal and refreshed. | `specs/os-support.md` | P1 | AUDITED (partial; image-content part, M2: REQ-OS-001 to 011; M2 scope Windows 11 Enterprise x64 by DEC-0009; 004, 005 AUDITED for M2 (DEC-0013 item 3; post-M2 OPEN-OS-2, OPEN-IMG-F1); 011 AUDITED (unknown facts in M2, DEC-0013, CR-516); OPEN: 003, 006, 010 in part. Install and refresh not specced) | SRC-004, SRC-005, SRC-058, SRC-064, SRC-065, SRC-066, SRC-067, DEC-0009, DEC-0013 |
| OS-2 | Linux distributions (Red Hat Enterprise Linux, CentOS, Debian, Ubuntu, Rocky Linux, AlmaLinux) can be installed and refreshed. | `specs/os-support.md` | P3 | NOT SPECCED | SRC-005, SRC-006 |
| OS-3 | Cloud-hosted virtual machines (Microsoft Azure) are supported. | `specs/os-support.md` | P3 | NOT SPECCED | SRC-004 |

## Observed limits (to be specced per area)

Public release notes indicate support for packages with more than 100 files,
image uploads over 10 GB, long-running install steps (hours), and length
limits on the name and description of another operator-defined object.
Exact values beyond these are `OPEN`. (SRC-004, SRC-006)
The M2 specs carry these as REQ-IMG-003, REQ-IMG-031, REQ-IMG-042 and
OPEN-IMG-L1 in `specs/os-images.md`; whether packages have such limits
is OPEN in REQ-IMG-002.

## Unconfirmed

No public source found yet. Not to be implemented from these notes; each
needs a cited source or a product decision.

- Secure Boot behaviour (signed boot chain on UEFI devices).
- IPv6 network boot.
- Pre-registering bare-metal devices by MAC address or SMBIOS UUID so they
  receive a specific deployment without a choice at the device.
- Zero-touch bare-metal installs with no input at the device. (M3: a
  public source says an operator-configurable mode needing no input at
  the device exists but does not define it; see `specs/targeting.md`
  REQ-TGT-007.)
- Multicast image delivery.
- What network configuration the boot service requires beyond what
  `specs/boot-network.md` states. DHCP coexistence itself is now settled
  by project decision (M1, DEC-0003): the boot service never assigns
  addresses and works beside the site DHCP server (REQ-BOOT-010 to
  REQ-BOOT-012). There is still no vendor source for it.
- BitLocker or other encryption of the installed OS disk; TPM handling.
- Windows Server as a target OS.
- A general operator API (only a retirement-specific API is mentioned).
- A general audit trail of operator actions beyond retirement.
- Approval workflows before a deployment or wipe runs.
- Details of user-state migration during refresh (one mention only).
- Whether any domain-join material is held on the device during or after
  install, beyond what the open offline-join mechanism itself places there
  (standards topic 13). DOM-1 claims only that the answer file is free of
  join credentials.
- Which host operating systems may serve as a local boot service (RELAY-1).

## Open-standards topics needed in `specs/standards/`

To be summarised later with section citations.

This is a **reading list, not a design decision**. Listing a standard, or a
part of one, does not mean the product uses it or that usg-provision must.
Each item names the capability IDs that motivate it. Items or parts marked
**(conditional)** relate only to behaviour in the Unconfirmed list or to
choices nobody has made yet. Summarise them for reference only; do not build
them until a sourced capability or a recorded product decision calls for
them. Which optional parts of a standard to use is for the clean side to
decide.

1. PXE boot flow and DHCP options for PXE/UEFI clients (Intel PXE 2.1;
   RFC 2131, RFC 2132, RFC 4578 client architecture types). For BOOT-1,
   BOOT-2, BOOT-3. *(conditional)* RFC 5970 IPv6 boot options, only if
   IPv6 boot (Unconfirmed) is confirmed or decided. **Summarised:
   `specs/standards/pxe-dhcp.md`** (IPv4; RFC 5970 noted in §11; the PXE
   2.1 primary text was not retrievable, so the Intel PXE Internet-Draft
   and UEFI Appendix E are used; §5.5, the RFC 4578 presence rule for
   options 93, 94 and 97, added 2026-10-26; §3.1 server reply fields
   (RFC 2131 Table 3), §3.2 RFC 1542 minimum message size, and §6.1 tag 71
   layout (from the PXE draft and UEFI, PXE 2.1 not read) added
   2026-10-26; OPEN-T71-1, tag 71 byte order, and OPEN-T71-2, what a boot
   server puts in its tag 71 reply, both need the PXE 2.1 text).
2. Proxy DHCP behaviour and PXE boot-server discovery (PXE 2.1). No longer
   conditional: by project decision (M1) the boot service never assigns
   addresses. For BOOT-1. **Summarised: `specs/standards/proxy-dhcp.md`**
   (partly from secondary sources, marked in the file).
3. TFTP (RFC 1350) for BOOT-1, BOOT-2, BOOT-3. Option extensions (RFC 2347,
   RFC 2348, RFC 2349) are background reading; whether any are used is a
   clean-side decision. *(conditional)* RFC 7440 windowsize; no source
   covers transfer tuning. **Summarised: `specs/standards/tftp.md`**
   (includes RFC 1123 §4.2; §10 windowsize end-of-transfer rule corrected
   2026-10-26).
4. UEFI HTTP boot (UEFI specification, HTTP Boot chapter; vendor-class
   identifier semantics). For BOOT-4 (single source).
5. UEFI boot manager variables and boot-order changes after install (UEFI
   specification, Boot Manager chapter). For BOOT-5. **Summarised:
   `specs/standards/uefi-boot-manager.md`** (UEFI 2.10; M3 added §9,
   creating the installed Windows boot entry from Windows PE with
   Microsoft's BCDBoot and its boot-order effect; OPEN-UBM-1; AUDITED
   2026-10-28).
6. *(conditional)* UEFI Secure Boot and the signed boot chain (UEFI
   specification, Secure Boot chapter; Microsoft public guidance on signing
   requirements). Relates to Secure Boot (Unconfirmed). **Summarised as
   background only: `specs/standards/uefi-secure-boot.md`** (no signing
   design).
7. Legacy BIOS boot and MBR partitioning. For BOOT-3, DISK-1.
8. GPT partitioning and the Windows recommended UEFI partition layout
   (UEFI specification GPT chapter; Microsoft Learn partition guidance).
   For BOOT-2, DISK-1. **Summarised: `specs/standards/gpt.md`** (M3,
   AUDITED 2026-10-28; UEFI 2.10 chapter 5 with §1.9.1, §4.2.1, §13.3; Microsoft's
   layout, types, attributes and sizes; NTFS/FAT32 at summary level only;
   OPEN-GPT-1 CRC parameters, OPEN-GPT-2 MSR/ESP size conflict between
   Microsoft pages).
9. WIM image format and edition indexes (Microsoft Learn WIM/DISM docs and
   the published WIM format documentation). For IMG-2, IMG-4, IMG-5.
   **Summarised: `specs/standards/wim.md`** (M2, audited; from
   Microsoft's public WIM paper and Learn pages; byte order and several
   layout points are [reading] or OPEN-WIM-1 to OPEN-WIM-11; M2 fix
   round 1 added [observed] notes from the project's own DISM samples,
   OBS-001 to OBS-017, which settle OPEN-WIM-1 and parts of others for
   run R1, and two header rules marked [project rule] that cite DEC-0017
   (accepted 2026-10-27); these notes were audited
   2026-10-27. After run R2, OBS-018 to OBS-023 added [observed] notes
   on files changed after capture: shared metadata for identical
   images, unreliable reference counts, unnamed stale ranges (which
   contradict the earlier "no gap" note), and lookup order giving the
   image index when offset order differs; OPEN-WIM-6 is narrowed and
   samples S12C, S12D, S11C and S11D are still needed; these R2 notes
   were audited 2026-10-27). Codecs are topic 20.
10. Windows unattended setup answer files and configuration passes
    (Microsoft Learn unattend reference). For CFG-1, CFG-2, CFG-3, CFG-4.
11. Windows PE: building from the Windows ADK, adding drivers, startup
    scripts, and its licensing/redistribution constraints (Microsoft Learn).
    For PE-1, PE-2, PE-3, DRV-2. **Summarised: `specs/standards/winpe.md`**
    (M2, audited; the ADK licence terms are click-through and were not
    read; one secondary Q&A source on redistribution; OPEN-PE-LIC for
    counsel; M3 added §5.1 automatic start, §5.2 networking, §5.3 boot
    information and §9 RAM disk, AUDITED 2026-10-28, with OPEN-WINPE-1; network boot
    of WinPE is topic 22).
12. Offline driver injection (DISM driver servicing; INF/CAB packaging).
    For DRV-1, DRV-2.
13. Offline domain join provisioning (Microsoft Learn `djoin` documentation).
    For DOM-1, DOM-3, RELAY-4. The summary must state what provisioning
    data the open mechanism places on the device.
14. SMBIOS system identifiers: serial number and chassis type (DMTF SMBIOS
    specification). For TGT-3, DRV-3. *(conditional)* System UUID, only for
    pre-registration (Unconfirmed).
15. Secure disk sanitisation (NIST SP 800-88). For RET-1, RET-2.
16. Bootable ISO and USB layout (ISO 9660 / El Torito; FAT32 for UEFI
    removable media per UEFI specification). For MEDIA-1, MEDIA-4.
17. HTTP semantics and TLS for content download (RFC 9110, RFC 8446). For
    MEDIA-2, RFR-1, RELAY-2, BOOT-4. *(conditional)* HTTP range requests
    (RFC 9110 §14); no source covers resumable downloads. Also for IMG-2
    uploads and operator sessions (M2). **Summarised:
    `specs/standards/http-tls.md`** (M2, audited; RFC 9110; RFC 8446,
    noting that RFC 9846 now obsoletes it; NIST SP 800-52 Rev. 2 from its
    publication page only, [primary not read], OPEN-TLS-1).
18. Long and repeated DHCPv4 options (RFC 3396, with RFC 2131 §4.1 and
    RFC 2132 §9.3 option overload) and what they mean for the PXE options
    in topic 1. For BOOT-1. **Summarised:
    `specs/standards/dhcp-long-options.md`** (OPEN-LONG-1).
19. GUID/UUID text form and byte order: UEFI Appendix A against RFC 9562 /
    RFC 4122, the RFC 4578 option 97 identifier, and the SMBIOS type 1
    system UUID. For BOOT-1 and TGT-3. The SMBIOS part relates to
    pre-registration (Unconfirmed) and to topic 14. **Summarised:
    `specs/standards/uefi-guid-text.md`** (the SMBIOS byte order rests on
    a search summary because the DMTF PDF could not be read, again in fix
    round 1; no REQ may cite those points until confirmed; the byte order
    of pre-2.6 tables is not confirmed; OPEN-GUID-1 to OPEN-GUID-5).
20. WIM compression codecs: XPRESS with Huffman ([MS-XCA]), LZX (the
    archived Microsoft Cabinet LZX format, with [MS-PATCH] LZXD as
    background), LZMS (no public format found). For IMG-2, PE-1.
    **Summarised: `specs/standards/wim-compression.md`** (M2, audited;
    how WIM applies each codec is not stated by Microsoft: OPEN-WIMC-1 to
    OPEN-WIMC-4; OPEN-WIMC-1 confirmed for run R1 by [observed] notes,
    OBS-012 and OBS-013, added in M2 fix round 1 and audited
    2026-10-27; §3.3 refill rule added in M2 fix round 2).
21. Security baseline: FIPS 186-5 signatures, RFC 5280 certificates, NIST
    SP 800-57 Part 1 key management, and operator authentication (FIPS
    201-3, SP 800-73-5, SP 800-63B). For IMG-2 integrity, RBAC-2.
    **Summarised: `specs/standards/security-baseline.md`** (M2, audited;
    NIST PDFs could not be read; FIPS 186-5, SP 800-57, FIPS 201-3 and
    SP 800-73-5 rest on NIST's publication pages only, [primary not
    read]; SP 800-63B read from NIST's HTML edition; OPEN-SB-1 to
    OPEN-SB-3).
22. Windows PE network boot and its boot configuration (Microsoft Learn:
    PXE server for WinPE; archived Windows Deployment Services pages;
    BCD settings). For PE-1, BOOT-1, BOOT-5. **Summarised:
    `specs/standards/winpe-network-boot.md`** (M3, AUDITED 2026-10-28; the BCD file
    format is not public and is not described; OPEN-WPXE-1 and 2 open;
    OPEN-WPXE-3 and 4 (who builds the BCD, TFTP size limit) settled for
    the project by DEC-0018, labelled [project rule]; walkthrough example
    values labelled in fix round 1).
