# Capability index

Survey baseline, 2026-10-25. All capabilities are `NOT SPECCED`; each area
reserves the REQ ID range `REQ-<AREA>-001` to `REQ-<AREA>-099`.

Priority is for a **Windows client (10/11 Enterprise) first** release:

- **P1**: needed to provision one Windows client over the network end to end.
- **P2**: needed for production fleet use.
- **P3**: later, or other operating systems.

Sources are IDs in the provenance log (dirty side only).

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

| ID | Capability (behavioural) | Spec file | Priority | Status | Sources |
|----|--------------------------|-----------|----------|--------|---------|
| BOOT-1 | A device on the local network can boot over the network (PXE) and be served the provisioning environment by a boot service on that segment, including when the boot service answers across subnets. | `specs/boot-network.md` | P1 | NOT SPECCED | SRC-003, SRC-004, SRC-005, SRC-006 |
| BOOT-2 | Network boot works on UEFI firmware. | `specs/boot-network.md` | P1 | NOT SPECCED | SRC-004, SRC-009 |
| BOOT-3 | Network boot also works on legacy BIOS firmware, including first-generation virtual machines, with working video output. | `specs/boot-network.md` | P2 | NOT SPECCED | SRC-004, SRC-006, SRC-007 |
| BOOT-4 | UEFI devices can use HTTP boot instead of TFTP-based PXE, for faster transfer. *Single source (SRC-009, dated 2022); the public release notes do not mention it. Any requirement derived from this row is capped at SHOULD, or marked `OPEN`, until a second public source confirms it.* | `specs/boot-network.md` | P2 | NOT SPECCED | SRC-009 |
| BOOT-5 | After a network-booted install, the device's next boot goes to the installed disk rather than looping back into network boot. | `specs/boot-network.md` | P1 | NOT SPECCED | SRC-004 |
| BOOT-6 | ARM-architecture devices can be provisioned. | `specs/boot-network.md` | P3 | NOT SPECCED | SRC-004, SRC-007 |

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
| PE-1 | Windows installs run from a Windows PE environment that the operator prepares from Microsoft's deployment kit (the product does not ship Microsoft components). | `specs/preinstall-env.md` | P1 | NOT SPECCED | SRC-004, SRC-008 |
| PE-2 | The environment is usable at the device: network/Wi-Fi selection, on-screen keyboard, a command shell on error, and optional company branding. | `specs/preinstall-env.md` | P2 | NOT SPECCED | SRC-004, SRC-005, SRC-006 |
| PE-3 | Access to the environment's shell and administrative functions is protected by operator-set passwords. | `specs/preinstall-env.md` | P2 | NOT SPECCED | SRC-004 |
| PE-4 | A Linux-based environment is used for Linux installs and Linux image capture. | `specs/preinstall-env.md` | P3 | NOT SPECCED | SRC-004, SRC-006 |

### IMG — OS images and deployment packages

| ID | Capability (behavioural) | Spec file | Priority | Status | Sources |
|----|--------------------------|-----------|----------|--------|---------|
| IMG-1 | An operator defines a deployment package that combines an OS image with its configuration, and can create, clone, view, edit, and delete packages. | `specs/os-images.md` | P1 | NOT SPECCED | SRC-001, SRC-004 |
| IMG-2 | Windows images in WIM format can be uploaded (including multi-gigabyte files and images containing many editions, where one edition is selected). | `specs/os-images.md` | P1 | NOT SPECCED | SRC-004, SRC-006 |
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
| DISK-1 | The installer selects the target disk at boot; existing partitions are wiped and the disk is partitioned for the OS. | `specs/disk.md` | P1 | NOT SPECCED | SRC-001, SRC-004, SRC-006 |
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
| TGT-1 | For bare metal, operators make deployment packages available on a boot service; the person at the device picks the package and target disk at boot. | `specs/targeting.md` | P1 | NOT SPECCED | SRC-001, SRC-006 |
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
| JOB-1 | Operators can see per-device deployment progress, including download progress, and a clear persistent error when a step or download fails. | `specs/progress.md` | P1 | NOT SPECCED | SRC-002, SRC-004, SRC-006 |
| JOB-2 | An overview shows fleet metrics, recent deployments, and boot-service health. | `specs/progress.md` | P2 | NOT SPECCED | SRC-004 |
| JOB-3 | Provisioning logs are kept on the device and can be collected centrally. | `specs/progress.md` | P2 | NOT SPECCED | SRC-004 |
| JOB-4 | Provisioning events can be forwarded to external systems. | `specs/progress.md` | P2 | NOT SPECCED | SRC-004 |

### RBAC — Roles and permissions

| ID | Capability (behavioural) | Spec file | Priority | Status | Sources |
|----|--------------------------|-----------|----------|--------|---------|
| RBAC-1 | Operator capabilities are gated by roles, including separate administrator and read-only roles for device retirement and an administrator right to create boot services. | `specs/rbac.md` | P2 | NOT SPECCED | SRC-004, SRC-006 |

### AUD — Audit

| ID | Capability (behavioural) | Spec file | Priority | Status | Sources |
|----|--------------------------|-----------|----------|--------|---------|
| AUD-1 | Retirement actions are logged with operator notes and the log can be exported. | `specs/audit.md` | P2 | NOT SPECCED | SRC-004 |

### RET — Wipe and retirement

| ID | Capability (behavioural) | Spec file | Priority | Status | Sources |
|----|--------------------------|-----------|----------|--------|---------|
| RET-1 | A drive can be securely wiped with a configurable number of overwrite passes (1 to 25), ending in shutdown or a summary screen. | `specs/retirement.md` | P2 | NOT SPECCED | SRC-001, SRC-004 |
| RET-2 | Lost, stolen, or decommissioned managed devices can be retired remotely (data wiped). | `specs/retirement.md` | P3 | NOT SPECCED | SRC-001, SRC-004, SRC-008 |

### OS — Supported target operating systems

| ID | Capability (behavioural) | Spec file | Priority | Status | Sources |
|----|--------------------------|-----------|----------|--------|---------|
| OS-1 | Windows 10 and Windows 11 can be installed on bare metal and refreshed. | `specs/os-support.md` | P1 | NOT SPECCED | SRC-004, SRC-005 |
| OS-2 | Linux distributions (Red Hat Enterprise Linux, CentOS, Debian, Ubuntu, Rocky Linux, AlmaLinux) can be installed and refreshed. | `specs/os-support.md` | P3 | NOT SPECCED | SRC-005, SRC-006 |
| OS-3 | Cloud-hosted virtual machines (Microsoft Azure) are supported. | `specs/os-support.md` | P3 | NOT SPECCED | SRC-004 |

## Observed limits (to be specced per area)

Public release notes indicate support for packages with more than 100 files,
image uploads over 10 GB, long-running install steps (hours), and length
limits on package names and descriptions. Exact values beyond these are
`OPEN`. (SRC-004, SRC-006)

## Unconfirmed

No public source found yet. Not to be implemented from these notes; each
needs a cited source or a product decision.

- Secure Boot behaviour (signed boot chain on UEFI devices).
- IPv6 network boot.
- Pre-registering bare-metal devices by MAC address or SMBIOS UUID so they
  receive a specific deployment without a choice at the device.
- Zero-touch bare-metal installs with no input at the device.
- Multicast image delivery.
- Coexistence with an existing DHCP server (proxy DHCP behaviour) and what
  network configuration the boot service requires.
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
   IPv6 boot (Unconfirmed) is confirmed or decided.
2. *(conditional)* Proxy DHCP behaviour and PXE boot-server discovery
   (PXE 2.1). Relates to DHCP coexistence (Unconfirmed). Background for
   BOOT-1 only.
3. TFTP (RFC 1350) for BOOT-1, BOOT-2, BOOT-3. Option extensions (RFC 2347,
   RFC 2348, RFC 2349) are background reading; whether any are used is a
   clean-side decision. *(conditional)* RFC 7440 windowsize; no source
   covers transfer tuning.
4. UEFI HTTP boot (UEFI specification, HTTP Boot chapter; vendor-class
   identifier semantics). For BOOT-4 (single source).
5. UEFI boot manager variables and boot-order changes after install (UEFI
   specification, Boot Manager chapter). For BOOT-5.
6. *(conditional)* UEFI Secure Boot and the signed boot chain (UEFI
   specification, Secure Boot chapter; Microsoft public guidance on signing
   requirements). Relates to Secure Boot (Unconfirmed).
7. Legacy BIOS boot and MBR partitioning. For BOOT-3, DISK-1.
8. GPT partitioning and the Windows recommended UEFI partition layout
   (UEFI specification GPT chapter; Microsoft Learn partition guidance).
   For BOOT-2, DISK-1.
9. WIM image format and edition indexes (Microsoft Learn WIM/DISM docs and
   the published WIM format documentation). For IMG-2, IMG-4, IMG-5.
10. Windows unattended setup answer files and configuration passes
    (Microsoft Learn unattend reference). For CFG-1, CFG-2, CFG-3, CFG-4.
11. Windows PE: building from the Windows ADK, adding drivers, startup
    scripts, and its licensing/redistribution constraints (Microsoft Learn).
    For PE-1, PE-2, PE-3, DRV-2.
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
    (RFC 9110 §14); no source covers resumable downloads.
