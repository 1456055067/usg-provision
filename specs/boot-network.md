# Network boot (BOOT-1, BOOT-2, BOOT-5 for milestone M1)

Status: AUDITED (clean-room re-verify round 1; DEC-0004 accepted by the
owner on 2026-10-26). REQs marked OPEN stay open. Spec run M3
(2026-10-27) added REQ-BOOT-063 to REQ-BOOT-067. M3 fix round 1
(2026-10-28) settled REQ-BOOT-035 and 064 by DEC-0018 item 2 (project
rule). After re-audit round 1, REQ-BOOT-035 and 063 to 066 are AUDITED
(2026-10-28); 067 stays OPEN. REQ range in use: `REQ-BOOT-001` to
`REQ-BOOT-070`. Numbers are grouped by topic in tens, so some numbers are
unused.

## Purpose

A bare-metal or blank device must be able to start the provisioning
environment over the wired network without local media. The device's own
firmware starts the network boot. A boot service on the network answers it,
names a boot program, and delivers that program. After provisioning, the
device must not keep booting back into the network.

This spec covers the network-boot phase only. It ends when the device's
firmware has received the boot program and passed control to it. What the
boot program does next belongs to other areas (PE-1, RELAY-2, SEQ-1).

M3 extends this in two places: the boot service also serves the files
that Microsoft's boot manager fetches after it starts (REQ-BOOT-063,
REQ-BOOT-064), and the end of an install sets up the next boot from disk
(REQ-BOOT-065 to REQ-BOOT-067).

M1 scope: UEFI firmware on x86-64 hardware, IPv4, PXE with TFTP transfer.
The device may be on the boot service's own segment or on another subnet
whose DHCP traffic is forwarded by a relay agent.

## Actors and roles

- **Device**: the machine being provisioned. Its firmware contains a PXE
  client that follows the PXE and UEFI standards. Nothing on the device is
  under the product's control until the boot program runs.
- **Person at the device**: starts the network boot with the firmware's own
  boot-selection key (SRC-009), or relies on a network boot option in the
  firmware's boot order (UEFI 2.10 §3.1, SRC-021).
- **Boot service**: the product component that answers network-boot
  requests on a segment and serves boot files. Where it runs and how it gets
  the role belongs to RELAY-1.
- **Operator**: a person who configures the boot service through the
  product and looks at its status.
- **Site DHCP server**: the site's existing address server. The product
  does not supply, replace, or reconfigure it.
- **Relay agent**: a router or switch function that forwards DHCP traffic
  from the device's subnet to servers on other subnets.

## Definitions

- **Boot program**: the first executable file the firmware downloads and
  runs (called the network bootstrap program in the PXE material).
- **Network-boot attempt**: one run of the firmware's PXE client, from its
  first DHCP discover message until it runs a boot program or gives up.
- **Offer a boot program**: answer a device's PXE request with a reply that
  names a boot program and a server from which to fetch it.
- **Suppressed device**: a device that the operator has told the boot
  service not to offer a boot program to (REQ-BOOT-050).

Standards background for every term below: `specs/standards/pxe-dhcp.md`,
`specs/standards/proxy-dhcp.md`, `specs/standards/tftp.md`,
`specs/standards/uefi-boot-manager.md`, `specs/standards/uefi-secure-boot.md`.

## Requirements

### Devices served

### REQ-BOOT-001: Answer PXE network boot on the local segment

When a device on the same segment as a running boot service starts a PXE
network boot, the boot service answers it. The answer lets the device fetch
a boot program from the boot service and run it, so the provisioning
environment starts with no local media.

- Priority: MUST
- Source: SRC-003, SRC-004, SRC-005
- Standards: RFC 2131 §3.1; PXE flow as summarised in
  `specs/standards/pxe-dhcp.md` §7 (SRC-018 §3, SRC-020 §24.3)
- Status: AUDITED

### REQ-BOOT-002: Answer devices on other subnets through a relay agent

A device on a subnet other than the boot service's own can network boot
from that boot service, as long as the site's relay agent forwards the
device's DHCP messages to the boot service. Such a device must reach the
same result as a device on the local segment.

- Priority: MUST
- Source: SRC-004, SRC-006, SRC-007, SRC-024
- Standards: RFC 2131 §4.1; RFC 1542 §4.1.1, §4.1.2, §5.4
- Status: AUDITED

### REQ-BOOT-003: UEFI x86-64 firmware

The boot service serves devices whose PXE client identifies as UEFI on
x86-64. That identification is client architecture type 7 in the DHCP
client system architecture option. The boot program it offers to these
devices must be a UEFI application built for x86-64. Restricting M1 to
x86-64 (and to IPv4) is the project's M1 scope, not described product
behaviour.

- Priority: MUST
- Source: DEC-0004 (x86-64 and IPv4 scope); SRC-004 (indirect: network
  boot of UEFI devices)
- Standards: RFC 4578 §2.1 as corrected by erratum 4624 (SRC-014); IANA
  processor architecture registry (SRC-017)
- Status: AUDITED

### REQ-BOOT-004: Answer only PXE clients

The boot service answers only DHCP messages from devices that identify
themselves as PXE clients through the vendor class identifier. It sends no
reply of any kind to other DHCP clients (ordinary computers, phones,
printers, and so on), so their address set-up is untouched.

- Priority: MUST
- Source: SRC-018, SRC-033
- Standards: RFC 2132 §9.13; draft-henry-remote-boot-protocol-00 §3, §3.1.1
- Status: AUDITED

### REQ-BOOT-005: Do not offer a boot program to unsupported architectures

A PXE client whose architecture type the boot service has no boot program
for gets no boot program. In M1 that means any type other than UEFI
x86-64. The boot service never offers a program built for one architecture
to a device that reports another. If a device reports several
architectures, it is served only if one of them is supported.

- Priority: MUST
- Source: SRC-013; DEC-0004 (the M1 architecture set)
- Standards: RFC 4578 §2.1, §5
- Status: AUDITED

### REQ-BOOT-006: Ignore malformed and non-request traffic

The boot service ignores any DHCP or PXE message that is malformed, is not
a client request, or that it does not understand. This includes messages
that are too short, lack the DHCP magic cookie, or have inconsistent option
lengths, as well as replies sent by other servers. It never answers such
traffic with an error or with partial data, and the traffic must not
disturb its service to other devices.

- Priority: MUST
- Source: SRC-011, SRC-012
- Standards: RFC 2131 §2, §3; RFC 2132 §2
- Status: AUDITED

### REQ-BOOT-007: How a device is recognised

The boot service identifies a device by the network hardware address in its
DHCP messages. If the device also sends a client machine identifier (a
16-octet GUID), the boot service records that too. The standards note that
a hardware address alone may not single out one machine, because it can be
shared (docking stations) and one machine can have several adapters.

Operator part: wherever this spec lets an operator name a device
(REQ-BOOT-050), the operator can use either value, and the machine
identifier can be used whenever the device sends one. This requirement is
only about recognising a device that is network booting. It does not imply
that devices can or must be registered in advance (pre-registration is in
the INDEX Unconfirmed list).

- Priority: MUST
- Source: SRC-011, SRC-013 (field facts); DEC-0004 (operator part)
- Basis: project design (not described product behaviour), for the operator part
- Standards: RFC 2131 §2 (`chaddr`); RFC 4578 §1, §2.3
- Status: AUDITED

### Coexistence with the site DHCP server

### REQ-BOOT-010: Never assign addresses

The boot service never assigns, offers, renews, or withdraws IP addresses or
leases. Its replies contain no address for the device and no lease, router,
or subnet settings. The device always gets its address from the site DHCP
server.

- Priority: MUST
- Source: DEC-0003; SRC-018, SRC-033, SRC-034 (standard proxy behaviour)
- Basis: project design (not described product behaviour)
- Standards: `specs/standards/proxy-dhcp.md` §3, §4
- Status: AUDITED

### REQ-BOOT-011: Work beside an unmodified site DHCP server

The boot service works on a segment whose site DHCP server carries no
network-boot settings at all. Operators must not have to add boot-related
options to their site DHCP server. Where a site DHCP server is already set
to point PXE clients elsewhere, the operator can be told that this setting
may conflict.

- Priority: MUST
- Source: DEC-0003; SRC-024, SRC-019 (standard behaviour relied on)
- Basis: project design (not described product behaviour)
- Standards: `specs/standards/proxy-dhcp.md` §5
- Status: AUDITED

### REQ-BOOT-012: Behaviour when no site DHCP server answers

If no site DHCP server gives the device an address, the boot service still
does not give it one (REQ-BOOT-010). The device then cannot finish network
boot and moves on to its next boot option, as REQ-BOOT-051 describes.

- Priority: MUST
- Source: DEC-0003; SRC-021, SRC-020 (firmware behaviour relied on)
- Basis: project design (not described product behaviour)
- Standards: UEFI 2.10 §3.1.2; §24.3.8 (SRC-020)
- Status: AUDITED

### REQ-BOOT-013: Other boot services on the same segment

What a device does when it hears more than one boot service, including
another vendor's, is decided by the device's firmware, not by the product.

- Priority: SHOULD
- Source: SRC-020
- Standards: UEFI 2.10 §24.3.8 (offer ordering)
- Status: OPEN (Should the boot service warn the operator when it sees
  another PXE responder on its segment, and must it stay silent for devices
  another responder is already serving? No public source covers this.)

### REQ-BOOT-014: Boot service on the same host as a DHCP server

The PXE standard allows a boot responder to share a host with a DHCP server
by listening on the alternate port. Whether the product supports that
arrangement is undecided.

- Priority: MAY
- Source: SRC-024, SRC-033, SRC-036
- Standards: `specs/standards/proxy-dhcp.md` §4.2
- Status: OPEN (Is co-hosting the boot service with a DHCP server
  supported? Deciding is the product owner's job; no vendor source covers
  it.)

### Cross-subnet operation

### REQ-BOOT-020: Reply through the relay agent

When a device's request reaches the boot service through a relay agent, the
boot service sends its reply back through that relay agent, not straight to
the device. The relay agent can then deliver it on the device's own subnet.

- Priority: MUST
- Source: SRC-011, SRC-016 (reply routing); SRC-004, SRC-006, SRC-007
  (outcome only: cross-subnet boot works)
- Standards: RFC 2131 §4.1; RFC 1542 §5.4, §4.1.2
- Status: AUDITED

### REQ-BOOT-021: Preserve relay agent information

If a relayed request carries relay agent information, the boot service
returns that information unchanged in its reply. It does not use it to grant
anything. When it cannot fit the information into the reply, it sends the
reply without it.

- Priority: MUST
- Source: SRC-015
- Standards: RFC 3046 §2.2, §5
- Status: AUDITED

### REQ-BOOT-022: Name a server the device can reach

The boot-file server address that the boot service gives a device must be
one the device can reach from its own subnet. For a relayed device it must
not be an address that works only on the boot service's local segment.

- Priority: MUST
- Source: SRC-011, SRC-016, SRC-019 (server address use and routing);
  SRC-004, SRC-006, SRC-007 (outcome only: cross-subnet boot works)
- Standards: RFC 2131 §2 (`siaddr`); UEFI 2.10 Appendix E.4.20.2 (SRC-019)
- Status: AUDITED

### REQ-BOOT-023: State what the network must provide for relayed boot

The product's operator-facing information states what the network must
provide for cross-subnet boot. The relay agent on the device's subnet must
forward DHCP to the boot service as well as to the site DHCP server, and
the routed path must carry the device's later unicast traffic to the boot
service (boot-server requests and TFTP).

- Priority: SHOULD
- Source: SRC-024
- Standards: RFC 1542 §4.1.1
- Status: AUDITED

### Boot program delivery

### REQ-BOOT-030: Deliver the boot program by TFTP

The boot service delivers the boot program, and any further files the
firmware requests over TFTP, as TFTP read transfers in octet mode.

- Priority: MUST
- Source: SRC-004, SRC-020
- Standards: RFC 1350 §1, §4, §5, §6; UEFI 2.10 §24.3.10
- Status: AUDITED

### REQ-BOOT-031: Accept requests with or without TFTP options

The boot service correctly serves a request that carries no TFTP options
and also one that carries options. It answers options it supports according
to their RFCs and ignores the rest, as RFC 2347 requires. Which options it
supports is a clean-side decision. Either way, a standards-compliant UEFI
x86-64 firmware must be able to download the boot program.

- Priority: MUST
- Source: SRC-027, SRC-020
- Standards: RFC 2347 (negotiation protocol); RFC 2348; RFC 2349; UEFI
  2.10 §24.3.10
- Status: AUDITED

### REQ-BOOT-032: Reliable transfer behaviour

TFTP transfers follow the RFC timing rules. The service retransmits only on
timeout, never because a duplicate acknowledgement arrived. Retransmission
timeouts adapt and back off. Retries are capped, and a transfer that hits
the cap is abandoned and its resources released.

- Priority: MUST
- Source: SRC-031, SRC-030, SRC-026
- Standards: RFC 1123 §4.2.3.1, §4.2.3.2, §4.2.4; RFC 1350 §2, §6; RFC 7440 §6
- Status: AUDITED

### REQ-BOOT-033: Missing file

When a device asks for a file the boot service does not have, the service
answers with the TFTP file-not-found error and ends that transfer. It does
not send a substitute file.

- Priority: MUST
- Source: SRC-026
- Standards: RFC 1350 §7, Appendix (error code 1)
- Status: AUDITED

### REQ-BOOT-034: Many devices at once

The boot service handles network-boot requests and transfers for many
devices at the same time. One slow, stalled, or failed device must not stop
or noticeably delay the others.

- Priority: MUST
- Source: SRC-004
- Standards: RFC 1350 §4 (one transfer identifier per transfer)
- Status: AUDITED

### REQ-BOOT-035: Files too large for the transfer

TFTP block numbers are 16 bits wide, so the largest file a transfer can
carry depends on the block size. The boot service must not send a corrupt
or truncated file because of this limit.

- Priority: MUST
- Source: SRC-026, SRC-028
- Basis: DEC-0018 item 2 (wrap-around and large-block negotiation;
  project rule, not described product behaviour)
- Standards: RFC 1350 §5; RFC 2348
- Status: AUDITED (2026-10-28; was OPEN before M3. Settled in M3 fix
  round 1 by DEC-0018 item 2, project rule, not described product
  behaviour. The boot service allows
  the block number to wrap and negotiates larger blocks when asked;
  REQ-BOOT-064. Requirement text unchanged. Wrap-around is not
  standardised; see `specs/standards/tftp.md` §8.)

### Security on the unauthenticated boot network

### REQ-BOOT-040: Read-only file service

The boot service's TFTP function is read-only. It refuses every write
request with a TFTP error and never creates, changes, or deletes a file
because of a network request.

- Priority: MUST
- Source: SRC-026, SRC-031
- Standards: RFC 1350 Security Considerations; RFC 1123 §4.2.3.4
- Status: AUDITED

### REQ-BOOT-041: Serve only published boot files

The boot service serves only the files the product has published for
network boot. A request for any other name is refused. That includes names
that try to reach other locations on the host (for example by parent-path
components or absolute paths) and names that point to other host files.

- Priority: MUST
- Source: SRC-031, SRC-026
- Standards: RFC 1123 §4.2.3.4; RFC 1350 Security Considerations
- Status: AUDITED

### REQ-BOOT-042: Ignore broadcast file requests

TFTP requests sent to a broadcast address are dropped silently.

- Priority: SHOULD
- Source: SRC-031
- Standards: RFC 1123 §4.2.3.5
- Status: AUDITED

### REQ-BOOT-043: No secrets over the boot network

Anything sent over the DHCP and TFTP phases can be seen and changed by any
host on the path, and anyone can ask for it. Those phases therefore carry
no credentials, keys, passwords, domain-join material, or device-specific
secrets. Any later exchange that needs such material happens through a
separately protected channel defined in another area.

- Priority: MUST
- Source: SRC-013, SRC-015, SRC-018, SRC-026
- Standards: RFC 4578 §5; RFC 3046 §5; RFC 1350 Security Considerations;
  draft-henry-remote-boot-protocol-00 §4
- Status: AUDITED

### REQ-BOOT-044: Withstand heavy or hostile request volume

A flood of boot requests, whether from many genuine devices or from a hostile
host, must not make the boot service crash, run out of resources, or stop
answering for long periods. No single source of requests can deny service
to other devices, and the service's total resource use stays bounded
however many requests arrive. How that is achieved is a clean-side design
choice. When it has to shed load, it drops requests rather than sending
malformed or partial answers, and it carries on serving once the load
falls.

- Priority: MUST
- Source: SRC-004 (symptom only; no mechanism is described)
- Standards: RFC 7440 §7 (throughput limits in boot environments)
- Status: AUDITED (numeric limits: see OPEN-BOOT-L1)

### REQ-BOOT-045: Suppression is not access control

Hardware addresses and machine identifiers on the boot network are claimed
by the device and are not authenticated, so suppressing a device
(REQ-BOOT-050) is a convenience, not a security control. The product must
not present it to the operator as a way to stop a hostile device from
fetching boot files. REQ-BOOT-043 is what protects the content.

- Priority: MUST
- Source: SRC-015, SRC-018
- Standards: RFC 3046 §5; draft-henry-remote-boot-protocol-00 §4
- Status: AUDITED

### Operator control and observation

### REQ-BOOT-050: Tell the boot service not to boot a device

An operator can tell the boot service not to offer a boot program to a
particular device, identified as in REQ-BOOT-007, and can later lift that
instruction. Both changes apply from the device's next network-boot
attempt, with no restart of the boot service.

- Priority: MUST
- Source: DEC-0004; SRC-004 (outcome only: no loop back into network boot)
- Basis: project design (not described product behaviour)
- Standards: UEFI 2.10 §3.1.2 (SRC-021)
- Status: AUDITED

### REQ-BOOT-051: A suppressed device falls through

A suppressed device gets no reply from the boot service at all, not a
refusal message. Its firmware therefore treats the network boot option as
failed and moves to its next boot option, as it would with no boot service
present.

- Priority: MUST
- Source: DEC-0004; SRC-021, SRC-020, SRC-019 (firmware behaviour relied on)
- Basis: project design (not described product behaviour)
- Standards: UEFI 2.10 §3.1.2, §24.3.8; Appendix E.4.20.1 (SRC-019)
- Status: AUDITED

### REQ-BOOT-052: Boot service status and missing content

The operator can see whether each boot service is running. The operator is
told when a boot service lacks content it needs to offer a boot program
(for example, no boot program published for UEFI x86-64). Derived from
those two points rather than from a source: a boot service in that state
does not offer a boot program it cannot deliver.

- Priority: MUST
- Source: SRC-004; SRC-006 (service status sentence only)
- Basis: project design (not described product behaviour), for the last sentence
- Standards: none
- Status: AUDITED

### REQ-BOOT-053: Settings survive service updates

When the boot service is updated to a newer version, its operator-set
configuration (including the suppressed-device list) is kept.

- Priority: SHOULD
- Source: SRC-007
- Standards: none
- Status: AUDITED

### REQ-BOOT-054: Record of network-boot attempts

The operator can see that a device attempted network boot, when it did so,
how it identified itself, and whether it was offered a boot program or
ignored and why (unsupported architecture, suppressed, missing content, not
a PXE client), along with the outcome of the file transfer.

- Priority: SHOULD
- Source: none
- Standards: none
- Status: OPEN (Is a per-attempt record shown to operators, and how long
  is it kept? No public source describes one. It relates to JOB-1.)

### After-install boot order (BOOT-5)

### REQ-BOOT-060: No network-boot loop after provisioning

Once a device has network booted into provisioning, later restarts during
and after the install do not land it back in network boot and restart
provisioning. The device continues into the installed system unless an
operator deliberately makes it eligible for network boot again.

- Priority: MUST
- Source: SRC-004
- Standards: UEFI 2.10 §3.1.1, §3.1.2 (SRC-021)
- Status: AUDITED

### REQ-BOOT-061: Next boot goes to the installed disk

After a network-booted install finishes, the device's next boot starts the
installed operating system from its disk.

- Priority: MUST
- Source: SRC-004
- Standards: UEFI 2.10 §3.1.1, §3.1.2, §3.3 (SRC-021)
- Status: OPEN (Does the device's lasting firmware boot order change,
  putting the installed system ahead of network boot, or is only the next
  boot steered? Does REQ-BOOT-050 apply to the device automatically when
  provisioning finishes, or only when an operator sets it? The public
  source gives the outcome only.)

### REQ-BOOT-062: Make a device eligible for network boot again

An operator can make a previously provisioned or suppressed device eligible
to network boot and provision again.

- Priority: SHOULD
- Source: SRC-004 (re-imaging is a product outcome)
- Standards: none
- Status: OPEN (Through what operator action, and does it also need a
  change at the device, such as the firmware boot order? No public source
  covers this.)

### Serving the provisioning environment and finishing (M3)

REQ-BOOT-063 to REQ-BOOT-067 were added in spec run M3 (2026-10-27).
063 to 066 are AUDITED (2026-10-28); 067 is OPEN. REQ-BOOT-065 partly answers the
question in REQ-BOOT-061, whose text is unchanged.

### REQ-BOOT-063: Serve the Windows PE boot files

For a UEFI x64 device it answers, the boot service offers Microsoft's
UEFI boot manager from the operator's environment kit as the boot
program, then serves by TFTP the further files that boot manager asks
for: the boot configuration, the RAM-disk support file, the Windows PE
image and any font files (`specs/preinstall-env.md` REQ-PE-012). These
are published boot files under REQ-BOOT-041; nothing else is served.

- Priority: MUST
- Source: SRC-091 (files a PXE server needs to load Windows PE); SRC-092
  (on EFI the boot program fetches the boot configuration, SDI file and
  WIM itself); SRC-094 (Microsoft's UEFI boot manager is its UEFI
  network boot program); SRC-004 (outcome only: devices network boot
  into the provisioning environment)
- Standards: `specs/standards/winpe-network-boot.md` §2, §3, §5;
  `specs/standards/tftp.md`
- Status: AUDITED (2026-10-28; exact file paths: OPEN-WPXE-1 in
  `winpe-network-boot.md`)

### REQ-BOOT-064: Deliver the Windows PE image in full

The boot service delivers the Windows PE image, typically hundreds of
megabytes, to Microsoft's boot manager by TFTP intact and complete, and
never sends a truncated or corrupted file because of the 16-bit TFTP
block number (REQ-BOOT-035). It answers the TFTP options the boot
manager uses for block size and window size according to their RFCs.
[project rule] When a client asks for a larger block size, the boot
service negotiates it under RFC 2348; and when a transfer needs more
blocks than a 16-bit block number can count, the boot service lets the
block number wrap around and carries on, so that the whole file is
delivered.

- Priority: MUST
- Source: SRC-093 (the boot manager's TFTP block and window size
  settings, defaults 1432 bytes and 4, recommended block size at most
  16384); SRC-091
- Basis: DEC-0018 item 2 (wrap-around and large-block negotiation;
  project rule, not described product behaviour)
- Standards: RFC 1350 §5; RFC 2348; RFC 7440; `specs/standards/tftp.md`
  §7, §8, §10; `specs/standards/winpe-network-boot.md` §5, §7
- Status: AUDITED (2026-10-28; wrap-around is not standardised, `tftp.md` §8: the
  value the block number wraps to is a clean-side choice that must be
  checked against Microsoft's boot manager; which options the boot
  manager sends is still OPEN-WPXE-2)

### REQ-BOOT-065: The installed system becomes the next boot target

When an install finishes, the device's firmware boot order is left so
that the installed Windows boots before network boot on the next and
later restarts. The product achieves this from the provisioning
environment, before its final restart, by making the installed Windows
boot option first in the firmware's boot order (creating the option if
it does not exist).

- Priority: MUST
- Source: SRC-004 (outcome only: the device does not boot back into
  network boot; whether the change is lasting is not stated)
- Basis: making the change lasting and putting the Windows option first
  is project design; it is also what Microsoft's boot-file tool does by
  default (SRC-089)
- Standards: UEFI 2.10 §3.1.1, §3.3 (SRC-021);
  `specs/standards/uefi-boot-manager.md` §2, §8 item 1, §9
- Status: AUDITED (2026-10-28; lasting change: confirm as D-M3-6. Firmware may reorder
  options itself, `uefi-boot-manager.md` §2; OPEN-UBM-1 covers the case
  where no firmware option is created)

### REQ-BOOT-066: Create the installed system's boot files and entry

After the image is applied (`specs/preinstall-env.md` REQ-PE-017), the
installed Windows's boot files are placed on the EFI system partition
and a Windows boot configuration for the installed system is created
there, using the boot files from the applied image itself, so that the
installed system starts from the disk with no network. A firmware boot
option pointing at the Windows boot manager on that disk then exists
(REQ-BOOT-065).

- Priority: MUST
- Source: SRC-089 (Microsoft's documented way to make an applied image
  bootable: copy boot files from the applied Windows to the system
  partition, create its boot configuration, and add a firmware entry);
  SRC-088 (apply, then set up boot files); SRC-004 (outcome only)
- Standards: `specs/standards/uefi-boot-manager.md` §9;
  `specs/standards/gpt.md` §10, §11
- Status: AUDITED (2026-10-28; the boot configuration is an undocumented Microsoft
  format, `winpe-network-boot.md` §6; using Microsoft's tool from the
  applied image is the documented route. Which boot files, 2011 or 2023
  CA, is OPEN-BOOT-SB)

### REQ-BOOT-067: Boot service behaviour for a device whose install is done

Once a device's install has succeeded, whether the boot service keeps
answering that device's network boots (it is then protected from a loop
only by REQ-BOOT-065), or stops answering it automatically as for a
suppressed device (REQ-BOOT-050, REQ-BOOT-051) until an operator makes
it eligible again (REQ-BOOT-062), is not settled.

- Priority: SHOULD
- Source: SRC-004 (outcome only: no loop back into network boot)
- Standards: UEFI 2.10 §3.1.2 (SRC-021);
  `specs/standards/uefi-boot-manager.md` §8
- Status: OPEN (D-M3-6: automatic suppression after success? If yes, a
  person who deliberately network boots the device later gets no
  answer until an operator acts; if no, a device whose boot order was
  reset by its firmware will start provisioning again. No public source
  says which the product does.)

### Timing

### REQ-BOOT-070: Answer within the client's retry window

The boot service answers each eligible PXE request quickly enough that the
device gets the answer before its first DHCP retransmission. The PXE client
starts retrying at about 4 seconds, and it may hear the site DHCP server's
offer much sooner.

- Priority: SHOULD
- Source: SRC-019
- Standards: UEFI 2.10 Appendix E.4.20.1; RFC 2131 §4.1
- Status: AUDITED

## States and transitions

**Boot service.** *Stopped*: no answers at all. *Running*: answers eligible
devices. *Running with missing content*: running, but unable to offer a boot
program for one or more supported architectures. The operator is told
(REQ-BOOT-052), and affected devices are not offered a program. Moving
between these states must not lose configuration (REQ-BOOT-053).

**One network-boot attempt, as the boot service sees it.**

1. *Request received*: a DHCP discover, or a later PXE request, arrives
   directly or through a relay agent.
2. *Classified*: the request is dropped (malformed, not a PXE client,
   unsupported architecture, suppressed device, or the service is shedding
   load) or found eligible. A dropped request gets no reply.
3. *Offered*: the device was told which boot program to fetch and from
   where. The site DHCP server gives the address separately.
4. *Transferring*: the device is reading the boot program over TFTP.
5. *Delivered*: the last block was acknowledged, or the transfer ended
   normally under RFC 1350 §6. *Failed*: an error was sent (such as a
   missing file), or the retry cap was reached (REQ-BOOT-032).

A device may make more than one attempt, and each attempt is separate.

**Device lifecycle relevant to BOOT-5.** *Eligible*: the device is offered
a boot program. *Provisioning*: it booted the boot program and is
installing. *Installed*: its next boot goes to disk (REQ-BOOT-061).
*Suppressed*: the operator has told the service not to answer it, and it
falls through (REQ-BOOT-051). How devices move between Provisioning,
Installed, and Suppressed is partly OPEN (REQ-BOOT-061, REQ-BOOT-062).

## Limits

- The public sources give no per-segment or per-device limit on concurrent
  network boots, and no timeout set by the boot service. (OPEN-BOOT-L1)
- Standard limits that bound the behaviour, summarised in the standards
  files:
  - PXE client DHCP retry schedule of 4, 8, 16, and 32 seconds, repeated up
    to three times (UEFI Appendix E.4.20.1). The client gives up after at
    least 31 seconds in a single DHCP call (UEFI §24.3.8).
  - DHCP messages: options field of at least 312 octets, and at least 576
    octets of message must be accepted (RFC 2131 §2; RFC 2132 §9.10).
  - TFTP: 512-octet default block; negotiated block size 8 to 65464; timeout
    option 1 to 255 seconds; window size 1 to 65535; 16-bit block numbers
    (RFC 1350, RFC 2348, RFC 2349, RFC 7440).
  - Relay agents drop requests above 16 hops (RFC 1542 §4.1.1).
  - The UEFI boot manager arms a 5-minute watchdog before it starts a boot
    image (UEFI §3.1.2).

## Error behaviour (as the device and operator observe it)

- **Boot service unreachable, stopped, or not serving this device**: the
  device gets an address from the site DHCP server, if one exists, but no
  PXE answer. Its firmware retries on the standard schedule, reports that
  no boot offer was received, and moves to its next boot option
  (`specs/standards/uefi-boot-manager.md` §5). A suppressed device looks the
  same (REQ-BOOT-051). The operator view is OPEN (REQ-BOOT-054).
- **Boot service slow**: an answer that arrives after the device stopped
  listening is ignored by the device. Meeting REQ-BOOT-070 avoids this.
- **Relay agent not forwarding to the boot service**: same as unreachable.
  REQ-BOOT-023 tells the operator what the network needs.
- **Boot file missing**: the device gets a TFTP file-not-found error, its
  firmware reports a download failure, and it moves to its next boot option
  (REQ-BOOT-033). The operator is told about missing content
  (REQ-BOOT-052).
- **Transfer interrupted**: the device's TFTP client times out or gets an
  error, and the firmware treats the boot option as failed. The boot
  service abandons the transfer after its retry cap (REQ-BOOT-032).
- **Boot program corrupt or not trusted by the firmware**: the firmware
  refuses to start it. With Secure Boot on, a program that fails signature
  checks is not started and the boot manager moves on
  (`specs/standards/uefi-secure-boot.md` §5). How the product handles Secure
  Boot is OPEN (see below).

## Security expectations (summary)

The boot network is unauthenticated. DHCP and TFTP give no way to prove who
a device is, who the server is, or that a file was not changed in transit.
The boot service must therefore:

- refuse to assign addresses or act as a DHCP server (REQ-BOOT-010);
- answer PXE clients only, and only with programs for their architecture
  (REQ-BOOT-004, REQ-BOOT-005);
- serve read-only, and only published files (REQ-BOOT-040, REQ-BOOT-041,
  REQ-BOOT-042);
- carry no secrets in boot-phase traffic or files (REQ-BOOT-043);
- survive floods and malformed input (REQ-BOOT-006, REQ-BOOT-044);
- not treat claimed device identity as authentication (REQ-BOOT-045);
- pass relay agent information through untouched and not trust it
  (REQ-BOOT-021).

## Standards relied on

- RFC 2131, RFC 2132, RFC 1542, RFC 3046, RFC 4578 (with erratum 4624),
  IANA processor architecture registry: `specs/standards/pxe-dhcp.md`.
- PXE ProxyDHCP and boot-server discovery, from the 1999 Intel PXE
  Internet-Draft, UEFI 2.10 Appendix E, and public secondary references:
  `specs/standards/proxy-dhcp.md`.
- RFC 1350, RFC 1123 §4.2, RFC 2347, RFC 2348, RFC 2349, RFC 7440
  (conditional): `specs/standards/tftp.md`.
- UEFI 2.10 chapter 3 and §24.3: `specs/standards/uefi-boot-manager.md`.
- UEFI 2.10 chapter 32 and §7.4: `specs/standards/uefi-secure-boot.md`
  (background only).

## Out of scope / unknown

Out of scope for M1. No requirements are written yet; see `specs/INDEX.md`:

- **BOOT-3** legacy BIOS network boot (INDEX row BOOT-3, P2).
- **BOOT-4** UEFI HTTP boot (INDEX row BOOT-4, P2, single source).
- **BOOT-6** ARM devices (INDEX row BOOT-6, P3).
- IPv6 network boot (INDEX Unconfirmed; RFC 5970 noted as conditional in
  `specs/standards/pxe-dhcp.md` §11).
- Multicast boot-file delivery (INDEX Unconfirmed).
- PXE boot menus and prompts shown by the firmware: no source says the
  product uses them.
- Everything after the boot program starts: the provisioning environment
  (PE), content fetch (RELAY-2), authenticated exchanges with the boot
  service, and workflow (SEQ).
- Where the boot service runs and how it gets the role (RELAY-1).

Unknown (OPEN):

- **OPEN-BOOT-L1**: Is there any per-segment or per-device limit on
  concurrent network boots, or a timeout the boot service applies (for
  example to abandon an idle transfer)? Values are needed for
  REQ-BOOT-044.
- **OPEN-BOOT-SB**: Must network boot work with Secure Boot enabled on the
  device, and if so, which signing authority must the boot program chain
  to? This is in the INDEX Unconfirmed list. Background is in
  `specs/standards/uefi-secure-boot.md`.
- REQ-BOOT-013, REQ-BOOT-014, REQ-BOOT-054, REQ-BOOT-061,
  REQ-BOOT-062, REQ-BOOT-067: see the question in each Status line. M3
  note: REQ-BOOT-035 and REQ-BOOT-064 are settled by DEC-0018 item 2
  (project rule); REQ-BOOT-065 answers the first question of
  REQ-BOOT-061 for the project, pending D-M3-6.
- M3 standards: `specs/standards/winpe-network-boot.md` (topic 22) and
  `specs/standards/uefi-boot-manager.md` §9 (boot entry creation).
- The primary PXE 2.1 specification text could not be retrieved from any
  public, login-free location during this run. Behaviour summarised from
  the 1999 Internet-Draft and secondary sources is labelled as such in
  `specs/standards/proxy-dhcp.md`. If the primary text becomes available,
  re-check it.
