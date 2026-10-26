# Standards summary: PXE boot flow and DHCP for network boot (IPv4)

Topic 1 of the standards reading list. This is a summary in our own words
for implementers. Field names and numeric constants are as defined in the
standards. Source IDs (SRC-nnn) refer to the provenance log. Clean-side
readers need only the citations shown here.

Primary sources: RFC 2131 (DHCP), RFC 2132 (DHCP options), RFC 951
(BOOTP, §3.2 only), RFC 1542 (BOOTP relay clarifications), RFC 3046
(relay agent information), RFC 4578 (PXE
options) with verified erratum 4624, the IANA Processor Architecture Types
registry, UEFI 2.10 §24.3 and Appendix E.4.20, and the 1999 Intel PXE
Internet-Draft `draft-henry-remote-boot-protocol-00` (expired, informational
only).

**Caveat:** the Intel PXE 2.1 specification itself (September 1999) could
not be retrieved from a public, login-free location during this run. The
PXE-specific behaviour below comes from the Internet-Draft that Intel
published for the same protocol, the UEFI specification's PXE material, and
RFC 4578. Points that rest only on secondary sources are marked
**[secondary]**.

## 1. Roles

- **PXE client**: the firmware network-boot code on the device. On UEFI it
  is the PXE Base Code protocol (UEFI §24.3).
- **DHCP server**: assigns the device's IPv4 address (RFC 2131).
- **ProxyDHCP / boot server**: gives PXE-specific boot information without
  assigning addresses. See `proxy-dhcp.md`.
- **Relay agent**: forwards DHCP between subnets (RFC 1542 §4; RFC 2131 §1).
- **TFTP server**: serves the boot program. See `tftp.md`.

## 2. Ports and addressing

- Servers receive on UDP 67 and clients receive on UDP 68 (RFC 2131 §4.1).
- The PXE boot-server and ProxyDHCP alternate port is UDP 4011
  (draft-henry §3.3.1; see `proxy-dhcp.md` §4).
- TFTP requests go to UDP 69 (RFC 1350 §4).
- A client without an address sends from 0.0.0.0 to the limited broadcast
  address 255.255.255.255 (RFC 2131 §4.1; RFC 1542 §4.1.2 for the limited
  broadcast address).

## 3. DHCP message layout (RFC 2131 §2, Figure 1, Table 1)

Fixed-format header followed by options:

| Field | Octets | Meaning |
|-------|--------|---------|
| `op` | 1 | 1 = request (client to server), 2 = reply |
| `htype` | 1 | hardware type (1 = Ethernet) |
| `hlen` | 1 | hardware address length (6 for Ethernet) |
| `hops` | 1 | client sets 0, relay agents increment it |
| `xid` | 4 | transaction ID chosen by the client; replies echo it |
| `secs` | 2 | seconds since the client began this exchange |
| `flags` | 2 | most significant bit = BROADCAST; the other bits must be zero |
| `ciaddr` | 4 | client's current address, if it has one |
| `yiaddr` | 4 | address being given to the client |
| `siaddr` | 4 | address of the next server to use in bootstrap (boot-file server) |
| `giaddr` | 4 | relay agent address (0 when not relayed) |
| `chaddr` | 16 | client hardware address (first `hlen` octets used) |
| `sname` | 64 | optional server host name, null-terminated |
| `file` | 128 | boot file name, null-terminated |
| `options` | variable | starts with the magic cookie 99.130.83.99 (0x63825363) |

- Clients must accept an options field of at least 312 octets. All parties
  must handle messages of at least 576 octets, and larger sizes can be
  negotiated with option 57 (RFC 2131 §2; RFC 2132 §9.10).
- **Option overload** (option 52): value 1 means `file` carries options, 2
  means `sname` does, 3 means both. Those fields are then parsed after
  `options` (RFC 2132 §9.3; RFC 2131 §4.1). When `file` or `sname` is
  overloaded, the boot file name and server name travel in options 67 and 66
  instead (RFC 2132 §9.4, §9.5).

### 3.1 Server reply fields (RFC 2131 §4.3.1, Table 3)

RFC 2131 §4.3.1 Table 3 lists what a DHCP server puts in each header
field of its replies. Summary for DHCPOFFER and DHCPACK (DHCPNAK shown
for contrast):

| Field | DHCPOFFER | DHCPACK | DHCPNAK |
|-------|-----------|---------|---------|
| `op` | 2 (BOOTREPLY) | 2 (BOOTREPLY) | 2 (BOOTREPLY) |
| `htype` | hardware type per the IANA assigned numbers (1 = Ethernet) | same | same |
| `hlen` | hardware address length in octets (6 for Ethernet) | same | same |
| `hops` | 0 | 0 | 0 |
| `xid` | copied from the client's DHCPDISCOVER | copied from the client's DHCPREQUEST (**[reading]** or DHCPINFORM, when the ACK answers one; Table 3 names only DHCPREQUEST) | copied from the client's DHCPREQUEST |
| `secs` | 0 | 0 | 0 |
| `ciaddr` | 0 | copied from the client's request, or 0 | 0 |
| `yiaddr` | address offered | address assigned | 0 |
| `siaddr` | address of the next server in the bootstrap (see note) | same | 0 |
| `flags` | copied from the DHCPDISCOVER | copied from the DHCPREQUEST | copied from the DHCPREQUEST |
| `giaddr` | copied from the DHCPDISCOVER | copied from the DHCPREQUEST | copied from the DHCPREQUEST |
| `chaddr` | copied from the DHCPDISCOVER | copied from the DHCPREQUEST | copied from the DHCPREQUEST |
| `sname` | server host name, or options if overload (52) says so | same | unused |
| `file` | client boot file name, or options if overload (52) says so | same | unused |

Option rows of the same table, for OFFER / ACK:

- Option 50 (requested IP address): must not be sent in either.
- Option 51 (lease time): must be sent in an OFFER and in an ACK that
  answers a DHCPREQUEST; must not be sent in an ACK that answers a
  DHCPINFORM.
- Option 52 (overload): may be sent.
- Option 53 (message type): must be sent (2 for OFFER, 5 for ACK).
- Option 54 (server identifier): must be sent.
- Option 55 (parameter request list) and option 57 (maximum message
  size): must not be sent.
- Option 56 (message text): should be sent.
- Option 61 (client identifier): must not be sent.
- Option 60 (vendor class identifier): may be sent.
- All other options: may be sent.

Notes:

- `siaddr`: RFC 2131 §2 says a server may put its own address here when
  it supplies the next stage of the bootstrap. §4.3.1 itself adds nothing
  more. For how PXE clients choose between `siaddr` and option 54, see §7
  step 3a.
- **[reading]** Table 3 describes a server that assigns addresses. It does
  not describe a ProxyDHCP reply, which carries no address; for that see
  `proxy-dhcp.md`. The option 61 "must not" row is a rule for the address
  server's reply. For options 93, 94 and 97 in server packets, see §5.5 of this
  file.

### 3.2 Minimum BOOTP message size (RFC 1542 §2.1)

- RFC 1542 §2.1 takes the minimum BOOTP header size from RFC 951: 300
  octets, counted in the UDP data (that is, excluding the IP and UDP
  headers). The 300 octets are the 236 octets of fixed fields in the table
  above plus the original 64-octet vendor area (RFC 951 §3, where the
  BOOTP layout ends in a 64-octet vendor-specific field and the 2 octets
  later used for `flags` are unused).
- The rule is written as a receiver check, not as a sender duty: a
  receiver should check that the IP total length and UDP length are large
  enough to hold that 300-octet header (and that `op` is 1 or 2). A
  message that fails the checks must be silently discarded: no reply and
  no ICMP error; the event should be logged and counted (RFC 1542 §1.2,
  §2.1; repeated for relays in §4.1 and servers in §5.1).
- Messages longer than 300 octets must be accepted (RFC 1542 §2.1).
- **[reading]** A sender whose message is shorter than 300 octets of UDP
  data risks being dropped by receivers that run this check, so replies
  should be padded (for example with Pad options or zero octets after End)
  to at least 300 octets. RFC 1542 §2.1 does not itself state a padding
  rule. For the DHCP 576-octet and 312-octet-options figures, see the
  bullets above (RFC 2131 §2).

## 4. Option encoding (RFC 2132 §2)

Each option is a code octet, then a length octet, then that many data
octets. The exceptions are Pad (0) and End (255), which are one octet each.
Multi-octet numbers are in network byte order. Codes 128 to 254 were
originally site-specific (RFC 2132 §2). PXE clients request 128 to 135,
which see below. Text options should not end in a null, but receivers must
tolerate one.

## 5. Options used in network boot

| Code | Name | Length | Use in network boot | Ref |
|------|------|--------|---------------------|-----|
| 0 / 255 | Pad / End | 1 | framing | RFC 2132 §3.1, §3.2 |
| 1 | Subnet mask | 4 | address set-up (DHCP server only) | RFC 2132 §3.3 |
| 3 | Router | n×4 | address set-up (DHCP server only) | RFC 2132 §3.5 |
| 13 | Boot file size | 2 | size in 512-octet blocks (optional) | RFC 2132 §3.15 |
| 43 | Vendor-specific information | ≥1 | carries the encapsulated PXE sub-options (§6) when the reply's class is PXEClient | RFC 2132 §8.4 |
| 51 | Lease time | 4 | address set-up (DHCP server only) | RFC 2132 §9.2 |
| 52 | Option overload | 1 | see §3 | RFC 2132 §9.3 |
| 53 | Message type | 1 | 1 DISCOVER, 2 OFFER, 3 REQUEST, 4 DECLINE, 5 ACK, 6 NAK, 7 RELEASE, 8 INFORM | RFC 2132 §9.6 |
| 54 | Server identifier | 4 | identifies the replying server; client uses it as a unicast target | RFC 2132 §9.7 |
| 55 | Parameter request list | ≥1 | option codes the client wants | RFC 2132 §9.8 |
| 57 | Maximum message size | 2 | ≥ 576 | RFC 2132 §9.10 |
| 60 | Vendor class identifier | ≥1 | client: `PXEClient:Arch:xxxxx:UNDI:yyyzzz`; server reply: `PXEClient` | RFC 2132 §9.13; draft-henry §3.1.1; UEFI Table 24.1 |
| 61 | Client identifier | ≥2 | type octet and identifier; may be sent by PXE clients | RFC 2132 §9.14; draft-henry §3.1.1 |
| 66 | TFTP server name | ≥1 | used when `sname` is overloaded | RFC 2132 §9.4 |
| 67 | Bootfile name | ≥1 | used when `file` is overloaded | RFC 2132 §9.5 |
| 82 | Relay agent information | var | added by relays; servers echo it (§9) | RFC 3046 §2 |
| 93 | Client system architecture | 2n | one or more 16-bit types | RFC 4578 §2.1 |
| 94 | Client network interface identifier | 3 | type (1 = UNDI), major, minor | RFC 4578 §2.2 |
| 97 | Client machine identifier | 17 | type 0 and a 16-octet GUID | RFC 4578 §2.3 |
| 128–135 | PXE-reserved | — | requested by PXE clients; content not defined by PXE | RFC 4578 §2.4 |

### 5.1 Option 60 (vendor class identifier)

- PXE clients send a string that starts with `PXEClient`, followed by the
  architecture and UNDI version fields in the form
  `PXEClient:Arch:xxxxx:UNDI:yyyzzz`. Here `xxxxx` is the 5-digit decimal
  architecture type, and `yyy` and `zzz` are the 3-digit decimal UNDI major
  and minor versions (draft-henry §3.1.1; UEFI §24.3, Table 24.1). The
  architecture and version values in the string match options 93 and 94.
- PXE-aware server replies carry option 60 with the value `PXEClient`. When
  several offers arrive, the client prefers those that carry it
  (draft-henry §3.1.2). UEFI Appendix E.4.20.1 says that if offers lack the
  PXEClient tag, the client shortens its retry cycle (§8).
- A server that does not understand a class ignores it (RFC 2132 §9.13).

### 5.2 Option 93 (client system architecture)

- The length must be even and non-zero. A client that supports several
  architectures may list them in its first DHCP and PXE boot-server
  packets, and the list may be shortened in any later exchange with the
  server or servers (RFC 4578 §2.1). For when the option must be present,
  see §5.5.
- Values (IANA registry, SRC-017; RFC 4578 §2.1 as corrected by verified
  erratum 4624):

| Value | Architecture |
|-------|--------------|
| 0 | x86 BIOS |
| 6 | x86 (32-bit) UEFI |
| **7** | **x64 (x86-64) UEFI** (the M1 target) |
| 9 | EFI Byte Code |
| 10 | ARM 32-bit UEFI |
| 11 | ARM 64-bit UEFI |
| 15 | x86 UEFI HTTP boot |
| 16 | x64 UEFI HTTP boot |

  **Important:** the original RFC 4578 text lists 7 as EFI BC and 9 as EFI
  x86-64. Erratum 4624 (verified 2016) swaps them, and the IANA registry
  and UEFI implementations use **7 = x86-64 UEFI**. Other values in the
  registry are deprecated or relate to other platforms.

### 5.3 Option 94 (network interface identifier)

Three octets: type `t`, major `M`, minor `m`. The only defined type is 1
(UNDI). Version 3.x indicates 32/64-bit UNDI with EFI (3.00, 3.10, 3.20,
per RFC 4578 §2.2). UEFI sends type 1, version 3.0 by default when no
network interface identifier protocol is present (UEFI §24.3, Table 24.1).
For when the option must be present, see §5.5.

### 5.4 Option 97 (client machine identifier)

Type 0 followed by a 16-octet GUID, length 17. The GUID format is the one in
the EFI specification's GUID appendix (RFC 4578 §2.3). RFC 4578 §1 explains
why it exists: a hardware address alone may not identify a machine, because
docking stations can share an address and one machine can have several
adapters. For when the option must be present, see §5.5. For the GUID's
byte order and text form, see `uefi-guid-text.md`.

### 5.5 Presence of options 93, 94 and 97 (RFC 4578 §2.1, §2.2, §2.3)

What RFC 4578 states:

- Each of §2.1 (option 93), §2.2 (option 94) and §2.3 (option 97) contains
  the same MUST-level rule: the option is to be present in every DHCP
  packet and every PXE packet sent by a client or server that complies
  with PXE.
- **Clients.** A compliant PXE client includes all three options in every
  DHCP and PXE packet it sends. **[reading]** In the flow of §7 that means
  the DISCOVER, the REQUEST and any boot-server request (steps 1, 2 and 3b).
- **Servers.** The rule names servers as well as clients. A PXE-compliant
  server includes all three options in every DHCP and PXE packet it sends.
  **[reading]** In the flow of §7 that means a ProxyDHCP offer, a PXE-aware
  DHCP server's OFFER and ACK, and a boot server's ACK (steps 2 and 3b).
  The three sections require only that the options be present. They say
  nothing else about what a server must do.
- RFC 4578 is an Informational RFC (SRC-013). **[reading]** Its MUST
  therefore states what PXE compliance involves, rather than a rule of the
  standards-track DHCP documents.

Not stated in RFC 4578 §2.1 to §2.3, marked **[reading]** where we infer:

- **What value a server puts in.** None of the three sections says what
  value a server's copy of each option should hold. They do not say
  whether it should repeat the client's value or describe the server.
  **[reading]** The content of a server's copy is therefore not defined
  by these sections.
- **What a server does with the client's values.** These sections give no
  server handling rule. RFC 4578 §1 gives the options' general purpose
  (helping the server hand back the right boot image), but that is a
  statement of purpose, not a rule in these sections.
- **Servers that are not PXE-aware.** **[reading]** The rule binds only
  PXE-compliant servers. An ordinary site DHCP server that knows nothing
  of PXE is not addressed by it, and its replies may lack these options.
- **Client reaction to a missing option.** RFC 4578 does not say whether a
  client ignores or rejects a server packet that lacks one of these
  options.
- **Interaction with RFC 2131.** **[reading]** RFC 2131 §4.3.1 bars a
  server from returning a value for a parameter it has neither configured
  nor a default for. RFC 4578 does not say how its presence rule fits
  with that. The clean side decides how to meet both.
- For repeated or split copies of these options, see
  `dhcp-long-options.md` §6.

## 6. PXE vendor sub-options carried in option 43

When a reply's option 60 is `PXEClient`, option 43 may carry PXE
sub-options. They use the encapsulated code/length/value format of RFC 2132
§8.4, with no magic cookie, and end with 255 (draft-henry §3.2.3; RFC 2132
§8.4).

| Tag | Name (as in the standards) | Purpose |
|-----|---------------------------|---------|
| < 6 | multicast TFTP parameters | used only for multicast TFTP; draft-henry §3.3.2.4–§3.3.2.5 describe tag 4 (start delay) and tag 5 (resend delay). Out of scope for M1 |
| 6 | PXE_DISCOVERY_CONTROL | bit field: bit 0 = disable broadcast discovery; bit 1 = disable multicast discovery; bit 2 = accept only servers in tag 8; bit 3 = if a boot file name is present in the offer, download it without discovery or menu **[secondary: SRC-034, SRC-035]** |
| 7 | DISCOVERY_MCAST_ADDR | multicast address for boot-server discovery |
| 8 | PXE_BOOT_SERVERS | list of boot-server types, each with a count and IP addresses |
| 9 | PXE_BOOT_MENU | menu entries describing server types |
| 10 | PXE_MENU_PROMPT | prompt text and timeout (0 = choose the first item at once; 255 = wait indefinitely) |
| 12 | PXE_CREDENTIAL_TYPES | credential types for boot integrity services |
| 71 | PXE_BOOT_ITEM | boot-server type and layer; the layer's high bit asks for credentials. Layout in §6.1 |
| 255 | End | end of sub-options |

Which tags must be present (UEFI Appendix E.4.20.3, clarifying PXE 2.1):

- Tag 6 is optional. If it is absent, all bits are treated as 0.
- Tag 8 is needed only when bit 2 of tag 6 is set.
- Tag 9 is needed only if the client is to show a boot menu.
- Tag 12 is needed only if the client makes security (credential)
  requests.
- Tag 71 is optional. If it is absent, type 0 and layer 0 are assumed.
- Option 43 itself is needed only when PXE sub-options have to be supplied.

Bit 3 of tag 6 is not described in the Internet-Draft. Secondary sources
describe it as above: a value of 11 (bits 0, 1, and 3) makes the client skip
broadcast and multicast discovery and use the file named in the initial
offer. They also report that vendor PXE ROMs then boot from the `file` and
`siaddr` of the initial DHCP or ProxyDHCP packet (SRC-034, SRC-035).

### 6.1 Tag 71 (PXE_BOOT_ITEM) layout

**Source strength.** The Intel PXE 2.1 specification could not be read
(see the caveat at the top). The layout below comes from the 1999 Intel
PXE Internet-Draft (draft-henry §3.2.3.6, repeated in §3.3.2.6), which is
the primary text we have, but an expired draft and not the final PXE 2.1
document. The type values and the layer mask come from UEFI 2.10 §24.3.9
(the firmware's discovery interface, not a wire format). The default when
the tag is absent comes from UEFI Appendix E.4.20.3. Points that are our
inference are marked **[reading]**.

Wire layout inside option 43 (draft-henry §3.2.3.6):

| Octets | Field | Width | Meaning |
|--------|-------|-------|---------|
| 0 | code | 1 | 71 |
| 1 | length | 1 | 4 |
| 2–3 | boot-server type | 2 | which kind of boot server or boot image is meant |
| 4–5 | layer | 2 | most significant bit = credentials flag; the rest = layer number |

- **Length.** Always 4. The draft gives the total length as 4 and draws
  the two fields as 2 octets each. Its text does not state the two widths
  separately; the 2 + 2 split comes from the diagram and the total. UEFI
  §24.3.9 independently types both the discovery type and the layer as
  16-bit unsigned values, which agrees.
- **Byte order. OPEN-T71-1.** No source read states it (the draft does
  not). **[reading]** Treat both fields as network byte order (most
  significant octet first), as RFC 2132 §2 does for multi-octet DHCP
  option values. This is an assumption, not a sourced rule; the PXE 2.1
  text would close it.
- **Layer number.** Selects which image in a boot-server type's sequence
  is meant. Layer 0 is always the first boot file for that type
  (draft-henry §3.2.3.6). The draft gives no upper limit. UEFI §24.3.9
  names an initial-layer value of 0x0000 and a layer mask of 0x7FFF.
- **Credentials flag.** The most significant bit of the layer field. 0 =
  the message is about the boot file itself; 1 = it is about the
  credentials (integrity data) for that boot file (draft-henry §3.2.3.6).
  The draft says only "most significant bit"; **[reading]** with the UEFI
  0x7FFF layer mask, this is bit 15 of the 16-bit value, i.e. 0x8000. A
  DHCPREQUEST with the flag set must also carry tag 12,
  PXE_CREDENTIAL_TYPES (draft-henry §3.2.3.6, §3.2.3.7). Credentials
  belong to boot integrity services.
- **Boot-server type values** (UEFI 2.10 §24.3.9; the draft defines no
  values):

  | Value | Meaning |
  |-------|---------|
  | 0 | PXE bootstrap server |
  | 1 to 16 | named vendor or product boot server types |
  | 17 to 32767 | reserved |
  | 32768 to 65279 | vendor use |
  | 65280 to 65534 | reserved |
  | 65535 | PXE test type |

- **Where it is carried** (draft-henry): in the client's boot-server
  DHCPREQUEST, layer 0 with the flag clear (§3.3.1); in the boot server's
  DHCPACK to that request (§3.3.2); in the credentials request, layer 0
  with the flag set (§3.5.1); and in the reply to that request (§3.5.2,
  which includes the tag but states neither the layer nor the flag;
  **[reading]** the flag is set there too). It also appears as an
  optional tag in a PXE offer (§6 above).
- **What the boot server puts in its reply. OPEN-T71-2.** The draft does
  not say in so many words that the reply repeats the requested type and layer.
  §3.3.2 has the server answer only for a type it serves. UEFI §24.3.9
  says the layer value passed to discovery is updated if the boot server
  changes it. **[reading]** A server should return the requested type and,
  normally, the requested layer. Only the UEFI point (the layer may be
  changed by the server) is sourced; the PXE 2.1 text would close this.
- **When absent.** PXE 2.1 lists the tag as required in a PXE offer;
  UEFI Appendix E.4.20.3 relaxes this: it is optional, and a client that
  does not find it assumes type 0, layer 0.

## 7. Message sequence for a UEFI x86-64 IPv4 client

The steps below follow RFC 2131 §3.1, draft-henry §3, UEFI §24.3.8 and
§24.3.9, and Appendix E.4.20. Steps 3a and 3b are the two PXE paths. Which
path a given reply triggers depends on the PXE options it carries (§6).

1. **DISCOVER.** The client broadcasts a DHCPDISCOVER from 0.0.0.0:68 to
   255.255.255.255:67. It carries option 53 = 1, option 55 (including 1, 3,
   43, 60, and 128 to 135), option 57, option 60
   `PXEClient:Arch:00007:UNDI:003xxx`, option 93 = 0x0007, option 94 = (1,
   3, x), and option 97 = (0, GUID). It may also carry option 61. `chaddr`
   holds the adapter's MAC address. The BROADCAST flag may be set.
2. **OFFERS.** The client collects replies.
   - The site DHCP server sends an ordinary DHCPOFFER with `yiaddr` and the
     address settings.
   - A ProxyDHCP service (`proxy-dhcp.md`) sends an offer with no address,
     with option 60 = `PXEClient`, option 54, and PXE information (option 43
     and/or `siaddr` and `file`). For options 93, 94 and 97 in PXE server
     packets, see §5.5.
   - A DHCP server may itself be PXE-aware and put the PXE information into
     its address offer.
   The client takes its address from a DHCP offer. Offers are tried in
   order of arrival, or sorted if the firmware is set to sort them (UEFI
   §24.3.8). Offers with `PXEClient` are preferred (draft-henry §3.1.2).
   The client then completes REQUEST/ACK with the chosen DHCP server
   (RFC 2131 §3.1).
3. **Boot information.**
   - **3a. Boot file in the offer.** If the PXE information gives a boot
     file name and discovery is not required (tag 6 bit 3 **[secondary]**,
     or no discovery options), the client uses the `file` field (or option
     67) and the boot-file server address. The address comes first from
     `siaddr` and only otherwise from option 54 (UEFI Appendix E.4.20.2,
     which corrects the order given in PXE 2.1).
   - **3b. Boot-server discovery.** Otherwise the client sends a
     boot-server request: a DHCPREQUEST with option 60, its identifiers,
     and option 43 carrying tag 71 with the chosen server type and layer 0.
     It tries multicast to the tag-7 address on port 4011, then broadcast on
     port 67, then unicast on port 4011 to each server in tag 8, as tag 6
     allows (draft-henry §3.3.1). A boot server for that type and
     architecture answers with a DHCPACK carrying the boot file name in
     `file` and a tag 71 (draft-henry §3.3.2). Only the initial layer uses
     multicast or broadcast, and later layers are unicast (UEFI §24.3.9).
     The client waits at least 10 seconds before reporting a discovery
     timeout (UEFI §24.3.9).
   - **Same-host variant.** When the DHCP server's own offer carries option
     60 = `PXEClient`, the client turns to port 4011 on that same server for
     the PXE information. SRC-024 describes this for an offer that carries
     option 60 together with options 66 and 67; if no PXE service answers
     on port 4011 of that host, the boot fails (SRC-024; see
     `proxy-dhcp.md` §4.2).
4. **Download.** The client reads the boot file by TFTP from the boot-file
   server (UEFI §24.3.10; `tftp.md`). UEFI recommends getting the file size
   first, using the TFTP size option where the server supports it (UEFI
   §24.3.10).
5. **Run.** The firmware loads and starts the image through the boot
   manager. With Secure Boot on, the signature checks in
   `uefi-secure-boot.md` apply first.

**Relayed variant (device on another subnet).** In step 1 the relay agent on
the device's subnet receives the broadcast. It sets `giaddr` to its
receiving interface address if `giaddr` is 0, increments `hops`, and
forwards the message by unicast to each configured server. All configured
servers receive every request from a given client. The servers send
replies to `giaddr` on port 67, and the relay delivers them on the client's
subnet to port 68 (§9). After the client has an address (step 3b unicast,
step 4), its traffic to the boot server and TFTP server is ordinary routed
unicast. For PXE across subnets, the router's forwarding list must include
the PXE server as well as the DHCP server (SRC-024).

## 8. Client timing

- **General DHCP**: randomised exponential backoff starting near 4 seconds,
  doubling, with ±1 second jitter, up to 64 seconds (RFC 2131 §4.1).
- **PXE DISCOVER** (UEFI Appendix E.4.20.1): four tries at 4, 8, 16, and 32
  seconds, a cycle that may repeat up to three times to allow for spanning
  tree delays in switches. When the received offers lack the PXEClient
  tag, the client retries only at the 4- and 8-second points.
- **UEFI DHCP call**: may take at least 31 seconds before reporting a
  timeout. If no valid PXE offer arrives, it reports "no response" (UEFI
  §24.3.8).
- **Link start-up**: network adapter start-up can take about 4 seconds, and
  up to 20 seconds with poor cabling (UEFI Appendix E.4.7).

## 9. Server reply addressing and relay rules

How a server addresses its reply (RFC 2131 §4.1; RFC 1542 §5.4):

1. If `giaddr` ≠ 0, the server sends to `giaddr`, UDP port 67.
2. Otherwise, if `ciaddr` ≠ 0, it unicasts to `ciaddr`, port 68.
3. Otherwise, if BROADCAST is set, it broadcasts to 255.255.255.255, port
   68.
4. Otherwise it unicasts to `yiaddr` and the `chaddr` link address, port
   68. A server that cannot send such a unicast may broadcast instead.

The server keeps the client's BROADCAST flag as it was so that the relay
can act on it (RFC 1542 §5.4).

What the relay agent does with requests (RFC 1542 §4.1.1):

- Relaying is off by default and must be configured.
- The relay drops requests whose `hops` exceeds 16. A lower configurable
  limit is recommended, with a default of 4.
- If `giaddr` is 0, the relay sets it to the receiving interface's address
  and uses one address consistently. It never writes a broadcast address
  there. A non-zero `giaddr` is left alone.
- It increments `hops`, changes nothing else, and does not send a broadcast
  back out the interface it arrived on.
- It sends every request from a given client to the same destination set,
  so per-request round-robin is not allowed.

What the relay agent does with replies (RFC 1542 §4.1.2): it uses `giaddr`
to choose the interface and drops the reply if no interface matches. It
sends to the client on port 68, broadcast if the BROADCAST flag is set and
unicast to `yiaddr`/`chaddr` otherwise. It changes no BOOTP fields.

Relay agent information, option 82 (RFC 3046):

- Relays add it as the last option, with sub-option 1 (circuit ID) and
  sub-option 2 (remote ID). It has no pad and no end marker (§2.0, §3.1,
  §3.2).
- A server that supports it echoes the whole option in its reply,
  preferably last. It never places it in `sname` or `file`. If it does not
  fit, the server sends the reply without it. Servers that do not support
  it ignore it (§2.2).
- The relay removes the option before passing the reply to the client
  (§2.1).
- A relay drops a packet that arrives on an untrusted circuit with
  `giaddr` = 0 but already carries option 82. It also drops a packet whose
  `giaddr` is one of its own addresses (§2.1, §2.1.1).

## 10. Security considerations in these standards

- DHCP has no authentication. The relay-to-server path is assumed to be
  trusted and the client untrusted, and anything that re-broadcasts DHCP
  replies downstream lets any host impersonate a server (RFC 3046 §5).
- Wrong architecture values can make a client fetch and run code meant for
  another platform. The options also reveal platform details to anyone
  watching DHCP traffic (RFC 4578 §5).
- Apart from optional boot-file authentication (BIS), the PXE protocols are
  not secure, and general DHCP protection methods are expected to apply
  (draft-henry §4).
- TFTP security: see `tftp.md` §9.

## 11. Conditional: IPv6 (RFC 5970)

Relevant only if IPv6 boot (INDEX Unconfirmed) is confirmed or decided.
RFC 5970 defines DHCPv6 options 59 (boot file URL), 60 (boot file
parameters), 61 (client system architecture, using the same IANA registry
as §5.2), and 62 (client network interface identifier) (RFC 5970 §3.1 to
§3.4). The boot file is named by URL, and `tftp` URLs are as defined in
RFC 3617 (RFC 5970 §5). Not used in M1.
