# Standards summary: ProxyDHCP and PXE boot-server discovery

Topic 2 of the standards reading list. The project decided that its boot
service never assigns addresses (`specs/boot-network.md` REQ-BOOT-010,
DEC-0003), so
this topic no longer depends on that open question. This file describes
only what the standards and public references say. It makes no design
choices.

**Source caveat:** the defining text is the Intel PXE 2.1 specification
(1999). No public, login-free copy could be retrieved during this run. The
UEFI Forum's related-documents page links to a third-party copy, which did
not respond. What follows comes from:

- the Intel PXE Internet-Draft `draft-henry-remote-boot-protocol-00`
  (June 1999, expired; SRC-018);
- UEFI 2.10 Appendix E (glossary and E.4.20 clarifications of PXE 2.1;
  SRC-019) and §24.3 (SRC-020);
- Microsoft Learn troubleshooting article for KB 259670 (SRC-024);
- secondary references: Wikipedia's PXE article, which cites PXE 2.1 for
  the two-server arrangement (SRC-033); a public blog post on discovery
  control (SRC-034); the iPXE project's public commit message on discovery
  control (SRC-035); and IBM's public AIX DHCP documentation (SRC-036).

Statements resting only on secondary sources are marked **[secondary]**.

## 1. Purpose

Primary sources say only this much:

- draft-henry §3 presents ProxyDHCP as an optional arrangement for cases
  where the DHCP service cannot itself answer PXE-specific requests, and
  leaves the details of its use out of scope. The proxy answers **only PXE
  clients**, and it may run on the DHCP server's host or on a separate host.
- The UEFI Appendix E glossary describes ProxyDHCP as a way to make PXE
  easier to fit alongside existing DHCP.

That the site DHCP server goes on assigning addresses while the proxy
supplies only boot information is stated by SRC-033 **[secondary]**, which
cites PXE 2.1. The primary text was not available to confirm it (§9).

## 2. Division of work

| Server | Supplies | To whom |
|--------|----------|---------|
| Site DHCP server | IPv4 address, subnet mask, router, lease, other site options | all DHCP clients |
| ProxyDHCP | boot-file server and boot program name, and/or PXE boot-server discovery information | PXE clients only |

(SRC-033 **[secondary]**, citing PXE 2.1; SRC-034 **[secondary]**.)

## 3. What a proxy reply contains

From the sources above:

- It marks itself as PXE-aware with option 60 = `PXEClient`
  (draft-henry §3.1.2; UEFI Appendix E.4.20.1).
- It names itself in option 54 (server identifier). The client uses this to
  address later unicast messages, and as the boot-file server only if
  `siaddr` is not set (RFC 2132 §9.7; UEFI Appendix E.4.20.2).
- It carries PXE information in one or both of these forms:
  - a boot program name in `file` (or option 67) and a boot-file server in
    `siaddr`, usually with discovery control set so that the client
    downloads that file directly (`pxe-dhcp.md` §6, §7 step 3a;
    **[secondary]** SRC-034, SRC-035);
  - PXE sub-options in option 43 (discovery control, boot-server list,
    menu, prompt) that send the client into boot-server discovery (§6
    below; draft-henry §3.2.3).
- PXE clients and servers include option 93 (and options 94 and 97 on the
  client side) in PXE messages (RFC 4578 §2.1 to §2.3).

## 4. Ports

### 4.1 Proxy on a different host from the DHCP server

A client without an address broadcasts its DHCPDISCOVER to server port 67
(RFC 2131 §4.1; `pxe-dhcp.md` §2). A proxy on another host on the same
segment therefore receives it on that port. Its reply then reaches the
client next to the DHCP server's offer, as in the two-server arrangement
of §2 (SRC-033 **[secondary]**). With a relay agent, the proxy is
reached only if the relay forwards to it too, because the relay sends to
its configured list of servers (SRC-024; RFC 1542 §4.1.1). Replies are
addressed according to `pxe-dhcp.md` §9.

### 4.2 Proxy on the same host as the DHCP server

A DHCP server already occupies port 67 on its host, so a proxy placed on
that same host is reached on **UDP 4011** instead (SRC-033
**[secondary]**; SRC-036). Here the DHCP server's offer includes option
60 = `PXEClient`, and the client takes that as its cue to fetch the PXE
information from port 4011 of the same server.

SRC-024 covers the failure case. The offer carries option 60 and also
names a boot server and boot file (options 66 and 67), but nothing on that
host is listening on port 4011. Clients then report that no ProxyDHCP
reply came. SRC-024 traces those port-4011 failures to this setup. As a
matter of support, it rules out redirecting PXE clients by configuring
options 60, 66 and 67 on a DHCP server.

### 4.3 Boot-server discovery requests

Boot-server requests go multicast or unicast to port 4011, or broadcast to
port 67 (draft-henry §3.3.1).

## 5. Interaction with the site DHCP server

- When a separate proxy serves the segment, the site DHCP server needs no
  PXE configuration (SRC-033 **[secondary]**; not confirmed from a primary
  source, see §9). draft-henry §3 supports only the narrower point that
  the proxy covers PXE requests the DHCP service cannot answer.
- Setting option 60 = `PXEClient` (with or without options 66 and 67) on a
  DHCP server that does not run a PXE service changes client behaviour
  (§4.2). Microsoft's guidance is to remove those options and instead add
  the PXE server to the router's DHCP forwarding (IP helper) list for
  cross-subnet use (SRC-024).
- A DHCP server's offer can itself carry discovery control so that the
  client boots the file that server named and does not look further for
  proxies or boot servers (SRC-034 **[secondary]**). *Unconfirmed
  inference, not stated by SRC-034:* a site set up this way might keep PXE
  clients from using a separate proxy.
- The client gets its address only from a DHCP offer. Section 7 of
  `pxe-dhcp.md` gives the full sequence.
- Microsoft's article lists the offer combinations a PXE client
  distinguishes: DHCP and boot information in a single offer, or an
  address-only DHCP offer combined with a separate proxy boot server
  (SRC-024).

## 6. Boot-server discovery

Sources: draft-henry §3.2.3, §3.3; UEFI §24.3.9; Appendix E.4.20.3.

- **Server types and layers**: discovery asks for a boot-server *type*
  (tag 71). The initial layer is 0, and further layers fetch further files
  or credentials. Only the initial layer may use multicast or broadcast,
  and later layers are unicast only (UEFI §24.3.9).
- **Order** (draft-henry §3.3.1): multicast to the tag-7 address (port
  4011), then broadcast (port 67), then unicast to each tag-8 server (port
  4011). Each step runs only if discovery control allows it:
  - bit 0 set: no broadcast;
  - bit 1 set: no multicast;
  - bit 2 set: accept only servers in tag 8.
- **Server list in the client** (UEFI §24.3.9): a list of servers supplies
  the unicast targets and, in list-only mode, limits which replies the
  client accepts (any server of a type, or only listed addresses).
- **Reply**: the boot server answers with a DHCPACK holding the boot file
  name in `file` and the tag 71 it is answering (draft-henry §3.3.2).
- **Menus and prompts** (tags 9 and 10): optional. Prompt timeout 0 picks
  the first item at once, 255 waits indefinitely, and with no prompt option
  the menu shows without a timeout (draft-henry §3.2.3.5). Tag 9 is
  required only if a menu is to be shown (UEFI Appendix E.4.20.3).
- **Timeout**: the UEFI discovery call may take at least 10 seconds before
  timing out (UEFI §24.3.9).

## 7. More than one PXE responder

The standards do not coordinate several proxies or boot servers on one
segment. The client gathers offers and either tries them in the order they
arrived or sorts them (UEFI §24.3.8), and it prefers PXE-tagged offers
(draft-henry §3.1.2). Which responder "wins" is therefore decided by the
client.

## 8. Security notes

- ProxyDHCP and boot-server discovery carry no authentication apart from
  optional boot-file credentials (BIS, tags 12 and 71 with the credentials
  bit). Any host on the segment can answer as a proxy (draft-henry §4).
- RFC 3046 §5 and RFC 4578 §5 apply as summarised in `pxe-dhcp.md` §10.

## 9. Not confirmed from a primary source

These need the PXE 2.1 text and are not established here:

- that the site DHCP server keeps assigning addresses while the proxy
  supplies only boot information (§1, §2), and that the site DHCP server
  needs no PXE configuration when a proxy is present (§5). Both rest on
  SRC-033 **[secondary]** only;
- any normative statement that a proxy reply must leave `yiaddr` at zero.
  The sources consistently say the proxy assigns no address (§2), but the
  exact field rule was not available;
- the exact port the client uses for a follow-up request to a proxy that
  answered on port 67;
- the full set of multicast TFTP tags below 6.
