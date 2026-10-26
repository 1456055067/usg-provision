# Standards conformance

Open standards implemented, by section, with any deviation. Section
references use the repo summaries in `specs/standards/` (`pxe-dhcp.md`,
`proxy-dhcp.md`, `dhcp-long-options.md`, `tftp.md`, `uefi-guid-text.md`,
`uefi-secure-boot.md`).

Status values:

- **Implemented (in-process)**: code exists and in-process tests pass. No
  firmware has exercised it yet, because boot smoke S1 to S8 are NOT RUN
  (POAM-17).
- **Not implemented**: the relay never uses or acknowledges it.

"Project design" in the Deviation column marks a rule the standards do not
state. It is our choice (OPEN-BOOT-L1 for numbers), not a claim about how
any product behaves.

| Standard | Section | Status | Deviation |
|----------|---------|--------|-----------|
| RFC 2131 | §2 message layout (`pxe-dhcp.md` §3) | Implemented (in-process) | Requests with `htype` other than 1 or `hlen` other than 6 are dropped, so a GUID in `chaddr` is not supported. |
| RFC 2131 | §4.3.1 Table 3, server reply fields (`pxe-dhcp.md` §3.1) | Implemented (in-process) | `yiaddr` is always 0 (ProxyDHCP; decision 0003). `ciaddr` is always 0, which the table allows for ACK and requires for OFFER. Only the BROADCAST bit of `flags` is copied. |
| RFC 2131 | §4.1 reply addressing (`pxe-dhcp.md` §9) | Implemented (in-process) | Step 1 (`giaddr`) and step 3 (broadcast) are followed. **Departure from step 2** (SC-5): a reply goes to `ciaddr`:68 only when `ciaddr` equals the UDP source address; otherwise it is broadcast on port 68. Step 4 is not used: a reply with `yiaddr` 0 cannot be sent to `yiaddr`. |
| RFC 2131 | §4.1, requests on port 67 from outside the interface subnet | Implemented (in-process) | **Project design (SC-5)**, no standard states it. A request on port 67 with `giaddr` 0 from a source outside the receiving interface's subnet is dropped (`off_segment_source`) when `ciaddr` is not that source. When `ciaddr` equals the source and the source is a unicast host, it is answered by unicast to `ciaddr`:68 (step 2), charged to the routed budget, so no broadcast is possible. The follow-up port to a proxy that answered on 67 is unconfirmed (`proxy-dhcp.md` §9), so routed clients with an address are answered on both 67 and 4011. |
| RFC 2131 | Interface subnet used for the rule above | Implemented (in-process); derivation from the Linux routing table is tested on parsed route text only | **Project design (OPEN-BOOT-L1).** The subnet is `interface[i].prefix_len` (8 to 31) or, when absent, the interface's connected route in the Linux routing table at start-up. With neither, start-up is refused. Secondary subnets on the same segment are not covered and are treated as routed. |
| RFC 1542 | §2.1, minimum BOOTP size, receiver check (`pxe-dhcp.md` §3.2) | Implemented (in-process) | Conforms: requests under 300 octets of UDP data are discarded silently and counted (`short_message`). Replies are zero-padded after End to at least 300 octets, a [reading] in `pxe-dhcp.md` §3.2. |
| RFC 1542 | §4.1.1 hops limit | Implemented (in-process) | Project design: the relay, acting as the server, drops requests with `hops` above 16, the relay-agent limit. |
| RFC 1542 | §5.4 BROADCAST flag kept in replies | Implemented (in-process) | None. |
| RFC 2132 | §2 encoding; §9.3 overload; §9.6 message type; §9.7 server identifier; §9.10 maximum message size; §9.13 vendor class (`pxe-dhcp.md` §4, §5.1) | Implemented (in-process) | Reply limit is 548 octets of DHCP message, or option 57 minus 28 (at most 1472) when option 57 is at least 576. Accepted request size is 300 to 1472 octets. |
| RFC 3396 | Long and repeated options (`dhcp-long-options.md` §2, §3, §4, §6, §7) | Implemented (in-process) | Only the 11 options the relay reads are joined. The relay never splits an option when it sends, so a joined option 82 longer than 255 octets is not echoed. |
| RFC 3046 | §2.2 option 82 echo (`pxe-dhcp.md` §9) | Implemented (in-process) | None: echoed unchanged as the last option, omitted when it does not fit. |
| RFC 4578 | §2.1 architecture (erratum 4624: 7 = x64), §2.2 interface identifier, §2.3 machine identifier (`pxe-dhcp.md` §5.2 to §5.5) | Implemented (in-process) | Architecture 7 only in M1 (decision 0004). Option values are project design (`pxe-dhcp.md` §5.5): 93 = 7; 94 = the client's value echoed, else type 1, version 3.0; 97 = the client's value echoed, else type 0 with the nil GUID. |
| PXE vendor options | Option 43, tag 71 boot item (`pxe-dhcp.md` §6, §6.1) | Implemented (in-process) | **No option 43 in OFFERs**: the relay relies on option 43 being optional for UEFI clients (UEFI E.4.20.3). Tag 71 is accepted only as exactly 4 octets, and only type 0, layer 0, no credentials is answered; the ACK echoes it. Byte order and reply contents (OPEN-T71-1, OPEN-T71-2) must be resolved before any other boot item is supported. |
| UEFI | Appendix E.4.20.2, boot server in `siaddr` | Implemented (in-process) | None. |
| ProxyDHCP | `proxy-dhcp.md` §2, §3, §4.1, §4.3 (proxy on its own host; ports 67 and 4011) | Implemented (in-process) | §4.2 co-hosting with a DHCP server is not supported (REQ-BOOT-014 is OPEN). DISCOVER on port 4011 is dropped. |
| RFC 1350 | §1 to §7 (`tftp.md` §1 to §5) | Implemented (in-process) | **Octet mode only** (REQ-BOOT-030): `netascii` and `mail` are refused with ERROR 4. **Read only**: WRQ gets ERROR 2. Errors are sent from a new TID. On a transfer socket, a datagram of at least 4 octets with opcode 5 from the client TID ends the transfer even if its message is not terminated; the port 69 parser stays strict. No ERROR is sent when the retry cap is reached. |
| RFC 1350 | §5 16-bit block numbers (`tftp.md` §8; REQ-BOOT-035) | Implemented (in-process) | **Refuse rather than wrap**: a file needing more than 65535 blocks at the negotiated size, or larger than `tftp.max_file_size_bytes`, is refused with **ERROR 3 before any OACK or DATA**. ERROR 3 is our choice of code, by analogy with RFC 2349 tsize. Block-number wrap is not implemented. |
| RFC 1123 | §4.2.3.1 Sorcerer's Apprentice fix (`tftp.md` §5) | Implemented (in-process) | None. |
| RFC 1123 | §4.2.3.2 adaptive timeout (`tftp.md` §5) | Implemented (in-process) | RTO is SRTT + 4 × RTTVAR with Karn's rule and doubling, clamped to the configured minimum and maximum. Before the first ACK the relay also applies the handshake deadline (`tftp.handshake_timeout_ms`, default 2000 ms, project design), which covers file verification as well; on expiry the request is dropped silently. |
| RFC 1123 | §4.2.3.4 path control (`tftp.md` §9) | Implemented (in-process) | Only names published in the manifest are served, matched byte for byte. |
| RFC 1123 | §4.2.3.5 broadcast requests ignored (`tftp.md` §9) | Implemented (bind plan only) | Port 69 is bound to the interface's unicast address. The live check (S4) is NOT RUN. |
| RFC 2347 | Option negotiation (`tftp.md` §6) | Implemented (in-process) | None: names case-insensitive, only requested options acknowledged, no OACK when none is accepted. |
| RFC 2348 | `blksize` (`tftp.md` §7) | Implemented (in-process) | Granted size is at most the request and at most `tftp.max_block_size` (default 1468, project design). |
| RFC 2349 | `tsize` (`tftp.md` §7) | Implemented (in-process) | `tsize` is answered only for a read request of 0. **No `timeout` option**: it is never acknowledged, which the RFC allows. |
| RFC 7440 | `windowsize` (`tftp.md` §10) | Not implemented | **No windowsize**: never acknowledged. |
| UEFI | GUID text form (`uefi-guid-text.md` §1 to §3) | Implemented (in-process) | Used for suppression-file GUIDs, case-insensitive. The nil GUID is refused in the suppression file (project design). §4 (SMBIOS) is not used. |
| UEFI | Secure Boot (`uefi-secure-boot.md`) | Not evidenced | The relay serves the program unchanged and never disables or works around the firmware check. The proof (M1 exit 5, S5) is NOT RUN. |
| Audit timing | `boot.file.verify_slow` interval | Implemented (in-process) | **Project design**: at most one event per published file per 60 s, with the count of suppressed timeouts. No standard or spec gives an interval. |

## Document Change History

| Date | Change |
|------|--------|
| 2026-10-26 | M1 final pass (QA report FP.8): rows for the port 67 off-subnet rule, the interface subnet, the 300-octet receiver check and the `boot.file.verify_slow` interval moved from QA re-verify pending to Implemented (in-process). |
| 2026-10-26 | M1: added DHCP, ProxyDHCP, PXE, TFTP and UEFI sections implemented by the relay, with deviations: no `timeout` option, no windowsize, no option 43 in OFFERs, refuse rather than wrap, octet only with ERROR 4, ERROR 3 before OACK, `ciaddr` departure from §4.1 step 2, the off-subnet port 67 rule and the derived-prefix rule as project design, the 300-octet receiver check (now conforming) and the `boot.file.verify_slow` interval. |
