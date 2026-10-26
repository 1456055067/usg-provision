# Standards summary: TFTP for network boot

Topic 3 of the standards reading list. This is our summary of RFC 1350
(TFTP revision 2), RFC 1123 §4.2 (host requirements for TFTP), RFC 2347
(option extension), RFC 2348 (blksize), RFC 2349 (timeout, tsize), and,
**conditionally**, RFC 7440 (windowsize). Whether options are used is a
clean-side decision. `specs/boot-network.md` REQ-BOOT-031 requires only that
requests with and without options both work.

## 1. Model (RFC 1350 §1, §2, §3)

- TFTP runs over UDP. It reads and writes files only: no directory listing
  and no authentication.
- Data moves in blocks, 512 octets by default. Each block must be
  acknowledged before the next is sent (lock-step), so the sender keeps one
  packet for retransmission.
- A data block shorter than the block size, including 0 octets, ends the
  transfer.
- Each side picks a transfer identifier (TID), which is used as its UDP
  port. TIDs range from 0 to 65535.

## 2. Starting a transfer (RFC 1350 §4)

- The client sends a read (RRQ) or write (WRQ) request to server port 69
  from a TID it chose.
- The server replies from a new TID of its own choosing. From then on both
  ends use that pair.
- A read request is answered with DATA block 1 (or with an OACK if options
  were accepted; §6). A write request is answered with ACK block 0 (or an
  OACK).
- A packet that arrives from an unexpected TID is discarded. The receiver
  sends an ERROR (code 5, unknown transfer ID) to that source, and the
  transfer in progress carries on undisturbed. This is the only error that
  does not end a transfer (RFC 1350 §2, §4).

## 3. Packet formats (RFC 1350 §5)

All fields are in network byte order. Strings are octet sequences ending in
a zero octet.

| Opcode | Type | Layout |
|--------|------|--------|
| 1 | RRQ | opcode (2) · filename · 0 · mode · 0 · [options; §6] |
| 2 | WRQ | opcode (2) · filename · 0 · mode · 0 · [options] |
| 3 | DATA | opcode (2) · block # (2) · 0 to blocksize octets of data |
| 4 | ACK | opcode (2) · block # (2) |
| 5 | ERROR | opcode (2) · error code (2) · message · 0 |
| 6 | OACK | opcode (2) · option · 0 · value · 0 · … (RFC 2347) |

- The first data block is number 1, and numbers go up by one. An ACK
  carries the number of the block it acknowledges. ACK 0 is used for WRQ
  and for confirming an OACK on a read (RFC 2347).
- **Modes**: `netascii` and `octet`, matched case-insensitively. `mail` is
  obsolete and should not be supported (RFC 1350 §1; RFC 1123 §4.2.2.1).
  Boot files are binary and use `octet`.
- RFC 1123 §4.2.2.2 corrects RFC 783's definition of the UDP length field:
  the length includes the 8-octet UDP header.

## 4. Error codes (RFC 1350 Appendix; RFC 2347)

| Code | Meaning |
|------|---------|
| 0 | not defined (see message text) |
| 1 | file not found |
| 2 | access violation |
| 3 | disk full or allocation exceeded |
| 4 | illegal TFTP operation |
| 5 | unknown transfer ID |
| 6 | file already exists |
| 7 | no such user |
| 8 | option negotiation failed; terminate (RFC 2347) |

An ERROR packet is neither acknowledged nor retransmitted. It is a courtesy
and may be lost, so both sides still need timeouts (RFC 1350 §2, §7).

## 5. Timeouts, retransmission, termination

- **Retransmission** (RFC 1350 §2): lost packets are recovered by timeout
  and retransmission of the last packet sent.
- **Adaptive timeout** (RFC 1123 §4.2.3.2, required): the timeout must
  adapt, using TCP's methods as a model, and must at least back off
  exponentially.
- **Sorcerer's Apprentice Syndrome** (RFC 1123 §4.2.3.1, required fix):
  when an ACK is delayed rather than lost, the sender's timeout resends the
  block. Both copies are then acknowledged, and if the sender answers each
  duplicate ACK with the next block, every later block is sent twice, and
  this compounds. The required fix is that **a sender must not retransmit
  its current DATA packet when it receives a duplicate ACK**. Only its timer
  triggers a resend. The receiver's retransmission timer then becomes
  optional, though keeping it is harmless.
- **Retry cap**: RFC 7440 §6 says implementations should limit
  retransmission attempts and abort the transfer when the limit is reached.
  RFC 1350 §6 already lets the sender give up on the final block after a
  timeout. RFC 1350 sets no number for the cap.
- **Normal end** (RFC 1350 §6): the last DATA packet carries fewer octets
  than the block size (0 to 511 by default). The sender retransmits it until
  it is acknowledged or the sender gives up. The receiver should wait a
  short while after sending its final ACK ("dally") so that it can resend
  that ACK if it sees the last DATA again. If a file is an exact multiple of
  the block size, the sender adds a final DATA packet of 0 octets (RFC 2348).
- **Premature end** (RFC 1350 §7): an ERROR packet, or a timeout.

## 6. Option negotiation (RFC 2347)

- Options follow the mode string in RRQ/WRQ as null-terminated
  name/value pairs in any order. Names and values are case-insensitive. The
  whole request must not exceed 512 octets.
- A server that supports options may answer with an **OACK** (opcode 6)
  listing only the options it accepts, each with its accepted value. It
  must not add options the client did not ask for. Unsupported options are
  left out silently. Each option's own RFC says how invalid values are
  handled.
- Options not acknowledged are ignored by both sides.
- **Client confirms**: on a read it sends ACK 0, and on a write it sends
  DATA 1 using the negotiated values. To reject, it sends ERROR 8 and the
  transfer ends. An OACK that contains an option the client did not
  request should be rejected with ERROR 8.
- **Server without option support**: it ignores the options and answers
  plainly with DATA 1 or ACK 0. If a server answers an option-bearing
  request with an error, the client may retry without options.
- **No OACK** is sent when the server supports none of the requested
  options.

## 7. Defined options

| Option | RFC | Value | Rules |
|--------|-----|-------|-------|
| `blksize` | 2348 | 8 to 65464 octets (data only, excluding the 4-octet header) | The server may reply with a value no larger than the request. The client must use the OACK value or abort with ERROR 8. The transfer ends on a block shorter than the negotiated size. Worked example: 1428 = Ethernet MTU minus IP, UDP, and TFTP headers. Blocks larger than the path MTU cause IP fragmentation. |
| `timeout` | 2349 | 1 to 255 seconds | Retransmission timeout requested by the client. If the server accepts it, the OACK must carry the same value. A server that does not accept it leaves it out. |
| `tsize` | 2349 | file size in octets (ASCII decimal) | On a read the client sends 0, and the server returns the file's size in the OACK. On a write the client sends the size, and the server may abort with ERROR 3 if the file is too large. A client may abort a read with ERROR 3 if the file is too large for it. |
| `windowsize` | 7440 (**conditional**) | 1 to 65535 blocks | See §10. |

UEFI firmware relevance: UEFI's TFTP read path can ask for a file's size
before reading, and recommends doing so for large files, because without
option support the whole file has to be downloaded just to learn its size
(UEFI 2.10 §24.3.10). If the buffer is too small, the firmware reports that
and, where the server supports options, returns the file size.

## 8. Numeric limits

| Item | Limit | Source |
|------|-------|--------|
| Default block size | 512 octets | RFC 1350 §2 |
| Negotiated block size | 8 to 65464 octets | RFC 2348 |
| Request packet size with options | ≤ 512 octets | RFC 2347 |
| Timeout option | 1 to 255 s | RFC 2349 |
| Window size option | 1 to 65535 blocks | RFC 7440 §3 |
| Block number | 16-bit, starting at 1 | RFC 1350 §5 |
| TID / port | 0 to 65535 | RFC 1350 §3 |
| Server well-known port | 69 | RFC 1350 §4 |

**Largest file without block-number wrap**: 65535 blocks × block size, for
example about 32 MiB at 512 octets or about 4 GiB at 65464 octets. None of
these RFCs defines what happens when the block number wraps past 65535.
Behaviour beyond that point is not standardised (RFC 7440 also leaves
rollover unaddressed). See `specs/boot-network.md` REQ-BOOT-035.

## 9. Security considerations

- TFTP has no login or access control. The server process should have only
  the rights it needs. Typical deployments serve only publicly readable
  files and do not allow writes (RFC 1350 Security Considerations).
- Servers should let the administrator control which paths can be accessed
  (RFC 1123 §4.2.3.4, recommended).
- Requests sent to a broadcast address should be ignored silently, because
  directed broadcasts to arbitrary networks could open a security hole (RFC
  1123 §4.2.3.5, recommended).
- RFC 2348, RFC 2349 and RFC 7440 add no security and no new risks. RFC
  7440 §7 notes that servers in boot environments may impose throughput
  limits and that TFTP offers no protection against on-path attackers.

## 10. Conditional: windowsize (RFC 7440)

Read this only if the clean side decides to support it. No source covers
transfer tuning.

- Negotiated like the other options. The server's value must be no larger
  than the client's, and the client uses it or aborts with ERROR 8 (§3).
- The sender sends `windowsize` consecutive blocks and then waits for one
  ACK, for the last block of the window. The receiver ACKs that last block
  (§4).
- On a gap or an out-of-order block, the receiver should ACK the last block
  it received in sequence, and the sender restarts the window from the
  block after it. On a timeout, the sender restarts from the block after the
  last ACK it received (§4).
- **End of transfer.** RFC 7440 §3 says the rules for recognising the
  final packet are unchanged from RFC 1350 and RFC 2348. So, as in RFC
  1350 §6 (§5 above), the transfer ends with a DATA block shorter than the
  negotiated `blksize`, including a 0-octet block when the file is an exact
  multiple of `blksize`. The window that contains that short block may
  hold fewer than `windowsize` blocks (and does when the file is smaller
  than one window, §3).
- **[reading]** **Do not use window fill as the end test.** §3 also
  describes the final window as one received with fewer blocks than
  `windowsize`. Read alone, that sentence misses a final window that
  happens to be full (the block count, including any 0-octet block, is a
  multiple of `windowsize`), and a window can also be short mid-transfer
  after loss (§4 figure). The short DATA block is the condition to act
  on; window size is not.
- **[reading]** The receiver ACKs the short final block even if the window
  is not full, since it is the last block of the last window (§4 requires
  an ACK for the last block of each window; RFC 7440 does not state the
  short-window case separately). The RFC 1350 §6 dally and final
  retransmission rules then apply.
- `windowsize` = 1 must behave exactly like RFC 1350 lock-step (§4).
- Choose values conservatively (§5). Follow the UDP rate guidance in RFC
  5405 §3.1, and cap retries (§6).
