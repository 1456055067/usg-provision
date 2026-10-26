# Standards summary: long and repeated DHCPv4 options (RFC 3396)

This summary is in our own words, written for implementers. Field names,
option codes and constants are as the standards define them. Source IDs
(SRC-nnn) refer to the provenance log. Clean-side readers need only the
citations given here.

Primary sources: RFC 3396 (encoding long options), RFC 2131 §4.1 and
§4.3.1, RFC 2132 §2, §8.4, §9.3, §9.8, §9.13, RFC 3046 §2.1 and §2.2,
RFC 4578 §2, and two later option RFCs that opt in to RFC 3396 (RFC 3397,
RFC 3925).

Companion file: `pxe-dhcp.md`, which covers message layout (§3), option
encoding (§4) and the PXE-relevant options (§5, §6).

Points marked **[reading]** are our own inference from the cited text. The
standards do not state them outright.

## 1. Why options repeat

Every DHCPv4 option other than Pad (0) and End (255) has a one-octet length,
so a single instance carries at most 255 octets of data (RFC 2132 §2;
RFC 3396 §1). An option appears more than once in one message in two cases
(RFC 3396 Abstract, §4):

- its value is longer than 255 octets, or
- it fits in no single remaining space, but there is room if it is split
  across the options area and the overloaded `file`/`sname` fields.

RFC 2131 §4.1 had said that options appear only once unless their
definition allows otherwise, and that a client joins the values of repeated
instances. It did not say in what order. RFC 3396 updates RFC 2131: it fixes
the order, and it removes the "only once" rule (RFC 3396 §1).

## 2. The aggregate option buffer (RFC 3396 §5)

Think of the option space as one logical buffer formed by joining, in this
order:

1. the `options` field (after the magic cookie),
2. the `file` field, only if option 52 says it carries options,
3. the `sname` field, only if option 52 says it carries options.

This is the logical order. It is not the physical order of the fields in
the packet, where `sname` comes before `file` (RFC 3396 §5; `pxe-dhcp.md`
§3). The order matches the parsing order in RFC 2131 §4.1 and RFC 2132
§9.3: `options` first, then `file`, then `sname`.

- Option 52 (overload): 1 means `file` carries options, 2 means `sname`
  does, 3 means both (RFC 2132 §9.3). The receiver reads the `options`
  field first and only then the fields that option 52 names (RFC 2132 §9.3;
  RFC 2131 §4.1). **[reading]** Option 52 must therefore be found in the
  `options` field itself, because it decides whether the other fields are
  read as options at all.
- A field that is not overloaded is not part of the buffer, and its
  contents (a boot file name or server name) are not options (RFC 3396 §5).
- No single option instance may cross the boundary between two fields. A
  split, however, may put consecutive pieces in different fields
  (RFC 3396 §5, §6).

## 3. Receiver rules (decoding)

From RFC 3396 §4 and §7:

- **Any repeated code is a split option.** When two or more instances with
  the same code appear anywhere in the aggregate buffer, the receiver
  treats them as pieces of one option.
- **Reassemble in buffer order.** The receiver joins the pieces' data in the
  order they occur in the aggregate buffer (§2 above). The result is a
  single option whose length is the sum of the pieces' lengths, and the
  receiver interprets that, not the separate pieces.
- **Split points mean nothing.** A sender may split at any octet, and the
  position of a split carries no meaning. A receiver must not attach any
  meaning to where the pieces start and end (RFC 3396 §6, §7). For an option
  that holds structured data, such as the sub-options of option 43 or 82, a
  sub-option can be cut in two across pieces, so the receiver must parse
  sub-options only after reassembly **[reading]**.
- **No alignment.** Senders do not align options, so receivers must not
  assume that a value starts on any particular boundary (RFC 3396 §7).
- **Who must reassemble.** A receiver must join same-code options,
  whatever the option (RFC 3396 §4). Any implementation that supports at
  least one concatenation-requiring option (§5 below) must be able to
  reassemble both that kind and ordinary options on receipt (RFC 3396 §4).
- **Validate after reassembly.** Length checks in an option's own
  definition, such as "even and non-zero" for option 93 or "exactly 17"
  for option 97, apply to the reassembled value, not to each piece
  **[reading]**, following RFC 3396 §7, which says the joined result is the
  one option.

## 4. Sender rules (encoding)

From RFC 3396 §4 and §6:

- A sender that has to send a value longer than 255 octets, or one that
  fits only when split, must either split it as described here or leave the
  option out (§4).
- To split, cut the value at any octet into pieces of at most 255 octets.
  Encode each piece as an ordinary option with the same code, and place the
  pieces in order in the aggregate buffer. The pieces' lengths must add up
  to the full value's length (§6).
- A sender must not encode meaning in the split points (§6).
- **Be conservative.** Many deployed DHCP agents cannot reassemble, so a
  sender should not split an option unless it has no alternative or knows
  the peer can reassemble (§4). The peer is presumed able to do so if it has
  sent or requested at least one concatenation-requiring option, or if an
  administrator has configured that (§4).
- The other ways to gain room are option 52 overload (RFC 2132 §9.3) and a
  larger message size, which the client advertises in option 57 (minimum
  576; RFC 2132 §9.10; `pxe-dhcp.md` §3). Both are limited by what the
  client accepts.

## 5. Which options this applies to

- **On receipt, every option.** The decoding rule in §3 applies to any code
  that appears more than once (RFC 3396 §7).
- **Concatenation-requiring options.** An option is concatenation-requiring
  only if its own defining document explicitly refers to RFC 3396
  (RFC 3396 §4). Examples confirmed in this run:
  - option 119, domain search list (RFC 3397 §2), and
  - options 124 and 125, vendor-identifying vendor class and vendor-specific
    information (RFC 3925 §2, §3, §4).
- **The options used in PXE boot are not concatenation-requiring.** RFC 2132
  (options 43, 55, 60), RFC 4578 (93, 94, 97) and RFC 3046 (82) do not refer
  to RFC 3396. RFC 2132 and RFC 3046 predate it, and RFC 4578 has no
  reference to it (RFC 4578, normative references). Their repeats are still
  reassembled on receipt (§3), but a sender should not split them unless the
  conditions in §4 hold.
- RFC 3925 §1 notes a side effect: because repeats are joined, a client
  cannot use several copies of option 60 or 43 to express several
  independent vendor identities. The copies merge into one value. RFC 3925
  adds options 124 and 125 for that purpose.

## 6. Interaction with the PXE-relevant options (`pxe-dhcp.md` §5, §6)

All the options below fit in a single instance in ordinary PXE traffic.
The notes describe what follows if a peer does split or repeat one.

| Option | Normal size | Effect of RFC 3396 |
|--------|-------------|--------------------|
| 43 vendor-specific information | variable; PXE sub-options (`pxe-dhcp.md` §6) | Reassemble first, then parse sub-options from the joined value. A sub-option may straddle pieces. The sub-option list ends at sub-option 255 or at the end of the joined value (RFC 2132 §8.4). A server whose PXE sub-options (for example a long boot menu, tag 9) exceed 255 octets would have to split option 43. By §4 it should do so only if the client is known to reassemble. Whether PXE client firmware reassembles option 43 is not stated in RFC 4578, draft-henry, or UEFI 2.10 chapter 24 (see Open points). |
| 55 parameter request list | one octet per requested code | Pieces are joined into one list. The order of codes is the client's preference order, and the server should try to insert the requested options in that order (RFC 2132 §9.8). |
| 60 vendor class identifier | short string | Pieces are joined into one string, so a check for the `PXEClient` prefix must look at the joined string. Two copies cannot express two classes (RFC 3925 §1). |
| 82 relay agent information | variable; sub-options 1 and 2 (`pxe-dhcp.md` §9) | The relay adds it as the last option in the `options` field and must not use `sname` or `file`, or add option 52, to make room. If adding it would make the packet too large, the relay forwards the packet without it (RFC 3046 §2.1). The server echoes it, preferably last, never in `sname` or `file`, and leaves it out if it does not fit (RFC 3046 §2.2). RFC 3046 §2.1 also says a relay does not add a second copy when a trusted element has already added one. If two copies did arrive, RFC 3396 would join them. |
| 93 client system architecture | 2n octets | Reassemble, then check that the length is even and non-zero (RFC 4578 §2.1). |
| 94 client network interface identifier | 3 octets | Reassemble, then check the length (RFC 4578 §2.2). |
| 97 client machine identifier | 17 octets (type 0, GUID) | Reassemble, then check the type and length (RFC 4578 §2.3). For the GUID's byte order and text form, see `uefi-guid-text.md`. For when 93, 94 and 97 must be present, see `pxe-dhcp.md` §5.5. |

Option 52 is never split. It is one octet long and decides whether `file`
and `sname` belong to the buffer (§2).

When `file` or `sname` is overloaded, the boot file name and server name
travel in options 67 and 66 instead (RFC 2132 §9.4, §9.5; `pxe-dhcp.md`
§3). Like other options, those options may be repeated and joined.

## 7. Options a server does not need

What a server may do with options it does not use:

- **Skip by length.** Every option except 0 and 255 has a length octet, so a
  receiver can step over any code it does not recognise (RFC 2132 §2).
- **Ignore unknown vendor data.** A server that cannot interpret a client's
  vendor class (option 60) or vendor-specific information (option 43) must
  ignore it, though it may report it (RFC 2132 §8.4, §9.13).
- **Ignore unsupported relay information.** A server that does not support
  option 82 ignores it and does not echo it (RFC 3046 §2.2).
- **Ignore client hints.** A server may ignore options that a client sends
  as hints for requested values (RFC 2131 §3.5).
- **Return only what it has.** In replies the server includes as many
  requested parameters as it can, leaves out those it cannot supply, and
  must not return a value for a parameter it neither has configured nor
  knows a default for (RFC 2131 §4.3.1). It may add parameters the client
  did not request (RFC 2131 §4.3.1). It must not include option 55 in a
  reply (RFC 2131 Table 3).
- **Reassembly of discarded options.** **[reading]** RFC 3396 requires
  reassembly before an option's value is interpreted. A server that only
  skips an option, and never interprets or echoes it, observes no
  difference whether it joins the pieces or not. Options the server does
  interpret or echo (for example 82) must be handled as joined values.

## 8. Security considerations

- RFC 3396 adds no new threats (RFC 3396 §9). The existing ones are in
  RFC 2131 §7 and in `pxe-dhcp.md` §10.
- The authentication option (RFC 3118) may itself be split. When computing
  or checking its MAC, an implementation must zero the authentication
  field correctly in every piece (RFC 3396 §9). This is background only:
  `pxe-dhcp.md` does not use that option.
- **[reading]** A reassembled option can be longer than 255 octets, up to
  the total option space of the message (§2). A piece whose length octet
  runs past the end of the field that holds it is malformed, because no
  single instance may cross a field boundary (RFC 3396 §5, §6).

## 9. Open points

- **OPEN-LONG-1**: Do common UEFI PXE clients reassemble a split option 43
  or option 60? No primary source read in this run (RFC 4578, draft-henry,
  UEFI 2.10 chapter 24) says so. Until this is answered, the conservative
  sender rule in §4 applies: keep each PXE option within one instance of
  255 octets.
