//! Negative tests: every RFC length and option limit for incoming DHCP
//! messages (plan §10.2, DHCP list; one test per item).
//!
//! Each malformed message must yield a drop decision, never a reply.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), SA-11 (Developer
//   Testing and Evaluation)
// - SPEC: specs/boot-network.md#REQ-BOOT-006

use std::net::{Ipv4Addr, SocketAddrV4};

use usgp_dhcp::craft::RequestBuilder;
use usgp_dhcp::reply::{ProxyReply, inspect_reply};
use usgp_dhcp::{
    BootItem, BootPolicy, ClientArch, Decision, DropReason, Guid, ListenPort, MacAddr, ParseError,
    ReplyKind, ResponderContext, handle, parse_request,
};

const SERVER: Ipv4Addr = Ipv4Addr::new(10, 20, 1, 2);

struct Policy;

impl BootPolicy for Policy {
    fn boot_program(&self, arch: ClientArch) -> Option<&[u8]> {
        (arch == ClientArch::X64_UEFI).then_some(&b"usgp-test-payload.efi"[..])
    }
    fn is_suppressed(&self, _mac: MacAddr, _guid: Option<Guid>) -> bool {
        false
    }
    fn is_local_address(&self, addr: Ipv4Addr) -> bool {
        addr == SERVER
    }
}

fn ctx() -> ResponderContext {
    ResponderContext {
        server_addr: SERVER,
        port: ListenPort::Dhcp67,
        source: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 68),
    }
}

fn decide(bytes: &[u8]) -> Decision {
    handle(bytes, &ctx(), &Policy)
}

fn assert_malformed(bytes: &[u8], want: ParseError) {
    assert_eq!(parse_request(bytes), Err(want));
    assert_eq!(decide(bytes), Decision::Drop(DropReason::Malformed(want)));
}

fn assert_drop(bytes: &[u8], want: DropReason) {
    assert_eq!(decide(bytes), Decision::Drop(want));
}

fn assert_replies(bytes: &[u8]) {
    let d = decide(bytes);
    assert!(matches!(d, Decision::Reply(_)), "expected a reply: {d:?}");
    if let Decision::Reply(r) = d {
        let v = inspect_reply(&r.bytes);
        assert!(
            matches!(v, Ok(ref v) if v.yiaddr == Ipv4Addr::UNSPECIFIED),
            "{v:?}"
        );
    }
}

fn discover() -> RequestBuilder {
    RequestBuilder::pxe_discover()
}

fn bad_len(code: u8, len: usize) -> ParseError {
    ParseError::BadOptionLength { code, len }
}

// ---- Size -------------------------------------------------------------

#[test]
fn size_0() {
    assert_malformed(&[], ParseError::TooShort { len: 0 });
}

#[test]
fn size_1() {
    assert_malformed(&[1], ParseError::TooShort { len: 1 });
}

#[test]
fn size_235() {
    let b = discover().build();
    assert_malformed(&b[..235], ParseError::TooShort { len: 235 });
}

#[test]
fn size_236_to_239_no_cookie() {
    let b = discover().build();
    for len in 236..=239 {
        assert_malformed(&b[..len], ParseError::MissingCookie);
    }
}

/// RFC 1542 §2.1 receiver check (specs/standards/pxe-dhcp.md §3.2): a
/// message shorter than the 300-octet BOOTP minimum is dropped silently,
/// even when it is otherwise a complete PXE DISCOVER.
#[test]
fn size_240_to_299_short_message() {
    // Without options 55 and 97 the DISCOVER is 291 octets unpadded.
    let mut rb = discover().without(55).without(97);
    rb.pad_to = 0;
    let unpadded = rb.build();
    assert!(unpadded.len() < 300, "{}", unpadded.len());
    assert_malformed(
        &unpadded,
        ParseError::ShortMessage {
            len: unpadded.len(),
        },
    );
    for len in 240..300 {
        let mut b = unpadded.clone();
        b.resize(len.max(b.len()), 0);
        b.truncate(len);
        assert_malformed(&b, ParseError::ShortMessage { len });
    }
    // The same message padded with zeros after End to 300 is answered.
    let mut b = unpadded;
    b.resize(300, 0);
    assert_replies(&b);
    assert_eq!(ParseError::ShortMessage { len: 0 }.label(), "short_message");
}

#[test]
fn bad_cookie() {
    let mut rb = discover();
    rb.cookie = [99, 130, 83, 98];
    assert_malformed(&rb.build(), ParseError::BadCookie);
}

#[test]
fn size_1473() {
    let mut rb = discover();
    let base = rb.build().len();
    rb.trailing = vec![0; 1473 - base];
    let b = rb.build();
    assert_eq!(b.len(), 1473);
    assert_malformed(&b, ParseError::TooLong { len: 1473 });
    // 1472 is still accepted.
    let ok = &b[..1472];
    assert_replies(ok);
}

// ---- Header -----------------------------------------------------------

#[test]
fn op2_reply_ignored() {
    let mut rb = discover();
    rb.op = 2;
    assert_malformed(&rb.build(), ParseError::NotBootRequest { op: 2 });
}

#[test]
fn htype_not_ethernet() {
    let mut rb = discover();
    rb.htype = 6;
    assert_malformed(&rb.build(), ParseError::BadHardwareType { htype: 6 });
}

#[test]
fn hlen_not_6() {
    let mut rb = discover();
    rb.hlen = 16;
    assert_malformed(&rb.build(), ParseError::BadHardwareLength { hlen: 16 });
}

#[test]
fn hops_17() {
    let b = discover()
        .giaddr(Ipv4Addr::new(10, 20, 2, 1))
        .hops(17)
        .build();
    assert_drop(&b, DropReason::TooManyHops);
}

// ---- Options walk -----------------------------------------------------

#[test]
fn option_code_at_last_byte() {
    let mut rb = discover();
    rb.end = false;
    rb.trailing = vec![60];
    assert_malformed(&rb.build(), ParseError::OptionTruncated { code: 60 });
}

#[test]
fn option_length_past_end() {
    let mut rb = discover();
    rb.end = false;
    rb.trailing = vec![60, 20, b'P', b'X'];
    assert_malformed(&rb.build(), ParseError::OptionTruncated { code: 60 });
}

#[test]
fn end_missing() {
    let mut rb = discover();
    rb.end = false;
    assert_malformed(&rb.build(), ParseError::MissingEnd);
}

#[test]
fn pad_only_options_area() {
    let mut rb = discover();
    rb.options.clear();
    rb.end = false;
    rb.trailing = vec![0; 64];
    assert_malformed(&rb.build(), ParseError::MissingEnd);
}

// ---- Option 52 --------------------------------------------------------

#[test]
fn overload_values_0_and_4_malformed() {
    for v in [0u8, 4] {
        let b = discover().option(52, vec![v]).build();
        assert_malformed(&b, ParseError::BadOverload { value: v });
    }
    let b = discover().option(52, vec![1, 1]).build();
    assert_malformed(&b, bad_len(52, 2));
}

fn area(content: &[u8], len: usize) -> Vec<u8> {
    let mut v = content.to_vec();
    v.resize(len, 0);
    v
}

#[test]
fn overload_1_file_parsed() {
    let b = discover()
        .without(93)
        .option(52, vec![1])
        .file_area(area(&[93, 2, 0, 7, 255], 128))
        .build();
    assert_replies(&b);
}

#[test]
fn overload_2_sname_parsed() {
    let b = discover()
        .without(93)
        .option(52, vec![2])
        .sname_area(area(&[93, 2, 0, 7, 255], 64))
        .build();
    assert_replies(&b);
    // Without overload the same `sname` content is not parsed.
    let b = discover()
        .without(93)
        .set_option(60, b"PXEClient".to_vec())
        .sname_area(area(&[93, 2, 0, 7, 255], 64))
        .build();
    assert_drop(&b, DropReason::UnsupportedArch);
}

#[test]
fn overload_3_both_parsed() {
    let b = discover()
        .without(93)
        .without(97)
        .option(52, vec![3])
        .file_area(area(&[93, 2, 0, 7, 255], 128))
        .sname_area(area(
            &[
                97, 17, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            ],
            64,
        ))
        .build();
    let r = parse_request(&b).unwrap();
    assert!(r.arch.contains(ClientArch::X64_UEFI));
    assert!(r.guid.is_some());
}

#[test]
fn overload_inside_file_ignored() {
    // An option 52 inside `file` neither errors nor triggers sname parsing,
    // and does not count as a duplicate of the main-area option 52.
    let b = discover()
        .option(52, vec![1])
        .file_area(area(&[52, 1, 2, 255], 128))
        .sname_area(area(&[54, 4, 1, 2, 3, 4, 255], 64))
        .build();
    let r = parse_request(&b).unwrap();
    assert_eq!(r.server_id, None);
    let b = discover()
        .option(52, vec![1])
        .file_area(area(&[52, 1, 9, 255], 128))
        .build();
    assert!(parse_request(&b).is_ok());
}

#[test]
fn overrun_inside_file_malformed() {
    let mut f = area(&[], 128);
    if let Some(tail) = f.get_mut(126..) {
        tail.copy_from_slice(&[60, 9]);
    }
    let b = discover().option(52, vec![1]).file_area(f).build();
    assert_malformed(&b, ParseError::OptionTruncated { code: 60 });
}

#[test]
fn overrun_inside_sname_malformed() {
    let b = discover()
        .option(52, vec![2])
        .sname_area(area(&[0, 0, 61, 200], 64))
        .build();
    assert_malformed(&b, ParseError::OptionTruncated { code: 61 });
}

// ---- Option 53 --------------------------------------------------------

#[test]
fn msg_type_length_0_and_2() {
    let b = discover().set_option(53, vec![]).build();
    assert_malformed(&b, bad_len(53, 0));
    let b = discover().set_option(53, vec![1, 1]).build();
    assert_malformed(&b, bad_len(53, 2));
}

#[test]
fn msg_type_2_and_4_to_8_ignored() {
    for v in [2u8, 4, 5, 6, 7, 8] {
        let b = discover().set_option(53, vec![v]).build();
        assert_malformed(&b, ParseError::UnhandledMessageType { value: v });
    }
}

#[test]
fn msg_type_missing_is_bootp() {
    let b = discover().without(53).build();
    assert_malformed(&b, ParseError::MissingMessageType);
}

// ---- Option 54 --------------------------------------------------------

#[test]
fn server_id_length_3_and_5() {
    for len in [3usize, 5] {
        let b = RequestBuilder::pxe_request()
            .option(54, vec![10; len])
            .build();
        assert_malformed(&b, bad_len(54, len));
    }
}

// ---- Option 57 --------------------------------------------------------

#[test]
fn max_message_size_length_1() {
    let b = discover().set_option(57, vec![5]).build();
    assert_malformed(&b, bad_len(57, 1));
}

#[test]
fn max_message_size_575_treated_as_absent() {
    let b = discover()
        .set_option(57, 575u16.to_be_bytes().to_vec())
        .build();
    assert_eq!(parse_request(&b).unwrap().max_message_size, None);
    let b = discover()
        .set_option(57, 576u16.to_be_bytes().to_vec())
        .build();
    assert_eq!(parse_request(&b).unwrap().max_message_size, Some(576));
}

// ---- Option 60 --------------------------------------------------------

#[test]
fn vendor_class_empty() {
    let b = discover().set_option(60, vec![]).build();
    assert_malformed(&b, bad_len(60, 0));
}

#[test]
fn vendor_class_wrong_case() {
    let b = discover()
        .set_option(60, b"PXECLIENT:Arch:00007".to_vec())
        .build();
    assert_drop(&b, DropReason::NotPxeClient);
}

#[test]
fn vendor_class_truncated_prefix() {
    let b = discover().set_option(60, b"PXEClien".to_vec()).build();
    assert_drop(&b, DropReason::NotPxeClient);
}

#[test]
fn vendor_class_bare_pxeclient_accepted() {
    let b = discover().set_option(60, b"PXEClient".to_vec()).build();
    assert_replies(&b);
}

#[test]
fn vendor_class_arch_non_numeric() {
    let b = discover()
        .set_option(60, b"PXEClient:Arch:0000x:UNDI:003016".to_vec())
        .build();
    assert_malformed(&b, ParseError::BadVendorClassArch);
}

#[test]
fn vendor_class_arch_disagrees_with_93() {
    let b = discover()
        .set_option(60, b"PXEClient:Arch:00000:UNDI:002001".to_vec())
        .build();
    assert_malformed(&b, ParseError::VendorClassArchMismatch);
}

// ---- Option 93 --------------------------------------------------------

#[test]
fn arch_lengths_0_1_3() {
    for len in [0usize, 1, 3] {
        let b = discover().set_option(93, vec![0; len]).build();
        assert_malformed(&b, bad_len(93, len));
    }
}

#[test]
fn arch_64_entries() {
    let mut d = Vec::new();
    for i in 0..64u16 {
        d.extend_from_slice(&(if i == 63 { 7 } else { 100 + i }).to_be_bytes());
    }
    let b = discover()
        .set_option(93, d)
        .set_option(60, b"PXEClient".to_vec())
        .build();
    let r = parse_request(&b).unwrap();
    assert_eq!(r.arch.len(), 64);
    assert_replies(&b);
}

#[test]
fn arch_without_7() {
    let b = discover()
        .set_option(93, vec![0, 0, 0, 6, 0, 11])
        .set_option(60, b"PXEClient".to_vec())
        .build();
    assert_drop(&b, DropReason::UnsupportedArch);
}

// ---- Option 94 --------------------------------------------------------

#[test]
fn ndi_length_2_and_4() {
    for len in [2usize, 4] {
        let b = discover().set_option(94, vec![1; len]).build();
        assert_malformed(&b, bad_len(94, len));
    }
}

// ---- Option 97 --------------------------------------------------------

#[test]
fn machine_id_length_16_and_18() {
    for len in [16usize, 18] {
        let b = discover().set_option(97, vec![0; len]).build();
        assert_malformed(&b, bad_len(97, len));
    }
}

#[test]
fn machine_id_type_1() {
    let mut d = vec![1u8];
    d.extend_from_slice(&[0xaa; 16]);
    let b = discover().set_option(97, d).build();
    assert_malformed(&b, ParseError::BadMachineIdType { kind: 1 });
}

// ---- Option 82 --------------------------------------------------------

#[test]
fn relay_info_255_fits_default_limit() {
    let ri: Vec<u8> = (0..255u8).collect();
    let b = discover()
        .giaddr(Ipv4Addr::new(10, 20, 2, 1))
        .hops(1)
        .option(82, ri.clone())
        .build();
    match decide(&b) {
        Decision::Reply(r) => {
            assert!(r.relay_info_echoed);
            let v = inspect_reply(&r.bytes).unwrap();
            assert_eq!(v.relay_info, Some(&ri[..]));
            assert_eq!(v.last_code, Some(82));
        }
        Decision::Drop(why) => panic!("dropped: {why:?}"),
    }
}

#[test]
fn relay_info_255_does_not_fit_small_limit() {
    let ri = [0x5a; 255];
    let reply = ProxyReply {
        kind: ReplyKind::Offer,
        xid: 1,
        flags: 0,
        giaddr: Ipv4Addr::new(10, 20, 2, 1),
        chaddr: MacAddr::new([0x52, 0x54, 0, 0, 1, 1]).unwrap(),
        server_addr: SERVER,
        boot_file: b"usgp-test-payload.efi",
        arch: ClientArch::X64_UEFI,
        client_ndi: None,
        client_guid: None,
        boot_item: None,
        relay_info: Some(&ri),
    };
    let e = reply.encode(400).unwrap();
    assert!(!e.relay_info_echoed);
    assert!(e.bytes.len() <= 400);
    assert_eq!(inspect_reply(&e.bytes).unwrap().relay_info, None);
}

// ---- Option 43 tag 71 -------------------------------------------------

fn tag71(item: [u8; 4]) -> Vec<u8> {
    let mut d = vec![71, 4];
    d.extend_from_slice(&item);
    d.push(255);
    d
}

#[test]
fn tag71_wrong_length() {
    for d in [vec![71, 3, 0, 0, 0, 255], vec![71, 5, 0, 0, 0, 0, 0, 255]] {
        let b = RequestBuilder::pxe_request().option(43, d).build();
        assert_malformed(&b, ParseError::BadVendorSubOption { tag: 71 });
    }
}

#[test]
fn tag71_layer_nonzero() {
    let b = RequestBuilder::pxe_request()
        .option(43, tag71([0, 0, 0, 1]))
        .build();
    assert_drop(&b, DropReason::UnsupportedBootItem);
}

#[test]
fn tag71_credentials_bit() {
    let b = RequestBuilder::pxe_request()
        .option(43, tag71([0, 0, 0x80, 0]))
        .build();
    let r = parse_request(&b).unwrap();
    assert_eq!(
        r.boot_item,
        Some(BootItem {
            server_type: 0,
            layer: 0,
            credentials: true
        })
    );
    assert_drop(&b, DropReason::UnsupportedBootItem);
}

#[test]
fn tag71_type_nonzero() {
    let b = RequestBuilder::pxe_request()
        .option(43, tag71([0x80, 0x01, 0, 0]))
        .build();
    assert_drop(&b, DropReason::UnsupportedBootItem);
}

#[test]
fn tag71_default_accepted() {
    let b = RequestBuilder::pxe_request()
        .option(43, tag71([0, 0, 0, 0]))
        .build();
    assert_replies(&b);
}

// ---- Repeated options: RFC 3396 reassembly ---------------------------
//
// specs/standards/dhcp-long-options.md §2, §3, §6: repeated instances of a
// code are pieces of one option, joined in aggregate-buffer order (options,
// file, sname) and validated as the joined value.

/// Splits `data` into instances of `code` at the given cut points.
fn split(rb: RequestBuilder, code: u8, data: &[u8], cuts: &[usize]) -> RequestBuilder {
    let mut rb = rb.without(code);
    let mut start = 0;
    for &cut in cuts.iter().chain(std::iter::once(&data.len())) {
        rb = rb.option(code, data[start..cut].to_vec());
        start = cut;
    }
    rb
}

#[test]
fn split_option_60_reassembled() {
    let vc = b"PXEClient:Arch:00007:UNDI:003016";
    // Cut inside the "PXEClient" prefix and inside the Arch digits.
    let b = split(discover(), 60, vc, &[3, 18]).build();
    let r = parse_request(&b).unwrap();
    assert_eq!(&*r.vendor_class, &vc[..]);
    assert_replies(&b);
}

#[test]
fn split_option_60_with_empty_piece() {
    let b = split(discover(), 60, b"PXEClient", &[0, 9]).build();
    assert_eq!(&*parse_request(&b).unwrap().vendor_class, b"PXEClient");
}

#[test]
fn split_option_93_reassembled() {
    // [0, 0, 0, 7] cut mid-entry: pieces of odd length are fine.
    let b = split(discover(), 93, &[0, 0, 0, 7], &[1, 3])
        .set_option(60, b"PXEClient".to_vec())
        .build();
    let r = parse_request(&b).unwrap();
    assert_eq!(r.arch.iter().map(|a| a.0).collect::<Vec<_>>(), vec![0, 7]);
    assert_replies(&b);
}

#[test]
fn split_option_93_odd_joined_length_malformed() {
    let b = split(discover(), 93, &[0, 7, 0], &[2]).build();
    assert_malformed(&b, bad_len(93, 3));
}

#[test]
fn split_option_97_reassembled() {
    let mut d = vec![0u8];
    d.extend_from_slice(&usgp_dhcp::craft::SAMPLE_GUID_WIRE);
    let b = split(discover(), 97, &d, &[1, 9]).build();
    let r = parse_request(&b).unwrap();
    assert_eq!(
        r.guid,
        Some(Guid::from_wire(usgp_dhcp::craft::SAMPLE_GUID_WIRE))
    );
}

#[test]
fn split_option_97_wrong_joined_length() {
    let mut d = vec![0u8];
    d.extend_from_slice(&[1; 16]);
    // Two full copies join to 34 octets: malformed.
    let b = discover()
        .without(97)
        .option(97, d.clone())
        .option(97, d)
        .build();
    assert_malformed(&b, bad_len(97, 34));
}

#[test]
fn split_option_43_suboption_straddles_pieces() {
    let b = split(
        RequestBuilder::pxe_request(),
        43,
        &[71, 4, 0, 0, 0, 0, 255],
        &[1, 4],
    )
    .build();
    let r = parse_request(&b).unwrap();
    assert_eq!(r.boot_item, Some(BootItem::DEFAULT));
    assert_replies(&b);
}

#[test]
fn split_option_43_repeated_tag71_malformed() {
    let t = tag71([0, 0, 0, 0]);
    let b = RequestBuilder::pxe_request()
        .option(43, t.clone())
        .option(43, t)
        .build();
    // The first joined copy ends at sub-option End; with End inside the
    // joined value, parsing stops there, so a second tag 71 after End is
    // not seen. Without End the repeat is malformed:
    let r = parse_request(&b).unwrap();
    assert_eq!(r.boot_item, Some(BootItem::DEFAULT));
    let t = vec![71, 4, 0, 0, 0, 0];
    let b = RequestBuilder::pxe_request()
        .option(43, t.clone())
        .option(43, t)
        .build();
    assert_malformed(&b, ParseError::BadVendorSubOption { tag: 71 });
}

#[test]
fn split_across_overloaded_file_and_sname() {
    // 60 starts in options, continues in file, ends in sname.
    let b = discover()
        .without(60)
        .option(60, b"PXECl".to_vec())
        .option(52, vec![3])
        .file_area(area(&[60, 4, b'i', b'e', b'n', b't', 255], 128))
        .sname_area(area(
            &[
                60, 6, b':', b'A', b'r', b'c', b'h', b':', 60, 5, b'0', b'0', b'0', b'0', b'7', 255,
            ],
            64,
        ))
        .build();
    let r = parse_request(&b).unwrap();
    assert_eq!(&*r.vendor_class, b"PXEClient:Arch:00007");
    assert_replies(&b);
}

#[test]
fn split_order_is_options_file_sname_not_physical() {
    // Physically sname precedes file; logically file comes first.
    let b = discover()
        .without(60)
        .option(60, b"PXE".to_vec())
        .option(52, vec![3])
        .file_area(area(&[60, 3, b'C', b'l', b'i', 255], 128))
        .sname_area(area(&[60, 3, b'e', b'n', b't', 255], 64))
        .build();
    assert_eq!(&*parse_request(&b).unwrap().vendor_class, b"PXEClient");
}

#[test]
fn split_93_across_overloaded_file() {
    let b = discover()
        .option(52, vec![1])
        .set_option(93, vec![0, 0])
        .set_option(60, b"PXEClient".to_vec())
        .file_area(area(&[93, 2, 0, 7, 255], 128))
        .build();
    let r = parse_request(&b).unwrap();
    assert_eq!(r.arch.len(), 2);
    assert_replies(&b);
}

#[test]
fn piece_overrunning_its_field_malformed() {
    // A piece may not cross from `file` into the next field.
    let mut f = area(&[], 128);
    if let Some(tail) = f.get_mut(124..) {
        tail.copy_from_slice(&[60, 6, b'a', b'b']);
    }
    let b = discover().option(52, vec![3]).file_area(f).build();
    assert_malformed(&b, ParseError::OptionTruncated { code: 60 });
}

#[test]
fn joined_option_82_over_255_parsed_but_not_echoed() {
    let a = vec![1u8, 253];
    let mut a = a;
    a.extend_from_slice(&[b'x'; 253]);
    let b = discover()
        .giaddr(Ipv4Addr::new(10, 20, 2, 1))
        .option(82, a.clone())
        .option(82, vec![2, 2, 0, 1])
        .build();
    let r = parse_request(&b).unwrap();
    assert_eq!(r.relay_info.as_deref().map(<[u8]>::len), Some(259));
    match decide(&b) {
        Decision::Reply(rep) => {
            assert!(!rep.relay_info_echoed, "never split on send");
            assert_eq!(inspect_reply(&rep.bytes).unwrap().relay_info, None);
        }
        Decision::Drop(why) => panic!("dropped: {why:?}"),
    }
}

#[test]
fn repeated_fixed_length_options_join_to_bad_length() {
    let cases: [(u8, Vec<u8>, usize); 5] = [
        (52, vec![1], 2),
        (53, vec![1], 2),
        (54, SERVER.octets().to_vec(), 8),
        (57, 1472u16.to_be_bytes().to_vec(), 4),
        (94, vec![1, 3, 16], 6),
    ];
    for (code, data, joined) in cases {
        let b = RequestBuilder::pxe_request()
            .set_option(code, data.clone())
            .option(code, data)
            .build();
        assert_malformed(&b, bad_len(code, joined));
    }
}

#[test]
fn repeated_option_60_joins_to_non_pxe_class() {
    let b = discover()
        .set_option(60, b"PXEClient".to_vec())
        .option(60, b"PXEClient".to_vec())
        .build();
    assert_eq!(
        &*parse_request(&b).unwrap().vendor_class,
        b"PXEClientPXEClient"
    );
    assert_drop(&b, DropReason::NotPxeClient);
}

#[test]
fn repeated_option_61_joined() {
    let b = discover()
        .option(61, vec![1])
        .option(61, vec![0x52, 0x54, 0, 0, 1, 1])
        .build();
    assert_replies(&b);
    let b = discover().option(61, vec![1]).build();
    assert_malformed(&b, bad_len(61, 1));
}

#[test]
fn overload_inside_overloaded_area_not_joined() {
    let b = discover()
        .option(52, vec![1])
        .file_area(area(&[52, 1, 1, 255], 128))
        .build();
    assert!(parse_request(&b).is_ok());
}

#[test]
fn repeated_uninterpreted_option_ignored() {
    let b = discover().option(55, vec![1]).build();
    assert_replies(&b);
}

// ---- Addresses --------------------------------------------------------

#[test]
fn giaddr_limited_broadcast() {
    let b = discover().giaddr(Ipv4Addr::BROADCAST).build();
    assert_drop(&b, DropReason::BadGiaddr);
}

#[test]
fn giaddr_multicast() {
    let b = discover().giaddr(Ipv4Addr::new(224, 0, 0, 1)).build();
    assert_drop(&b, DropReason::BadGiaddr);
}

#[test]
fn giaddr_loopback() {
    let b = discover().giaddr(Ipv4Addr::LOCALHOST).build();
    assert_drop(&b, DropReason::BadGiaddr);
}

#[test]
fn giaddr_our_own_address() {
    let b = discover().giaddr(SERVER).build();
    assert_drop(&b, DropReason::BadGiaddr);
}

#[test]
fn ciaddr_broadcast_malformed() {
    let b = discover().ciaddr(Ipv4Addr::BROADCAST).build();
    assert_malformed(&b, ParseError::BadCiaddr);
}

// ---- chaddr -----------------------------------------------------------

#[test]
fn chaddr_multicast() {
    let b = discover().chaddr([0x01, 0x00, 0x5e, 0, 0, 1]).build();
    assert_malformed(&b, ParseError::BadChaddr);
}

#[test]
fn chaddr_all_zero() {
    let b = discover().chaddr([0; 6]).build();
    assert_malformed(&b, ParseError::BadChaddr);
}

// ---- Every reply over a mutation sweep --------------------------------

#[test]
fn single_byte_mutations_never_assign_addresses() {
    // Flip every byte of a valid DISCOVER in turn; whatever the decision,
    // a reply must keep yiaddr 0, no lease options, and the size limit.
    let base = discover()
        .option(82, vec![1, 2, b'c', b'd'])
        .giaddr(Ipv4Addr::new(10, 20, 2, 1))
        .build();
    for i in 0..base.len() {
        for x in [0x01u8, 0x80, 0xff] {
            let mut b = base.clone();
            if let Some(byte) = b.get_mut(i) {
                *byte ^= x;
            }
            if let Decision::Reply(r) = decide(&b) {
                let v = inspect_reply(&r.bytes).unwrap();
                assert_eq!(v.yiaddr, Ipv4Addr::UNSPECIFIED);
                for c in usgp_dhcp::reply::FORBIDDEN_REPLY_OPTIONS {
                    assert!(!v.codes.contains(c));
                }
                assert!(r.bytes.len() <= 1472);
            }
        }
    }
}

// ---- Deterministic random sweep (fuzz invariants, plan §10.4) ---------

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn byte(&mut self) -> u8 {
        self.next().to_le_bytes()[0]
    }
}

#[test]
fn random_inputs_hold_reply_invariants() {
    let mut rng = XorShift(0x9e37_79b9_7f4a_7c15);
    let seed = discover()
        .giaddr(Ipv4Addr::new(10, 20, 2, 1))
        .option(82, vec![1, 2, b'a', b'b'])
        .build();
    for i in 0..60_000u32 {
        let b: Vec<u8> = if i % 2 == 0 {
            let len = usize::try_from(rng.next() % 1600).unwrap();
            (0..len).map(|_| rng.byte()).collect()
        } else {
            // Mutate a valid message so the deep paths are reached.
            let mut b = seed.clone();
            for _ in 0..(1 + rng.next() % 8) {
                let at = usize::try_from(rng.next()).unwrap() % b.len();
                b[at] = rng.byte();
            }
            b
        };
        let Ok(req) = parse_request(&b) else { continue };
        let Decision::Reply(r) = usgp_dhcp::respond(&req, &ctx(), &Policy) else {
            continue;
        };
        let v = inspect_reply(&r.bytes).unwrap();
        assert_eq!(v.yiaddr, Ipv4Addr::UNSPECIFIED);
        for c in usgp_dhcp::reply::FORBIDDEN_REPLY_OPTIONS {
            assert!(!v.codes.contains(c));
        }
        assert_eq!(v.xid, req.xid);
        assert_eq!(v.chaddr, req.chaddr.octets());
        assert!(r.bytes.len() <= usgp_dhcp::reply::reply_size_limit(req.max_message_size));
        if let (Some(a), Some(b)) = (req.relay_info.as_deref(), v.relay_info) {
            assert_eq!(a, b);
        }
    }
}
