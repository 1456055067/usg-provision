# Spec traceability

Every specced requirement maps to code and a test. Rows cover every REQ ID
that milestone M1 put in scope (`specs/boot-network.md`, all AUDITED), plus
the OPEN REQs of the same spec that M1 deliberately leaves alone.

Evidence rules for the Status column:

- **Tested** means the test is named in the M1 QA report (2026-10-26:
  initial pass, re-verify round 1 or the final pass) and passed there.
- **Tested (in-process)** means the same, but the test runs the relay
  in-process with in-memory sockets. Live behaviour on a real network and
  real firmware is the boot smoke scenario named next to it.
- **S1 to S8 NOT RUN**: the boot smoke scenarios need Linux, root network
  namespaces and network-capable firmware. They did not run on the macOS
  development host and have not yet run in CI. NOT RUN is never a pass.
- **Documented**: an operator-facing statement in
  [`docs/operations/relay.md`](../operations/relay.md). The QA review
  result is given in each row.
- **OPEN**: the spec leaves a product question open; nothing is
  implemented beyond the AUDITED parts.

Test path abbreviations: `responder`, `reply`, `ident`, `packet` are
`crates/usgp-dhcp/src/*.rs` unit tests; `dhcp-neg` is
`crates/usgp-dhcp/tests/negative.rs`; `qa_invariants` is
`crates/usgp-dhcp/tests/qa_invariants.rs`; `transfer`, `rto` are
`crates/usgp-tftp/src/*.rs`; `tftp-neg`, `sorcerer`, `qa_rfc_limits` are
`crates/usgp-tftp/tests/*.rs`; `relay::<module>` are unit tests in
`services/usgp-relay/src/`; `dhcp_service`, `tftp_service`,
`content_integrity`, `config`, `startup`, `qa_m1`, `qa_r1`, `qa_r3` are
`services/usgp-relay/tests/*.rs`; `netlab::dhcpd` and `netlab::probe` are
`testing/netlab/src/dhcpd.rs` and `probe.rs`.

| REQ ID | Spec | Code | Test | Status |
|--------|------|------|------|--------|
| REQ-BOOT-001 | Answer PXE on the local segment | [responder.rs](../../crates/usgp-dhcp/src/responder.rs), [dhcp.rs](../../services/usgp-relay/src/dhcp.rs) | `responder::discover_same_segment_broadcast`; `dhcp_service::same_segment_offer` | Tested (in-process). S1 NOT RUN |
| REQ-BOOT-002 | Other subnets through a relay agent (any relay agent accepted, owner answer Q-1) | [responder.rs](../../crates/usgp-dhcp/src/responder.rs), [dhcp.rs](../../services/usgp-relay/src/dhcp.rs) | `responder::relayed_reply_to_giaddr_67`; `dhcp_service::relayed_any_source_default`, `relayed_and_local_global_budgets_are_separate`; `qa_m1::event_yiaddr_matches_wire_on_every_path`; `testing/netlab/tests/relayed_flow.rs`. `dhcp_service::off_segment_ciaddr_source_on_67_routed_unicast`; `qa_r3::origin_recorded_in_dhcp_events_on_every_path` | Tested (in-process). S2 NOT RUN |
| REQ-BOOT-003 | UEFI x86-64 (arch 7) | [responder.rs](../../crates/usgp-dhcp/src/responder.rs), [ident.rs](../../crates/usgp-dhcp/src/ident.rs), [config.rs](../../services/usgp-relay/src/config.rs) | `responder::arch7_gets_program`; `ident::only_x64_uefi_supported_in_m1`; `config::boot_rules`. Boot smoke `payload-disk` PASS shows only that the test payload runs on x86-64 UEFI firmware from disk | Tested (in-process). Network boot by firmware: S1 NOT RUN |
| REQ-BOOT-004 | Answer only PXE clients | [packet.rs](../../crates/usgp-dhcp/src/packet.rs), [responder.rs](../../crates/usgp-dhcp/src/responder.rs) | `responder::non_pxe_vendor_class_dropped`, `missing_option60_dropped`; `dhcp-neg` option 60 cases; `dhcp_service::non_pxe_client_gets_nothing` | Tested. S4 probe NOT RUN |
| REQ-BOOT-005 | No program for unsupported architectures | [responder.rs](../../crates/usgp-dhcp/src/responder.rs) | `responder::arch_list_without_7_dropped`, `multi_arch_with_7_served`; `dhcp_service::unsupported_arch_gets_nothing` | Tested. S4 probe NOT RUN |
| REQ-BOOT-006 | Ignore malformed and non-request traffic | [packet.rs](../../crates/usgp-dhcp/src/packet.rs), [options.rs](../../crates/usgp-dhcp/src/options.rs), [dhcp.rs](../../services/usgp-relay/src/dhcp.rs) | `dhcp-neg` (73 tests at QA, including `op2_reply_ignored`); fuzz target `dhcp_packet`; `qa_m1::drops_are_counted_not_logged_per_packet`. 300-octet floor: `dhcp-neg::size_240_to_299_short_message`, `dhcp_service::short_requests_dropped_and_counted`; `netlab::probe::qa_vectors_meet_bootp_minimum_in_every_mode_and_seed` | Tested |
| REQ-BOOT-007 | How a device is recognised (MAC or GUID) | [ident.rs](../../crates/usgp-dhcp/src/ident.rs), [suppress.rs](../../services/usgp-relay/src/suppress.rs) | `ident::mac_parse_*`, `guid_parse_*`, `guid_standards_worked_example`; `dhcp_service::suppress_by_mac_and_lift_without_restart`, `suppress_by_guid`; `qa_m1::suppression_guid_text_is_case_insensitive` | Tested |
| REQ-BOOT-010 | Never assign addresses (decision 0003) | [reply.rs](../../crates/usgp-dhcp/src/reply.rs) | `reply::yiaddr_always_zero`, `reply_has_no_lease_options`; `qa_m1::lease_request_never_honoured_on_any_path`, `event_yiaddr_matches_wire_on_every_path`; `qa_invariants::replies_carry_only_allowed_options_under_mutation`; `dhcp_packet` fuzz invariant | Tested |
| REQ-BOOT-011 | Work beside an unmodified site DHCP server | [reply.rs](../../crates/usgp-dhcp/src/reply.rs) (ProxyDHCP reply only) | `netlab::dhcpd::replies_carry_no_pxe_or_boot_options` (lab DHCP server carries no boot options; lab tool test only). Conflict note: [relay.md](../operations/relay.md) | Partial: design and lab-tool test; conflict note Documented. S1/S2 NOT RUN |
| REQ-BOOT-012 | No site DHCP answer: no address, device falls through | [responder.rs](../../crates/usgp-dhcp/src/responder.rs) | `responder::discover_offer_without_address` | Unit test only. Firmware fall-through: S7 NOT RUN |
| REQ-BOOT-020 | Reply through the relay agent | [responder.rs](../../crates/usgp-dhcp/src/responder.rs) | `responder::relayed_reply_to_giaddr_67`, `broadcast_flag_preserved`; `dhcp_service::relayed_any_source_default` | Tested (in-process). S2 NOT RUN |
| REQ-BOOT-021 | Preserve relay agent information (option 82) | [reply.rs](../../crates/usgp-dhcp/src/reply.rs) | `reply::opt82_echoed_unchanged_last`, `opt82_omitted_when_too_large`, `opt82_over_255_never_split`; `qa_m1::option82_echo_and_drop_recorded_in_audit`; `qa_invariants::replies_carry_only_allowed_options_under_mutation` | Tested. S2 NOT RUN |
| REQ-BOOT-022 | Name a server the device can reach | [config.rs](../../services/usgp-relay/src/config.rs), [responder.rs](../../crates/usgp-dhcp/src/responder.rs) | `responder::siaddr_equals_interface_address`; `config::interface_address_rules_req_022`; `qa_invariants::replies_carry_only_allowed_options_under_mutation` | Tested. S2 NOT RUN |
| REQ-BOOT-023 | State what the network must provide for relayed boot | [relay.md](../operations/relay.md) "Network requirements" | QA doc review (final pass) | Documented; QA doc review passed (2026-10-26) |
| REQ-BOOT-030 | Deliver the boot program by TFTP (octet) | [transfer.rs](../../crates/usgp-tftp/src/transfer.rs), [tftp.rs](../../services/usgp-relay/src/tftp.rs) | `transfer::octet_rrq_full_download`, `netascii_refused`; `tftp_service::octet_rrq_full_download_no_options`, `exact_multiple_sends_final_empty_block`, `empty_file_one_empty_block`, `netascii_refused_error4` | Tested (in-process). S1 NOT RUN |
| REQ-BOOT-031 | Requests with or without TFTP options | [options.rs](../../crates/usgp-tftp/src/options.rs), [transfer.rs](../../crates/usgp-tftp/src/transfer.rs) | `transfer::rrq_no_options_data1_512`, `rrq_blksize_tsize_oack`, `unknown_option_ignored`, `timeout_option_not_acked`; `tftp-neg`; `tftp_service::blksize_tsize_oack_download`, `timeout_option_not_acknowledged`; `qa_rfc_limits::option_names_case_insensitive`, `negotiation_properties_hold_for_random_option_sets` | Tested. S1 NOT RUN |
| REQ-BOOT-032 | Reliable transfer behaviour | [transfer.rs](../../crates/usgp-tftp/src/transfer.rs), [rto.rs](../../crates/usgp-tftp/src/rto.rs), [tftp.rs](../../services/usgp-relay/src/tftp.rs) | `sorcerer::dup_ack_no_resend`, `delayed_ack_does_not_double_the_stream`; `rto::rto_backoff_doubles`, `rto_adapts_from_samples`; `transfer::retry_cap_aborts`, `karn_skip_retransmitted`, `unterminated_client_error_ends_transfer`; `tftp_service::retry_cap_releases_slot`, `handshake_timeout_releases_pending_slot`, `duplicate_ack_never_resends`; `qa_m1::tftp_retry_cap_emits_failed_event`, `sloppy_client_error_ends_relay_transfer_only_from_client_tid` | Tested |
| REQ-BOOT-033 | Missing file | [tftp.rs](../../services/usgp-relay/src/tftp.rs), [content.rs](../../services/usgp-relay/src/content.rs) | `tftp_service::unknown_name_error1`; `content_integrity::missing_file_reported_missing` | Tested |
| REQ-BOOT-034 | Many devices at once | [tftp.rs](../../services/usgp-relay/src/tftp.rs) | `tftp_service::stalled_client_does_not_delay_50_others` | Tested (in-process). S8 NOT RUN. Reliability residual for large files: POAM-15 |
| REQ-BOOT-035 (AUDITED part) | Never send a corrupt or truncated file | [transfer.rs](../../crates/usgp-tftp/src/transfer.rs) | `transfer::block_count_65535_ok_65536_refused`, `refused_before_oack`; `tftp_service::block_count_limit_refused_before_data`; `qa_rfc_limits::full_65535_block_transfer_never_wraps`, `one_octet_over_refused_at_each_block_size`; `qa_m1::too_many_blocks_with_options_refused_before_oack` | Tested: refused with ERROR 3, never wraps. The OPEN question (refuse or wrap) is not decided |
| REQ-BOOT-040 | Read-only file service | [tftp.rs](../../services/usgp-relay/src/tftp.rs) | `tftp_service::wrq_error2_no_fs_access`; `qa_m1::every_tftp_refusal_audited_and_discloses_nothing` | Tested. S4 NOT RUN |
| REQ-BOOT-041 | Serve only published boot files | [boot_file_name.rs](../../crates/usgp-proto/src/boot_file_name.rs), [content.rs](../../services/usgp-relay/src/content.rs) | `boot_file_name` unit tests; `tftp_service::traversal_names_error1`, `embedded_nul_never_served`; `content_integrity::symlink_refused`, `symlinked_directory_under_root_refused`, `unpublished_name_never_read`; `qa_m1::every_tftp_refusal_audited_and_discloses_nothing`. `config::boot_root_resolved_once_at_load`; `qa_r3::boot_root_symlink_target_is_what_gets_trust_checked` | Tested |
| REQ-BOOT-042 | Ignore broadcast file requests | [net.rs](../../services/usgp-relay/src/net.rs) | `relay::net::bind_plan_tftp_unicast_only`, `only_dhcp_is_wildcard_and_broadcast` | Bind plan tested only. Live broadcast RRQ drop: S4 NOT RUN |
| REQ-BOOT-043 | No secrets over the boot network | [config.rs](../../services/usgp-relay/src/config.rs), [relay.md](../operations/relay.md) | `config::config_has_no_secret_keys`; `qa_m1::every_tftp_refusal_audited_and_discloses_nothing`, `dhcp_replies_carry_no_host_data` | Tested for traffic. Operator statement Documented: QA doc review found it conforming except QA-004 (MINOR), fixed in relay.md on 2026-10-26; QA re-check of the fix pending |
| REQ-BOOT-044 | Withstand heavy or hostile request volume | [limits.rs](../../services/usgp-relay/src/limits.rs), [dhcp.rs](../../services/usgp-relay/src/dhcp.rs), [tftp.rs](../../services/usgp-relay/src/tftp.rs), [content.rs](../../services/usgp-relay/src/content.rs) | `relay::limits` unit tests; `dhcp_service::per_client_rate_limit_and_refill`, `relay_source_rate_limit`, `global_reply_budget`, `flood_bounded_then_recovers`, `relayed_and_local_global_budgets_are_separate`; `tftp_service::pending_cap`, `per_client_cap`, `error_rate_cap`, `spoofed_rrq_trickle_does_not_block_real_clients`, `global_rrq_admission_bucket`, `bad_sources_dropped_before_any_slot`; `qa_r1::handshake_timeout_must_not_exceed_max_transfer`. `tftp_service::rrq_flood_on_one_interface_does_not_shed_another`, `verification_wait_bounded_by_handshake_timeout`; `dhcp_service::off_segment_sources_never_use_same_segment_budget`, `unknown_prefix_fails_closed`, `off_segment_ciaddr_source_on_67_routed_unicast`; `relay::content::cancelled_verification_keeps_permit_until_read_ends`, `verify_slow_report_rate_limited_per_file`; `qa_r3::same_segment_prefix_boundaries`, `verify_slow_event_fields_and_rate_limit_from_tftp_path` | Tested (in-process). S4 rate probe NOT RUN. Residuals: POAM-9, POAM-10 |
| REQ-BOOT-045 | Suppression is not access control | [suppress.rs](../../services/usgp-relay/src/suppress.rs) (module comment), [relay.md](../operations/relay.md) | QA doc review (final pass) | Documented; QA doc review passed (2026-10-26) |
| REQ-BOOT-050 | Suppress and lift without restart | [suppress.rs](../../services/usgp-relay/src/suppress.rs) | `relay::suppress::reload_applies_without_restart`, `broken_file_keeps_previous_and_reports_once`; `dhcp_service::suppress_by_mac_and_lift_without_restart`; `qa_m1::suppression_file_with_nil_guid_rejected_previous_kept`; `qa_r1::suppression_file_trust_rules_at_start_and_reload` | Tested (in-process). S6 NOT RUN |
| REQ-BOOT-051 | A suppressed device falls through | [responder.rs](../../crates/usgp-dhcp/src/responder.rs) | `responder::suppressed_no_reply`; `qa_m1::suppressed_device_gets_nothing_on_every_path_and_one_event`; `qa_invariants::suppression_wins_over_every_reply_path` | Tested: no reply on every path. Firmware fall-through: S6 NOT RUN |
| REQ-BOOT-052 | Status and missing content | [state.rs](../../services/usgp-relay/src/state.rs), [content.rs](../../services/usgp-relay/src/content.rs), [main.rs](../../services/usgp-relay/src/main.rs) | `content_integrity::flip_first_byte`, `flip_middle_byte`, `flip_last_byte`, `truncated_file_refused`, `appended_file_refused`, `tampered_file_rrq_gets_error1`; `dhcp_service::missing_content_no_offer_then_recovers`; `startup::check_config_missing_content_exits_3`; `qa_m1::rrq_tamper_stops_offers_and_audits_then_recovers`; `relay::state::stale_result_ignored`; `qa_r1::check_results_ordered_by_start_under_random_interleaving` | Tested. Operator view is events plus `--check-config` (owner answer Q-4); live view: POAM-12 |
| REQ-BOOT-053 | Settings survive service updates | [config.rs](../../services/usgp-relay/src/config.rs) | `config::golden_v1_config_parses`, `golden_with_any_unknown_key_refused`, `config_file_is_only_read_req_053` | Tested (schema and read-only). No package or conffile handling exists yet |
| REQ-BOOT-060 | No network-boot loop after provisioning | M1 hook only: suppression ([suppress.rs](../../services/usgp-relay/src/suppress.rs)) | No in-process test of the requirement. S6 would show a suppressed device boots from disk | Not met in M1: hook only, automatic suppression is POAM-16. S6 NOT RUN |
| REQ-BOOT-070 | Answer within the client's retry window | [dhcp.rs](../../services/usgp-relay/src/dhcp.rs) | `dhcp_service::reply_latency_under_50ms` | Tested (in-process). S1 timing NOT RUN |
| REQ-BOOT-013 | Other boot services on the same segment | None | None | OPEN. Not implemented in M1 (brief) |
| REQ-BOOT-014 | Boot service on the same host as a DHCP server | None | None | OPEN. Co-hosting not supported in M1 (brief) |
| REQ-BOOT-035 (OPEN question) | Refuse or wrap past 65535 blocks | See the AUDITED row | See the AUDITED row | OPEN. M1 refuses; wrap is not implemented |
| REQ-BOOT-054 | Record of network-boot attempts | None | None | OPEN. Not implemented in M1 (brief) |
| REQ-BOOT-061 | Next boot goes to the installed disk | None | None | OPEN. Out of M1 scope |
| REQ-BOOT-062 | Make a device eligible for network boot again | None | None | OPEN. Out of M1 scope |

## Document Change History

| Date | Change |
|------|--------|
| 2026-10-26 | M1 (network boot): added every REQ-BOOT ID in the M1 brief with code, tests and status from the M1 QA report; S1 to S8 recorded as NOT RUN; fix-round 2 and 3 tests marked as pending QA re-verify; OPEN REQs listed. |
| 2026-10-26 | M1 final pass (QA report FP.8): round-2 and round-3 tests moved to Tested; added `qa_r3` and netlab probe tests; REQ-BOOT-023 and 045 QA doc review passed; REQ-BOOT-043 statement corrected for QA-004. |
