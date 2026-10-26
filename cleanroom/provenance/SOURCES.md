# Provenance log

Dirty-side record. Clean-side agents do not read this file.

Public-access verification method for every row: the page was retrieved
anonymously over HTTPS by an automated fetcher with no cookies, credentials,
or session, and the returned content showed no login wall, licence
click-through, or customer-portal gate. SRC-001 to SRC-010 were first
accessed on 2026-10-25 (UTC) during the bootstrap survey.

Rules for later runs (fix round 1, CR-008):

- In survey mode the last column lists area codes. When area specs are
  drafted, replace the area codes with the REQ IDs each source supports.
- If the vendor online user guide becomes readable and is used, take only
  user-visible behaviour from it. Its UI layouts, field and setting names,
  internal component names, and sample values must not reach `specs/`.

Spec run M1 network boot (`target/agent-workflow/20261025-234122-spec-m1-boot`):

- For SRC-003 to SRC-007 and SRC-009, the BOOT area code is replaced by
  REQ IDs. Area codes for areas that are not specced yet stay as they are.
  BOOT capabilities that are not specced yet (BOOT-3, BOOT-4, BOOT-6) are
  listed by capability ID.
- SRC-003 to SRC-007 and SRC-009 were fetched again in this run. Each fetch
  asked for a paraphrase of boot-related behaviour only, with no quotations,
  UI labels, setting names, or component names. SRC-003 is a one-page PDF.
  The fetcher could not extract its text, so the researcher read the
  rendered page directly. Only its general claim about a boot service per
  segment was used, for REQ-BOOT-001. Its relay section was not reworded
  again.
- SRC-011 onward are open standards and public third-party references.
  Access dates come from the session clock: 2026-10-25 until the date
  changed during the run, 2026-10-26 after that.
- The search engine was not used on the vendor or the vendor product in
  this run. Three searches were run on open-standard topics (see
  "Consulted, not used").

M1 network boot, fix round 1 (CR-101 to CR-108):

- "Used for" entries were corrected so that vendor sources are listed only
  for what they state. "(outcome only)", "(indirect)" and "(symptom only)"
  mark rows where the vendor source supports the user-level outcome but
  not the mechanism, which comes from the cited standard.
- Project decisions are now logged as `DEC-nnnn` rows (table below) and
  cited by ID, replacing the earlier "Project decision (M1 spec request)"
  wording, which pointed into the gitignored run directory.
- No new research. Only SRC-018 (draft-henry §3) was fetched again, to
  check how it frames ProxyDHCP for CR-106; paraphrase-only prompt.

## Project decisions cited

These are project design decisions, not product behaviour. They are
recorded in the repository and need no public-access check.

| ID | Title | Repo path | Date | Nature | Used for REQ IDs |
|----|-------|-----------|------|--------|------------------|
| DEC-0003 | Boot service never leases addresses (ProxyDHCP only) | `docs/decisions/0003-proxy-dhcp-only.md` | 2026-10-25 (Accepted) | Project decision, not product behaviour | REQ-BOOT-010, REQ-BOOT-011, REQ-BOOT-012; INDEX BOOT-1 and Unconfirmed (DHCP coexistence); standards/proxy-dhcp.md header |
| DEC-0004 | M1 network-boot scope and per-device boot suppression | `docs/decisions/0004-m1-boot-scope-and-suppression.md` | 2026-10-26 (Accepted by the owner, 2026-10-26) | Project decision, not product behaviour | REQ-BOOT-003 (x86-64 and IPv4 scope), REQ-BOOT-005 (M1 architecture set), REQ-BOOT-007 (operator part), REQ-BOOT-050, REQ-BOOT-051; INDEX BOOT-2, BOOT-5 |

## Sources used

| ID | Title | URL | Accessed (UTC date) | Public? (how verified) | Used for (area codes in survey; REQ IDs once area specs exist) |
|----|-------|-----|---------------------|------------------------|-----------------------------------------|
| SRC-001 | Vendor blog: bare-metal imaging walkthrough (Tech Talks #82) | https://www.tanium.com/blog/bare-metal-imaging-with-tanium-provision-tanium-tech-talks-82/ | 2026-10-25 | Yes: anonymous fetch, public marketing blog, no gate | MEDIA, IMG, DISK, CFG, DOM, SEQ, AGT, TGT, RET |
| SRC-002 | Vendor blog: OS imaging for Windows and Linux endpoints | https://www.tanium.com/blog/windows-linux-endpoint-imaging-tanium-provision/ | 2026-10-25 | Yes: anonymous fetch, public marketing blog, no gate | AGT, RFR, RELAY, JOB |
| SRC-003 | Vendor solution brief: bare-metal provisioning (PDF, 2022) | https://site.tanium.com/rs/790-QFJ-925/images/SB-Tanium_Baremetal-provisioning-EN.pdf | 2026-10-25 | Yes: anonymous download of public marketing PDF, no form or gate. Fix round 1 re-check: the URL appears as the top result of an ordinary public web search on the brief's subject; the link goes straight to the PDF and no lead or registration form was shown. The host serves marketing assets that are sometimes form-gated, but this file was not. M1 run: downloaded again anonymously, still no form. | REQ-BOOT-001; MEDIA, DRV, DOM, RELAY |
| SRC-004 | Vendor public knowledge base: cloud release notes for the product (all releases 2022–2026) | https://kb.tanium.com/Tanium_Cloud_Release_Notes_Provision | 2026-10-25 | Yes: anonymous fetch of public KB page, no gate (re-checked in M1 run) | REQ-BOOT-001, REQ-BOOT-002, REQ-BOOT-003 (indirect: UEFI network boot), REQ-BOOT-020 (outcome only), REQ-BOOT-022 (outcome only), REQ-BOOT-030, REQ-BOOT-034, REQ-BOOT-044 (symptom only), REQ-BOOT-050 (outcome only), REQ-BOOT-052 (missing-content notice), REQ-BOOT-060, REQ-BOOT-061, REQ-BOOT-062; BOOT-3, BOOT-6 (not yet specced); MEDIA, PE, IMG, DRV, DISK, CFG, DOM, SEQ, TGT, RFR, RELAY, JOB, RBAC, AUD, RET, OS, limits |
| SRC-005 | Vendor public knowledge base: release notes version 1.5 | https://kb.tanium.com/Release_Notes_Provision_(Version_1.5) | 2026-10-25 | Yes: anonymous fetch of public KB page, no gate (re-checked in M1 run) | REQ-BOOT-001; MEDIA, PE, DOM, RFR, OS |
| SRC-006 | Vendor public knowledge base: release notes version 1.6 | https://kb.tanium.com/Release_Notes_Provision_(Version_1.6) | 2026-10-25 | Yes: anonymous fetch of public KB page, no gate (re-checked in M1 run) | REQ-BOOT-002, REQ-BOOT-020 (outcome only), REQ-BOOT-022 (outcome only), REQ-BOOT-052 (service status sentence only); BOOT-3 (not yet specced); PE, IMG, DRV, DISK, CFG, SEQ, TGT, RFR, RELAY, JOB, RBAC, OS, limits |
| SRC-007 | Vendor public knowledge base: release notes version 1.7 | https://kb.tanium.com/Release_Notes_Provision_(Version_1.7) | 2026-10-25 | Yes: anonymous fetch of public KB page, no gate (re-checked in M1 run) | REQ-BOOT-002, REQ-BOOT-020 (outcome only), REQ-BOOT-022 (outcome only), REQ-BOOT-053; BOOT-3, BOOT-6 (not yet specced); MEDIA, IMG, DRV, CFG, SEQ, TGT, RELAY |
| SRC-008 | Vendor public knowledge base: release notes version 1.8 | https://kb.tanium.com/Release_Notes_Provision_(Version_1.8) | 2026-10-25 | Yes: anonymous fetch of public KB page, no gate | PE, RET |
| SRC-009 | Public personal blog post (Out of Office Hours, M. Niehaus) describing the product's PXE, HTTP boot, and Wi-Fi/USB flows | https://oofhours.com/?p=3414 | 2026-10-25 | Yes: anonymous fetch of public blog; content readable with no login or form (the site's optional log-in link and subscribe widget do not gate it). Post dated 2022-03-05 (from the post URL), so it may be out of date. Why we treat it as vendor-associated: the author writes in the first person plural about building the product, the post is filed under the vendor's category on the blog, and it sends readers to their vendor representative. The author bio on the page does not name the vendor. No confidentiality or NDA marking. Not obtained through private contact with the author or vendor staff. Contains no code or downloads. Only public source for BOOT-4. In fix round 1, SRC-004 to SRC-008 were checked for HTTP boot and none mention it. M1 run: fetched again; it says little about PXE beyond the device being started into network boot with a firmware key on wired Ethernet. | boot-network.md "Actors" (person at the device: firmware boot key only). Removed from REQ-BOOT-003 and INDEX BOOT-2 in fix round 1 (CR-103). BOOT-4 (not yet specced); MEDIA, RELAY |
| SRC-010 | Vendor conference (Converge 2024) public session abstract: imaging service replacement | https://converge.tanium.com/2024/session/2475552/a-big-upgrade-for-imaging-services | 2026-10-25 | Yes: anonymous fetch of public session catalogue page, no gate | DOM, AGT |
| SRC-011 | IETF RFC 2131, Dynamic Host Configuration Protocol | https://www.rfc-editor.org/rfc/rfc2131 | 2026-10-25 | Yes: anonymous fetch from RFC Editor; IETF open standard | REQ-BOOT-002, REQ-BOOT-006, REQ-BOOT-007 (field facts), REQ-BOOT-020, REQ-BOOT-022, REQ-BOOT-070; standards/pxe-dhcp.md, standards/proxy-dhcp.md §4.1 |
| SRC-012 | IETF RFC 2132, DHCP Options and BOOTP Vendor Extensions | https://www.rfc-editor.org/rfc/rfc2132 | 2026-10-25 | Yes: anonymous fetch from RFC Editor; IETF open standard | REQ-BOOT-004, REQ-BOOT-006; standards/pxe-dhcp.md, standards/proxy-dhcp.md |
| SRC-013 | IETF RFC 4578, DHCP Options for the Intel PXE | https://www.rfc-editor.org/rfc/rfc4578 | 2026-10-25 | Yes: anonymous fetch from RFC Editor; IETF informational RFC | REQ-BOOT-003, REQ-BOOT-005, REQ-BOOT-007 (field facts), REQ-BOOT-043; standards/pxe-dhcp.md |
| SRC-014 | RFC Editor errata for RFC 4578 (erratum 4624, verified) | https://errata.rfc-editor.org/rfc4578 | 2026-10-26 | Yes: anonymous fetch from RFC Editor errata site | REQ-BOOT-003; standards/pxe-dhcp.md §5.2 |
| SRC-015 | IETF RFC 3046, DHCP Relay Agent Information Option | https://www.rfc-editor.org/rfc/rfc3046 | 2026-10-25 | Yes: anonymous fetch from RFC Editor; IETF open standard | REQ-BOOT-021, REQ-BOOT-043, REQ-BOOT-045; standards/pxe-dhcp.md §9, §10 |
| SRC-016 | IETF RFC 1542, Clarifications and Extensions for BOOTP (relay agents) | https://www.rfc-editor.org/rfc/rfc1542 | 2026-10-25 | Yes: anonymous fetch from RFC Editor; IETF open standard | REQ-BOOT-002, REQ-BOOT-020, REQ-BOOT-022, REQ-BOOT-023; standards/pxe-dhcp.md §9 |
| SRC-017 | IANA DHCPv6 parameters registry, Processor Architecture Types | https://www.iana.org/assignments/dhcpv6-parameters/dhcpv6-parameters.xhtml | 2026-10-26 | Yes: anonymous fetch of public IANA registry | REQ-BOOT-003; standards/pxe-dhcp.md §5.2 |
| SRC-018 | IETF Internet-Draft draft-henry-remote-boot-protocol-00, Intel Preboot Execution Environment (June 1999, expired) | https://datatracker.ietf.org/doc/html/draft-henry-remote-boot-protocol-00 | 2026-10-25 | Yes: anonymous fetch from IETF Datatracker; an expired individual draft published openly by Intel through the IETF; no gate. Used in place of the PXE 2.1 PDF, which could not be retrieved (see below) | REQ-BOOT-001, REQ-BOOT-004, REQ-BOOT-010, REQ-BOOT-043, REQ-BOOT-045; standards/pxe-dhcp.md, standards/proxy-dhcp.md (§1 limited in fix round 1 to: optional arrangement, PXE clients only, same or separate host). Re-fetched 2026-10-26 for CR-106 |
| SRC-019 | UEFI Specification 2.10, Appendix E (Universal Network Driver Interfaces), incl. E.4.20 PXE 2.1 wire-protocol clarifications | https://uefi.org/specs/UEFI/2.10/Apx_E_Universal_Network_Driver_Interfaces.html | 2026-10-25 | Yes: anonymous fetch of HTML specification published by the UEFI Forum; no click-through | REQ-BOOT-011, REQ-BOOT-022, REQ-BOOT-051, REQ-BOOT-070; standards/pxe-dhcp.md, standards/proxy-dhcp.md |
| SRC-020 | UEFI Specification 2.10, chapter 24 (Network Protocols: SNP, PXE, BIS), §24.3 PXE Base Code | https://uefi.org/specs/UEFI/2.10/24_Network_Protocols_SNP_PXE_BIS.html | 2026-10-25 | Yes: as SRC-019 | REQ-BOOT-001, REQ-BOOT-012, REQ-BOOT-013, REQ-BOOT-030, REQ-BOOT-031, REQ-BOOT-051; standards/pxe-dhcp.md, standards/tftp.md, standards/uefi-boot-manager.md |
| SRC-021 | UEFI Specification 2.10, chapter 3 (Boot Manager) | https://uefi.org/specs/UEFI/2.10/03_Boot_Manager.html | 2026-10-25 | Yes: as SRC-019 | REQ-BOOT-012, REQ-BOOT-050, REQ-BOOT-051, REQ-BOOT-060, REQ-BOOT-061; boot-network.md "Actors" (boot order); standards/uefi-boot-manager.md |
| SRC-022 | UEFI Specification 2.10, chapter 32 (Secure Boot and Driver Signing) | https://uefi.org/specs/UEFI/2.10/32_Secure_Boot_and_Driver_Signing.html | 2026-10-25 | Yes: as SRC-019 | standards/uefi-secure-boot.md (background; OPEN-BOOT-SB) |
| SRC-023 | UEFI Specification 2.10, chapter 7 (Boot Services), §7.4 image services | https://uefi.org/specs/UEFI/2.10/07_Services_Boot_Services.html | 2026-10-26 | Yes: as SRC-019 | standards/uefi-secure-boot.md §5, standards/uefi-boot-manager.md §5.1 |
| SRC-024 | Microsoft Learn: PXE clients don't start (DHCP options 60, 66, 67; former KB 259670) | https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/pxe-clients-not-start-dhcp-60-66-67-option | 2026-10-25 | Yes: anonymous fetch of public Microsoft Learn page (reached by redirect from support.microsoft.com/kb/259670) | REQ-BOOT-002, REQ-BOOT-011, REQ-BOOT-014, REQ-BOOT-023; standards/proxy-dhcp.md §4.2, §5 |
| SRC-025 | Microsoft Learn: Secure boot (OEM guidance) | https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-secure-boot | 2026-10-26 | Yes: anonymous fetch of public Microsoft Learn page | standards/uefi-secure-boot.md |
| SRC-026 | IETF RFC 1350, The TFTP Protocol (Revision 2) | https://www.rfc-editor.org/rfc/rfc1350 | 2026-10-25 | Yes: anonymous fetch from RFC Editor; IETF open standard | REQ-BOOT-030, REQ-BOOT-032, REQ-BOOT-033 (sole source), REQ-BOOT-035, REQ-BOOT-040, REQ-BOOT-041, REQ-BOOT-043; standards/tftp.md |
| SRC-027 | IETF RFC 2347, TFTP Option Extension | https://www.rfc-editor.org/rfc/rfc2347 | 2026-10-25 | Yes: anonymous fetch from RFC Editor | REQ-BOOT-031; standards/tftp.md §6 |
| SRC-028 | IETF RFC 2348, TFTP Blocksize Option | https://www.rfc-editor.org/rfc/rfc2348 | 2026-10-25 | Yes: anonymous fetch from RFC Editor | REQ-BOOT-031, REQ-BOOT-035; standards/tftp.md §7, §8 |
| SRC-029 | IETF RFC 2349, TFTP Timeout Interval and Transfer Size Options | https://www.rfc-editor.org/rfc/rfc2349 | 2026-10-25 | Yes: anonymous fetch from RFC Editor | REQ-BOOT-031 (standards cite); standards/tftp.md §7 |
| SRC-030 | IETF RFC 7440, TFTP Windowsize Option | https://www.rfc-editor.org/rfc/rfc7440 | 2026-10-25 | Yes: anonymous fetch from RFC Editor | REQ-BOOT-032, REQ-BOOT-044 (standards cite); standards/tftp.md §10 (conditional) |
| SRC-031 | IETF RFC 1123, Requirements for Internet Hosts (§4.2 TFTP) | https://www.rfc-editor.org/rfc/rfc1123 | 2026-10-25 | Yes: anonymous fetch from RFC Editor | REQ-BOOT-032, REQ-BOOT-040, REQ-BOOT-041, REQ-BOOT-042; standards/tftp.md |
| SRC-032 | IETF RFC 5970, DHCPv6 Options for Network Boot | https://www.rfc-editor.org/rfc/rfc5970 | 2026-10-26 | Yes: anonymous fetch from RFC Editor | standards/pxe-dhcp.md §11 (conditional) |
| SRC-033 | Wikipedia: Preboot Execution Environment (secondary reference) | https://en.wikipedia.org/wiki/Preboot_Execution_Environment | 2026-10-25 | Yes: anonymous fetch of public encyclopedia article. Secondary source; cites PXE 2.1 for the DHCP/ProxyDHCP split. Used only where marked [secondary] | REQ-BOOT-004, REQ-BOOT-010, REQ-BOOT-014; standards/proxy-dhcp.md (§1 and §5 address-division and no-site-change points, §4.1, §4.2; all [secondary]) |
| SRC-034 | Public technical blog post (sysmgr.org, 2010) on PXE discovery control | https://sysmgr.org/blog/2010/06/19/forcing_pxe_clients_not_to_broadcast_for_extra_dhcp_options/ | 2026-10-25 | Yes: anonymous fetch of public blog; no gate. Secondary source; not vendor-related | REQ-BOOT-010; standards/pxe-dhcp.md §6, standards/proxy-dhcp.md |
| SRC-035 | iPXE project public commit message: honour discovery-control skip option | https://github.com/ipxe/ipxe/commit/620b98ee4b9d8fa87c56bfa72b4391c1eed9dce6 | 2026-10-25 | Yes: anonymous fetch of public GitHub page for the open-source iPXE project (not vendor). Only the commit message was used. The fetch was told to ignore the code diff, and no code was copied or summarised | standards/pxe-dhcp.md §6, standards/proxy-dhcp.md §3 (secondary) |
| SRC-036 | IBM Documentation (AIX 7.2): PXE vendor container suboption | https://www.ibm.com/docs/ssw_aix_72/network/tcpip_dhcp_preboot.html | 2026-10-25 | Yes: anonymous fetch of public IBM docs page; no gate. Third-party product documentation, used only to back up the standard port-4011 same-host arrangement | REQ-BOOT-014; standards/proxy-dhcp.md §4.2 |

## Consulted, not used

| Title | URL | Accessed (UTC date) | Reason not used |
|-------|-----|---------------------|-----------------|
| Vendor online user guide (help/resource center) | https://help.tanium.com/bundle/ug_provision_cloud/page/provision/index.html (redirect target of https://docs.tanium.com/provision/provision/index.html) | 2026-10-25 | Page is script-rendered; anonymous fetch returned only an empty shell with no product content. Re-try with a rendering-capable fetch in a later run if still login-free. If it is used, take user-visible behaviour only (see the rules above). Not retried in the M1 run. |
| Vendor privacy datasheet (PDF) | https://site.tanium.com/rs/790-QFJ-925/images/Tanium-Provision-Privacy-Datasheet.pdf | 2026-10-25 | Redirected to vendor home page; content not retrieved. |
| Vendor blog: Tech Talks #55 | https://www.tanium.com/blog/tanium-provision-part-1-tech-talks-55/ | 2026-10-25 | Public, but contained no capability detail (video only). |
| Public web search, fix round 1 (query on the vendor's bare-metal provisioning solution brief) | n/a (search engine results page) | 2026-10-25 | Run only to confirm SRC-003 can be reached from a public search (CR-007). The search tool's result summary included snippet text from SRC-003's relay section. That text was not used. RELAY-1 and RELAY-2 were rewritten in fix round 1 from the behavioural idea, with a new structure, and not from the snippet or the PDF. Disclosed in the run's spec report. |
| Competitor comparison page (ManageEngine) | https://www.manageengine.com/uk/products/desktop-central/endpoint-central-vs-tanium.html | 2026-10-25 | Seen only as a search-result snippet; competitor claim, not authoritative. Not fetched or used. |
| UEFI Forum related-documents page | https://uefi.org/uefi | 2026-10-25 | Used only to find where the UEFI Forum points readers for the PXE 2.1 specification (a third-party copy at pix.net). No behaviour taken from it. |
| Intel PXE Specification 2.1, copy linked by the UEFI Forum | http://www.pix.net/software/pxeboot/archive/pxespec.pdf (also tried over https) | 2026-10-25 | Fetch failed with no response. Not read. |
| Intel PXE Specification 2.1, university wiki copy | https://wiki.cs.umbc.edu/images/3/3d/Pxespec.pdf | 2026-10-25 | TLS certificate rejected; not read. Its origin and redistribution terms are unverified, so it was not pursued further. |
| Intel PXE Specification 2.1, Intel download URL | https://download.intel.com/design/archives/wfm/downloads/pxespec.pdf | 2026-10-25 | HTTP 403. Not read. |
| Internet Archive copy of the pix.net PXE PDF | https://web.archive.org/web/2020id_/http://www.pix.net/software/pxeboot/archive/pxespec.pdf | 2026-10-25 | Fetch tool cannot reach web.archive.org. Not read. |
| IETF draft-viswanathan-remote_boot-protocol-00 (earlier Intel PXE draft) | https://datatracker.ietf.org/doc/html/draft-viswanathan-remote_boot-protocol-00 ; https://potaroo.net/ietf/idref/draft-viswanathan-remote_boot-protocol | 2026-10-25 | 404 and fetch failure. Superseded by SRC-018 in any case. |
| dnsmasq manual page | https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html ; https://dnsmasq.org/docs/dnsmasq-man.html | 2026-10-25 | Fetch failed; not read. |
| ISC DHCP PXE option definitions file (NetBSD and Minix source mirrors) | https://ftp.riken.jp/NetBSD/NetBSD-current/src/external/mpl/dhcp/share/dhcpd/pxe.defs ; https://src.rcs.uwaterloo.ca/xref/minix3/external/bsd/dhcp/share/dhcpd/pxe.defs | 2026-10-25 | Connection refused; not read. A search-result summary described its discovery-control bit list. That summary was not relied on; bit 3 rests on SRC-034 and SRC-035 and is marked secondary. |
| Cisco support document: Understanding and troubleshooting PXE boot (ACI) | https://www.cisco.com/c/en/us/support/docs/cloud-systems-management/application-policy-infrastructure-controller-apic/212041-Understanding-and-Troubleshooting-PXE-bo.html | 2026-10-25 | Public; read. Third-party product-specific detail that added nothing beyond SRC-024. Not used. |
| Public web searches, M1 run (three queries: PXE 2.1 specification copy; ProxyDHCP port 4011 with option 60; PXE discovery-control bit 3) | n/a (search engine results pages) | 2026-10-25 | Used only to find standards copies and public references. No query named the vendor or its product. The result summaries quoted open-source project text (iPXE, ISC DHCP) and Microsoft KB text, not vendor text. Nothing was copied from the summaries. |
