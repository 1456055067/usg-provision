# Provenance log

Dirty-side record. Clean-side agents do not read this file.

Public-access verification method for every row: the page was retrieved
anonymously over HTTPS by an automated fetcher with no cookies, credentials,
or session, and the returned content showed no login wall, licence
click-through, or customer-portal gate. All accessed 2026-10-25 (UTC).

Rules for later runs (fix round 1, CR-008):

- In survey mode the last column lists area codes. When area specs are
  drafted, replace the area codes with the REQ IDs each source supports.
- If the vendor online user guide becomes readable and is used, take only
  user-visible behaviour from it. Its UI layouts, field and setting names,
  internal component names, and sample values must not reach `specs/`.

## Sources used

| ID | Title | URL | Accessed (UTC date) | Public? (how verified) | Used for (area codes in survey; REQ IDs once area specs exist) |
|----|-------|-----|---------------------|------------------------|-----------------------------------------|
| SRC-001 | Vendor blog: bare-metal imaging walkthrough (Tech Talks #82) | https://www.tanium.com/blog/bare-metal-imaging-with-tanium-provision-tanium-tech-talks-82/ | 2026-10-25 | Yes: anonymous fetch, public marketing blog, no gate | MEDIA, IMG, DISK, CFG, DOM, SEQ, AGT, TGT, RET |
| SRC-002 | Vendor blog: OS imaging for Windows and Linux endpoints | https://www.tanium.com/blog/windows-linux-endpoint-imaging-tanium-provision/ | 2026-10-25 | Yes: anonymous fetch, public marketing blog, no gate | AGT, RFR, RELAY, JOB |
| SRC-003 | Vendor solution brief: bare-metal provisioning (PDF, 2022) | https://site.tanium.com/rs/790-QFJ-925/images/SB-Tanium_Baremetal-provisioning-EN.pdf | 2026-10-25 | Yes: anonymous download of public marketing PDF, no form or gate. Fix round 1 re-check: the URL appears as the top result of an ordinary public web search on the brief's subject; the link goes straight to the PDF and no lead or registration form was shown. The host serves marketing assets that are sometimes form-gated, but this file was not. | BOOT, MEDIA, DRV, DOM, RELAY |
| SRC-004 | Vendor public knowledge base: cloud release notes for the product (all releases 2022–2026) | https://kb.tanium.com/Tanium_Cloud_Release_Notes_Provision | 2026-10-25 | Yes: anonymous fetch of public KB page, no gate | BOOT, MEDIA, PE, IMG, DRV, DISK, CFG, DOM, SEQ, TGT, RFR, RELAY, JOB, RBAC, AUD, RET, OS, limits |
| SRC-005 | Vendor public knowledge base: release notes version 1.5 | https://kb.tanium.com/Release_Notes_Provision_(Version_1.5) | 2026-10-25 | Yes: anonymous fetch of public KB page, no gate | BOOT, MEDIA, PE, DOM, RFR, OS |
| SRC-006 | Vendor public knowledge base: release notes version 1.6 | https://kb.tanium.com/Release_Notes_Provision_(Version_1.6) | 2026-10-25 | Yes: anonymous fetch of public KB page, no gate | BOOT, PE, IMG, DRV, DISK, CFG, SEQ, TGT, RFR, RELAY, JOB, RBAC, OS, limits |
| SRC-007 | Vendor public knowledge base: release notes version 1.7 | https://kb.tanium.com/Release_Notes_Provision_(Version_1.7) | 2026-10-25 | Yes: anonymous fetch of public KB page, no gate | BOOT, MEDIA, IMG, DRV, CFG, SEQ, TGT, RELAY |
| SRC-008 | Vendor public knowledge base: release notes version 1.8 | https://kb.tanium.com/Release_Notes_Provision_(Version_1.8) | 2026-10-25 | Yes: anonymous fetch of public KB page, no gate | PE, RET |
| SRC-009 | Public personal blog post (Out of Office Hours, M. Niehaus) describing the product's PXE, HTTP boot, and Wi-Fi/USB flows | https://oofhours.com/?p=3414 | 2026-10-25 | Yes: anonymous fetch of public blog; content readable with no login or form (the site's optional log-in link and subscribe widget do not gate it). Post dated 2022-03-05 (from the post URL), so it may be out of date. Why we treat it as vendor-associated: the author writes in the first person plural about building the product, the post is filed under the vendor's category on the blog, and it sends readers to their vendor representative. The author bio on the page does not name the vendor. No confidentiality or NDA marking. Not obtained through private contact with the author or vendor staff. Contains no code or downloads. Only public source for BOOT-4. In fix round 1, SRC-004 to SRC-008 were checked for HTTP boot and none mention it. | BOOT, MEDIA, RELAY |
| SRC-010 | Vendor conference (Converge 2024) public session abstract: imaging service replacement | https://converge.tanium.com/2024/session/2475552/a-big-upgrade-for-imaging-services | 2026-10-25 | Yes: anonymous fetch of public session catalogue page, no gate | DOM, AGT |

## Consulted, not used

| Title | URL | Accessed (UTC date) | Reason not used |
|-------|-----|---------------------|-----------------|
| Vendor online user guide (help/resource center) | https://help.tanium.com/bundle/ug_provision_cloud/page/provision/index.html (redirect target of https://docs.tanium.com/provision/provision/index.html) | 2026-10-25 | Page is script-rendered; anonymous fetch returned only an empty shell with no product content. Re-try with a rendering-capable fetch in a later run if still login-free. If it is used, take user-visible behaviour only (see the rules above). |
| Vendor privacy datasheet (PDF) | https://site.tanium.com/rs/790-QFJ-925/images/Tanium-Provision-Privacy-Datasheet.pdf | 2026-10-25 | Redirected to vendor home page; content not retrieved. |
| Vendor blog: Tech Talks #55 | https://www.tanium.com/blog/tanium-provision-part-1-tech-talks-55/ | 2026-10-25 | Public, but contained no capability detail (video only). |
| Public web search, fix round 1 (query on the vendor's bare-metal provisioning solution brief) | n/a (search engine results page) | 2026-10-25 | Run only to confirm SRC-003 can be reached from a public search (CR-007). The search tool's result summary included snippet text from SRC-003's relay section. That text was not used. RELAY-1 and RELAY-2 were rewritten in fix round 1 from the behavioural idea, with a new structure, and not from the snippet or the PDF. Disclosed in the run's spec report. |
| Competitor comparison page (ManageEngine) | https://www.manageengine.com/uk/products/desktop-central/endpoint-central-vs-tanium.html | 2026-10-25 | Seen only as a search-result snippet; competitor claim, not authoritative. Not fetched or used. |
