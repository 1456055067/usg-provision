# 0023: M3 Review Decisions: Token Binding, Boot Stops, Space Reserve

- Status: Accepted (owner, 2026-10-29)
- Date: 2026-10-29
- Decider: project owner
- Amends: decision 0020 (token wording), decision 0021 item 2 (boot-stop
  scope)
- Resolves: review findings NIST-008, SEC-002, BOOT-005, BOOT-003 (M3)

## Decision

1. **Device session token (NIST-008).** The token is bound to the source
   network it was issued to: the same per-source key the rate limits use
   (an IPv4 address or an IPv6 /64). A request from another source network
   is refused and audited. A confirmed session expires with its job's
   lost-job timeout, so a token never outlives its job's activity.
   Clarified 2026-10-29: for an unfinished job the token stops working
   at last contact plus twice the lost-job timeout, so a lost job can
   still resume (`specs/progress.md`); for a finished job, at finish
   plus the lost-job timeout.
   Decision 0020's phrase "bound to the TLS session" is replaced by "bound
   to the session's source network, with an expiry". The residual risk (a
   host on the same source network) is recorded as a POA&M item.
2. **Boot stops (SEC-002, BOOT-005).** Stops are still recorded for the
   MAC addresses the agent claims, with these guards:
   - the claimed MACs are shown at confirmation and recorded in
     `job.succeeded`;
   - a MAC that already has a live stop, or a running job under another
     session, is refused at confirmation;
   - each stop is marked "claimed" in its audit record;
   - stops apply on every active boot service whose subnets include the
     device's source address, not only on the job's own boot service.

   Stops based on MACs the relay observed, and stops by the SMBIOS UUID or
   DHCP option 97 GUID, are recorded as a POA&M item for M5.
3. **Space reserve (BOOT-003).** Both the pre-wipe check and the minimum
   disk size require the image's expanded size plus a documented
   file-system overhead estimate plus 16 GiB free on the Windows partition
   (`gpt.md` §10). An image that does not fit is refused before anything
   is written.

## Consequences

- `usgp-api` and `usgp-db` change for items 1 and 2, and `usgp-disk` and
  `usgp-deploy` for item 3.
- The compliance mapping records SC-23 and AC-12 with the source-network
  binding. The two residuals become POA&M items.
