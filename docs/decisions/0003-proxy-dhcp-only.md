# 0003: Boot Service Never Leases Addresses (ProxyDHCP Only)

- Status: Accepted
- Date: 2026-10-25
- Decider: project owner
- Resolves: roadmap decision D-1 (DHCP coexistence)

## Context

Network boot requires boot options to reach PXE/UEFI clients. Sites already
run DHCP servers; a second address-leasing server on a segment is a rogue-DHCP
risk and an operational hazard.

## Decision

The boot service **never assigns IP addresses**. It answers PXE/HTTP-boot
clients only as a ProxyDHCP responder (selected by the vendor-class
identifier, RFC 2132 option 60, per the PXE specification, with client
architecture from RFC 4578 option 93), alongside the site's DHCP server.
A mode where the site's own DHCP carries the boot options and the boot
service runs no DHCP listener at all is also permitted,
since it leases nothing either. A full DHCP server mode is out of scope.

## Consequences

- `usgp-dhcp` implements only ProxyDHCP replies; any code path that would
  emit a lease (`yiaddr` != 0 in an OFFER/ACK) is a defect.
- Documentation explains the site-DHCP configuration alternative.
