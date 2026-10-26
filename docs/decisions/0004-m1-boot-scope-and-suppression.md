# 0004: M1 Network-Boot Scope and Per-Device Boot Suppression

- Status: Accepted (owner, 2026-10-26)
- Date: 2026-10-26
- Decider: project owner
- Drafted by: orchestrator (clean side), from docs/ROADMAP.md M1 and the
  M1 spec request; written to resolve clean-room finding CR-104
- Basis: project design (docs/ROADMAP.md M1); not described product behaviour

## Context

Milestone M1 delivers network boot to a test payload. The roadmap scopes it
to one firmware/architecture and one address family, and needs a way to stop
the boot service from offering a boot program to a given device so that the
device falls through to its next boot option (groundwork for BOOT-5).

## Decision

1. **Scope.** M1 serves UEFI x86-64 PXE clients (client architecture type 7,
   RFC 4578 as corrected by erratum 4624) over IPv4 only. Legacy BIOS, ARM,
   HTTP boot and IPv6 are later milestones.
2. **Suppression.** An operator can mark a device so that the boot service
   offers it no boot program, and can lift that mark. A suppressed device
   gets no reply at all, so its firmware treats the network boot option as
   failed and moves to its next boot option.
3. **Device identity for suppression.** A device is identified by its DHCP
   hardware address (`chaddr`) and, when sent, its client machine identifier
   (RFC 4578 option 97 GUID); the operator may use either. This does not
   imply pre-registration of devices.
4. Suppression is a convenience, not an access control: identifiers on the
   boot network are unauthenticated.

## Consequences

- Specs that rely on these points cite this decision and label themselves
  as project design.
- Automatic suppression after a completed install, and the persistent boot
  order question, remain open product questions (BOOT-5 REQs 061/062).
