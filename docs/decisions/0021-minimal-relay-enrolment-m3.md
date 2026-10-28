# 0021: Minimal Relay Enrolment Brought Forward to M3

- Status: Accepted (owner, 2026-10-28)
- Date: 2026-10-28
- Decider: project owner
- Refines: roadmap M5 (relay enrolment)
- Resolves: M3 plan questions Q3 and Q4

## Context

REQ-BOOT-067 requires the boot service to stop offering a boot program to
a device once its job has succeeded. REQ-TGT-001 offers packages per boot
service. Both need the relay to know which server it serves, and to learn
job outcomes from it. Full enrolment and caching are in M5.

## Decision

1. M3 adds manual enrolment. An administrative server command binds a
   relay's client certificate to a boot-service record and the subnets it
   serves. The command is audited.
2. The relay pulls a signed, generation-numbered boot-policy list from the
   server over mTLS, and refuses a generation older than the last one it
   applied. Devices whose jobs have succeeded are on the stop list.
3. A stop is reversed only by an audited `boot-stop clear` operator
   command, until REQ-BOOT-062 is specced.
4. Content verification uses two passes (plan question Q4). Before the
   wipe, the agent downloads and verifies all content for the selected
   edition and then discards it. During apply, it fetches and verifies the
   content again. Network transfer doubles, but no content is written to
   disk before it has been verified, and no staging space is needed.

## Consequences

- Automatic enrolment, caching and relay health remain in M5.
- The M5 cache will reduce the cost of the second fetch.
