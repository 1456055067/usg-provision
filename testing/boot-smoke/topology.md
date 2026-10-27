# Boot smoke lab topology (test only)

`scripts/boot-smoke.sh` builds this lab on a Linux host as root (plan WU-11,
section 10.5). It is test infrastructure, not part of the product. Every
name below is created at the start of a run and removed on any exit.

```text
 namespace usgp-lab: bridges br-a, br-b, br-x and the QEMU taps
 (no addresses; pure L2)

 br-a 10.20.1.0/24 (segment A)         br-b 10.20.2.0/24 (segment B)
  |- tapA, tapA2 (QEMU guests A)        |- tapB (QEMU guest B, S2, S8)
  |- usgp-relay  relay0 10.20.1.2       |
  |              (configured)           |
  |- usgp-site   dhcp0  10.20.1.3       |
  |              lab-dhcpd, pools A, B  |
  |- usgp-router rtA    10.20.1.1 ------+- rtB 10.20.2.1
  |              ip_forward=1, lab-relay-agent
  |              (client side rtB -> servers 10.20.1.3, 10.20.1.2)
  |- usgp-probe  p0     10.20.1.9 (lab-probe)

 br-x 10.20.9.0/24 (unconfigured segment)
  |- usgp-relay  relay9 10.20.9.2 (NOT in relay.toml; S4 probe)
  |- usgp-probe  px     10.20.9.9
```

Each leg is a veth pair. The bridge side is named `v<ifname>`, for example
`vrelay0`. `usgp-relay`, `usgp-site` and `usgp-probe` route 10.20.2.0/24
through 10.20.1.1. Reverse-path filtering is off in every namespace.

## Processes

| Process | Namespace | Runs as |
|---------|-----------|---------|
| `usgp-relay --config` (release, FIPS build) | usgp-relay | uid 65534, ambient `net_bind_service,net_raw` only, no-new-privs |
| `lab-dhcpd` | usgp-site | same as the relay |
| `lab-relay-agent` | usgp-router | same as the relay |
| `lab-probe` | usgp-probe | same as the relay |
| `qemu-system-x86_64` | usgp-lab | `$SUDO_USER` (or `USGP_QEMU_USER`), the owner of the taps |

## Simplification: the lab relay agent always broadcasts replies

`lab-relay-agent` sends every reply it relays to the client segment as a
limited broadcast to port 68. RFC 1542 §4.1.2 says a relay agent unicasts
to `yiaddr` and the `chaddr` link address when `yiaddr` is not 0 and the
BROADCAST flag is clear (`specs/standards/pxe-dhcp.md` §9). The agent does
not do that, because a UDP socket cannot send to a client that has no ARP
entry yet; doing it would need a raw link-layer socket or a static
neighbour entry per client.

Effect on the scenarios (finding BOOT-007):

- usgp-relay's replies always have `yiaddr` = 0. For them, broadcast is
  the only usable delivery: `specs/standards/pxe-dhcp.md` §9 (RFC 1542
  §4.1.2) does not cover a reply with `yiaddr` = 0 and BROADCAST clear,
  so this is our reading, not a rule stated in RFC 1542. The relay's own
  reply addressing is checked separately (it sends to `giaddr`, port 67).
- `lab-dhcpd`'s OFFER and ACK carry an address. When the guest clears
  BROADCAST, S2 delivers them by broadcast, not unicast. S2 therefore does
  not show that a client accepts a unicast relayed reply. That is client
  and router behaviour, not usgp-relay behaviour, and it is out of M1
  scope.

## Guest MAC addresses

| MAC | Use |
|-----|-----|
| 52:54:00:00:01:00 | preflight firmware PXE check |
| 52:54:00:00:01:01 | S1 |
| 52:54:00:00:02:01 | S2 (segment B) |
| 52:54:00:00:01:03 | S3 |
| 52:54:00:00:01:05, 52:54:00:00:01:15 | S5, first and second NIC |
| 52:54:00:00:01:06 | S6 |
| 52:54:00:00:01:07 | S7 |
| 52:54:00:00:01:08, 52:54:00:00:02:08 | S8 |

Each scenario uses its own MAC, so per-client rate limits from one
scenario do not affect the next.

## Guest boot options in fall-through scenarios

S6 and S7 expect a guest's network boot to fail and the boot manager to
move on to the disk (`specs/standards/uefi-boot-manager.md` §5); S5 expects
it to move on after the firmware refuses the image. OVMF creates four
network boot options per NIC (IPv4 PXE, IPv6 PXE, IPv4 HTTP, IPv6 HTTP),
and QEMU's `bootindex` on the NIC places all four ahead of the disk. Each
failed network option costs about 60 s of firmware timeouts, so the disk
came up only after about 250 s, past the first CI run's deadline.

The harness therefore starts these guests with the fw_cfg item
`opt/org.tianocore/IPv6Support=no` (`vm_start --ipv4-only`), which turns
off the firmware's IPv6 network stack. The guest then tries IPv4 PXE, IPv4
HTTP, and the disk (about 120 s). This was checked against Ubuntu 24.04's
ovmf package 2024.02-2ubuntu0.10, the build the CI runner used (same
SHA-256 for `OVMF_CODE_4M.fd`, `OVMF_VARS_4M.fd`,
`OVMF_CODE_4M.secboot.fd` and `OVMF_VARS_4M.ms.fd` as in the run's
`environment.txt`): the item name is present in both firmware builds, and
a guest started with it skipped both IPv6 options. Neither that build nor
QEMU offers a switch for IPv4 HTTP boot, and `-boot strict=on` does not
remove it (also checked). Firmware that does not know the item ignores it.

As a fallback, the fall-through deadline (`USGP_FALLTHROUGH_DEADLINE`,
default twice the boot deadline plus 180 s: 420 s with KVM, 780 s with
TCG) covers the full four-option sequence. The wait ends as soon as a
marker appears, so the longer deadline costs time only when a scenario is
failing.

Besides the disk marker, S6 and S7 require positive evidence of the
fall-through on the serial console: the firmware's line reporting that the
IPv4 PXE boot option failed (`failed to load Boot#### "UEFI PXEv4 ...`)
must come before the disk payload's marker. The `PXE-E16` line and whether
any IPv6 option was tried are recorded as evidence.

## Evidence

Each run writes to `target/boot-smoke/run-<UTC time>/` (or
`USGP_BOOT_SMOKE_OUT`):

- `results.txt` and `summary.txt`;
- `relay.log` (the relay's JSON audit lines), `lab-dhcpd.log` and
  `lab-relay-agent.log`;
- `serial/<scenario>.log` and the QEMU logs;
- `probe/*.log` and `probe/ss-ulpn.txt`;
- `config/` (relay config, manifest, `usgp-cli` output, `--check-config`
  output);
- `topology.txt` and `environment.txt` (tool versions and SHA-256 of
  firmware and artifacts).
