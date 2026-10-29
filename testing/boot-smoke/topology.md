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

 S9 only: root namespace usgp-srv0 10.20.250.1/30 <-veth-> usgp-relay srv0
 10.20.250.2/30 (usgp-server's operator and relay listener, :18443).
 The server's device listener is 127.0.0.1:18444 in the root namespace,
 where the simulated agent runs. PostgreSQL is the container of
 scripts/pg-test-setup.sh on 127.0.0.1.
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
| `usgp-server serve` (S9) | root namespace | the QEMU user, which is also its `--admin-uid` (`--allow-shared-admin-uid`, as in the server tests); the admin database key is mode 0000 while it runs |
| `usgp-preboot-agent --sim` (S9) | root namespace | the QEMU user; disks are regular files |
| `usgp-relay --config relay-feed.toml` (S9) | usgp-relay | as the relay above; replaces the S1 to S8 relay for S9 only |

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
| 52:54:00:00:01:09 | S9 (also the simulated agent's MAC, so the job's boot stop names it) |

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

## M3 scenarios S9 and S10 (plan M3 section 10.3)

S9 (BOOT-5 stop, REQ-BOOT-067 and REQ-BOOT-061) runs after S8, as the last
network scenario:

1. A throwaway CA (openssl, ECDSA P-384, two days, with a CRL) issues the
   server, operator and relay certificates; the CA key is then deleted.
   `usgp-server keygen` makes the five server keys. The server is migrated
   on the pg-test-setup database; the operator and the relay's certificate
   (as a boot service for 127.0.0.0/8 and 10.20.0.0/16) are enrolled.
2. `usgp-server serve` starts. The S1 to S8 relay is stopped and the relay
   is started again with `[server_feed]` (poll 5 s). It must apply the
   server's signed list (0 stops) before anything else.
3. `usgp-cli` uploads the synthetic image (`fuzz/corpus/wim_apply_plan/
   xpress.bin`) and PE (`fuzz/corpus/wim_check/none-1.bin`), declares the
   edition, makes the package Ready and assigns it to the boot service.
4. Positive control: the guest PXE-boots the payload.
5. `usgp-cli code issue`; the agent with `--sim` (MAC 52:54:00:00:01:09, a
   70 GB sparse target file and a 4 MiB second file) answers the code,
   package 1, disk 1 and `WIPE` on standard input. The code is never
   written to the evidence. The job must be Succeeded, the second file
   unchanged, `sgdisk -v` clean on the target, and one active boot stop
   listed for the MAC.
6. The relay applies the next generation with 1 stop. The ESP of the
   agent-written disk gets a FAT file system (mkfs.fat) holding the disk
   payload, so the device's own disk is what it falls through to.
7. Stopped boot: the PXE option fails before the disk marker (as in S6),
   `boot.device.stopped` names the MAC, and no offer was sent to it.
8. `usgp-cli boot-stop clear`; the relay applies a later generation with 0
   stops; the next boot is a normal PXE boot again.

S10 (our GPT under independent firmware, OPEN-GPT-1, GPT-OBS-002) needs no
network or root. Its disks are rebuilt from two committed seeds made by
`usgp_disk::GptPlan` (`fuzz/corpus/gpt_readback/SOURCE.md`):

| Case | Disk | Pass condition |
|------|------|----------------|
| `s10-512` | `wu14-gpt-512-two-parts.bin`, 512-byte sectors; the ESP (entry 0, type checked with `od`) holds a mkfs.fat file system with the payload as `\EFI\BOOT\BOOTX64.EFI`; `sgdisk -v` clean | the payload marker |
| `s10-512-primary-bad` | the same with one octet of the primary header changed (its CRC fails) | the payload marker: the firmware used our backup header and array |
| `s10-512-arrays-bad` | the same with one octet of entry 0 changed in both arrays | no marker, and the firmware's `failed to load Boot####` line for the disk |
| `s10-4096` | `wu14-gpt-4096-one-part.bin` on a 4096-byte logical sector disk (`logical_block_size=4096`); the basic data partition holds the payload | the payload marker |

The FAT file system is placed at the partition's first LBA, read from the
table with `od`, never at LBA 0, so the firmware can reach the payload
only through the partition table. Whether the firmware rewrote the primary
header from the backup (and the disk then equals what usgp-disk wrote) is
recorded as information. `s10/gpt-obs-002.txt` holds the run's GPT-OBS-002
record.

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
  firmware and artifacts);
- `s9/` (server log, every `usgp-cli` and admin command's output, the
  agent's screen, `sgdisk` output) and `config/server-s9.toml`,
  `config/relay-feed.toml`;
- `s10/` (`sgdisk -v` output and `gpt-obs-002.txt`).
