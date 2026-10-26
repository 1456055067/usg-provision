# usgp-netlab (test only)

Lab network tools for the M1 boot smoke (plan WU-10, section 10.5). This is
**not part of the product**. It is a separate Cargo workspace, excluded from
the product workspace by the root `Cargo.toml` (`exclude = ["testing"]`). It
must never be a dependency of a product crate, and it must not depend on
`usgp-dhcp` or `usgp-tftp`. It has its own small DHCP and TFTP codecs, so a
bug in the product codec cannot be hidden by the same bug here.

| Binary | Role | Standards |
|--------|------|-----------|
| `lab-dhcpd` | Site DHCP server emulator. Leases addresses from in-memory pools, chosen by `giaddr` or, when not relayed, by the receiving interface. Sends options 1, 3, 51, 53 and 54 only, plus an echo of option 82. Sends **no PXE or boot options** and leaves `siaddr`, `sname` and `file` zero (REQ-BOOT-011). Logs every DISCOVER's option 60. | RFC 2131 §3.1, §4.1, §4.3; RFC 3046 §2.2 |
| `lab-relay-agent` | DHCP relay agent. Sets `giaddr` when it is 0, increments `hops`, drops `hops` > 4, adds option 82 (circuit ID = client interface name, remote ID = `usgp-netlab`), and forwards to every server. On replies it checks that option 82 came back unchanged (`opt82=ok\|missing\|changed`), strips it, and broadcasts on the client interface to port 68. | RFC 1542 §4.1.1, §4.1.2; RFC 3046 §2.0, §2.1 |
| `lab-probe` | Crafted DHCP and TFTP traffic, with assertions on the replies (scenario S4). | see `lab-probe` with no arguments |

## Platform

The protocol logic is sans-IO and its tests run on any host (`cargo test`).
The socket code (`src/net.rs`) is Linux only, because each socket is tied to
its interface with `SO_BINDTODEVICE`. On other systems every binary checks
its arguments (exit 2 on a usage error), then prints `NOT SUPPORTED` and
exits **77**, which the harness reports as NOT RUN.

The binaries bind UDP 67 or 68, so they need root or
`CAP_NET_BIND_SERVICE` (the harness runs them inside network namespaces as
root).

## Output

Every line on stdout is `tool key=value ...`. Values from the network are
escaped (non-printable bytes as `\xNN`, quotes and backslashes escaped), so
a hostile packet cannot forge log fields. Lines the harness relies on:

- `lab-dhcpd ... event=ready ...` once per listening interface.
- `lab-dhcpd ... event=discover ... opt60="PXEClient:Arch:00007:UNDI:003000"`
  (preflight greps `PXEClient:Arch:00007`).
- `lab-relay-agent event=ready ...`, `event=forward ... opt82=added`, and
  `event=reply ... opt82=ok`.
- `lab-probe check=<name> result=PASS|FAIL ...` per check, then
  `lab-probe summary pass=N fail=M`. Exit 0 only if every check passed.

## Examples (topology from plan section 10.5)

```sh
# ns-site: site DHCP for segments A and B
lab-dhcpd --listen dhcp0=10.20.1.3 \
  --pool 10.20.1.0/24,10.20.1.100-10.20.1.199,10.20.1.1 \
  --pool 10.20.2.0/24,10.20.2.100-10.20.2.199,10.20.2.1

# ns-router: relay segment B to the site server and the boot service
lab-relay-agent --client-iface rtB --client-addr 10.20.2.1 \
  --server-iface rtA --own-addr 10.20.1.1 \
  --server 10.20.1.3 --server 10.20.1.2

# S4 probes against the relay at 10.20.1.2 from a host at 10.20.1.9
lab-probe dhcp-offer   --iface p0 --local 10.20.1.9 --server 10.20.1.2 --expect-file usgp-test-payload.efi
lab-probe dhcp-offer   --iface p0 --local 10.20.1.9 --server 10.20.1.2 --port 4011
lab-probe dhcp-vectors --iface p0 --local 10.20.1.9 --server 10.20.1.2
lab-probe dhcp-random  --iface p0 --local 10.20.1.9 --server 10.20.1.2 --count 10000 --seed 1
lab-probe dhcp-rate    --iface p0 --local 10.20.1.9 --server 10.20.1.2 --per-sec 50 --secs 10 --max-replies 13
lab-probe tftp-wrq       --server 10.20.1.2 --file x
lab-probe tftp-traversal --server 10.20.1.2
lab-probe tftp-rrq --server 10.20.1.255     --file usgp-test-payload.efi --expect none
lab-probe tftp-rrq --server 255.255.255.255 --file usgp-test-payload.efi --expect none --iface p0
lab-probe tftp-rrq --server 10.20.1.2 --file usgp-test-payload.efi --expect ok --blksize 1468 --tsize --compare payload.efi
lab-probe tftp-stall --server 10.20.1.2 --file usgp-test-payload.efi --hold-secs 60

# From unconfigured segment br-x: no reply expected
lab-probe dhcp-offer --mode direct --iface px --server 10.20.9.2 --expect-none
```

`--max-replies` for `dhcp-rate` is computed by the harness from the relay's
configured limits: burst + refill over the run (for the defaults, 8 + 10 s /
2 s = 13).

Vectors whose reply would go to a `giaddr` other than the probe (the four
`giaddr-*` vectors) print `observable=false`. A PASS for them only means the
probe saw nothing; the harness must also check the relay log for their xid.
`lab-probe dhcp-vectors --list` prints the vector names.

## Tests

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --target x86_64-unknown-linux-gnu -- -D warnings   # socket code
cargo test
```

All test inputs are built by this crate's own builders from the standards
(CONTRIBUTING.md test-data rule). There are no fixture files.
