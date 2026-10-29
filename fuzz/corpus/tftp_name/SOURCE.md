# Seed origin: `tftp_name`

Every seed here is a file name written in the generator from the request
name rules of the M3 plan §1 and `specs/standards/winpe-network-boot.md`
§5 (backslash paths). None comes from a packet capture, a log or any
deployment of another product (fuzz/README.md, seed origin rule).

Octet 0 selects: 0, one request name; 1, a NUL-separated list of
published names.

Regenerate (from `fuzz/`; function `name_seeds`):

```sh
cargo run --example gen_seeds_m3 -- corpus
```

| Seed | Content |
|------|---------|
| `wu14-name-backslash.bin` | `\Boot\BCD` |
| `wu14-name-slash.bin` | `/Boot/BCD` |
| `wu14-name-plain.bin` | `bootmgfw.efi` |
| `wu14-name-mixed.bin` | `\sources/boot.wim` |
| `wu14-name-dotdot.bin` | `..\x` (refused) |
| `wu14-name-double-slash.bin` | `a//b` (refused) |
| `wu14-name-dot.bin` | `a/./b` (refused) |
| `wu14-name-too-long.bin` | 128 x `a` (refused) |
| `wu14-name-percent.bin` | `%2e%2e/x` (refused) |
| `wu14-names-collision.bin` | `Boot/BCD`, `bootmgfw.efi`, `boot/bcd` (a collision) |
