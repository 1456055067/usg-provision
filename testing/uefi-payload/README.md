# usgp-test-payload (test only)

A minimal UEFI x86-64 application used by the M1 boot smoke (plan WU-9,
section 10.5). It is **not part of the product** and is never shipped. It is
a separate Cargo workspace, excluded from the product workspace by the root
`Cargo.toml` (`exclude = ["testing"]`).

What it does, in order:

1. Prints one marker line through the console's Simple Text Output protocol
   (`OutputString`, UEFI 2.10 §12.4). OVMF mirrors the console to the serial
   port, so the harness reads the marker from QEMU's serial log. The line is
   `CR LF <marker> CR LF`.
2. Waits one second (`Stall`, UEFI 2.10 §7.5) so the line reaches the serial
   port.
3. Shuts the machine down (`ResetSystem(EfiResetShutdown)`, UEFI 2.10
   §8.5.1). QEMU then exits with status 0. If shutdown is unavailable or
   returns, the payload returns `EFI_SUCCESS` to the boot manager.

It contains no secrets, keys or credentials (REQ-BOOT-043).

## Markers

The marker is fixed at compile time from the `USGP_PAYLOAD_MARKER`
environment variable:

| Build | `USGP_PAYLOAD_MARKER` | Marker |
|-------|-----------------------|--------|
| Network boot program | unset | `USGP-M1-PAYLOAD-OK` |
| Disk fallback (S6, S7) | `USGP-M1-DISK-FALLBACK-OK` | `USGP-M1-DISK-FALLBACK-OK` |

A marker must be 1 to 64 visible ASCII characters (0x21 to 0x7E). Anything
else fails the build (a compile-time assertion in `src/lib.rs`). Cargo
tracks the variable, so changing it rebuilds the payload. Both builds write
the same output path, so copy the file out before building the other one.

## Unsigned by design

The payload is **not signed**. That is deliberate: M1 exit 5 requires that
OVMF with Secure Boot enforced (keys enrolled, user mode) refuses to run it
(`specs/standards/uefi-secure-boot.md` §5). Do not sign it and do not enroll
its hash in any `db`.

## Build

The toolchain file pins Rust 1.99.1 with the `x86_64-unknown-uefi` target, so
rustup installs the target on first use. `.cargo/config.toml` makes that
target the default and puts build output under the repository's top-level
`target/testing/uefi-payload/`. A local `testing/uefi-payload/target/` would
be scanned by `scripts/check-names.sh`, and the IA-64 architecture name in
r-efi's compiled metadata contains the gate's pattern (a false positive; the
final `.efi` does not contain it).

```sh
cd testing/uefi-payload
cargo build --release
# -> ../../target/testing/uefi-payload/x86_64-unknown-uefi/release/usgp-test-payload.efi

USGP_PAYLOAD_MARKER=USGP-M1-DISK-FALLBACK-OK cargo build --release
```

Checks:

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings            # UEFI target
cargo clippy --release -- -D warnings
cargo clippy --target "$(rustc -vV | sed -n 's/host: //p')" --lib --tests -- -D warnings
cargo test --target "$(rustc -vV | sed -n 's/host: //p')" --lib
```

The library (`src/lib.rs`, marker selection and UCS-2 encoding) is tested on
the build host. The binary (`src/main.rs`) only builds for the UEFI target.

## Disk-boot check (no network needed)

This proves the payload runs and prints its marker. It does not exercise
network boot. With QEMU and an x86-64 OVMF build:

```sh
mkdir -p disk/EFI/BOOT
cp ../../target/testing/uefi-payload/x86_64-unknown-uefi/release/usgp-test-payload.efi disk/EFI/BOOT/BOOTX64.EFI
cp "$OVMF_VARS_TEMPLATE" vars.fd      # fresh writable copy per run
qemu-system-x86_64 -machine q35 -m 512 -display none -no-reboot -nic none \
  -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
  -drive if=pflash,format=raw,file=vars.fd \
  -drive file=fat:ro:disk,format=raw,if=virtio,readonly=on \
  -serial file:serial.log
grep -- USGP-M1-PAYLOAD-OK serial.log
```

Note `readonly=on` on the `fat:ro:` drive: QEMU 11.1.2 refuses the drive
without it ("Block node is read-only"). `BOOTX64.EFI` is the x64 default
removable-media name (UEFI 2.10 §3.5.1.1, Table 3.2).

## Unsafe code

The binary needs `unsafe` to dereference the firmware's system table and
call UEFI services through function pointers. Every block has a
`// SAFETY:` comment, `clippy::undocumented_unsafe_blocks` is denied, and
`unsafe_op_in_unsafe_fn` is denied. The library has no `unsafe`.
