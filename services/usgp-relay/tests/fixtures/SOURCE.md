# Relay test fixtures

Two hand-written golden files are checked in:

- `relay-v1.toml`: every v1 relay configuration key, each set to a
  non-default value (`tests/config.rs::golden_v1_config_parses`);
- `suppress-v1.toml`: one MAC entry and one GUID entry
  (`tests/config.rs::golden_v1_suppression_parses`).

Both were written by us from plan section 3.3/3.4 (M3: plan section 3.9
for the `[tftp]` window and wrap keys and `[server_feed]`) and contain no
device or site data. The `[server_feed]` URL, paths and boot service id
are made-up examples. Every other boot file, manifest, configuration file and
directory is generated at test time by `tests/common/mod.rs`:

- boot file content: `common::bytes(len, seed)`, a deterministic xorshift
  byte stream written by our own code;
- manifests: `usgp_proto::BootManifest::new(..).to_toml()` over those files,
  with digests from `usgp_crypto::sha256`;
- configuration: `ConfigDocument` values built in code (`common::doc`) and
  `relay.toml` files written by `common::write_config_toml`.

Files live in a per-test directory under the system temporary directory
and are removed when the test ends. No test reads a real device, a real
network interface, or any external file.

Every device identifier in these fixtures and in the tests is synthetic:
MAC addresses use the QEMU locally administered prefix `52:54:00` with
made-up host parts, and machine GUIDs are byte-pattern values such as
`00112233-4455-6677-8899-aabbccddeeff` (distinct bytes in every field, so
the mixed-endian wire/text conversion is still exercised). The non-PXE
vendor class used by the DHCP tests, `usgp-non-pxe-client`, is an arbitrary
string chosen by us (RFC 2132 §9.13 allows any class identifier).
