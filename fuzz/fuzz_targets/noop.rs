//! Placeholder target: it only proves the fuzz harness builds. Delete it
//! when the first real target (`dhcp_packet`, M1) lands.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|_data: &[u8]| {});
