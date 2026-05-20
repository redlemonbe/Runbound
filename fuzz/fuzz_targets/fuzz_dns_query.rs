// SPDX-License-Identifier: AGPL-3.0-or-later
// Fuzz target: parse raw UDP DNS wire bytes through hickory-proto.
// Exercises the DNS message parser for any panic, OOM, or infinite loop.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // parse_dns_bytes is gated on #[cfg(any(test, feature = "fuzz"))]
    let _ = runbound::parse_dns_bytes(data);
});
