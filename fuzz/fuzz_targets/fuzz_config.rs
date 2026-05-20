// SPDX-License-Identifier: AGPL-3.0-or-later
// Fuzz target: parse arbitrary bytes as an Unbound-format config string.
// Exercises parse_str() for any panic or unexpected behaviour on malformed input.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // parse_config_str is gated on #[cfg(any(test, feature = "fuzz"))]
        let _ = runbound::parse_config_str(s);
    }
});
