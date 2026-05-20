// SPDX-License-Identifier: AGPL-3.0-or-later
// Fuzz target: validate arbitrary strings as DNS names.
// Exercises fuzz_validate_dns_name() and the sanitize_dns_name path
// (via hickory_proto LowerName) for panics on unexpected input.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // fuzz_validate_dns_name is gated on #[cfg(any(test, feature = "fuzz"))]
        let _ = runbound::fuzz_validate_dns_name(s);

        // Also exercise hickory_proto's name parser — it must not panic.
        let _ = hickory_proto::rr::Name::from_str_relaxed(s);
    }
});
