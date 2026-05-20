// SPDX-License-Identifier: AGPL-3.0-or-later
// Fuzz target: deserialise arbitrary bytes as the AddDnsRequest, AddFeedRequest,
// and AddBlacklistRequest JSON bodies used by the REST API.
// Exercises serde_json deserialisation for panics on malformed input.
#![no_main]

use libfuzzer_sys::fuzz_target;
use runbound::api_fuzz::{AddDnsRequest, AddFeedRequest, AddBlacklistRequest};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Try to deserialise as each of the three API request structs.
        let _ = serde_json::from_str::<AddDnsRequest>(s);
        let _ = serde_json::from_str::<AddFeedRequest>(s);
        let _ = serde_json::from_str::<AddBlacklistRequest>(s);
    }
});
