#![no_main]

use libfuzzer_sys::fuzz_target;
use psrp_rs::parse_clixml;

fuzz_target!(|data: &[u8]| {
    // `parse_clixml` is a known attack surface: unknown or malformed XML
    // must never cause a panic, stack overflow, or infinite loop.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = parse_clixml(s);
    }
});
