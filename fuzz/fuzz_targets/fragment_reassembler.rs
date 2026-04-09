#![no_main]

use libfuzzer_sys::fuzz_target;
use psrp_rs::fragment::Reassembler;

fuzz_target!(|data: &[u8]| {
    // Panic-safety: arbitrary bytes fed into the reassembler must either
    // parse as a sequence of messages or return a structured error — it
    // must NEVER panic.
    let mut r = Reassembler::new();
    let _ = r.feed(data);
});
