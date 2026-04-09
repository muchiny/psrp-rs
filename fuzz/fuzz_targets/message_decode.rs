#![no_main]

use libfuzzer_sys::fuzz_target;
use psrp_rs::message::PsrpMessage;

fuzz_target!(|data: &[u8]| {
    // PSRP message header decoder must be panic-free on arbitrary
    // bytes.
    let _ = PsrpMessage::decode(data);
});
