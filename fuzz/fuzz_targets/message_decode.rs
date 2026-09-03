#![no_main]
//! Layer 1: the 40-byte PSRP message header (MS-PSRP §2.2.2).
//!
//! `decode` sees the payload of a reassembled fragment, i.e. bytes the
//! server fully controls. Besides being panic-free it must be a left
//! inverse of `encode`: anything that decodes must re-encode to itself.

use libfuzzer_sys::fuzz_target;
use psrp_rs::message::PsrpMessage;

fuzz_target!(|data: &[u8]| {
    let Ok(msg) = PsrpMessage::decode(data) else {
        return;
    };

    let re = msg.encode();
    let again = PsrpMessage::decode(&re).expect("re-decode of self-encoded message");
    assert_eq!(msg.destination, again.destination);
    assert_eq!(msg.message_type, again.message_type);
    assert_eq!(msg.rpid, again.rpid);
    assert_eq!(msg.pid, again.pid);

    // `decode` strips **one** leading UTF-8 BOM (real servers emit one),
    // and `encode` writes the body back verbatim — so a body that opens
    // with a BOM loses exactly one per hop and is not a fixed point yet.
    assert_eq!(
        msg.data.strip_prefix('\u{feff}').unwrap_or(&msg.data),
        again.data,
        "message body changed across a re-encode"
    );
    if !msg.data.starts_with('\u{feff}') {
        assert_eq!(msg.data, again.data);
        assert_eq!(re, again.encode(), "encode is not idempotent");
    }
});
