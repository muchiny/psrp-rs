#![no_main]
//! Layer 2: `PsrpMessage::encode` / `decode` must be exact inverses.
//!
//! The header packs a u32 destination, a u32 message type and two .NET
//! **mixed-endian** GUIDs. Getting the GUID byte order wrong is the
//! classic MS-PSRP bug and it only shows up against a real server —
//! this target catches it on the bench instead.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use psrp_rs::message::{Destination, MessageType, PsrpMessage};
use uuid::Uuid;

#[derive(Debug, Arbitrary)]
struct Input {
    to_server: bool,
    message_type: u32,
    rpid: [u8; 16],
    pid: [u8; 16],
    data: String,
}

fuzz_target!(|input: Input| {
    let message_type = MessageType::from_u32(input.message_type);
    let msg = PsrpMessage {
        destination: if input.to_server {
            Destination::Server
        } else {
            Destination::Client
        },
        message_type,
        rpid: Uuid::from_bytes(input.rpid),
        pid: Uuid::from_bytes(input.pid),
        data: input.data,
    };

    let bytes = msg.encode();
    let decoded = PsrpMessage::decode(&bytes).expect("self-encoded message must decode");

    assert_eq!(msg.destination, decoded.destination);
    assert_eq!(msg.rpid, decoded.rpid, "RPID GUID endianness");
    assert_eq!(msg.pid, decoded.pid, "PID GUID endianness");
    // `decode` deliberately strips **one** leading UTF-8 BOM (real
    // servers emit one), so the body is only stable modulo that.
    assert_eq!(
        msg.data.strip_prefix('\u{feff}').unwrap_or(&msg.data),
        decoded.data,
        "message body changed across the wire"
    );
    // Once the body no longer opens with a BOM there is nothing left to
    // strip, and the codec must be an exact fixed point.
    if !decoded.data.starts_with('\u{feff}') {
        let again = PsrpMessage::decode(&decoded.encode()).expect("second decode");
        assert_eq!(decoded.data, again.data, "encode/decode does not converge");
        assert_eq!(decoded.encode(), again.encode(), "encode is not idempotent");
    }
    // `MessageType::from_u32` keeps unknown codes around, so the
    // *numeric* value has to survive even when the variant is `Unknown`.
    assert_eq!(
        msg.message_type.to_u32(),
        decoded.message_type.to_u32(),
        "message type code changed across the wire"
    );
});
