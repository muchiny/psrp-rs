#![no_main]
//! Layer 1, full depth: bytes off the wire all the way to typed records.
//!
//! This is the closest thing to "a hostile server is talking to us"
//! without standing up a transport: raw bytes go through the
//! reassembler, the message header decoder, the CLIXML parser and every
//! `FromPsObject` implementation, exactly as `RunspacePool` does it.

use libfuzzer_sys::fuzz_target;
use psrp_rs::clixml::parse_clixml;
use psrp_rs::fragment::Reassembler;
use psrp_rs::message::PsrpMessage;
use psrp_rs::records::{
    ErrorRecord, FromPsObject, InformationRecord, ProgressRecord, TraceRecord, WarningRecord,
};

fuzz_target!(|data: &[u8]| {
    let mut reassembler = Reassembler::new();
    let Ok(payloads) = reassembler.feed(data) else {
        return;
    };
    for payload in payloads {
        let Ok(msg) = PsrpMessage::decode(&payload) else {
            continue;
        };
        let Ok(values) = parse_clixml(&msg.data) else {
            continue;
        };
        for value in &values {
            let _ = ErrorRecord::from_ps_object(value);
            let _ = WarningRecord::from_ps_object(value);
            let _ = InformationRecord::from_ps_object(value);
            let _ = ProgressRecord::from_ps_object(value);
            let _ = TraceRecord::from_ps_object(value);
        }
    }
});
