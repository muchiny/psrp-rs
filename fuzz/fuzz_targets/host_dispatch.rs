#![no_main]
//! Layer 3: server-driven host callbacks.
//!
//! A `RunspacePoolHostCall` lets the *server* pick a method id and the
//! argument list. `dispatch_host_call` therefore runs attacker-chosen
//! code paths with attacker-shaped arguments, and the CLIXML response
//! builders embed those values straight back into XML.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use psrp_fuzz::{ArbValue, runtime};
use psrp_rs::clixml::parse_clixml;
use psrp_rs::host::{BufferedHost, HostMethodId, dispatch_host_call};
use psrp_rs::internal::build::{host_response_body, host_response_error_body};

#[derive(Debug, Arbitrary)]
struct Input {
    method_id: i64,
    args: Vec<ArbValue>,
    call_id: i64,
}

fuzz_target!(|input: Input| {
    let mi = HostMethodId::from_i64(input.method_id);
    let args: Vec<_> = input.args.into_iter().map(|v| v.0).collect();

    let host = BufferedHost::new();
    let result = runtime().block_on(dispatch_host_call(&host, mi, &args));

    // Void methods never produce a response; non-void ones either return
    // a value or a rejection. Both branches feed the XML builders.
    match result {
        Ok(Some(value)) => {
            let body = host_response_body(input.call_id, input.method_id, &value);
            parse_clixml(&body).expect("host response body must be well-formed CLIXML");
        }
        Ok(None) => {
            assert!(
                mi.is_void(),
                "{mi:?} returned no value but is not a void method"
            );
        }
        Err(e) => {
            let body = host_response_error_body(input.call_id, input.method_id, &e.to_string());
            parse_clixml(&body).expect("host error body must be well-formed CLIXML");
        }
    }
});
