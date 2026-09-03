#![no_main]
//! Layer 4: the pure runspace-pool state machine.
//!
//! `on_message` is fed straight from the wire, so the server picks the
//! transition sequence. The machine is the last line of defence against
//! a server that tries to skip negotiation, resurrect a closed pool, or
//! flip a broken pool back to `Opened` — so the invariants below are
//! security properties, not style preferences.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use psrp_rs::clixml::{PsObject, PsValue, to_clixml};
use psrp_rs::message::{Destination, MessageType, PsrpMessage};
use psrp_rs::runspace::{RunspacePoolState, RunspacePoolStateMachine};
use uuid::Uuid;

#[derive(Debug, Arbitrary)]
enum Step {
    Open,
    Connect,
    Close,
    MarkClosed,
    /// A `RunspacePoolState` message carrying an arbitrary state code.
    ServerState(i32),
    /// Any other message type, with an arbitrary CLIXML-ish body.
    ServerMessage { message_type: u32, body: String },
}

#[derive(Debug, Arbitrary)]
struct Input {
    min_runspaces: i32,
    max_runspaces: i32,
    steps: Vec<Step>,
}

fn state_message(code: i32) -> PsrpMessage {
    PsrpMessage {
        destination: Destination::Client,
        message_type: MessageType::RunspacePoolState,
        rpid: Uuid::nil(),
        pid: Uuid::nil(),
        data: to_clixml(&PsValue::Object(
            PsObject::new().with("RunspaceState", PsValue::I32(code)),
        )),
    }
}

fuzz_target!(|input: Input| {
    let Ok(mut machine) =
        RunspacePoolStateMachine::new(Uuid::nil(), input.min_runspaces, input.max_runspaces)
    else {
        return;
    };
    // Constructor contract: it only succeeds on sane bounds.
    assert!(machine.min_runspaces() >= 1);
    assert!(machine.max_runspaces() >= machine.min_runspaces());

    let mut ever_closed = false;
    let mut ever_broken = false;

    for step in input.steps.iter().take(64) {
        match step {
            Step::Open => {
                let _ = machine.open();
            }
            Step::Connect => {
                let _ = machine.connect();
            }
            Step::Close => {
                let _ = machine.close();
            }
            Step::MarkClosed => machine.mark_closed(),
            Step::ServerState(code) => {
                let _ = machine.on_message(&state_message(*code));
            }
            Step::ServerMessage { message_type, body } => {
                let msg = PsrpMessage {
                    destination: Destination::Client,
                    message_type: MessageType::from_u32(*message_type),
                    rpid: Uuid::nil(),
                    pid: Uuid::nil(),
                    data: body.clone(),
                };
                let _ = machine.on_message(&msg);
            }
        }

        let state = machine.state();
        // `is_opened` must never drift away from `state`.
        assert_eq!(
            machine.is_opened(),
            state == RunspacePoolState::Opened,
            "is_opened disagrees with state {state:?}"
        );
        // A pool that has been closed, or that the server declared
        // broken, must never report itself as usable again.
        if ever_closed || ever_broken {
            assert_ne!(
                state,
                RunspacePoolState::Opened,
                "pool resurrected into Opened after closed={ever_closed} broken={ever_broken}"
            );
        }
        ever_closed |= state == RunspacePoolState::Closed;
        ever_broken |= state == RunspacePoolState::Broken;
        // The identity of the pool is immutable.
        assert_eq!(machine.rpid(), Uuid::nil());
    }
});
