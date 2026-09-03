#![no_main]
//! Layer 4: the real async runspace pool, driven by a hostile server.
//!
//! `MockTransport` stands in for WinRM, so this exercises the genuine
//! receive loop — reassembly, message dispatch, host-call handling,
//! per-stream demultiplexing and pipeline termination — with bytes the
//! fuzzer chose, and with no network involved.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use psrp_fuzz::runtime;
use psrp_rs::clixml::{PsObject, PsValue, to_clixml};
use psrp_rs::fragment::encode_message;
use psrp_rs::internal::pool::next_message;
use psrp_rs::internal::transport::MockTransport;
use psrp_rs::message::{Destination, MessageType, PsrpMessage};
use psrp_rs::runspace::{RunspacePool, RunspacePoolState};
use psrp_rs::Pipeline;
use uuid::Uuid;

#[derive(Debug, Arbitrary)]
struct Input {
    /// Chunks handed out by successive `recv_chunk` calls.
    chunks: Vec<Vec<u8>>,
    /// Run a pipeline after the pool opens, instead of just closing it.
    run_pipeline: bool,
}

fn opened_state_bytes() -> Vec<u8> {
    let body = to_clixml(&PsValue::Object(
        PsObject::new().with(
            "RunspaceState",
            PsValue::I32(RunspacePoolState::Opened as i32),
        ),
    ));
    encode_message(
        1,
        &PsrpMessage {
            destination: Destination::Client,
            message_type: MessageType::RunspacePoolState,
            rpid: Uuid::nil(),
            pid: Uuid::nil(),
            data: body,
        }
        .encode(),
    )
}

fuzz_target!(|input: Input| {
    runtime().block_on(async move {
        let transport = MockTransport::new();
        // Open the pool for real, then let the fuzzer take over the wire.
        transport.push_incoming(opened_state_bytes());
        let Ok(mut pool) = RunspacePool::open_with_transport(transport.clone()).await else {
            return;
        };

        for chunk in input.chunks.into_iter().take(32) {
            transport.push_incoming(chunk);
        }

        if input.run_pipeline {
            // A forced nil PID makes the fuzzer's messages routable to
            // the pipeline instead of being dropped as "wrong PID".
            let pipeline = Pipeline::new("Get-Date").__with_forced_pid_for_test(Uuid::nil());
            let _ = pipeline.run_all_streams(&mut pool).await;
        } else {
            // Drain whatever the fuzzer queued through the pool's own
            // message loop.
            while transport.inbox.lock().unwrap().front().is_some() {
                if next_message(&mut pool).await.is_err() {
                    break;
                }
            }
        }

        let _ = pool.close().await;
    });
});
