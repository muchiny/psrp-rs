//! OutOfProc framing: the line protocol spoken by `pwsh -sshs`.
//!
//! The protocol in ten lines:
//!
//! 1. Both sides exchange one XML element per line, each terminated by a newline.
//! 2. `<Data Stream='Default' PSGuid='{guid}'>{base64}</Data>` carries PSRP fragment bytes.
//! 3. `<DataAck/>`, `<Command/>`, `<CommandAck/>`, `<Signal/>`, `<SignalAck/>`, `<Close/>`
//!    and `<CloseAck/>` carry only a `PSGuid` attribute.
//! 4. `PSGuid` is `Guid.Empty` for the session (the runspace pool), else a pipeline id.
//! 5. The client keeps one request in flight and waits for its `*Ack` before the next.
//! 6. A `<Command/>` must precede any `<Data>` on a pipeline id, and be closed by `<Close/>`.
//! 7. The server treats a blank line, a malformed line or a wrong attribute count as fatal.
//! 8. It then writes `__NamedPipeError__:<message>` and exits with code 4000.
//! 9. Lines from the server may end in `\r\n` (Windows) or `\n` (Linux).
//! 10. A noisy shell profile can put non-XML lines on stdout, which must be rejected clearly.
//!
//! Sources (PowerShell tag `v7.6.7`, under
//! `src/System.Management.Automation/engine/remoting/`):
//! `fanin/OutOfProcTransportManager.cs` (packet format, lines 76-140, and the
//! client side of the error line, 417 and 1899-1923) and
//! `server/OutOfProcServerMediator.cs` (what the server rejects, 102-107 and 347-416).
//!
//! This module is pure and synchronous: it never touches `russh` or `winrm_rs`.

// removed by Task 5 (the three lint attributes below)
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "wired into SshPsrpTransport by a later commit of this series"
    )
)]
#![cfg_attr(
    not(test),
    expect(
        unused_imports,
        reason = "re-exports consumed by SshPsrpTransport in a later commit of this series"
    )
)]
// The unit tests exercise `packet` directly, so under `cfg(test)` the
// re-exports below and the not-yet-used items would only warn.
#![cfg_attr(
    test,
    allow(
        dead_code,
        unused_imports,
        reason = "wired into SshPsrpTransport by a later commit of this series"
    )
)]

mod packet;

pub(crate) use packet::{
    LineSplitter, MAX_DATA_PAYLOAD, MAX_LINE_BYTES, Packet, SERVER_ERROR_PREFIX, Stream, parse_line,
};
