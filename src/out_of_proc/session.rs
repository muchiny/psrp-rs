//! OutOfProc session engine: one request in flight, and its acknowledgement
//! read before anything else is written.
//!
//! [`OutOfProcSession`] turns the transport operations (send PSRP fragment
//! bytes, receive, stop the pipeline, close) into the request / `*Ack`
//! exchanges `pwsh -sshs` expects, over any [`Pipe`]. Every `<Data>` the
//! server sends while a request waits for its acknowledgement is kept for
//! [`OutOfProcSession::recv`].
//!
//! Cancellation. [`Pipe::read`] is cancel-safe and the chunk it returns is
//! processed without any `.await`, so a future dropped at any point loses no
//! received byte. A request dropped after its line was written leaves its
//! acknowledgement awaited: the next operation reads it before deciding
//! anything, and the command state only changes when an acknowledgement is
//! read, so it always matches what the server confirmed.
//!
//! A request dropped *while* its line is being written may have put a prefix
//! of the line on the wire, which would corrupt the next line and kill
//! `pwsh`. The session then fails closed: the next operation breaks it ("a
//! request was abandoned while its line was being written") and writes
//! nothing. A send dropped between two `<Data>` lines of one payload leaves a
//! partial PSRP message on the server: discarded when the pipeline's command
//! is closed, but on the session (`Guid.Empty`) it stays in the server's
//! reassembler.
//!
//! Every wait for an acknowledgement is bounded by [`ACK_TIMEOUT`]; expiry,
//! end of stream, a server error line or a malformed line break the session
//! for good. Every later request then fails at once with the same reason,
//! without writing anything.

use std::collections::VecDeque;
use std::time::Duration;

use async_trait::async_trait;
use uuid::Uuid;

use super::packet::{LineSplitter, MAX_DATA_PAYLOAD, Packet, Stream, parse_line};
use crate::error::{PsrpError, Result};

/// Bound on every request: writing its line, then waiting for its
/// acknowledgement. PowerShell's own client waits 60 s for `SignalAck` and
/// for the session `CloseAck`.
pub(crate) const ACK_TIMEOUT: Duration = Duration::from_secs(60);

/// Received `<Data>` bytes not yet taken by [`OutOfProcSession::recv`] beyond
/// which the session is broken.
pub(crate) const MAX_QUEUED_BYTES: usize = 64 << 20;

/// Why the session breaks when a request was dropped in the middle of [`Pipe::write`].
const ABANDONED_WRITE: &str = "a request was abandoned while its line was being written";

/// The byte channel to a `pwsh -sshs` process: its stdin and its stdout.
#[async_trait]
pub(crate) trait Pipe: Send {
    /// Writes every byte to the remote stdin.
    ///
    /// Need not be cancel-safe. The future may be dropped mid-way, when the
    /// caller's operation is cancelled, possibly after part of the bytes
    /// went out. The session then never writes again (it breaks itself), so
    /// the pipe need not resume nor roll back a partial write; it must only
    /// tolerate being dropped at any await point, and still be torn down
    /// afterwards.
    async fn write(&mut self, bytes: &[u8]) -> Result<()>;
    /// Next non-empty chunk of remote stdout; `Err` once the remote end is
    /// gone. Must be cancel-safe: dropping the future loses no byte.
    async fn read(&mut self) -> Result<Vec<u8>>;
}

/// The client side of one OutOfProc session, that is one runspace pool.
pub(crate) struct OutOfProcSession<P: Pipe> {
    /// The channel to `pwsh`.
    pipe: P,
    /// Cuts the server's stdout into lines.
    lines: LineSplitter,
    /// `<Data>` payloads received and not yet handed out by `recv`.
    inbound: VecDeque<Vec<u8>>,
    /// Total bytes in `inbound`.
    inbound_bytes: usize,
    /// Limit on `inbound_bytes`: [`MAX_QUEUED_BYTES`] outside tests.
    max_queued_bytes: usize,
    /// The acknowledgement the request in flight waits for.
    awaiting: Option<Packet>,
    /// Set for the duration of [`Pipe::write`]: still set afterwards means
    /// the write was abandoned, maybe with part of the line sent. Implies
    /// `awaiting`, which only a `pump` (which checks this first) clears.
    write_in_progress: bool,
    /// The pipeline whose `<Command>` was acknowledged and not yet closed.
    open_command: Option<Uuid>,
    /// Why the session is unusable, once it is.
    broken: Option<String>,
}

impl<P: Pipe> OutOfProcSession<P> {
    pub(crate) fn new(pipe: P) -> Self {
        Self {
            pipe,
            lines: LineSplitter::new(),
            inbound: VecDeque::new(),
            inbound_bytes: 0,
            max_queued_bytes: MAX_QUEUED_BYTES,
            awaiting: None,
            write_in_progress: false,
            open_command: None,
            broken: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_max_queued_bytes(mut self, n: usize) -> Self {
        self.max_queued_bytes = n;
        self
    }

    /// Sends PSRP fragment bytes to the pool (`Uuid::nil()`) or to pipeline `guid`.
    ///
    /// A pipeline other than the open one first closes the open one, then
    /// opens its own `<Command>`. The bytes go out in `<Data>` lines of at
    /// most [`MAX_DATA_PAYLOAD`] bytes, each acknowledged before the next.
    /// An empty payload writes nothing.
    pub(crate) async fn send(&mut self, guid: Uuid, payload: &[u8]) -> Result<()> {
        if payload.is_empty() {
            return Ok(());
        }
        if !guid.is_nil() {
            // A request dropped mid-flight may have opened or closed a
            // command: read its acknowledgement before looking.
            self.settle_bounded().await?;
            if self.open_command != Some(guid) {
                if let Some(prev) = self.open_command {
                    self.request(Packet::Close(prev), Packet::CloseAck(prev))
                        .await?;
                }
                self.request(Packet::Command(guid), Packet::CommandAck(guid))
                    .await?;
            }
        }
        for chunk in payload.chunks(MAX_DATA_PAYLOAD) {
            let data = Packet::Data {
                stream: Stream::Default,
                guid,
                payload: chunk.to_vec(),
            };
            self.request(data, Packet::DataAck(guid)).await?;
        }
        Ok(())
    }

    /// The next `<Data>` payload from the server, in arrival order; never empty.
    ///
    /// What is already queued is handed out even after the session broke, so
    /// that the pool can still see a terminal state; then comes the error.
    pub(crate) async fn recv(&mut self) -> Result<Vec<u8>> {
        loop {
            while let Some(payload) = self.inbound.pop_front() {
                self.inbound_bytes = self.inbound_bytes.saturating_sub(payload.len());
                if !payload.is_empty() {
                    return Ok(payload);
                }
            }
            self.pump().await?;
        }
    }

    /// Stops the open pipeline with `<Signal>`. Without one, writes nothing.
    pub(crate) async fn signal(&mut self) -> Result<()> {
        self.settle_bounded().await?;
        match self.open_command {
            Some(pid) => {
                self.request(Packet::Signal(pid), Packet::SignalAck(pid))
                    .await
            }
            None => Ok(()),
        }
    }

    /// Closes the open command, if any, then the session.
    ///
    /// `pwsh` never acknowledges the session `<Close>` while a command is
    /// open, hence the order.
    pub(crate) async fn close(&mut self) -> Result<()> {
        self.settle_bounded().await?;
        if let Some(pid) = self.open_command {
            self.request(Packet::Close(pid), Packet::CloseAck(pid))
                .await?;
        }
        let nil = Uuid::nil();
        self.request(Packet::Close(nil), Packet::CloseAck(nil))
            .await
    }

    pub(crate) fn pipe_mut(&mut self) -> &mut P {
        &mut self.pipe
    }

    /// One request: write `packet`, then read until `ack`, within [`ACK_TIMEOUT`].
    ///
    /// Fails at once, writing nothing, on a broken session.
    async fn request(&mut self, packet: Packet, ack: Packet) -> Result<()> {
        self.usable()?;
        let line = packet.to_line();
        let fallback = ack.clone();
        match tokio::time::timeout(ACK_TIMEOUT, self.exchange(line.as_bytes(), ack)).await {
            Ok(result) => result,
            Err(_elapsed) => Err(self.timed_out(&fallback)),
        }
    }

    async fn exchange(&mut self, line: &[u8], ack: Packet) -> Result<()> {
        self.settle().await?;
        self.awaiting = Some(ack);
        self.write_in_progress = true;
        let written = self.pipe.write(line).await;
        self.write_in_progress = false;
        if let Err(e) = written {
            return Err(self.fail(e));
        }
        self.settle().await
    }

    /// Reads until no acknowledgement is awaited.
    async fn settle(&mut self) -> Result<()> {
        while self.awaiting.is_some() {
            self.pump().await?;
        }
        Ok(())
    }

    /// [`Self::settle`] within [`ACK_TIMEOUT`], for an acknowledgement left
    /// awaited by a dropped request.
    async fn settle_bounded(&mut self) -> Result<()> {
        let Some(pending) = self.awaiting.clone() else {
            return Ok(());
        };
        match tokio::time::timeout(ACK_TIMEOUT, self.settle()).await {
            Ok(result) => result,
            Err(_elapsed) => Err(self.timed_out(&pending)),
        }
    }

    /// Breaks the session after [`ACK_TIMEOUT`] elapsed writing a line or
    /// waiting for an acknowledgement (the awaited one, else `fallback`).
    fn timed_out(&mut self, fallback: &Packet) -> PsrpError {
        let (element, guid) = request_element(self.awaiting.as_ref().unwrap_or(fallback));
        let secs = ACK_TIMEOUT.as_secs();
        let reason = if self.write_in_progress {
            format!(
                "PowerShell did not accept {element} for {guid} within {secs} s: the write did not complete"
            )
        } else {
            format!("PowerShell did not acknowledge {element} for {guid} within {secs} s")
        };
        self.fail(PsrpError::protocol(reason))
    }

    /// Reads one chunk and processes every line it completes.
    ///
    /// The read is the only `.await`: the processing that follows is
    /// synchronous, so a dropped future loses nothing.
    async fn pump(&mut self) -> Result<()> {
        self.usable()?;
        let read = self.pipe.read().await;
        let processed = read.and_then(|chunk| self.process(&chunk));
        processed.map_err(|e| self.fail(e))
    }

    fn process(&mut self, chunk: &[u8]) -> Result<()> {
        for line in self.lines.push(chunk)? {
            self.on_line(&line)?;
        }
        Ok(())
    }

    fn on_line(&mut self, line: &str) -> Result<()> {
        let Some(packet) = parse_line(line)? else {
            return Ok(());
        };
        match packet {
            Packet::Data { payload, .. } => self.queue(payload),
            Packet::DataAck(_)
            | Packet::CommandAck(_)
            | Packet::SignalAck(_)
            | Packet::CloseAck(_) => {
                if self.awaiting.as_ref() == Some(&packet) {
                    self.awaiting = None;
                    self.acknowledged(&packet);
                } else {
                    // PowerShell's client ignores them too.
                    tracing::debug!(?packet, "ignoring an unexpected OutOfProc acknowledgement");
                }
                Ok(())
            }
            Packet::Command(_) | Packet::Signal(_) | Packet::Close(_) => {
                Err(PsrpError::protocol(format!(
                    "PowerShell sent a packet only a client may send: {}",
                    packet.to_line().trim_end()
                )))
            }
        }
    }

    fn queue(&mut self, payload: Vec<u8>) -> Result<()> {
        let total = self.inbound_bytes.saturating_add(payload.len());
        if total > self.max_queued_bytes {
            return Err(PsrpError::protocol(format!(
                "PowerShell sent more than {} bytes of data that were not received",
                self.max_queued_bytes
            )));
        }
        self.inbound_bytes = total;
        self.inbound.push_back(payload);
        Ok(())
    }

    /// Records what the request acknowledged by `ack` changed on the server.
    fn acknowledged(&mut self, ack: &Packet) {
        match ack {
            Packet::CommandAck(pid) => self.open_command = Some(*pid),
            Packet::CloseAck(pid) if self.open_command == Some(*pid) => self.open_command = None,
            _ => {}
        }
    }

    /// `Err` on a broken session; breaks it first if a write was abandoned.
    fn usable(&mut self) -> Result<()> {
        if let Some(reason) = &self.broken {
            return Err(PsrpError::Protocol(reason.clone()));
        }
        if self.write_in_progress {
            return Err(self.fail(PsrpError::protocol(ABANDONED_WRITE)));
        }
        Ok(())
    }

    /// Breaks the session; returns the reason as a protocol error.
    ///
    /// The first reason sticks: every later operation reports it.
    fn fail(&mut self, err: PsrpError) -> PsrpError {
        let reason = match err {
            PsrpError::Protocol(reason) => reason,
            other => other.to_string(),
        };
        PsrpError::Protocol(self.broken.get_or_insert(reason).clone())
    }
}

/// The element of the request that `ack` acknowledges, and its `PSGuid`.
fn request_element(ack: &Packet) -> (&'static str, Uuid) {
    match ack {
        Packet::Data { guid, .. } | Packet::DataAck(guid) => ("Data", *guid),
        Packet::Command(g) | Packet::CommandAck(g) => ("Command", *g),
        Packet::Signal(g) | Packet::SignalAck(g) => ("Signal", *g),
        Packet::Close(g) | Packet::CloseAck(g) => ("Close", *g),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fragment::{Reassembler, encode_message};
    use crate::message::{MessageType, PsrpMessage};
    use crate::out_of_proc::fake::{FakeHandle, FakePwsh};
    use crate::pipeline::{PipelineState, extract_pipeline_state};
    use tokio::time::timeout;

    const P1: Uuid = Uuid::from_u128(0x1111_1111_1111_4111_8111_1111_1111_1111);
    const P2: Uuid = Uuid::from_u128(0x2222_2222_2222_4222_8222_2222_2222_2222);
    const G: Uuid = Uuid::from_u128(0x0a1b_2c3d_4e5f_4071_8293_a4b5_c6d7_e8f9);
    const RPID: Uuid = Uuid::from_u128(0x3333_3333_3333_4333_8333_3333_3333_3333);
    const NIL: &str = "00000000-0000-0000-0000-000000000000";

    fn session() -> (OutOfProcSession<FakePwsh>, FakeHandle) {
        let (fake, handle) = FakePwsh::new();
        (OutOfProcSession::new(fake), handle)
    }

    fn data(guid: Uuid, payload: &[u8]) -> Packet {
        Packet::Data {
            stream: Stream::Default,
            guid,
            payload: payload.to_vec(),
        }
    }

    /// A packet as the client writes it, as `written()` reports it (no `\n`).
    fn line(packet: &Packet) -> String {
        packet.to_line().trim_end_matches('\n').to_owned()
    }

    /// A packet as `pwsh` on Windows writes it, CRLF-terminated.
    fn server_line(packet: &Packet) -> String {
        format!("{}\r\n", line(packet))
    }

    #[tokio::test]
    async fn send_on_the_pool_writes_one_data_line_and_waits_for_its_ack() -> Result<()> {
        let (mut s, h) = session();
        s.send(Uuid::nil(), b"abc").await?;
        assert_eq!(
            h.written(),
            [format!("<Data Stream='Default' PSGuid='{NIL}'>YWJj</Data>")]
        );
        assert!(h.violations().is_empty(), "{:?}", h.violations());
        Ok(())
    }

    #[tokio::test]
    async fn first_send_on_a_pipeline_opens_its_command() -> Result<()> {
        let (mut s, h) = session();
        s.send(P1, b"x").await?;
        assert_eq!(
            h.written(),
            [line(&Packet::Command(P1)), line(&data(P1, b"x"))]
        );
        assert_eq!(
            line(&data(P1, b"x")),
            format!("<Data Stream='Default' PSGuid='{P1}'>eA==</Data>")
        );
        assert!(h.violations().is_empty(), "{:?}", h.violations());
        Ok(())
    }

    #[tokio::test]
    async fn a_new_pipeline_closes_the_previous_command_first() -> Result<()> {
        let (mut s, h) = session();
        s.send(P1, b"x").await?;
        s.send(P2, b"y").await?;
        assert_eq!(
            h.written(),
            [
                line(&Packet::Command(P1)),
                line(&data(P1, b"x")),
                line(&Packet::Close(P1)),
                line(&Packet::Command(P2)),
                line(&data(P2, b"y")),
            ]
        );
        assert!(h.violations().is_empty(), "{:?}", h.violations());
        Ok(())
    }

    #[tokio::test]
    async fn large_payloads_are_split_at_32_kib() -> Result<()> {
        let (mut s, h) = session();
        let input = vec![7u8; 70_000];
        s.send(Uuid::nil(), &input).await?;
        let mut sizes = Vec::new();
        let mut joined = Vec::new();
        for l in h.written() {
            match parse_line(&l)? {
                Some(Packet::Data {
                    guid,
                    payload,
                    stream: Stream::Default,
                }) if guid.is_nil() => {
                    sizes.push(payload.len());
                    joined.extend(payload);
                }
                other => panic!("not a Data line on the pool: {other:?}"),
            }
        }
        assert_eq!(sizes, [32_768, 32_768, 4_464]);
        assert_eq!(joined, input);
        assert!(h.violations().is_empty(), "{:?}", h.violations());
        Ok(())
    }

    #[tokio::test]
    async fn empty_payload_writes_nothing() -> Result<()> {
        let (mut s, h) = session();
        s.send(P1, b"").await?;
        assert!(h.written().is_empty(), "{:?}", h.written());
        Ok(())
    }

    #[tokio::test]
    async fn data_received_while_waiting_for_an_ack_is_kept_for_recv() -> Result<()> {
        let (mut s, h) = session();
        h.inject(&server_line(&data(Uuid::nil(), b"early")));
        s.send(Uuid::nil(), b"a").await?;
        assert_eq!(s.recv().await?, b"early");
        assert!(h.violations().is_empty(), "{:?}", h.violations());
        Ok(())
    }

    #[tokio::test]
    async fn signal_targets_the_open_command() -> Result<()> {
        let (mut s, h) = session();
        h.set_pipelines_run_forever(true);
        let create = PsrpMessage::to_server(
            MessageType::CreatePipeline,
            RPID,
            P1,
            "<Obj RefId=\"0\"><MS /></Obj>".to_owned(),
        )
        .encode();
        s.send(P1, &encode_message(1, &create)).await?;

        s.signal().await?;

        assert_eq!(h.written().last(), Some(&line(&Packet::Signal(P1))));
        let mut reassembler = Reassembler::new();
        let messages = loop {
            let done = reassembler.feed(&s.recv().await?)?;
            if !done.is_empty() {
                break done;
            }
        };
        let msg = PsrpMessage::decode(&messages[0])?;
        assert_eq!(msg.message_type, MessageType::PipelineState);
        assert_eq!(msg.pid, P1);
        assert_eq!(extract_pipeline_state(&msg.data)?, PipelineState::Stopped);
        assert!(h.violations().is_empty(), "{:?}", h.violations());
        Ok(())
    }

    #[tokio::test]
    async fn signal_without_a_command_writes_nothing() -> Result<()> {
        let (mut s, h) = session();
        s.signal().await?;
        assert!(h.written().is_empty(), "{:?}", h.written());
        s.send(Uuid::nil(), b"a").await?;
        s.signal().await?;
        assert_eq!(h.written(), [line(&data(Uuid::nil(), b"a"))]);
        Ok(())
    }

    #[tokio::test]
    async fn close_closes_the_open_command_before_the_session() -> Result<()> {
        let (mut s, h) = session();
        s.send(P1, b"x").await?;
        s.close().await?;
        let written = h.written();
        assert_eq!(
            written[written.len() - 2..],
            [line(&Packet::Close(P1)), line(&Packet::Close(Uuid::nil()))]
        );
        assert!(h.violations().is_empty(), "{:?}", h.violations());
        Ok(())
    }

    #[tokio::test]
    async fn eof_is_an_error_and_breaks_the_session() {
        let (mut s, h) = session();
        h.hang_up();
        let first = s.recv().await.unwrap_err();
        assert!(matches!(first, PsrpError::Protocol(_)), "{first:?}");
        let before = h.written();

        let second = s.send(Uuid::nil(), b"a").await.unwrap_err();
        assert!(matches!(second, PsrpError::Protocol(_)), "{second:?}");
        assert_eq!(second.to_string(), first.to_string());
        assert_eq!(h.written(), before);
    }

    #[tokio::test]
    async fn server_error_line_is_reported_and_breaks_the_session() {
        let (mut s, h) = session();
        h.inject("__NamedPipeError__:boom\r\n   at Foo()\r\n");
        let err = s.recv().await.unwrap_err();
        assert!(err.to_string().contains("boom"), "{err}");
        assert!(s.send(Uuid::nil(), b"a").await.is_err());
    }

    #[tokio::test]
    async fn unexpected_ack_is_ignored() -> Result<()> {
        let (mut s, h) = session();
        h.inject(&server_line(&Packet::CloseAck(G)));
        s.send(Uuid::nil(), b"a").await?;
        assert!(h.violations().is_empty(), "{:?}", h.violations());
        Ok(())
    }

    #[tokio::test]
    async fn server_may_not_send_client_packets() {
        let (mut s, h) = session();
        h.inject(&server_line(&Packet::Command(G)));
        assert!(s.recv().await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn a_dropped_send_is_settled_before_the_next_request() -> Result<()> {
        let (mut s, h) = session();
        h.hold_replies(true);
        assert!(
            timeout(Duration::from_secs(1), s.send(Uuid::nil(), b"a"))
                .await
                .is_err()
        );
        h.hold_replies(false);

        s.send(Uuid::nil(), b"b").await?;

        assert_eq!(
            h.written(),
            [
                line(&data(Uuid::nil(), b"a")),
                line(&data(Uuid::nil(), b"b"))
            ]
        );
        assert!(h.violations().is_empty(), "{:?}", h.violations());
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_send_dropped_while_opening_a_command_does_not_reopen_it() -> Result<()> {
        let (mut s, h) = session();
        h.hold_replies(true);
        assert!(
            timeout(Duration::from_secs(1), s.send(P1, b"x"))
                .await
                .is_err()
        );
        h.hold_replies(false);

        s.send(P1, b"y").await?;

        assert_eq!(
            h.written(),
            [line(&Packet::Command(P1)), line(&data(P1, b"y"))]
        );
        assert!(h.violations().is_empty(), "{:?}", h.violations());
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_close_dropped_after_closing_the_command_does_not_close_it_twice() -> Result<()> {
        let (mut s, h) = session();
        s.send(P1, b"x").await?;
        h.hold_replies(true);
        assert!(timeout(Duration::from_secs(1), s.close()).await.is_err());
        h.hold_replies(false);

        s.close().await?;

        let written = h.written();
        assert_eq!(
            written[2..],
            [line(&Packet::Close(P1)), line(&Packet::Close(Uuid::nil()))]
        );
        assert!(h.violations().is_empty(), "{:?}", h.violations());
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_request_dropped_while_its_line_is_written_breaks_the_session() -> Result<()> {
        let (mut s, h) = session();
        h.inject(&server_line(&data(Uuid::nil(), b"early")));
        s.send(Uuid::nil(), b"a").await?;
        let before = h.written();
        h.stall_writes(true);
        assert!(
            timeout(Duration::from_secs(1), s.send(Uuid::nil(), b"b"))
                .await
                .is_err()
        );
        h.stall_writes(false);

        let err = s.send(Uuid::nil(), b"c").await.unwrap_err();
        assert!(matches!(err, PsrpError::Protocol(_)), "{err:?}");
        assert!(
            err.to_string()
                .contains("a request was abandoned while its line was being written"),
            "{err}"
        );
        assert_eq!(s.signal().await.unwrap_err().to_string(), err.to_string());
        assert_eq!(s.close().await.unwrap_err().to_string(), err.to_string());
        // What was already received is still handed out, then the error.
        assert_eq!(s.recv().await?, b"early");
        assert_eq!(s.recv().await.unwrap_err().to_string(), err.to_string());
        // Nothing after the half-written line: it would have been corrupted.
        assert_eq!(h.written(), before);
        assert!(h.violations().is_empty(), "{:?}", h.violations());
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_write_stuck_past_the_timeout_is_reported_as_such() {
        let (mut s, h) = session();
        h.stall_writes(true);

        let err = s.send(Uuid::nil(), b"a").await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(&format!(
                "PowerShell did not accept Data for {NIL} within 60 s"
            )),
            "{msg}"
        );
        assert!(!msg.contains("acknowledge"), "{msg}");

        let again = s.send(Uuid::nil(), b"b").await.unwrap_err();
        assert_eq!(again.to_string(), msg);
        assert!(h.written().is_empty(), "{:?}", h.written());
    }

    #[tokio::test(start_paused = true)]
    async fn an_unacknowledged_request_times_out_and_breaks_the_session() {
        let (mut s, h) = session();
        h.hold_replies(true);

        let first = s.send(Uuid::nil(), b"a").await.unwrap_err();
        assert!(first.to_string().contains("within 60 s"), "{first}");

        let second = s.send(Uuid::nil(), b"b").await.unwrap_err();
        assert!(matches!(second, PsrpError::Protocol(_)), "{second:?}");
        assert_eq!(h.written().len(), 1, "{:?}", h.written());
    }

    #[tokio::test]
    async fn flooding_without_ack_breaks_the_session() {
        let (fake, h) = FakePwsh::new();
        let mut s = OutOfProcSession::new(fake).with_max_queued_bytes(1024);
        h.hold_replies(true);
        for _ in 0..3 {
            h.inject(&server_line(&data(Uuid::nil(), &[1u8; 600])));
        }
        h.hold_replies(false);

        assert!(s.send(Uuid::nil(), b"a").await.is_err());
    }

    #[tokio::test]
    async fn byte_at_a_time_crlf_stdout_is_reassembled() -> Result<()> {
        let (mut s, h) = session();
        h.set_chunk_size(1);
        s.send(P1, b"x").await?;

        let payload = b"\x00\x01\r\n<Data>\xff".to_vec();
        h.inject(&server_line(&data(P1, &payload)));
        assert_eq!(s.recv().await?, payload);
        assert!(h.violations().is_empty(), "{:?}", h.violations());
        Ok(())
    }
}
