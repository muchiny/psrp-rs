//! A fake `pwsh -sshs` for the unit tests, and the oracle for protocol
//! violations.
//!
//! [`FakePwsh`] is a [`Pipe`] that answers each client line the way
//! PowerShell 7 does, and records as a violation every rule the client
//! breaks; [`FakeHandle`] configures it and reports what happened. Replies are
//! queued synchronously inside `write`, PSRP being decoded per `PSGuid`.
//! `read` hands the queue out and, when it is empty, waits for the next write
//! like a real server; it fails (end of stream) only after
//! [`FakeHandle::hang_up`] or a death.
//!
//! A death (after [`FakeHandle::die_after_writes`] or a fatal violation) is
//! what `pwsh` does on a protocol error: no reply to the offending line, the
//! line [`DEATH`], then end of stream.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;
use tokio::sync::Notify;
use uuid::Uuid;

use super::packet::{MAX_DATA_PAYLOAD, Packet, Stream, parse_line};
use super::session::Pipe;
use crate::clixml::{PsObject, PsValue, to_clixml};
use crate::error::{PsrpError, Result};
use crate::fragment::{Reassembler, split_message};
use crate::message::{Destination, MessageType, PsrpMessage};
use crate::pipeline::PipelineState;
use crate::runspace::RunspacePoolState;

/// What the fake writes when it dies, before the end of stream.
pub(crate) const DEATH: &str = "__NamedPipeError__:fake pwsh exited\r\n   at Fake()\r\n";

/// How much of an offending line a violation quotes, in characters.
const QUOTED: usize = 100;

/// One line to queue on stdout, and whether it is the acknowledgement.
type Reply = (String, bool);

/// What the fake does with one client line.
enum Reaction {
    /// Queue these lines.
    Reply(Vec<Reply>),
    /// A rule was broken and `pwsh` would block forever: answer nothing.
    Hang(String),
    /// A rule was broken and `pwsh` dies.
    Die(String),
}

#[derive(Default)]
struct State {
    // What the client did.
    /// Every complete line the client wrote, without its `\n`.
    written: Vec<String>,
    /// Every rule the client broke.
    violations: Vec<String>,
    /// Client bytes after the last `\n`.
    partial: Vec<u8>,
    /// Client lines reacted to (lines after the exit are not counted).
    lines_seen: usize,

    // Configuration.
    die_after: Option<usize>,
    /// Replies to the client lines after this many are held.
    hold_after: Option<usize>,
    chunk_size: Option<usize>,
    output: Vec<PsValue>,
    run_forever: bool,
    stall_writes: bool,

    // Server-side protocol state.
    /// The pool's RPID, from `InitRunspacePool`.
    rpid: Uuid,
    /// Pipelines with an acknowledged `<Command>` and no `<Close>` yet.
    open: HashSet<Uuid>,
    /// The RPID each pipeline was created with.
    pipeline_rpids: HashMap<Uuid, Uuid>,
    /// One PSRP reassembler per `PSGuid`.
    reassemblers: HashMap<Uuid, Reassembler>,
    /// Last PSRP object id used.
    object_id: u64,

    // Stdout.
    /// Bytes `read` may hand out.
    out: VecDeque<u8>,
    /// While replies are held: the bytes queued since, after those of `out`.
    held: Option<Vec<u8>>,
    /// The fake exited (hang-up or death): it no longer reacts to client
    /// lines, and `read` ends the stream once everything queued was read.
    exited: bool,
    /// Bytes ever queued on stdout.
    queued: usize,
    /// Bytes ever handed out by `read`.
    read: usize,
    /// Stdout offset just past the last acknowledgement queued.
    ack_end: usize,
}

impl State {
    fn client_bytes(&mut self, bytes: &[u8]) {
        self.partial.extend_from_slice(bytes);
        while let Some(end) = self.partial.iter().position(|b| *b == b'\n') {
            let mut line: Vec<u8> = self.partial.drain(..=end).collect();
            line.pop();
            self.client_line(String::from_utf8_lossy(&line).into_owned());
        }
    }

    fn client_line(&mut self, line: String) {
        self.written.push(line.clone());
        if self.exited {
            return;
        }
        self.lines_seen += 1;
        let reaction = if self.read < self.ack_end {
            Reaction::Die(format!(
                "request written before the previous acknowledgement was read: {}",
                quote(&line)
            ))
        } else {
            self.react(&line)
        };
        let replies = match reaction {
            Reaction::Reply(replies) => replies,
            Reaction::Hang(violation) => {
                self.violations.push(violation);
                Vec::new()
            }
            Reaction::Die(violation) => {
                self.violations.push(violation);
                self.die();
                return;
            }
        };
        if self.die_after == Some(self.lines_seen) {
            self.die();
            return;
        }
        if self.hold_after.is_some_and(|n| self.lines_seen > n) {
            self.held.get_or_insert_with(Vec::new);
        }
        for (text, is_ack) in replies {
            self.emit(&text);
            if is_ack {
                self.ack_end = self.queued;
            }
        }
    }

    fn react(&mut self, line: &str) -> Reaction {
        if line.trim().is_empty() {
            return Reaction::Die("blank line".to_owned());
        }
        if line.trim() != line {
            return Reaction::Die(format!("whitespace around the element: {}", quote(line)));
        }
        let packet = match parse_line(line) {
            Ok(Some(packet)) => packet,
            Ok(None) => return Reaction::Die("blank line".to_owned()),
            Err(e) => return Reaction::Die(format!("malformed line ({e})")),
        };
        let nil = Uuid::nil();
        match packet {
            Packet::DataAck(_)
            | Packet::CommandAck(_)
            | Packet::SignalAck(_)
            | Packet::CloseAck(_) => Reaction::Die(format!(
                "acknowledgement sent to the server: {}",
                quote(line)
            )),
            Packet::Signal(pid) if pid.is_nil() => {
                Reaction::Die(format!("Signal on the session: {}", quote(line)))
            }
            Packet::Signal(pid) => {
                let rpid = self.pipeline_rpids.get(&pid).copied().unwrap_or(self.rpid);
                let mut replies = self.pipeline_state(pid, rpid, PipelineState::Stopped);
                replies.push(ack(Packet::SignalAck(pid)));
                Reaction::Reply(replies)
            }
            Packet::Command(pid) => {
                if self.open.insert(pid) {
                    Reaction::Reply(vec![ack(Packet::CommandAck(pid))])
                } else {
                    Reaction::Die(format!("Command for {pid}, already open"))
                }
            }
            Packet::Close(pid) if pid.is_nil() => {
                if self.open.is_empty() {
                    let mut replies = self.pool_state(RunspacePoolState::Closed);
                    replies.push(ack(Packet::CloseAck(nil)));
                    Reaction::Reply(replies)
                } else {
                    Reaction::Hang(format!(
                        "Close of the session while commands are open: {:?}",
                        self.open
                    ))
                }
            }
            Packet::Close(pid) => {
                self.open.remove(&pid);
                self.reassemblers.remove(&pid);
                Reaction::Reply(vec![ack(Packet::CloseAck(pid))])
            }
            Packet::Data { guid, payload, .. } => self.data(guid, &payload),
        }
    }

    fn data(&mut self, guid: Uuid, payload: &[u8]) -> Reaction {
        if payload.len() > MAX_DATA_PAYLOAD {
            return Reaction::Die(format!(
                "Data of {} bytes, above {MAX_DATA_PAYLOAD}",
                payload.len()
            ));
        }
        if !guid.is_nil() && !self.open.contains(&guid) {
            return Reaction::Die(format!("Data on {guid} without an open Command"));
        }
        // Pool replies come before the DataAck, pipeline replies after it.
        let mut before = Vec::new();
        let mut after = Vec::new();
        for message in self.decode(guid, payload) {
            let creates = matches!(
                message.message_type,
                MessageType::CreatePipeline | MessageType::GetCommandMetadata
            );
            if creates && message.pid != guid {
                return Reaction::Die(format!(
                    "{:?} for PID {} carried by Data on {guid}",
                    message.message_type, message.pid
                ));
            }
            if message.message_type == MessageType::InitRunspacePool {
                self.rpid = message.rpid;
                before.extend(self.pool_state(RunspacePoolState::Opened));
            } else if creates {
                self.pipeline_rpids.insert(guid, message.rpid);
                if !self.run_forever {
                    for value in self.output.clone() {
                        after.extend(self.message(
                            guid,
                            MessageType::PipelineOutput,
                            message.rpid,
                            to_clixml(&value),
                        ));
                    }
                    after.extend(self.pipeline_state(guid, message.rpid, PipelineState::Completed));
                }
            }
        }
        let mut replies = before;
        replies.push(ack(Packet::DataAck(guid)));
        replies.extend(after);
        Reaction::Reply(replies)
    }

    /// The PSRP messages `payload` completes on `guid`. Bytes that are not
    /// PSRP complete none.
    fn decode(&mut self, guid: Uuid, payload: &[u8]) -> Vec<PsrpMessage> {
        match self.reassemblers.entry(guid).or_default().feed(payload) {
            Ok(done) => done
                .iter()
                .filter_map(|bytes| PsrpMessage::decode(bytes).ok())
                .collect(),
            Err(_) => {
                self.reassemblers.remove(&guid);
                Vec::new()
            }
        }
    }

    fn pool_state(&mut self, state: RunspacePoolState) -> Vec<Reply> {
        let body = PsObject::new().with("RunspaceState", PsValue::I32(state as i32));
        let rpid = self.rpid;
        self.message(
            Uuid::nil(),
            MessageType::RunspacePoolState,
            rpid,
            to_clixml(&PsValue::Object(body)),
        )
    }

    fn pipeline_state(&mut self, pid: Uuid, rpid: Uuid, state: PipelineState) -> Vec<Reply> {
        let body = PsObject::new().with("PipelineState", PsValue::I32(state as i32));
        self.message(
            pid,
            MessageType::PipelineState,
            rpid,
            to_clixml(&PsValue::Object(body)),
        )
    }

    /// A server-to-client PSRP message for `pid`, one `<Data>` line per fragment.
    fn message(
        &mut self,
        pid: Uuid,
        message_type: MessageType,
        rpid: Uuid,
        data: String,
    ) -> Vec<Reply> {
        let bytes = PsrpMessage {
            destination: Destination::Client,
            message_type,
            rpid,
            pid,
            data,
        }
        .encode();
        self.object_id += 1;
        split_message(self.object_id, &bytes)
            .iter()
            .map(|fragment| {
                let line = crlf(&Packet::Data {
                    stream: Stream::Default,
                    guid: pid,
                    payload: fragment.encode(),
                });
                (line, false)
            })
            .collect()
    }

    fn emit(&mut self, text: &str) {
        self.emit_bytes(text.as_bytes());
    }

    fn emit_bytes(&mut self, bytes: &[u8]) {
        self.queued += bytes.len();
        if let Some(held) = &mut self.held {
            held.extend_from_slice(bytes);
        } else {
            self.out.extend(bytes);
        }
    }

    fn die(&mut self) {
        self.emit(DEATH);
        self.exited = true;
    }

    /// The next chunk `read` hands out: one line, or `chunk_size` bytes.
    fn next_chunk(&mut self) -> Option<Vec<u8>> {
        if self.out.is_empty() {
            return None;
        }
        let n = match self.chunk_size {
            Some(n) => n.min(self.out.len()),
            None => self
                .out
                .iter()
                .position(|b| *b == b'\n')
                .map_or(self.out.len(), |i| i + 1),
        };
        self.read += n;
        Some(self.out.drain(..n).collect())
    }

    fn at_eof(&self) -> bool {
        self.exited && self.out.is_empty() && self.held.as_ref().is_none_or(Vec::is_empty)
    }
}

fn ack(packet: Packet) -> Reply {
    (crlf(&packet), true)
}

/// `packet` as `pwsh` on Windows writes it.
fn crlf(packet: &Packet) -> String {
    format!("{}\r\n", packet.to_line().trim_end_matches('\n'))
}

fn quote(line: &str) -> String {
    let head: String = line.chars().take(QUOTED).collect();
    format!("{head:?}")
}

fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The fake server's end of the pipe.
pub(crate) struct FakePwsh {
    state: Arc<Mutex<State>>,
    notify: Arc<Notify>,
}

/// Configures a [`FakePwsh`] and reports what the client did.
#[derive(Clone)]
pub(crate) struct FakeHandle {
    state: Arc<Mutex<State>>,
    notify: Arc<Notify>,
}

impl FakePwsh {
    pub(crate) fn new() -> (Self, FakeHandle) {
        let state = Arc::new(Mutex::new(State::default()));
        let notify = Arc::new(Notify::new());
        let handle = FakeHandle {
            state: Arc::clone(&state),
            notify: Arc::clone(&notify),
        };
        (Self { state, notify }, handle)
    }
}

#[async_trait]
impl Pipe for FakePwsh {
    async fn write(&mut self, bytes: &[u8]) -> Result<()> {
        let stalled = {
            let mut state = lock(&self.state);
            if state.stall_writes {
                state.client_bytes(&bytes[..bytes.len() / 2]);
            } else {
                state.client_bytes(bytes);
            }
            state.stall_writes
        };
        self.notify.notify_one();
        if stalled {
            std::future::pending::<()>().await;
        }
        Ok(())
    }

    async fn read(&mut self) -> Result<Vec<u8>> {
        loop {
            {
                let mut state = lock(&self.state);
                if let Some(chunk) = state.next_chunk() {
                    return Ok(chunk);
                }
                if state.at_eof() {
                    return Err(PsrpError::protocol("fake pwsh: end of stdout"));
                }
            }
            // Only this reader waits, so a permit stored by a write in
            // between is never lost.
            self.notify.notified().await;
        }
    }
}

impl FakeHandle {
    /// Every line the client wrote, without `\n`.
    pub(crate) fn written(&self) -> Vec<String> {
        lock(&self.state).written.clone()
    }

    /// The protocol rules the client broke.
    pub(crate) fn violations(&self) -> Vec<String> {
        lock(&self.state).violations.clone()
    }

    /// Hands stdout out `n` bytes per read (default: one line per read).
    pub(crate) fn set_chunk_size(&self, n: usize) {
        lock(&self.state).chunk_size = Some(n.max(1));
    }

    /// The `PipelineOutput` every pipeline sends before `Completed`.
    pub(crate) fn set_output(&self, values: Vec<PsValue>) {
        lock(&self.state).output = values;
    }

    /// Pipelines send no output and no `Completed`: only `Signal` stops them.
    pub(crate) fn set_pipelines_run_forever(&self, on: bool) {
        lock(&self.state).run_forever = on;
    }

    /// While on, replies (and injected text) are buffered, invisible to `read`.
    /// Turning it off also cancels [`Self::hold_replies_after_writes`].
    pub(crate) fn hold_replies(&self, on: bool) {
        {
            let mut state = lock(&self.state);
            if on {
                state.held.get_or_insert_with(Vec::new);
            } else {
                state.hold_after = None;
                if let Some(held) = state.held.take() {
                    state.out.extend(held);
                }
            }
        }
        self.notify.notify_one();
    }

    /// Replies to the first `n` client lines go out as usual; from the next
    /// one on, replies are held as by [`Self::hold_replies`].
    pub(crate) fn hold_replies_after_writes(&self, n: usize) {
        lock(&self.state).hold_after = Some(n);
    }

    /// While on, `write` hands the first half of its bytes to the server and
    /// never completes: a write stuck mid-line, as on a full SSH window.
    pub(crate) fn stall_writes(&self, on: bool) {
        lock(&self.state).stall_writes = on;
    }

    /// Queues raw stdout text: an error line, junk, a BOM, a stray `<Data>`.
    pub(crate) fn inject(&self, raw: &str) {
        self.inject_bytes(raw.as_bytes());
    }

    /// Queues raw stdout bytes, not necessarily UTF-8.
    pub(crate) fn inject_bytes(&self, raw: &[u8]) {
        lock(&self.state).emit_bytes(raw);
        self.notify.notify_one();
    }

    /// The `n`-th client line (counted from the first) gets no reply: the
    /// fake dies instead.
    pub(crate) fn die_after_writes(&self, n: usize) {
        lock(&self.state).die_after = Some(n);
    }

    /// The fake exits: end of stream once everything queued was read, and no
    /// reaction to later client lines.
    pub(crate) fn hang_up(&self) {
        lock(&self.state).exited = true;
        self.notify.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clixml::parse_clixml;
    use crate::fragment::encode_message;
    use std::time::Duration;

    const P1: Uuid = Uuid::from_u128(0x1111_1111_1111_4111_8111_1111_1111_1111);
    const P2: Uuid = Uuid::from_u128(0x2222_2222_2222_4222_8222_2222_2222_2222);
    const RPID: Uuid = Uuid::from_u128(0x3333_3333_3333_4333_8333_3333_3333_3333);

    fn data(guid: Uuid, payload: &[u8]) -> Packet {
        Packet::Data {
            stream: Stream::Default,
            guid,
            payload: payload.to_vec(),
        }
    }

    /// The fragment bytes of a client message.
    fn message(message_type: MessageType, pid: Uuid) -> Vec<u8> {
        let body = "<Obj RefId=\"0\"><MS /></Obj>".to_owned();
        encode_message(
            1,
            &PsrpMessage::to_server(message_type, RPID, pid, body).encode(),
        )
    }

    async fn write(fake: &mut FakePwsh, packet: &Packet) {
        fake.write(packet.to_line().as_bytes()).await.unwrap();
    }

    /// Everything `read` can hand out right now, as raw text.
    fn drain(fake: &FakePwsh) -> String {
        let mut out = Vec::new();
        while let Some(chunk) = lock(&fake.state).next_chunk() {
            out.extend(chunk);
        }
        String::from_utf8(out).unwrap()
    }

    fn name(guid: Uuid) -> &'static str {
        match guid {
            g if g.is_nil() => "nil",
            P1 => "P1",
            RPID => "R",
            _ => "?",
        }
    }

    fn property(clixml: &str, key: &str) -> i32 {
        let values = parse_clixml(clixml).unwrap();
        let PsValue::Object(obj) = &values[0] else {
            panic!("not an object: {clixml}");
        };
        obj.get(key).and_then(PsValue::as_i32).unwrap()
    }

    /// What `read` can hand out right now, one short description per line.
    fn replies(fake: &FakePwsh) -> Vec<String> {
        let text = drain(fake);
        let mut lines: Vec<&str> = text.split_inclusive('\n').collect();
        assert!(lines.iter().all(|l| l.ends_with("\r\n")), "{text:?}");
        for l in &mut lines {
            *l = l.trim_end();
        }
        lines
            .into_iter()
            .map(|line| match parse_line(line).unwrap().unwrap() {
                Packet::Data { guid, payload, .. } => {
                    let done = Reassembler::new().feed(&payload).unwrap();
                    let msg = PsrpMessage::decode(&done[0]).unwrap();
                    assert_eq!(msg.destination, Destination::Client);
                    assert_eq!(msg.pid, guid, "Data routed off its PID");
                    let detail = match msg.message_type {
                        MessageType::RunspacePoolState => {
                            property(&msg.data, "RunspaceState").to_string()
                        }
                        MessageType::PipelineState => {
                            property(&msg.data, "PipelineState").to_string()
                        }
                        _ => msg.data.clone(),
                    };
                    let (mt, rpid) = (msg.message_type, name(msg.rpid));
                    format!("{mt:?}={detail} {}/{rpid}", name(guid))
                }
                other => {
                    let rendered = other.to_line();
                    let element = rendered.split_whitespace().next().unwrap();
                    let guid = match other {
                        Packet::DataAck(g)
                        | Packet::CommandAck(g)
                        | Packet::SignalAck(g)
                        | Packet::CloseAck(g) => g,
                        _ => panic!("the fake sent a client packet: {line}"),
                    };
                    format!("{} {}", &element[1..], name(guid))
                }
            })
            .collect()
    }

    #[tokio::test]
    async fn fake_flags_a_request_sent_before_the_previous_ack_was_read() {
        let (mut fake, h) = FakePwsh::new();
        let line = data(Uuid::nil(), b"a").to_line();
        fake.write(line.as_bytes()).await.unwrap();
        fake.write(line.as_bytes()).await.unwrap();
        assert_eq!(h.violations().len(), 1, "{:?}", h.violations());
        assert_eq!(h.written().len(), 2);
    }

    #[tokio::test]
    async fn fake_accepts_a_request_once_the_previous_ack_was_read() {
        let (mut fake, h) = FakePwsh::new();
        h.set_chunk_size(3);
        let line = data(Uuid::nil(), b"a").to_line();
        fake.write(line.as_bytes()).await.unwrap();
        assert_eq!(replies(&fake), ["DataAck nil"]);
        fake.write(line.as_bytes()).await.unwrap();
        assert!(h.violations().is_empty(), "{:?}", h.violations());
    }

    #[tokio::test]
    async fn fake_answers_like_pwsh() {
        let nil = Uuid::nil();
        let (mut fake, h) = FakePwsh::new();
        h.set_output(vec![PsValue::I32(2)]);

        write(
            &mut fake,
            &data(nil, &message(MessageType::SessionCapability, nil)),
        )
        .await;
        assert_eq!(replies(&fake), ["DataAck nil"]);
        write(
            &mut fake,
            &data(nil, &message(MessageType::InitRunspacePool, nil)),
        )
        .await;
        assert_eq!(replies(&fake), ["RunspacePoolState=2 nil/R", "DataAck nil"]);
        write(&mut fake, &Packet::Command(P1)).await;
        assert_eq!(replies(&fake), ["CommandAck P1"]);
        write(
            &mut fake,
            &data(P1, &message(MessageType::CreatePipeline, P1)),
        )
        .await;
        assert_eq!(
            replies(&fake),
            [
                "DataAck P1",
                "PipelineOutput=<I32>2</I32> P1/R",
                "PipelineState=4 P1/R"
            ]
        );
        write(&mut fake, &Packet::Signal(P1)).await;
        assert_eq!(replies(&fake), ["PipelineState=3 P1/R", "SignalAck P1"]);
        write(&mut fake, &Packet::Close(P1)).await;
        assert_eq!(replies(&fake), ["CloseAck P1"]);
        write(
            &mut fake,
            &data(nil, &message(MessageType::CloseRunspacePool, nil)),
        )
        .await;
        assert_eq!(replies(&fake), ["DataAck nil"]);
        write(&mut fake, &Packet::Close(nil)).await;
        assert_eq!(
            replies(&fake),
            ["RunspacePoolState=3 nil/R", "CloseAck nil"]
        );
        assert!(h.violations().is_empty(), "{:?}", h.violations());
    }

    #[tokio::test]
    async fn fake_pipelines_can_run_forever() {
        let (mut fake, h) = FakePwsh::new();
        h.set_output(vec![PsValue::I32(2)]);
        h.set_pipelines_run_forever(true);
        write(&mut fake, &Packet::Command(P1)).await;
        assert_eq!(replies(&fake), ["CommandAck P1"]);
        write(
            &mut fake,
            &data(P1, &message(MessageType::GetCommandMetadata, P1)),
        )
        .await;
        assert_eq!(replies(&fake), ["DataAck P1"]);
        write(&mut fake, &Packet::Signal(P1)).await;
        assert_eq!(replies(&fake), ["PipelineState=3 P1/R", "SignalAck P1"]);
        assert!(h.violations().is_empty(), "{:?}", h.violations());
    }

    #[tokio::test]
    async fn fake_records_each_violation_then_dies() {
        let nil = Uuid::nil();
        let line = |p: &Packet| p.to_line();
        let command = vec![Packet::Command(P1)];
        let cases: Vec<(&str, Vec<Packet>, String)> = vec![
            ("blank line", vec![], "\n".to_owned()),
            (
                "whitespace",
                vec![],
                format!(" {}", line(&Packet::Close(nil))),
            ),
            ("not XML", vec![], "hello from .bashrc\n".to_owned()),
            ("ack to the server", vec![], line(&Packet::DataAck(nil))),
            ("Signal on the session", vec![], line(&Packet::Signal(nil))),
            ("Data without Command", vec![], line(&data(P1, b"x"))),
            (
                "Data above 32 KiB",
                vec![],
                line(&data(nil, &[0; MAX_DATA_PAYLOAD + 1])),
            ),
            ("Command twice", command.clone(), line(&Packet::Command(P1))),
            (
                "creation PID differs from the Data PSGuid",
                command,
                line(&data(P1, &message(MessageType::CreatePipeline, P2))),
            ),
            (
                "creation carried on the session",
                vec![],
                line(&data(nil, &message(MessageType::GetCommandMetadata, P1))),
            ),
        ];
        for (case, setup, bad) in cases {
            let (mut fake, h) = FakePwsh::new();
            for packet in &setup {
                write(&mut fake, packet).await;
                drain(&fake);
            }
            fake.write(bad.as_bytes()).await.unwrap();
            assert_eq!(h.violations().len(), 1, "{case}: {:?}", h.violations());
            assert_eq!(drain(&fake), DEATH, "{case}");
            assert!(fake.read().await.is_err(), "{case}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn fake_hangs_on_a_session_close_with_a_command_open() {
        let (mut fake, h) = FakePwsh::new();
        write(&mut fake, &Packet::Command(P1)).await;
        drain(&fake);
        write(&mut fake, &Packet::Close(Uuid::nil())).await;
        assert_eq!(h.violations().len(), 1, "{:?}", h.violations());
        assert!(
            tokio::time::timeout(Duration::from_secs(5), fake.read())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn fake_dies_instead_of_answering_the_nth_line() {
        let nil = Uuid::nil();
        let (mut fake, h) = FakePwsh::new();
        h.die_after_writes(2);
        write(
            &mut fake,
            &data(nil, &message(MessageType::SessionCapability, nil)),
        )
        .await;
        assert_eq!(replies(&fake), ["DataAck nil"]);
        write(
            &mut fake,
            &data(nil, &message(MessageType::InitRunspacePool, nil)),
        )
        .await;
        assert_eq!(drain(&fake), DEATH);
        assert!(fake.read().await.is_err());
        assert!(h.violations().is_empty(), "{:?}", h.violations());
    }

    #[tokio::test(start_paused = true)]
    async fn fake_read_waits_for_the_next_write() {
        let (mut fake, h) = FakePwsh::new();
        assert!(
            tokio::time::timeout(Duration::from_secs(5), fake.read())
                .await
                .is_err()
        );
        h.hold_replies(true);
        write(&mut fake, &data(Uuid::nil(), b"a")).await;
        assert_eq!(drain(&fake), "");
        h.hang_up();
        assert!(
            tokio::time::timeout(Duration::from_secs(5), fake.read())
                .await
                .is_err(),
            "end of stream before the held replies"
        );
        h.hold_replies(false);
        assert_eq!(replies(&fake), ["DataAck nil"]);
        assert!(fake.read().await.is_err());
    }
}
