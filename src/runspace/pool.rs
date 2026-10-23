//! Async driver that owns the transport and executes the state machine's
//! actions.

use std::sync::Arc;

use uuid::Uuid;

use crate::clixml::{PsObject, PsValue, parse_clixml, to_clixml};
use crate::error::{PsrpError, Result};
use crate::fragment::{Reassembler, encode_message};
use crate::host::{HostMethodId, NoInteractionHost, PsHost, dispatch_host_call};
use crate::message::{Destination, MessageType, PsrpMessage};
use crate::transport::PsrpTransport;

use super::state::{Action, RunspacePoolState, RunspacePoolStateMachine};

/// A runspace pool.
///
/// Generic over the transport so tests can drive the state machine with an
/// in-memory mock. In real usage, parameterize with
/// [`crate::transport::WinrmPsrpTransport`].
pub struct RunspacePool<T: PsrpTransport> {
    transport: T,
    reassembler: Reassembler,
    machine: RunspacePoolStateMachine,
    next_object_id: u64,
    closed: bool,
    host: Arc<dyn PsHost>,
    session_key: Option<crate::crypto::SessionKey>,
    /// The RSA key pair of a session-key exchange whose `PublicKey` is sent
    /// and whose `EncryptedSessionKey` is awaited. Single use.
    pending_client_key: Option<crate::crypto::ClientSessionKey>,
    /// Host-call answers holding a `SecureString`, parked until the session
    /// key arrives (sent encrypted then, never in clear).
    deferred_host_responses: Vec<DeferredHostResponse>,
    /// Messages decoded from a single recv_chunk that contained multiple
    /// PSRP messages. Drained before the next transport read.
    pending_messages: Vec<PsrpMessage>,
}

/// A host-call answer waiting for the session key.
struct DeferredHostResponse {
    response_type: MessageType,
    pid: Uuid,
    ci: i64,
    mi: i64,
    value: PsValue,
}

impl<T: PsrpTransport> RunspacePool<T> {
    /// Open a runspace pool with the default `[1,1]` runspace bounds.
    ///
    /// For mock transports, the opening `SessionCapability` +
    /// `InitRunspacePool` messages are sent via `send_fragment` on the
    /// existing transport. For real transports (e.g.
    /// [`WinrmPsrpTransport`](crate::transport::WinrmPsrpTransport)),
    /// use [`open_with_transport`](Self::open_with_transport) instead — it embeds the creation
    /// fragments in the WS-Man `<creationXml>`.
    pub async fn open_with_transport(transport: T) -> Result<Self> {
        Self::open_with_options(transport, 1, 1).await
    }

    /// Open a runspace pool with explicit min/max runspace counts.
    pub async fn open_with_options(
        transport: T,
        min_runspaces: i32,
        max_runspaces: i32,
    ) -> Result<Self> {
        Self::open_with_options_and_host(
            transport,
            min_runspaces,
            max_runspaces,
            Arc::new(NoInteractionHost),
        )
        .await
    }

    /// Open a runspace pool with an explicit [`PsHost`].
    pub async fn open_with_options_and_host(
        transport: T,
        min_runspaces: i32,
        max_runspaces: i32,
        host: Arc<dyn PsHost>,
    ) -> Result<Self> {
        let machine = RunspacePoolStateMachine::new(Uuid::new_v4(), min_runspaces, max_runspaces)?;
        let mut pool = Self {
            transport,
            reassembler: Reassembler::new(),
            machine,
            next_object_id: 1,
            closed: false,
            host,
            session_key: None,
            pending_client_key: None,
            deferred_host_responses: Vec::new(),
            pending_messages: Vec::new(),
        };

        let actions = pool.machine.open();
        pool.execute(actions).await?;
        pool.drain_until_opened().await?;
        Ok(pool)
    }

    /// Build the raw PSRP opening fragments (SessionCapability +
    /// InitRunspacePool) for a pool with the given parameters. Returns
    /// `(rpid, fragment_bytes)` suitable for
    /// [`WinrmPsrpTransport::open`](crate::transport::WinrmPsrpTransport::open).
    ///
    /// This is a static helper — it doesn't require a transport
    /// instance.
    pub fn build_creation_fragments(
        min_runspaces: i32,
        max_runspaces: i32,
    ) -> Result<(Uuid, Vec<u8>)> {
        let mut machine =
            RunspacePoolStateMachine::new(Uuid::new_v4(), min_runspaces, max_runspaces)?;
        let actions = machine.open();
        let rpid = machine.rpid();
        let mut next_oid = 1u64;
        let mut buf = Vec::new();
        for action in actions {
            match action {
                Action::SendMessage { message_type, body } => {
                    let msg = PsrpMessage {
                        destination: Destination::Server,
                        message_type,
                        rpid,
                        pid: Uuid::nil(),
                        data: body,
                    };
                    let encoded = msg.encode();
                    buf.extend_from_slice(&encode_message(next_oid, &encoded));
                    next_oid += 1;
                }
            }
        }
        Ok((rpid, buf))
    }

    /// Wrap an already-opened transport + pre-negotiated RPID into a
    /// pool and drain until `Opened`. Used by the real PSRP path where
    /// the creation fragments were embedded in the WS-Man shell create.
    pub async fn open_from_transport(
        transport: T,
        rpid: Uuid,
        min_runspaces: i32,
        max_runspaces: i32,
    ) -> Result<Self> {
        Self::open_from_transport_with_host(
            transport,
            rpid,
            min_runspaces,
            max_runspaces,
            Arc::new(NoInteractionHost),
        )
        .await
    }

    /// Like [`open_from_transport`](Self::open_from_transport) but with
    /// a custom host.
    pub async fn open_from_transport_with_host(
        transport: T,
        rpid: Uuid,
        min_runspaces: i32,
        max_runspaces: i32,
        host: Arc<dyn PsHost>,
    ) -> Result<Self> {
        // Build a machine in NegotiationSent state — the open()
        // actions were already embedded in the WS-Man creationXml.
        let mut machine = RunspacePoolStateMachine::new(rpid, min_runspaces, max_runspaces)?;
        // Manually advance past BeforeOpen → NegotiationSent.
        let _ = machine.open(); // produces actions we won't send (already sent)
        let mut pool = Self {
            transport,
            reassembler: Reassembler::new(),
            machine,
            next_object_id: 3, // 1 = SessionCapability, 2 = InitRunspacePool
            closed: false,
            host,
            session_key: None,
            pending_client_key: None,
            deferred_host_responses: Vec::new(),
            pending_messages: Vec::new(),
        };
        pool.drain_until_opened().await?;
        Ok(pool)
    }

    /// Current state.
    #[must_use]
    pub fn state(&self) -> RunspacePoolState {
        self.machine.state()
    }

    /// Configured minimum runspaces.
    #[must_use]
    pub fn min_runspaces(&self) -> i32 {
        self.machine.min_runspaces()
    }

    /// Configured maximum runspaces.
    #[must_use]
    pub fn max_runspaces(&self) -> i32 {
        self.machine.max_runspaces()
    }

    /// Runspace pool UUID.
    #[must_use]
    pub fn id(&self) -> Uuid {
        self.machine.rpid()
    }

    /// Return `Err(BadState)` unless `self.state() == expected`.
    pub fn ensure_state(&self, expected: RunspacePoolState) -> Result<()> {
        if self.machine.state() != expected {
            return Err(PsrpError::BadState {
                expected: format!("{expected:?}"),
                actual: format!("{:?}", self.machine.state()),
            });
        }
        Ok(())
    }

    /// Disconnect the pool, leaving the server-side shell alive so it
    /// can be reconnected later via [`DisconnectedPool::reconnect`].
    ///
    /// Sends `CloseRunspacePool` is **not** called — the runspace stays
    /// alive on the server. To tear it down for good, call [`RunspacePool::close`]
    /// instead.
    pub async fn disconnect(mut self) -> Result<DisconnectedPool> {
        if self.closed {
            return Err(PsrpError::protocol("pool already closed"));
        }
        self.closed = true;
        if !self.deferred_host_responses.is_empty() {
            tracing::warn!(
                parked = self.deferred_host_responses.len(),
                "disconnecting with host calls still waiting for a session key: they will not be answered"
            );
        }
        let shell_id = match self.transport.disconnect_shell().await {
            Ok(id) => id,
            Err(e) => {
                // `disconnect` takes `self`, so a failure here would drop the
                // pool — and with it the only handle to the server-side
                // runspace, which stays alive. The WinRS PowerShell plugin on
                // Server 2012 R2 rejects Disconnect outright, so every attempt
                // leaked one runspace against `MaxShellsPerUser`. Tear the
                // shell down before surfacing the error.
                if let Err(close_err) = self.transport.close_shell().await {
                    tracing::debug!("shell close after failed disconnect: {close_err}");
                }
                return Err(e);
            }
        };
        Ok(DisconnectedPool {
            shell_id,
            rpid: self.machine.rpid(),
            min_runspaces: self.machine.min_runspaces(),
            max_runspaces: self.machine.max_runspaces(),
            host: self.host.clone(),
            session_key: self.session_key.clone(),
        })
    }

    /// Close the pool, sending `CloseRunspacePool` then tearing down the
    /// transport. Consumes `self`.
    pub async fn close(mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let actions = self.machine.close();
        let send_result = self.execute(actions).await;
        if let Err(e) = &send_result {
            tracing::debug!("CloseRunspacePool send failed: {e}");
        }
        self.transport.close_shell().await?;
        self.machine.mark_closed();
        send_result
    }

    /// Run a PowerShell script and collect every `PipelineOutput` as a
    /// [`PsValue`]. For richer access to every stream, see
    /// [`crate::pipeline::Pipeline::run_all_streams`].
    pub async fn run_script(&mut self, script: &str) -> Result<Vec<PsValue>> {
        crate::pipeline::Pipeline::new(script).run(self).await
    }

    /// Session key negotiated with the server for `SecureString`
    /// transport, or `None` if negotiation hasn't happened yet.
    #[must_use]
    pub fn session_key(&self) -> Option<&crate::crypto::SessionKey> {
        self.session_key.as_ref()
    }

    /// Inject a pre-existing session key. Useful in tests that want to
    /// exercise `SecureString` encrypt/decrypt without driving the full
    /// RSA handshake, and available to callers that negotiate a key out
    /// of band.
    ///
    /// An exchange the pool had started is abandoned (its reply would
    /// replace this key), and the host answers that were waiting for a key
    /// are sent, encrypted with this one, by the next read.
    pub fn set_session_key(&mut self, key: crate::crypto::SessionKey) {
        self.session_key = Some(key);
        self.pending_client_key = None;
    }

    /// Encrypt a plaintext `SecureString` value using the currently
    /// negotiated session key. Returns a base64-encoded ciphertext
    /// ready to be embedded in a CLIXML `<SS>` element.
    pub fn encrypt_secure_string(&self, plaintext: &str) -> Result<String> {
        let key = self
            .session_key
            .as_ref()
            .ok_or_else(|| PsrpError::protocol("session key not negotiated yet"))?;
        let bytes = key.encrypt_secure_string(plaintext);
        Ok(crate::clixml::encode::base64_encode(&bytes))
    }

    /// Decrypt a `<SS>` element's base64-encoded body using the current
    /// session key.
    pub fn decrypt_secure_string(&self, base64_body: &str) -> Result<String> {
        let key = self
            .session_key
            .as_ref()
            .ok_or_else(|| PsrpError::protocol("session key not negotiated yet"))?;
        let bytes = crate::clixml::encode::base64_decode(base64_body)
            .ok_or_else(|| PsrpError::protocol("secure string: invalid base64"))?;
        key.decrypt_secure_string(&bytes)
    }

    /// Kick off a PSRP session-key exchange so that `SecureString`
    /// values can be transported between the client and the server.
    ///
    /// Sends a `PublicKey` message containing a freshly-generated
    /// 2048-bit RSA public key and blocks until the server responds
    /// with an `EncryptedSessionKey` — the 256-bit AES key wrapped in
    /// RSAES-PKCS1-v1_5, base64-encoded.
    ///
    /// # Errors
    ///
    /// A server that rejects the key breaks or closes the pool instead of
    /// answering. The call then fails with [`PsrpError::Protocol`], whose
    /// message ends with the server's reason when it gives one, and
    /// [`state`](Self::state) reports `Broken` or `Closed`: the pool can no
    /// longer be used and must be closed. Transport errors and a malformed
    /// reply are returned as well.
    ///
    /// An exchange the pool started itself (a host answer holding a
    /// `SecureString`, or the server's `PublicKeyRequest`) is awaited, not
    /// repeated.
    ///
    /// # No timeout
    ///
    /// A server that never answers keeps the call waiting. Wrapping it in
    /// `tokio::time::timeout` is not safe over WinRM: dropping the call
    /// mid-Receive loses the response that Receive returned. After a
    /// timeout expires, close the pool; do not reuse it.
    pub async fn request_session_key(&mut self) -> Result<()> {
        if self.session_key.is_some() {
            return Ok(());
        }
        // An exchange the pool already started (a host call that needs the
        // key, or the server's `PublicKeyRequest`) is awaited, not repeated.
        if self.pending_client_key.is_none() {
            let client_key = crate::crypto::ClientSessionKey::generate()?;
            self.start_exchange(client_key).await?;
        }
        self.await_session_key().await
    }

    /// The exchange of [`request_session_key`](Self::request_session_key)
    /// with a caller-supplied key pair (so tests need not generate one).
    #[cfg(test)]
    async fn exchange_session_key(
        &mut self,
        client_key: crate::crypto::ClientSessionKey,
    ) -> Result<()> {
        self.start_exchange(client_key).await?;
        self.await_session_key().await
    }

    /// Send the `PublicKey` message and remember the key pair for the reply.
    async fn start_exchange(&mut self, client_key: crate::crypto::ClientSessionKey) -> Result<()> {
        // MS-PSRP 2.2.2.3 — the PublicKey message body is an <Obj> with a
        // single <MS>/<S N="PublicKey"> holding the base64 PUBLICKEYBLOB.
        let body = crate::clixml::to_clixml(&PsValue::Object(PsObject::new().with(
            "PublicKey",
            PsValue::String(client_key.public_blob_base64()),
        )));
        self.send_psrp_message(MessageType::PublicKey, body).await?;
        self.pending_client_key = Some(client_key);
        Ok(())
    }

    /// Start an exchange unless there is a key or one is in flight: what a
    /// host answer holding a `SecureString` and the server's
    /// `PublicKeyRequest` (`PUBLIC_KEY_REQUEST`) both need.
    async fn ensure_key_exchange_started(&mut self) -> Result<()> {
        if self.session_key.is_some() {
            return Ok(());
        }
        self.start_exchange_unless_pending().await
    }

    /// Start an exchange unless one is in flight, even when a key is held:
    /// a server that sends `PublicKeyRequest` has no key for this client
    /// (it may have lost it across a reconnect), and the new key then
    /// replaces the old.
    async fn start_exchange_unless_pending(&mut self) -> Result<()> {
        if self.pending_client_key.is_some() {
            return Ok(());
        }
        let client_key = crate::crypto::ClientSessionKey::generate()?;
        self.start_exchange(client_key).await
    }

    /// Read until the session key is in place. Every message other than the
    /// key goes to the state machine, as in `drain_until_opened`: a server
    /// that rejects the key breaks or closes the pool instead of
    /// answering, and the machine turns that state into an error
    /// carrying the server's reason. Host calls are answered by
    /// `next_message` itself, and so is the `EncryptedSessionKey`.
    ///
    /// No timeout bounds this wait: `WinrmPsrpTransport::recv_chunk` is
    /// not cancel-safe (dropping it mid-Receive loses the bytes that
    /// Receive returned), so timing out could corrupt the pool.
    async fn await_session_key(&mut self) -> Result<()> {
        while self.session_key.is_none() {
            let msg = self.next_message().await?;
            if msg.message_type != MessageType::EncryptedSessionKey {
                self.machine.on_message(&msg)?;
            }
        }
        Ok(())
    }

    /// Take the key out of an `EncryptedSessionKey` message, then send the
    /// host answers that were waiting for it.
    ///
    /// When the reply is unusable, the parked answers are replaced by an
    /// error response each, so the server's host calls do not wait for ever
    /// for an answer that can no longer be encrypted.
    async fn accept_encrypted_session_key(&mut self, msg: &PsrpMessage) -> Result<()> {
        // The key pair is single use, whatever comes of the reply.
        let Some(client_key) = self.pending_client_key.take() else {
            tracing::debug!("EncryptedSessionKey without a pending exchange: ignored");
            return Ok(());
        };
        if let Err(e) = self.take_session_key(msg, &client_key) {
            self.fail_deferred_host_responses(&e).await;
            return Err(e);
        }
        self.flush_deferred_host_responses().await
    }

    fn take_session_key(
        &mut self,
        msg: &PsrpMessage,
        client_key: &crate::crypto::ClientSessionKey,
    ) -> Result<()> {
        let parsed = parse_clixml(&msg.data)?;
        let encoded = parsed
            .into_iter()
            .find_map(|v| match v {
                PsValue::Object(obj) => obj
                    .get("EncryptedSessionKey")
                    .and_then(PsValue::as_str)
                    .map(str::to_string),
                _ => None,
            })
            .ok_or_else(|| {
                PsrpError::protocol(
                    "EncryptedSessionKey message missing EncryptedSessionKey property",
                )
            })?;
        // MS-PSRP 2.2.2.4 — the property is base64, not hex.
        let bytes = crate::clixml::encode::base64_decode(&encoded)
            .ok_or_else(|| PsrpError::protocol("EncryptedSessionKey: invalid base64"))?;
        let raw = client_key.decrypt_session_key(&bytes)?;
        self.session_key = Some(crate::crypto::SessionKey::from_bytes(raw));
        Ok(())
    }

    /// Send the parked host answers, encrypted. One at a time, and removed
    /// once sent: a read dropped in the middle (a cancelled pipeline) leaves
    /// the rest for the next one.
    async fn flush_deferred_host_responses(&mut self) -> Result<()> {
        let Some(key) = self.session_key.clone() else {
            return Ok(());
        };
        while let Some(parked) = self.deferred_host_responses.first() {
            let value = encrypt_secure_strings(&parked.value, &key);
            let body = build_host_response_body(parked.ci, parked.mi, &value);
            let (response_type, pid) = (parked.response_type, parked.pid);
            self.send_pipeline_message(response_type, pid, body).await?;
            self.deferred_host_responses.remove(0);
        }
        Ok(())
    }

    /// Answer every parked host call with an error carrying `why`.
    async fn fail_deferred_host_responses(&mut self, why: &PsrpError) {
        let message = format!("the SecureString could not be sent: {why}");
        for parked in std::mem::take(&mut self.deferred_host_responses) {
            let body = build_host_response_error_body(parked.ci, parked.mi, &message);
            if let Err(e) = self
                .send_pipeline_message(parked.response_type, parked.pid, body)
                .await
            {
                tracing::debug!("host error response not sent: {e}");
            }
        }
    }

    /// Run a script with a cancellation token.
    pub async fn run_script_with_cancel(
        &mut self,
        script: &str,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<Vec<PsValue>> {
        crate::pipeline::Pipeline::new(script)
            .run_with_cancel(self, cancel)
            .await
    }

    // --- internals used by `pipeline.rs` ---

    pub(crate) async fn send_psrp_message(&mut self, mt: MessageType, body: String) -> Result<()> {
        let msg = PsrpMessage {
            destination: Destination::Server,
            message_type: mt,
            rpid: self.machine.rpid(),
            pid: Uuid::nil(),
            data: body,
        };
        let encoded = msg.encode();
        let oid = self.next_object_id;
        self.next_object_id += 1;
        let frag_bytes = encode_message(oid, &encoded);
        self.transport.send_fragment(&frag_bytes).await
    }

    pub(crate) async fn next_message(&mut self) -> Result<PsrpMessage> {
        loop {
            // Answers parked for a key that `set_session_key` has since given.
            if !self.deferred_host_responses.is_empty() && self.session_key.is_some() {
                self.flush_deferred_host_responses().await?;
            }
            // Drain any buffered messages from a previous recv_chunk that
            // produced multiple PSRP messages at once.
            if let Some(msg) = self.pending_messages.pop() {
                match msg.message_type {
                    MessageType::RunspacePoolHostCall | MessageType::PipelineHostCall => {
                        self.handle_host_call(&msg).await?;
                        continue;
                    }
                    // Both are answered here, whoever is reading, and still
                    // handed on: the readers ignore what is not theirs.
                    MessageType::EncryptedSessionKey => {
                        self.accept_encrypted_session_key(&msg).await?;
                        return Ok(msg);
                    }
                    MessageType::PublicKeyRequest => {
                        self.start_exchange_unless_pending().await?;
                        return Ok(msg);
                    }
                    _ => return Ok(msg),
                }
            }

            let chunk = self.transport.recv_chunk().await?;
            if chunk.is_empty() {
                if self.reassembler.is_idle() && self.pending_messages.is_empty() {
                    return Ok(PsrpMessage {
                        destination: Destination::Client,
                        message_type: MessageType::PipelineState,
                        rpid: self.machine.rpid(),
                        pid: Uuid::nil(),
                        data: crate::clixml::to_clixml(&PsValue::Object(
                            PsObject::new().with("PipelineState", PsValue::I32(4)),
                        )),
                    });
                }
            }
            let completed = self.reassembler.feed(&chunk)?;
            // Decode all messages and push to pending buffer (reversed
            // so pop() returns them in FIFO order).
            let mut decoded: Vec<PsrpMessage> = Vec::new();
            for payload in completed {
                decoded.push(PsrpMessage::decode(&payload)?);
            }
            decoded.reverse();
            self.pending_messages.extend(decoded);
        }
    }

    async fn handle_host_call(&mut self, msg: &PsrpMessage) -> Result<()> {
        // PSRP host call body: an Obj with MS containing ci (call id, I64),
        // mi (method id, I32/I64 depending on server), mp (method params list).
        let parsed = parse_clixml(&msg.data)?;
        let root = parsed
            .into_iter()
            .next()
            .ok_or_else(|| PsrpError::protocol("host call: empty body"))?;
        let obj = match &root {
            PsValue::Object(o) => o,
            _ => return Err(PsrpError::protocol("host call: body is not an object")),
        };
        let ci = obj
            .get("ci")
            .and_then(PsValue::as_i64)
            .ok_or_else(|| PsrpError::protocol("host call: missing ci"))?;
        // `mi` is a `RemoteHostMethodId` enum: PowerShell sends it as an
        // `<Obj>` with the number as a bare child (read under `_value`),
        // other implementations as a plain integer.
        let mi_raw = obj
            .get("mi")
            .and_then(|v| match v {
                PsValue::Object(o) => o.get("_value"),
                plain => Some(plain),
            })
            .and_then(|v| v.as_i64().or_else(|| v.as_i32().map(i64::from)))
            .ok_or_else(|| PsrpError::protocol("host call: missing mi"))?;
        let mi = HostMethodId::from_i64(mi_raw);
        let mp: Vec<PsValue> = match obj.get("mp") {
            Some(PsValue::List(items)) => items.clone(),
            Some(PsValue::Object(inner)) => match inner.get("_value") {
                Some(PsValue::List(items)) => items.clone(),
                _ => Vec::new(),
            },
            _ => Vec::new(),
        };

        let result = dispatch_host_call(self.host.as_ref(), mi, &mp).await;

        // Void methods return Ok(None) — nothing to send back.
        let response_value = match result {
            Ok(None) => return Ok(()),
            Ok(Some(v)) => v,
            Err(e) => {
                // Non-void errored — send an ExceptionRecord response so
                // the server doesn't hang waiting for a reply.
                let body = build_host_response_error_body(ci, mi_raw, &e.to_string());
                let response_type = match msg.message_type {
                    MessageType::RunspacePoolHostCall => MessageType::RunspacePoolHostResponse,
                    _ => MessageType::PipelineHostResponse,
                };
                return self
                    .send_pipeline_message(response_type, msg.pid, body)
                    .await;
            }
        };

        let response_type = match msg.message_type {
            MessageType::RunspacePoolHostCall => MessageType::RunspacePoolHostResponse,
            _ => MessageType::PipelineHostResponse,
        };
        // A `SecureString` crosses the wire encrypted with the session key
        // (MS-PSRP 2.2.5.1.24), never as the plaintext the host returned: with
        // no key yet the exchange is started and the answer parked until
        // the key arrives.
        let mut value = response_value;
        if contains_secure_string(&value) {
            match self.session_key.clone() {
                Some(key) => value = encrypt_secure_strings(&value, &key),
                None => {
                    self.ensure_key_exchange_started().await?;
                    self.deferred_host_responses.push(DeferredHostResponse {
                        response_type,
                        pid: msg.pid,
                        ci,
                        mi: mi_raw,
                        value,
                    });
                    return Ok(());
                }
            }
        }
        let body = build_host_response_body(ci, mi_raw, &value);
        self.send_pipeline_message(response_type, msg.pid, body)
            .await
    }

    pub(crate) fn allocate_object_id(&mut self) -> u64 {
        let id = self.next_object_id;
        self.next_object_id += 1;
        id
    }

    pub(crate) async fn signal_transport_stop(&mut self) -> Result<()> {
        self.transport.signal_stop().await
    }

    pub(crate) async fn send_pipeline_message(
        &mut self,
        mt: MessageType,
        pid: Uuid,
        body: String,
    ) -> Result<()> {
        let msg = PsrpMessage {
            destination: Destination::Server,
            message_type: mt,
            rpid: self.machine.rpid(),
            pid,
            data: body,
        };
        let encoded = msg.encode();
        let oid = self.allocate_object_id();
        let frag_bytes = encode_message(oid, &encoded);

        // For CreatePipeline: the first fragment must go via Execute
        // (Command) with the PID as CommandId, not via Send.
        if mt == MessageType::CreatePipeline {
            self.transport.execute_pipeline(&frag_bytes, pid).await
        } else {
            self.transport
                .send_pipeline_fragment(&frag_bytes, pid)
                .await
        }
    }

    // --- private ---

    /// Execute a batch of state-machine actions on the transport.
    async fn execute(&mut self, actions: Vec<Action>) -> Result<()> {
        for action in actions {
            match action {
                Action::SendMessage { message_type, body } => {
                    self.send_psrp_message(message_type, body).await?;
                }
            }
        }
        Ok(())
    }

    async fn drain_until_opened(&mut self) -> Result<()> {
        loop {
            let msg = self.next_message().await?;
            self.machine.on_message(&msg)?;
            if self.machine.is_opened() {
                return Ok(());
            }
        }
    }
}

/// A runspace pool that has been disconnected from its transport but
/// whose server-side shell is still alive.
///
/// Obtain one from [`RunspacePool::disconnect`], then call
/// [`DisconnectedPool::reconnect`] to re-establish the transport and
/// resume the session.
pub struct DisconnectedPool {
    shell_id: String,
    rpid: Uuid,
    min_runspaces: i32,
    max_runspaces: i32,
    host: Arc<dyn PsHost>,
    session_key: Option<crate::crypto::SessionKey>,
}

impl std::fmt::Debug for DisconnectedPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DisconnectedPool")
            .field("rpid", &self.rpid)
            .field("shell_id", &self.shell_id)
            .field("min_runspaces", &self.min_runspaces)
            .field("max_runspaces", &self.max_runspaces)
            .finish()
    }
}

impl DisconnectedPool {
    /// Runspace pool UUID.
    #[must_use]
    pub fn rpid(&self) -> Uuid {
        self.rpid
    }

    /// Server-side shell identifier — pass this to
    /// [`crate::transport::WinrmPsrpTransport::reconnect`] to rebuild the
    /// transport before calling [`reconnect`](Self::reconnect).
    #[must_use]
    pub fn shell_id(&self) -> &str {
        &self.shell_id
    }

    /// Resume the runspace pool by attaching it to a freshly-rebuilt
    /// transport. The caller is responsible for re-creating the
    /// transport with the same `shell_id` (use
    /// [`WinrmPsrpTransport::reconnect`](crate::transport::WinrmPsrpTransport::reconnect)
    /// for the live path).
    ///
    /// The WSMan `Reconnect` the transport performs resumes the shell, and
    /// the reused `SessionId` keeps the server-side runspace `Opened`, so no
    /// PSRP handshake is replayed here.
    // Stays `async` for API stability (2.0.x): callers `.await` it, and the
    // existing-client reconnect no longer needs to send or receive anything
    // now that the transport does the WSMan Reconnect itself.
    #[allow(clippy::unused_async_trait_impl)]
    pub async fn reconnect<T: PsrpTransport>(self, transport: T) -> Result<RunspacePool<T>> {
        let mut machine =
            RunspacePoolStateMachine::new(self.rpid, self.min_runspaces, self.max_runspaces)?;
        // Existing-client reconnect: the transport has already issued the
        // WSMan Reconnect, and the reused SessionId keeps the server-side
        // runspace Opened. `connect` therefore emits no PSRP message and
        // marks the machine Opened — no handshake to send, no state to drain.
        // Replaying the handshake and draining for a fresh Opened state made
        // the follow-up Receive time out (`w:TimedOut`), the server having
        // nothing left to say.
        let actions = machine.connect();
        debug_assert!(actions.is_empty() && machine.is_opened());
        let pool = RunspacePool {
            transport,
            reassembler: Reassembler::new(),
            machine,
            next_object_id: 1,
            closed: false,
            host: self.host,
            session_key: self.session_key,
            pending_client_key: None,
            deferred_host_responses: Vec::new(),
            pending_messages: Vec::new(),
        };
        Ok(pool)
    }
}

/// Whether `value` holds a `SecureString` anywhere in it.
fn contains_secure_string(value: &PsValue) -> bool {
    match value {
        PsValue::SecureString(_) => true,
        PsValue::List(items) => items.iter().any(contains_secure_string),
        PsValue::Dict(entries) => entries
            .iter()
            .any(|(k, v)| contains_secure_string(k) || contains_secure_string(v)),
        PsValue::Object(obj) => obj.properties.values().any(contains_secure_string),
        _ => false,
    }
}

/// `value` with every `SecureString` plaintext replaced by the base64 of
/// its encryption under `key`.
fn encrypt_secure_strings(value: &PsValue, key: &crate::crypto::SessionKey) -> PsValue {
    match value {
        PsValue::SecureString(plain) => PsValue::SecureString(
            crate::clixml::encode::base64_encode(&key.encrypt_secure_string(plain)),
        ),
        PsValue::List(items) => PsValue::List(
            items
                .iter()
                .map(|v| encrypt_secure_strings(v, key))
                .collect(),
        ),
        PsValue::Dict(entries) => PsValue::Dict(
            entries
                .iter()
                .map(|(k, v)| {
                    (
                        encrypt_secure_strings(k, key),
                        encrypt_secure_strings(v, key),
                    )
                })
                .collect(),
        ),
        PsValue::Object(obj) => {
            let mut out = obj.clone();
            for v in out.properties.values_mut() {
                *v = encrypt_secure_strings(v, key);
            }
            PsValue::Object(out)
        }
        other => other.clone(),
    }
}

pub(crate) fn build_host_response_body(ci: i64, mi: i64, value: &PsValue) -> String {
    let obj = PsObject::new()
        .with("ci", PsValue::I64(ci))
        .with("mi", PsValue::I64(mi))
        .with("mr", value.clone());
    to_clixml(&PsValue::Object(obj))
}

pub(crate) fn build_host_response_error_body(ci: i64, mi: i64, message: &str) -> String {
    let exception = PsObject::new()
        .with("Message", PsValue::String(message.to_string()))
        .with_type_names(["System.Exception"]);
    let obj = PsObject::new()
        .with("ci", PsValue::I64(ci))
        .with("mi", PsValue::I64(mi))
        .with("me", PsValue::Object(exception));
    to_clixml(&PsValue::Object(obj))
}

impl<T: PsrpTransport> std::fmt::Debug for RunspacePool<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Manual impl because `PsrpTransport` is not a `Debug` bound.
        f.debug_struct("RunspacePool")
            .field("state", &self.machine.state())
            .field("rpid", &self.machine.rpid())
            .field("min_runspaces", &self.machine.min_runspaces())
            .field("max_runspaces", &self.machine.max_runspaces())
            .field("next_object_id", &self.next_object_id)
            .field("closed", &self.closed)
            .field("reassembler_idle", &self.reassembler.is_idle())
            .field("transport", &"..")
            .finish()
    }
}

impl<T: PsrpTransport> Drop for RunspacePool<T> {
    fn drop(&mut self) {
        if !self.closed {
            tracing::warn!("RunspacePool dropped without close() — server-side shell may leak");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clixml::{PsObject, to_clixml};
    use crate::transport::mock::MockTransport;

    fn state_message_bytes(state: RunspacePoolState) -> Vec<u8> {
        let body = to_clixml(&PsValue::Object(
            PsObject::new().with("RunspaceState", PsValue::I32(state as i32)),
        ));
        PsrpMessage {
            destination: Destination::Client,
            message_type: MessageType::RunspacePoolState,
            rpid: Uuid::nil(),
            pid: Uuid::nil(),
            data: body,
        }
        .encode()
    }

    fn wire(oid: u64, payload: &[u8]) -> Vec<u8> {
        encode_message(oid, payload)
    }

    #[tokio::test]
    async fn open_reaches_opened_state() {
        let t = MockTransport::new();
        t.push_incoming(wire(100, &state_message_bytes(RunspacePoolState::Opened)));

        let pool = RunspacePool::open_with_transport(t.clone()).await.unwrap();
        assert_eq!(pool.state(), RunspacePoolState::Opened);
        assert_eq!(t.sent().len(), 2); // SessionCapability + InitRunspacePool
        pool.close().await.unwrap();
        assert!(*t.closed.lock().unwrap());
    }

    #[tokio::test]
    async fn broken_state_during_open_errors() {
        let t = MockTransport::new();
        t.push_incoming(wire(1, &state_message_bytes(RunspacePoolState::Broken)));
        let err = RunspacePool::open_with_transport(t).await.unwrap_err();
        assert!(matches!(err, PsrpError::Protocol(_)));
    }

    #[tokio::test]
    async fn invalid_runspace_bounds() {
        let t = MockTransport::new();
        let err = RunspacePool::open_with_options(t, 0, 0).await.unwrap_err();
        assert!(matches!(err, PsrpError::Protocol(_)));
    }

    #[tokio::test]
    async fn invalid_runspace_bounds_max_lt_min() {
        let t = MockTransport::new();
        let err = RunspacePool::open_with_options(t, 5, 3).await.unwrap_err();
        assert!(matches!(err, PsrpError::Protocol(_)));
    }

    #[tokio::test]
    async fn open_ignores_unrelated_messages() {
        let t = MockTransport::new();
        let app_data = PsrpMessage {
            destination: Destination::Client,
            message_type: MessageType::ApplicationPrivateData,
            rpid: Uuid::nil(),
            pid: Uuid::nil(),
            data: "<Obj RefId=\"0\"><MS/></Obj>".into(),
        }
        .encode();
        t.push_incoming(wire(1, &app_data));
        t.push_incoming(wire(2, &state_message_bytes(RunspacePoolState::Opened)));
        let pool = RunspacePool::open_with_transport(t).await.unwrap();
        assert_eq!(pool.state(), RunspacePoolState::Opened);
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn ensure_state_works() {
        let t = MockTransport::new();
        t.push_incoming(wire(1, &state_message_bytes(RunspacePoolState::Opened)));
        let pool = RunspacePool::open_with_transport(t).await.unwrap();
        assert!(pool.ensure_state(RunspacePoolState::Opened).is_ok());
        assert!(pool.ensure_state(RunspacePoolState::Broken).is_err());
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn close_is_idempotent_and_drop_warns() {
        let t = MockTransport::new();
        t.push_incoming(wire(1, &state_message_bytes(RunspacePoolState::Opened)));
        let pool = RunspacePool::open_with_transport(t).await.unwrap();
        pool.close().await.unwrap();

        let t = MockTransport::new();
        t.push_incoming(wire(1, &state_message_bytes(RunspacePoolState::Opened)));
        let pool = RunspacePool::open_with_transport(t).await.unwrap();
        drop(pool);
    }

    #[tokio::test]
    async fn debug_impl_does_not_panic() {
        let t = MockTransport::new();
        t.push_incoming(wire(1, &state_message_bytes(RunspacePoolState::Opened)));
        let pool = RunspacePool::open_with_transport(t).await.unwrap();
        let s = format!("{pool:?}");
        assert!(s.contains("RunspacePool"));
        assert!(s.contains("Opened"));
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn min_max_runspaces_exposed() {
        let t = MockTransport::new();
        t.push_incoming(wire(1, &state_message_bytes(RunspacePoolState::Opened)));
        let pool = RunspacePool::open_with_options(t, 2, 5).await.unwrap();
        assert_eq!(pool.min_runspaces(), 2);
        assert_eq!(pool.max_runspaces(), 5);
        assert_ne!(pool.id(), Uuid::nil());
        let _ = pool.close().await;
    }

    // ---------- Phase D coverage tests ----------

    fn host_call_bytes(ci: i64, mi: i64, mp: PsValue) -> Vec<u8> {
        host_call_bytes_with(ci, mi, mp, Uuid::nil(), Uuid::nil())
    }

    fn host_call_bytes_with(ci: i64, mi: i64, mp: PsValue, rpid: Uuid, pid: Uuid) -> Vec<u8> {
        let obj = PsObject::new()
            .with("ci", PsValue::I64(ci))
            .with("mi", PsValue::I64(mi))
            .with("mp", mp);
        let body = to_clixml(&PsValue::Object(obj));
        PsrpMessage {
            destination: Destination::Client,
            message_type: MessageType::RunspacePoolHostCall,
            rpid,
            pid,
            data: body,
        }
        .encode()
    }

    async fn opened_pool_with_host(
        t: &MockTransport,
        host: Arc<dyn PsHost>,
    ) -> RunspacePool<MockTransport> {
        t.inbox
            .lock()
            .unwrap()
            .push_front(wire(1, &state_message_bytes(RunspacePoolState::Opened)));
        RunspacePool::open_with_options_and_host(t.clone(), 1, 1, host)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn host_call_dispatches_write_line_and_swallows_message() {
        let t = MockTransport::new();
        let host = crate::host::BufferedHost::new();
        let mut pool = opened_pool_with_host(&t, Arc::new(host.clone())).await;
        let rpid = pool.id();
        let pid = Uuid::new_v4();
        // Host call (RunspacePoolHostCall): pool intercepts it before the
        // pipeline filter, so the embedded pid does not need to match.
        t.push_incoming(wire(
            2,
            &host_call_bytes(
                42,
                crate::host::HostMethodId::WriteLine1.to_i64(),
                PsValue::List(vec![PsValue::String("hello from host".into())]),
            ),
        ));
        // Pipeline output + state must carry our pipeline's rpid/pid so
        // they pass the pipeline-level pid filter.
        t.push_incoming(wire(
            3,
            &PsrpMessage {
                destination: Destination::Client,
                message_type: MessageType::PipelineOutput,
                rpid,
                pid,
                data: "<I32>1</I32>".into(),
            }
            .encode(),
        ));
        t.push_incoming(wire(
            4,
            &PsrpMessage {
                destination: Destination::Client,
                message_type: MessageType::PipelineState,
                rpid,
                pid,
                data: to_clixml(&PsValue::Object(PsObject::new().with(
                    "PipelineState",
                    PsValue::I32(crate::pipeline::PipelineState::Completed as i32),
                ))),
            }
            .encode(),
        ));
        let out = crate::pipeline::Pipeline::new("irrelevant")
            .__with_forced_pid_for_test(pid)
            .run(&mut pool)
            .await
            .unwrap();
        assert_eq!(out, vec![PsValue::I32(1)]);
        // The host received the WriteLine.
        assert_eq!(host.lines(), vec!["hello from host".to_string()]);
        // After open (2 sent) + CreatePipeline (1 sent) we should NOT have
        // any additional sent frames — WriteLine1 is a void host method.
        assert_eq!(t.sent().len(), 3);
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn host_call_read_line_sends_error_response() {
        let t = MockTransport::new();
        let mut pool = opened_pool_with_host(&t, Arc::new(crate::host::NoInteractionHost)).await;
        let rpid = pool.id();
        let pid = Uuid::new_v4();
        // ReadLine with NoInteractionHost will be rejected and the pool
        // should ship an error response so the server doesn't hang.
        t.push_incoming(wire(
            2,
            &host_call_bytes(
                7,
                crate::host::HostMethodId::ReadLine.to_i64(),
                PsValue::List(Vec::new()),
            ),
        ));
        t.push_incoming(wire(
            3,
            &PsrpMessage {
                destination: Destination::Client,
                message_type: MessageType::PipelineState,
                rpid,
                pid,
                data: to_clixml(&PsValue::Object(PsObject::new().with(
                    "PipelineState",
                    PsValue::I32(crate::pipeline::PipelineState::Completed as i32),
                ))),
            }
            .encode(),
        ));
        let _ = crate::pipeline::Pipeline::new("irrelevant")
            .__with_forced_pid_for_test(pid)
            .run(&mut pool)
            .await;
        // open (2) + CreatePipeline (1) + HostResponse error (1) = 4
        assert_eq!(t.sent().len(), 4);
        let _ = pool.close().await;
    }

    /// Real servers send `mi` as an enum `<Obj>` (captured shape), not as a
    /// bare integer: the call used to fail with "host call: missing mi".
    #[tokio::test]
    async fn host_call_accepts_the_method_id_as_an_enum_object() {
        use async_trait::async_trait;
        struct Alice;
        #[async_trait]
        impl crate::host::PsHost for Alice {
            async fn read_line(&self) -> Result<String> {
                Ok("alice".into())
            }
        }
        let t = MockTransport::new();
        let mut pool = opened_pool_with_host(&t, Arc::new(Alice)).await;
        let body = format!(
            concat!(
                r#"<Obj RefId="0"><MS><I64 N="ci">7</I64>"#,
                r#"<Obj N="mi" RefId="1"><TN RefId="1"><T>System.Management.Automation.Remoting.RemoteHostMethodId</T>"#,
                r#"<T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN>"#,
                r#"<ToString>ReadLine</ToString><I32>{}</I32></Obj>"#,
                r#"<Obj N="mp" RefId="2"><TN RefId="2"><T>System.Collections.ArrayList</T><T>System.Object</T></TN><LST/></Obj>"#,
                r#"</MS></Obj>"#,
            ),
            crate::host::HostMethodId::ReadLine.to_i64()
        );
        let msg = PsrpMessage {
            destination: Destination::Client,
            message_type: MessageType::RunspacePoolHostCall,
            rpid: Uuid::nil(),
            pid: Uuid::nil(),
            data: body,
        };
        pool.handle_host_call(&msg).await.unwrap();
        let mut reassembler = Reassembler::new();
        let response = t
            .sent()
            .iter()
            .flat_map(|fragment| reassembler.feed(fragment).unwrap())
            .map(|payload| PsrpMessage::decode(&payload).unwrap())
            .rfind(|m| m.message_type == MessageType::RunspacePoolHostResponse)
            .expect("a response was sent");
        assert!(response.data.contains("alice"), "{}", response.data);
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn host_call_read_line_with_custom_host_sends_value_response() {
        use async_trait::async_trait;

        struct YesHost;
        #[async_trait]
        impl crate::host::PsHost for YesHost {
            async fn read_line(&self) -> Result<String> {
                Ok("alice".into())
            }
        }

        let t = MockTransport::new();
        let mut pool = opened_pool_with_host(&t, Arc::new(YesHost)).await;
        let rpid = pool.id();
        let pid = Uuid::new_v4();
        t.push_incoming(wire(
            2,
            &host_call_bytes(
                3,
                crate::host::HostMethodId::ReadLine.to_i64(),
                PsValue::List(Vec::new()),
            ),
        ));
        t.push_incoming(wire(
            3,
            &PsrpMessage {
                destination: Destination::Client,
                message_type: MessageType::PipelineState,
                rpid,
                pid,
                data: to_clixml(&PsValue::Object(PsObject::new().with(
                    "PipelineState",
                    PsValue::I32(crate::pipeline::PipelineState::Completed as i32),
                ))),
            }
            .encode(),
        ));
        let _ = crate::pipeline::Pipeline::new("irrelevant")
            .__with_forced_pid_for_test(pid)
            .run(&mut pool)
            .await;
        // open + CreatePipeline + HostResponse success = 4
        assert_eq!(t.sent().len(), 4);
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn encrypt_secure_string_without_key_errors() {
        let t = MockTransport::new();
        t.push_incoming(wire(1, &state_message_bytes(RunspacePoolState::Opened)));
        let pool = RunspacePool::open_with_transport(t).await.unwrap();
        let err = pool.encrypt_secure_string("x").unwrap_err();
        assert!(matches!(err, PsrpError::Protocol(_)));
        let err = pool.decrypt_secure_string("AAAA").unwrap_err();
        assert!(matches!(err, PsrpError::Protocol(_)));
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn secure_string_roundtrip_via_set_session_key() {
        let t = MockTransport::new();
        t.push_incoming(wire(1, &state_message_bytes(RunspacePoolState::Opened)));
        let mut pool = RunspacePool::open_with_transport(t).await.unwrap();
        pool.set_session_key(crate::crypto::SessionKey::from_bytes([7u8; 32]));
        assert!(pool.session_key().is_some());
        let b64 = pool.encrypt_secure_string("héllo 🌍").unwrap();
        let pt = pool.decrypt_secure_string(&b64).unwrap();
        assert_eq!(pt, "héllo 🌍");
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn decrypt_secure_string_rejects_bad_base64() {
        let t = MockTransport::new();
        t.push_incoming(wire(1, &state_message_bytes(RunspacePoolState::Opened)));
        let mut pool = RunspacePool::open_with_transport(t).await.unwrap();
        pool.set_session_key(crate::crypto::SessionKey::from_bytes([0u8; 32]));
        let err = pool.decrypt_secure_string("!!!not base64!!!").unwrap_err();
        assert!(matches!(err, PsrpError::Protocol(_)));
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn disconnect_returns_disconnected_pool() {
        let t = MockTransport::new();
        t.push_incoming(wire(1, &state_message_bytes(RunspacePoolState::Opened)));
        let pool = RunspacePool::open_with_options(t, 2, 5).await.unwrap();
        let disconnected = pool.disconnect().await.unwrap();
        assert_eq!(disconnected.shell_id(), "MOCK-SHELL-ID");
        assert_ne!(disconnected.rpid(), Uuid::nil());
        // Debug impl exercised.
        let s = format!("{disconnected:?}");
        assert!(s.contains("DisconnectedPool"));
        assert!(s.contains("MOCK-SHELL-ID"));
    }

    #[tokio::test]
    async fn disconnect_then_reconnect_roundtrip() {
        // First half: open + disconnect via the mock.
        let t = MockTransport::new();
        t.push_incoming(wire(1, &state_message_bytes(RunspacePoolState::Opened)));
        let pool = RunspacePool::open_with_transport(t).await.unwrap();
        let disconnected = pool.disconnect().await.unwrap();

        // Second half: existing-client reconnect. The WSMan Reconnect the
        // transport performs already resumed the shell, so the pool is Opened
        // with no PSRP handshake and nothing to drain — pushing an Opened
        // state or expecting SessionCapability/ConnectRunspacePool would
        // encode the old bug that timed the server out (`w:TimedOut`).
        let t2 = MockTransport::new();
        let pool = disconnected.reconnect(t2.clone()).await.unwrap();
        assert_eq!(pool.state(), RunspacePoolState::Opened);
        assert!(t2.sent().is_empty(), "reconnect must send no PSRP message");
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn double_disconnect_errors() {
        let t = MockTransport::new();
        t.push_incoming(wire(1, &state_message_bytes(RunspacePoolState::Opened)));
        let pool = RunspacePool::open_with_transport(t).await.unwrap();
        let _disc = pool.disconnect().await.unwrap();
        // The original pool was consumed. Re-disconnect on a freshly
        // closed pool: build a new one and close it first.
        let t2 = MockTransport::new();
        t2.push_incoming(wire(1, &state_message_bytes(RunspacePoolState::Opened)));
        let pool2 = RunspacePool::open_with_transport(t2).await.unwrap();
        pool2.close().await.unwrap();
        // Double-close was already covered; this just keeps the symmetry.
    }

    /// An opened mock pool plus a key pair for the exchange.
    async fn pool_for_key_exchange() -> (
        MockTransport,
        RunspacePool<MockTransport>,
        crate::crypto::ClientSessionKey,
    ) {
        let t = MockTransport::new();
        t.push_incoming(wire(1, &state_message_bytes(RunspacePoolState::Opened)));
        let pool = RunspacePool::open_with_transport(t.clone()).await.unwrap();
        let key = crate::crypto::ClientSessionKey::generate().unwrap();
        (t, pool, key)
    }

    fn encrypted_session_key_reply(property: &str) -> Vec<u8> {
        wire(
            9,
            &PsrpMessage {
                destination: Destination::Client,
                message_type: MessageType::EncryptedSessionKey,
                rpid: Uuid::nil(),
                pid: Uuid::nil(),
                data: to_clixml(&PsValue::Object(
                    PsObject::new().with("EncryptedSessionKey", PsValue::String(property.into())),
                )),
            }
            .encode(),
        )
    }

    /// The `PublicKey` string of the last message the pool sent.
    fn sent_public_key(t: &MockTransport) -> String {
        let sent = t.sent();
        let mut reassembler = Reassembler::new();
        let payload = reassembler
            .feed(sent.last().expect("a message was sent"))
            .unwrap()
            .pop()
            .expect("one complete message");
        let msg = PsrpMessage::decode(&payload).unwrap();
        assert_eq!(msg.message_type, MessageType::PublicKey);
        parse_clixml(&msg.data)
            .unwrap()
            .into_iter()
            .find_map(|v| match v {
                PsValue::Object(o) => o
                    .get("PublicKey")
                    .and_then(PsValue::as_str)
                    .map(str::to_string),
                _ => None,
            })
            .expect("PublicKey property")
    }

    #[tokio::test]
    async fn session_key_exchange_uses_base64_both_ways() {
        // MS-PSRP 2.2.2.3 / 2.2.2.4: the PUBLICKEYBLOB and the encrypted
        // session key are both base64. The "server" here wraps an AES key
        // from the blob it reads back out of the sent message.
        let (t, mut pool, key) = pool_for_key_exchange().await;
        let aes = [0x42u8; 32];
        let blob = key.public_blob();
        let wrapped = crate::crypto::test_support::server_wrap_session_key(&blob, &aes);
        t.push_incoming(encrypted_session_key_reply(
            &crate::clixml::encode::base64_encode(&wrapped),
        ));

        pool.exchange_session_key(key).await.unwrap();

        let public_key = sent_public_key(&t);
        assert_eq!(
            crate::clixml::encode::base64_decode(&public_key).as_deref(),
            Some(blob.as_slice()),
            "PublicKey must be the base64 of the 276-byte PUBLICKEYBLOB: {public_key}"
        );
        assert_eq!(blob.len(), 276);
        // The unwrapped key is the one the server chose.
        let sealed = crate::crypto::SessionKey::from_bytes(aes).encrypt_secure_string("pw");
        assert_eq!(
            pool.session_key()
                .unwrap()
                .decrypt_secure_string(&sealed)
                .unwrap(),
            "pw"
        );
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn session_key_exchange_rejects_a_hex_reply() {
        // The old (wrong) encoding: hex of the SIMPLEBLOB. Its characters
        // happen to be valid base64, so it must fail on length/header, not
        // panic and not yield a key.
        let (t, mut pool, key) = pool_for_key_exchange().await;
        let wrapped =
            crate::crypto::test_support::server_wrap_session_key(&key.public_blob(), &[1; 32]);
        let hex = wrapped.iter().fold(String::new(), |mut acc, b| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{b:02X}");
            acc
        });
        t.push_incoming(encrypted_session_key_reply(&hex));
        let err = pool.exchange_session_key(key).await.unwrap_err();
        assert!(matches!(err, PsrpError::Protocol(_)), "{err:?}");
        assert!(pool.session_key().is_none());
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn session_key_exchange_rejects_invalid_base64_reply() {
        let (t, mut pool, key) = pool_for_key_exchange().await;
        t.push_incoming(encrypted_session_key_reply("not base64 !!!"));
        let err = pool.exchange_session_key(key).await.unwrap_err();
        assert!(err.to_string().contains("base64"), "{err}");
        assert!(pool.session_key().is_none());
        let _ = pool.close().await;
    }

    /// A `RunspacePoolState` message carrying the server's error as its
    /// `ExceptionAsErrorRecord` (MS-PSRP 2.2.2.9).
    fn terminal_state_reply(state: RunspacePoolState, message: &str) -> Vec<u8> {
        let exception = PsObject::new()
            .with("Message", PsValue::String(message.into()))
            .with_type_names(["System.Security.Cryptography.CryptographicException"]);
        let record = PsObject::new()
            .with("Exception", PsValue::Object(exception))
            .with(
                "FullyQualifiedErrorId",
                PsValue::String("ServerKeyExchangeFailed".into()),
            )
            .with_type_names(["System.Management.Automation.ErrorRecord"]);
        let body = to_clixml(&PsValue::Object(
            PsObject::new()
                .with("RunspaceState", PsValue::I32(state as i32))
                .with("ExceptionAsErrorRecord", PsValue::Object(record)),
        ));
        wire(
            9,
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

    /// An unrelated message the exchange must not consume after a terminal
    /// state: it shows the wait ended as soon as the pool died.
    fn trailing_message() -> Vec<u8> {
        wire(
            10,
            &PsrpMessage {
                destination: Destination::Client,
                message_type: MessageType::ApplicationPrivateData,
                rpid: Uuid::nil(),
                pid: Uuid::nil(),
                data: "<Obj RefId=\"0\"><MS/></Obj>".into(),
            }
            .encode(),
        )
    }

    #[tokio::test]
    async fn session_key_exchange_reports_a_broken_pool() {
        // Issue #22: a server that rejects the public key breaks the pool
        // instead of answering with EncryptedSessionKey. The exchange used
        // to drop that message and wait for a key that never came.
        let (t, mut pool, key) = pool_for_key_exchange().await;
        t.push_incoming(terminal_state_reply(
            RunspacePoolState::Broken,
            "Invalid public key data.",
        ));
        t.push_incoming(trailing_message());

        let err = pool.exchange_session_key(key).await.unwrap_err();

        assert!(matches!(err, PsrpError::Protocol(_)), "{err:?}");
        let text = err.to_string();
        assert!(text.contains("Broken"), "{text}");
        assert!(text.contains("Invalid public key data."), "{text}");
        assert_eq!(pool.state(), RunspacePoolState::Broken);
        assert!(pool.session_key().is_none());
        assert_eq!(t.inbox.lock().unwrap().len(), 1, "read past the state");
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn session_key_exchange_reports_a_closed_pool() {
        let (t, mut pool, key) = pool_for_key_exchange().await;
        t.push_incoming(wire(9, &state_message_bytes(RunspacePoolState::Closed)));
        t.push_incoming(trailing_message());

        let err = pool.exchange_session_key(key).await.unwrap_err();

        assert!(matches!(err, PsrpError::Protocol(_)), "{err:?}");
        assert!(err.to_string().contains("Closed"), "{err}");
        assert_eq!(pool.state(), RunspacePoolState::Closed);
        assert!(pool.session_key().is_none());
        assert_eq!(t.inbox.lock().unwrap().len(), 1, "read past the state");
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn session_key_exchange_skips_other_messages_and_answers_host_calls() {
        // While waiting for the key, a non-terminal state message and
        // informational messages are passed over, and a host call is
        // answered, as on every other receive path.
        let (t, mut pool, key) = pool_for_key_exchange().await;
        t.push_incoming(wire(7, &state_message_bytes(RunspacePoolState::Opened)));
        t.push_incoming(trailing_message());
        t.push_incoming(wire(
            8,
            &host_call_bytes(
                7,
                crate::host::HostMethodId::ReadLine.to_i64(),
                PsValue::List(Vec::new()),
            ),
        ));
        let wrapped =
            crate::crypto::test_support::server_wrap_session_key(&key.public_blob(), &[3; 32]);
        t.push_incoming(encrypted_session_key_reply(
            &crate::clixml::encode::base64_encode(&wrapped),
        ));
        let sent_before = t.sent().len();

        pool.exchange_session_key(key).await.unwrap();

        assert!(pool.session_key().is_some());
        assert_eq!(pool.state(), RunspacePoolState::Opened);
        // PublicKey + the host response to ReadLine.
        let sent = t.sent();
        assert_eq!(sent.len(), sent_before + 2);
        let mut reassembler = Reassembler::new();
        let payload = reassembler
            .feed(sent.last().expect("a message was sent"))
            .unwrap()
            .pop()
            .expect("one complete message");
        assert_eq!(
            PsrpMessage::decode(&payload).unwrap().message_type,
            MessageType::RunspacePoolHostResponse
        );
        let _ = pool.close().await;
    }

    #[test]
    fn build_creation_fragments_produces_nonempty_bytes() {
        let (rpid, bytes) = RunspacePool::<MockTransport>::build_creation_fragments(1, 1).unwrap();
        assert!(!rpid.is_nil());
        // Must contain at least the fragment headers for SessionCapability + InitRunspacePool
        assert!(bytes.len() > 42); // 21-byte header × 2 at minimum
    }

    #[test]
    fn build_creation_fragments_rejects_bad_bounds() {
        let err = RunspacePool::<MockTransport>::build_creation_fragments(0, 0);
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn open_from_transport_reaches_opened() {
        let t = MockTransport::new();
        let (rpid, _bytes) = RunspacePool::<MockTransport>::build_creation_fragments(1, 1).unwrap();
        t.push_incoming(wire(100, &state_message_bytes(RunspacePoolState::Opened)));
        let pool = RunspacePool::open_from_transport(t.clone(), rpid, 1, 1)
            .await
            .unwrap();
        assert_eq!(pool.state(), RunspacePoolState::Opened);
        pool.close().await.unwrap();
    }

    #[tokio::test]
    async fn close_already_closed_is_noop() {
        let t = MockTransport::new();
        t.push_incoming(wire(100, &state_message_bytes(RunspacePoolState::Opened)));
        let mut pool = RunspacePool::open_with_transport(t.clone()).await.unwrap();
        // Mark as closed internally by calling close once
        pool.closed = true;
        pool.close().await.unwrap(); // should early-return Ok(())
    }

    #[tokio::test]
    async fn disconnect_already_closed_errors() {
        let t = MockTransport::new();
        t.push_incoming(wire(100, &state_message_bytes(RunspacePoolState::Opened)));
        let mut pool = RunspacePool::open_with_transport(t.clone()).await.unwrap();
        pool.closed = true;
        let err = pool.disconnect().await.unwrap_err();
        assert!(err.to_string().contains("already closed"));
    }

    /// Every PSRP message the pool has sent, decoded.
    fn sent_messages(t: &MockTransport) -> Vec<PsrpMessage> {
        let mut reassembler = Reassembler::new();
        t.sent()
            .iter()
            .flat_map(|fragment| reassembler.feed(fragment).unwrap())
            .map(|payload| PsrpMessage::decode(&payload).unwrap())
            .collect()
    }

    /// The `mr` of the last host response sent, as the SecureString body.
    fn sent_host_response_secret(t: &MockTransport) -> String {
        let msg = sent_messages(t)
            .into_iter()
            .rfind(|m| m.message_type == MessageType::RunspacePoolHostResponse)
            .expect("a host response was sent");
        let PsValue::Object(o) = parse_clixml(&msg.data).unwrap().remove(0) else {
            panic!("host response is not an object");
        };
        match o.get("mr") {
            Some(PsValue::SecureString(body)) => body.clone(),
            other => panic!("mr is not a SecureString: {other:?}"),
        }
    }

    struct SecretHost;
    #[async_trait::async_trait]
    impl crate::host::PsHost for SecretHost {
        async fn read_line_as_secure_string(&self) -> Result<String> {
            Ok("hunter2".into())
        }
    }

    fn secure_host_call() -> PsrpMessage {
        PsrpMessage::decode(&host_call_bytes(
            5,
            crate::host::HostMethodId::ReadLineAsSecureString.to_i64(),
            PsValue::List(Vec::new()),
        ))
        .unwrap()
    }

    /// #36: a `Read-Host -AsSecureString` answer went out as the plaintext
    /// the host returned, which PowerShell cannot decrypt.
    #[tokio::test]
    async fn host_secure_string_answer_is_encrypted_with_the_session_key() {
        let t = MockTransport::new();
        let mut pool = opened_pool_with_host(&t, Arc::new(SecretHost)).await;
        let key = crate::crypto::SessionKey::from_bytes([3u8; 32]);
        pool.set_session_key(key.clone());

        pool.handle_host_call(&secure_host_call()).await.unwrap();

        let body = sent_host_response_secret(&t);
        assert_ne!(body, "hunter2");
        let sealed = crate::clixml::encode::base64_decode(&body).expect("base64");
        assert_eq!(key.decrypt_secure_string(&sealed).unwrap(), "hunter2");
        assert!(
            !t.sent()
                .iter()
                .flatten()
                .copied()
                .collect::<Vec<u8>>()
                .windows(7)
                .any(|w| w == b"hunter2"),
            "the plaintext crossed the transport"
        );
        let _ = pool.close().await;
    }

    /// With no key yet the answer is parked, the exchange is started, and
    /// the answer goes out encrypted once the key arrives, without any
    /// reader having to ask for the key.
    #[tokio::test]
    async fn host_secure_string_answer_waits_for_the_session_key() {
        let t = MockTransport::new();
        let mut pool = opened_pool_with_host(&t, Arc::new(SecretHost)).await;

        pool.handle_host_call(&secure_host_call()).await.unwrap();
        let sent = sent_messages(&t);
        assert_eq!(sent.last().unwrap().message_type, MessageType::PublicKey);
        assert!(
            !sent
                .iter()
                .any(|m| m.message_type == MessageType::RunspacePoolHostResponse),
            "a response left before the key"
        );

        // A second answer meanwhile does not start a second exchange.
        pool.handle_host_call(&secure_host_call()).await.unwrap();
        let public_keys = sent_messages(&t)
            .iter()
            .filter(|m| m.message_type == MessageType::PublicKey)
            .count();
        assert_eq!(public_keys, 1);

        let aes = [0x24u8; 32];
        let blob = crate::clixml::encode::base64_decode(&sent_public_key(&t)).unwrap();
        let wrapped = crate::crypto::test_support::server_wrap_session_key(&blob, &aes);
        t.push_incoming(encrypted_session_key_reply(
            &crate::clixml::encode::base64_encode(&wrapped),
        ));
        let msg = pool.next_message().await.unwrap();
        assert_eq!(msg.message_type, MessageType::EncryptedSessionKey);

        assert!(pool.session_key().is_some());
        let responses: Vec<_> = sent_messages(&t)
            .into_iter()
            .filter(|m| m.message_type == MessageType::RunspacePoolHostResponse)
            .collect();
        assert_eq!(responses.len(), 2, "both parked answers are sent");
        let sealed = crate::clixml::encode::base64_decode(&sent_host_response_secret(&t)).unwrap();
        assert_eq!(
            crate::crypto::SessionKey::from_bytes(aes)
                .decrypt_secure_string(&sealed)
                .unwrap(),
            "hunter2"
        );
        assert!(
            !t.sent()
                .iter()
                .flatten()
                .copied()
                .collect::<Vec<u8>>()
                .windows(7)
                .any(|w| w == b"hunter2"),
            "the plaintext crossed the transport"
        );
        let _ = pool.close().await;
    }

    /// A reply that cannot be taken must not leave the server's host call
    /// waiting for ever: it is answered with an error, never with the
    /// plaintext, and the pool can try again.
    #[tokio::test]
    async fn a_failed_key_exchange_answers_the_parked_host_calls_with_an_error() {
        let t = MockTransport::new();
        let mut pool = opened_pool_with_host(&t, Arc::new(SecretHost)).await;
        pool.handle_host_call(&secure_host_call()).await.unwrap();

        t.push_incoming(encrypted_session_key_reply("not base64 !!!"));
        let err = pool.next_message().await.unwrap_err();
        assert!(err.to_string().contains("invalid base64"), "{err}");
        assert!(pool.session_key().is_none());

        let response = sent_messages(&t)
            .into_iter()
            .rfind(|m| m.message_type == MessageType::RunspacePoolHostResponse)
            .expect("the host call was answered");
        assert!(response.data.contains("the SecureString could not be sent"));
        assert!(!response.data.contains("hunter2"));
        assert!(
            !t.sent()
                .iter()
                .flatten()
                .copied()
                .collect::<Vec<u8>>()
                .windows(7)
                .any(|w| w == b"hunter2")
        );

        // A later host call starts a fresh exchange (the first key pair died).
        pool.handle_host_call(&secure_host_call()).await.unwrap();
        let public_keys = sent_messages(&t)
            .iter()
            .filter(|m| m.message_type == MessageType::PublicKey)
            .count();
        assert_eq!(public_keys, 2);
        let _ = pool.close().await;
    }

    /// `PublicKeyRequest` while an exchange is in flight repeats nothing; with
    /// a key already held it still answers (the server lost its copy).
    #[tokio::test]
    async fn public_key_request_while_pending_or_with_a_key() {
        let public_keys = |t: &MockTransport| {
            sent_messages(t)
                .iter()
                .filter(|m| m.message_type == MessageType::PublicKey)
                .count()
        };
        let request = || {
            wire(
                4,
                &PsrpMessage {
                    destination: Destination::Client,
                    message_type: MessageType::PublicKeyRequest,
                    rpid: Uuid::nil(),
                    pid: Uuid::nil(),
                    data: to_clixml(&PsValue::Object(PsObject::new())),
                }
                .encode(),
            )
        };

        let t = MockTransport::new();
        let mut pool = opened_pool_with_host(&t, Arc::new(SecretHost)).await;
        t.push_incoming(request());
        pool.next_message().await.unwrap();
        t.push_incoming(request());
        pool.next_message().await.unwrap();
        assert_eq!(public_keys(&t), 1, "a pending exchange is not repeated");
        let _ = pool.close().await;

        let t = MockTransport::new();
        let mut pool = opened_pool_with_host(&t, Arc::new(SecretHost)).await;
        pool.set_session_key(crate::crypto::SessionKey::from_bytes([1u8; 32]));
        t.push_incoming(request());
        pool.next_message().await.unwrap();
        assert_eq!(public_keys(&t), 1, "a held key does not mute the request");
        let _ = pool.close().await;
    }

    /// A key injected while answers are parked abandons the exchange and
    /// releases them, encrypted with the injected key, at the next read.
    #[tokio::test]
    async fn set_session_key_releases_the_parked_host_answers() {
        let t = MockTransport::new();
        let mut pool = opened_pool_with_host(&t, Arc::new(SecretHost)).await;
        pool.handle_host_call(&secure_host_call()).await.unwrap();

        let key = crate::crypto::SessionKey::from_bytes([8u8; 32]);
        pool.set_session_key(key.clone());
        // The reply of the abandoned exchange arrives: ignored, and the
        // parked answer is released before it is read, under the injected key.
        t.push_incoming(encrypted_session_key_reply("AAAA"));
        let msg = pool.next_message().await.unwrap();
        assert_eq!(msg.message_type, MessageType::EncryptedSessionKey);

        let sealed = crate::clixml::encode::base64_decode(&sent_host_response_secret(&t)).unwrap();
        assert_eq!(key.decrypt_secure_string(&sealed).unwrap(), "hunter2");
        let probe = pool.encrypt_secure_string("probe").unwrap();
        let sealed = crate::clixml::encode::base64_decode(&probe).unwrap();
        assert_eq!(key.decrypt_secure_string(&sealed).unwrap(), "probe");
        let _ = pool.close().await;
    }

    /// The server asks for the client's key when it has a
    /// `SecureString` to send; it used to be ignored.
    #[tokio::test]
    async fn public_key_request_starts_the_exchange() {
        let t = MockTransport::new();
        let mut pool = opened_pool_with_host(&t, Arc::new(SecretHost)).await;
        t.push_incoming(wire(
            4,
            &PsrpMessage {
                destination: Destination::Client,
                message_type: MessageType::PublicKeyRequest,
                rpid: Uuid::nil(),
                pid: Uuid::nil(),
                data: to_clixml(&PsValue::Object(PsObject::new())),
            }
            .encode(),
        ));
        let msg = pool.next_message().await.unwrap();
        assert_eq!(msg.message_type, MessageType::PublicKeyRequest);
        assert_eq!(
            sent_messages(&t).last().unwrap().message_type,
            MessageType::PublicKey
        );

        // The reply completes the exchange.
        let aes = [0x31u8; 32];
        let blob = crate::clixml::encode::base64_decode(&sent_public_key(&t)).unwrap();
        let wrapped = crate::crypto::test_support::server_wrap_session_key(&blob, &aes);
        t.push_incoming(encrypted_session_key_reply(
            &crate::clixml::encode::base64_encode(&wrapped),
        ));
        pool.request_session_key().await.unwrap();
        assert!(pool.session_key().is_some());
        // ... without a second PublicKey.
        let public_keys = sent_messages(&t)
            .iter()
            .filter(|m| m.message_type == MessageType::PublicKey)
            .count();
        assert_eq!(public_keys, 1);
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn an_unsolicited_session_key_is_ignored() {
        let t = MockTransport::new();
        let mut pool = opened_pool_with_host(&t, Arc::new(SecretHost)).await;
        t.push_incoming(encrypted_session_key_reply("AAAA"));
        let msg = pool.next_message().await.unwrap();
        assert_eq!(msg.message_type, MessageType::EncryptedSessionKey);
        assert!(pool.session_key().is_none());
        let _ = pool.close().await;
    }

    #[test]
    fn secure_strings_are_found_and_encrypted_wherever_they_sit() {
        let key = crate::crypto::SessionKey::from_bytes([5u8; 32]);
        let credential = PsValue::Object(
            PsObject::new()
                .with("UserName", PsValue::String("alice".into()))
                .with("Password", PsValue::SecureString("pw".into())),
        );
        let value = PsValue::List(vec![
            PsValue::I32(1),
            PsValue::Dict(vec![(PsValue::String("k".into()), credential)]),
        ]);
        assert!(contains_secure_string(&value));
        // A SecureString used as a dictionary key is found and encrypted too.
        let keyed = PsValue::Dict(vec![(PsValue::SecureString("k".into()), PsValue::I32(1))]);
        assert!(contains_secure_string(&keyed));
        let PsValue::Dict(entries) = encrypt_secure_strings(&keyed, &key) else {
            panic!()
        };
        assert_ne!(entries[0].0, PsValue::SecureString("k".into()));
        assert!(!contains_secure_string(&PsValue::List(vec![
            PsValue::String("pw".into())
        ])));

        let encrypted = encrypt_secure_strings(&value, &key);
        assert_ne!(encrypted, value);
        let PsValue::List(items) = &encrypted else {
            panic!()
        };
        let PsValue::Dict(entries) = &items[1] else {
            panic!()
        };
        let PsValue::Object(cred) = &entries[0].1 else {
            panic!()
        };
        assert_eq!(cred.get("UserName"), Some(&PsValue::String("alice".into())));
        let Some(PsValue::SecureString(body)) = cred.get("Password") else {
            panic!()
        };
        let sealed = crate::clixml::encode::base64_decode(body).unwrap();
        assert_eq!(key.decrypt_secure_string(&sealed).unwrap(), "pw");
    }

    #[tokio::test]
    async fn build_host_response_body_shapes() {
        let body = build_host_response_body(3, 11, &PsValue::I32(0));
        assert!(body.contains("<I64 N=\"ci\">3</I64>"));
        assert!(body.contains("<I64 N=\"mi\">11</I64>"));
        assert!(body.contains("N=\"mr\""));

        let err = build_host_response_error_body(3, 51, "boom");
        assert!(err.contains("<I64 N=\"ci\">3</I64>"));
        assert!(err.contains("<I64 N=\"mi\">51</I64>"));
        assert!(err.contains("boom"));
    }

    #[tokio::test]
    async fn request_session_key_is_idempotent_when_key_already_set() {
        // Once a session key is in place, request_session_key must
        // short-circuit: no PublicKey message is sent, and the function
        // does not block waiting for an EncryptedSessionKey reply (which
        // would deadlock the test against an empty mock inbox).
        let t = MockTransport::new();
        t.push_incoming(wire(1, &state_message_bytes(RunspacePoolState::Opened)));
        let mut pool = RunspacePool::open_with_transport(t.clone()).await.unwrap();
        pool.set_session_key(crate::crypto::SessionKey::from_bytes([9u8; 32]));
        let sent_before = t.sent().len();
        // Must return Ok promptly. If the early-return check were
        // missing, this would hang trying to recv from the empty inbox
        // (or, more precisely, return a synthetic completion message
        // and loop). The test would then time out.
        pool.request_session_key().await.unwrap();
        // No new outgoing PublicKey fragment.
        assert_eq!(t.sent().len(), sent_before);
        let _ = pool.close().await;
    }

    // ---------- pid routing at the transport boundary ----------

    #[tokio::test]
    async fn pipeline_input_carries_its_pid_to_the_transport() {
        let t = MockTransport::new();
        let mut pool = opened_pool_with_host(&t, Arc::new(NoInteractionHost)).await;
        let pid = Uuid::new_v4();
        let mut handle = crate::pipeline::Pipeline::new("$input")
            .with_input(true)
            .__with_forced_pid_for_test(pid)
            .start(&mut pool)
            .await
            .unwrap();
        handle.write_input(PsValue::I32(1)).await.unwrap();
        handle.end_input().await.unwrap();
        // CreatePipeline goes through `execute_pipeline`, not recorded here.
        assert_eq!(t.pipeline_sends(), vec![pid, pid]);
    }

    #[tokio::test]
    async fn host_response_is_routed_with_the_call_pid() {
        let t = MockTransport::new();
        let mut pool = opened_pool_with_host(&t, Arc::new(crate::host::NoInteractionHost)).await;
        let rpid = pool.id();
        let pid = Uuid::new_v4();
        t.push_incoming(wire(
            2,
            &host_call_bytes_with(
                7,
                crate::host::HostMethodId::ReadLine.to_i64(),
                PsValue::List(vec![]),
                rpid,
                pid,
            ),
        ));
        t.push_incoming(wire(
            3,
            &PsrpMessage {
                destination: Destination::Client,
                message_type: MessageType::PipelineState,
                rpid,
                pid,
                data: to_clixml(&PsValue::Object(PsObject::new().with(
                    "PipelineState",
                    PsValue::I32(crate::pipeline::PipelineState::Completed as i32),
                ))),
            }
            .encode(),
        ));
        let _ = crate::pipeline::Pipeline::new("irrelevant")
            .__with_forced_pid_for_test(pid)
            .run(&mut pool)
            .await;
        // open (2) + CreatePipeline (1) + HostResponse (1).
        assert_eq!(t.pipeline_sends(), vec![pid]);
        assert_eq!(t.sent().len(), 4);
    }

    #[tokio::test]
    async fn command_metadata_is_routed_with_its_pid() {
        let t = MockTransport::new();
        let mut pool = opened_pool_with_host(&t, Arc::new(NoInteractionHost)).await;
        // The empty inbox makes the wait for the reply fail, as expected.
        let _ = pool
            .get_command_metadata(&["Get-Date"], crate::metadata::CommandType::CMDLET)
            .await;
        assert_eq!(t.pipeline_sends().len(), 1);
        assert!(!t.pipeline_sends()[0].is_nil());
    }
}
