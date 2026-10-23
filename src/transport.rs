//! Thin wrapper around [`winrm_rs::Shell`] that ferries PSRP fragments.
//!
//! This module is the **only** place in the crate that imports
//! `winrm_rs::Shell`. Every higher-level component (runspace pool,
//! pipeline) talks to the transport through the [`PsrpTransport`] trait so
//! it can be mocked in tests without standing up a fake SOAP server.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use tracing::{debug, warn};
use winrm_rs::{RESOURCE_URI_PSRP, ReceiveOutput, Shell, SoapError, WinrmClient, WinrmError};

use crate::error::{PsrpError, Result};

/// Abstract transport used by the runspace pool and pipeline.
///
/// `send_fragment` sends the messages addressed to the pool and
/// `send_pipeline_fragment` those addressed to a pipeline, as pre-encoded
/// fragment bytes. How they travel is up to each transport:
/// [`WinrmPsrpTransport`] writes them in a single `send_input` call; the
/// SSH transport (`ssh` feature) writes them in `<Data>` lines of at most
/// 32 KiB, each acknowledged before the next. `recv_chunk` MUST
/// transparently retry on `WinrmError::Timeout` (long-polling is expected)
/// but propagate every other error — in particular SOAP faults, which
/// usually mean the server-side shell has died and the pool must be
/// recreated.
///
/// A transport that wraps or forwards to another one MUST forward
/// `send_pipeline_fragment` too, not only `send_fragment`. Its default
/// body calls `send_fragment`, which addresses the pool: around the SSH
/// transport, such a wrapper would send every pipeline message on
/// `Guid.Empty` instead of the pipeline's id, with no compile error and
/// no warning.
#[async_trait]
pub trait PsrpTransport: Send {
    async fn send_fragment(&self, bytes: &[u8]) -> Result<()>;

    /// Send the fragments of a message addressed to pipeline `pipeline_id`
    /// (`Uuid::nil()` addresses the pool). Transports that multiplex by
    /// pipeline (PowerShell's out-of-process protocol) override it; the
    /// default forwards to `send_fragment`, which keeps WinRM unchanged.
    ///
    /// Takes `&mut self`, like [`PsrpTransport::execute_pipeline`]: with
    /// `&self`, `#[async_trait]` would require `Self: Sync` on a default
    /// body, which this trait does not promise.
    async fn send_pipeline_fragment(
        &mut self,
        bytes: &[u8],
        pipeline_id: uuid::Uuid,
    ) -> Result<()> {
        let _ = pipeline_id;
        self.send_fragment(bytes).await
    }

    async fn recv_chunk(&mut self) -> Result<Vec<u8>>;
    async fn signal_stop(&self) -> Result<()>;
    async fn close_shell(&mut self) -> Result<()>;

    /// Start a pipeline by executing a WS-Man Command with the first
    /// PSRP fragment as an argument and the pipeline's UUID as the
    /// CommandId. Subsequent Send/Receive use this CommandId.
    /// Default: sends via `send_fragment` (mock transport behavior).
    async fn execute_pipeline(
        &mut self,
        fragment_bytes: &[u8],
        _pipeline_id: uuid::Uuid,
    ) -> Result<()> {
        self.send_fragment(fragment_bytes).await
    }

    /// Disconnect the underlying transport while leaving the server-side
    /// resources alive. Returns an opaque handle that the caller can pass
    /// back to the transport-specific reconnect path. For
    /// [`WinrmPsrpTransport`] this is the WinRM `shell_id`.
    ///
    /// Default implementation returns an error so that transports that
    /// don't support disconnect (e.g. mocks) don't have to implement it.
    async fn disconnect_shell(&mut self) -> Result<String> {
        Err(PsrpError::protocol(
            "this transport does not implement disconnect_shell",
        ))
    }
}

/// One future that survives its caller giving up.
///
/// A WS-Man Receive is a long poll: the server holds the request until it has
/// output, and the response, once the server has produced it, is lost if the
/// client drops the request (hyper closes the connection). `recv_chunk` is
/// dropped by `select!` when a pipeline is cancelled, so the Receive it was
/// polling is kept here instead and resumed by the next call.
struct Parked<'c, T> {
    /// In a `Mutex` only to make the transport `Sync` (the trait's `&self`
    /// methods need it, a boxed future is not): it is only ever reached
    /// through `&mut self`, with `get_mut`.
    in_flight: std::sync::Mutex<Option<Pin<Box<dyn Future<Output = T> + Send + 'c>>>>,
}

impl<'c, T> Parked<'c, T> {
    const fn new() -> Self {
        Self {
            in_flight: std::sync::Mutex::new(None),
        }
    }

    fn slot(&mut self) -> &mut Option<Pin<Box<dyn Future<Output = T> + Send + 'c>>> {
        self.in_flight
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Drive the parked future, starting `start()` first if there is none.
    ///
    /// Cancel-safe: dropping this call leaves the future parked, and the next
    /// call polls the same one. It is forgotten only once it has completed.
    async fn drive<F>(&mut self, start: impl FnOnce() -> F) -> T
    where
        F: Future<Output = T> + Send + 'c,
    {
        let in_flight = self.slot().get_or_insert_with(|| Box::pin(start()));
        let output = in_flight.as_mut().await;
        *self.slot() = None;
        output
    }

    /// Give up the parked future (its response, if any, is lost).
    fn discard(&mut self) {
        *self.slot() = None;
    }
}

/// Transport backed by a live `winrm_rs::Shell`.
pub struct WinrmPsrpTransport<'c> {
    shell: Option<Arc<Shell<'c>>>,
    /// The Receive in flight for `command_id`, if a `recv_chunk` was dropped.
    receive: Parked<'c, std::result::Result<ReceiveOutput, WinrmError>>,
    command_id: String,
    /// A stop signal was accepted for `command_id`. The server then deletes
    /// the command, and answers the Receive in flight with `InvalidSelectors`
    /// instead of a final `PipelineState`: that fault means "stopped".
    stop_signalled: std::sync::atomic::AtomicBool,
    done: bool,
    /// True after a pipeline command has been started via Execute.
    /// Before this, Receive/Send use the PSRP-no-commandid path.
    has_command: bool,
}

impl std::fmt::Debug for WinrmPsrpTransport<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WinrmPsrpTransport")
            .field("command_id", &self.command_id)
            .field("has_shell", &self.shell.is_some())
            .field("done", &self.done)
            .finish()
    }
}

impl<'c> WinrmPsrpTransport<'c> {
    /// Open a PSRP shell embedding the opening fragments in `<creationXml>`.
    ///
    /// `creation_fragments` are the raw bytes of the
    /// `SessionCapability + InitRunspacePool` PSRP messages, already
    /// fragment-encoded. They get base64-wrapped and embedded in the
    /// WS-Man Create Shell body.
    pub async fn open(
        client: &'c WinrmClient,
        host: &str,
        creation_fragments: &[u8],
    ) -> Result<Self> {
        let creation_b64 = crate::clixml::encode::base64_encode(creation_fragments);
        let shell = client
            .open_psrp_shell(host, &creation_b64, RESOURCE_URI_PSRP)
            .await?;
        // PSRP shells do NOT use Execute Command — the shell IS the PS
        // process. Receive/Send operate directly on the shell, using
        // the shell_id as the "command_id" in the WS-Man envelope.
        let command_id = shell.shell_id().to_string();
        debug!(command_id, "PSRP transport started (no command yet)");
        Ok(Self {
            shell: Some(Arc::new(shell)),
            receive: Parked::new(),
            stop_signalled: std::sync::atomic::AtomicBool::new(false),
            command_id,
            done: false,
            has_command: false,
        })
    }

    /// Reconnect to a previously-disconnected PSRP shell.
    pub async fn reconnect(client: &'c WinrmClient, host: &str, shell_id: &str) -> Result<Self> {
        let shell = client
            .reconnect_shell(host, shell_id, RESOURCE_URI_PSRP)
            .await?;
        let command_id = shell.shell_id().to_string();
        debug!(command_id, "PSRP transport reconnected");
        Ok(Self {
            shell: Some(Arc::new(shell)),
            receive: Parked::new(),
            stop_signalled: std::sync::atomic::AtomicBool::new(false),
            command_id,
            done: false,
            has_command: false,
        })
    }

    /// Execute an empty command inside the PSRP shell to obtain a
    /// `command_id` for Send/Receive. Called by the pool after the
    /// opening handshake completes. After this, `send_fragment` and
    /// `recv_chunk` include `CommandId` in their SOAP envelopes.
    pub async fn start_pipeline_command(&mut self) -> Result<()> {
        let shell = self.shell()?;
        let cmd_id = shell.start_command("", &[]).await?;
        debug!(cmd_id, "PSRP pipeline command started");
        self.receive.discard();
        self.stop_signalled
            .store(false, std::sync::atomic::Ordering::SeqCst);
        self.command_id = cmd_id;
        self.has_command = true;
        Ok(())
    }

    fn shell(&self) -> Result<&Shell<'c>> {
        self.shell
            .as_deref()
            .ok_or_else(|| PsrpError::protocol("transport closed"))
    }

    /// Take the shell out to consume it (`close`, `disconnect`). A Receive
    /// still parked holds a second handle on it: it is dropped first.
    fn take_shell(&mut self) -> Result<Option<Shell<'c>>> {
        self.receive.discard();
        let Some(shell) = self.shell.take() else {
            return Ok(None);
        };
        Arc::try_unwrap(shell)
            .map(Some)
            .map_err(|_| PsrpError::protocol("transport busy: the shell is still shared"))
    }
}

#[async_trait]
impl PsrpTransport for WinrmPsrpTransport<'_> {
    async fn send_fragment(&self, bytes: &[u8]) -> Result<()> {
        self.shell()?
            .send_input(&self.command_id, bytes, false)
            .await?;
        Ok(())
    }

    async fn recv_chunk(&mut self) -> Result<Vec<u8>> {
        loop {
            let polled = {
                let shell = self
                    .shell
                    .as_ref()
                    .ok_or_else(|| PsrpError::protocol("transport closed"))?;
                let (shell, command_id) = (Arc::clone(shell), self.command_id.clone());
                // Cancel-safe: a dropped call leaves this Receive parked for
                // the next one (see `Parked`).
                self.receive
                    .drive(move || async move { shell.receive_next(&command_id).await })
                    .await
            };
            match polled {
                Ok(out) => {
                    if out.done {
                        self.done = true;
                    }
                    if out.stdout.is_empty() && !self.done {
                        continue;
                    }
                    return Ok(out.stdout);
                }
                Err(WinrmError::Timeout(_)) => continue,
                Err(WinrmError::Soap(SoapError::Fault {
                    ref code,
                    ref reason,
                })) if code.contains("TimedOut") => {
                    // PSRP long-polling: the WinRM server returns a SOAP
                    // fault with code `w:TimedOut` when there's nothing to
                    // read yet. This is the normal long-poll cycle and MUST
                    // be retried (briefing §5 P7). Only fatal SOAP faults
                    // (e.g. shell died, access denied) should propagate.
                    debug!(%code, %reason, "PSRP recv_chunk: w:TimedOut — retrying");
                    continue;
                }
                Err(WinrmError::Soap(SoapError::Fault { ref code, .. }))
                    if code.contains("InvalidSelectors")
                        && self
                            .stop_signalled
                            .load(std::sync::atomic::Ordering::SeqCst) =>
                {
                    // The stop was accepted and the server deleted the
                    // command: it will say nothing more about it.
                    debug!(%code, "PSRP recv_chunk: command gone after the stop signal");
                    return Err(PsrpError::Stopped);
                }
                Err(WinrmError::Soap(SoapError::Fault { code, reason })) => {
                    warn!(%code, %reason, "PSRP transport SOAP fault — shell likely dead");
                    return Err(PsrpError::Winrm(WinrmError::Soap(SoapError::Fault {
                        code,
                        reason,
                    })));
                }
                Err(e) => return Err(PsrpError::Winrm(e)),
            }
        }
    }

    async fn execute_pipeline(
        &mut self,
        fragment_bytes: &[u8],
        pipeline_id: uuid::Uuid,
    ) -> Result<()> {
        let shell = self.shell()?;
        let b64 = crate::clixml::encode::base64_encode(fragment_bytes);
        // pypsrp sends: command("", arguments=[b64_first_frag], command_id=pipeline_id)
        // The WS-Man Execute carries the first fragment as the sole argument
        // and uses the pipeline UUID as the CommandId.
        let cmd_id = shell
            .start_command_with_id("", &[&b64], &pipeline_id.hyphenated().to_string())
            .await?;
        debug!(cmd_id, "PSRP pipeline Execute started");
        // A Receive still parked belongs to the previous command.
        self.receive.discard();
        self.stop_signalled
            .store(false, std::sync::atomic::Ordering::SeqCst);
        self.command_id = cmd_id;
        self.has_command = true;
        Ok(())
    }

    async fn signal_stop(&self) -> Result<()> {
        self.shell()?.signal_ctrl_c(&self.command_id).await?;
        self.stop_signalled
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    async fn close_shell(&mut self) -> Result<()> {
        if let Some(shell) = self.take_shell()? {
            shell.close().await?;
        }
        Ok(())
    }

    async fn disconnect_shell(&mut self) -> Result<String> {
        let shell = self
            .take_shell()?
            .ok_or_else(|| PsrpError::protocol("transport closed"))?;
        let id = shell.disconnect().await?;
        Ok(id)
    }
}

impl Drop for WinrmPsrpTransport<'_> {
    fn drop(&mut self) {
        if self.shell.is_some() {
            warn!("WinrmPsrpTransport dropped without close — shell leaked server-side");
        }
    }
}

#[cfg(any(test, feature = "__internal"))]
#[doc(hidden)]
pub mod mock {
    use super::{PsrpError, PsrpTransport, Result, async_trait};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use uuid::Uuid;

    /// In-memory transport used by the test suite.
    #[derive(Clone, Default, Debug)]
    pub struct MockTransport {
        pub inbox: Arc<Mutex<VecDeque<Vec<u8>>>>, // bytes to hand out of recv_chunk
        pub outbox: Arc<Mutex<Vec<Vec<u8>>>>,     // bytes captured from send_fragment
        pub stopped: Arc<Mutex<bool>>,
        pub closed: Arc<Mutex<bool>>,
        pub fail_send: Arc<Mutex<bool>>,
        pub fail_recv: Arc<Mutex<Option<PsrpError>>>,
        /// Pipeline ids passed to `send_pipeline_fragment`, in call order.
        pub pipeline_sends: Arc<Mutex<Vec<Uuid>>>,
    }

    impl MockTransport {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn push_incoming(&self, bytes: Vec<u8>) {
            self.inbox.lock().unwrap().push_back(bytes);
        }

        pub fn sent(&self) -> Vec<Vec<u8>> {
            self.outbox.lock().unwrap().clone()
        }

        pub fn pipeline_sends(&self) -> Vec<Uuid> {
            self.pipeline_sends.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl PsrpTransport for MockTransport {
        async fn send_fragment(&self, bytes: &[u8]) -> Result<()> {
            if *self.fail_send.lock().unwrap() {
                return Err(PsrpError::protocol("mock send failure"));
            }
            self.outbox.lock().unwrap().push(bytes.to_vec());
            Ok(())
        }

        async fn send_pipeline_fragment(&mut self, bytes: &[u8], pipeline_id: Uuid) -> Result<()> {
            self.send_fragment(bytes).await?;
            self.pipeline_sends.lock().unwrap().push(pipeline_id);
            Ok(())
        }

        async fn recv_chunk(&mut self) -> Result<Vec<u8>> {
            if let Some(e) = self.fail_recv.lock().unwrap().take() {
                return Err(e);
            }
            let mut inbox = self.inbox.lock().unwrap();
            if let Some(bytes) = inbox.pop_front() {
                Ok(bytes)
            } else {
                Err(PsrpError::protocol("mock inbox empty"))
            }
        }

        async fn signal_stop(&self) -> Result<()> {
            *self.stopped.lock().unwrap() = true;
            Ok(())
        }

        async fn close_shell(&mut self) -> Result<()> {
            *self.closed.lock().unwrap() = true;
            Ok(())
        }

        async fn disconnect_shell(&mut self) -> Result<String> {
            *self.closed.lock().unwrap() = true;
            Ok("MOCK-SHELL-ID".into())
        }
    }

    #[tokio::test]
    async fn mock_roundtrip() {
        let mut t = MockTransport::new();
        t.send_fragment(b"hello").await.unwrap();
        assert_eq!(t.sent(), vec![b"hello".to_vec()]);

        t.push_incoming(b"world".to_vec());
        let got = t.recv_chunk().await.unwrap();
        assert_eq!(got, b"world");

        t.signal_stop().await.unwrap();
        t.close_shell().await.unwrap();
        assert!(*t.stopped.lock().unwrap());
        assert!(*t.closed.lock().unwrap());
    }

    #[tokio::test]
    async fn mock_recv_failure() {
        let mut t = MockTransport::new();
        *t.fail_recv.lock().unwrap() = Some(PsrpError::protocol("boom"));
        assert!(t.recv_chunk().await.is_err());
    }

    #[tokio::test]
    async fn mock_send_failure() {
        let t = MockTransport::new();
        *t.fail_send.lock().unwrap() = true;
        assert!(t.send_fragment(b"x").await.is_err());
    }
}

#[cfg(test)]
mod parked_tests {
    use super::Parked;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;

    /// Sets a flag when it is dropped, to tell a parked future that was kept
    /// from one that was dropped.
    struct DropFlag(Arc<AtomicUsize>);
    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// The point of `Parked` (#27): a call dropped while its Receive is in
    /// flight, as `select!` does when a pipeline is cancelled, must not drop
    /// the Receive. The next call resumes it, and the response is not lost.
    #[tokio::test]
    async fn a_dropped_call_leaves_the_future_parked_and_the_next_resumes_it() {
        let started = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Notify::new());
        let mut parked: Parked<'_, &'static str> = Parked::new();

        let start = || {
            started.fetch_add(1, Ordering::SeqCst);
            let (gate, flag) = (Arc::clone(&gate), DropFlag(Arc::clone(&dropped)));
            async move {
                let _flag = flag;
                gate.notified().await;
                "response"
            }
        };

        // The caller gives up while the Receive is still waiting.
        tokio::select! {
            _ = parked.drive(start) => panic!("nothing was ready"),
            () = tokio::task::yield_now() => {}
        }
        assert_eq!(started.load(Ordering::SeqCst), 1);
        assert_eq!(dropped.load(Ordering::SeqCst), 0, "the Receive was dropped");

        // The server answers meanwhile; the next call gets that answer and
        // does not start a second Receive.
        gate.notify_one();
        assert_eq!(parked.drive(start).await, "response");
        assert_eq!(
            started.load(Ordering::SeqCst),
            1,
            "a second Receive was sent"
        );
        assert_eq!(
            dropped.load(Ordering::SeqCst),
            1,
            "a finished future is released"
        );
    }

    /// Once a future has completed, the next call starts a new one.
    #[tokio::test]
    async fn a_completed_future_is_not_replayed() {
        let started = Arc::new(AtomicUsize::new(0));
        let mut parked: Parked<'_, usize> = Parked::new();
        for expected in 1..=3 {
            let n = parked
                .drive(|| {
                    let n = started.fetch_add(1, Ordering::SeqCst) + 1;
                    async move { n }
                })
                .await;
            assert_eq!(n, expected);
        }
    }

    /// A new command makes the parked Receive of the old one meaningless:
    /// `discard` drops it.
    #[tokio::test]
    async fn discard_drops_the_parked_future() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut parked: Parked<'_, ()> = Parked::new();
        tokio::select! {
            () = parked.drive(|| {
                let flag = DropFlag(Arc::clone(&dropped));
                async move {
                    let _flag = flag;
                    std::future::pending::<()>().await;
                }
            }) => panic!("never ready"),
            () = tokio::task::yield_now() => {}
        }
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        parked.discard();
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }
}
