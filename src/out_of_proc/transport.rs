//! [`PsrpTransport`] over an OutOfProc session.
//!
//! A thin adapter: every method maps onto one [`OutOfProcSession`]
//! operation, and the session already bounds each wait for an
//! acknowledgement, so this layer adds no timeout of its own.

use async_trait::async_trait;
use tokio::sync::Mutex;
use uuid::Uuid;

use super::session::{OutOfProcSession, Pipe};
use crate::error::Result;
use crate::transport::PsrpTransport;

/// A [`PsrpTransport`] speaking the OutOfProc protocol over a [`Pipe`].
///
/// The session sits behind a mutex only so that the `&self` trait methods
/// (`send_fragment`, `signal_stop`) can reach it; the `&mut self` ones use
/// the mutex's `get_mut`, which cannot wait.
pub(crate) struct OutOfProcTransport<P: Pipe> {
    session: Mutex<OutOfProcSession<P>>,
}

impl<P: Pipe> OutOfProcTransport<P> {
    #[cfg(test)]
    pub(crate) fn new(pipe: P) -> Self {
        Self {
            session: Mutex::new(OutOfProcSession::new(pipe)),
        }
    }

    /// As [`Self::new`], bounding every acknowledgement by `timeout`.
    pub(crate) fn with_ack_timeout(pipe: P, timeout: std::time::Duration) -> Self {
        Self {
            session: Mutex::new(OutOfProcSession::new(pipe).with_ack_timeout(timeout)),
        }
    }

    /// Closes the open command, then the session. Bounded, since every
    /// wait for an acknowledgement is ([`ACK_TIMEOUT`](super::session::ACK_TIMEOUT) unless configured).
    ///
    /// Leaves the pipe open: the caller tears it down.
    pub(crate) async fn close_session(&self) -> Result<()> {
        self.session.lock().await.close().await
    }

    pub(crate) fn pipe_mut(&mut self) -> &mut P {
        self.session.get_mut().pipe_mut()
    }
}

#[async_trait]
impl<P: Pipe> PsrpTransport for OutOfProcTransport<P> {
    async fn send_fragment(&self, bytes: &[u8]) -> Result<()> {
        self.session.lock().await.send(Uuid::nil(), bytes).await
    }

    async fn send_pipeline_fragment(&mut self, bytes: &[u8], pipeline_id: Uuid) -> Result<()> {
        self.session.get_mut().send(pipeline_id, bytes).await
    }

    /// Never returns an empty chunk: the session guarantees it, and the
    /// pool's open loop would spin on one.
    async fn recv_chunk(&mut self) -> Result<Vec<u8>> {
        self.session.get_mut().recv().await
    }

    async fn signal_stop(&self) -> Result<()> {
        self.session.lock().await.signal().await
    }

    async fn close_shell(&mut self) -> Result<()> {
        self.session.get_mut().close().await
    }

    async fn execute_pipeline(&mut self, fragment_bytes: &[u8], pipeline_id: Uuid) -> Result<()> {
        self.session
            .get_mut()
            .send(pipeline_id, fragment_bytes)
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::timeout;
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    use super::*;
    use crate::clixml::PsValue;
    use crate::error::PsrpError;
    use crate::metadata::CommandType;
    use crate::out_of_proc::fake::{FakeHandle, FakePwsh};
    use crate::out_of_proc::{Packet, parse_line};
    use crate::pipeline::Pipeline;
    use crate::runspace::RunspacePool;

    type Pool = RunspacePool<OutOfProcTransport<FakePwsh>>;

    async fn open() -> Result<(Pool, FakeHandle)> {
        let (fake, handle) = FakePwsh::new();
        let pool = RunspacePool::open_with_transport(OutOfProcTransport::new(fake)).await?;
        Ok((pool, handle))
    }

    /// Every line the client wrote, parsed.
    fn packets(h: &FakeHandle) -> Vec<Packet> {
        h.written()
            .iter()
            .filter_map(|l| parse_line(l).ok().flatten())
            .collect()
    }

    fn position(all: &[Packet], wanted: &Packet) -> Option<usize> {
        all.iter().position(|p| p == wanted)
    }

    /// The pipeline ids of the `Command` lines, in order.
    fn command_pids(all: &[Packet]) -> Vec<Uuid> {
        all.iter()
            .filter_map(|p| match p {
                Packet::Command(pid) => Some(*pid),
                _ => None,
            })
            .collect()
    }

    fn assert_closed_last(all: &[Packet], pid: Uuid) {
        assert!(all.len() >= 2, "{all:?}");
        assert_eq!(
            all[all.len() - 2..],
            [Packet::Close(pid), Packet::Close(Uuid::nil())]
        );
    }

    async fn open_runs_and_closes(chunk: Option<usize>) -> Result<()> {
        let (fake, h) = FakePwsh::new();
        h.set_output(vec![PsValue::I32(2)]);
        if let Some(n) = chunk {
            h.set_chunk_size(n);
        }
        let mut pool = RunspacePool::open_with_transport(OutOfProcTransport::new(fake)).await?;
        assert_eq!(pool.run_script("1 + 1").await?, vec![PsValue::I32(2)]);
        pool.close().await?;

        let all = packets(&h);
        let pids = command_pids(&all);
        assert_eq!(pids.len(), 1, "{all:?}");
        assert_closed_last(&all, pids[0]);
        assert!(h.violations().is_empty(), "{:?}", h.violations());
        Ok(())
    }

    #[tokio::test]
    async fn pool_opens_runs_and_closes_over_out_of_proc() -> Result<()> {
        open_runs_and_closes(None).await
    }

    #[tokio::test]
    async fn byte_at_a_time_crlf_stdout_still_works() -> Result<()> {
        open_runs_and_closes(Some(1)).await
    }

    #[tokio::test]
    async fn consecutive_pipelines_each_get_their_own_command() -> Result<()> {
        let (mut pool, h) = open().await?;
        for script in ["1", "2", "3"] {
            pool.run_script(script).await?;
        }
        let all = packets(&h);
        let pids = command_pids(&all);
        assert_eq!(pids.len(), 3, "{all:?}");
        for pair in pids.windows(2) {
            let close = position(&all, &Packet::Close(pair[0]));
            let next = position(&all, &Packet::Command(pair[1]));
            assert!(
                matches!((close, next), (Some(c), Some(n)) if c < n),
                "{all:?}"
            );
        }
        assert!(h.violations().is_empty(), "{:?}", h.violations());
        Ok(())
    }

    #[tokio::test]
    async fn command_metadata_opens_a_command() -> Result<()> {
        let (mut pool, h) = open().await?;
        let found = pool
            .get_command_metadata(&["Get-Date"], CommandType::CMDLET)
            .await?;
        assert!(found.is_empty(), "{found:?}");

        let all = packets(&h);
        let pids = command_pids(&all);
        assert_eq!(pids.len(), 1, "{all:?}");
        let command = position(&all, &Packet::Command(pids[0]));
        let data = all
            .iter()
            .position(|p| matches!(p, Packet::Data { guid, .. } if *guid == pids[0]));
        assert!(
            matches!((command, data), (Some(c), Some(d)) if c < d),
            "{all:?}"
        );
        assert!(h.violations().is_empty(), "{:?}", h.violations());
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn cancel_signals_and_reports_cancelled() -> Result<()> {
        let (mut pool, h) = open().await?;
        h.set_pipelines_run_forever(true);
        let token = CancellationToken::new();
        token.cancel();

        let result = Pipeline::new("Start-Sleep 60")
            .run_with_cancel(&mut pool, token)
            .await;

        assert!(matches!(result, Err(PsrpError::Cancelled)), "{result:?}");
        let all = packets(&h);
        let pids = command_pids(&all);
        assert_eq!(pids.len(), 1, "{all:?}");
        assert!(all.contains(&Packet::Signal(pids[0])), "{all:?}");
        assert!(h.violations().is_empty(), "{:?}", h.violations());
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn server_exit_during_open_is_an_error_not_a_hang() {
        let (fake, h) = FakePwsh::new();
        h.die_after_writes(2);

        let opened = timeout(
            Duration::from_secs(5),
            RunspacePool::open_with_transport(OutOfProcTransport::new(fake)),
        )
        .await;

        let Ok(result) = opened else {
            panic!("open hung");
        };
        let Err(err) = result else {
            panic!("open succeeded against a dead server");
        };
        assert!(err.to_string().contains("fake pwsh exited"), "{err}");
        assert!(h.violations().is_empty(), "{:?}", h.violations());
    }

    #[tokio::test]
    async fn server_exit_mid_pipeline_is_an_error() -> Result<()> {
        let (mut pool, h) = open().await?;
        h.die_after_writes(4);
        let err = pool.run_script("1 + 1").await.unwrap_err();
        assert!(err.to_string().contains("fake pwsh exited"), "{err}");
        assert!(h.violations().is_empty(), "{:?}", h.violations());
        Ok(())
    }

    #[tokio::test]
    async fn close_after_an_abandoned_pipeline_closes_its_command_first() -> Result<()> {
        let (mut pool, h) = open().await?;
        h.set_pipelines_run_forever(true);
        // The handle is dropped at once: the pipeline is abandoned.
        Pipeline::new("x").start(&mut pool).await?;

        pool.close().await?;

        let all = packets(&h);
        let pids = command_pids(&all);
        assert_eq!(pids.len(), 1, "{all:?}");
        assert_closed_last(&all, pids[0]);
        assert_eq!(
            all.iter().filter(|p| **p == Packet::Close(pids[0])).count(),
            1,
            "{all:?}"
        );
        assert!(h.violations().is_empty(), "{:?}", h.violations());
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn close_is_bounded_when_pwsh_never_acknowledges() -> Result<()> {
        let (pool, h) = open().await?;
        h.hold_replies(true);

        let err = pool.close().await.unwrap_err();

        // The pool's CloseRunspacePool message (Data on the pool) goes
        // first, and its acknowledgement never comes.
        assert!(
            err.to_string().contains(
                "PowerShell did not acknowledge Data for \
                 00000000-0000-0000-0000-000000000000 within 60 s"
            ),
            "{err}"
        );
        assert!(h.violations().is_empty(), "{:?}", h.violations());
        Ok(())
    }
}
