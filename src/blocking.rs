//! Synchronous wrapper around the async API.
//!
//! `reqwest::blocking`-style: a single dedicated current-thread Tokio runtime
//! is created on demand and used to drive the async implementation. Suitable
//! for command-line tools or contexts where async is inconvenient.

use std::sync::OnceLock;

use tokio::runtime::Runtime;
use winrm_rs::WinrmClient;

use crate::clixml::PsValue;
use crate::error::{PsrpError, Result};
use crate::pipeline::{Pipeline, PipelineResult};
use crate::runspace::RunspacePool;
use crate::transport::WinrmPsrpTransport;

fn runtime() -> Result<&'static Runtime> {
    static RT: OnceLock<Runtime> = OnceLock::new();
    if let Some(rt) = RT.get() {
        return Ok(rt);
    }
    // Only a built runtime is cached. A failed build (threads or file
    // descriptors exhausted) is returned, and the next call tries again, as
    // it did when the failure was a panic that left the cell empty.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            PsrpError::protocol(format!("failed to build the blocking Tokio runtime: {e}"))
        })?;
    // Two first calls may race: the runtime that loses is dropped unused.
    let _ = RT.set(rt);
    RT.get()
        .ok_or_else(|| PsrpError::protocol("the blocking Tokio runtime was not stored"))
}

/// Run a single PowerShell script against `host` via a freshly-opened pool.
///
/// `host` is bare, as in [`WinrmPsrpTransport::open`]. The pool is closed
/// cleanly before returning.
pub fn run_script(client: &WinrmClient, host: &str, script: &str) -> Result<Vec<PsValue>> {
    runtime()?.block_on(async move {
        let (rpid, creation) =
            RunspacePool::<WinrmPsrpTransport<'_>>::build_creation_fragments(1, 1)?;
        let transport = WinrmPsrpTransport::open(client, host, &creation).await?;
        let mut pool = RunspacePool::open_from_transport(transport, rpid, 1, 1).await?;
        let result = pool.run_script(script).await;
        let _ = pool.close().await;
        result
    })
}

/// Run a pre-built [`Pipeline`] against `host` via a freshly-opened pool,
/// returning every stream. `host` is bare, as in
/// [`WinrmPsrpTransport::open`].
pub fn run_pipeline(
    client: &WinrmClient,
    host: &str,
    pipeline: Pipeline,
) -> Result<PipelineResult> {
    runtime()?.block_on(async move {
        let (rpid, creation) =
            RunspacePool::<WinrmPsrpTransport<'_>>::build_creation_fragments(1, 1)?;
        let transport = WinrmPsrpTransport::open(client, host, &creation).await?;
        let mut pool = RunspacePool::open_from_transport(transport, rpid, 1, 1).await?;
        let result = pipeline.run_all_streams(&mut pool).await;
        let _ = pool.close().await;
        result
    })
}

/// Run a PowerShell script over SSH. The pool is opened and closed
/// within the call.
#[cfg(feature = "ssh")]
pub fn run_script_ssh(config: crate::ssh::SshConfig, script: &str) -> Result<Vec<PsValue>> {
    runtime()?.block_on(async move {
        let transport = crate::ssh::SshPsrpTransport::connect(config).await?;
        let mut pool = RunspacePool::open_with_transport(transport).await?;
        let result = pool.run_script(script).await;
        let _ = pool.close().await;
        result
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_is_reusable() {
        // Touch the runtime twice to exercise the OnceLock fast path.
        let rt1 = std::ptr::from_ref(runtime().unwrap());
        let rt2 = std::ptr::from_ref(runtime().unwrap());
        assert_eq!(rt1, rt2);
        runtime().unwrap().block_on(async { 1 + 1 });
    }
}
