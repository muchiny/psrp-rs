# psrp-rs

Async [PowerShell Remoting Protocol (MS-PSRP)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/)
client for Rust, built on top of [`winrm-rs`](https://github.com/muchini/winrm-rs).

`psrp-rs` layers PSRP fragments, CLIXML serialization and a runspace pool
state machine on top of `winrm-rs`, so Rust code can run PowerShell
pipelines against Windows hosts and receive **typed** results with
isolated Output / Error / Warning / Verbose / Debug / Information /
Progress streams.

## Quickstart

```rust,no_run
use psrp_rs::{RunspacePool, WinrmPsrpTransport};
use winrm_rs::{AuthMethod, WinrmClient, WinrmConfig, WinrmCredentials};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = WinrmClient::new(
        WinrmConfig {
            auth_method: AuthMethod::Ntlm,
            ..Default::default()
        },
        WinrmCredentials::new("administrator", "Passw0rd!", ""),
    )?;

    let transport = WinrmPsrpTransport::open(&client, "win-host.lab").await?;
    let mut pool = RunspacePool::open_with_transport(transport).await?;

    let objects = pool
        .run_script("Get-Process | Select-Object -First 5 Name, Id")
        .await?;

    for obj in objects {
        println!("{obj:?}");
    }

    pool.close().await?;
    Ok(())
}
```

A synchronous wrapper is available in the [`blocking`] module for
callers that do not want to manage an async runtime.

## Scope

| Feature                         | Status |
|---------------------------------|--------|
| Fragment encode / reassemble    | ✅     |
| CLIXML primitives + `<Obj>` + list/dict | ✅     |
| Runspace pool open / close      | ✅     |
| `Pipeline` builder with parameters | ✅     |
| All standard PSRP streams       | ✅     |
| Async **and** blocking API      | ✅     |
| CLIXML `<Ref>` round-tripping (read-only) | ⚠️ partial |
| Pipeline input streaming        | ❌     |
| Reconnect / disconnect pool     | ❌     |

## License

Dual-licensed under **MIT** or **Apache-2.0**.
