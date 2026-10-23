//! Live integration tests against a real Windows host.
//!
//! Every test in this file is `#[ignore]`-d by default. They only run
//! when the caller explicitly passes `--ignored` **and** provides the
//! required env vars. See [Vagrantfile](../Vagrantfile) for how to
//! spin up a disposable VM.
//!
//! ```bash
//! vagrant.exe up --provider=hyperv
//! vagrant.exe ssh -c "ipconfig"     # grab the VM IP
//! PSRP_INTEGRATION_HOST=<ip> \
//! PSRP_INTEGRATION_USER=vagrant \
//! PSRP_INTEGRATION_PASS=vagrant \
//!   cargo test --test integration_real -- --ignored
//! ```
//!
//! Set `PSRP_INTEGRATION_TLS=1` to use HTTPS on port 5986, or the env var
//! `PSRP_INTEGRATION_PORT` to override the port.

use std::env;

use psrp_rs::{
    AuthMethod, Command, Pipeline, PipelineState, PsValue, RunspacePool, WinrmClient, WinrmConfig,
    WinrmCredentials, WinrmPsrpTransport,
};

struct LiveConfig {
    host: String,
    user: String,
    pass: String,
    port: u16,
    tls: bool,
}

impl LiveConfig {
    fn from_env() -> Option<Self> {
        let host = env::var("PSRP_INTEGRATION_HOST").ok()?;
        let user = env::var("PSRP_INTEGRATION_USER").unwrap_or_else(|_| "vagrant".into());
        let pass = env::var("PSRP_INTEGRATION_PASS").unwrap_or_else(|_| "vagrant".into());
        let tls = env::var("PSRP_INTEGRATION_TLS")
            .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
        let default_port = if tls { 5986 } else { 5985 };
        let port = env::var("PSRP_INTEGRATION_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(default_port);
        Some(Self {
            host,
            user,
            pass,
            port,
            tls,
        })
    }
}

fn build_client(cfg: &LiveConfig) -> WinrmClient {
    // Use the auth method specified by env, defaulting to Basic for HTTP
    // (works through WSL → Hyper-V proxies) and NTLM for HTTPS.
    let auth_method = match std::env::var("PSRP_INTEGRATION_AUTH").ok().as_deref() {
        Some("ntlm") => AuthMethod::Ntlm,
        Some("basic") => AuthMethod::Basic,
        _ => {
            if cfg.tls {
                AuthMethod::Ntlm
            } else {
                AuthMethod::Basic
            }
        }
    };
    WinrmClient::new(
        WinrmConfig {
            auth_method,
            port: cfg.port,
            use_tls: cfg.tls,
            accept_invalid_certs: cfg.tls, // eval box, self-signed
            operation_timeout_secs: 20,
            ..Default::default()
        },
        WinrmCredentials::new(cfg.user.clone(), cfg.pass.clone(), ""),
    )
    .expect("build WinrmClient")
}

async fn open_pool<'c>(
    client: &'c WinrmClient,
    host: &str,
) -> RunspacePool<WinrmPsrpTransport<'c>> {
    let (rpid, creation) = RunspacePool::<WinrmPsrpTransport<'_>>::build_creation_fragments(1, 1)
        .expect("build creation fragments");
    let transport = WinrmPsrpTransport::open(client, host, &creation)
        .await
        .expect("open transport");
    RunspacePool::open_from_transport(transport, rpid, 1, 1)
        .await
        .expect("open runspace pool")
}

#[tokio::test]
#[ignore = "requires PSRP_INTEGRATION_HOST"]
async fn live_smoke_one_plus_one() {
    let Some(cfg) = LiveConfig::from_env() else {
        return;
    };
    let client = build_client(&cfg);
    let mut pool = open_pool(&client, &cfg.host).await;

    let out = pool.run_script("1 + 1").await.expect("run_script");
    assert_eq!(out.len(), 1, "expected a single result, got {out:?}");
    assert_eq!(out[0].as_i32(), Some(2), "got {out:?}");

    // Close may fail if the server already tore down the shell after
    // CommandState/Done. This is expected and harmless.
    let _ = pool.close().await;
}

#[tokio::test]
#[ignore = "requires PSRP_INTEGRATION_HOST"]
async fn live_get_date_returns_object() {
    let Some(cfg) = LiveConfig::from_env() else {
        return;
    };
    let client = build_client(&cfg);
    let mut pool = open_pool(&client, &cfg.host).await;

    let out = pool.run_script("Get-Date").await.expect("run_script");
    assert!(!out.is_empty(), "Get-Date returned nothing");
    // DateTime is emitted either as <DT> (future) or an Obj containing one.
    // Until we implement <DT>, just assert we got *something* back.
    let _ = pool.close().await;
}

#[tokio::test]
#[ignore = "requires PSRP_INTEGRATION_HOST"]
async fn live_get_process_select_name_id() {
    let Some(cfg) = LiveConfig::from_env() else {
        return;
    };
    let client = build_client(&cfg);
    let mut pool = open_pool(&client, &cfg.host).await;

    let out = pool
        .run_script("Get-Process | Select-Object -First 3 Name, Id")
        .await
        .expect("run_script");
    assert_eq!(out.len(), 3, "expected exactly 3 rows, got {}", out.len());
    for row in &out {
        let props = row.properties().expect("row is an Obj with MS");
        assert!(props.get("Name").is_some(), "Name missing");
        assert!(props.get("Id").is_some(), "Id missing");
    }
    let _ = pool.close().await;
}

#[tokio::test]
#[ignore = "requires PSRP_INTEGRATION_HOST"]
async fn live_pipeline_builder_with_parameter() {
    let Some(cfg) = LiveConfig::from_env() else {
        return;
    };
    let client = build_client(&cfg);
    let mut pool = open_pool(&client, &cfg.host).await;

    // `Write-Output 42` via builder instead of raw script.
    let pipeline = Pipeline::empty()
        .add_command(Command::new("Write-Output").with_parameter("InputObject", PsValue::I32(42)));

    let result = pipeline
        .run_all_streams(&mut pool)
        .await
        .expect("run_all_streams");
    assert_eq!(result.state, PipelineState::Completed);
    assert_eq!(result.output, vec![PsValue::I32(42)]);
    assert!(result.errors.is_empty(), "{:?}", result.errors);

    let _ = pool.close().await;
}

#[tokio::test]
#[ignore = "requires PSRP_INTEGRATION_HOST"]
async fn live_error_stream_is_captured() {
    let Some(cfg) = LiveConfig::from_env() else {
        return;
    };
    let client = build_client(&cfg);
    let mut pool = open_pool(&client, &cfg.host).await;

    // `Write-Error` sends on the error stream without terminating the pipeline.
    let result = Pipeline::new("Write-Error 'boom' -ErrorAction Continue; 'after'")
        .run_all_streams(&mut pool)
        .await
        .expect("run_all_streams");
    assert_eq!(result.state, PipelineState::Completed);
    assert!(
        !result.errors.is_empty(),
        "expected an ErrorRecord, got {result:?}"
    );
    assert_eq!(result.output, vec![PsValue::String("after".into())]);

    let _ = pool.close().await;
}

#[tokio::test]
#[ignore = "requires PSRP_INTEGRATION_HOST"]
async fn live_warning_stream_is_captured() {
    let Some(cfg) = LiveConfig::from_env() else {
        return;
    };
    let client = build_client(&cfg);
    let mut pool = open_pool(&client, &cfg.host).await;

    let result = Pipeline::new("Write-Warning 'careful'; 'done'")
        .run_all_streams(&mut pool)
        .await
        .expect("run_all_streams");
    assert_eq!(result.state, PipelineState::Completed);
    assert!(
        !result.warnings.is_empty(),
        "expected a warning record, got {result:?}"
    );

    let _ = pool.close().await;
}

#[tokio::test]
#[ignore = "requires PSRP_INTEGRATION_HOST"]
async fn live_disconnect_reconnect_pool() {
    let Some(cfg) = LiveConfig::from_env() else {
        return;
    };
    let client = build_client(&cfg);

    // Open + run something + disconnect.
    let mut pool = open_pool(&client, &cfg.host).await;
    let pre = pool.run_script("'before'").await.unwrap();
    assert_eq!(pre, vec![PsValue::String("before".into())]);
    let disconnect_result = pool.disconnect().await;
    // The PowerShell provider (pwrshplugin.dll) on some Windows versions
    // does not support disconnect/reconnect for PSRP shells. When the
    // server rejects it, we skip the rest of the test rather than fail.
    let disconnected = match disconnect_result {
        Ok(d) => d,
        Err(e) => {
            eprintln!("disconnect not supported on this server: {e}");
            return;
        }
    };

    // Rebuild the transport with the same shell id and reconnect.
    let transport =
        psrp_rs::WinrmPsrpTransport::reconnect(&client, &cfg.host, disconnected.shell_id())
            .await
            .expect("rebuild transport");
    let mut pool = disconnected.reconnect(transport).await.expect("reconnect");
    let post = pool.run_script("'after'").await.unwrap();
    assert_eq!(post, vec![PsValue::String("after".into())]);
    let _ = pool.close().await;
}

#[tokio::test]
#[ignore = "requires PSRP_INTEGRATION_HOST"]
async fn live_pool_survives_multiple_pipelines() {
    let Some(cfg) = LiveConfig::from_env() else {
        return;
    };
    let client = build_client(&cfg);
    let mut pool = open_pool(&client, &cfg.host).await;

    for i in 1..=3i32 {
        let out = pool
            .run_script(&format!("{i} * 10"))
            .await
            .expect("run_script");
        assert_eq!(out, vec![PsValue::I32(i * 10)]);
    }

    let _ = pool.close().await;
}

/// `SecureString`s in both directions, against PowerShell's own layout
/// (#21): AES-256-CBC with the session key, a zero IV, no IV prefix.
///
/// The codec does not encrypt `<SS>` by itself: the test encrypts and
/// decrypts with the pool's helpers.
async fn secure_string_round_trip<T: psrp_rs::PsrpTransport>(pool: &mut RunspacePool<T>) {
    pool.request_session_key().await.expect("session key");

    // One block, several blocks with a character outside the BMP, and the
    // empty string (one block of padding; `ConvertTo-SecureString` refuses
    // an empty string, hence the constructor).
    for (secret, make) in [
        ("p@ss", "ConvertTo-SecureString 'p@ss' -AsPlainText -Force"),
        (
            "héllo 🌍 world, long secret",
            "ConvertTo-SecureString 'héllo 🌍 world, long secret' -AsPlainText -Force",
        ),
        ("", "[securestring]::new()"),
    ] {
        // Server -> client: PowerShell encrypts the SecureString it outputs.
        let out = pool.run_script(make).await.expect("run_script");
        let [PsValue::SecureString(body)] = out.as_slice() else {
            panic!("expected one SecureString, got {out:?}");
        };
        assert_eq!(
            pool.decrypt_secure_string(body).expect("decrypt"),
            secret,
            "server-encrypted {secret:?}"
        );

        // Client -> server: PowerShell decrypts the `<SS>` we send.
        let sealed = pool.encrypt_secure_string(secret).expect("encrypt");
        let result = Pipeline::empty()
            .add_command(
                Command::script("param($s) [System.Net.NetworkCredential]::new('', $s).Password")
                    .with_parameter("s", PsValue::SecureString(sealed)),
            )
            .run_all_streams(pool)
            .await
            .expect("run_all_streams");
        assert!(result.errors.is_empty(), "{:?}", result.errors);
        assert_eq!(
            result.output,
            vec![PsValue::String(secret.into())],
            "client-encrypted {secret:?}"
        );
    }
}

#[tokio::test]
#[ignore = "requires PSRP_INTEGRATION_HOST"]
async fn live_secure_string_round_trip() {
    let Some(cfg) = LiveConfig::from_env() else {
        return;
    };
    let client = build_client(&cfg);
    let mut pool = open_pool(&client, &cfg.host).await;

    secure_string_round_trip(&mut pool).await;

    let _ = pool.close().await;
}

/// An object that appears twice in one graph is serialized once and then
/// referenced by a self-closed `<Ref />`: it used to vanish from a list (the
/// items after it moved up) and read as `Null` in a dictionary.
#[tokio::test]
#[ignore = "requires PSRP_INTEGRATION_HOST"]
async fn live_shared_object_in_list_and_dict() {
    let Some(cfg) = LiveConfig::from_env() else {
        return;
    };
    let client = build_client(&cfg);
    let mut pool = open_pool(&client, &cfg.host).await;

    let value = |out: &[PsValue]| match out {
        [PsValue::Object(o)] => o.get("_value").cloned().expect("a collection"),
        other => panic!("expected one collection, got {other:?}"),
    };

    let out = pool
        .run_script("$o = [pscustomobject]@{a = 1}; ,@($o, $o, 5)")
        .await
        .expect("list");
    let PsValue::List(items) = value(&out) else {
        panic!("not a list: {out:?}");
    };
    assert_eq!(items.len(), 3, "{items:?}");
    assert_eq!(items[0], items[1]);
    assert_ne!(items[0], PsValue::Null);
    assert_eq!(items[2], PsValue::I32(5));

    let out = pool
        .run_script("$o = [pscustomobject]@{a = 1}; ,@{x = $o; y = $o}")
        .await
        .expect("dict");
    let PsValue::Dict(entries) = value(&out) else {
        panic!("not a dict: {out:?}");
    };
    assert_eq!(entries.len(), 2, "{entries:?}");
    assert_eq!(entries[0].1, entries[1].1);
    assert_ne!(entries[0].1, PsValue::Null, "{entries:?}");

    let _ = pool.close().await;
}

/// `"😀".ToCharArray()` is two `<C>` of surrogates: they used to fail the whole
/// pipeline; now each is U+FFFD. A `[char]` sent from a non-BMP `char` goes out
/// as U+FFFD too (PowerShell rejects `<C>128512</C>`).
#[tokio::test]
#[ignore = "requires PSRP_INTEGRATION_HOST"]
async fn live_char_surrogates_and_non_bmp() {
    let Some(cfg) = LiveConfig::from_env() else {
        return;
    };
    let client = build_client(&cfg);
    let mut pool = open_pool(&client, &cfg.host).await;

    let out = pool
        .run_script("([string]::new([char[]](0xD83D,0xDE00))).ToCharArray()")
        .await
        .expect("a surrogate half must not fail the pipeline");
    assert_eq!(
        out,
        vec![PsValue::Char('\u{FFFD}'), PsValue::Char('\u{FFFD}')]
    );

    let pipeline = Pipeline::empty().add_command(
        Command::script("param($c) [int]$c").with_argument(PsValue::Char('\u{1F600}')),
    );
    let result = pipeline.run_all_streams(&mut pool).await.expect("run");
    assert_eq!(result.output, vec![PsValue::I32(0xFFFD)]);

    let _ = pool.close().await;
}

/// A terminating error (`throw`, a failed `-ErrorAction Stop`) is reported
/// in the `PipelineState` message only: `PipelineFailed` used to say
/// "unknown error", and the message of an error-stream `ErrorRecord` was a
/// dump of the whole record.
#[tokio::test]
#[ignore = "requires PSRP_INTEGRATION_HOST"]
async fn live_failed_pipeline_reports_its_reason() {
    let Some(cfg) = LiveConfig::from_env() else {
        return;
    };
    let client = build_client(&cfg);
    let mut pool = open_pool(&client, &cfg.host).await;

    for (script, expected) in [
        ("throw 'boom'", "boom"),
        ("1/0", "divide by zero"),
        ("Write-Error 'first'; throw 'second'", "second"),
    ] {
        let err = pool
            .run_script(script)
            .await
            .expect_err("the pipeline must fail");
        let psrp_rs::PsrpError::PipelineFailed(message) = &err else {
            panic!("{script}: {err:?}");
        };
        assert!(message.contains(expected), "{script}: {message:?}");
        assert!(!message.contains("PsObject"), "{script}: {message:?}");
        assert!(message.len() < 1200, "{script}: {} bytes", message.len());
    }

    let _ = pool.close().await;
}

// ---- SSH transport tests ----

/// Build the SSH config from `PSRP_INTEGRATION_SSH_{HOST,PORT,USER,PASS}`.
/// `None` when no host is configured, so the tests are no-ops by default.
#[cfg(feature = "ssh")]
async fn ssh_config() -> Option<psrp_rs::SshConfig> {
    let host = std::env::var("PSRP_INTEGRATION_SSH_HOST").ok()?;
    let user = std::env::var("PSRP_INTEGRATION_SSH_USER").unwrap_or_else(|_| "vagrant".into());
    let pass = std::env::var("PSRP_INTEGRATION_SSH_PASS").unwrap_or_else(|_| "vagrant".into());
    let port: u16 = std::env::var("PSRP_INTEGRATION_SSH_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(22);
    Some(
        psrp_rs::SshConfig::new(host, user, psrp_rs::SshAuth::Password(pass.into()))
            .with_port(port),
    )
}

/// Connect over SSH and open a runspace pool, or `None` when unconfigured.
#[cfg(feature = "ssh")]
async fn ssh_pool() -> Option<RunspacePool<psrp_rs::SshPsrpTransport>> {
    let config = ssh_config().await?;
    let transport = psrp_rs::SshPsrpTransport::connect(config)
        .await
        .expect("SSH connect");
    Some(
        RunspacePool::open_with_transport(transport)
            .await
            .expect("open pool over SSH"),
    )
}

#[cfg(feature = "ssh")]
#[tokio::test]
#[ignore = "requires PSRP_INTEGRATION_SSH_HOST"]
async fn live_ssh_one_plus_one() {
    let Some(mut pool) = ssh_pool().await else {
        return;
    };
    let out = pool.run_script("1 + 1").await.expect("run_script");
    assert_eq!(out, vec![PsValue::I32(2)]);
    pool.close().await.expect("close");
}

#[cfg(feature = "ssh")]
#[tokio::test]
#[ignore = "requires PSRP_INTEGRATION_SSH_HOST"]
async fn live_ssh_multiple_scripts() {
    let Some(mut pool) = ssh_pool().await else {
        return;
    };
    for i in 1..=3i32 {
        let out = pool
            .run_script(&format!("{i} * 10"))
            .await
            .expect("run_script");
        assert_eq!(out, vec![PsValue::I32(i * 10)]);
    }
    pool.close().await.expect("close");
}

#[cfg(feature = "ssh")]
#[tokio::test]
#[ignore = "requires PSRP_INTEGRATION_SSH_HOST"]
async fn live_ssh_large_output() {
    let Some(mut pool) = ssh_pool().await else {
        return;
    };
    let out = pool.run_script("'x' * 200000").await.expect("run_script");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].as_str().map(str::len), Some(200_000));
    pool.close().await.expect("close");
}

#[cfg(feature = "ssh")]
#[tokio::test]
#[ignore = "requires PSRP_INTEGRATION_SSH_HOST"]
async fn live_ssh_large_script() {
    let Some(mut pool) = ssh_pool().await else {
        return;
    };
    let script = format!("$a = '{}'; $a.Length", "y".repeat(100_000));
    let out = pool.run_script(&script).await.expect("run_script");
    assert_eq!(out, vec![PsValue::I32(100_000)]);
    pool.close().await.expect("close");
}

#[cfg(feature = "ssh")]
#[tokio::test]
#[ignore = "requires PSRP_INTEGRATION_SSH_HOST"]
async fn live_ssh_pipeline_input() {
    let Some(mut pool) = ssh_pool().await else {
        return;
    };
    let mut handle = Pipeline::new("$input | ForEach-Object { $_ * 2 }")
        .with_input(true)
        .start(&mut pool)
        .await
        .expect("start");
    for i in 1..=3i32 {
        handle
            .write_input(PsValue::I32(i))
            .await
            .expect("write_input");
    }
    handle.end_input().await.expect("end_input");
    let result = handle.collect().await.expect("collect");
    assert_eq!(
        result.output,
        vec![PsValue::I32(2), PsValue::I32(4), PsValue::I32(6)]
    );
    pool.close().await.expect("close");
}

#[cfg(feature = "ssh")]
#[tokio::test]
#[ignore = "requires PSRP_INTEGRATION_SSH_HOST"]
async fn live_ssh_cancel_then_reuse() {
    let Some(mut pool) = ssh_pool().await else {
        return;
    };
    let token = tokio_util::sync::CancellationToken::new();
    let canceller = token.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        canceller.cancel();
    });
    let started = std::time::Instant::now();
    let res = Pipeline::new("Start-Sleep -Seconds 60")
        .run_with_cancel(&mut pool, token)
        .await;
    let elapsed = started.elapsed();
    eprintln!("cancel took {elapsed:?}");
    assert!(
        matches!(res, Err(psrp_rs::PsrpError::Cancelled)),
        "expected Cancelled, got {res:?}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(20),
        "cancel took {elapsed:?}"
    );

    let out = pool.run_script("7").await.expect("pool reusable");
    assert_eq!(out, vec![PsValue::I32(7)]);
    pool.close().await.expect("close");
}

#[cfg(feature = "ssh")]
#[tokio::test]
#[ignore = "requires PSRP_INTEGRATION_SSH_HOST"]
async fn live_ssh_command_metadata() {
    let Some(mut pool) = ssh_pool().await else {
        return;
    };
    let meta = pool
        .get_command_metadata(&["Get-Date"], psrp_rs::CommandType::CMDLET)
        .await
        .expect("get_command_metadata");
    // `any` below also proves the list is non-empty.
    assert!(
        meta.iter().any(|m| m.name == "Get-Date"),
        "Get-Date not in non-empty metadata list: {meta:?}"
    );
    pool.close().await.expect("close");
}

#[cfg(feature = "ssh")]
#[tokio::test]
#[ignore = "requires PSRP_INTEGRATION_SSH_HOST"]
async fn live_ssh_session_key() {
    let Some(mut pool) = ssh_pool().await else {
        return;
    };
    pool.request_session_key().await.expect("session key");
    pool.close().await.expect("close");
}

#[cfg(feature = "ssh")]
#[tokio::test]
#[ignore = "requires PSRP_INTEGRATION_SSH_HOST"]
async fn live_ssh_secure_string_round_trip() {
    let Some(mut pool) = ssh_pool().await else {
        return;
    };
    secure_string_round_trip(&mut pool).await;
    pool.close().await.expect("close");
}

#[cfg(feature = "ssh")]
#[tokio::test]
#[ignore = "requires PSRP_INTEGRATION_SSH_HOST"]
async fn live_ssh_refused_subsystem() {
    let Some(config) = ssh_config().await else {
        return;
    };
    let err =
        psrp_rs::SshPsrpTransport::connect(config.with_subsystem("psrp-rs-no-such-subsystem"))
            .await
            .expect_err("connect must fail for an unknown subsystem");
    assert!(err.to_string().contains("refused"), "{err}");
}

#[cfg(feature = "ssh")]
#[tokio::test]
#[ignore = "requires PSRP_INTEGRATION_SSH_HOST"]
async fn live_ssh_server_exit_is_an_error() {
    let Some(mut pool) = ssh_pool().await else {
        return;
    };
    let res = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        pool.run_script("[Environment]::Exit(7)"),
    )
    .await
    .expect("run_script must not hang when the server exits");
    assert!(res.is_err(), "expected an error, got {res:?}");
}
