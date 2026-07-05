//! Outbound auxiliary lookups (identd). Dedicated process to keep network egress isolated from the
//! byte-forwarding hot path:
//!
//! - acceptor accepts a TCP/TLS client, fires a one-line JSON "`session_observed`" event to the
//!   scanner's UDS, drops the connection.
//! - scanner picks up the event, kicks off an identd probe with a short timeout, logging the
//!   outcome.
//!
//! The scanner is a peer to processor/plain/tls in the supervisor's view: own control socket, own
//! listener FD that survives self-upgrade, and participates the rolling upgrade walk and `status`
//! command.

mod control;
mod sidecar;
mod upgrade;

use std::collections::HashSet;
use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use futures::StreamExt;
#[cfg(test)]
use tokio::io::AsyncReadExt;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::UnixListener,
    signal::unix::{SignalKind, signal},
    sync::{mpsc, watch},
};
use tokio_util::codec::{FramedRead, LinesCodec};

use crate::{
    auth::{PeerAllowlist, check_peer},
    config::Config,
    control::SessionMetadata,
    handoff::{
        ENV_UPGRADE_GENERATION, SelfExe, now_unix_ms, open_self_exe, signal_ready_to_parent,
    },
    security::{apply_sandbox, drop_privileges},
    worker_common::{SocketsDialer, adopt_or_bind_uds_listener},
};

use control::{StatusCtx, UpgradeReq};

/// One-line JSON envelope acceptors write to the scanner UDS on every accept
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScanRequest {
    SessionObserved {
        client_ip: String,
        client_port: u16,
        server_port: u16,
        role: String,
        /// Acceptor-assigned trace ID for the originating session. Lets scanner logs (identd probe,
        /// sidecar publish) join the acceptor + processor's session lines on a single id.
        #[serde(default)]
        trace_id: String,
    },
}

#[derive(Default)]
pub(super) struct ScannerRegistry {
    next_id: u64,
    in_flight: HashSet<u64>,
}

pub async fn run(mut config: Config) -> Result<()> {
    let sock_path: PathBuf = config.scanner_sock();
    let control_basename = Config::socket_basename("ctrl-scanner");
    let generation: u64 = env::var(ENV_UPGRADE_GENERATION)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    tracing::info!(generation, "scanner generation");

    let mut listener = adopt_or_bind_uds_listener(&sock_path, "scanner", &config).await?;
    let started_at_unix_ms = now_unix_ms();
    let allow = Arc::new(std::sync::RwLock::new(PeerAllowlist::from_config(
        &config.auth.allowed_uids,
    )));

    // Open the sockets-dir FD before dropping/sandboxing so the sidecar dial works under FreeBSD
    // Capscium
    let dialer = Arc::new(SocketsDialer::open(&config.sockets_dir).context("open sockets_dir")?);
    // Self-exe path + FD for fexecve under cap_enter; see processor.rs
    let self_exe = Arc::new(open_self_exe().context("open self exe")?);
    drop_privileges("scanner", &mut config.security)?;

    // The scanner's job is outbound TCP probes (identd), which FreeBSD Capsicum forbids:
    // `connect()` to an arbitary address returns ECAPMODE, and the probe then silently yields
    // nothing. Warn loudly if it's about to be sandboxed there, so a misconfig isn't mistaken for
    // "no hits."
    #[cfg(target_os = "freebsd")]
    if config.security.effective_sandbox("scanner") != crate::config::SandboxMode::Off {
        tracing::warn!(
            "scanner sandboxed under Capsicum: outbound identd probes will \
             fail (connect() -> ECAPMODE) and silently return empty. Set \
             [security.sandbox_overrides] scanner = \"off\" to enable egress."
        );
    }
    apply_sandbox("scanner", &config.security)?;

    // After listener is up and adopted, tell the parent (if any) we're alive so it commits the
    // upgrade. No-op on cold start.
    signal_ready_to_parent().context("signal ready")?;

    let registry: Arc<Mutex<ScannerRegistry>> = Arc::new(Mutex::new(ScannerRegistry::default()));

    let (sidecar_tx, sidecar_rx) = tokio::sync::mpsc::channel::<SessionMetadata>(256);
    tokio::spawn(sidecar::run_sidecar_publisher(dialer.clone(), sidecar_rx));

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (upgrade_tx, upgrade_rx) = watch::channel::<Option<UpgradeReq>>(None);

    // Hand the control client *clones* and keep the originals alive for the
    // loop's lifetime (dropped below). If the task owned the only senders, a
    // control disconnect mid-upgrade would make `upgrade_rx.changed()` resolve
    // `Err` while `borrow()` still held the just-processed request, re-running a
    // rolled-back upgrade. See the acceptor/processor for the same guard.
    let listener_addr = sock_path.display().to_string();
    spawn_scanner_control(
        control_basename.clone(),
        shutdown_tx.clone(),
        upgrade_tx.clone(),
        allow.clone(),
        dialer.clone(),
        StatusCtx {
            registry: registry.clone(),
            generation,
            started_at_unix_ms,
            listener_addr: listener_addr.clone(),
        },
    );

    listener = run_scanner_loop(ScannerLoop {
        listener,
        registry: registry.clone(),
        allow,
        dialer,
        sidecar_tx,
        config: &config,
        self_exe: &self_exe,
        generation,
        shutdown_rx,
        upgrade_rx,
        control_basename,
        control_shutdown_tx: shutdown_tx.clone(),
        control_upgrade_tx: upgrade_tx.clone(),
        started_at_unix_ms,
        listener_addr,
    })
    .await?;

    drop((shutdown_tx, upgrade_tx));
    drop(listener);
    if generation == 0 {
        let _ = fs::remove_file(&sock_path);
    }
    Ok(())
}

fn spawn_scanner_control(
    basename: String,
    shutdown_tx: watch::Sender<bool>,
    upgrade_tx: watch::Sender<Option<UpgradeReq>>,
    allow: Arc<std::sync::RwLock<PeerAllowlist>>,
    dialer: Arc<SocketsDialer>,
    ctx: StatusCtx,
) {
    tokio::spawn(async move {
        if let Err(e) =
            control::run_control_client(dialer, basename, shutdown_tx, upgrade_tx, allow, ctx).await
        {
            tracing::warn!(error = %e, "control-plane client exited");
        }
    });
}

struct ScannerLoop<'a> {
    listener: UnixListener,
    registry: Arc<Mutex<ScannerRegistry>>,
    allow: Arc<std::sync::RwLock<PeerAllowlist>>,
    dialer: Arc<SocketsDialer>,
    sidecar_tx: mpsc::Sender<SessionMetadata>,
    config: &'a Config,
    self_exe: &'a SelfExe,
    generation: u64,
    shutdown_rx: watch::Receiver<bool>,
    upgrade_rx: watch::Receiver<Option<UpgradeReq>>,
    // Stored so we can respawn the control client after a rollback.
    control_basename: String,
    control_shutdown_tx: watch::Sender<bool>,
    control_upgrade_tx: watch::Sender<Option<UpgradeReq>>,
    started_at_unix_ms: u64,
    listener_addr: String,
}

async fn run_scanner_loop(mut runtime: ScannerLoop<'_>) -> Result<UnixListener> {
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    loop {
        tokio::select! {
            res = runtime.listener.accept() => handle_scanner_accept(
                res,
                &runtime.registry,
                &runtime.allow,
                &runtime.sidecar_tx,
                runtime.config.identd_port,
            ),
            _ = sigterm.recv() => { tracing::info!("SIGTERM"); break; }
            _ = sigint.recv() => { tracing::info!("SIGINT"); break; }
            _ = runtime.shutdown_rx.changed() => {
                if *runtime.shutdown_rx.borrow() {
                    tracing::info!("control-plane Shutdown");
                    break;
                }
            }
            _ = runtime.upgrade_rx.changed() => {
                let req = runtime.upgrade_rx.borrow().clone();
                let Some(req) = req else { continue };
                tracing::info!(?req.binary_path, "scanner Upgrade requested");
                let dirs = crate::handoff::HandoffDirFds {
                    sockets: runtime.dialer.dir_raw_fd(),
                    ..Default::default()
                };
                runtime.listener = upgrade::do_upgrade(
                    runtime.listener,
                    &runtime.registry,
                    runtime.generation,
                    req.binary_path,
                    runtime.config,
                    runtime.self_exe,
                    dirs,
                )
                .await?;
                // Only reached on rollback (commit calls process::exit). Respawn the control
                // client that exited when it sent the Upgrade message.
                tracing::info!("scanner upgrade rolled back; respawning control client");
                spawn_scanner_control(
                    runtime.control_basename.clone(),
                    runtime.control_shutdown_tx.clone(),
                    runtime.control_upgrade_tx.clone(),
                    runtime.allow.clone(),
                    runtime.dialer.clone(),
                    control::StatusCtx {
                        registry: runtime.registry.clone(),
                        generation: runtime.generation,
                        started_at_unix_ms: runtime.started_at_unix_ms,
                        listener_addr: runtime.listener_addr.clone(),
                    },
                );
            }
        }
    }
    Ok(runtime.listener)
}

fn handle_scanner_accept(
    res: std::io::Result<(tokio::net::UnixStream, tokio::net::unix::SocketAddr)>,
    registry: &Arc<Mutex<ScannerRegistry>>,
    allow: &std::sync::RwLock<PeerAllowlist>,
    sidecar_tx: &mpsc::Sender<SessionMetadata>,
    identd_port: u16,
) {
    match res {
        Ok((stream, _)) => {
            let peer_check = {
                let allow = allow.read().unwrap();
                check_peer(&stream, &allow)
            };
            if let Err(e) = peer_check {
                tracing::warn!(error = %e, "scanner peer rejected");
                return;
            }
            spawn_request(registry.clone(), stream, sidecar_tx.clone(), identd_port);
        }
        Err(e) => tracing::warn!(error = %e, "scanner accept failed"),
    }
}

fn spawn_request(
    registry: Arc<Mutex<ScannerRegistry>>,
    stream: tokio::net::UnixStream,
    sidecar_tx: mpsc::Sender<SessionMetadata>,
    identd_port: u16,
) {
    tokio::spawn(async move {
        let (read_half, _write_half) = stream.into_split();
        let mut reader = FramedRead::new(read_half, LinesCodec::new_with_max_length(8192));
        let Some(line_res) = reader.next().await else {
            return;
        };
        let line = match line_res {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(error = %e, "scanner read error");
                return;
            }
        };
        drop(reader); // We don't reply on inbound UDS

        let req: ScanRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, line = %line, "scanner bad request");
                return;
            }
        };
        let id = {
            let mut r = registry.lock().unwrap();
            let id = r.next_id;
            r.next_id += 1;
            r.in_flight.insert(id);
            id
        };

        match req {
            ScanRequest::SessionObserved {
                client_ip,
                client_port,
                server_port,
                role,
                trace_id,
            } => {
                let ident = ident_lookup(&client_ip, client_port, server_port, identd_port).await;
                let peer = format!("{client_ip}:{client_port}");
                let meta = SessionMetadata {
                    peer: peer.clone(),
                    ident: ident.clone(),
                    trace_id: trace_id.clone(),
                };
                if let Err(e) = sidecar_tx.try_send(meta) {
                    tracing::debug!(
                        error = %e,
                        trace_id = %trace_id,
                        "sidecar channel full / closed; dropping metadata",
                    );
                }
                tracing::info!(
                    role = %role,
                    client = %peer,
                    trace_id = %trace_id,
                    server_port,
                    ident = ?ident,
                    "scan complete",
                );
            }
        }

        registry.lock().unwrap().in_flight.remove(&id);
    });
}

/// Dial `client_ip:identd_port` (identd), send "`client_port,server_port\r\n`", read one line back, return
/// the trailing field. 2s timeout. Failures are normal (most hosts don't run identd); we can return
/// None.
async fn ident_lookup(
    client_ip: &str,
    client_port: u16,
    server_port: u16,
    identd_port: u16,
) -> Option<String> {
    let addr = format!("{client_ip}:{identd_port}");
    let dial = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::TcpStream::connect(&addr),
    );
    let stream = match dial.await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            tracing::debug!(addr = %addr, error = %e, "identd dial failed");
            return None;
        }
        Err(_) => {
            tracing::debug!(addr = %addr, "identd dial timed out");
            return None;
        }
    };
    ident_exchange(stream, client_port, server_port).await
}

/// Given an already-connected identd stream, send the `client_port,server_port` query and read one
/// line back (2s write + 2s read timeout). Split out from `ident_lookup` so the post-dial exchange
/// can be unit-tested over an in-memory duplex, without binding privileged port 113.
async fn ident_exchange<S>(mut stream: S, client_port: u16, server_port: u16) -> Option<String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let req = format!("{client_port},{server_port}\r\n");
    match tokio::time::timeout(
        Duration::from_secs(2),
        write_ident_request(&mut stream, req.as_bytes()),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            tracing::debug!(error = %e, "identd write failed");
            return None;
        }
        Err(_) => {
            tracing::debug!("identd write timed out");
            return None;
        }
    }
    let mut buf = Vec::with_capacity(256);
    let read = tokio::time::timeout(Duration::from_secs(2), async {
        use tokio::io::AsyncReadExt;
        let mut tmp = [0u8; 256];
        let n = stream.read(&mut tmp).await.ok()?;
        buf.extend_from_slice(&tmp[..n]);
        Some(())
    })
    .await;
    if read.is_err() || buf.is_empty() {
        return None;
    }
    let line = String::from_utf8_lossy(&buf).trim().to_string();
    Some(line)
}

async fn write_ident_request<W>(writer: &mut W, req: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io,
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::io::AsyncWrite;

    struct AlwaysErrWriter;

    impl AsyncWrite for AlwaysErrWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::Error::other("write failed")))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn write_ident_request_propagates_write_error() {
        let mut writer = AlwaysErrWriter;
        let err = write_ident_request(&mut writer, b"1,2\r\n")
            .await
            .expect_err("write should fail");
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }

    /// Mock RFC-1413 server. Binds on an OS-assigned port, accepts one connection at a time,
    /// parses the `lport,rport` query, and replies `lport, rport : USERID : UNIX : <username>`.
    /// Aborted on drop.
    struct MockIdentd {
        port: u16,
        handle: tokio::task::JoinHandle<()>,
    }

    impl MockIdentd {
        async fn start(username: impl Into<String> + Send + 'static) -> Self {
            use tokio::{
                io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
                net::TcpListener,
            };
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let username: String = username.into();
            let handle = tokio::spawn(async move {
                loop {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        break;
                    };
                    let username = username.clone();
                    tokio::spawn(async move {
                        let (rd, mut wr) = stream.split();
                        let mut lines = BufReader::new(rd).lines();
                        if let Ok(Some(line)) = lines.next_line().await {
                            let query = line.trim().to_string();
                            let parts: Vec<&str> = query.splitn(2, ',').collect();
                            let response = if parts.len() == 2 {
                                let lport = parts[0].trim();
                                let rport = parts[1].trim();
                                format!("{lport}, {rport} : USERID : UNIX : {username}\r\n")
                            } else {
                                format!("{query} : ERROR : INVALID-PORT\r\n")
                            };
                            let _ = wr.write_all(response.as_bytes()).await;
                        }
                    });
                }
            });
            Self { port, handle }
        }

        fn port(&self) -> u16 {
            self.port
        }
    }

    impl Drop for MockIdentd {
        fn drop(&mut self) {
            self.handle.abort();
        }
    }

    #[test]
    fn scan_request_deserializes_session_observed() {
        let json = r#"{"type":"session_observed","client_ip":"1.2.3.4","client_port":1234,"server_port":7070,"role":"plain","trace_id":"abc123"}"#;
        let req: ScanRequest = serde_json::from_str(json).unwrap();
        match req {
            ScanRequest::SessionObserved {
                client_ip,
                client_port,
                server_port,
                role,
                trace_id,
            } => {
                assert_eq!(client_ip, "1.2.3.4");
                assert_eq!(client_port, 1234);
                assert_eq!(server_port, 7070);
                assert_eq!(role, "plain");
                assert_eq!(trace_id, "abc123");
            }
        }
    }

    #[test]
    fn scan_request_trace_id_defaults_to_empty_string() {
        let json = r#"{"type":"session_observed","client_ip":"10.0.0.1","client_port":9999,"server_port":7071,"role":"tls"}"#;
        let req: ScanRequest = serde_json::from_str(json).unwrap();
        match req {
            ScanRequest::SessionObserved { trace_id, .. } => assert_eq!(trace_id, ""),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ident_lookup_returns_username_from_mock_identd() {
        let mock = MockIdentd::start("alice").await;
        let result = ident_lookup("127.0.0.1", 12345, 7070, mock.port()).await;
        assert_eq!(
            result.as_deref(),
            Some("12345, 7070 : USERID : UNIX : alice")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ident_lookup_returns_none_when_nothing_listens() {
        // Port 1 is almost certainly unbound; dial should fail fast and return None.
        let result = ident_lookup("127.0.0.1", 12345, 7070, 1).await;
        assert_eq!(result, None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ident_lookup_returns_none_when_server_closes_without_responding() {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let _ = stream.read(&mut buf).await;
            // drop stream → FIN, client reads 0 bytes → buf stays empty
        });
        let result = ident_lookup("127.0.0.1", 12345, 7070, port).await;
        assert_eq!(result, None, "empty response should yield None");
    }

    #[tokio::test]
    async fn ident_exchange_returns_trimmed_reply() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (client, mut server) = tokio::io::duplex(1024);
        let srv = tokio::spawn(async move {
            let mut buf = [0u8; 64];
            let n = server.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"5000,113\r\n");
            server
                .write_all(b"5000, 113 : USERID : UNIX : alice\r\n")
                .await
                .unwrap();
        });
        let got = ident_exchange(client, 5000, 113).await;
        srv.await.unwrap();
        assert_eq!(got.as_deref(), Some("5000, 113 : USERID : UNIX : alice"));
    }

    #[tokio::test]
    async fn ident_exchange_write_error_returns_none() {
        let (client, server) = tokio::io::duplex(64);
        drop(server);
        assert_eq!(ident_exchange(client, 1, 2).await, None);
    }

    #[tokio::test]
    async fn ident_exchange_empty_reply_returns_none() {
        let (client, mut server) = tokio::io::duplex(1024);
        let srv = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut buf = [0u8; 64];
            let _ = server.read(&mut buf).await.unwrap();
            drop(server);
        });
        assert_eq!(ident_exchange(client, 1, 2).await, None);
        srv.await.unwrap();
    }
}
