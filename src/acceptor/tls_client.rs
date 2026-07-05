use std::os::unix::io::IntoRawFd;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::oneshot,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::{
    control::ProcessorPreamble,
    handoff::{duration_millis_u64, now_unix_ms},
    worker_common,
};

use super::{data::ClientHandle, data::ClientRegistry, tls_drain::TlsHandoff};

pub(super) struct TlsClientContext {
    pub(super) registry: Arc<Mutex<ClientRegistry>>,
    pub(super) tls_acceptor: TlsAcceptor,
    pub(super) dialer: Arc<worker_common::SocketsDialer>,
    pub(super) idle_timeout: Duration,
}

/// Why a `bidirectional_with_idle` bridge stopped.
pub(super) enum BridgeExit {
    /// One side closed or the idle timeout fired: the session is over, nothing to preserve.
    Ended,
    /// An upgrade cancel arrived and the streams were quiesced at a frame boundary — every byte read
    /// from a stream had already been written to its peer — so the caller can hand the live streams
    /// (and rustls state) to the fork-drain child without losing in-flight data.
    Cancelled,
}

/// Once the bridge is asked to stop (upgrade cancel, idle, or EOF), how long a direction wedged
/// mid-`write_all` (a peer that stopped reading) gets to finish before we tear down anyway. A live
/// peer drains a mid-flight frame in microseconds; this only bounds the dead-peer case so a stuck
/// write can't hang the upgrade or the idle reaper.
const BRIDGE_DRAIN_GRACE: Duration = Duration::from_millis(500);

/// Bidirectional byte copy with an idle timeout and cancellation. Closes the session when either
/// side EOFs, when no bytes flow in either direction for `idle` (`idle == 0` disables the timeout),
/// or when `cancel` fires (upgrade).
///
/// We split both streams and run one copy loop per direction. Each loop only checks for a stop
/// *before* a read, never between the read and its write, so a frame that was read is always fully
/// written to the peer before the loop winds down — an upgrade never drops bytes that were read from
/// one side but not yet handed to the other (the write-side twin of the processor's
/// `partial_line_bytes`). Each direction stamps a shared `last_activity`; a watchdog stops the
/// bridge if `idle` elapses with no progress. A drained peer that wedges a write past
/// `BRIDGE_DRAIN_GRACE` is abandoned rather than allowed to hang the caller.
pub(super) async fn bidirectional_with_idle<A, B>(
    a: &mut A,
    b: &mut B,
    idle: Duration,
    cancel: oneshot::Receiver<()>,
    peer: &str,
    trace_id: &str,
) -> BridgeExit
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let token = CancellationToken::new();
    let upgrade = Arc::new(AtomicBool::new(false));
    let last_ms = Arc::new(AtomicU64::new(now_unix_ms()));

    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);

    let dir1 = copy_direction(&mut ar, &mut bw, &token, &last_ms);
    let dir2 = copy_direction(&mut br, &mut aw, &token, &last_ms);

    let watchdog = {
        let token = token.clone();
        let last_ms = last_ms.clone();
        let peer = peer.to_string();
        let trace_id = trace_id.to_string();
        async move {
            if idle.is_zero() {
                // No idle timeout: stay out of the way until another stop reason cancels the token.
                token.cancelled().await;
                return;
            }
            let idle_ms = duration_millis_u64(idle);
            let interval = (idle / 4).max(Duration::from_millis(100));
            loop {
                tokio::select! {
                    () = token.cancelled() => return,
                    () = tokio::time::sleep(interval) => {}
                }
                if now_unix_ms().saturating_sub(last_ms.load(Ordering::Relaxed)) > idle_ms {
                    tracing::info!(peer = %peer, trace_id = %trace_id, idle_ms, "TLS session idle timeout");
                    token.cancel();
                    return;
                }
            }
        }
    };

    // Bridge the caller's oneshot upgrade-cancel into the token, recording that the stop was an
    // upgrade so the caller knows to hand off. `upgrade` is set synchronously (not via this future's
    // return) so the drain-grace teardown below can read it even if this future is dropped.
    let external = {
        let token = token.clone();
        let upgrade = upgrade.clone();
        async move {
            tokio::select! {
                r = cancel => {
                    if r.is_ok() {
                        upgrade.store(true, Ordering::SeqCst);
                        token.cancel();
                    } else {
                        // Sender dropped without an upgrade cancel; wait for a real stop reason.
                        token.cancelled().await;
                    }
                }
                () = token.cancelled() => {}
            }
        }
    };

    let bridge = async { tokio::join!(dir1, dir2, watchdog, external) };
    let drain_grace = {
        let token = token.clone();
        async move {
            token.cancelled().await;
            tokio::time::sleep(BRIDGE_DRAIN_GRACE).await;
        }
    };

    tokio::select! {
        _ = bridge => {}
        () = drain_grace => {
            tracing::debug!(peer, trace_id, "bridge drain grace elapsed with a write in flight; tearing down");
        }
    }

    if upgrade.load(Ordering::SeqCst) {
        BridgeExit::Cancelled
    } else {
        BridgeExit::Ended
    }
}

/// One direction of the bridge: copy `r`→`w` frame by frame until EOF, a write error, or `token`
/// cancellation, then cancel `token` so the sibling direction and the watchdog wind down too.
/// Cancellation is only observed *before* a read (never between the read and its write), so a frame
/// that was read is always fully written before this returns — no in-flight bytes are dropped.
async fn copy_direction<R, W>(r: &mut R, w: &mut W, token: &CancellationToken, last_ms: &AtomicU64)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 8192];
    loop {
        let n = tokio::select! {
            biased;
            () = token.cancelled() => break,
            // `AsyncReadExt::read` is cancel-safe: if the cancel branch wins, no bytes were taken.
            res = r.read(&mut buf) => match res {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            },
        };
        if w.write_all(&buf[..n]).await.is_err() {
            break;
        }
        last_ms.store(now_unix_ms(), Ordering::Relaxed);
    }
    token.cancel();
}

/// Open a fresh UDS to the processor and write the `Session` preamble before switching the stream
/// over to raw byte forwarding. The preamble lets the processor attribute this session to a TCP
/// peer (and lets the scanner's sidecar later bind metadata to it by peer string).
pub(super) async fn open_processor_session(
    dialer: &worker_common::SocketsDialer,
    peer: &str,
    role: &str,
    trace_id: &str,
) -> Result<tokio::net::UnixStream> {
    let mut uds = dialer
        .dial(&crate::config::Config::socket_basename("proc"))
        .await?;
    let preamble = ProcessorPreamble::Session {
        peer: peer.to_string(),
        role: role.to_string(),
        trace_id: trace_id.to_string(),
    };
    let mut line = serde_json::to_string(&preamble)?;
    line.push('\n');
    uds.write_all(line.as_bytes()).await?;
    Ok(uds)
}

pub(super) async fn run_tls_client(
    ctx: TlsClientContext,
    tcp: tokio::net::TcpStream,
    peer_addr: String,
    trace_id: String,
) -> Result<()> {
    let TlsClientContext {
        registry,
        tls_acceptor,
        dialer,
        idle_timeout,
    } = ctx;
    let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
    let (tls_handoff_tx, tls_handoff_rx) = oneshot::channel::<TlsHandoff>();
    let id = {
        let mut reg = registry.lock().unwrap();
        let id = reg.next_id;
        reg.next_id += 1;
        reg.clients.insert(
            id,
            ClientHandle {
                cancel: cancel_tx,
                tls_handoff: Some(tls_handoff_rx),
            },
        );
        id
    };
    let mut cancel_rx = cancel_rx;

    let mut tls = match tokio::select! {
        res = tls_acceptor.accept(tcp) => res,
        _ = &mut cancel_rx => {
            registry.lock().unwrap().clients.remove(&id);
            return Ok(());
        }
    } {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(error = %e, "tls handshake failed");
            registry.lock().unwrap().clients.remove(&id);
            return Ok(());
        }
    };

    let mut uds = match tokio::select! {
        res = open_processor_session(&dialer, &peer_addr, "tls", &trace_id) => res,
        _ = &mut cancel_rx => {
            registry.lock().unwrap().clients.remove(&id);
            return Ok(());
        }
    } {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "processor unavailable for TLS client");
            registry.lock().unwrap().clients.remove(&id);
            return Ok(());
        }
    };

    // The bridge drains both directions to a frame boundary before returning `Cancelled`, so the
    // streams handed off below carry no read-but-unwritten bytes (finding #6).
    let exit = bidirectional_with_idle(
        &mut tls,
        &mut uds,
        idle_timeout,
        cancel_rx,
        &peer_addr,
        &trace_id,
    )
    .await;
    if let BridgeExit::Cancelled = exit {
        let (tcp_stream, conn) = tls.into_inner();
        let result = (|| -> Result<()> {
            let std_tcp = tcp_stream.into_std().context("tcp into_std")?;
            let std_uds = uds.into_std().context("uds into_std")?;
            let tcp_fd = std_tcp.into_raw_fd();
            let uds_fd = std_uds.into_raw_fd();
            let _ = tls_handoff_tx.send(TlsHandoff {
                tcp_fd,
                uds_fd,
                conn,
                peer_addr,
            });
            Ok(())
        })();
        if let Err(e) = result {
            tracing::warn!(error = %e, "tls handoff build failed");
        }
    }
    registry.lock().unwrap().clients.remove(&id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use std::{
        path::PathBuf,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::TlsAcceptor;

    use crate::{
        acceptor::{ClientRegistry, tls_cert::TlsCertSource},
        config::TlsConfig,
        worker_common::SocketsDialer,
    };

    use tokio::sync::oneshot;

    use super::{BridgeExit, TlsClientContext, bidirectional_with_idle, run_tls_client};

    fn paired_duplex() -> (tokio::io::DuplexStream, tokio::io::DuplexStream) {
        tokio::io::duplex(4096)
    }

    fn test_tls_acceptor() -> TlsAcceptor {
        // Generate a throwaway self-signed cert per test run rather than relying on a committed key.
        // Keeps `cargo test` hermetic on a fresh clone (no `certs/gen.sh` prerequisite, no private
        // key in the repo). The dir/FDs are read eagerly by `build_acceptor`, so we clean up after.
        use rcgen::{CertifiedKey, generate_simple_self_signed};

        let dir = unique_test_dir("tls-acceptor-cert");
        std::fs::create_dir_all(&dir).unwrap();
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_path = dir.join("server.crt");
        let key_path = dir.join("server.key");
        std::fs::write(&cert_path, cert.pem()).unwrap();
        std::fs::write(&key_path, signing_key.serialize_pem()).unwrap();

        let source = TlsCertSource::open(&TlsConfig {
            cert_path,
            key_path,
        })
        .unwrap();
        let acceptor = source.build_acceptor().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        acceptor
    }

    fn unique_test_dir(name: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        dir.push(format!("five-nines-echo-{name}-{nonce}"));
        dir
    }

    #[tokio::test(flavor = "current_thread")]
    async fn idle_zero_bridges_without_timeout() {
        let (mut a_client, mut a_srv) = paired_duplex();
        let (mut b_client, mut b_srv) = paired_duplex();
        let (_cancel_tx, cancel_rx) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            bidirectional_with_idle(&mut a_srv, &mut b_srv, Duration::ZERO, cancel_rx, "p", "t")
                .await
        });
        a_client.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        b_client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
        drop(a_client);
        drop(b_client);
        let exit = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("bridge should finish after close")
            .unwrap();
        assert!(matches!(exit, BridgeExit::Ended));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancel_stops_bridge_and_reports_cancelled() {
        let (mut a_client, mut a_srv) = paired_duplex();
        let (mut b_client, mut b_srv) = paired_duplex();
        let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
        // Long idle timeout so only the cancel can end the bridge.
        let task = tokio::spawn(async move {
            bidirectional_with_idle(
                &mut a_srv,
                &mut b_srv,
                Duration::from_secs(30),
                cancel_rx,
                "p",
                "t",
            )
            .await
        });
        // Establish live traffic first so the bridge is mid-session when cancel arrives.
        a_client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        b_client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        // Upgrade cancel: the bridge must stop promptly and report Cancelled (hand-off path), not
        // Ended, having drained the in-flight frame to its peer first.
        cancel_tx.send(()).unwrap();
        let exit = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("bridge should stop promptly on cancel")
            .unwrap();
        assert!(matches!(exit, BridgeExit::Cancelled));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn idle_timeout_closes_silent_bridge() {
        let (a_client, mut a_srv) = paired_duplex();
        let (b_client, mut b_srv) = paired_duplex();
        let (_cancel_tx, cancel_rx) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            bidirectional_with_idle(
                &mut a_srv,
                &mut b_srv,
                Duration::from_millis(200),
                cancel_rx,
                "peer",
                "trace",
            )
            .await
        });
        let exit = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("idle bridge should exit within 1s")
            .unwrap();
        assert!(matches!(exit, BridgeExit::Ended));
        drop(a_client);
        drop(b_client);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn keepalive_holds_bridge_open() {
        let (mut a_client, mut a_srv) = paired_duplex();
        let (mut b_client, mut b_srv) = paired_duplex();
        let (_cancel_tx, cancel_rx) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            bidirectional_with_idle(
                &mut a_srv,
                &mut b_srv,
                Duration::from_millis(300),
                cancel_rx,
                "peer",
                "trace",
            )
            .await;
        });
        for _ in 0..5 {
            a_client.write_all(b"x").await.unwrap();
            let mut buf = [0u8; 1];
            b_client.read_exact(&mut buf).await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(!task.is_finished(), "bridge exited despite keepalive");
        task.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn failed_tls_handshake_does_not_open_processor_session() {
        let registry = Arc::new(Mutex::new(ClientRegistry::default()));
        let tls_acceptor = test_tls_acceptor();

        let sockets_dir = unique_test_dir("tls-handshake");
        std::fs::create_dir_all(&sockets_dir).unwrap();
        let proc_path = sockets_dir.join("proc");
        let proc_listener = tokio::net::UnixListener::bind(&proc_path).unwrap();
        let proc_hits = Arc::new(AtomicUsize::new(0));
        let proc_hits_task = {
            let proc_hits = proc_hits.clone();
            tokio::spawn(async move {
                if let Ok((_sock, _addr)) = proc_listener.accept().await {
                    proc_hits.fetch_add(1, Ordering::SeqCst);
                }
            })
        };
        let dialer = Arc::new(SocketsDialer::open(&sockets_dir).unwrap());

        let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = tcp_listener.local_addr().unwrap();
        let server = {
            let registry = registry.clone();
            let dialer = dialer.clone();
            tokio::spawn(async move {
                let (tcp, peer) = tcp_listener.accept().await.unwrap();
                run_tls_client(
                    TlsClientContext {
                        registry,
                        tls_acceptor,
                        dialer,
                        idle_timeout: Duration::from_millis(50),
                    },
                    tcp,
                    peer.to_string(),
                    "trace".to_string(),
                )
                .await
                .unwrap();
            })
        };

        let client = tokio::spawn(async move {
            let mut s = tokio::net::TcpStream::connect(peer_addr).await.unwrap();
            let _ = s.write_all(b"not tls").await;
        });

        client.await.unwrap();
        server.await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(proc_hits.load(Ordering::SeqCst), 0);
        assert!(registry.lock().unwrap().clients.is_empty());
        proc_hits_task.abort();
        let _ = tokio::fs::remove_file(proc_path).await;
        let _ = tokio::fs::remove_dir(&sockets_dir).await;
    }
}
