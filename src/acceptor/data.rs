use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::oneshot,
};
use tokio_rustls::TlsAcceptor;

use crate::{config::Config, limits::SessionGuard, scanner::ScanRequest, worker_common};

use super::Role;

pub(in crate::acceptor) struct ClientHandle {
    pub(in crate::acceptor) cancel: oneshot::Sender<()>,
    /// `Some` for TLS: on upgrade we await this to recover the live rustls session state for the
    /// fork-and-drain path. Plain contains no per-client state in the acceptor; the acceptor
    /// forgets about plain clients the moment they're handed off.
    pub(in crate::acceptor) tls_handoff: Option<oneshot::Receiver<super::tls_drain::TlsHandoff>>,
}

#[derive(Default)]
pub(in crate::acceptor) struct ClientRegistry {
    pub(super) next_id: u64,
    pub(in crate::acceptor) clients: HashMap<u64, ClientHandle>,
}

#[derive(Clone)]
pub(in crate::acceptor) struct ClientRuntime {
    pub(in crate::acceptor) role: Role,
    pub(in crate::acceptor) registry: Arc<Mutex<ClientRegistry>>,
    pub(in crate::acceptor) dialer: Arc<worker_common::SocketsDialer>,
    pub(in crate::acceptor) tls_acceptor: Option<Arc<RwLock<TlsAcceptor>>>,
    pub(in crate::acceptor) tls_idle: Duration,
}

pub(in crate::acceptor) struct AcceptedClient {
    pub(in crate::acceptor) tcp: tokio::net::TcpStream,
    pub(in crate::acceptor) peer_addr: String,
    pub(in crate::acceptor) guard: SessionGuard,
    pub(in crate::acceptor) trace_id: String,
}

/// Fire-and-forget: dial the scanner UDS, write one JSON `SessionObserved` frame describing this
/// accept, drop the connection. Done in its own task so the accept loop never blocks on scanner
/// availability.
///
/// Dials via the `SocketsDialer` (not a raw `UnixStream::connect`) so the notification works after
/// FreeBSD `cap_enter()`; the acceptor is in capability mode, where a path-based connect to the
/// scanner would return ECAPMODE and the scan would silently never fire.
pub(in crate::acceptor) fn fire_scan_request(
    role: Role,
    peer: &std::net::SocketAddr,
    server_port: u16,
    dialer: Arc<worker_common::SocketsDialer>,
    trace_id: String,
) {
    let req = ScanRequest::SessionObserved {
        client_ip: peer.ip().to_string(),
        client_port: peer.port(),
        server_port,
        role: role.name().to_string(),
        trace_id,
    };
    tokio::spawn(async move {
        let Ok(mut line) = serde_json::to_string(&req) else {
            return;
        };
        line.push('\n');
        let scanner = Config::socket_basename("scanner");
        match tokio::time::timeout(Duration::from_millis(500), dialer.dial(&scanner)).await {
            Ok(Ok(mut s)) => {
                let _ = s.write_all(line.as_bytes()).await;
                let _ = s.shutdown().await;
            }
            Ok(Err(e)) => tracing::debug!(error = %e, "scanner UDS dial failed"),
            Err(_) => tracing::debug!("scanner UDS dial timed out"),
        }
    });
}

pub(in crate::acceptor) fn spawn_client(runtime: ClientRuntime, client: AcceptedClient) {
    let ClientRuntime {
        role,
        registry,
        dialer,
        tls_acceptor,
        tls_idle,
    } = runtime;
    let AcceptedClient {
        tcp,
        peer_addr,
        guard,
        trace_id,
    } = client;
    tcp.set_nodelay(true).ok();
    tracing::info!(role = role.name(), peer = %peer_addr, trace_id = %trace_id, "accepted client");
    match role {
        Role::Plain => {
            tokio::spawn(async move {
                let _guard = guard;
                if let Err(e) = bridge_plain_via_uds(&dialer, tcp, &peer_addr, &trace_id).await {
                    tracing::warn!(
                        error = %e,
                        peer = %peer_addr,
                        trace_id = %trace_id,
                        "plain bridge to processor failed",
                    );
                }
            });
        }
        Role::Tls => {
            let slot = tls_acceptor.expect("tls role without TlsAcceptor");
            let acceptor_now = slot.read().unwrap().clone();
            tokio::spawn(async move {
                let _guard = guard;
                let tls_ctx = super::tls_client::TlsClientContext {
                    registry,
                    tls_acceptor: acceptor_now,
                    dialer,
                    idle_timeout: tls_idle,
                };
                if let Err(e) =
                    super::tls_client::run_tls_client(tls_ctx, tcp, peer_addr, trace_id).await
                {
                    tracing::warn!(error = %e, "TLS client handling failed");
                }
            });
        }
    }
}

/// Plain-path delivery: keep the client TCP fd in the acceptor and byte-forward between the client
/// and a fresh processor UDS session — the TLS path
/// minus the crypto. Unlike the SCM handoff, the acceptor stays in the data path for the whole
/// session, so the caller's accept `SessionGuard` bounds the live plain-session count here rather
/// than in the processor.
///
/// Each direction is its own spawned task over an owned split half — the canonical robust proxy
/// shape. (Reusing `tls_client::bidirectional_with_idle`, which drives both directions from one
/// `select!` over `tokio::io::split` halves sharing a waker, exhibited a release-only ping-pong
/// stall where a request's echo was withheld until the next request arrived; two independently
/// scheduled tasks avoid it and deliver each echo immediately, matching SCM's "echo until close".)
async fn bridge_plain_via_uds(
    dialer: &worker_common::SocketsDialer,
    tcp: tokio::net::TcpStream,
    peer: &str,
    trace_id: &str,
) -> Result<()> {
    let uds = super::tls_client::open_processor_session(dialer, peer, "plain", trace_id)
        .await
        .context("open processor session for plain bridge")?;
    let (mut client_rd, mut client_wr) = tcp.into_split();
    let (mut proc_rd, mut proc_wr) = uds.into_split();
    let up = tokio::spawn(async move { pump(&mut client_rd, &mut proc_wr).await });
    let down = tokio::spawn(async move { pump(&mut proc_rd, &mut client_wr).await });
    // Await both: the first half-close shuts down its write side, cascading EOF to the peer pump, so
    // both drain before we drop the fds and release the session guard.
    let _ = tokio::join!(up, down);
    Ok(())
}

/// One-directional byte pump: copy reads to writes until EOF/error, then half-close the writer so
/// the peer pump observes EOF.
async fn pump<R, W>(r: &mut R, w: &mut W)
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 8192];
    loop {
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if w.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        }
    }
    let _ = w.shutdown().await;
}
