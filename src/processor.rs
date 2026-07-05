mod control;
mod sidecar;
mod upgrade;

use std::collections::HashMap;
use std::env;
use std::os::unix::io::IntoRawFd;
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};

use anyhow::{Context, Result};
use futures::{SinkExt, StreamExt};
use tokio::{
    net::UnixListener,
    signal::unix::{SignalKind, signal},
    sync::{oneshot, watch},
};
use tokio_util::codec::{Framed, LinesCodec};

use crate::{
    auth::{PeerAllowlist, check_peer},
    config::Config,
    control::{ProcessorPreamble, SessionMetadata},
    handoff::{
        ENV_UPGRADE_GENERATION, HandoffDirFds, SCHEMA_VERSION, SelfExe, SessionHandoff, Transport,
        now_unix_ms, open_self_exe, signal_ready_to_parent,
    },
    security::{apply_sandbox, drop_privileges},
    worker_common::{SocketsDialer, adopt_or_bind_uds_listener},
};
use control::{StatusCtx, run_control_client};
use sidecar::run_sidecar;
use upgrade::{
    ProcessorUpgradeContext, UpgradeReq, adopt_inflight_sessions, cleanup_generation_zero_socket,
    do_upgrade,
};

pub(in crate::processor) struct SessionHandle {
    pub(in crate::processor) cancel: oneshot::Sender<()>,
    pub(in crate::processor) handoff: oneshot::Receiver<SessionHandoff>,
    peer: String,
}

#[derive(Default)]
pub(in crate::processor) struct SessionRegistry {
    next_id: u64,
    pub(in crate::processor) sessions: HashMap<u64, SessionHandle>,
    /// Sidecar-published metadata: scanner pushes a `SessionMetadata` frame per scan completion; we
    /// stash it keyed by peer, so it's visible when we log echo activity for that session. Lazily
    /// evicted when a session ends.
    pub(in crate::processor) metadata: HashMap<String, SessionMetadata>,
}

pub async fn run(mut config: Config) -> Result<()> {
    let sock_path: PathBuf = config.processor_sock();
    let control_basename = Config::socket_basename("ctrl-processor");
    let generation: u64 = env::var(ENV_UPGRADE_GENERATION)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    tracing::info!(generation, "processor generation");

    let mut listener = adopt_or_bind_uds_listener(&sock_path, "processor", &config).await?;
    let started_at_unix_ms = now_unix_ms();

    let registry: Arc<Mutex<SessionRegistry>> = Arc::new(Mutex::new(SessionRegistry::default()));

    adopt_inflight_sessions(&registry).context("adopt in-flight sessions")?;

    // Allowlist is wrapped in RwLock so admin Reload can swap it without dropping live connections:
    // read lock per accept, write lock per reload
    let allow = Arc::new(std::sync::RwLock::new(PeerAllowlist::from_config(
        &config.auth.allowed_uids,
    )));

    // SocketsDialer wraps the control-plane dial path so it works under FreeBSD capsicum
    // `cap_enter()`. Must be opened before apply_sandbox.
    let dialer = Arc::new(SocketsDialer::open(&config.sockets_dir).context("open sockets")?);

    // Pre-resolve our own binary (path + FD) so the upgrade path doesn't touch the filesystem
    // namespace under FreeBSD `cap_enter()`. Must happen before apply_sandbox.
    let self_exe = Arc::new(open_self_exe().context("open self exe")?);

    // Drop privileges before signaling ready so a drop failure surfaces as a startup failure, not a
    // half-running worker.
    drop_privileges("processor", &mut config.security)?;
    apply_sandbox("processor", &config.security)?;

    // Past the point of no return: tell the parent (if any) we're alive
    signal_ready_to_parent().context("signal ready")?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (upgrade_tx, upgrade_rx) = watch::channel::<Option<UpgradeReq>>(None);

    // Hand the control client *clones* and keep the originals alive for the
    // loop's lifetime (dropped below). The control connection is torn down
    // mid-upgrade; if the task owned the only senders, dropping them would make
    // `upgrade_rx.changed()` resolve `Err` immediately while `borrow()` still
    // held the just-processed `Some(req)` — re-running (and committing) an
    // upgrade that had already rolled back. See the acceptor for the same guard.
    let listener_addr = sock_path.display().to_string();
    spawn_processor_control(
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

    listener = run_processor_loop(ProcessorLoop {
        listener,
        registry,
        allow,
        dialer,
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

    cleanup_generation_zero_socket(generation, &sock_path);

    Ok(())
}

fn spawn_processor_control(
    basename: String,
    shutdown_tx: watch::Sender<bool>,
    upgrade_tx: watch::Sender<Option<UpgradeReq>>,
    allow: Arc<std::sync::RwLock<PeerAllowlist>>,
    dialer: Arc<SocketsDialer>,
    ctx: StatusCtx,
) {
    tokio::spawn(async move {
        if let Err(e) =
            run_control_client(dialer, basename, shutdown_tx, upgrade_tx, allow, ctx).await
        {
            tracing::warn!(error = %e, "control-plane client exited");
        }
    });
}

struct ProcessorLoop<'a> {
    listener: UnixListener,
    registry: Arc<Mutex<SessionRegistry>>,
    allow: Arc<std::sync::RwLock<PeerAllowlist>>,
    dialer: Arc<SocketsDialer>,
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

async fn run_processor_loop(mut runtime: ProcessorLoop<'_>) -> Result<UnixListener> {
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    loop {
        tokio::select! {
            res = runtime.listener.accept() => handle_processor_accept(
                res,
                &runtime.registry,
                &runtime.allow,
            ),
            _ = sigterm.recv() => {
                tracing::info!("SIGTERM received, stopping accept");
                break;
            }
            _ = sigint.recv() => {
                tracing::info!("SIGINT received, stopping accept");
                break;
            }
            _ = runtime.shutdown_rx.changed() => {
                if *runtime.shutdown_rx.borrow() {
                    tracing::info!("control-plane Shutdown");
                    break;
                }
            }
            _ = runtime.upgrade_rx.changed() => {
                let req = runtime.upgrade_rx.borrow().clone();
                let Some(req) = req else { continue };
                tracing::info!(binary_path = ?req.binary_path, "upgrade requested");
                let dirs = HandoffDirFds {
                    sockets: runtime.dialer.dir_raw_fd(),
                    ..Default::default()
                };
                runtime.listener = do_upgrade(
                    runtime.listener,
                    runtime.registry.clone(),
                    ProcessorUpgradeContext {
                        generation: runtime.generation,
                        binary_path: req.binary_path,
                        config: runtime.config,
                        self_exe: runtime.self_exe,
                        dirs,
                    },
                ).await?;
                // Only reached on rollback (commit calls process::exit). Respawn the control
                // client that exited when it sent the Upgrade message.
                tracing::info!("processor upgrade rolled back; respawning control client");
                spawn_processor_control(
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

fn handle_processor_accept(
    res: std::io::Result<(tokio::net::UnixStream, tokio::net::unix::SocketAddr)>,
    registry: &Arc<Mutex<SessionRegistry>>,
    allow: &std::sync::RwLock<PeerAllowlist>,
) {
    match res {
        Ok((stream, _addr)) => {
            let peer_check = {
                let allow = allow.read().unwrap();
                check_peer(&stream, &allow)
            };
            if let Err(e) = peer_check {
                tracing::warn!(error = %e, "processor peer rejected");
                return;
            }
            dispatch_incoming(registry.clone(), stream);
        }
        Err(e) => tracing::warn!(error = %e, "accept failed"),
    }
}

/// Read the JSON preamble as the first framed line from a fresh UDS connection, then dispatch.
///
/// Two preamble variants, both fd-less — the plain and TLS acceptors and the scanner each open a
/// UDS, write a one-line preamble, then stream data on the same connection:
///   - `Session`: the rest of the connection is line-echo (plain or TLS plaintext, byte-bridged by
///     the acceptor)
///   - `Sidecar`: scanner pushing `SessionMetadata` frames
///
/// The preamble is just the first `LinesCodec` frame, so `Framed` owns the socket buffer from byte
/// zero: a preamble and first data line coalesced into a single read decode as two frames natively,
/// with no raw pre-read to hand off. (This replaced a custom `recvmsg` preamble reader whose only
/// reason to exist was grabbing an `SCM_RIGHTS` fd for the old plain-TCP handoff.)
fn dispatch_incoming(registry: Arc<Mutex<SessionRegistry>>, stream: tokio::net::UnixStream) {
    tokio::spawn(async move {
        if let Some(_f) = fault_inject!("processor.dispatch") {
            tracing::warn!("processor.dispatch fault injected; dropping connection");
            return;
        }
        let mut framed = Framed::new(stream, LinesCodec::new_with_max_length(64 * 1024));
        let line = match framed.next().await {
            Some(Ok(l)) => l,
            Some(Err(e)) => {
                tracing::warn!(error = %e, "preamble decode error");
                return;
            }
            None => {
                tracing::warn!("uds closed before preamble");
                return;
            }
        };
        let preamble: ProcessorPreamble = match serde_json::from_str(&line) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, line = %line, "bad processor preamble");
                return;
            }
        };
        match preamble {
            ProcessorPreamble::Session {
                peer,
                role,
                trace_id,
            } => {
                tracing::info!(peer = %peer, role = %role, trace_id = %trace_id, "new uds session");
                spawn_session(registry, framed, peer, 0, now_unix_ms(), trace_id);
            }
            ProcessorPreamble::Sidecar => {
                tracing::info!("scanner sidecar attached");
                run_sidecar(registry, framed).await;
            }
        }
    });
}

pub(in crate::processor) fn spawn_session(
    registry: Arc<Mutex<SessionRegistry>>,
    framed: Framed<tokio::net::UnixStream, LinesCodec>,
    peer: String,
    initial_count: u64,
    connected_at_unix_ms: u64,
    trace_id: String,
) {
    let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
    let (handoff_tx, handoff_rx) = oneshot::channel::<SessionHandoff>();
    let id = {
        let mut reg = registry.lock().unwrap();
        let id = reg.next_id;
        reg.next_id += 1;
        reg.sessions.insert(
            id,
            SessionHandle {
                cancel: cancel_tx,
                handoff: handoff_rx,
                peer: peer.clone(),
            },
        );
        id
    };

    let registry_clone = registry;
    let peer_for_task = peer;
    let trace_id_for_task = trace_id;
    tokio::spawn(async move {
        let counter = Arc::new(AtomicU64::new(initial_count));
        let mut framed = framed;
        tracing::info!(peer = %peer_for_task, trace_id = %trace_id_for_task, "session task started");

        // An adopted session may carry echo bytes that a pre-upgrade `send` was still flushing when
        // the old image cancelled it (`framed_with_lookahead` replays them into the write buffer).
        // Complete that flush before resuming so the interrupted echo lands intact instead of torn.
        // Fresh sessions have an empty write buffer and skip the flush entirely.
        if !framed.write_buffer().is_empty()
            && let Err(e) = SinkExt::<String>::flush(&mut framed).await
        {
            tracing::warn!(peer = %peer_for_task, trace_id = %trace_id_for_task, error = %e,
                "flush of adopted write buffer failed; ending session");
            registry_clone.lock().unwrap().sessions.remove(&id);
            return;
        }

        tokio::select! {
            () = echo_loop(&mut framed, counter.clone(), registry_clone.clone(), &peer_for_task, &trace_id_for_task) => {
                let mut reg = registry_clone.lock().unwrap();
                reg.sessions.remove(&id);
                // If this was the last live session for that peer, drop the sidecar metadata so it
                // doesn't pile up forever
                let still_used = reg.sessions.values().any(|h| h.peer == peer_for_task);
                if !still_used {
                    reg.metadata.remove(&peer_for_task);
                }
            }
            _ = cancel_rx => {
                // Capture both of LinesCodec's pending buffers before unwrapping to the raw stream:
                // the read buffer (bytes received but not yet decoded into a line) and the write
                // buffer (encoded echo bytes a `send` was still flushing when cancel fired). Losing
                // the latter would hand the client a torn echo whose completion it never sees.
                let saved_read = framed.read_buffer().to_vec();
                let saved_write = framed.write_buffer().to_vec();
                let stream = framed.into_inner();
                match stream.into_std() {
                    Ok(std_stream) => {
                        let fd = std_stream.into_raw_fd();
                        let _ = handoff_tx.send(SessionHandoff {
                            uds_fd: fd,
                            transport: Transport::Uds,
                            partial_line_bytes: saved_read,
                            pending_write_bytes: saved_write,
                            lines_echoed: counter.load(Ordering::SeqCst),
                            connected_at_unix_ms,
                            peer: peer_for_task,
                            // `do_upgrade` enriches this from the sidecar metadata map after
                            // awaiting the handoff; the session task itself doesn't see ident
                            ident: None,
                            trace_id: trace_id_for_task,
                            version: SCHEMA_VERSION,
                        });
                    }
                    Err(e) => tracing::warn!(error = %e, "session into_std failed"),
                }
            }
        }
    });
}

async fn echo_loop<S>(
    framed: &mut Framed<S, LinesCodec>,
    counter: Arc<AtomicU64>,
    registry: Arc<Mutex<SessionRegistry>>,
    peer: &str,
    trace_id: &str,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    while let Some(item) = framed.next().await {
        match item {
            Ok(line) => {
                if framed.send(line.clone()).await.is_err() {
                    return;
                }
                let count = counter.fetch_add(1, Ordering::SeqCst) + 1;
                let meta = registry.lock().unwrap().metadata.get(peer).cloned();
                tracing::debug!(
                    peer = %peer,
                    trace_id = %trace_id,
                    line_no = count,
                    bytes = line.len(),
                    ident = ?meta.as_ref().and_then(|m| m.ident.clone()),
                    "echoed",
                );
            }
            Err(_) => return,
        }
    }
}

// (Plain sessions now arrive as UDS bridges, same as TLS; there is no separate TCP-fd session path.
// `spawn_tcp_session` / `reconstruct_tcp` and the SCM handoff that fed them were removed.)
