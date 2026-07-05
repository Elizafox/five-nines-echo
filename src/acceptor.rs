mod control;
mod data;
mod tls_cert;
mod tls_client;
mod tls_drain;
mod upgrade;

use std::env;
use std::sync::{
    Arc, Mutex, RwLock,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::{net::TcpListener, sync::watch};
use tokio_rustls::TlsAcceptor;

use crate::{
    config::Config,
    handoff::{
        ENV_UPGRADE_GENERATION, HandoffDirFds, SelfExe, new_trace_id, now_unix_ms, open_self_exe,
        signal_ready_to_parent,
    },
    limits::AcceptorLimits,
    security::{apply_sandbox, drop_privileges},
    worker_common,
};
use control::{ControlActions, StatusCtx, UpgradeReq, run_control_client};
use data::{AcceptedClient, ClientRegistry, ClientRuntime, fire_scan_request, spawn_client};
use tls_cert::TlsCertSource;
use upgrade::{AcceptorUpgradeContext, do_upgrade};

#[derive(Copy, Clone, Debug)]
pub enum Role {
    Plain,
    Tls,
}

impl Role {
    pub(super) fn name(self) -> &'static str {
        match self {
            Role::Plain => "plain",
            Role::Tls => "tls",
        }
    }
    pub(super) fn arg(self) -> &'static str {
        self.name()
    }
    fn port(self, config: &Config) -> u16 {
        match self {
            Role::Plain => config.plain_port,
            Role::Tls => config.tls_port,
        }
    }
}

pub async fn run(role: Role, mut config: Config) -> Result<()> {
    let port: u16 = role.port(&config);
    let control_basename = Config::socket_basename(&format!("ctrl-{}", role.name()));
    // SocketsDialer wraps both the path and (on FreeBSD) a Capsicum-rights-limited dir FD so the
    // per-accept UDS dials work under cap_enter.
    let dialer =
        Arc::new(worker_common::SocketsDialer::open(&config.sockets_dir).context("open sockets")?);

    let generation: u64 = env::var(ENV_UPGRADE_GENERATION)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    tracing::info!(
        role = role.name(),
        generation,
        "acceptor role config loaded"
    );

    // TLS cert source. On FreeBSD this pre-opens the cert/key parent dirs as caps-rights-limited
    // FDs *before* `apply_sandbox` (below) so SIGHUP/admin reload can `openat()` them after
    // `cap_enter()`; elsewhere it just remembers the paths. Plain has no TLS, so the option is None
    // there.
    let tls_cert_source: Option<TlsCertSource> = match role {
        Role::Plain => None,
        Role::Tls => Some(TlsCertSource::open(&config.tls).context("open TLS cert source")?),
    };
    // For TLS we hold the acceptor behind an `RwLock` so SIGHUP can swap in a freshly-loaded
    // cert/key pair without restarting the role. Plain has no acceptor; the option is None there.
    let tls_acceptor: Option<Arc<RwLock<TlsAcceptor>>> = match &tls_cert_source {
        None => None,
        Some(src) => Some(Arc::new(RwLock::new(
            src.build_acceptor().context("build initial TLS acceptor")?,
        ))),
    };

    let listener = adopt_or_bind_listener(role, port, &config).await?;
    let started_at_unix_ms = now_unix_ms();
    let limits = AcceptorLimits::from_config(&config.limits);

    // Self-exe path+FD for fexecve under cap_enter; see processor.rs.
    let self_exe = Arc::new(open_self_exe().context("open self exe")?);

    // TLS cert is already loaded above; safe to drop privileges now.
    drop_privileges(role.name(), &mut config.security)?;
    apply_sandbox(role.name(), &config.security)?;
    // Signal "ready" to the parent (if any) so it commits the upgrade.
    signal_ready_to_parent().context("signal ready")?;
    let listener_addr = listener
        .local_addr()
        .map_or_else(|_| format!("127.0.0.1:{port}"), |a| a.to_string());

    let registry: Arc<Mutex<ClientRegistry>> = Arc::new(Mutex::new(ClientRegistry::default()));
    let client_runtime = ClientRuntime {
        role,
        registry: registry.clone(),
        dialer: dialer.clone(),
        tls_acceptor: tls_acceptor.clone(),
        tls_idle: Duration::from_secs(config.limits.tls_idle_timeout_secs),
    };

    let (shutdown, shutdown_rx) = watch::channel(None::<u64>);
    let (upgrade, upgrade_rx) = watch::channel::<Option<UpgradeReq>>(None);
    let (drain, drain_rx) = watch::channel(false);
    let (reload, reload_rx) = watch::channel(0u64);

    // Hand the control client *clones* of the action senders and keep the
    // originals alive for the accept loop's lifetime (bound below, dropped at
    // end of `run`). The control connection is torn down mid-upgrade; if the
    // task owned the only senders, dropping them would make every
    // `*_rx.changed()` resolve `Err` immediately and spuriously fire the
    // shutdown arm — killing the acceptor (and its in-flight sessions) right
    // after an upgrade rollback.
    let control_actions = ControlActions {
        shutdown: shutdown.clone(),
        upgrade: upgrade.clone(),
        drain: drain.clone(),
        reload: reload.clone(),
    };
    spawn_acceptor_control(
        control_basename.clone(),
        dialer.clone(),
        control_actions.clone(),
        StatusCtx {
            role: role.name().to_string(),
            registry: registry.clone(),
            generation,
            started_at_unix_ms,
            listener_addr: listener_addr.clone(),
            rate_limiter: limits.rate.clone(),
        },
    );

    let drained = Arc::new(AtomicBool::new(false));
    let result = run_acceptor_loop(AcceptorLoop {
        listener,
        role,
        generation,
        config: &config,
        dialer,
        registry,
        client_runtime,
        limits,
        self_exe: &self_exe,
        tls_cert_source: tls_cert_source.as_ref(),
        tls_acceptor: tls_acceptor.as_ref(),
        drained,
        shutdown_rx,
        upgrade_rx,
        drain_rx,
        reload_rx,
        control_basename,
        control_actions,
        started_at_unix_ms,
        listener_addr,
    })
    .await;
    // Keep the action senders alive until the accept loop exits so a dropped
    // control connection can't make `*_rx.changed()` resolve early (see above).
    drop((shutdown, upgrade, drain, reload));
    result
}

fn spawn_acceptor_control(
    basename: String,
    dialer: Arc<worker_common::SocketsDialer>,
    actions: ControlActions,
    ctx: StatusCtx,
) {
    tokio::spawn(async move {
        if let Err(e) = run_control_client(dialer, basename, actions, ctx).await {
            tracing::warn!(error = %e, "control-plane client exited");
        }
    });
}

struct AcceptorLoop<'a> {
    listener: TcpListener,
    role: Role,
    generation: u64,
    config: &'a Config,
    dialer: Arc<worker_common::SocketsDialer>,
    registry: Arc<Mutex<ClientRegistry>>,
    client_runtime: ClientRuntime,
    limits: AcceptorLimits,
    self_exe: &'a SelfExe,
    tls_cert_source: Option<&'a TlsCertSource>,
    tls_acceptor: Option<&'a Arc<RwLock<TlsAcceptor>>>,
    drained: Arc<AtomicBool>,
    shutdown_rx: watch::Receiver<Option<u64>>,
    upgrade_rx: watch::Receiver<Option<UpgradeReq>>,
    drain_rx: watch::Receiver<bool>,
    reload_rx: watch::Receiver<u64>,
    // Stored so we can respawn the control client if a rollback leaves the worker without one.
    control_basename: String,
    control_actions: ControlActions,
    started_at_unix_ms: u64,
    listener_addr: String,
}

async fn run_acceptor_loop(mut runtime: AcceptorLoop<'_>) -> Result<()> {
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    #[cfg(coverage)]
    let mut cov_sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    loop {
        tokio::select! {
            res = runtime.listener.accept() => handle_acceptor_accept(res, &runtime),
            _ = runtime.shutdown_rx.changed() => {
                let grace = runtime.shutdown_rx.borrow().unwrap_or(0);
                tracing::info!(grace_ms = grace, "shutdown requested, stopping accept");
                tokio::time::sleep(Duration::from_millis(grace)).await;
                return Ok(());
            }
            _ = runtime.upgrade_rx.changed() => {
                let req = runtime.upgrade_rx.borrow().clone();
                let Some(req) = req else { continue };
                let dirs = HandoffDirFds {
                    sockets: runtime.dialer.dir_raw_fd(),
                    cert: runtime.tls_cert_source.and_then(TlsCertSource::cert_dir_raw_fd),
                    key: runtime.tls_cert_source.and_then(TlsCertSource::key_dir_raw_fd),
                };
                tracing::info!(role = runtime.role.name(), binary_path = ?req.binary_path, "upgrade requested");
                runtime.listener = do_upgrade(
                    runtime.listener,
                    runtime.registry.clone(),
                    AcceptorUpgradeContext {
                        role: runtime.role,
                        generation: runtime.generation,
                        binary_path: req.binary_path,
                        config: runtime.config,
                        self_exe: runtime.self_exe,
                        dirs,
                    },
                ).await?;
                // Only reached on rollback (commit calls process::exit). The control client
                // set terminal=true on the Upgrade message and exited; respawn it so the
                // supervisor can still reach this worker.
                tracing::info!(role = runtime.role.name(), "upgrade rolled back; respawning control client");
                spawn_acceptor_control(
                    runtime.control_basename.clone(),
                    runtime.dialer.clone(),
                    runtime.control_actions.clone(),
                    StatusCtx {
                        role: runtime.role.name().to_string(),
                        registry: runtime.registry.clone(),
                        generation: runtime.generation,
                        started_at_unix_ms: runtime.started_at_unix_ms,
                        listener_addr: runtime.listener_addr.clone(),
                        rate_limiter: runtime.limits.rate.clone(),
                    },
                );
            }
            _ = runtime.drain_rx.changed() => {
                if *runtime.drain_rx.borrow() && !runtime.drained.load(Ordering::Relaxed) {
                    runtime.drained.store(true, Ordering::Relaxed);
                    tracing::info!(role = runtime.role.name(), "drained: new accepts will be dropped; existing sessions continue");
                }
            }
            _ = runtime.reload_rx.changed() => {
                reload_tls(runtime.tls_acceptor, runtime.tls_cert_source, "admin");
            }
            _ = sighup.recv() => {
                if runtime.tls_acceptor.is_some() {
                    reload_tls(runtime.tls_acceptor, runtime.tls_cert_source, "SIGHUP");
                } else {
                    tracing::debug!(role = runtime.role.name(), "SIGHUP on plain role; ignoring");
                }
            }
            // Always-present arm whose future only resolves under cfg(coverage); in production it
            // is `pending()` and never fires (tokio::select! can't take `#[cfg]` on an arm).
            () = async {
                #[cfg(coverage)]
                {
                    cov_sigterm.recv().await;
                }
                #[cfg(not(coverage))]
                {
                    std::future::pending::<()>().await;
                }
            } => {
                crate::coverage::flush_coverage();
                return Ok(());
            }
        }
    }
}

fn handle_acceptor_accept(
    res: std::io::Result<(tokio::net::TcpStream, std::net::SocketAddr)>,
    runtime: &AcceptorLoop<'_>,
) {
    let (tcp, peer) = match res {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "tcp accept failed");
            return;
        }
    };
    tracing::debug!(?peer, "accepted client");
    if runtime.drained.load(Ordering::Relaxed) {
        tracing::debug!(role = runtime.role.name(), peer = %peer, "drained: dropping accept");
        return;
    }
    if !runtime.limits.rate.try_take(peer.ip()) {
        tracing::warn!(role = runtime.role.name(), peer = %peer, "rate-limited: dropping accept");
        return;
    }
    let Some(guard) = runtime.limits.sessions.try_acquire() else {
        tracing::warn!(
            role = runtime.role.name(),
            peer = %peer,
            in_flight = runtime.limits.sessions.current(),
            "session cap reached: accept-then-close",
        );
        return;
    };
    let trace_id = new_trace_id();
    fire_scan_request(
        runtime.role,
        &peer,
        runtime.role.port(runtime.config),
        runtime.dialer.clone(),
        trace_id.clone(),
    );
    spawn_client(
        runtime.client_runtime.clone(),
        AcceptedClient {
            tcp,
            peer_addr: peer.to_string(),
            guard,
            trace_id,
        },
    );
}

fn reload_tls(
    tls_acceptor: Option<&Arc<RwLock<TlsAcceptor>>>,
    tls_cert_source: Option<&TlsCertSource>,
    source: &str,
) {
    let (Some(slot), Some(src)) = (tls_acceptor, tls_cert_source) else {
        return;
    };
    match src.build_acceptor() {
        Ok(new) => {
            *slot.write().unwrap() = new;
            // The trigger is named in the message text (not just the `source`
            // field) so log-scrapers and the e2e cert-reload test can match
            // "reloaded on SIGHUP" / "reloaded via admin reload".
            let trigger = match source {
                "SIGHUP" => "on SIGHUP",
                _ => "via admin reload",
            };
            tracing::info!(
                cert = %src.cert_path.display(),
                key = %src.key_path.display(),
                source,
                "TLS cert/key reloaded {trigger}",
            );
        }
        Err(e) => {
            tracing::error!(error = %e, source, "TLS reload failed; keeping previous cert/key");
        }
    }
}

async fn adopt_or_bind_listener(
    role: Role,
    port: u16,
    config: &Config,
) -> Result<tokio::net::TcpListener> {
    let addr = format!("127.0.0.1:{port}");
    worker_common::adopt_or_bind_tcp_listener(&addr, role.name(), config).await
}
