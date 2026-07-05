mod admin;
mod control;
mod drainer;
mod listeners;
mod metrics;
mod self_upgrade;
mod spawner;
mod watchdog;
mod worker;

use std::env;
use std::fs;
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::{
    net::UnixListener,
    net::unix::OwnedWriteHalf,
    signal::unix::{SignalKind, signal},
    task::JoinHandle,
};

use crate::{
    auth::{PeerAllowlist, SharedAllowlist},
    config::Config,
    handoff::{
        ENV_CTRL_ADMIN_FD, ENV_CTRL_DRAINER_FD, ENV_CTRL_PLAIN_FD, ENV_CTRL_PROCESSOR_FD,
        ENV_CTRL_SCANNER_FD, ENV_CTRL_SPAWNER_FD, ENV_CTRL_TLS_FD, ENV_LISTENER_PLAIN_FD,
        ENV_LISTENER_PROCESSOR_FD, ENV_LISTENER_SCANNER_FD, ENV_LISTENER_TLS_FD, ENV_PLAIN_GEN,
        ENV_PLAIN_PID, ENV_PROCESSOR_GEN, ENV_PROCESSOR_PID, ENV_SCANNER_GEN, ENV_SCANNER_PID,
        ENV_SUP_GENERATION, ENV_TLS_GEN, ENV_TLS_PID, ENV_UNDER_GRANDPARENT, now_unix_ms,
        signal_ready_to_parent,
    },
    metrics::UpgradeCounters,
    systemd::{self, SdListeners},
};
use admin::{accept_admin, rolling_upgrade};
use control::{
    ControlWriter, WorkerLink, accept_control, query_status, send_drain, send_reload,
    send_shutdown, send_upgrade,
};
use drainer::{accept_drainer, send_sigterm};
use listeners::{
    adopt_or_bind_control, adopt_or_bind_tcp_worker, adopt_or_bind_uds_worker, env_pid,
};
use metrics::run_metrics_writer;
use self_upgrade::{AdoptedState, ControlFds, do_self_upgrade};
use spawner::{SpawnerFds, accept_spawner};
use watchdog::{Watchdogs, watchdogs_init, watchdogs_snapshot};
use worker::{
    AcceptorRole, RoleSupervisor, spawn_acceptor, spawn_processor, spawn_scanner, supervise_role,
};

#[derive(Clone)]
pub(super) struct WorkerControlLinks {
    processor: ControlWriter,
    plain: ControlWriter,
    tls: ControlWriter,
    scanner: ControlWriter,
}

struct SupervisorPaths {
    processor_sock: PathBuf,
    scanner_sock: PathBuf,
    admin_sock: PathBuf,
    drainer_sock: PathBuf,
    ctrl_processor: PathBuf,
    ctrl_plain: PathBuf,
    ctrl_tls: PathBuf,
    ctrl_scanner: PathBuf,
    spawner_sock: PathBuf,
}

impl SupervisorPaths {
    fn from_config(config: &Config) -> Self {
        Self {
            processor_sock: config.processor_sock(),
            scanner_sock: config.scanner_sock(),
            admin_sock: config.admin_sock(),
            drainer_sock: config.drainer_sock(),
            ctrl_processor: config.control_sock("processor"),
            ctrl_plain: config.control_sock("plain"),
            ctrl_tls: config.control_sock("tls"),
            ctrl_scanner: config.control_sock("scanner"),
            spawner_sock: config.spawner_sock(),
        }
    }
}

struct ControlListeners {
    admin: UnixListener,
    processor: UnixListener,
    plain: UnixListener,
    tls: UnixListener,
    scanner: UnixListener,
    drainer: UnixListener,
    spawner: UnixListener,
}

struct SupervisorListeners {
    controls: ControlListeners,
    fds: ControlFds,
}

struct PidSlots {
    processor: Arc<std::sync::Mutex<Option<u32>>>,
    plain: Arc<std::sync::Mutex<Option<u32>>>,
    tls: Arc<std::sync::Mutex<Option<u32>>>,
    scanner: Arc<std::sync::Mutex<Option<u32>>>,
}

impl PidSlots {
    fn new() -> Self {
        Self {
            processor: Arc::new(std::sync::Mutex::new(None)),
            plain: Arc::new(std::sync::Mutex::new(None)),
            tls: Arc::new(std::sync::Mutex::new(None)),
            scanner: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// Snapshot the live worker PIDs together with each worker's last-reported generation (read
    /// from its control link) for the self-upgrade handoff. PIDs are read first into locals so no
    /// std `MutexGuard` is held across the async link locks.
    async fn snapshot(&self, links: &WorkerControlLinks) -> AdoptedState {
        let (processor, plain, tls, scanner) = (
            *self.processor.lock().unwrap(),
            *self.plain.lock().unwrap(),
            *self.tls.lock().unwrap(),
            *self.scanner.lock().unwrap(),
        );
        let processor_gen = links.processor.lock().await.last_generation.unwrap_or(0);
        let plain_gen = links.plain.lock().await.last_generation.unwrap_or(0);
        let tls_gen = links.tls.lock().await.last_generation.unwrap_or(0);
        let scanner_gen = links.scanner.lock().await.last_generation.unwrap_or(0);
        AdoptedState {
            processor,
            plain,
            tls,
            scanner,
            processor_gen,
            plain_gen,
            tls_gen,
            scanner_gen,
        }
    }
}

struct WorkerTasks {
    processor: JoinHandle<()>,
    plain: JoinHandle<()>,
    tls: JoinHandle<()>,
    scanner: JoinHandle<()>,
}

/// Parse a worker-generation env var handed across a supervisor self-upgrade. Absent or unparseable
/// means gen 0 (fresh start / no adopted worker for that role).
fn env_generation(key: &str) -> u64 {
    env::var(key).ok().and_then(|s| s.parse().ok()).unwrap_or(0)
}

async fn open_supervisor_listeners(
    config: &Config,
    paths: &SupervisorPaths,
    generation: u64,
) -> Result<SupervisorListeners> {
    let mut sd = SdListeners::from_env().context("read systemd listeners")?;
    let is_upgrade = generation > 0;

    let (admin, admin_fd) = adopt_control(
        ENV_CTRL_ADMIN_FD,
        "admin",
        &paths.admin_sock,
        is_upgrade,
        &mut sd,
    )
    .await?;
    let (processor, processor_fd) = adopt_control(
        ENV_CTRL_PROCESSOR_FD,
        "ctrl-processor",
        &paths.ctrl_processor,
        is_upgrade,
        &mut sd,
    )
    .await?;
    let (plain, plain_fd) = adopt_control(
        ENV_CTRL_PLAIN_FD,
        "ctrl-plain",
        &paths.ctrl_plain,
        is_upgrade,
        &mut sd,
    )
    .await?;
    let (tls, tls_fd) = adopt_control(
        ENV_CTRL_TLS_FD,
        "ctrl-tls",
        &paths.ctrl_tls,
        is_upgrade,
        &mut sd,
    )
    .await?;
    let (scanner, scanner_fd) = adopt_control(
        ENV_CTRL_SCANNER_FD,
        "ctrl-scanner",
        &paths.ctrl_scanner,
        is_upgrade,
        &mut sd,
    )
    .await?;
    let (drainer, drainer_fd) = adopt_control(
        ENV_CTRL_DRAINER_FD,
        "drainer",
        &paths.drainer_sock,
        is_upgrade,
        &mut sd,
    )
    .await?;
    let (spawner, spawner_fd) = adopt_control(
        ENV_CTRL_SPAWNER_FD,
        "spawner",
        &paths.spawner_sock,
        is_upgrade,
        &mut sd,
    )
    .await?;

    let worker_fds = open_worker_listener_fds(config, paths, is_upgrade, &mut sd)?;
    if !sd.is_empty() {
        tracing::warn!("systemd handed us listener FDs we didn't claim by name");
    }

    Ok(SupervisorListeners {
        controls: ControlListeners {
            admin,
            processor,
            plain,
            tls,
            scanner,
            drainer,
            spawner,
        },
        fds: ControlFds {
            admin: admin_fd,
            processor_ctrl: processor_fd,
            plain_ctrl: plain_fd,
            tls_ctrl: tls_fd,
            scanner_ctrl: scanner_fd,
            drainer: drainer_fd,
            spawner: spawner_fd,
            processor_listener: worker_fds.processor,
            plain_listener: worker_fds.plain,
            tls_listener: worker_fds.tls,
            scanner_listener: worker_fds.scanner,
        },
    })
}

async fn adopt_control(
    env_key: &str,
    sd_name: &str,
    path: &std::path::Path,
    is_upgrade: bool,
    sd: &mut SdListeners,
) -> Result<(UnixListener, RawFd)> {
    adopt_or_bind_control(env_key, sd_name, path, is_upgrade, sd).await
}

fn open_worker_listener_fds(
    config: &Config,
    paths: &SupervisorPaths,
    is_upgrade: bool,
    sd: &mut SdListeners,
) -> Result<SpawnerFds> {
    let (processor, _) = adopt_or_bind_uds_worker(
        ENV_LISTENER_PROCESSOR_FD,
        "processor",
        &paths.processor_sock,
        is_upgrade,
        sd,
    )?;
    let (scanner, _) = adopt_or_bind_uds_worker(
        ENV_LISTENER_SCANNER_FD,
        "scanner",
        &paths.scanner_sock,
        is_upgrade,
        sd,
    )?;
    let plain = adopt_or_bind_tcp_worker(ENV_LISTENER_PLAIN_FD, "plain", config.plain_port, sd)?;
    let tls = adopt_or_bind_tcp_worker(ENV_LISTENER_TLS_FD, "tls", config.tls_port, sd)?;
    Ok(SpawnerFds {
        processor,
        plain,
        tls,
        scanner,
    })
}

fn cleanup_socket_files(paths: &SupervisorPaths) {
    let _ = fs::remove_file(&paths.admin_sock);
    let _ = fs::remove_file(&paths.ctrl_processor);
    let _ = fs::remove_file(&paths.ctrl_plain);
    let _ = fs::remove_file(&paths.ctrl_tls);
    let _ = fs::remove_file(&paths.ctrl_scanner);
    let _ = fs::remove_file(&paths.drainer_sock);
    let _ = fs::remove_file(&paths.spawner_sock);
    let _ = fs::remove_file(&paths.processor_sock);
    let _ = fs::remove_file(&paths.scanner_sock);
}

fn new_worker_links() -> WorkerControlLinks {
    WorkerControlLinks {
        processor: Arc::new(tokio::sync::Mutex::new(WorkerLink::default())),
        plain: Arc::new(tokio::sync::Mutex::new(WorkerLink::default())),
        tls: Arc::new(tokio::sync::Mutex::new(WorkerLink::default())),
        scanner: Arc::new(tokio::sync::Mutex::new(WorkerLink::default())),
    }
}

fn spawn_control_services(
    controls: ControlListeners,
    fds: &ControlFds,
    worker_links: &WorkerControlLinks,
    watchdogs: &Watchdogs,
    upgrade_counters: &Arc<UpgradeCounters>,
    allow: SharedAllowlist,
    upgrade_lock: Arc<tokio::sync::Mutex<()>>,
) {
    tokio::spawn(accept_control(
        controls.processor,
        worker_links.processor.clone(),
        "processor",
        allow.clone(),
    ));
    tokio::spawn(accept_control(
        controls.plain,
        worker_links.plain.clone(),
        "plain",
        allow.clone(),
    ));
    tokio::spawn(accept_control(
        controls.tls,
        worker_links.tls.clone(),
        "tls",
        allow.clone(),
    ));
    tokio::spawn(accept_control(
        controls.scanner,
        worker_links.scanner.clone(),
        "scanner",
        allow.clone(),
    ));
    tokio::spawn(accept_drainer(controls.drainer, allow.clone()));
    tokio::spawn(accept_spawner(
        controls.spawner,
        SpawnerFds {
            processor: fds.processor_listener,
            plain: fds.plain_listener,
            tls: fds.tls_listener,
            scanner: fds.scanner_listener,
        },
        allow.clone(),
    ));
    tokio::spawn(accept_admin(
        controls.admin,
        admin::AdminState {
            links: worker_links.clone(),
            watchdogs: watchdogs.clone(),
            upgrade_counters: upgrade_counters.clone(),
            allow: allow.clone(),
            upgrade_lock,
        },
        allow,
    ));
}

fn spawn_worker_tasks(
    shutdown: &Arc<AtomicBool>,
    worker_links: &WorkerControlLinks,
    watchdogs: &Watchdogs,
    adopted: &AdoptedState,
    pids: &PidSlots,
) -> WorkerTasks {
    WorkerTasks {
        processor: tokio::spawn(supervise_role(
            RoleSupervisor {
                shutdown: shutdown.clone(),
                role: "processor",
                current_pid: pids.processor.clone(),
                adopted_pid: adopted.processor,
                adopted_gen: adopted.processor_gen,
                watchdogs: watchdogs.clone(),
                link: worker_links.processor.clone(),
            },
            spawn_processor,
        )),
        plain: tokio::spawn(supervise_role(
            RoleSupervisor {
                shutdown: shutdown.clone(),
                role: "plain",
                current_pid: pids.plain.clone(),
                adopted_pid: adopted.plain,
                adopted_gen: adopted.plain_gen,
                watchdogs: watchdogs.clone(),
                link: worker_links.plain.clone(),
            },
            || spawn_acceptor(AcceptorRole::Plain),
        )),
        tls: tokio::spawn(supervise_role(
            RoleSupervisor {
                shutdown: shutdown.clone(),
                role: "tls",
                current_pid: pids.tls.clone(),
                adopted_pid: adopted.tls,
                adopted_gen: adopted.tls_gen,
                watchdogs: watchdogs.clone(),
                link: worker_links.tls.clone(),
            },
            || spawn_acceptor(AcceptorRole::Tls),
        )),
        scanner: tokio::spawn(supervise_role(
            RoleSupervisor {
                shutdown: shutdown.clone(),
                role: "scanner",
                current_pid: pids.scanner.clone(),
                adopted_pid: adopted.scanner,
                adopted_gen: adopted.scanner_gen,
                watchdogs: watchdogs.clone(),
                link: worker_links.scanner.clone(),
            },
            spawn_scanner,
        )),
    }
}

fn start_health_endpoint(config: &Config, watchdogs: &Watchdogs) {
    if config.health.bind_addr.is_empty() {
        return;
    }
    let bind = config.health.bind_addr.clone();
    let wdc = watchdogs.clone();
    let snapshot_fn = Arc::new(move || watchdogs_snapshot(&wdc));
    tokio::spawn(async move {
        if let Err(e) = crate::health::run_health_server(bind, snapshot_fn).await {
            tracing::warn!(error = %e, "health endpoint exited");
        }
    });
}

fn start_metrics_writer(
    config: &Config,
    worker_links: &WorkerControlLinks,
    watchdogs: &Watchdogs,
    upgrade_counters: &Arc<UpgradeCounters>,
    generation: u64,
) {
    if config.metrics.path.as_os_str().is_empty() {
        return;
    }
    let interval = Duration::from_secs(config.metrics.interval_secs.max(1));
    let metrics_path = config.metrics.path.clone();
    let links = worker_links.clone();
    let watchdogs = watchdogs.clone();
    let upgrade_counters = upgrade_counters.clone();
    let started_at_unix_ms = now_unix_ms();
    tokio::spawn(async move {
        run_metrics_writer(
            metrics::MetricsWriterConfig {
                path: metrics_path,
                interval,
                sup_generation: generation,
                started_at_unix_ms,
            },
            links,
            watchdogs,
            upgrade_counters,
        )
        .await;
    });
}

struct SupervisorLoop<'a> {
    config: &'a Config,
    fds: &'a ControlFds,
    worker_links: &'a WorkerControlLinks,
    watchdogs: &'a Watchdogs,
    upgrade_counters: &'a Arc<UpgradeCounters>,
    pids: &'a PidSlots,
    generation: u64,
    upgrade_lock: &'a Arc<tokio::sync::Mutex<()>>,
}

async fn run_supervisor_loop(runtime: SupervisorLoop<'_>) -> Result<()> {
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigusr2 = signal(SignalKind::user_defined2())?;
    let mut sighup = signal(SignalKind::hangup())?;

    let watchdog_beacon = systemd::WatchdogBeacon::new();
    let _watchdog = systemd::spawn_watchdog(watchdog_beacon.clone());
    let mut beacon_ticker = tokio::time::interval(systemd::beacon_tick_interval());
    beacon_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    signal_ready_to_parent().context("signal ready")?;
    systemd::notify_ready();
    systemd::notify_status(&format!("ready (generation {})", runtime.generation));

    loop {
        tokio::select! {
            _ = sigterm.recv() => { tracing::info!("SIGTERM received"); break; }
            _ = sigint.recv() => { tracing::info!("SIGINT received"); break; }
            _ = beacon_ticker.tick() => { watchdog_beacon.tick(); }
            _ = sigusr2.recv() => {
                run_signal_upgrade(
                    runtime.worker_links,
                    runtime.watchdogs,
                    runtime.upgrade_counters,
                    runtime.upgrade_lock,
                ).await;
            }
            _ = sighup.recv() => {
                // Under grandparent mode the supervisor's process::exit(UPGRADE_COMMIT_EXIT_CODE)
                // triggers grandparent's killpg, which kills the successor it just handed off to.
                // Refuse the self-upgrade and document the workaround instead.
                if std::env::var(ENV_UNDER_GRANDPARENT).is_ok() {
                    tracing::warn!(
                        "SIGHUP ignored: supervisor self-upgrade is not supported under \
                         grandparent mode (process::exit would trigger killpg on the successor). \
                         Restart the grandparent process to upgrade the supervisor binary."
                    );
                } else {
                    tracing::info!("SIGHUP received; self-upgrading supervisor");
                    let pids = runtime.pids.snapshot(runtime.worker_links).await;
                    if let Err(e) = do_self_upgrade(
                        runtime.fds,
                        &pids,
                        runtime.generation,
                        runtime.config,
                    ).await {
                        tracing::error!(error = %e, "self-upgrade failed; continuing as-is");
                    }
                }
            }
        }
    }
    Ok(())
}

async fn run_signal_upgrade(
    worker_links: &WorkerControlLinks,
    watchdogs: &Watchdogs,
    upgrade_counters: &Arc<UpgradeCounters>,
    upgrade_lock: &Arc<tokio::sync::Mutex<()>>,
) {
    tracing::info!("SIGUSR2 received; starting rolling Upgrade");
    let mut no_sink: Option<OwnedWriteHalf> = None;
    let ok = rolling_upgrade(
        worker_links,
        admin::RollingUpgradeRequest {
            binary_path: None,
            include_tls: false,
            canary_secs: None,
            only_role: None,
        },
        watchdogs,
        upgrade_counters,
        &mut no_sink,
        upgrade_lock,
    )
    .await;
    tracing::info!(all_ok = ok, "SIGUSR2 rolling upgrade done");
}

async fn shutdown_supervisor(
    shutdown: &Arc<AtomicBool>,
    worker_links: &WorkerControlLinks,
    pids: &PidSlots,
    tasks: WorkerTasks,
) {
    shutdown.store(true, Ordering::SeqCst);
    tracing::info!("propagating shutdown");
    systemd::notify_stopping();

    send_shutdown(&worker_links.plain, 1000).await;
    send_shutdown(&worker_links.tls, 1000).await;
    send_shutdown(&worker_links.scanner, 500).await;
    send_shutdown(&worker_links.processor, 500).await;

    let processor_pid = *pids.processor.lock().unwrap();
    if let Some(pid) = processor_pid {
        send_sigterm(pid);
    }

    let drain = Duration::from_millis(1500);
    let _ = tokio::time::timeout(drain, async {
        let _ = tokio::join!(tasks.processor, tasks.plain, tasks.tls, tasks.scanner);
    })
    .await;
}

pub async fn run(config: Config) -> Result<()> {
    let generation: u64 = env::var(ENV_SUP_GENERATION)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    tracing::info!(generation, "supervisor generation");

    let paths = SupervisorPaths::from_config(&config);
    let listeners = open_supervisor_listeners(&config, &paths, generation).await?;
    let SupervisorListeners { controls, fds } = listeners;

    // The legacy "remove processor_sock if generation 0" cleanup is gone: supervisor now owns and
    // binds /tmp/fdpass-proc.sock itself via the adopt_or_bind_uds_worker call above. Removing it
    // after the bind would unlink the live socket file out from under everyone.

    let adopted = AdoptedState {
        processor: env_pid(ENV_PROCESSOR_PID),
        plain: env_pid(ENV_PLAIN_PID),
        tls: env_pid(ENV_TLS_PID),
        scanner: env_pid(ENV_SCANNER_PID),
        processor_gen: env_generation(ENV_PROCESSOR_GEN),
        plain_gen: env_generation(ENV_PLAIN_GEN),
        tls_gen: env_generation(ENV_TLS_GEN),
        scanner_gen: env_generation(ENV_SCANNER_GEN),
    };

    // Stale FDPASS_* vars don't need scrubbing here: every worker Command routes through
    // `child_command` -> `scrub_fdpass_env`, so children get a clean env regardless of what we
    // still hold in our own.

    let worker_links = new_worker_links();
    let allow: SharedAllowlist = Arc::new(std::sync::RwLock::new(PeerAllowlist::from_config(
        &config.auth.allowed_uids,
    )));
    let watchdogs: Watchdogs = watchdogs_init();
    let upgrade_counters = Arc::new(UpgradeCounters::new());
    let upgrade_lock = Arc::new(tokio::sync::Mutex::new(()));
    spawn_control_services(
        controls,
        &fds,
        &worker_links,
        &watchdogs,
        &upgrade_counters,
        allow,
        upgrade_lock.clone(),
    );

    let shutdown = Arc::new(AtomicBool::new(false));
    let pid_slots = PidSlots::new();
    let worker_tasks =
        spawn_worker_tasks(&shutdown, &worker_links, &watchdogs, &adopted, &pid_slots);

    start_health_endpoint(&config, &watchdogs);
    start_metrics_writer(
        &config,
        &worker_links,
        &watchdogs,
        &upgrade_counters,
        generation,
    );

    run_supervisor_loop(SupervisorLoop {
        config: &config,
        fds: &fds,
        worker_links: &worker_links,
        watchdogs: &watchdogs,
        upgrade_counters: &upgrade_counters,
        pids: &pid_slots,
        generation,
        upgrade_lock: &upgrade_lock,
    })
    .await?;

    shutdown_supervisor(&shutdown, &worker_links, &pid_slots, worker_tasks).await;
    cleanup_socket_files(&paths);

    tracing::info!("supervisor exiting");
    Ok(())
}
