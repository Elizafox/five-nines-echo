use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use futures::StreamExt;
use tokio::{io::AsyncWriteExt, net::unix::OwnedWriteHalf};
use tokio_util::codec::{FramedRead, LinesCodec};

use crate::{
    auth::{SharedAllowlist, check_peer},
    config::Config,
    control::{
        AdminResp, ControlMsg, HealthState, UpgradePhase, WorkerStatus, envelope_line,
        parse_envelope,
    },
    metrics::UpgradeCounters,
};

use super::{
    ControlWriter, WorkerControlLinks, query_status, send_drain, send_reload, send_shutdown,
    send_upgrade,
    watchdog::{Watchdogs, watchdog_health_state, watchdogs_snapshot},
};

#[derive(Clone)]
pub(super) struct AdminState {
    pub(super) links: WorkerControlLinks,
    pub(super) watchdogs: Watchdogs,
    pub(super) upgrade_counters: Arc<UpgradeCounters>,
    pub(super) allow: SharedAllowlist,
    /// Held for the duration of a rolling upgrade so concurrent admin connections and SIGUSR2
    /// don't interleave on the same `WorkerLinks`. `try_lock` — no queue, immediate error.
    pub(super) upgrade_lock: Arc<tokio::sync::Mutex<()>>,
}

pub(super) struct RollingUpgradeRequest {
    pub(super) binary_path: Option<PathBuf>,
    pub(super) include_tls: bool,
    pub(super) canary_secs: Option<u64>,
    /// Restrict the upgrade to this single worker instead of walking all roles. See
    /// `ControlMsg::Upgrade::only_role`.
    pub(super) only_role: Option<String>,
}

/// Sequential, health-checked upgrade. Walks processor -> plain -> scanner (and TLS when
/// requested). For each snapshots generation, fires Upgrade, polls Status until generation rolls
/// forward. Stops on the first failure. Progress is streamed to `sink` if present (the admin-CLI
/// write half) and logged either way.
///
/// `upgrade_lock` is try-locked on entry; if already held by a concurrent upgrade, returns false
/// immediately so the two walks don't interleave on the same `WorkerLinks`.
pub(super) async fn rolling_upgrade(
    links: &WorkerControlLinks,
    req: RollingUpgradeRequest,
    watchdogs: &Watchdogs,
    counters: &UpgradeCounters,
    sink: &mut Option<OwnedWriteHalf>,
    upgrade_lock: &Arc<tokio::sync::Mutex<()>>,
) -> bool {
    let Ok(_guard) = upgrade_lock.try_lock() else {
        tracing::warn!("rolling upgrade already in progress; ignoring concurrent request");
        notify(sink, &AdminResp::UpgradeComplete { all_ok: false }).await;
        return false;
    };
    let mut targets: Vec<(&str, &ControlWriter)> = vec![
        ("processor", &links.processor),
        ("plain", &links.plain),
        ("scanner", &links.scanner),
    ];
    if req.include_tls {
        targets.push(("tls", &links.tls));
    }
    if let Some(only) = &req.only_role {
        // Single-role upgrade: ignore walk order / include_tls and upgrade just this worker.
        // Upgrading the processor alone is the routine zero-downtime path — its in-flight sessions
        // survive via UDS handoff — while the thin accept+bridge acceptor is left running.
        targets = match only.as_str() {
            "processor" => vec![("processor", &links.processor)],
            "plain" => vec![("plain", &links.plain)],
            "scanner" => vec![("scanner", &links.scanner)],
            "tls" => vec![("tls", &links.tls)],
            other => {
                tracing::warn!(only_role = %other, "upgrade --role names no known worker");
                notify(sink, &AdminResp::UpgradeComplete { all_ok: false }).await;
                return false;
            }
        };
    }

    let mut all_ok = true;
    for (role, link) in targets {
        let baseline_state = watchdog_health_state(watchdogs, role);
        if !upgrade_one(role, link, req.binary_path.clone(), counters, sink).await {
            all_ok = false;
            break;
        }
        if let Some(secs) = req.canary_secs
            && !canary_observe(role, secs, baseline_state, watchdogs, counters, sink).await
        {
            all_ok = false;
            break;
        }
    }
    notify(sink, &AdminResp::UpgradeComplete { all_ok }).await;
    all_ok
}

/// Watch a just-upgraded role for `secs` seconds; abort the walk only if its watchdog state gets
/// worse than the pre-upgrade baseline.
async fn canary_observe(
    role: &str,
    secs: u64,
    baseline_state: HealthState,
    watchdogs: &Watchdogs,
    counters: &UpgradeCounters,
    sink: &mut Option<OwnedWriteHalf>,
) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    let mut last_state = HealthState::Healthy;
    while tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let state = watchdog_health_state(watchdogs, role);
        last_state = state;
        if health_state_rank(state) > health_state_rank(baseline_state) {
            tracing::warn!(
                role,
                ?baseline_state,
                ?state,
                "canary: role regressed; aborting walk"
            );
            counters.incr_canary_aborted(role);
            notify(
                sink,
                &AdminResp::UpgradeStep {
                    worker: role.into(),
                    phase: UpgradePhase::CanaryAborted,
                    generation_before: None,
                    generation_after: None,
                    ok: false,
                    message: Some(format!("watchdog state {state:?}")),
                },
            )
            .await;
            return false;
        }
    }
    tracing::info!(
        role,
        ?baseline_state,
        ?last_state,
        secs,
        "canary: window clean"
    );
    true
}

fn health_state_rank(state: HealthState) -> u8 {
    match state {
        HealthState::Healthy => 0,
        HealthState::Backoff => 1,
        HealthState::Flapping => 2,
        HealthState::Failed => 3,
    }
}

fn reload_supervisor_allowlist(allow: &SharedAllowlist) -> Result<Vec<u32>> {
    let new = Config::load(None)?;
    let configured = new.auth.allowed_uids;
    let new_allow = crate::auth::PeerAllowlist::from_config(&configured);
    *allow.write().unwrap() = new_allow;
    Ok(configured)
}

async fn upgrade_one(
    role: &str,
    link: &ControlWriter,
    binary_path: Option<PathBuf>,
    counters: &UpgradeCounters,
    sink: &mut Option<OwnedWriteHalf>,
) -> bool {
    // TLS upgrade drains in-flight sessions before exec'ing, so give it more slack than the
    // immediate-exec workers.
    let poll_secs: u64 = if role == "tls" { 10 } else { 5 };
    let Some(pre) = query_status(link).await else {
        counters.incr_skipped(role);
        notify(
            sink,
            &AdminResp::UpgradeStep {
                worker: role.into(),
                phase: UpgradePhase::Skipped,
                generation_before: None,
                generation_after: None,
                ok: false,
                message: Some("no control connection".into()),
            },
        )
        .await;
        return false;
    };
    let pre_gen = pre.generation;

    notify(
        sink,
        &AdminResp::UpgradeStep {
            worker: role.into(),
            phase: UpgradePhase::Starting,
            generation_before: Some(pre_gen),
            generation_after: None,
            ok: true,
            message: None,
        },
    )
    .await;

    send_upgrade(link, binary_path).await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(poll_secs);
    loop {
        if tokio::time::Instant::now() > deadline {
            counters.incr_timed_out(role);
            notify(
                sink,
                &AdminResp::UpgradeStep {
                    worker: role.into(),
                    phase: UpgradePhase::Timeout,
                    generation_before: Some(pre_gen),
                    generation_after: None,
                    ok: false,
                    message: Some("worker did not reconnect with a new generation".into()),
                },
            )
            .await;
            return false;
        }
        if let Some(status) = query_status(link).await
            && status.generation > pre_gen
        {
            counters.incr_committed(role);
            notify(
                sink,
                &AdminResp::UpgradeStep {
                    worker: role.into(),
                    phase: UpgradePhase::Done,
                    generation_before: Some(pre_gen),
                    generation_after: Some(status.generation),
                    ok: true,
                    message: None,
                },
            )
            .await;
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn notify(sink: &mut Option<OwnedWriteHalf>, resp: &AdminResp) {
    tracing::info!(?resp, "upgrade progress");
    if let Some(w) = sink.as_mut() {
        let Ok(line) = envelope_line(resp) else {
            return;
        };
        if let Err(e) = w.write_all(line.as_bytes()).await {
            tracing::warn!(error = %e, "progress write failed");
        }
    }
}

pub(super) async fn accept_admin(
    listener: tokio::net::UnixListener,
    state: AdminState,
    allow: SharedAllowlist,
) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let peer_check = {
                    let allow = allow.read().unwrap();
                    check_peer(&stream, &allow)
                };
                if let Err(e) = peer_check {
                    tracing::warn!(error = %e, "admin peer rejected");
                    continue;
                }
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_admin_request(stream, state).await {
                        tracing::warn!(error = %e, "admin request failed");
                    }
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "admin accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

async fn handle_admin_request(stream: tokio::net::UnixStream, state: AdminState) -> Result<()> {
    let AdminState {
        links,
        watchdogs,
        upgrade_counters,
        allow,
        upgrade_lock,
    } = state;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = FramedRead::new(read_half, LinesCodec::new_with_max_length(64 * 1024));
    let Some(line) = reader.next().await else {
        return Ok(());
    };
    let line = line.context("admin read")?;
    let msg: ControlMsg =
        parse_envelope(&line).with_context(|| format!("incompatible admin message: {line}"))?;
    match msg {
        ControlMsg::Upgrade {
            binary_path,
            include_tls,
            canary_secs,
            only_role,
        } => {
            tracing::info!(
                ?binary_path,
                include_tls,
                ?canary_secs,
                ?only_role,
                "admin Upgrade received; starting rolling upgrade"
            );
            run_admin_upgrade(
                RollingUpgradeRequest {
                    binary_path,
                    include_tls,
                    canary_secs,
                    only_role,
                },
                write_half,
                &links,
                &watchdogs,
                &upgrade_counters,
                &upgrade_lock,
            )
            .await;
            return Ok(());
        }
        ControlMsg::Shutdown { grace_ms } => {
            tracing::info!(grace_ms, "admin Shutdown received; broadcasting");
            send_shutdown(&links.plain, grace_ms).await;
            send_shutdown(&links.tls, grace_ms).await;
            send_shutdown(&links.scanner, grace_ms.min(500)).await;
            send_shutdown(&links.processor, grace_ms.min(500)).await;
            write_admin_resp(&mut write_half, &AdminResp::Ok).await;
        }
        ControlMsg::Status => {
            tracing::debug!("admin Status received; querying workers");
            let (processor, plain, tls, scanner) = tokio::join!(
                query_status(&links.processor),
                query_status(&links.plain),
                query_status(&links.tls),
                query_status(&links.scanner),
            );
            let workers: Vec<WorkerStatus> = [processor, plain, tls, scanner]
                .into_iter()
                .flatten()
                .collect();
            let health = watchdogs_snapshot(&watchdogs);
            write_admin_resp(&mut write_half, &AdminResp::Status { workers, health }).await;
        }
        ControlMsg::Drain => {
            tracing::info!("admin Drain received; broadcasting to acceptors");
            // Acceptors only. Processor/scanner have nothing to "stop accepting" since their work
            // is driven by clients dialing through the acceptors.
            send_drain(&links.plain).await;
            send_drain(&links.tls).await;
            write_admin_resp(&mut write_half, &AdminResp::Ok).await;
        }
        ControlMsg::Reload => {
            tracing::info!("admin Reload received; broadcasting");
            match reload_supervisor_allowlist(&allow) {
                Ok(allowed_uids) => {
                    tracing::info!(
                        ?allowed_uids,
                        "admin Reload: supervisor allowlist refreshed"
                    );
                }
                Err(e) => {
                    tracing::error!(error = %e, "admin Reload: supervisor config load failed; keeping previous");
                }
            }
            // Every worker re-reads config from disk. Failures don't propagate up; workers log and
            // keep serving on old config.
            send_reload(&links.processor).await;
            send_reload(&links.plain).await;
            send_reload(&links.tls).await;
            send_reload(&links.scanner).await;
            write_admin_resp(&mut write_half, &AdminResp::Ok).await;
        }
    }
    let _ = write_half.shutdown().await;
    Ok(())
}

/// Run a rolling upgrade for an admin connection, streaming progress to `write_half` and closing it
/// when done. Split out of `handle_admin_request` to keep that dispatcher under the line-count lint.
async fn run_admin_upgrade(
    req: RollingUpgradeRequest,
    write_half: OwnedWriteHalf,
    links: &WorkerControlLinks,
    watchdogs: &Watchdogs,
    upgrade_counters: &UpgradeCounters,
    upgrade_lock: &Arc<tokio::sync::Mutex<()>>,
) {
    let mut sink: Option<OwnedWriteHalf> = Some(write_half);
    let _ = rolling_upgrade(
        links,
        req,
        watchdogs,
        upgrade_counters,
        &mut sink,
        upgrade_lock,
    )
    .await;
    if let Some(mut w) = sink {
        let _ = w.shutdown().await;
    }
}

async fn write_admin_resp(w: &mut OwnedWriteHalf, resp: &AdminResp) {
    let line = match envelope_line(resp) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "admin resp serialize failed");
            return;
        }
    };
    if let Err(e) = w.write_all(line.as_bytes()).await {
        tracing::warn!(error = %e, "admin resp write failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::HealthState;
    use std::path::PathBuf;
    use std::sync::RwLock;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn tmp_config_path(tag: &str) -> PathBuf {
        static CTR: AtomicU32 = AtomicU32::new(0);
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        PathBuf::from("/tmp").join(format!(
            "fdpass-supervisor-admin-test-{}-{tag}-{n}.toml",
            std::process::id()
        ))
    }

    #[test]
    fn canary_only_aborts_when_health_worsens() {
        assert!(health_state_rank(HealthState::Healthy) < health_state_rank(HealthState::Backoff));
        assert!(health_state_rank(HealthState::Backoff) < health_state_rank(HealthState::Flapping));
        assert!(health_state_rank(HealthState::Flapping) < health_state_rank(HealthState::Failed));
        assert!(health_state_rank(HealthState::Healthy) <= health_state_rank(HealthState::Healthy));
        assert!(health_state_rank(HealthState::Healthy) <= health_state_rank(HealthState::Backoff));
        assert!(health_state_rank(HealthState::Backoff) <= health_state_rank(HealthState::Backoff));
        assert!(
            health_state_rank(HealthState::Healthy) <= health_state_rank(HealthState::Flapping)
        );
        assert!(health_state_rank(HealthState::Backoff) > health_state_rank(HealthState::Healthy));
    }

    #[test]
    fn reload_supervisor_allowlist_replaces_current_policy() {
        let env_lock = crate::test_env::lock();
        let path = tmp_config_path("reload");
        std::fs::write(&path, "[auth]\nallowed_uids = [42, 7]\n").unwrap();
        let _config_env = crate::test_env::EnvVarGuard::set(
            &env_lock,
            crate::config::ENV_CONFIG_PATH,
            path.clone().into_os_string(),
        );

        let allow: SharedAllowlist =
            Arc::new(RwLock::new(crate::auth::PeerAllowlist::from_uids([
                999_999,
            ])));
        let configured = reload_supervisor_allowlist(&allow).unwrap();
        assert_eq!(configured, vec![42, 7]);
        let allow = allow.read().unwrap();
        assert!(allow.contains(42));
        assert!(allow.contains(7));
        assert!(!allow.contains(999_999));
        drop(allow);

        let _ = std::fs::remove_file(path);
    }
}
