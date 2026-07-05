use std::env;
use std::io;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use nix::{
    errno::Errno,
    sys::{
        signal::kill,
        wait::{WaitPidFlag, WaitStatus, waitpid},
    },
    unistd::Pid,
};
use tokio::process::Command;

use crate::handoff::{UPGRADE_COMMIT_EXIT_CODE, duration_millis_u64, scrub_fdpass_env};

use super::{
    ControlWriter,
    watchdog::{WatchdogEvent, Watchdogs, watchdog_record, watchdog_record_exit},
};

/// Outcome of `wait_for_successor`. `Adopted(gen)` means a worker at generation `gen` — strictly
/// greater than the baseline — has reported in; `Timeout` means none did within the window, so the
/// upgrade child is presumed dead and a fresh respawn is okay.
#[derive(Debug, PartialEq, Eq)]
enum SuccessorOutcome {
    Adopted(u64),
    Timeout,
}

/// Outcome of `monitor_successor`. `Readopted(gen)` means the worker we were supervising committed
/// its *own* upgrade — a successor at a strictly higher generation registered on the control link —
/// so we re-adopt it with the same generation-strict treatment the first adoption got instead of
/// mistaking the brief control-channel churn for a loss. `Lost` means the writer half was absent for
/// the full loss grace with no newer generation, so the successor is presumed dead: respawn fresh.
#[derive(Debug, PartialEq, Eq)]
enum MonitorOutcome {
    Readopted(u64),
    Lost,
}

/// Window to wait for the upgrade successor to register itself after the parent exits with
/// `UPGRADE_COMMIT_EXIT_CODE`. Matches the `rolling_upgrade` per-role poll timeout; if a successor
/// isn't there by then, the rolling upgrade has already given up on this role.
const SUCCESSOR_WAIT_TIMEOUT: Duration = Duration::from_secs(5);

/// Once a successor is adopted, how long the control connection may be gone before we declare it
/// dead and respawn. Long enough to ride out a brief reconnect (transient socket churn), yet short
/// enough that a real crash doesn't leave the role unsupervised for long.
const SUCCESSOR_LOSS_GRACE: Duration = Duration::from_secs(3);

/// Either a freshly-spawned tokio child or a PID we adopted across our own exec.
pub(super) enum ChildHandle {
    Owned(tokio::process::Child),
    Adopted(Pid),
}

impl ChildHandle {
    async fn wait(&mut self) -> io::Result<ExitStatus> {
        match self {
            ChildHandle::Owned(c) => c.wait().await,
            ChildHandle::Adopted(pid) => wait_adopted(*pid).await,
        }
    }

    fn pid(&self) -> Option<u32> {
        match self {
            ChildHandle::Owned(c) => c.id(),
            ChildHandle::Adopted(p) => u32::try_from(p.as_raw()).ok(),
        }
    }
}

fn is_process_alive(pid: u32) -> bool {
    // `kill(pid, None)` sends signal 0: pure permission/existence probe, no signal delivered. ESRCH
    // means the PID is gone; anything else (including EPERM, "exists but not ours") still means
    // it's alive.
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    !matches!(kill(Pid::from_raw(pid), None), Err(Errno::ESRCH))
}

/// Poll-based wait for an adopted PID. Uses non-blocking waitpid; if a sibling SIGCHLD reaper has
/// already collected the zombie, we fall back to a `kill(pid, 0)` liveness probe. We only need to
/// detect "child gone"; the exact exit code isn't used by the watchdog, so any `WaitStatus` that
/// signals termination collapses to `ExitStatus::from_raw(0)`.
async fn wait_adopted(pid: Pid) -> io::Result<ExitStatus> {
    loop {
        let outcome = tokio::task::spawn_blocking(move || {
            match waitpid(Some(pid), Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::StillAlive) => None,
                Ok(_) => Some(ExitStatus::from_raw(0)),
                Err(Errno::ECHILD) => {
                    // Not (or no longer) our child to reap. If the PID isn't
                    // alive either, it's gone; surface that as an exit.
                    if matches!(kill(pid, None), Err(Errno::ESRCH)) {
                        Some(ExitStatus::from_raw(0))
                    } else {
                        None
                    }
                }
                Err(e) => Some(ExitStatus::from_raw(e as i32)),
            }
        })
        .await
        .map_err(|e| io::Error::other(format!("spawn_blocking join: {e}")))?;

        if let Some(status) = outcome {
            return Ok(status);
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Single supervisor loop shared by every worker role. The differences between roles lives entirely
/// in `spawn_fn`: the role string, env wiring, and any role-specific args are captured by the
/// closure.
pub(super) struct RoleSupervisor {
    pub(super) shutdown: Arc<AtomicBool>,
    pub(super) role: &'static str,
    pub(super) current_pid: Arc<std::sync::Mutex<Option<u32>>>,
    pub(super) adopted_pid: Option<u32>,
    /// Generation of the worker we're adopting at startup (carried across a supervisor self-upgrade
    /// via `AdoptedState`), or 0 for a fresh spawn. Seeds `current_generation` so the first
    /// `wait_for_successor` baseline reflects an adopted gen-N worker instead of defaulting to 0.
    pub(super) adopted_gen: u64,
    pub(super) watchdogs: Watchdogs,
    pub(super) link: ControlWriter,
}

pub(super) async fn supervise_role<F>(supervisor: RoleSupervisor, mut spawn_fn: F)
where
    F: FnMut() -> io::Result<ChildHandle>,
{
    let RoleSupervisor {
        shutdown,
        role,
        current_pid,
        adopted_pid,
        adopted_gen,
        watchdogs,
        link,
    } = supervisor;

    // Generation of the worker currently running under us. A fresh spawn is 0; a worker adopted
    // across a supervisor self-upgrade starts at the generation it reported before the exec
    // (`adopted_gen`); an adopted successor advances to the generation it reports. Used both for the
    // "worker child active" log line and to seed the `wait_for_successor` baseline so an adopted
    // gen-N worker isn't mistaken for gen 0.
    let mut current_generation: u64 = adopted_gen;
    let mut next: Option<ChildHandle> = adopted_pid.and_then(|p| {
        if is_process_alive(p) {
            tracing::info!(role, pid = p, "adopting existing worker");
            watchdog_record(&watchdogs, role, WatchdogEvent::Adoption);
            let pid = i32::try_from(p).ok()?;
            Some(ChildHandle::Adopted(Pid::from_raw(pid)))
        } else {
            tracing::warn!(role, pid = p, "adopted worker pid not alive; will respawn");
            None
        }
    });

    while !shutdown.load(Ordering::SeqCst) {
        let mut child = if let Some(h) = next.take() {
            // The initial adopted worker (self-upgrade handoff); it runs at `adopted_gen`.
            h
        } else {
            // Any spawn we perform ourselves is a brand-new gen-0 process tree.
            current_generation = 0;
            watchdog_record(&watchdogs, role, WatchdogEvent::Spawn);
            match spawn_fn() {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(role, error = %e, "spawn worker failed");
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    continue;
                }
            }
        };
        if let Some(pid) = child.pid() {
            *current_pid.lock().unwrap() = Some(pid);
            tracing::info!(
                role,
                pid,
                generation = current_generation,
                "worker child active"
            );
        }
        // Snapshot the generation the outgoing worker reported before we wait for it to exit. We use
        // this as the baseline in wait_for_successor: the successor must report a strictly higher
        // generation than this, preventing a stale value left in the link from the old worker
        // (before its control-socket EOF is processed) from triggering a false Adopted. Fall back to
        // `current_generation` when the link hasn't populated yet — for an adopted gen-N worker that
        // is N, not 0, which is exactly what closes the adopted-worker race (review follow-up #2).
        let pre_upgrade_gen = link
            .lock()
            .await
            .last_generation
            .unwrap_or(current_generation);
        let status = child.wait().await;
        *current_pid.lock().unwrap() = None;
        // status comes from tokio's wait -> io::Result; on Err we treat as an abnormal exit (don't
        // pass UPGRADE_COMMIT code accidentally)
        let exit_status = status
            .as_ref()
            .cloned()
            .unwrap_or_else(|_| ExitStatus::from_raw(0));
        let backoff = watchdog_record_exit(&watchdogs, role, exit_status);
        tracing::warn!(role, ?status, ?backoff, "worker exited");
        if shutdown.load(Ordering::SeqCst) {
            break;
        }

        // Two-phase upgrade hand-off: the child exec'd a fresh image, the ready-pipe was ACK'd, and
        // the child exits with the sentinel after the successor connects. Without intervention, the
        // loop would happily spawn a fresh gen-0 worker right behind it, racing the successor for
        // the (last-write wins) control-plane slot. On Linux, the successor usually wins; on
        // FreeBSD under cap_enter it usually loses, and the rolling_upgrade reports Timeout. The
        // state machine below pauses the respawn until either the successor is observed (adopt +
        // monitor) or the wait window expires (rollback -> respawn).
        if exit_status.code() == Some(UPGRADE_COMMIT_EXIT_CODE) {
            match wait_for_successor(&link, pre_upgrade_gen, SUCCESSOR_WAIT_TIMEOUT).await {
                SuccessorOutcome::Adopted(generation) => {
                    supervise_adopted_successor(
                        &link,
                        role,
                        &current_pid,
                        &watchdogs,
                        pre_upgrade_gen,
                        generation,
                    )
                    .await;
                    // The respawn falls through to the loop's fresh-spawn branch, which resets
                    // `current_generation` to 0.
                    continue;
                }
                SuccessorOutcome::Timeout => {
                    tracing::warn!(
                        role,
                        pre_upgrade_gen,
                        timeout_ms = duration_millis_u64(SUCCESSOR_WAIT_TIMEOUT),
                        "successor never registered; respawning fresh after backoff",
                    );
                    // Successor crashed or never started. Fall through to the normal backoff +
                    // respawn path, which resets `current_generation` to 0 for the fresh worker.
                }
            }
        }

        tokio::time::sleep(backoff).await;
    }
    tracing::info!(role, "worker supervisor exiting");
}

/// Supervise an adopted upgrade successor — and any successors *it* produces by upgrading itself —
/// until the control link is lost. Entered after `wait_for_successor` adopts a successor at
/// `generation`. `monitor_successor` returns `Readopted` on a generation advance, so a 2nd- (or
/// Nth-) generation upgrade is recognized by generation just like the first, closing the window
/// where a successor slow to dial in would otherwise race a fresh gen-0 respawn (follow-up review
/// #6). Returns once the successor's control connection has been gone for `SUCCESSOR_LOSS_GRACE`,
/// at which point the caller respawns fresh.
async fn supervise_adopted_successor(
    link: &ControlWriter,
    role: &'static str,
    current_pid: &std::sync::Mutex<Option<u32>>,
    watchdogs: &Watchdogs,
    pre_upgrade_gen: u64,
    mut generation: u64,
) {
    loop {
        tracing::info!(
            role,
            pre_upgrade_gen,
            generation,
            "successor adopted; standing down respawn",
        );
        // Record the adoption so the watchdog treats the new worker as already-running (uptime
        // starts now, restart counter unbumped; we didn't spawn it).
        watchdog_record(watchdogs, role, WatchdogEvent::Adoption);
        // The successor is a grandchild we never spawned (the old worker fork + exec'd it), so we
        // hold no ChildHandle for it. Surface the PID it reported over the control link so
        // status/metrics show the live worker rather than None.
        *current_pid.lock().unwrap() = link.lock().await.last_pid;
        // Block until the successor either upgrades itself (generation advances -> re-adopt) or its
        // control connection is gone for `SUCCESSOR_LOSS_GRACE` (-> respawn), refreshing
        // `current_pid` from status reports meanwhile (the PID read above can be stale if the
        // successor hadn't reported yet).
        match monitor_successor(link, current_pid, generation, SUCCESSOR_LOSS_GRACE).await {
            MonitorOutcome::Readopted(new_gen) => {
                tracing::info!(
                    role,
                    generation = new_gen,
                    "adopted successor upgraded itself; re-adopting",
                );
                generation = new_gen;
            }
            MonitorOutcome::Lost => {
                *current_pid.lock().unwrap() = None;
                tracing::warn!(role, "adopted successor disappeared; respawning fresh");
                return;
            }
        }
    }
}

/// Poll `link.last_generation` until it is strictly greater than `old_gen` or the deadline passes.
/// Polling (instead of a notifier) keeps the change local to `WorkerLink`: every `StatusReport`
/// that comes in already updates it, so we just observe.
///
/// Requiring `seen > old_gen` (not `seen >= expected_min_gen`) prevents a stale generation that
/// the old worker left in the link — before the control-socket EOF has been processed — from
/// triggering a false `Adopted` during the race between `child.wait()` and EOF handling.
async fn wait_for_successor(
    link: &ControlWriter,
    old_gen: u64,
    timeout: Duration,
) -> SuccessorOutcome {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Some(seen) = link.lock().await.last_generation
            && seen > old_gen
        {
            return SuccessorOutcome::Adopted(seen);
        }
        if tokio::time::Instant::now() >= deadline {
            return SuccessorOutcome::Timeout;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Supervise an already-adopted successor running at generation `monitored_gen`.
///
/// Returns `Readopted(gen)` the moment a strictly-higher generation registers on the link: the
/// worker committed its own upgrade, so we re-adopt the new successor with the same
/// generation-strict treatment the first adoption got. This is what gives a second (or Nth)
/// generation upgrade the same protection as the first, instead of leaving it to ride on the
/// weaker writer-absence heuristic and race a fresh gen-0 respawn on transient control-channel
/// churn. The generation signal is reliable both ways: on a genuine loss the reader clears
/// `last_generation` to `None` (it still owns the epoch), while an upgrade's successor bumps the
/// epoch and reports its higher generation, so the old connection's teardown leaves it intact.
///
/// Returns `Lost` once the writer half has been absent continuously for at least `loss_grace` with
/// no newer generation. A brief disconnect-then-reconnect at the same generation (a worker
/// re-establishing its control channel) doesn't count. While the successor is connected, refresh
/// `current_pid` from its latest status report: the PID captured at adoption can be stale (the
/// dying worker's) if the successor hadn't reported yet, so keeping it current means status/metrics
/// track the live worker for its whole lifetime.
async fn monitor_successor(
    link: &ControlWriter,
    current_pid: &std::sync::Mutex<Option<u32>>,
    monitored_gen: u64,
    loss_grace: Duration,
) -> MonitorOutcome {
    let mut absent_since: Option<tokio::time::Instant> = None;
    loop {
        let (connected, last_pid, last_gen) = {
            let l = link.lock().await;
            (l.writer.is_some(), l.last_pid, l.last_generation)
        };
        if let Some(g) = last_gen
            && g > monitored_gen
        {
            return MonitorOutcome::Readopted(g);
        }
        match (connected, absent_since) {
            (true, _) => {
                absent_since = None;
                if last_pid.is_some() {
                    *current_pid.lock().unwrap() = last_pid;
                }
            }
            (false, None) => absent_since = Some(tokio::time::Instant::now()),
            (false, Some(t)) if t.elapsed() >= loss_grace => return MonitorOutcome::Lost,
            (false, _) => {}
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

pub(super) fn spawn_processor() -> io::Result<ChildHandle> {
    let mut cmd = child_command("processor");
    let child = cmd.spawn()?;
    tracing::info!(pid = ?child.id(), "processor spawned");
    Ok(ChildHandle::Owned(child))
}

pub(super) fn spawn_scanner() -> io::Result<ChildHandle> {
    let mut cmd = child_command("scanner");
    let child = cmd.spawn()?;
    tracing::info!(pid = ?child.id(), "scanner spawned");
    Ok(ChildHandle::Owned(child))
}

#[derive(Copy, Clone)]
pub(super) enum AcceptorRole {
    Plain,
    Tls,
}

impl AcceptorRole {
    fn arg(self) -> &'static str {
        match self {
            AcceptorRole::Plain => "plain",
            AcceptorRole::Tls => "tls",
        }
    }
}

pub(super) fn spawn_acceptor(role: AcceptorRole) -> io::Result<ChildHandle> {
    let mut cmd = child_command(role.arg());
    let child = cmd.spawn()?;
    tracing::info!(role = role.arg(), pid = ?child.id(), "acceptor spawned");
    Ok(ChildHandle::Owned(child))
}

fn child_command(sub: &str) -> Command {
    let exe = env::current_exe().expect("current_exe");
    let mut cmd = Command::new(exe);
    cmd.arg(sub).kill_on_drop(true);
    scrub_fdpass_env(cmd.as_std_mut());
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::WorkerLink;
    use tokio::net::unix::OwnedWriteHalf;

    fn empty_link() -> ControlWriter {
        Arc::new(tokio::sync::Mutex::new(WorkerLink::default()))
    }

    /// Manufacture a real `OwnedWriteHalf` so the monitor tests exercise the actual
    /// `writer.is_some()` check. The peer half is kept alive by the caller; dropping it on the
    /// test side closes the stream, but the owned write half on our side stays present until we
    /// explicitly `.take()` it.
    fn live_writer() -> (OwnedWriteHalf, tokio::net::UnixStream) {
        let (a, b) = tokio::net::UnixStream::pair().expect("UnixStream::pair");
        let (_r, w) = a.into_split();
        (w, b)
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn successor_wait_adopts_on_generation_bump() {
        let link = empty_link();
        // old_gen=0: successor must report generation > 0
        let waiter = {
            let link = link.clone();
            tokio::spawn(async move { wait_for_successor(&link, 0, Duration::from_secs(5)).await })
        };
        // Let the waiter poll a few times against an empty link, then drop in the generation bump
        // that should adopt.
        tokio::time::sleep(Duration::from_millis(100)).await;
        link.lock().await.last_generation = Some(1);
        assert_eq!(waiter.await.unwrap(), SuccessorOutcome::Adopted(1));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn successor_wait_times_out_with_no_signal() {
        let link = empty_link();
        let outcome = wait_for_successor(&link, 0, Duration::from_secs(5)).await;
        assert_eq!(outcome, SuccessorOutcome::Timeout);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn successor_wait_rejects_stale_generation() {
        // A gen≥1 worker whose control socket hasn't closed yet leaves last_generation=N in the
        // link. wait_for_successor with old_gen=N must not match that stale value — it requires
        // strictly greater.
        let link = empty_link();
        link.lock().await.last_generation = Some(1);
        let outcome = wait_for_successor(&link, 1, Duration::from_secs(5)).await;
        assert_eq!(
            outcome,
            SuccessorOutcome::Timeout,
            "stale gen-1 must not be adopted when old_gen=1"
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn monitor_returns_when_writer_lost_for_grace() {
        let link = empty_link();
        let (writer, _peer) = live_writer();
        link.lock().await.writer = Some(writer);

        // Start the monitor while the writer is present, then drop it after a short delay and
        // verify it returns >= grace later.
        let monitor = {
            let link = link.clone();
            tokio::spawn(async move {
                let current_pid = std::sync::Mutex::new(None);
                let started = tokio::time::Instant::now();
                let outcome =
                    monitor_successor(&link, &current_pid, 0, Duration::from_secs(3)).await;
                (outcome, started.elapsed())
            })
        };
        tokio::time::sleep(Duration::from_millis(500)).await;
        link.lock().await.writer = None;

        let (outcome, elapsed) = monitor.await.unwrap();
        assert_eq!(outcome, MonitorOutcome::Lost);
        // 500ms writer-present + 3s grace = ~3.5s minimum.
        assert!(
            elapsed >= Duration::from_millis(3500),
            "monitor returned in {elapsed:?}, expected >= 3.5s",
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "monitor took too long: {elapsed:?}",
        );
    }

    #[test]
    fn is_process_alive_recognizes_current_process() {
        assert!(is_process_alive(std::process::id()));
    }

    #[test]
    fn is_process_alive_returns_false_for_reaped_child() {
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn 'true'");
        let pid = child.id();
        child.wait().expect("wait for 'true'");
        // After wait() reaps the zombie the PID is freed; it should no longer be alive.
        // PID reuse between wait() and the probe is theoretically possible but vanishingly
        // unlikely in a test environment.
        assert!(!is_process_alive(pid));
    }

    #[test]
    fn acceptor_role_arg_returns_correct_strings() {
        assert_eq!(AcceptorRole::Plain.arg(), "plain");
        assert_eq!(AcceptorRole::Tls.arg(), "tls");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn monitor_ignores_brief_disconnect() {
        let link = empty_link();
        let (writer, _peer) = live_writer();
        link.lock().await.writer = Some(writer);

        let monitor = {
            let link = link.clone();
            tokio::spawn(async move {
                let current_pid = std::sync::Mutex::new(None);
                monitor_successor(&link, &current_pid, 0, Duration::from_secs(3)).await
            })
        };

        // Flap: drop the writer, reinstate it before the grace expires.
        tokio::time::sleep(Duration::from_millis(500)).await;
        link.lock().await.writer = None;
        tokio::time::sleep(Duration::from_secs(1)).await;
        let (writer2, _peer2) = live_writer();
        link.lock().await.writer = Some(writer2);

        // Give the monitor an extra full grace window. It must NOT have returned (the brief
        // disconnect was inside the grace window).
        tokio::time::sleep(Duration::from_secs(4)).await;
        assert!(
            !monitor.is_finished(),
            "monitor returned despite the disconnect being inside the grace window",
        );
        monitor.abort();
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn monitor_readopts_on_generation_advance() {
        // The adopted worker at gen 5 upgrades itself: its successor registers at gen 6 while the
        // control link is still present (the common case — the successor connects before the old
        // connection tears down). The monitor must recognize this by generation and re-adopt,
        // rather than sit in a stale supervision call.
        let link = empty_link();
        let (writer, _peer) = live_writer();
        {
            let mut l = link.lock().await;
            l.writer = Some(writer);
            l.last_generation = Some(5);
        }
        let monitor = {
            let link = link.clone();
            tokio::spawn(async move {
                let current_pid = std::sync::Mutex::new(None);
                monitor_successor(&link, &current_pid, 5, Duration::from_secs(3)).await
            })
        };
        tokio::time::sleep(Duration::from_millis(200)).await;
        link.lock().await.last_generation = Some(6);
        assert_eq!(monitor.await.unwrap(), MonitorOutcome::Readopted(6));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn monitor_readopts_when_successor_arrives_within_grace() {
        // The racy sub-case from follow-up review #6: a 2nd-generation upgrade where the old
        // control connection tore down (writer=None, generation cleared by the epoch-owning reader)
        // *before* the successor dialed in. As long as the higher generation registers within the
        // loss grace, the monitor re-adopts instead of declaring the worker lost and racing a fresh
        // gen-0 respawn.
        let link = empty_link();
        let (writer, _peer) = live_writer();
        {
            let mut l = link.lock().await;
            l.writer = Some(writer);
            l.last_generation = Some(5);
        }
        let monitor = {
            let link = link.clone();
            tokio::spawn(async move {
                let current_pid = std::sync::Mutex::new(None);
                monitor_successor(&link, &current_pid, 5, Duration::from_secs(3)).await
            })
        };
        // Old connection's teardown: writer gone, generation cleared to None (looks like a loss).
        tokio::time::sleep(Duration::from_millis(300)).await;
        {
            let mut l = link.lock().await;
            l.writer = None;
            l.last_generation = None;
        }
        // Successor dials in within the grace window with the higher generation.
        tokio::time::sleep(Duration::from_secs(1)).await;
        let (writer2, _peer2) = live_writer();
        {
            let mut l = link.lock().await;
            l.writer = Some(writer2);
            l.last_generation = Some(6);
        }
        assert_eq!(monitor.await.unwrap(), MonitorOutcome::Readopted(6));
    }
}
