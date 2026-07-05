use std::collections::HashMap;
use std::process::ExitStatus;
use std::sync::Arc;
use std::time::Duration;

use crate::{
    control::{HealthState, RoleHealth},
    handoff::{UPGRADE_COMMIT_EXIT_CODE, duration_millis_u64, now_unix_ms},
};

const WATCHDOG_INITIAL_BACKOFF: Duration = Duration::from_millis(200);
const WATCHDOG_MAX_BACKOFF: Duration = Duration::from_secs(30);
const WATCHDOG_HEALTHY_UPTIME: Duration = Duration::from_secs(5);
const WATCHDOG_FLAP_THRESHOLD: u32 = 4;

/// Mark the role as FAILED after this many consecutive fast exits; the binary is broken enough that
/// paging an on-caller is warranted. We keep respawning at max backoff (so an admin upgrade can
/// still land on a live worker), but `status` reports `failed` so external watchdogs / humans can
/// intervene.
const WATCHDOG_FAIL_THRESHOLD: u32 = 5;

#[derive(Default)]
pub(super) struct WatchdogState {
    consecutive_fast_exits: u32,
    next_backoff: Duration,
    last_spawned_at: Option<tokio::time::Instant>,
    total_restarts: u64,
    last_restart_at_unix_ms: Option<u64>,
}

impl WatchdogState {
    fn new() -> Self {
        Self {
            next_backoff: WATCHDOG_INITIAL_BACKOFF,
            ..Self::default()
        }
    }
    fn record_spawn(&mut self) {
        self.last_spawned_at = Some(tokio::time::Instant::now());
        self.total_restarts += 1;
        self.last_restart_at_unix_ms = Some(now_unix_ms());
    }
    fn record_adoption(&mut self) {
        // Adopted workers were already alive; mark "uptime starts now" so a graceful exit later
        // isn't treated as a fast crash, but don't bump the restart counter (we didn't restart
        // them)
        self.last_spawned_at = Some(tokio::time::Instant::now());
    }

    /// Process an exit; returns how long the next spawn should wait. A graceful upgrade commit
    /// (`UPGRADE_COMMIT_EXIT_CODE`) doesn't count toward the fast-exit total; the worker handed off
    /// cleanly to a successor that's already serving.
    fn record_exit(&mut self, status: ExitStatus) -> Duration {
        let uptime = self.last_spawned_at.map_or(Duration::ZERO, |t| t.elapsed());
        self.apply_exit(status, uptime)
    }

    /// Logic split out from `record_exit` so unit tests can drive the FSM with controlled uptimes
    /// (no sleep needed)
    fn apply_exit(&mut self, status: ExitStatus, uptime: Duration) -> Duration {
        if status.code() == Some(UPGRADE_COMMIT_EXIT_CODE) {
            self.consecutive_fast_exits = 0;
            self.next_backoff = WATCHDOG_INITIAL_BACKOFF;
            return self.next_backoff;
        }
        if uptime < WATCHDOG_HEALTHY_UPTIME {
            self.consecutive_fast_exits += 1;
            self.next_backoff = (self.next_backoff * 2).min(WATCHDOG_MAX_BACKOFF);
        } else {
            self.consecutive_fast_exits = 0;
            self.next_backoff = WATCHDOG_INITIAL_BACKOFF;
        }
        self.next_backoff
    }
    fn health_state(&self) -> HealthState {
        if self.consecutive_fast_exits >= WATCHDOG_FAIL_THRESHOLD {
            return HealthState::Failed;
        }

        // If the worker is currently alive and has been up for at least the healthy threshold,
        // surface "healthy" regardless of historical fast exits. The backing counter is only
        // flushed on the next `record_exit`, which keeps "total_restarts" honest whilst letting the
        // displayed state catch up with live reality.
        if let Some(t) = self.last_spawned_at
            && t.elapsed() >= WATCHDOG_HEALTHY_UPTIME
        {
            return HealthState::Healthy;
        }
        if self.consecutive_fast_exits == 0 {
            HealthState::Healthy
        } else if self.consecutive_fast_exits >= WATCHDOG_FLAP_THRESHOLD {
            HealthState::Flapping
        } else {
            HealthState::Backoff
        }
    }

    fn is_failed(&self) -> bool {
        self.consecutive_fast_exits >= WATCHDOG_FAIL_THRESHOLD
    }
    fn snapshot(&self, role: &str) -> RoleHealth {
        RoleHealth {
            role: role.to_string(),
            state: self.health_state(),
            consecutive_fast_exits: self.consecutive_fast_exits,
            next_backoff_ms: duration_millis_u64(self.next_backoff),
            total_restarts: self.total_restarts,
            last_restart_at_unix_ms: self.last_restart_at_unix_ms,
        }
    }
}

pub(super) type Watchdogs = Arc<std::sync::Mutex<HashMap<String, WatchdogState>>>;

pub(super) fn watchdogs_init() -> Watchdogs {
    let mut m: HashMap<String, WatchdogState> = HashMap::new();
    for r in ["processor", "plain", "tls", "scanner"] {
        m.insert(r.to_string(), WatchdogState::new());
    }
    Arc::new(std::sync::Mutex::new(m))
}

#[derive(Debug, Copy, Clone)]
pub(super) enum WatchdogEvent {
    Spawn,
    Adoption,
}

pub(super) fn watchdog_record(wd: &Watchdogs, role: &str, event: WatchdogEvent) {
    record_watchdog_event(&mut wd.lock().unwrap(), role, event);
}

/// Process a worker exit and return the backoff to wait before the next respawn attempt. When the
/// role has hit FAIL threshold, the backoff stays at the cap so a broken binary doesn't churn.
/// Failed is otherwise just an observable state, not a hard "stop forever."
pub(super) fn watchdog_record_exit(wd: &Watchdogs, role: &str, status: ExitStatus) -> Duration {
    let (backoff, log_event) = record_watchdog_exit(&mut wd.lock().unwrap(), role, status);
    if let Some((failed, consecutive_fast_exits, state)) = log_event {
        let level = if failed {
            tracing::Level::ERROR
        } else {
            tracing::Level::WARN
        };
        let evt = if failed {
            "watchdog: role marked FAILED; not respawning"
        } else {
            "watchdog: fast exit"
        };
        if level == tracing::Level::ERROR {
            tracing::error!(role, consecutive_fast_exits, ?state, "{}", evt,);
        } else {
            tracing::warn!(
                role,
                consecutive_fast_exits,
                backoff_ms = duration_millis_u64(backoff),
                ?state,
                "{}",
                evt,
            );
        }
    }
    backoff
}

fn record_watchdog_event(
    watchdogs: &mut HashMap<String, WatchdogState>,
    role: &str,
    event: WatchdogEvent,
) {
    let state = watchdogs.entry(role.to_string()).or_default();
    match event {
        WatchdogEvent::Spawn => state.record_spawn(),
        WatchdogEvent::Adoption => state.record_adoption(),
    }
}

fn record_watchdog_exit(
    watchdogs: &mut HashMap<String, WatchdogState>,
    role: &str,
    status: ExitStatus,
) -> (Duration, Option<(bool, u32, HealthState)>) {
    let state = watchdogs.entry(role.to_string()).or_default();
    let backoff = state.record_exit(status);
    let failed = state.is_failed();
    let log_event = (state.consecutive_fast_exits > 0)
        .then(|| (failed, state.consecutive_fast_exits, state.health_state()));
    (backoff, log_event)
}

pub(super) fn watchdogs_snapshot(wd: &Watchdogs) -> Vec<RoleHealth> {
    let g = wd.lock().unwrap();
    ["processor", "plain", "tls", "scanner"]
        .iter()
        .map(|r| {
            g.get(*r).map_or_else(
                || {
                    // Shouldn't happen; we pre-seeded all four. Fall back to fresh.
                    WatchdogState::new().snapshot(r)
                },
                |s| s.snapshot(r),
            )
        })
        .collect()
}

pub(super) fn watchdog_health_state(wd: &Watchdogs, role: &str) -> HealthState {
    wd.lock()
        .unwrap()
        .get(role)
        .map_or(HealthState::Healthy, WatchdogState::health_state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    fn fast_exit() -> ExitStatus {
        // Any non-zero, non-upgrade-commit exit code; pretend a crash.
        ExitStatus::from_raw(1 << 8)
    }

    fn commit_exit() -> ExitStatus {
        // (code << 8) matches what waitpid encodes for a normal exit.
        ExitStatus::from_raw(UPGRADE_COMMIT_EXIT_CODE << 8)
    }

    #[test]
    fn fresh_watchdog_is_healthy() {
        let w = WatchdogState::new();
        assert_eq!(w.health_state(), HealthState::Healthy);
        assert_eq!(w.consecutive_fast_exits, 0);
    }

    #[test]
    fn fast_exits_double_the_backoff() {
        let mut w = WatchdogState::new();
        let b1 = w.apply_exit(fast_exit(), Duration::ZERO);
        let b2 = w.apply_exit(fast_exit(), Duration::ZERO);
        let b3 = w.apply_exit(fast_exit(), Duration::ZERO);
        assert_eq!(b1, Duration::from_millis(400));
        assert_eq!(b2, Duration::from_millis(800));
        assert_eq!(b3, Duration::from_millis(1600));
    }

    #[test]
    fn fast_exits_progress_through_states() {
        let mut w = WatchdogState::new();
        for _ in 0..(WATCHDOG_FLAP_THRESHOLD - 1) {
            w.apply_exit(fast_exit(), Duration::ZERO);
            assert_eq!(w.health_state(), HealthState::Backoff);
        }
        w.apply_exit(fast_exit(), Duration::ZERO);
        assert_eq!(w.health_state(), HealthState::Flapping);
        while !w.is_failed() {
            w.apply_exit(fast_exit(), Duration::ZERO);
        }
        assert_eq!(w.health_state(), HealthState::Failed);
    }

    #[test]
    fn healthy_uptime_resets_counter() {
        let mut w = WatchdogState::new();
        for _ in 0..3 {
            w.apply_exit(fast_exit(), Duration::ZERO);
        }
        assert!(w.consecutive_fast_exits > 0);
        w.apply_exit(
            fast_exit(),
            WATCHDOG_HEALTHY_UPTIME + Duration::from_secs(1),
        );
        assert_eq!(w.consecutive_fast_exits, 0);
        assert_eq!(w.next_backoff, WATCHDOG_INITIAL_BACKOFF);
    }

    #[test]
    fn upgrade_commit_exit_does_not_count() {
        let mut w = WatchdogState::new();
        // Build up some fast exits first.
        for _ in 0..3 {
            w.apply_exit(fast_exit(), Duration::ZERO);
        }
        let before = w.consecutive_fast_exits;
        // A commit-coded exit immediately after spawn (uptime=0) should NOT increment the counter;
        // it's a planned handoff.
        w.apply_exit(commit_exit(), Duration::ZERO);
        assert!(w.consecutive_fast_exits < before);
        assert_eq!(w.consecutive_fast_exits, 0);
    }

    #[test]
    fn backoff_caps_at_max() {
        let mut w = WatchdogState::new();
        for _ in 0..30 {
            w.apply_exit(fast_exit(), Duration::ZERO);
        }
        assert!(w.next_backoff <= WATCHDOG_MAX_BACKOFF);
        assert_eq!(w.next_backoff, WATCHDOG_MAX_BACKOFF);
    }

    #[test]
    fn watchdogs_init_seeds_all_four_roles() {
        let wd = watchdogs_init();
        let snap = watchdogs_snapshot(&wd);
        assert_eq!(snap.len(), 4);
        let roles: Vec<&str> = snap.iter().map(|r| r.role.as_str()).collect();
        for expected in &["processor", "plain", "tls", "scanner"] {
            assert!(roles.contains(expected), "missing role {expected}");
        }
    }

    #[test]
    fn watchdog_snapshot_reflects_fresh_state() {
        let wd = watchdogs_init();
        for s in watchdogs_snapshot(&wd) {
            assert_eq!(s.state, HealthState::Healthy);
            assert_eq!(s.consecutive_fast_exits, 0);
            assert_eq!(s.total_restarts, 0);
        }
    }

    #[test]
    fn watchdog_record_exit_increments_counter_and_transitions_state() {
        let wd = watchdogs_init();
        watchdog_record_exit(&wd, "plain", fast_exit());
        assert_eq!(watchdog_health_state(&wd, "plain"), HealthState::Backoff);
    }

    #[test]
    fn watchdog_record_exit_reaches_failed_at_threshold() {
        let wd = watchdogs_init();
        for _ in 0..WATCHDOG_FAIL_THRESHOLD {
            watchdog_record_exit(&wd, "scanner", fast_exit());
        }
        assert_eq!(watchdog_health_state(&wd, "scanner"), HealthState::Failed);
    }

    #[test]
    fn watchdog_record_exit_commit_code_resets_counter() {
        let wd = watchdogs_init();
        watchdog_record_exit(&wd, "tls", fast_exit());
        watchdog_record_exit(&wd, "tls", fast_exit());
        watchdog_record_exit(&wd, "tls", commit_exit());
        assert_eq!(watchdog_health_state(&wd, "tls"), HealthState::Healthy);
    }

    #[test]
    fn watchdog_health_state_returns_healthy_for_fresh_role() {
        let wd = watchdogs_init();
        assert_eq!(
            watchdog_health_state(&wd, "processor"),
            HealthState::Healthy
        );
    }

    #[test]
    fn watchdog_health_state_returns_healthy_for_unknown_role() {
        let wd = watchdogs_init();
        // Unknown role falls back to Healthy (or_default).
        assert_eq!(
            watchdog_health_state(&wd, "does-not-exist"),
            HealthState::Healthy
        );
    }

    #[test]
    fn snapshot_method_round_trips_state() {
        let mut w = WatchdogState::new();
        w.apply_exit(fast_exit(), Duration::ZERO);
        let s = w.snapshot("myrole");
        assert_eq!(s.role, "myrole");
        assert_eq!(s.state, HealthState::Backoff);
        assert_eq!(s.consecutive_fast_exits, 1);
        assert_eq!(s.total_restarts, 0); // apply_exit doesn't bump restarts
    }

    #[tokio::test(flavor = "current_thread")]
    async fn watchdog_record_spawn_increments_total_restarts() {
        let wd = watchdogs_init();
        watchdog_record(&wd, "processor", WatchdogEvent::Spawn);
        let snap: Vec<_> = watchdogs_snapshot(&wd)
            .into_iter()
            .filter(|s| s.role == "processor")
            .collect();
        assert_eq!(snap[0].total_restarts, 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn watchdog_record_adoption_does_not_increment_restarts() {
        let wd = watchdogs_init();
        watchdog_record(&wd, "plain", WatchdogEvent::Adoption);
        let snap: Vec<_> = watchdogs_snapshot(&wd)
            .into_iter()
            .filter(|s| s.role == "plain")
            .collect();
        assert_eq!(snap[0].total_restarts, 0);
    }
}
