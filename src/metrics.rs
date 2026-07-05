//! Prometheus textfile-collector output.
//!
//! The supervisor periodically gathers state from its watchdogs (and from workers via the
//! control-plane status query) into a `MetricsSnapshot` and writes it as a `.prom` file.
//! `node_exporter`'s textfile collector picks the file up on its own scrape cadence. Writing is
//! atomic (we write to a sibling `.tmp` then `rename()` into place) so a scraper never sees a
//! partially-written file.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};

use crate::control::{HealthState, RateLimiterStats, RoleHealth, WorkerStatus};

fn unix_ms_as_seconds(ms: u64) -> String {
    format!("{}.{:03}", ms / 1000, ms % 1000)
}

/// Per-role counters incremented as the supervisor walks rolling-upgrades.
/// One counter per (role, outcome) pair; outcomes are: `committed`, `timed_out`, `canary_aborted`,
/// and `skipped`.
///
/// "Committed" means generation actually rolled forward from the supervisor's perspective; a
/// worker-side rollback shows up as a "`timed_out`" because the supervisor never sees the new
/// generation.
#[derive(Debug)]
pub struct UpgradeCounters {
    committed: HashMap<String, AtomicU64>,
    timed_out: HashMap<String, AtomicU64>,
    canary_aborted: HashMap<String, AtomicU64>,
    skipped: HashMap<String, AtomicU64>,
}

impl UpgradeCounters {
    pub fn new() -> Self {
        fn zero_map() -> HashMap<String, AtomicU64> {
            ["processor", "plain", "tls", "scanner"]
                .into_iter()
                .map(|r| (r.to_string(), AtomicU64::new(0)))
                .collect()
        }
        Self {
            committed: zero_map(),
            timed_out: zero_map(),
            canary_aborted: zero_map(),
            skipped: zero_map(),
        }
    }

    pub fn incr_committed(&self, role: &str) {
        if let Some(c) = self.committed.get(role) {
            c.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn incr_timed_out(&self, role: &str) {
        if let Some(c) = self.timed_out.get(role) {
            c.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn incr_canary_aborted(&self, role: &str) {
        if let Some(c) = self.canary_aborted.get(role) {
            c.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn incr_skipped(&self, role: &str) {
        if let Some(c) = self.skipped.get(role) {
            c.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn snapshot(&self) -> Vec<UpgradeMetric> {
        let mut out = Vec::with_capacity(self.committed.len() * 4);
        for (map, outcome) in [
            (&self.committed, "committed"),
            (&self.timed_out, "timed_out"),
            (&self.canary_aborted, "canary_aborted"),
            (&self.skipped, "skipped"),
        ] {
            for (role, ctr) in map {
                out.push(UpgradeMetric {
                    role: role.clone(),
                    outcome,
                    value: ctr.load(Ordering::Relaxed),
                });
            }
        }
        out
    }
}

#[derive(Debug)]
pub struct UpgradeMetric {
    pub role: String,
    pub outcome: &'static str,
    pub value: u64,
}

/// Single roll-up of everything the supervisor wants to expose. Built by the supervisor each
/// metrics tick; serialized via [`write_textfile`].
#[derive(Debug)]
pub struct MetricsSnapshot {
    pub supervisor_generation: u64,
    pub supervisor_started_at_unix_ms: u64,
    pub roles: Vec<RoleMetrics>,
    pub upgrades: Vec<UpgradeMetric>,
}

#[derive(Debug)]
pub struct RoleMetrics {
    pub role: String,
    pub generation: u64,
    pub in_flight: u64,
    pub pid: u32,
    pub health: HealthState,
    pub consecutive_fast_exits: u32,
    pub total_restarts: u64,
    pub last_restart_at_unix_ms: Option<u64>,
    pub rate_limiter_stats: Option<RateLimiterStats>,
}

impl MetricsSnapshot {
    pub fn from_parts(
        supervisor_generation: u64,
        supervisor_started_at_unix_ms: u64,
        statuses: &[WorkerStatus],
        healths: &[RoleHealth],
        upgrades: &UpgradeCounters,
    ) -> Self {
        let mut roles = Vec::with_capacity(healths.len());
        for h in healths {
            let status = statuses.iter().find(|s| s.role == h.role);
            roles.push(RoleMetrics {
                role: h.role.clone(),
                generation: status.map_or(0, |s| s.generation),
                in_flight: status.map_or(0, |s| s.in_flight),
                pid: status.map_or(0, |s| s.pid),
                health: h.state,
                consecutive_fast_exits: h.consecutive_fast_exits,
                total_restarts: h.total_restarts,
                last_restart_at_unix_ms: h.last_restart_at_unix_ms,
                rate_limiter_stats: status.and_then(|s| s.rate_limiter_stats.clone()),
            });
        }
        Self {
            supervisor_generation,
            supervisor_started_at_unix_ms,
            roles,
            upgrades: upgrades.snapshot(),
        }
    }

    pub fn render(&self) -> String {
        let mut s = String::with_capacity(2048);
        self.write_supervisor_metrics(&mut s);
        self.write_worker_identity_metrics(&mut s);
        self.write_worker_health_metrics(&mut s);
        self.write_worker_restart_metrics(&mut s);
        self.write_upgrade_metrics(&mut s);
        self.write_rate_limiter_metrics(&mut s);
        s
    }

    fn write_supervisor_metrics(&self, s: &mut String) {
        write_metric_header(
            s,
            "fdpass_supervisor_generation",
            "Current supervisor generation.",
            "gauge",
        );
        let _ = writeln!(
            s,
            "fdpass_supervisor_generation {}",
            self.supervisor_generation
        );

        write_metric_header(
            s,
            "fdpass_supervisor_started_at_seconds",
            "Unix epoch when this supervisor started.",
            "gauge",
        );
        let _ = writeln!(
            s,
            "fdpass_supervisor_started_at_seconds {}",
            unix_ms_as_seconds(self.supervisor_started_at_unix_ms),
        );
    }

    fn write_worker_identity_metrics(&self, s: &mut String) {
        write_metric_header(
            s,
            "fdpass_worker_generation",
            "Current generation of the worker process.",
            "gauge",
        );
        for r in &self.roles {
            let _ = writeln!(
                s,
                "fdpass_worker_generation{{role=\"{}\"}} {}",
                r.role, r.generation
            );
        }

        write_metric_header(
            s,
            "fdpass_worker_in_flight",
            "Currently-tracked sessions for the worker.",
            "gauge",
        );
        for r in &self.roles {
            let _ = writeln!(
                s,
                "fdpass_worker_in_flight{{role=\"{}\"}} {}",
                r.role, r.in_flight
            );
        }

        write_metric_header(
            s,
            "fdpass_worker_pid",
            "Current worker pid (0 if no live worker).",
            "gauge",
        );
        for r in &self.roles {
            let _ = writeln!(s, "fdpass_worker_pid{{role=\"{}\"}} {}", r.role, r.pid);
        }
    }

    fn write_worker_health_metrics(&self, s: &mut String) {
        write_metric_header(
            s,
            "fdpass_worker_health",
            "Watchdog state (0=healthy 1=backoff 2=flapping 3=failed).",
            "gauge",
        );
        for r in &self.roles {
            let v = match r.health {
                HealthState::Healthy => 0,
                HealthState::Backoff => 1,
                HealthState::Flapping => 2,
                HealthState::Failed => 3,
            };
            let _ = writeln!(s, "fdpass_worker_health{{role=\"{}\"}} {}", r.role, v);
        }

        write_metric_header(
            s,
            "fdpass_worker_consecutive_fast_exits",
            "Current fast-exit counter.",
            "gauge",
        );
        for r in &self.roles {
            let _ = writeln!(
                s,
                "fdpass_worker_consecutive_fast_exits{{role=\"{}\"}} {}",
                r.role, r.consecutive_fast_exits
            );
        }
    }

    fn write_worker_restart_metrics(&self, s: &mut String) {
        write_metric_header(
            s,
            "fdpass_worker_restarts_total",
            "Total times the watchdog respawned the worker.",
            "counter",
        );
        for r in &self.roles {
            let _ = writeln!(
                s,
                "fdpass_worker_restarts_total{{role=\"{}\"}} {}",
                r.role, r.total_restarts
            );
        }

        write_metric_header(
            s,
            "fdpass_worker_last_restart_seconds",
            "Unix epoch of the most recent respawn (0 if never).",
            "gauge",
        );
        for r in &self.roles {
            let v = r
                .last_restart_at_unix_ms
                .map_or_else(|| "0".to_string(), unix_ms_as_seconds);
            let _ = writeln!(
                s,
                "fdpass_worker_last_restart_seconds{{role=\"{}\"}} {}",
                r.role, v
            );
        }
    }

    fn write_upgrade_metrics(&self, s: &mut String) {
        write_metric_header(
            s,
            "fdpass_upgrade_total",
            "Per-role upgrade outcomes (committed/timed_out/canary_aborted/skipped).",
            "counter",
        );
        for u in &self.upgrades {
            let _ = writeln!(
                s,
                "fdpass_upgrade_total{{role=\"{}\",outcome=\"{}\"}} {}",
                u.role, u.outcome, u.value
            );
        }
    }

    fn write_rate_limiter_metrics(&self, s: &mut String) {
        write_metric_header(
            s,
            "fdpass_ratelimit_tracked_ips",
            "Current number of tracked IPs in per-IP rate limiter.",
            "gauge",
        );
        for r in &self.roles {
            if let Some(stats) = &r.rate_limiter_stats {
                let _ = writeln!(
                    s,
                    "fdpass_ratelimit_tracked_ips{{role=\"{}\"}} {}",
                    r.role, stats.tracked_ips
                );
            }
        }

        write_metric_header(
            s,
            "fdpass_ratelimit_evictions_total",
            "Total rate limiter bucket evictions by reason.",
            "counter",
        );
        for r in &self.roles {
            if let Some(stats) = &r.rate_limiter_stats {
                for (reason, count) in [
                    ("idle", stats.idle_evictions),
                    ("lru", stats.lru_evictions),
                    ("cap_refused", stats.cap_refused),
                ] {
                    let _ = writeln!(
                        s,
                        "fdpass_ratelimit_evictions_total{{role=\"{}\",reason=\"{}\"}} {}",
                        r.role, reason, count
                    );
                }
            }
        }
    }
}

fn write_metric_header(s: &mut String, name: &str, help: &str, kind: &str) {
    let _ = writeln!(s, "# HELP {name} {help}");
    let _ = writeln!(s, "# TYPE {name} {kind}");
}

/// Atomically write the rendered snapshot to `path`. Creates parent dirs
/// on demand; replaces any existing file.
pub fn write_textfile(path: &Path, snapshot: &MetricsSnapshot) -> Result<()> {
    if let Some(f) = fault_inject!("metrics.write") {
        return Err(f.into_anyhow().context("synthetic metrics write failure"));
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("create metrics dir {}", parent.display()))?;
    }
    let mut tmp_path = PathBuf::from(path);
    let mut name = tmp_path
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_default();
    name.push(".tmp");
    tmp_path.set_file_name(name);

    let text = snapshot.render();
    {
        let mut f = fs::File::create(&tmp_path)
            .with_context(|| format!("create {}", tmp_path.display()))?;
        f.write_all(text.as_bytes())
            .with_context(|| format!("write {}", tmp_path.display()))?;
        f.sync_all().ok();
    }
    fs::rename(&tmp_path, path)
        .with_context(|| format!("rename {} -> {}", tmp_path.display(), path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_snapshot() -> MetricsSnapshot {
        let statuses = vec![WorkerStatus {
            role: "processor".into(),
            pid: 4242,
            generation: 3,
            started_at_unix_ms: 1_700_000_000_000,
            in_flight: 17,
            listener_addr: Some("/tmp/x.sock".into()),
            rate_limiter_stats: None,
        }];
        let healths = vec![RoleHealth {
            role: "processor".into(),
            state: HealthState::Backoff,
            consecutive_fast_exits: 2,
            next_backoff_ms: 800,
            total_restarts: 12,
            last_restart_at_unix_ms: Some(1_700_000_005_000),
        }];
        let upgrades = UpgradeCounters::new();
        upgrades.incr_committed("processor");
        upgrades.incr_canary_aborted("plain");
        MetricsSnapshot::from_parts(7, 1_700_000_000_000, &statuses, &healths, &upgrades)
    }

    #[test]
    fn render_contains_all_metric_families() {
        let snap = sample_snapshot();
        let text = snap.render();
        for needle in [
            "fdpass_supervisor_generation 7",
            "fdpass_worker_generation{role=\"processor\"} 3",
            "fdpass_worker_in_flight{role=\"processor\"} 17",
            "fdpass_worker_pid{role=\"processor\"} 4242",
            "fdpass_worker_health{role=\"processor\"} 1",
            "fdpass_worker_consecutive_fast_exits{role=\"processor\"} 2",
            "fdpass_worker_restarts_total{role=\"processor\"} 12",
            "fdpass_upgrade_total{role=\"processor\",outcome=\"committed\"} 1",
            "fdpass_upgrade_total{role=\"plain\",outcome=\"canary_aborted\"} 1",
            "fdpass_upgrade_total{role=\"scanner\",outcome=\"timed_out\"} 0",
        ] {
            assert!(
                text.contains(needle),
                "missing line {needle:?}\n--- got ---\n{text}"
            );
        }
    }

    #[test]
    fn each_metric_has_help_and_type() {
        let text = sample_snapshot().render();
        for family in [
            "fdpass_supervisor_generation",
            "fdpass_worker_generation",
            "fdpass_worker_in_flight",
            "fdpass_worker_pid",
            "fdpass_worker_health",
            "fdpass_worker_consecutive_fast_exits",
            "fdpass_worker_restarts_total",
            "fdpass_worker_last_restart_seconds",
            "fdpass_upgrade_total",
            "fdpass_ratelimit_tracked_ips",
            "fdpass_ratelimit_evictions_total",
        ] {
            assert!(
                text.contains(&format!("# HELP {family} ")),
                "no HELP for {family}"
            );
            assert!(
                text.contains(&format!("# TYPE {family} ")),
                "no TYPE for {family}"
            );
        }
    }

    #[test]
    fn write_textfile_atomic_rename() {
        let dir = std::env::temp_dir().join(format!(
            "fdpass-metrics-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos()),
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("metrics.prom");
        write_textfile(&path, &sample_snapshot()).unwrap();
        let text = fs::read_to_string(&path).unwrap();

        assert!(text.contains("fdpass_supervisor_generation 7"));

        // The sibling `.tmp` should be gone (rename moved it)
        assert!(
            !dir.join("metrics.prom.tmp").exists(),
            "tmp file should have been renamed",
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
