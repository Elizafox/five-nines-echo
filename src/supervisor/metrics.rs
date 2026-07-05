use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::{
    control::WorkerStatus,
    metrics::{MetricsSnapshot, UpgradeCounters},
};

use super::{
    WorkerControlLinks, query_status,
    watchdog::{Watchdogs, watchdogs_snapshot},
};

pub(super) struct MetricsWriterConfig {
    pub(super) path: PathBuf,
    pub(super) interval: Duration,
    pub(super) sup_generation: u64,
    pub(super) started_at_unix_ms: u64,
}

/// Background task: every `interval`, gather watchdog snapshot + per-worker status, write a
/// Prometheus textfile.
pub(super) async fn run_metrics_writer(
    config: MetricsWriterConfig,
    links: WorkerControlLinks,
    watchdogs: Watchdogs,
    upgrade_counters: Arc<UpgradeCounters>,
) {
    let MetricsWriterConfig {
        path,
        interval,
        sup_generation,
        started_at_unix_ms,
    } = config;
    tracing::info!(path = %path.display(), ?interval, "metrics writer started");
    loop {
        let healths = watchdogs_snapshot(&watchdogs);
        let mut statuses: Vec<WorkerStatus> = Vec::with_capacity(4);
        for (link, _name) in [
            (&links.processor, "processor"),
            (&links.plain, "plain"),
            (&links.tls, "tls"),
            (&links.scanner, "scanner"),
        ] {
            if let Some(s) = query_status(link).await {
                statuses.push(s);
            }
        }
        let snap = MetricsSnapshot::from_parts(
            sup_generation,
            started_at_unix_ms,
            &statuses,
            &healths,
            &upgrade_counters,
        );
        if let Err(e) = crate::metrics::write_textfile(&path, &snap) {
            tracing::warn!(error = %e, path = %path.display(), "metrics write failed");
        }
        tokio::time::sleep(interval).await;
    }
}
