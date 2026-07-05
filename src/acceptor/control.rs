use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use futures::StreamExt;
use tokio::{io::AsyncWriteExt, sync::watch};
use tokio_util::codec::{FramedRead, LinesCodec};

use crate::{
    control::{
        ControlMsg, RateLimiterStats, WorkerMsg, WorkerStatus, envelope_line, parse_envelope,
    },
    worker_common,
};

use super::ClientRegistry;

#[derive(Debug, Clone, Default)]
pub(super) struct UpgradeReq {
    pub(super) binary_path: Option<PathBuf>,
}

pub(super) struct StatusCtx {
    pub(super) role: String,
    pub(super) registry: Arc<Mutex<ClientRegistry>>,
    pub(super) generation: u64,
    pub(super) started_at_unix_ms: u64,
    pub(super) listener_addr: String,
    pub(super) rate_limiter: crate::limits::RateLimiter,
}

impl StatusCtx {
    pub(super) fn snapshot(&self) -> WorkerStatus {
        let in_flight = self.registry.lock().unwrap().clients.len() as u64;
        let (tracked_ips, idle_evictions, lru_evictions, cap_refused) = self.rate_limiter.stats();
        let rate_limiter_stats =
            if tracked_ips > 0 || idle_evictions > 0 || lru_evictions > 0 || cap_refused > 0 {
                Some(RateLimiterStats {
                    tracked_ips,
                    idle_evictions,
                    lru_evictions,
                    cap_refused,
                })
            } else {
                None
            };
        WorkerStatus {
            role: self.role.clone(),
            pid: std::process::id(),
            generation: self.generation,
            started_at_unix_ms: self.started_at_unix_ms,
            in_flight,
            listener_addr: Some(self.listener_addr.clone()),
            rate_limiter_stats,
        }
    }
}

#[derive(Clone)]
pub(super) struct ControlActions {
    pub(super) shutdown: watch::Sender<Option<u64>>,
    pub(super) upgrade: watch::Sender<Option<UpgradeReq>>,
    pub(super) drain: watch::Sender<bool>,
    pub(super) reload: watch::Sender<u64>,
}

pub(super) async fn run_control_client(
    dialer: Arc<worker_common::SocketsDialer>,
    basename: String,
    actions: ControlActions,
    ctx: StatusCtx,
) -> Result<()> {
    let ControlActions {
        shutdown,
        upgrade,
        drain,
        reload,
    } = actions;
    loop {
        let Some(stream) = worker_common::dial_control_plane(&dialer, &basename).await else {
            tracing::warn!(sock = %basename, "control-plane unreachable; giving up");
            return Ok(());
        };
        tracing::info!(sock = %basename, "control-plane connected");

        let (read_half, mut write_half) = stream.into_split();
        let mut reader = FramedRead::new(read_half, LinesCodec::new_with_max_length(64 * 1024));
        let mut terminal = false;
        while let Some(line) = reader.next().await {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    tracing::debug!(error = %e, "control-plane decode error");
                    break;
                }
            };
            let parsed = parse_envelope(&line);
            match parsed {
                Ok(ControlMsg::Shutdown { grace_ms }) => {
                    tracing::info!(grace_ms, "control-plane Shutdown");
                    let _ = shutdown.send(Some(grace_ms));
                    terminal = true;
                    break;
                }
                Ok(ControlMsg::Upgrade { binary_path, .. }) => {
                    tracing::info!(?binary_path, "control-plane Upgrade");
                    let _ = upgrade.send(Some(UpgradeReq { binary_path }));
                    terminal = true;
                    break;
                }
                Ok(ControlMsg::Status) => {
                    let status = ctx.snapshot();
                    let out = envelope_line(&WorkerMsg::StatusReport(status)).unwrap();
                    if let Err(e) = write_half.write_all(out.as_bytes()).await {
                        tracing::warn!(error = %e, "status reply write failed");
                        break;
                    }
                }
                Ok(ControlMsg::Drain) => {
                    tracing::info!("control-plane Drain");
                    let _ = drain.send(true);
                }
                Ok(ControlMsg::Reload) => {
                    tracing::info!("control-plane Reload");
                    reload.send_modify(|n| *n = n.wrapping_add(1));
                }
                Err(e) => tracing::warn!(error = %e, line = %line, "unknown control message"),
            }
        }
        if terminal {
            return Ok(());
        }
        tracing::info!("control-plane disconnected; will reconnect");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
