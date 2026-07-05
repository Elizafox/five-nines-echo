use std::path::PathBuf;
use std::process;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use futures::StreamExt;
use tokio::{io::AsyncWriteExt, sync::watch};
use tokio_util::codec::{FramedRead, LinesCodec};

use crate::{
    auth::PeerAllowlist,
    config::Config,
    control::{ControlMsg, WorkerMsg, WorkerStatus, envelope_line, parse_envelope},
    scanner::ScannerRegistry,
    worker_common::{SocketsDialer, dial_control_plane},
};

#[derive(Debug, Clone, Default)]
pub(super) struct UpgradeReq {
    pub(super) binary_path: Option<PathBuf>,
}

pub(super) struct StatusCtx {
    pub(super) registry: Arc<Mutex<ScannerRegistry>>,
    pub(super) generation: u64,
    pub(super) started_at_unix_ms: u64,
    pub(super) listener_addr: String,
}

impl StatusCtx {
    fn snapshot(&self) -> WorkerStatus {
        let in_flight = self.registry.lock().unwrap().in_flight.len() as u64;
        WorkerStatus {
            role: "scanner".to_string(),
            pid: process::id(),
            generation: self.generation,
            started_at_unix_ms: self.started_at_unix_ms,
            in_flight,
            listener_addr: Some(self.listener_addr.clone()),
            rate_limiter_stats: None,
        }
    }
}

pub(super) async fn run_control_client(
    dialer: Arc<SocketsDialer>,
    basename: String,
    shutdown_tx: watch::Sender<bool>,
    upgrade_tx: watch::Sender<Option<UpgradeReq>>,
    allow: Arc<std::sync::RwLock<PeerAllowlist>>,
    ctx: StatusCtx,
) -> Result<()> {
    loop {
        let Some(stream) = dial_control_plane(&dialer, &basename).await else {
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
                    let _ = shutdown_tx.send(true);
                    terminal = true;
                    break;
                }
                Ok(ControlMsg::Upgrade { binary_path, .. }) => {
                    tracing::info!(?binary_path, "control-plane Upgrade");
                    let _ = upgrade_tx.send(Some(UpgradeReq { binary_path }));
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
                    tracing::debug!("control-plane Drain (scanner: noop)");
                }
                Ok(ControlMsg::Reload) => match Config::load(None) {
                    Ok(new) => {
                        let new_allow = PeerAllowlist::from_config(&new.auth.allowed_uids);
                        *allow.write().unwrap() = new_allow;
                        tracing::info!(
                            allowed_uids = ?new.auth.allowed_uids,
                            "control-plane Reload: auth allowlist refreshed",
                        );
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "control-plane Reload: config load failed; keeping previous");
                    }
                },
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
