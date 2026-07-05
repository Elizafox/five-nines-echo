use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use tokio::{io::AsyncWriteExt, net::unix::OwnedWriteHalf, sync::oneshot};
use tokio_util::codec::{FramedRead, LinesCodec};

use crate::{
    auth::{SharedAllowlist, check_peer},
    control::{ControlMsg, WorkerMsg, WorkerStatus, envelope_line, parse_envelope},
};

#[derive(Default)]
pub(super) struct WorkerLink {
    pub(super) writer: Option<OwnedWriteHalf>,
    pub(super) pending_status: Option<tokio::sync::oneshot::Sender<WorkerStatus>>,
    /// Updated every time a `StatusReport` lands. `supervise_role` consults this after an
    /// `UPGRADE_COMMIT` exit to decide whether the upgrade successor is already serving (adopt +
    /// monitor) or never arrived (respawn fresh)
    pub(super) last_generation: Option<u64>,
    /// PID reported by the worker that currently owns the control link. Lets `supervise_role` point
    /// `current_pid` at an adopted upgrade successor: a grandchild it never spawned and holds no
    /// `ChildHandle` for
    pub(super) last_pid: Option<u32>,
    /// Monotonic id of the connection that currently owns `writer`. Each accepted control
    /// connection bumps it. A reader only tears down the link's connection state on disconnect if
    /// it still owns the current epoch, so a stale reader can't clobber a newer worker that already
    /// reconnected (the last-write-wins replacement in `accept_control`).
    pub(super) conn_epoch: u64,
}

pub(super) type ControlWriter = Arc<tokio::sync::Mutex<WorkerLink>>;

#[allow(clippy::similar_names, reason = "line and link are distinct enough")]
pub(super) async fn accept_control(
    listener: tokio::net::UnixListener,
    link: ControlWriter,
    role: &'static str,
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
                    tracing::warn!(role, error = %e, "control peer rejected");
                    continue;
                }
                tracing::info!(role, "control-plane client connected");
                let (read_half, write_half) = stream.into_split();
                // Bump the connection epoch as we install this writer, so the reader task below can
                // tell on disconnect whether it still owns the link or a newer worker already
                // replaced it.
                let my_epoch = {
                    let mut l = link.lock().await;
                    l.conn_epoch = l.conn_epoch.wrapping_add(1);
                    l.writer = Some(write_half);
                    l.conn_epoch
                };
                let link_clone = link.clone();
                tokio::spawn(async move {
                    let mut reader =
                        FramedRead::new(read_half, LinesCodec::new_with_max_length(64 * 1024));
                    while let Some(line) = reader.next().await {
                        let Ok(line) = line else {
                            break;
                        };
                        let parsed = if let Some(f) = fault_inject!("control.decode") {
                            Err(f.into_anyhow().context("synthetic control decode error"))
                        } else {
                            parse_envelope(&line)
                        };
                        match parsed {
                            Ok(WorkerMsg::StatusReport(status)) => {
                                let mut l = link_clone.lock().await;
                                l.last_generation = Some(status.generation);
                                l.last_pid = Some(status.pid);
                                if let Some(tx) = l.pending_status.take() {
                                    let _ = tx.send(status);
                                }
                            }
                            Err(e) => tracing::warn!(role, error = %e, line = %line,
                                "unknown or incompatible worker message"),
                        }
                    }
                    // Tear down this connection's state on disconnect, but only if we still own the
                    // link. A post-exec successor may have already reconnected and bumped
                    // conn_epoch (the last-write-wins replacement above); leave its writer /
                    // generation / pid intact in that case. Clearing the writer when we *do* still
                    // own it is precisely what lets monitor_successor observe an adopted worker
                    // going away. (pending_status self-heals via the query_status timeout.)
                    {
                        let mut l = link_clone.lock().await;
                        if l.conn_epoch == my_epoch {
                            l.writer = None;
                            l.last_generation = None;
                            l.last_pid = None;
                        }
                    }
                    tracing::info!(role, "control-plane client disconnected");
                });
            }
            Err(e) => {
                tracing::warn!(role, error = %e, "control-plane accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

#[allow(clippy::similar_names, reason = "line and link are distinct enough")]
pub(super) async fn query_status(link: &ControlWriter) -> Option<WorkerStatus> {
    let (tx, rx) = oneshot::channel::<WorkerStatus>();
    {
        let mut l = link.lock().await;
        let writer = l.writer.as_mut()?;
        let line = envelope_line(&ControlMsg::Status).ok()?;
        writer.write_all(line.as_bytes()).await.ok()?;
        l.pending_status = Some(tx);
    }
    if let Ok(Ok(status)) = tokio::time::timeout(Duration::from_millis(750), rx).await {
        Some(status)
    } else {
        let mut l = link.lock().await;
        l.pending_status = None;
        None
    }
}

/// Push a non-terminal control message to a worker without consuming the writer half (drain /
/// reload, unlike Shutdown, leave the channel open)
#[allow(
    clippy::significant_drop_tightening,
    reason = "hold the control writer lock across the write to preserve message ordering"
)]
#[allow(clippy::similar_names, reason = "line and link are distinct enough")]
async fn send_non_terminal(link: &ControlWriter, msg: ControlMsg, label: &'static str) {
    let line = envelope_line(&msg).unwrap();
    let mut l = link.lock().await;
    let Some(w) = l.writer.as_mut() else {
        tracing::warn!(label, "no control connection");
        return;
    };
    if let Err(e) = w.write_all(line.as_bytes()).await {
        tracing::warn!(label, error = %e, "control msg write failed");
    }
}

pub(super) async fn send_drain(link: &ControlWriter) {
    send_non_terminal(link, ControlMsg::Drain, "Drain").await;
}

pub(super) async fn send_reload(link: &ControlWriter) {
    send_non_terminal(link, ControlMsg::Reload, "Reload").await;
}

#[allow(clippy::similar_names, reason = "line and link are distinct enough")]
pub(super) async fn send_shutdown(link: &ControlWriter, grace_ms: u64) {
    // Take the writer out under the lock, then drop the guard before any network I/O so concurrent
    // tasks (new accepts, status reads) keep moving whilst we shutdown
    let mut w = {
        let mut l = link.lock().await;
        l.pending_status = None;
        if let Some(w) = l.writer.take() {
            w
        } else {
            tracing::warn!("no control connection to send Shutdown");
            return;
        }
    };
    let line = envelope_line(&ControlMsg::Shutdown { grace_ms }).unwrap();
    if let Err(e) = w.write_all(line.as_bytes()).await {
        tracing::warn!(error = %e, "Shutdown write failed");
    }
    let _ = w.shutdown().await;
}

#[allow(clippy::similar_names, reason = "line and link are distinct enough")]
pub(super) async fn send_upgrade(link: &ControlWriter, binary_path: Option<PathBuf>) {
    let mut w = {
        let mut l = link.lock().await;
        l.pending_status = None;
        if let Some(w) = l.writer.take() {
            w
        } else {
            tracing::warn!("no control connection to send Upgrade");
            return;
        }
    };
    let line = envelope_line(&ControlMsg::Upgrade {
        binary_path,
        include_tls: false,
        canary_secs: None,
        only_role: None,
    })
    .unwrap();
    if let Err(e) = w.write_all(line.as_bytes()).await {
        tracing::warn!(error = %e, "Upgrade write failed");
    }
    let _ = w.shutdown().await;
}
