use std::time::Duration;

use futures::StreamExt;
use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};
use tokio_util::codec::{FramedRead, LinesCodec};

use crate::{
    auth::{SharedAllowlist, check_peer},
    control::DrainerEvent,
};

/// Accept connections from fork-and-drain child processes and log their event stream. Each child
/// opens one connection, writes Hello + per-session `SessionDoneFrames` + a terminal Complete or
/// `DeadlineExit`, then `_exit`s.
pub(super) async fn accept_drainer(listener: tokio::net::UnixListener, allow: SharedAllowlist) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let peer_check = {
                    let allow = allow.read().unwrap();
                    check_peer(&stream, &allow)
                };
                if let Err(e) = peer_check {
                    tracing::warn!(error = %e, "drainer peer rejected");
                    continue;
                }
                tokio::spawn(handle_drainer_connection(stream));
            }
            Err(e) => {
                tracing::warn!(error = %e, "drainer accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

async fn handle_drainer_connection(stream: tokio::net::UnixStream) {
    let (read_half, _write_half) = stream.into_split();
    let mut reader = FramedRead::new(read_half, LinesCodec::new_with_max_length(64 * 1024));
    while let Some(line) = reader.next().await {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(error = %e, "drainer decode error");
                break;
            }
        };
        match serde_json::from_str::<DrainerEvent>(&line) {
            Ok(DrainerEvent::Hello {
                role,
                pid,
                generation,
                session_count,
            }) => {
                tracing::info!(
                    role = %role,
                    pid,
                    generation,
                    session_count,
                    "drainer: child connected",
                );
            }
            Ok(DrainerEvent::SessionDone { peer, outcome }) => {
                tracing::info!(peer = %peer, ?outcome, "drainer: session done");
            }
            Ok(DrainerEvent::Complete) => {
                tracing::info!("drainer: all sessions drained, child exiting clean");
            }
            Ok(DrainerEvent::DeadlineExit { remaining }) => {
                tracing::warn!(remaining, "drainer: deadline hit; force-exit");
            }
            Err(e) => tracing::warn!(error = %e, line = %line, "drainer bad event"),
        }
    }
    tracing::debug!("drainer connection closed");
}

pub(super) fn send_sigterm(pid: u32) {
    let Ok(pid) = i32::try_from(pid) else {
        tracing::warn!(pid, "refusing to signal pid outside platform range");
        return;
    };
    let _ = kill(Pid::from_raw(pid), Some(Signal::SIGTERM));
}
