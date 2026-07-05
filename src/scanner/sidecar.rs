use std::sync::Arc;

use tokio::{io::AsyncWriteExt, sync::mpsc};

use crate::{
    config::Config,
    control::{ProcessorPreamble, SessionMetadata},
    worker_common::SocketsDialer,
};

pub(super) async fn run_sidecar_publisher(
    dialer: Arc<SocketsDialer>,
    mut rx: mpsc::Receiver<SessionMetadata>,
) {
    loop {
        let mut stream = match dialer.dial(&Config::socket_basename("proc")).await {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!(error = %e, "sidecar dial failed; retry");
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                continue;
            }
        };
        let Ok(mut preamble) = serde_json::to_string(&ProcessorPreamble::Sidecar) else {
            return;
        };
        preamble.push('\n');
        if let Err(e) = stream.write_all(preamble.as_bytes()).await {
            tracing::debug!(error = %e, "sidecar preamble write failed; retry");
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            continue;
        }
        tracing::info!("sidecar connected to processor");

        loop {
            let Some(meta) = rx.recv().await else {
                tracing::info!("sidecar publisher channel closed");
                return;
            };
            let mut line = match serde_json::to_string(&meta) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "sidecar serialize failed");
                    continue;
                }
            };
            line.push('\n');
            if let Err(e) = stream.write_all(line.as_bytes()).await {
                tracing::warn!(error = %e, peer = %meta.peer, "sidecar write failed; will reconnect");
                break;
            }
        }
    }
}
