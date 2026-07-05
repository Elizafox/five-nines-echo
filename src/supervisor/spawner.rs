use std::os::unix::io::RawFd;
use std::time::Duration;

use anyhow::{Result, bail};
use futures::StreamExt;
use tokio::io::AsyncWriteExt;
use tokio_util::codec::{FramedRead, LinesCodec};

use crate::{
    auth::{SharedAllowlist, check_peer},
    worker_common,
};

#[derive(Clone)]
pub(super) struct SpawnerFds {
    pub(super) processor: RawFd,
    pub(super) plain: RawFd,
    pub(super) tls: RawFd,
    pub(super) scanner: RawFd,
}

/// Spawner accept loop. Workers dial in, send `{"role":"..."}`, get back the listener FD that role
/// owns via `SCM_RIGHTS`.
pub(super) async fn accept_spawner(
    listener: tokio::net::UnixListener,
    fds: SpawnerFds,
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
                    tracing::warn!(error = %e, "spawner peer rejected");
                    continue;
                }
                let fds = fds.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_spawn_request(stream, &fds).await {
                        tracing::warn!(error = %e, "spawner request failed");
                    }
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "spawner accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

async fn handle_spawn_request(stream: tokio::net::UnixStream, fds: &SpawnerFds) -> Result<()> {
    // Read one JSON line from the request side. We don't want to take ownership of `stream`
    // permanently yet because we need it for the SCM_RIGHTS reply on the SAME socket. So; split,
    // read, recombine.
    let (read_half, write_half) = stream.into_split();
    let mut reader = FramedRead::new(read_half, LinesCodec::new_with_max_length(8192));
    let line = match reader.next().await {
        Some(Ok(l)) => l,
        Some(Err(e)) => bail!("spawn request decode: {e}"),
        None => return Ok(()),
    };
    let stream = reader.into_inner().reunite(write_half).unwrap();

    let req: worker_common::SpawnRequest = serde_json::from_str(&line)?;
    let fd = match req.role.as_str() {
        "processor" => fds.processor,
        "plain" => fds.plain,
        "tls" => fds.tls,
        "scanner" => fds.scanner,
        other => {
            let msg = format!("err: unknown role {other}\n");
            let (_, mut w) = stream.into_split();
            let _ = w.write_all(msg.as_bytes()).await;
            return Ok(());
        }
    };
    worker_common::send_fd_via_scm(&stream, fd, b"ok\n").await?;
    tracing::info!(role = %req.role, fd, "served listener FD via SCM_RIGHTS");
    Ok(())
}
