use std::env;
use std::fs;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;

use crate::{config::Config, handoff::ENV_LISTENER_FD};

use super::recv_fd_via_scm;

/// Request/response on the supervisor's spawner UDS. Workers dial in,
/// announce their role, receive their listener FD via `SCM_RIGHTS`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpawnRequest {
    pub role: String,
}

/// Dial the supervisor's spawner UDS, send `{role}`, receive the listener FD via `SCM_RIGHTS`.
/// Bounded retries as the supervisor may not yet be ready.
pub async fn request_listener_fd(role: &str, config: &Config) -> Result<OwnedFd> {
    let sock = config.spawner_sock();
    let mut stream = dial_with_retry(&sock)
        .await
        .with_context(|| format!("dial spawner {}", sock.display()))?;
    let req = SpawnRequest {
        role: role.to_string(),
    };
    let mut line = serde_json::to_string(&req)?;
    line.push('\n');
    stream.write_all(line.as_bytes()).await?;
    let (owned_fd, payload) = recv_fd_via_scm(&stream).await?;
    let payload_str = String::from_utf8_lossy(&payload);
    if !payload_str.starts_with("ok") {
        bail!("spawner replied: {}", payload_str.trim());
    }
    Ok(owned_fd)
}

async fn dial_with_retry(path: &Path) -> io::Result<tokio::net::UnixStream> {
    let mut last_err: Option<io::Error> = None;
    for attempt in 0..50 {
        match tokio::net::UnixStream::connect(path).await {
            Ok(s) => return Ok(s),
            Err(e) => {
                last_err = Some(e);
                let delay = if attempt < 5 { 100 } else { 300 };
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::other("dial budget exhausted")))
}

/// Three-priority listener acquisition, in order:
///   1. `ENV_LISTENER_FD`: set by our previous self at exec time (graceful self-upgrade path);
///   2. `SCM_RIGHTS` from the supervisor's spawner socket: fresh spawn after a crash, where the
///      supervisor still owns the listener, or;
///   3. Bind fresh at `sock_path`: only useful for standalone runs.
pub async fn adopt_or_bind_uds_listener(
    sock_path: &Path,
    role: &'static str,
    config: &Config,
) -> Result<tokio::net::UnixListener> {
    if let Ok(fd_str) = env::var(ENV_LISTENER_FD) {
        let fd: RawFd = fd_str
            .parse()
            .with_context(|| ENV_LISTENER_FD.to_string())?;
        // SAFETY: env var set by our previous self right before exec, with CLOEXEC cleared; we own
        // the FD now
        let std_listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
        std_listener.set_nonblocking(true)?;
        let listener = tokio::net::UnixListener::from_std(std_listener)?;
        tracing::info!(role, fd, "adopted inherited UDS listener from env");
        return Ok(listener);
    }

    match request_listener_fd(role, config).await {
        Ok(owned) => {
            let fd = owned.into_raw_fd();
            // SAFETY: SCM_RIGHTS minted this FD for us; we own it from here
            let std_listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
            std_listener.set_nonblocking(true)?;
            let listener = tokio::net::UnixListener::from_std(std_listener)?;
            tracing::info!(role, fd, "received UDS listener via SCM_RIGHTS");
            return Ok(listener);
        }
        Err(e) => {
            tracing::warn!(role, error = %e, "spawner unavailable; falling back to bind");
        }
    }

    let _ = fs::remove_file(sock_path);
    let listener = tokio::net::UnixListener::bind(sock_path)
        .with_context(|| format!("bind {}", sock_path.display()))?;
    fs::set_permissions(sock_path, fs::Permissions::from_mode(0o600))?;
    tracing::info!(role, sock = %sock_path.display(), "bound new UDS listener (fallback)");
    Ok(listener)
}

/// TCP analog of `adopt_or_bind_uds_listener`. Used by the plain/TLS acceptors. Same env FD ->
/// `SCM_RIGHTS` -> bind priority.
pub async fn adopt_or_bind_tcp_listener(
    addr: &str,
    role: &'static str,
    config: &Config,
) -> Result<tokio::net::TcpListener> {
    if let Ok(fd_str) = env::var(ENV_LISTENER_FD) {
        let fd: RawFd = fd_str
            .parse()
            .with_context(|| ENV_LISTENER_FD.to_string())?;
        // SAFETY: see uds variant above
        let std_listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
        std_listener.set_nonblocking(true)?;
        let listener = tokio::net::TcpListener::from_std(std_listener)?;
        tracing::info!(role, fd, "adopted inherited TCP listener from env");
        return Ok(listener);
    }

    match request_listener_fd(role, config).await {
        Ok(owned) => {
            let fd = owned.into_raw_fd();
            // SAFETY: SCM_RIGHTS-minted; we own it
            let std_listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
            std_listener.set_nonblocking(true)?;
            let listener = tokio::net::TcpListener::from_std(std_listener)?;
            tracing::info!(role, fd, "received TCP listener via SCM_RIGHTS");
            return Ok(listener);
        }
        Err(e) => {
            tracing::warn!(role, error = %e, "spawner unavailable; falling back to bind");
        }
    }

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    tracing::info!(role, addr, "bound new TCP listener (fallback)");
    Ok(listener)
}
