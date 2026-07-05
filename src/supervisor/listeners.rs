use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::systemd::SdListeners;

/// Read an optional PID from the environment.
pub(super) fn env_pid(key: &str) -> Option<u32> {
    env::var(key).ok().and_then(|s| s.parse().ok())
}

/// Same idea as `adopt_or_bind_control` but supervisor keeps the FD as a bare `RawFd` instead of
/// wrapping into a `tokio::net::UnixListener`. Supervisor never accepts these directly; they're
/// passed to workers via `SCM_RIGHTS`.
pub(super) fn adopt_or_bind_uds_worker(
    env_key: &str,
    sd_name: &str,
    path: &Path,
    is_upgrade: bool,
    sd: &mut SdListeners,
) -> Result<(RawFd, PathBuf)> {
    if let Some(owned) = sd.take_by_name(sd_name) {
        let fd = owned.into_raw_fd();
        tracing::info!(sd_name, fd, "adopted worker UDS listener FD from systemd");
        return Ok((fd, path.to_path_buf()));
    }
    if let Ok(fd_str) = env::var(env_key) {
        let fd: RawFd = fd_str.parse().with_context(|| env_key.to_string())?;
        tracing::info!(
            env_key,
            fd,
            "adopted worker UDS listener FD across self-upgrade"
        );
        return Ok((fd, path.to_path_buf()));
    }
    if !is_upgrade {
        let _ = fs::remove_file(path);
    }
    let std_listener = std::os::unix::net::UnixListener::bind(path)
        .with_context(|| format!("bind {}", path.display()))?;
    let fd = std_listener.into_raw_fd();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    tracing::info!(env_key, sock = %path.display(), fd, "bound new worker UDS listener");
    Ok((fd, path.to_path_buf()))
}

pub(super) fn adopt_or_bind_tcp_worker(
    env_key: &str,
    sd_name: &str,
    port: u16,
    sd: &mut SdListeners,
) -> Result<RawFd> {
    if let Some(owned) = sd.take_by_name(sd_name) {
        let fd = owned.into_raw_fd();
        tracing::info!(sd_name, fd, "adopted worker TCP listener FD from systemd");
        return Ok(fd);
    }
    if let Ok(fd_str) = env::var(env_key) {
        let fd: RawFd = fd_str.parse().with_context(|| env_key.to_string())?;
        tracing::info!(
            env_key,
            fd,
            "adopted worker TCP listener FD across self-upgrade"
        );
        return Ok(fd);
    }
    let std_listener = std::net::TcpListener::bind(("127.0.0.1", port))
        .with_context(|| format!("bind 127.0.0.1:{port}"))?;
    let fd = std_listener.into_raw_fd();
    tracing::info!(env_key, port, fd, "bound new worker TCP listener");
    Ok(fd)
}

/// Adopt or bind a control-plane `UnixListener`, returning the live listener and its raw fd so the
/// supervisor can preserve it across self-upgrade.
pub(super) async fn adopt_or_bind_control(
    env_key: &str,
    sd_name: &str,
    path: &Path,
    is_upgrade: bool,
    sd: &mut SdListeners,
) -> Result<(tokio::net::UnixListener, RawFd)> {
    if let Some(owned) = sd.take_by_name(sd_name) {
        let fd = owned.into_raw_fd();
        // SAFETY: systemd already bound and listen()ed on this FD. We just wrap it; the OwnedFd we
        // consumed via into_raw_fd means nothing else holds a reference.
        let std_listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
        std_listener.set_nonblocking(true)?;
        let listener = tokio::net::UnixListener::from_std(std_listener)?;
        tracing::info!(sd_name, fd, "adopted control-plane listener from systemd");
        return Ok((listener, fd));
    }
    if let Ok(fd_str) = env::var(env_key) {
        let fd: RawFd = fd_str.parse().with_context(|| env_key.to_string())?;
        // SAFETY: env var was set by the previous-generation supervisor immediately before exec,
        // with CLOEXEC cleared. We own the FD now.
        let std_listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
        std_listener.set_nonblocking(true)?;
        let listener = tokio::net::UnixListener::from_std(std_listener)?;
        tracing::info!(sock = %path.display(), fd, "adopted inherited control-plane listener");
        return Ok((listener, fd));
    }
    if !is_upgrade {
        let _ = fs::remove_file(path);
    }
    let listener =
        tokio::net::UnixListener::bind(path).with_context(|| format!("bind {}", path.display()))?;
    let fd = listener.as_raw_fd();
    tracing::info!(sock = %path.display(), fd, "bound new control-plane listener");
    Ok((listener, fd))
}
