use std::mem;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
use std::process;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use nix::unistd::close;

use crate::{
    config::Config,
    handoff::{
        CloexecGuard, ENV_LISTENER_FD, ENV_READY_FD, ENV_UPGRADE_GENERATION, HandoffDirFds,
        SelfExe, UPGRADE_COMMIT_EXIT_CODE, fdpass_env_to_remove, install_fexecve_pre_exec,
        make_ready_pipe, require_static_for_capmode_upgrade, resolve_upgrade_exe, scrub_fdpass_env,
        wait_for_child_ready,
    },
};

use super::ScannerRegistry;

/// Spawn a fresh scanner binary via the two-phase ready-pipe protocol. On commit, this function
/// calls `process::exit(UPGRADE_COMMIT_EXIT_CODE)` and never returns, so the supervisor treats the
/// old scanner as cleanly replaced. On rollback (child failed to signal ready in time), kills the
/// child and hands the listener back to the caller so it can resume serving.
pub(super) async fn do_upgrade(
    listener: tokio::net::UnixListener,
    registry: &Arc<Mutex<ScannerRegistry>>,
    generation: u64,
    binary_path: Option<std::path::PathBuf>,
    config: &Config,
    self_exe: &SelfExe,
    #[cfg_attr(
        not(target_os = "freebsd"),
        allow(
            unused_variables,
            reason = "directory FDs are only handed to cap-mode successors on FreeBSD"
        )
    )]
    dirs: HandoffDirFds,
) -> Result<tokio::net::UnixListener> {
    let drain_deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    loop {
        let count = registry.lock().unwrap().in_flight.len();
        if count == 0 {
            break;
        }
        if tokio::time::Instant::now() > drain_deadline {
            tracing::warn!(
                remaining = count,
                "scanner drain deadline; abandoning in-flight"
            );
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let std_listener = listener.into_std().context("listener into_std")?;
    let listener_fd = std_listener.into_raw_fd();
    let cloexec_guard =
        CloexecGuard::clear(listener_fd).context("clear CLOEXEC on scanner listener")?;
    let target_overridden = binary_path.is_some();
    let exe = resolve_upgrade_exe(binary_path, &self_exe.path);
    let (parent_read, child_write_fd) = make_ready_pipe().context("ready pipe")?;

    tracing::info!(
        next_generation = generation + 1,
        exe = %exe.display(),
        "scanner spawning upgrade child",
    );

    let mut cmd = tokio::process::Command::new(&exe);
    scrub_fdpass_env(cmd.as_std_mut());
    cmd.arg("scanner");
    cmd.env(ENV_LISTENER_FD, listener_fd.to_string());
    cmd.env(ENV_UPGRADE_GENERATION, (generation + 1).to_string());
    cmd.env(ENV_READY_FD, child_write_fd.to_string());

    #[cfg_attr(
        not(target_os = "freebsd"),
        allow(
            unused_mut,
            reason = "FreeBSD cap-mode handoff appends inherited FD env vars before fexecve"
        )
    )]
    let mut fexecve_env = vec![
        (ENV_LISTENER_FD.to_string(), listener_fd.to_string()),
        (
            ENV_UPGRADE_GENERATION.to_string(),
            (generation + 1).to_string(),
        ),
        (ENV_READY_FD.to_string(), child_write_fd.to_string()),
    ];
    #[cfg(target_os = "freebsd")]
    let _handoff_guards = crate::handoff::cap_mode_handoff(
        &mut fexecve_env,
        config,
        self_exe,
        dirs,
        target_overridden,
        "scanner",
    )?;

    if !target_overridden {
        require_static_for_capmode_upgrade(self_exe)?;
        install_fexecve_pre_exec(
            cmd.as_std_mut(),
            self_exe.fd.as_raw_fd(),
            self_exe.path.to_string_lossy().into_owned(),
            "scanner".to_string(),
            fexecve_env,
            fdpass_env_to_remove(),
        );
    }

    let mut child = cmd.spawn().context("spawn upgrade child")?;
    let _ = close(child_write_fd);

    match wait_for_child_ready(parent_read, config.ready_timeout()).await {
        Ok(()) => {
            tracing::info!(generation = generation + 1, "upgrade committed; exiting");
            mem::forget(child);
            cloexec_guard.commit();
            process::exit(UPGRADE_COMMIT_EXIT_CODE);
        }
        Err(e) => {
            tracing::error!(error = %e, "upgrade rollback: killing child");
            let _ = child.kill().await;
            let _ = child.wait().await;
            // SAFETY: `listener_fd` is still owned by this process on rollback; the child has been
            // reaped, so wrapping it returns listener ownership to the scanner loop.
            let std_l = unsafe { std::os::unix::net::UnixListener::from_raw_fd(listener_fd) };
            std_l.set_nonblocking(true)?;
            Ok(tokio::net::UnixListener::from_std(std_l)?)
        }
    }
}
