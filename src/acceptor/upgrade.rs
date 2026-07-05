use std::mem;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
use std::path::PathBuf;
use std::process;
use std::sync::{Arc, Mutex};

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

use super::{ClientRegistry, Role, tls_drain::do_upgrade_tls_fork_drain};

pub(super) struct AcceptorUpgradeContext<'a> {
    pub(super) role: Role,
    pub(super) generation: u64,
    pub(super) binary_path: Option<PathBuf>,
    pub(super) config: &'a Config,
    pub(super) self_exe: &'a SelfExe,
    pub(super) dirs: HandoffDirFds,
}

/// Drive an upgrade. The Ok variant is reached only when the upgrade rolled back and the listener
/// is returned to the caller; on commit, the plain path calls
/// `process::exit(UPGRADE_COMMIT_EXIT_CODE)`. The TLS path still uses `exec()` and so has no
/// rollback (the fork-drain child is already detached by then); it returns only on exec error.
pub(super) async fn do_upgrade(
    listener: tokio::net::TcpListener,
    registry: Arc<Mutex<ClientRegistry>>,
    ctx: AcceptorUpgradeContext<'_>,
) -> Result<tokio::net::TcpListener> {
    match ctx.role {
        Role::Plain => do_upgrade_plain(listener, ctx).await,
        Role::Tls => {
            do_upgrade_tls_fork_drain(listener, registry, ctx).await?;
            unreachable!("tls fork-drain returns only on exec error")
        }
    }
}

async fn do_upgrade_plain(
    listener: tokio::net::TcpListener,
    ctx: AcceptorUpgradeContext<'_>,
) -> Result<tokio::net::TcpListener> {
    let AcceptorUpgradeContext {
        role,
        generation,
        binary_path,
        config,
        self_exe,
        dirs,
    } = ctx;
    #[cfg(not(target_os = "freebsd"))]
    let _ = dirs;

    let std_listener = listener.into_std().context("listener into_std")?;
    let listener_fd = std_listener.into_raw_fd();
    let cloexec_guard = CloexecGuard::clear(listener_fd).context("clear CLOEXEC on listener")?;

    let target_overridden = binary_path.is_some();
    let exe = resolve_upgrade_exe(binary_path, &self_exe.path);
    let (parent_read, child_write_fd) = make_ready_pipe().context("ready pipe")?;

    tracing::info!(
        role = role.name(),
        listener_fd,
        next_generation = generation + 1,
        exe = %exe.display(),
        "plain acceptor spawning upgrade child",
    );

    let mut cmd = tokio::process::Command::new(&exe);
    scrub_fdpass_env(cmd.as_std_mut());
    cmd.arg(role.arg());
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
        role.name(),
    )?;

    if !target_overridden {
        require_static_for_capmode_upgrade(self_exe)?;
        install_fexecve_pre_exec(
            cmd.as_std_mut(),
            self_exe.fd.as_raw_fd(),
            self_exe.path.to_string_lossy().into_owned(),
            role.arg().to_string(),
            fexecve_env,
            fdpass_env_to_remove(),
        );
    }

    let mut child = cmd.spawn().context("spawn upgrade child")?;
    let _ = close(child_write_fd);

    match wait_for_child_ready(parent_read, config.ready_timeout()).await {
        Ok(()) => {
            tracing::info!(
                role = role.name(),
                generation = generation + 1,
                "upgrade committed"
            );
            mem::forget(child);
            cloexec_guard.commit();
            process::exit(UPGRADE_COMMIT_EXIT_CODE)
        }
        Err(e) => {
            tracing::error!(role = role.name(), error = %e, "upgrade rollback: killing child");
            let _ = child.kill().await;
            let _ = child.wait().await;
            // SAFETY: `listener_fd` is still owned by this process on rollback; the child has been
            // reaped, so wrapping it returns listener ownership to the accept loop.
            let std_l = unsafe { std::net::TcpListener::from_raw_fd(listener_fd) };
            std_l.set_nonblocking(true)?;
            Ok(tokio::net::TcpListener::from_std(std_l)?)
        }
    }
}
