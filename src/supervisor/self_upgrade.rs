use std::env;
use std::mem;
use std::os::unix::io::RawFd;
use std::process;

use anyhow::{Context, Result};
use tokio::process::Command;

use crate::{
    config::Config,
    handoff::{
        CloexecGuard, ENV_CTRL_ADMIN_FD, ENV_CTRL_DRAINER_FD, ENV_CTRL_PLAIN_FD,
        ENV_CTRL_PROCESSOR_FD, ENV_CTRL_SCANNER_FD, ENV_CTRL_SPAWNER_FD, ENV_CTRL_TLS_FD,
        ENV_LISTENER_PLAIN_FD, ENV_LISTENER_PROCESSOR_FD, ENV_LISTENER_SCANNER_FD,
        ENV_LISTENER_TLS_FD, ENV_PLAIN_GEN, ENV_PLAIN_PID, ENV_PROCESSOR_GEN, ENV_PROCESSOR_PID,
        ENV_READY_FD, ENV_SCANNER_GEN, ENV_SCANNER_PID, ENV_SUP_GENERATION, ENV_TLS_GEN,
        ENV_TLS_PID, UPGRADE_COMMIT_EXIT_CODE, make_ready_pipe, scrub_fdpass_env,
        wait_for_child_ready,
    },
};

#[derive(Default, Clone)]
pub(super) struct AdoptedState {
    pub(super) processor: Option<u32>,
    pub(super) plain: Option<u32>,
    pub(super) tls: Option<u32>,
    pub(super) scanner: Option<u32>,
    /// Each worker's last-reported generation, carried across the supervisor self-upgrade so the
    /// fresh supervisor seeds its `wait_for_successor` baseline with the real generation instead of
    /// defaulting an adopted gen-N worker to 0. Only meaningful where the matching PID is `Some`.
    pub(super) processor_gen: u64,
    pub(super) plain_gen: u64,
    pub(super) tls_gen: u64,
    pub(super) scanner_gen: u64,
}

/// Bundle of inherited FDs preserved across the supervisor's self-upgrade exec: six control-plane
/// sockets (`*_ctrl`, `admin`, `drainer`, `spawner`) plus the four worker listener FDs that
/// supervisor owns and `SCM_RIGHTS`'s to workers on spawn.
pub(super) struct ControlFds {
    pub(super) admin: RawFd,
    pub(super) processor_ctrl: RawFd,
    pub(super) plain_ctrl: RawFd,
    pub(super) tls_ctrl: RawFd,
    pub(super) scanner_ctrl: RawFd,
    pub(super) drainer: RawFd,
    pub(super) spawner: RawFd,
    pub(super) processor_listener: RawFd,
    pub(super) plain_listener: RawFd,
    pub(super) tls_listener: RawFd,
    pub(super) scanner_listener: RawFd,
}

/// Two-phase supervisor self-upgrade. On commit, calls
/// `process::exit(UPGRADE_COMMIT_EXIT_CODE)` so the spawned child takes over with all the inherited
/// FDs and the grandparent treats the old supervisor as cleanly replaced. On rollback (child failed
/// to signal ready), kills the child and returns Ok; the old supervisor's tasks (control planes,
/// watchdogs, supervise loops) are unaffected as they were never torn down. Returns Err only if
/// the upgrade machinery failed (couldn't spawn, etc.).
pub(super) async fn do_self_upgrade(
    fds: &ControlFds,
    pids: &AdoptedState,
    generation: u64,
    config: &Config,
) -> Result<()> {
    let mut cloexec_guards: Vec<CloexecGuard> = Vec::new();
    for (fd, label) in [
        (fds.admin, "ctrl-admin"),
        (fds.processor_ctrl, "ctrl-processor"),
        (fds.plain_ctrl, "ctrl-plain"),
        (fds.tls_ctrl, "ctrl-tls"),
        (fds.scanner_ctrl, "ctrl-scanner"),
        (fds.drainer, "ctrl-drainer"),
        (fds.spawner, "ctrl-spawner"),
        (fds.processor_listener, "listener-processor"),
        (fds.plain_listener, "listener-plain"),
        (fds.tls_listener, "listener-tls"),
        (fds.scanner_listener, "listener-scanner"),
    ] {
        cloexec_guards
            .push(CloexecGuard::clear(fd).with_context(|| format!("clear CLOEXEC {label}"))?);
    }

    let exe = env::current_exe().context("current_exe")?;
    let (parent_read, child_write_fd) = make_ready_pipe().context("ready pipe")?;

    let mut cmd = Command::new(exe);
    scrub_fdpass_env(cmd.as_std_mut());
    cmd.arg("supervisor");
    cmd.env(ENV_CTRL_ADMIN_FD, fds.admin.to_string());
    cmd.env(ENV_CTRL_PROCESSOR_FD, fds.processor_ctrl.to_string());
    cmd.env(ENV_CTRL_PLAIN_FD, fds.plain_ctrl.to_string());
    cmd.env(ENV_CTRL_TLS_FD, fds.tls_ctrl.to_string());
    cmd.env(ENV_CTRL_SCANNER_FD, fds.scanner_ctrl.to_string());
    cmd.env(ENV_CTRL_DRAINER_FD, fds.drainer.to_string());
    cmd.env(ENV_CTRL_SPAWNER_FD, fds.spawner.to_string());
    cmd.env(
        ENV_LISTENER_PROCESSOR_FD,
        fds.processor_listener.to_string(),
    );
    cmd.env(ENV_LISTENER_PLAIN_FD, fds.plain_listener.to_string());
    cmd.env(ENV_LISTENER_TLS_FD, fds.tls_listener.to_string());
    cmd.env(ENV_LISTENER_SCANNER_FD, fds.scanner_listener.to_string());
    // Pair each adopted PID with its generation so the successor supervisor can seed the role's
    // wait_for_successor baseline (see `AdoptedState`).
    if let Some(p) = pids.processor {
        cmd.env(ENV_PROCESSOR_PID, p.to_string());
        cmd.env(ENV_PROCESSOR_GEN, pids.processor_gen.to_string());
    }
    if let Some(p) = pids.plain {
        cmd.env(ENV_PLAIN_PID, p.to_string());
        cmd.env(ENV_PLAIN_GEN, pids.plain_gen.to_string());
    }
    if let Some(p) = pids.tls {
        cmd.env(ENV_TLS_PID, p.to_string());
        cmd.env(ENV_TLS_GEN, pids.tls_gen.to_string());
    }
    if let Some(p) = pids.scanner {
        cmd.env(ENV_SCANNER_PID, p.to_string());
        cmd.env(ENV_SCANNER_GEN, pids.scanner_gen.to_string());
    }
    cmd.env(ENV_SUP_GENERATION, (generation + 1).to_string());
    cmd.env(ENV_READY_FD, child_write_fd.to_string());

    tracing::info!(
        next_generation = generation + 1,
        "spawning self-upgrade child",
    );

    let mut child = cmd.spawn().context("spawn self-upgrade child")?;
    let _ = nix::unistd::close(child_write_fd);

    match wait_for_child_ready(parent_read, config.ready_timeout()).await {
        Ok(()) => {
            tracing::info!(
                generation = generation + 1,
                "self-upgrade committed; exiting"
            );
            mem::forget(child);
            for g in cloexec_guards {
                g.commit();
            }
            process::exit(UPGRADE_COMMIT_EXIT_CODE)
        }
        Err(e) => {
            tracing::error!(error = %e, "self-upgrade rollback: killing child");
            let _ = child.kill().await;
            let _ = child.wait().await;
            // Our control planes, watchdogs, and supervise loops are all still running. Nothing to
            // restore beyond the guards' Drop, which restores CLOEXEC on every FD we cleared.
            Ok(())
        }
    }
}
