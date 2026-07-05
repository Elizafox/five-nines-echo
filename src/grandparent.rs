//! Grandparent: respawns the supervisor if it crashes.
//!
//! The grandparent is a thin watchdog around `echod supervisor`. It puts the supervisor in its own
//! process group so the full worker tree can be killed together if the supervisor dies
//! unexpectedly, then respawns with exponential backoff. In production, this layer is normally
//! provided by an init system (systemd `Restart=on-failure`); grandparent mode is a self-contained
//! alternative for demos and environments without systemd.

use std::process::ExitStatus;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use nix::{
    sys::signal::{Signal, kill, killpg},
    unistd::Pid,
};
use tokio::{
    process::Command,
    signal::unix::{SignalKind, signal},
    time::sleep,
};
use tracing::{error, info};

use crate::handoff::{ENV_UNDER_GRANDPARENT, duration_millis_u64};

const MIN_BACKOFF: Duration = Duration::from_millis(500);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
const HEALTHY_UPTIME: Duration = Duration::from_mins(1);

pub async fn run() -> Result<()> {
    let exe = std::env::current_exe().context("current_exe")?;
    let mut backoff = MIN_BACKOFF;

    let mut term = signal(SignalKind::terminate())?;
    let mut intr = signal(SignalKind::interrupt())?;

    loop {
        let mut cmd = Command::new(&exe);
        cmd.arg("supervisor");
        // Place the supervisor in a fresh process group so we can target
        // killpg(2) at it and its descendants together. Workers inherit the
        // group from the supervisor at spawn time.
        cmd.process_group(0);
        // Tell the supervisor it's running under grandparent supervision so it can refuse
        // SIGHUP self-upgrade (which would process::exit and trigger our killpg, killing the
        // newly committed successor before it has a chance to run).
        cmd.env(ENV_UNDER_GRANDPARENT, "1");

        let start = Instant::now();
        let mut child = cmd.spawn().context("spawn supervisor")?;
        let sup_pid = child
            .id()
            .and_then(|pid| i32::try_from(pid).ok())
            .expect("just-spawned child has valid pid");
        info!(sup_pid, "grandparent: supervisor spawned");

        let outcome = tokio::select! {
            r = child.wait() => Outcome::Exited(r?),
            _ = term.recv() => Outcome::Signaled(Signal::SIGTERM),
            _ = intr.recv() => Outcome::Signaled(Signal::SIGINT),
        };

        match outcome {
            Outcome::Signaled(sig) => {
                info!(
                    ?sig,
                    sup_pid, "grandparent: forwarding signal to supervisor"
                );
                let _ = kill(Pid::from_raw(sup_pid), sig);
                let _ = child.wait().await;
                return Ok(());
            }
            Outcome::Exited(status) if status.success() => {
                info!(sup_pid, ?status, "grandparent: supervisor exited cleanly");
                return Ok(());
            }
            Outcome::Exited(status) => {
                let uptime = start.elapsed();
                error!(
                    sup_pid,
                    ?status,
                    uptime_ms = duration_millis_u64(uptime),
                    backoff_ms = duration_millis_u64(backoff),
                    "grandparent: supervisor crashed; killing worker pgrp and respawning",
                );
                // Orphaned workers can't be controlled (their admin/control
                // sockets pointed at the dead supervisor). Nuke them so the
                // new supervisor can rebind listening ports.
                let _ = killpg(Pid::from_raw(sup_pid), Signal::SIGKILL);
                if uptime > HEALTHY_UPTIME {
                    backoff = MIN_BACKOFF;
                }
                sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
}

enum Outcome {
    Exited(ExitStatus),
    Signaled(Signal),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_until_max() {
        let mut b = MIN_BACKOFF;
        let mut seen = vec![b];
        for _ in 0..20 {
            b = (b * 2).min(MAX_BACKOFF);
            seen.push(b);
        }
        assert_eq!(seen[0], MIN_BACKOFF);
        assert_eq!(*seen.last().unwrap(), MAX_BACKOFF);
        assert!(seen.windows(2).all(|w| w[1] >= w[0]));
    }

    #[test]
    fn healthy_uptime_threshold_resets_backoff() {
        // Mirror the logic in run(): if uptime > HEALTHY_UPTIME we reset.
        let uptime_ok = Duration::from_mins(2);
        let uptime_bad = Duration::from_secs(5);
        let reset = |u: Duration, b: Duration| if u > HEALTHY_UPTIME { MIN_BACKOFF } else { b };
        assert_eq!(reset(uptime_ok, Duration::from_secs(8)), MIN_BACKOFF);
        assert_eq!(
            reset(uptime_bad, Duration::from_secs(8)),
            Duration::from_secs(8)
        );
    }
}
