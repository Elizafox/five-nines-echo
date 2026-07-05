//! systemd integration: socket activation + `Type=notify` ready signaling.
//!
//! All entry points are no-ops when the relevant systemd env vars aren't
//! set, so the daemon behaves identically when launched outside a unit.
//! Auto-detected via the standard `LISTEN_PID == getpid()` and
//! `NOTIFY_SOCKET` env-var contracts — no CLI flag.

use std::collections::VecDeque;
use std::env;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;

use anyhow::{Context, Result};

use crate::handoff::duration_millis_u64;

/// systemd's `sd_listen_fds()` says inherited FDs start at 3.
const SD_LISTEN_FDS_START: RawFd = 3;

/// Listeners passed in by systemd, in the order they appeared in the unit
/// file. Names come from `LISTEN_FDNAMES` (or `"unknown"` if absent), and may
/// repeat when a single `.socket` unit declares multiple `ListenStream=`s.
pub struct SdListeners {
    inner: VecDeque<(String, OwnedFd)>,
}

impl SdListeners {
    /// Detect socket activation. Returns an empty handle when the env vars
    /// aren't set or `LISTEN_PID` doesn't match us — the standard guard
    /// against inherited-env confusion in forked children.
    pub fn from_env() -> Result<Self> {
        let listen_pid: u32 = match env::var("LISTEN_PID") {
            Ok(s) => s.parse().context("parse LISTEN_PID")?,
            Err(_) => return Ok(Self::empty()),
        };
        if listen_pid != std::process::id() {
            tracing::debug!(
                listen_pid,
                self_pid = std::process::id(),
                "LISTEN_PID mismatch; not adopting systemd FDs"
            );
            return Ok(Self::empty());
        }
        let count: i32 = match env::var("LISTEN_FDS") {
            Ok(s) => s.parse().context("parse LISTEN_FDS")?,
            Err(_) => return Ok(Self::empty()),
        };
        if count <= 0 {
            return Ok(Self::empty());
        }
        let names_env = env::var("LISTEN_FDNAMES").unwrap_or_default();
        let names: Vec<&str> = if names_env.is_empty() {
            Vec::new()
        } else {
            names_env.split(':').collect()
        };

        let count = usize::try_from(count).context("LISTEN_FDS must be non-negative")?;
        let mut inner = VecDeque::with_capacity(count);
        for i in 0..count {
            let fd = SD_LISTEN_FDS_START + RawFd::try_from(i).context("LISTEN_FDS too large")?;
            let name = names.get(i).copied().unwrap_or("unknown").to_string();
            // SAFETY: systemd handed us this FD via fork+exec; we own it
            // from here. Wrapping in OwnedFd means Drop will close it if we
            // never consume it.
            let owned = unsafe { OwnedFd::from_raw_fd(fd) };
            inner.push_back((name, owned));
        }

        // Scrub the env so nothing downstream (re-exec'd children, etc.)
        // mistakes them for fresh activation. The standard sd_listen_fds()
        // does this too.
        // SAFETY: this runs during single-threaded startup (FD adoption
        // happens before the tokio runtime and any workers spawn), so no other
        // thread can be reading the environment concurrently.
        #[allow(clippy::multiple_unsafe_ops_per_block, reason = "related operations")]
        unsafe {
            env::remove_var("LISTEN_PID");
            env::remove_var("LISTEN_FDS");
            env::remove_var("LISTEN_FDNAMES");
        }

        tracing::info!(count, names = %names_env, "adopted systemd-activated listeners");
        Ok(Self { inner })
    }

    fn empty() -> Self {
        Self {
            inner: VecDeque::new(),
        }
    }

    /// Take the first FD whose `LISTEN_FDNAMES` entry matches `name`.
    /// Returns `None` if we're not under socket activation or the name
    /// doesn't appear.
    pub fn take_by_name(&mut self, name: &str) -> Option<OwnedFd> {
        let pos = self.inner.iter().position(|(n, _)| n == name)?;
        let (_, fd) = self.inner.remove(pos)?;
        Some(fd)
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

// --- Type=notify ready signaling -----------------------------------------

/// Send `READY=1` to systemd. No-op if `NOTIFY_SOCKET` is unset.
pub fn notify_ready() {
    notify("READY=1\n");
}

/// Send `STOPPING=1` so systemd marks us as cleanly shutting down.
pub fn notify_stopping() {
    notify("STOPPING=1\n");
}

/// Send a short human-visible status line shown in `systemctl status`.
pub fn notify_status(line: &str) {
    notify(&format!("STATUS={line}\n"));
}

fn notify(message: &str) {
    if let Err(e) = notify_impl(message) {
        tracing::debug!(error = %e, "sd_notify failed");
    }
}

fn notify_impl(message: &str) -> Result<()> {
    let Some(path_os) = env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };
    let bytes = path_os.as_encoded_bytes();
    let sock = UnixDatagram::unbound().context("notify socket")?;

    if bytes.starts_with(b"@") {
        // Abstract namespace (Linux-only). `@/foo/bar` → `\0/foo/bar`.
        #[cfg(target_os = "linux")]
        {
            use nix::sys::socket::{MsgFlags, UnixAddr, sendto};
            use std::os::fd::AsRawFd;

            let addr =
                UnixAddr::new_abstract(&bytes[1..]).context("abstract NOTIFY_SOCKET addr")?;
            sendto(
                sock.as_raw_fd(),
                message.as_bytes(),
                &addr,
                MsgFlags::empty(),
            )
            .context("sendto abstract NOTIFY_SOCKET")?;
            return Ok(());
        }
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("abstract NOTIFY_SOCKET only supported on Linux");
        }
    }

    sock.send_to(message.as_bytes(), Path::new(&path_os))
        .context("send_to NOTIFY_SOCKET")?;
    Ok(())
}

// --- Type=notify watchdog (WatchdogSec=) ----------------------------------

/// A liveness beacon for the systemd watchdog.
///
/// The supervisor's core `select!` loop bumps this counter as it makes
/// forward progress. The watchdog ping task only sends `WATCHDOG=1` when the
/// counter has advanced since its previous check — so a wedged runtime (which
/// can no longer poll the select loop, hence can't advance the beacon) is
/// correctly reported to systemd as hung, rather than being masked by a
/// free-running timer that would keep pinging regardless.
#[derive(Clone, Default)]
pub struct WatchdogBeacon(Arc<AtomicU64>);

impl WatchdogBeacon {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one unit of forward progress in the supervisor's core loop.
    pub fn tick(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    fn load(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// systemd's watchdog interval (`WATCHDOG_USEC`), or `None` when the watchdog
/// isn't enabled for us. Mirrors `sd_watchdog_enabled`: requires a non-zero
/// `WATCHDOG_USEC`, and — when `WATCHDOG_PID` is present — that it names this
/// process (the same guard pattern as `LISTEN_PID`). A forked worker inherits
/// `WATCHDOG_USEC` but not a matching PID, so this returns `None` there; an
/// `execve`-based supervisor self-upgrade keeps the PID, so it stays enabled.
fn watchdog_usec() -> Option<u64> {
    let usec: u64 = env::var("WATCHDOG_USEC").ok()?.parse().ok()?;
    if usec == 0 {
        return None;
    }
    if let Ok(pid) = env::var("WATCHDOG_PID")
        && pid.parse::<u32>().ok() != Some(std::process::id())
    {
        return None;
    }
    Some(usec)
}

/// How often the supervisor should bump the beacon from its select loop: a
/// quarter of the watchdog interval, so the beacon advances ~twice per ping.
/// Falls back to a slow tick when the watchdog is off (the beacon is then
/// unused, but the select-loop arm still needs a duration).
pub fn beacon_tick_interval() -> Duration {
    match watchdog_usec() {
        Some(usec) => Duration::from_micros((usec / 4).max(1)),
        None => Duration::from_secs(10),
    }
}

/// Spawn the watchdog ping task, if systemd configured `WatchdogSec=` for us.
///
/// Pings at half the interval (systemd's recommended margin for scheduling
/// jitter) but only while `beacon` keeps advancing. Returns `None` — no task
/// spawned — when the watchdog isn't enabled for this process, so callers can
/// invoke it unconditionally.
pub fn spawn_watchdog(beacon: WatchdogBeacon) -> Option<tokio::task::JoinHandle<()>> {
    let usec = watchdog_usec()?;
    let interval = Duration::from_micros((usec / 2).max(1));
    tracing::info!(
        watchdog_usec = usec,
        ping_interval_ms = duration_millis_u64(interval),
        "systemd watchdog enabled"
    );
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // Consume the immediate first tick and seed from the current beacon so
        // we don't log a spurious stall before the loop has run even once.
        ticker.tick().await;
        let mut last_seen = beacon.load();
        loop {
            ticker.tick().await;
            let now = beacon.load();
            if now == last_seen {
                tracing::error!("watchdog beacon stalled; not pinging systemd");
            } else {
                last_seen = now;
                notify("WATCHDOG=1\n");
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn from_env_with_no_listen_pid_is_empty() {
        let env_lock = crate::test_env::lock();
        let _e = crate::test_env::EnvScope::save(
            &env_lock,
            &["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"],
        );
        let l = SdListeners::from_env().unwrap();
        assert!(l.is_empty());
    }

    #[test]
    fn from_env_with_mismatched_pid_is_empty() {
        let env_lock = crate::test_env::lock();
        let _e = crate::test_env::EnvScope::save(
            &env_lock,
            &["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"],
        );
        // SAFETY: serialized by the shared test env lock.
        #[allow(clippy::multiple_unsafe_ops_per_block, reason = "related env writes")]
        unsafe {
            env::set_var("LISTEN_PID", "1"); // not us
            env::set_var("LISTEN_FDS", "1");
        }
        let l = SdListeners::from_env().unwrap();
        assert!(l.is_empty());
    }

    #[test]
    fn from_env_with_pid_match_but_zero_fds_is_empty() {
        let env_lock = crate::test_env::lock();
        let _e = crate::test_env::EnvScope::save(
            &env_lock,
            &["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"],
        );
        // SAFETY: serialized by the shared test env lock.
        #[allow(clippy::multiple_unsafe_ops_per_block, reason = "related env writes")]
        unsafe {
            env::set_var("LISTEN_PID", std::process::id().to_string());
            env::set_var("LISTEN_FDS", "0");
        }
        let l = SdListeners::from_env().unwrap();
        assert!(l.is_empty());
    }

    #[test]
    fn from_env_parse_error_propagates() {
        let env_lock = crate::test_env::lock();
        let _e = crate::test_env::EnvScope::save(
            &env_lock,
            &["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"],
        );
        // SAFETY: serialized by the shared test env lock.
        unsafe {
            env::set_var("LISTEN_PID", "not-a-number");
        }
        let r = SdListeners::from_env();
        assert!(r.is_err());
    }

    #[test]
    fn take_by_name_on_empty_returns_none() {
        let env_lock = crate::test_env::lock();
        let _e = crate::test_env::EnvScope::save(
            &env_lock,
            &["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"],
        );
        let mut l = SdListeners::from_env().unwrap();
        assert!(l.take_by_name("anything").is_none());
    }

    #[test]
    fn notify_with_no_socket_env_is_noop() {
        let env_lock = crate::test_env::lock();
        let _e = crate::test_env::EnvScope::save(&env_lock, &["NOTIFY_SOCKET"]);
        // Should not panic; errors are swallowed.
        notify_ready();
        notify_stopping();
        notify_status("hello");
    }

    #[test]
    fn notify_ready_sends_datagram_to_filesystem_socket() {
        let env_lock = crate::test_env::lock();
        let _e = crate::test_env::EnvScope::save(&env_lock, &["NOTIFY_SOCKET"]);

        let sock_path = std::env::temp_dir().join(format!(
            "fdpass-notify-test-{}-{}.sock",
            std::process::id(),
            line!(),
        ));
        let _ = std::fs::remove_file(&sock_path);
        let sock = UnixDatagram::bind(&sock_path).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        // SAFETY: serialized by the shared test env lock.
        unsafe { env::set_var("NOTIFY_SOCKET", &sock_path) };

        notify_ready();

        let mut buf = [0u8; 64];
        let n = sock.recv(&mut buf).expect("READY=1 datagram never arrived");
        assert_eq!(&buf[..n], b"READY=1\n");

        let _ = std::fs::remove_file(&sock_path);
    }

    #[test]
    fn notify_status_carries_inline_text() {
        let env_lock = crate::test_env::lock();
        let _e = crate::test_env::EnvScope::save(&env_lock, &["NOTIFY_SOCKET"]);

        let sock_path = std::env::temp_dir().join(format!(
            "fdpass-notify-test-{}-{}.sock",
            std::process::id(),
            line!(),
        ));
        let _ = std::fs::remove_file(&sock_path);
        let sock = UnixDatagram::bind(&sock_path).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        // SAFETY: serialized by the shared test env lock.
        unsafe { env::set_var("NOTIFY_SOCKET", &sock_path) };

        notify_status("upgrade in progress");

        let mut buf = [0u8; 128];
        let n = sock.recv(&mut buf).expect("STATUS datagram never arrived");
        assert_eq!(&buf[..n], b"STATUS=upgrade in progress\n");

        let _ = std::fs::remove_file(&sock_path);
    }

    fn bind_notify_socket(tag: u32) -> (std::path::PathBuf, UnixDatagram) {
        let sock_path = std::env::temp_dir().join(format!(
            "fdpass-watchdog-test-{}-{}.sock",
            std::process::id(),
            tag,
        ));
        let _ = std::fs::remove_file(&sock_path);
        let sock = UnixDatagram::bind(&sock_path).unwrap();
        (sock_path, sock)
    }

    #[test]
    fn watchdog_noop_when_env_unset() {
        let env_lock = crate::test_env::lock();
        let _e = crate::test_env::EnvScope::save(
            &env_lock,
            &["NOTIFY_SOCKET", "WATCHDOG_USEC", "WATCHDOG_PID"],
        );
        // No WATCHDOG_USEC → watchdog not enabled, no task spawned.
        assert!(spawn_watchdog(WatchdogBeacon::new()).is_none());
    }

    #[test]
    fn watchdog_noop_when_pid_mismatch() {
        let env_lock = crate::test_env::lock();
        let _e = crate::test_env::EnvScope::save(
            &env_lock,
            &["NOTIFY_SOCKET", "WATCHDOG_USEC", "WATCHDOG_PID"],
        );
        // SAFETY: serialized by the shared test env lock.
        #[allow(clippy::multiple_unsafe_ops_per_block, reason = "related env writes")]
        unsafe {
            env::set_var("WATCHDOG_USEC", "40000");
            env::set_var("WATCHDOG_PID", "1"); // PID 1 is never the test process
        }
        assert!(spawn_watchdog(WatchdogBeacon::new()).is_none());
    }

    // The shared test env lock must span the whole test, awaits included: it serializes the
    // process-global env mutations below against the other env-touching tests,
    // which the harness may run on parallel threads. Safe here — a
    // current_thread runtime means no other task runs while the guard is held.
    #[allow(
        clippy::await_holding_lock,
        reason = "test serializes process-global env mutation across awaits on current_thread runtime"
    )]
    #[tokio::test(flavor = "current_thread")]
    async fn watchdog_pings_when_beacon_advances() {
        let env_lock = crate::test_env::lock();
        let _e = crate::test_env::EnvScope::save(
            &env_lock,
            &["NOTIFY_SOCKET", "WATCHDOG_USEC", "WATCHDOG_PID"],
        );
        let (sock_path, sock) = bind_notify_socket(line!());
        sock.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        // SAFETY: serialized by the shared test env lock. WATCHDOG_PID left unset -> enabled
        // regardless of our PID (the absent-PID branch of watchdog_usec).
        #[allow(clippy::multiple_unsafe_ops_per_block, reason = "related env writes")]
        unsafe {
            env::set_var("NOTIFY_SOCKET", &sock_path);
            env::set_var("WATCHDOG_USEC", "40000"); // ping interval = 20ms
        }

        let beacon = WatchdogBeacon::new();
        let handle = spawn_watchdog(beacon.clone()).expect("watchdog should be enabled");
        // Keep the beacon advancing across several ping intervals.
        for _ in 0..6 {
            beacon.tick();
            tokio::time::sleep(Duration::from_millis(15)).await;
        }

        let mut buf = [0u8; 64];
        let n = sock
            .recv(&mut buf)
            .expect("WATCHDOG=1 datagram never arrived");
        assert_eq!(&buf[..n], b"WATCHDOG=1\n");

        handle.abort();
        let _ = std::fs::remove_file(&sock_path);
    }

    // See `watchdog_pings_when_beacon_advances`: the shared test env lock intentionally spans
    // the awaits to serialize env mutation against parallel tests.
    #[allow(
        clippy::await_holding_lock,
        reason = "test serializes process-global env mutation across awaits on current_thread runtime"
    )]
    #[tokio::test(flavor = "current_thread")]
    async fn watchdog_silent_when_beacon_stalled() {
        let env_lock = crate::test_env::lock();
        let _e = crate::test_env::EnvScope::save(
            &env_lock,
            &["NOTIFY_SOCKET", "WATCHDOG_USEC", "WATCHDOG_PID"],
        );
        let (sock_path, sock) = bind_notify_socket(line!());
        // SAFETY: serialized by the shared test env lock.
        #[allow(clippy::multiple_unsafe_ops_per_block, reason = "related env writes")]
        unsafe {
            env::set_var("NOTIFY_SOCKET", &sock_path);
            env::set_var("WATCHDOG_USEC", "40000"); // ping interval = 20ms
        }

        let beacon = WatchdogBeacon::new();
        let handle = spawn_watchdog(beacon.clone()).expect("watchdog should be enabled");
        // Never tick the beacon. Wait out several ping intervals.
        tokio::time::sleep(Duration::from_millis(120)).await;
        handle.abort();

        // Nothing should have been sent while the beacon was stalled.
        sock.set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let mut buf = [0u8; 64];
        assert!(
            sock.recv(&mut buf).is_err(),
            "watchdog pinged systemd despite a stalled beacon"
        );

        let _ = std::fs::remove_file(&sock_path);
    }
}
