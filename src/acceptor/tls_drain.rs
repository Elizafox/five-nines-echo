use std::io::{self, Read, Write};
use std::mem;
use std::os::unix::io::{AsFd, AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{self, Command};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use nix::{
    libc,
    poll::{PollFd, PollFlags, PollTimeout, poll},
    unistd::{ForkResult, close, fork},
};

use crate::{
    control::{DrainerEvent, SessionOutcome},
    handoff::{
        CloexecGuard, ENV_LISTENER_FD, ENV_UPGRADE_GENERATION, fdpass_env_to_remove,
        install_fexecve_pre_exec, require_static_for_capmode_upgrade, resolve_upgrade_exe,
        scrub_fdpass_env,
    },
};

use super::{ClientRegistry, upgrade::AcceptorUpgradeContext};
use crate::coverage::flush_coverage;

/// Live TLS-session snapshot harvested from the tokio task during upgrade. The `conn` is the rustls
/// in-memory state (traffic secrets, sequence numbers, pending TLS records); we keep it as-is and
/// hand it to the post-fork child drainer, which drives the session synchronously to completion.
pub(super) struct TlsHandoff {
    pub(super) tcp_fd: RawFd,
    pub(super) uds_fd: RawFd,
    pub(super) conn: rustls::ServerConnection,
    pub(super) peer_addr: String,
}

/// TLS upgrade path: fork-and-drain.
///
/// 1. Cancel all in-flight TLS tasks; each task hands back its live `(tcp_fd, uds_fd,
///    rustls::ServerConnection)` via a oneshot.
/// 2. `nix::unistd::fork()`.
/// 3. PARENT exec's the new binary; the listener FD passes via env (CLOEXEC cleared). Session FDs
///    stay CLOEXEC=true so the parent's exec drops them in the new image. The child keeps its
///    copies; CLOEXEC doesn't fire on fork.
/// 4. CHILD must not touch tokio after fork (the reactor inherits shared kqueue/epoll FDs with the
///    parent; it's UB to keep driving it). Instead, it spawns one std OS thread per session that
///    runs `rustls::ServerConnection` against blocking std sockets via `nix::poll::poll`. A
///    deadline thread calls `libc::_exit(0)` at 5s.
pub(super) async fn do_upgrade_tls_fork_drain(
    listener: tokio::net::TcpListener,
    registry: Arc<Mutex<ClientRegistry>>,
    ctx: AcceptorUpgradeContext<'_>,
) -> Result<()> {
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

    let handoffs = harvest_tls_handoffs(&registry, role).await;

    // Prepare listener FD for parent's execve.
    let std_listener = listener.into_std().context("listener into_std")?;
    let listener_fd = std_listener.into_raw_fd();
    let cloexec_guard = CloexecGuard::clear(listener_fd).context("clear CLOEXEC on listener")?;

    // Session FDs keep CLOEXEC=true (default), so they vanish in the parent's
    // post-exec image and only the child retains them.

    let target_overridden = binary_path.is_some();
    let exe = resolve_upgrade_exe(binary_path, &self_exe.path);

    // SAFETY: we're about to either exec (parent) or _exit (child) without
    // returning into async code. The child must not touch tokio.
    let pid = match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            // Child here
            // Don't .await, don't touch tokio. Use blocking I/O on threads.
            run_tls_drainer_child(
                handoffs,
                listener_fd,
                generation + 1,
                &config.drainer_sock(),
            );

            // Belt-and-suspenders: should be unreachable.
            flush_coverage();
            // SAFETY: We're past fork in the child; bypassing Rust destructors is exactly the point.
            unsafe { libc::_exit(0) };
        }
        Ok(ForkResult::Parent { child }) => child.as_raw(),
        Err(e) => bail!("fork failed: {e}"),
    };

    // Parent.
    tracing::info!(
        role = role.name(),
        child_pid = pid,
        sessions_handed_off = handoffs.len(),
        listener_fd,
        next_generation = generation + 1,
        exe = %exe.display(),
        "tls fork-drain: parent exec'ing new image",
    );
    // Forget the handoff vector: its `RawFd`s are plain ints (no Drop). The session FDs stay open
    // in the parent until exec; CLOEXEC then closes them in the new image. Dropping the Vec doesn't
    // close anything either, so this is just for clarity.
    mem::forget(handoffs);

    let mut cmd = Command::new(&exe);
    scrub_fdpass_env(&mut cmd);
    cmd.arg(role.arg());
    cmd.env(ENV_LISTENER_FD, listener_fd.to_string());
    cmd.env(ENV_UPGRADE_GENERATION, (generation + 1).to_string());
    // No ENV_CLIENTS: rustls state isn't serializable; child has it instead.

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
    ];
    // Cap-mode self-upgrade: hand the pre-opened config/sockets/cert/key/self-exe
    // FDs to the successor (see `cap_mode_handoff`). Guards must outlive the
    // exec below; on exec success the image is replaced (Drop never runs).
    #[cfg(target_os = "freebsd")]
    let _handoff_guards = crate::handoff::cap_mode_handoff(
        &mut fexecve_env,
        config,
        self_exe,
        dirs,
        target_overridden,
        role.name(),
    )?;

    // Under FreeBSD cap_enter, path-based execve is blocked. Install the fexecve hook so the exec
    // uses our pre-opened binary FD instead. The hook runs in the would-be-forked child context,
    // but we're calling .exec() which is sync: std forks internally, runs pre_exec, then execvp. We
    // want pre_exec to win.
    if !target_overridden {
        require_static_for_capmode_upgrade(self_exe)?;
        install_fexecve_pre_exec(
            &mut cmd,
            self_exe.fd.as_raw_fd(),
            self_exe.path.to_string_lossy().into_owned(),
            role.arg().to_string(),
            fexecve_env,
            fdpass_env_to_remove(),
        );
    }

    // exec() either replaces our process or returns Err; we're about to disappear into the new
    // image. CLOEXEC=false on the listener is the whole point.
    cloexec_guard.commit();
    // exec replaces this image; capture the parent's coverage (this function's harvest path) first.
    flush_coverage();
    let err = cmd.exec();
    bail!("execve failed: {err}")
}

async fn harvest_tls_handoffs(
    registry: &Arc<Mutex<ClientRegistry>>,
    role: super::Role,
) -> Vec<TlsHandoff> {
    let clients = {
        let mut reg = registry.lock().unwrap();
        mem::take(&mut reg.clients)
    };
    tracing::info!(
        role = role.name(),
        initial = clients.len(),
        "harvesting tls sessions for fork-drain"
    );

    let mut tls_handoff_rxs = Vec::new();
    for (_id, handle) in clients {
        let _ = handle.cancel.send(());
        if let Some(rx) = handle.tls_handoff {
            tls_handoff_rxs.push(rx);
        }
    }

    let mut handoffs = Vec::new();
    for rx in tls_handoff_rxs {
        let rx = rx;
        tokio::pin!(rx);
        let slow_handoff = tokio::time::sleep(Duration::from_secs(1));
        tokio::pin!(slow_handoff);
        let handoff = tokio::select! {
            res = &mut rx => res,
            () = &mut slow_handoff => {
                tracing::warn!(
                    "tls handoff still pending; waiting to preserve zero-downtime upgrade"
                );
                (&mut rx).await
            }
        };
        if let Ok(h) = handoff {
            handoffs.push(h);
        }
    }
    tracing::info!(
        role = role.name(),
        harvested = handoffs.len(),
        "tls sessions harvested; about to fork",
    );
    handoffs
}

// =================================================================================================
//                          POST-FORK CHILD DRAINER
// =================================================================================================
// EVERYTHING below this point runs in the forked child. NO tokio. NO async. NO Rust destructors
// that touch shared state. We exit via `libc::_exit` so the runtime never gets a chance to clean up
// its (forked, undefined) state.

fn run_tls_drainer_child(
    handoffs: Vec<TlsHandoff>,
    listener_fd: RawFd,
    generation: u64,
    drainer_sock_path: &PathBuf,
) {
    // Close the listener: parent owns the accept queue via exec. In the child it's a dup the
    // parent still owns and will exec with, so closing here only releases our local handle.
    let _ = close(listener_fd);

    let n = handoffs.len();
    eprintln!("[tls-drainer] child started, {n} session(s)");

    // Best-effort sync UDS to the supervisor's drainer socket. If supervisor is gone or socket is
    // missing, drainer keeps draining; it just won't report.
    let reporter: Arc<Mutex<Option<std::os::unix::net::UnixStream>>> = Arc::new(Mutex::new(
        std::os::unix::net::UnixStream::connect(drainer_sock_path).ok(),
    ));
    send_drainer_event(
        &reporter,
        &DrainerEvent::Hello {
            role: "tls".to_string(),
            pid: process::id(),
            generation,
            session_count: n,
        },
    );

    // Live count of sessions still being drained; read by the deadline thread so its DeadlineExit
    // frame can report how many were forcibly killed.
    let remaining = Arc::new(AtomicUsize::new(n));

    // Deadline thread: hard cap on how long we drain.
    {
        let reporter = reporter.clone();
        let remaining = remaining.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(5));
            let r = remaining.load(Ordering::SeqCst);
            send_drainer_event(&reporter, &DrainerEvent::DeadlineExit { remaining: r });
            // Tiny grace so the kernel actually flushes our last frame before
            // _exit yanks the FD out.
            std::thread::sleep(Duration::from_millis(100));
            eprintln!("[tls-drainer] deadline hit; _exit");
            flush_coverage();
            // SAFETY: We're past fork in the child; bypassing Rust destructors is exactly the point.
            unsafe { libc::_exit(0) };
        });
    }

    let mut threads = Vec::with_capacity(n);
    for (i, h) in handoffs.into_iter().enumerate() {
        let peer = h.peer_addr.clone();
        let reporter = reporter.clone();
        let remaining = remaining.clone();
        let t = std::thread::spawn(move || {
            let outcome = match drain_one_tls_session(h) {
                Ok(()) => {
                    eprintln!("[tls-drainer] session #{i} ({peer}) drained clean");
                    SessionOutcome::CleanEof
                }
                Err(e) => {
                    eprintln!("[tls-drainer] session #{i} ({peer}) ended: {e}");
                    SessionOutcome::Error {
                        message: e.to_string(),
                    }
                }
            };
            send_drainer_event(&reporter, &DrainerEvent::SessionDone { peer, outcome });
            remaining.fetch_sub(1, Ordering::SeqCst);
        });
        threads.push(t);
    }
    for t in threads {
        let _ = t.join();
    }
    send_drainer_event(&reporter, &DrainerEvent::Complete);
    eprintln!("[tls-drainer] all sessions done; _exit");

    flush_coverage();
    // SAFETY: see drain_one_tls_session; post-fork, skipping destructors.
    unsafe { libc::_exit(0) };
}

fn send_drainer_event(
    reporter: &Arc<Mutex<Option<std::os::unix::net::UnixStream>>>,
    ev: &DrainerEvent,
) {
    let Ok(mut line) = serde_json::to_string(ev) else {
        return;
    };
    line.push('\n');
    let Ok(mut guard) = reporter.lock() else {
        return;
    };
    let Some(stream) = guard.as_mut() else {
        return;
    };
    if stream.write_all(line.as_bytes()).is_err() {
        // Stream broke. Drop it so subsequent events don't keep failing.
        *guard = None;
    }
}

fn drain_one_tls_session(h: TlsHandoff) -> io::Result<()> {
    // SAFETY: the TlsHandoff carries owned RawFds the parent forked to us; nothing else in this
    // child wraps them. Consuming `h` here transfers ownership into the std stream types.
    let (mut tcp, mut uds) = (
        unsafe { std::net::TcpStream::from_raw_fd(h.tcp_fd) },
        unsafe { std::os::unix::net::UnixStream::from_raw_fd(h.uds_fd) },
    );
    tcp.set_nonblocking(true)?;
    uds.set_nonblocking(true)?;
    let mut conn = h.conn;

    let mut last_progress = Instant::now();
    let idle_timeout = Duration::from_millis(1500);
    let poll_timeout = PollTimeout::try_from(250i32).unwrap();
    let read_or_done = PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR;

    loop {
        if conn.wants_write() {
            match conn.write_tls(&mut tcp) {
                Ok(_) => last_progress = Instant::now(),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }

        let mut tcp_poll_flags = PollFlags::POLLIN;
        if conn.wants_write() {
            tcp_poll_flags |= PollFlags::POLLOUT;
        }
        let mut fds = [
            PollFd::new(tcp.as_fd(), tcp_poll_flags),
            PollFd::new(uds.as_fd(), PollFlags::POLLIN),
        ];
        let rc = match poll(&mut fds, poll_timeout) {
            Ok(n) => n,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(io::Error::from(e)),
        };
        if rc == 0 {
            if last_progress.elapsed() > idle_timeout {
                // No progress for a while; call it drained.
                return Ok(());
            }
            continue;
        }

        let tcp_revents = fds[0].revents().unwrap_or(PollFlags::empty());
        let uds_revents = fds[1].revents().unwrap_or(PollFlags::empty());

        // TCP -> UDS (decrypt incoming TLS, push plaintext to processor).
        if tcp_revents.intersects(read_or_done) {
            match conn.read_tls(&mut tcp) {
                Ok(0) => return Ok(()), // TLS peer EOF
                Ok(_) => {
                    if let Err(e) = conn.process_new_packets() {
                        return Err(io::Error::other(e));
                    }
                    let mut buf = [0u8; 8192];
                    loop {
                        match conn.reader().read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                let mut sent = 0;
                                while sent < n {
                                    match uds.write(&buf[sent..n]) {
                                        Ok(0) => return Ok(()),
                                        Ok(m) => sent += m,
                                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                            std::thread::sleep(Duration::from_millis(5));
                                        }
                                        Err(e) => return Err(e),
                                    }
                                }
                                last_progress = Instant::now();
                            }
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            Err(e) => return Err(e),
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }

        // UDS -> TLS (read plaintext from processor, encrypt out to client).
        if uds_revents.intersects(read_or_done) {
            let mut buf = [0u8; 8192];
            match uds.read(&mut buf) {
                Ok(0) => return Ok(()), // processor side EOF
                Ok(n) => {
                    conn.writer().write_all(&buf[..n])?;
                    last_progress = Instant::now();
                    while conn.wants_write() {
                        match conn.write_tls(&mut tcp) {
                            Ok(_) => {}
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            Err(e) => return Err(e),
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
    }
}
