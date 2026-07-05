use std::collections::HashMap;
use std::env;
use std::fs;
use std::io;
use std::mem;
use std::os::fd::OwnedFd;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::path::PathBuf;
use std::process;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use nix::unistd::{close, pipe};
use tokio::net::UnixListener;
use tokio::task::JoinHandle;
use tokio_util::codec::{Framed, FramedParts, LinesCodec};

use crate::{
    config::Config,
    control::SessionMetadata,
    handoff::{
        CloexecGuard, ENV_LISTENER_FD, ENV_READY_FD, ENV_SESSIONS, ENV_SESSIONS_FD,
        ENV_UPGRADE_GENERATION, HandoffDirFds, SelfExe, SessionHandoff, Transport,
        UPGRADE_COMMIT_EXIT_CODE, clear_cloexec, fdpass_env_to_remove, install_fexecve_pre_exec,
        is_schema_compatible, make_ready_pipe, require_static_for_capmode_upgrade,
        resolve_upgrade_exe, scrub_fdpass_env, set_cloexec, wait_for_child_ready,
    },
};

use super::{SessionRegistry, spawn_session};

// `Framed::new` initialises `is_readable` to `false`, so `read_buffer_mut().extend_from_slice`
// silently strands any pre-loaded bytes until the peer sends more. `FramedParts` sets `is_readable`
// when `read_buf` is non-empty, so `poll_next` decodes buffered lines immediately.
//
// `write_lookahead` seeds the write buffer with echo bytes a pre-upgrade `send` was still flushing
// when the session was cancelled; the adopted session task flushes them before resuming so the
// interrupted echo completes instead of arriving torn.
fn framed_with_lookahead(
    stream: tokio::net::UnixStream,
    read_lookahead: &[u8],
    write_lookahead: &[u8],
) -> Framed<tokio::net::UnixStream, LinesCodec> {
    let mut parts = FramedParts::new::<String>(stream, LinesCodec::new_with_max_length(64 * 1024));
    parts.read_buf.extend_from_slice(read_lookahead);
    parts.write_buf.extend_from_slice(write_lookahead);
    Framed::from_parts(parts)
}

#[derive(Debug, Clone, Default)]
pub(super) struct UpgradeReq {
    pub(super) binary_path: Option<PathBuf>,
}

pub(super) struct ProcessorUpgradeContext<'a> {
    pub(super) generation: u64,
    pub(super) binary_path: Option<PathBuf>,
    pub(super) config: &'a Config,
    pub(super) self_exe: &'a SelfExe,
    pub(super) dirs: HandoffDirFds,
}

struct ProcessorUpgradeAttempt<'a> {
    child: tokio::process::Child,
    sessions_writer: JoinHandle<Result<()>>,
    parent_read: OwnedFd,
    config: &'a Config,
    generation: u64,
    registry: &'a Arc<Mutex<SessionRegistry>>,
    handoffs: Vec<SessionHandoff>,
    listener_fd: RawFd,
    cloexec_guard: CloexecGuard,
}

pub(super) fn cleanup_generation_zero_socket(generation: u64, sock_path: &std::path::Path) {
    // Generation 0 owns the socket file on disk; later generations adopted it.
    if generation == 0 {
        let _ = fs::remove_file(sock_path);
    }
}

pub(super) fn adopt_inflight_sessions(registry: &Arc<Mutex<SessionRegistry>>) -> Result<()> {
    let Some(payload) = read_handoff_sessions_json()? else {
        return Ok(());
    };
    let Some(sessions) = parse_handoff_sessions_payload(&payload)? else {
        return Ok(());
    };
    let raw_count = sessions.len();
    let sessions: Vec<SessionHandoff> = sessions
        .into_iter()
        .filter(|h| {
            let ok = is_schema_compatible(h.version);
            if !ok {
                tracing::warn!(
                    peer = %h.peer,
                    version = h.version,
                    "declined to adopt session with incompatible schema",
                );
            }
            ok
        })
        .collect();
    tracing::info!(
        count = sessions.len(),
        dropped = raw_count - sessions.len(),
        "adopting in-flight sessions"
    );
    for h in sessions {
        if let Some(ident) = h.ident.clone() {
            tracing::info!(
                peer = %h.peer,
                ident = %ident,
                "reinstating ident on adopted session",
            );
            registry.lock().unwrap().metadata.insert(
                h.peer.clone(),
                SessionMetadata {
                    peer: h.peer.clone(),
                    ident: Some(ident),
                    trace_id: h.trace_id.clone(),
                },
            );
        }
        match h.transport {
            Transport::Uds => match reconstruct_uds(h.uds_fd) {
                Ok(stream) => {
                    let framed = framed_with_lookahead(
                        stream,
                        &h.partial_line_bytes,
                        &h.pending_write_bytes,
                    );
                    spawn_session(
                        registry.clone(),
                        framed,
                        h.peer,
                        h.lines_echoed,
                        h.connected_at_unix_ms,
                        h.trace_id,
                    );
                }
                Err(e) => {
                    tracing::warn!(error = %e, uds_fd = h.uds_fd,
                        "uds session reconstruction failed; closing FD");
                    let _ = close(h.uds_fd);
                }
            },
            Transport::Tcp => {
                // Legacy plain-TCP session from a pre-bridge (SCM-era) generation. The SCM handoff
                // is gone, so there is no TCP session path to adopt into; decline cleanly rather
                // than misread a TCP fd as a UDS stream. Only reachable on the one upgrade that
                // removes SCM; afterwards all handoffs are `Uds`.
                tracing::warn!(peer = %h.peer, tcp_fd = h.uds_fd,
                    "declining legacy TCP session handoff; SCM plain path removed");
                let _ = close(h.uds_fd);
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum HandoffSessionsSource {
    Fd,
    Env,
}

struct HandoffSessionsPayload {
    json: String,
    source: HandoffSessionsSource,
}

fn read_handoff_sessions_json() -> Result<Option<HandoffSessionsPayload>> {
    match env::var(ENV_SESSIONS_FD) {
        Ok(fd_str) => {
            let fd: RawFd = fd_str
                .parse()
                .with_context(|| format!("parse {ENV_SESSIONS_FD}"))?;
            // SAFETY: the parent created this pipe read end for this successor, cleared CLOEXEC
            // before spawn, and advertised the fd number in ENV_SESSIONS_FD. We take ownership and
            // close it after reading the streamed JSON payload.
            let mut file = unsafe { fs::File::from_raw_fd(fd) };
            let mut json = String::new();
            io::Read::read_to_string(&mut file, &mut json)
                .with_context(|| format!("read {ENV_SESSIONS_FD} fd {fd}"))?;
            Ok(Some(HandoffSessionsPayload {
                json,
                source: HandoffSessionsSource::Fd,
            }))
        }
        Err(env::VarError::NotPresent) => {
            Ok(env::var(ENV_SESSIONS)
                .ok()
                .map(|json| HandoffSessionsPayload {
                    json,
                    source: HandoffSessionsSource::Env,
                }))
        }
        Err(e) => Err(e).context(ENV_SESSIONS_FD),
    }
}

fn parse_handoff_sessions_payload(
    payload: &HandoffSessionsPayload,
) -> Result<Option<Vec<SessionHandoff>>> {
    match serde_json::from_str(&payload.json) {
        Ok(v) => Ok(Some(v)),
        Err(e) => match payload.source {
            HandoffSessionsSource::Fd => {
                Err(e).context("parse session handoff JSON from FDPASS_SESSIONS_FD")
            }
            HandoffSessionsSource::Env => {
                tracing::error!(error = %e, "session handoff JSON parse failed; sessions lost");
                Ok(None)
            }
        },
    }
}

fn make_sessions_pipe() -> Result<(OwnedFd, OwnedFd)> {
    let (read_end, write_end) = pipe().context("session handoff pipe")?;
    clear_cloexec(read_end.as_raw_fd()).context("clear CLOEXEC on session handoff read fd")?;
    set_cloexec(write_end.as_raw_fd()).context("set CLOEXEC on session handoff write fd")?;
    Ok((read_end, write_end))
}

async fn finish_sessions_pipe_writer(writer: tokio::task::JoinHandle<Result<()>>) -> Result<()> {
    writer.await.context("session handoff writer join")?
}

fn spawn_sessions_pipe_writer(
    write_end: OwnedFd,
    sessions_json: String,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut file = fs::File::from(write_end);
        io::Write::write_all(&mut file, sessions_json.as_bytes())
            .context("write session handoff pipe")?;
        Ok(())
    })
}

fn reconstruct_uds(fd: RawFd) -> Result<tokio::net::UnixStream> {
    // SAFETY: caller hands us a fresh FD from a SessionHandoff that no one else has wrapped; we take
    // ownership here.
    let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
    std_stream.set_nonblocking(true)?;
    Ok(tokio::net::UnixStream::from_std(std_stream)?)
}

/// Drive a processor upgrade with rollback support.
///
/// On commit, calls `process::exit(UPGRADE_COMMIT_EXIT_CODE)` so the supervisor treats the old
/// processor as cleanly replaced by the spawned child. On rollback (child failed to signal ready in
/// time), re-adopts the previously-drained sessions back into our registry and returns the listener
/// so the accept loop can resume.
pub(super) async fn do_upgrade(
    listener: UnixListener,
    registry: Arc<Mutex<SessionRegistry>>,
    ctx: ProcessorUpgradeContext<'_>,
) -> Result<UnixListener> {
    let ProcessorUpgradeContext {
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
    let cloexec_guard =
        CloexecGuard::clear(listener_fd).context("clear CLOEXEC on processor listener")?;
    tracing::info!(listener_fd, "prepared listener FD for upgrade child");

    let handoffs = drain_session_handoffs(&registry).await;

    let target_overridden = binary_path.is_some();
    let exe = resolve_upgrade_exe(binary_path, &self_exe.path);
    let (parent_read, child_write_fd) = make_ready_pipe().context("ready pipe")?;

    tracing::info!(
        sessions = handoffs.len(),
        next_generation = generation + 1,
        exe = %exe.display(),
        "processor spawning upgrade child"
    );

    let sessions_json = serde_json::to_string(&handoffs)?;
    let (sessions_read, sessions_write) = make_sessions_pipe()?;
    let sessions_read_fd = sessions_read.as_raw_fd();
    let mut cmd = tokio::process::Command::new(&exe);
    scrub_fdpass_env(cmd.as_std_mut());
    cmd.arg("processor");
    cmd.env(ENV_LISTENER_FD, listener_fd.to_string());
    cmd.env(ENV_SESSIONS_FD, sessions_read_fd.to_string());
    cmd.env(ENV_UPGRADE_GENERATION, (generation + 1).to_string());
    cmd.env(ENV_READY_FD, child_write_fd.to_string());

    // On FreeBSD this swaps the stdlib's execvp(path) for fexecve(binary_fd), because
    // `cap_enter()` blocks path-based exec. No-op elsewhere. We only install the hook when the
    // upgrade is to our own image (no --target): a custom target path can't be pre-opened across
    // `cap_enter()`, so we leave the standard `execvp()` path for that case (which fails under
    // `cap_mode()`, a documented limitation).
    #[cfg_attr(
        not(target_os = "freebsd"),
        allow(
            unused_mut,
            reason = "FreeBSD cap-mode handoff appends inherited FD env vars before fexecve"
        )
    )]
    let mut fexecve_env = vec![
        (ENV_LISTENER_FD.to_string(), listener_fd.to_string()),
        (ENV_SESSIONS_FD.to_string(), sessions_read_fd.to_string()),
        (
            ENV_UPGRADE_GENERATION.to_string(),
            (generation + 1).to_string(),
        ),
        (ENV_READY_FD.to_string(), child_write_fd.to_string()),
    ];
    // Cap-mode self-upgrade: hand the pre-opened config/sockets/self-exe FDs to the successor so
    // its sandboxed startup never touches the path namespace. Guards held until the spawn below,
    // restored on rollback.
    #[cfg(target_os = "freebsd")]
    let _handoff_guards = crate::handoff::cap_mode_handoff(
        &mut fexecve_env,
        config,
        self_exe,
        dirs,
        target_overridden,
        "processor",
    )?;

    if !target_overridden {
        require_static_for_capmode_upgrade(self_exe)?;
        install_fexecve_pre_exec(
            cmd.as_std_mut(),
            self_exe.fd.as_raw_fd(),
            self_exe.path.to_string_lossy().into_owned(),
            "processor".to_string(),
            fexecve_env,
            fdpass_env_to_remove(),
        );
    }

    let child = cmd.spawn().context("spawn upgrade child")?;
    drop(sessions_read);
    let sessions_writer = spawn_sessions_pipe_writer(sessions_write, sessions_json);
    let _ = close(child_write_fd);

    finish_upgrade_attempt(ProcessorUpgradeAttempt {
        child,
        sessions_writer,
        parent_read,
        config,
        generation,
        registry: &registry,
        handoffs,
        listener_fd,
        cloexec_guard,
    })
    .await
}

async fn finish_upgrade_attempt(mut attempt: ProcessorUpgradeAttempt<'_>) -> Result<UnixListener> {
    let ready_result = if let Some(f) = fault_inject!("upgrade.ready_signal") {
        Err(f
            .into_anyhow()
            .context("synthetic: upgrade child never signaled ready"))
    } else {
        wait_for_child_ready(attempt.parent_read, attempt.config.ready_timeout()).await
    };

    if let Err(e) = ready_result {
        tracing::error!(error = %e, "upgrade rollback: re-adopting drained sessions");
        let _ = attempt.child.kill().await;
        let _ = attempt.child.wait().await;
        let _ = finish_sessions_pipe_writer(attempt.sessions_writer).await;

        // SAFETY: listener_fd still open; child's copy will close when it dies.
        let std_l = unsafe { std::os::unix::net::UnixListener::from_raw_fd(attempt.listener_fd) };
        std_l.set_nonblocking(true)?;
        let listener = UnixListener::from_std(std_l)?;
        readopt_sessions(attempt.registry, attempt.handoffs);
        return Ok(listener);
    }

    finish_sessions_pipe_writer(attempt.sessions_writer).await?;
    tracing::info!(generation = attempt.generation + 1, "upgrade committed");
    mem::forget(attempt.child);
    attempt.cloexec_guard.commit();
    process::exit(UPGRADE_COMMIT_EXIT_CODE)
}

async fn drain_session_handoffs(registry: &Arc<Mutex<SessionRegistry>>) -> Vec<SessionHandoff> {
    let (sessions, metadata_snapshot) = {
        let mut reg = registry.lock().unwrap();
        (mem::take(&mut reg.sessions), reg.metadata.clone())
    };

    let mut handoffs = Vec::new();
    for (_id, handle) in sessions {
        let _ = handle.cancel.send(());
        if let Some(handoff) = await_session_handoff(handle.handoff).await {
            handoffs.push(enrich_handoff(handoff, &metadata_snapshot));
        }
    }
    handoffs
}

async fn await_session_handoff(
    rx: tokio::sync::oneshot::Receiver<SessionHandoff>,
) -> Option<SessionHandoff> {
    if let Some(f) = fault_inject!("upgrade.session_handoff") {
        match f {
            crate::fault_inject::InjectedFault::Skip => {
                tracing::warn!("session handoff skipped by fault injection");
                if let Ok(h) = rx.await {
                    let _ = close(h.uds_fd);
                }
                return None;
            }
            other => {
                tracing::warn!(
                    error = %other.into_anyhow(),
                    "session handoff delayed by fault injection"
                );
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }

    let rx = rx;
    tokio::pin!(rx);
    let slow_handoff = tokio::time::sleep(Duration::from_secs(1));
    tokio::pin!(slow_handoff);
    let handoff = tokio::select! {
        res = &mut rx => res,
        () = &mut slow_handoff => {
            tracing::warn!(
                "session handoff still pending; waiting to preserve zero-downtime upgrade"
            );
            (&mut rx).await
        }
    };
    handoff.ok().and_then(|h| {
        if let Err(e) = clear_cloexec(h.uds_fd) {
            tracing::warn!(error = %e, "clear_cloexec on session FD failed; closing");
            let _ = close(h.uds_fd);
            return None;
        }
        Some(h)
    })
}

fn enrich_handoff(
    mut handoff: SessionHandoff,
    metadata_snapshot: &HashMap<String, SessionMetadata>,
) -> SessionHandoff {
    if let Some(metadata) = metadata_snapshot.get(&handoff.peer) {
        handoff.ident.clone_from(&metadata.ident);
    }
    handoff
}

/// Restore session handoffs back into the live registry after an upgrade rollback.
fn readopt_sessions(registry: &Arc<Mutex<SessionRegistry>>, handoffs: Vec<SessionHandoff>) {
    for h in handoffs {
        // Re-stash sidecar metadata if we have ident.
        if let Some(ident) = h.ident.clone() {
            registry.lock().unwrap().metadata.insert(
                h.peer.clone(),
                SessionMetadata {
                    peer: h.peer.clone(),
                    ident: Some(ident),
                    trace_id: h.trace_id.clone(),
                },
            );
        }
        match h.transport {
            Transport::Uds => match reconstruct_uds(h.uds_fd) {
                Ok(stream) => {
                    let framed = framed_with_lookahead(
                        stream,
                        &h.partial_line_bytes,
                        &h.pending_write_bytes,
                    );
                    spawn_session(
                        registry.clone(),
                        framed,
                        h.peer,
                        h.lines_echoed,
                        h.connected_at_unix_ms,
                        h.trace_id,
                    );
                }
                Err(e) => {
                    tracing::warn!(error = %e, uds_fd = h.uds_fd, "re-adopt UDS failed; closing");
                    let _ = close(h.uds_fd);
                }
            },
            Transport::Tcp => {
                // Legacy TCP session (see `adopt_inflight_sessions`). A new-image parent only ever
                // drains `Uds` sessions, so this is unreachable in practice; decline for safety.
                tracing::warn!(peer = %h.peer, tcp_fd = h.uds_fd,
                    "declining legacy TCP session on rollback; SCM plain path removed");
                let _ = close(h.uds_fd);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::IntoRawFd;

    use crate::handoff::{SCHEMA_VERSION, SessionHandoff, Transport};

    fn sample_handoff(fd: i32, version: u32, peer: &str, ident: Option<&str>) -> SessionHandoff {
        SessionHandoff {
            uds_fd: fd,
            transport: Transport::Uds,
            partial_line_bytes: b"pending".to_vec(),
            pending_write_bytes: Vec::new(),
            lines_echoed: 3,
            connected_at_unix_ms: 1_700_000_000_000,
            peer: peer.to_string(),
            ident: ident.map(str::to_string),
            trace_id: format!("trace-{peer}"),
            version,
        }
    }

    #[tokio::test]
    async fn sessions_pipe_streams_payload_to_reader() {
        let payload =
            r#"[{"uds_fd":42,"partial_line_bytes":[],"lines_echoed":0,"connected_at_unix_ms":0}]"#;
        let (read_end, write_end) = make_sessions_pipe().unwrap();
        let writer = spawn_sessions_pipe_writer(write_end, payload.to_string());

        // SAFETY: this test owns the read end returned by make_sessions_pipe and consumes it here
        // so the File closes it after read_to_string reaches EOF.
        let mut file = unsafe { fs::File::from_raw_fd(read_end.into_raw_fd()) };
        let mut got = String::new();
        io::Read::read_to_string(&mut file, &mut got).unwrap();

        finish_sessions_pipe_writer(writer).await.unwrap();
        assert_eq!(got, payload);
    }

    #[test]
    fn fd_session_payload_parse_error_is_fatal() {
        let payload = HandoffSessionsPayload {
            json: "not-json".to_string(),
            source: HandoffSessionsSource::Fd,
        };

        let err = parse_handoff_sessions_payload(&payload).unwrap_err();

        assert!(
            err.to_string().contains("FDPASS_SESSIONS_FD"),
            "error should identify the inherited session FD payload: {err:#}"
        );
    }

    #[test]
    fn env_session_payload_parse_error_is_nonfatal() {
        let payload = HandoffSessionsPayload {
            json: "not-json".to_string(),
            source: HandoffSessionsSource::Env,
        };

        let parsed = parse_handoff_sessions_payload(&payload).unwrap();

        assert!(parsed.is_none());
    }

    #[test]
    fn parse_handoff_sessions_payload_ok_returns_sessions() {
        let json = r#"[{"uds_fd":5,"transport":"uds","partial_line_bytes":[],"lines_echoed":3,"connected_at_unix_ms":1000,"peer":"1.2.3.4:5678","version":1}]"#;
        let payload = HandoffSessionsPayload {
            json: json.to_string(),
            source: HandoffSessionsSource::Env,
        };
        let sessions = parse_handoff_sessions_payload(&payload).unwrap().unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].uds_fd, 5);
        assert_eq!(sessions[0].lines_echoed, 3);
        assert_eq!(sessions[0].peer, "1.2.3.4:5678");
    }

    #[test]
    fn cleanup_generation_zero_socket_removes_file() {
        let path = std::env::temp_dir().join(format!("fdpass-cg0-{}.sock", std::process::id()));
        let _ = fs::remove_file(&path);
        fs::write(&path, b"").unwrap();
        cleanup_generation_zero_socket(0, &path);
        assert!(!path.exists(), "gen-0 must delete the socket file");
    }

    #[test]
    fn cleanup_generation_zero_socket_leaves_file_for_later_generations() {
        let path = std::env::temp_dir().join(format!("fdpass-cg1-{}.sock", std::process::id()));
        let _ = fs::remove_file(&path);
        fs::write(&path, b"").unwrap();
        cleanup_generation_zero_socket(1, &path);
        assert!(path.exists(), "gen-1 must not delete the socket file");
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn read_handoff_sessions_prefers_inherited_fd_over_env_payload() {
        let env_lock = crate::test_env::lock();
        let _unset_fd = crate::test_env::EnvVarGuard::unset(&env_lock, ENV_SESSIONS_FD);
        let _unset_env = crate::test_env::EnvVarGuard::unset(&env_lock, ENV_SESSIONS);

        let env_json = r#"[{"uds_fd":99,"peer":"env-peer"}]"#;
        let _env = crate::test_env::EnvVarGuard::set(&env_lock, ENV_SESSIONS, env_json);

        let fd_json = r#"[{"uds_fd":7,"peer":"fd-peer"}]"#;
        let (read_end, write_end) = make_sessions_pipe().unwrap();
        let mut file = fs::File::from(write_end);
        io::Write::write_all(&mut file, fd_json.as_bytes()).unwrap();
        drop(file);
        let _fd = crate::test_env::EnvVarGuard::set(
            &env_lock,
            ENV_SESSIONS_FD,
            read_end.into_raw_fd().to_string(),
        );

        let payload = read_handoff_sessions_json().unwrap().unwrap();

        assert!(matches!(payload.source, HandoffSessionsSource::Fd));
        assert_eq!(payload.json, fd_json);
    }

    #[test]
    fn malformed_inherited_fd_is_fatal_even_if_env_payload_exists() {
        let env_lock = crate::test_env::lock();
        let _unset_fd = crate::test_env::EnvVarGuard::unset(&env_lock, ENV_SESSIONS_FD);
        let _unset_env = crate::test_env::EnvVarGuard::unset(&env_lock, ENV_SESSIONS);
        let _env = crate::test_env::EnvVarGuard::set(
            &env_lock,
            ENV_SESSIONS,
            r#"[{"uds_fd":5,"peer":"env-peer"}]"#,
        );
        let _fd = crate::test_env::EnvVarGuard::set(&env_lock, ENV_SESSIONS_FD, "not-a-fd");

        let Err(err) = read_handoff_sessions_json() else {
            panic!("malformed {ENV_SESSIONS_FD} should not fall back to env payload");
        };

        assert!(
            err.to_string().contains(ENV_SESSIONS_FD),
            "error should point at malformed inherited FD: {err:#}"
        );
    }

    #[allow(
        clippy::await_holding_lock,
        reason = "test serializes process-global env vars via shared test env lock; held across a short await that lets spawned session tasks register"
    )]
    #[tokio::test]
    async fn adopt_inflight_sessions_skips_incompatible_records_only() {
        let env_lock = crate::test_env::lock();
        let _unset_fd = crate::test_env::EnvVarGuard::unset(&env_lock, ENV_SESSIONS_FD);
        let _unset_env = crate::test_env::EnvVarGuard::unset(&env_lock, ENV_SESSIONS);

        let (keep_a, peer_a) = std::os::unix::net::UnixStream::pair().unwrap();
        let (drop_b, peer_b) = std::os::unix::net::UnixStream::pair().unwrap();
        keep_a.set_nonblocking(true).unwrap();
        drop_b.set_nonblocking(true).unwrap();
        let keep_a_fd = keep_a.into_raw_fd();
        let drop_b_fd = drop_b.into_raw_fd();

        let payload = serde_json::to_string(&vec![
            sample_handoff(keep_a_fd, SCHEMA_VERSION, "peer-a", Some("alice")),
            sample_handoff(drop_b_fd, SCHEMA_VERSION + 1, "peer-b", Some("bob")),
        ])
        .unwrap();
        let _env = crate::test_env::EnvVarGuard::set(&env_lock, ENV_SESSIONS, payload);

        let registry = Arc::new(Mutex::new(SessionRegistry::default()));
        adopt_inflight_sessions(&registry).unwrap();

        tokio::time::sleep(Duration::from_millis(25)).await;

        let reg = registry.lock().unwrap();
        assert_eq!(
            reg.sessions.len(),
            1,
            "only the compatible session should be adopted"
        );
        assert_eq!(
            reg.metadata.get("peer-a").and_then(|m| m.ident.as_deref()),
            Some("alice")
        );
        assert!(!reg.metadata.contains_key("peer-b"));

        drop(reg);
        drop(peer_a);
        drop(peer_b);
    }

    /// Regression for the `FramedParts` lookahead bug (review #2) *and* the write-side byte loss on
    /// upgrade cancel (review #6): an adopted session must complete an interrupted echo and echo
    /// every already-buffered line without the client sending anything more. Before the fix the
    /// buffered read lines stranded (`is_readable=false`) and the half-flushed echo was dropped, so
    /// a client waiting on its reply stalled forever.
    #[tokio::test]
    async fn adopted_session_flushes_pending_write_and_echoes_buffered_lines() {
        use futures::StreamExt;

        // Server side is the adopted processor end; the client is an echo peer that sends nothing
        // further after handoff.
        let (client, server) = tokio::net::UnixStream::pair().unwrap();

        // Simulate a session captured mid-echo: "a\n" was still in the write buffer (a `send` the
        // old image was flushing when cancel fired) and "b\nc\n" had been received but not yet
        // decoded into lines.
        let framed = framed_with_lookahead(server, b"b\nc\n", b"a\n");

        let registry = Arc::new(Mutex::new(SessionRegistry::default()));
        spawn_session(
            registry,
            framed,
            "peer-x".to_string(),
            0,
            1_700_000_000_000,
            "trace-x".to_string(),
        );

        // The client writes NOTHING. It must still receive the completed echo of the interrupted
        // line ("a") followed by both buffered lines ("b", "c"), in order.
        let mut client = Framed::new(client, LinesCodec::new_with_max_length(64 * 1024));
        let mut got = Vec::new();
        for _ in 0..3 {
            let line = tokio::time::timeout(Duration::from_secs(2), client.next())
                .await
                .expect("echo should arrive without further client input")
                .expect("stream still open")
                .expect("valid line");
            got.push(line);
        }
        assert_eq!(got, vec!["a", "b", "c"]);
    }
}
