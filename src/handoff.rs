use std::env;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::io::{BorrowedFd, IntoRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::process;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use nix::{
    fcntl::{FcntlArg, FdFlag, fcntl},
    unistd::{close, pipe, read, write},
};
use serde::{Deserialize, Serialize};

pub const ENV_LISTENER_FD: &str = "FDPASS_LISTENER_FD";
pub const ENV_SESSIONS: &str = "FDPASS_SESSIONS";
pub const ENV_SESSIONS_FD: &str = "FDPASS_SESSIONS_FD";
pub const ENV_UPGRADE_GENERATION: &str = "FDPASS_GENERATION";

pub const ENV_CTRL_ADMIN_FD: &str = "FDPASS_CTRL_ADMIN_FD";
pub const ENV_CTRL_PROCESSOR_FD: &str = "FDPASS_CTRL_PROCESSOR_FD";
pub const ENV_CTRL_PLAIN_FD: &str = "FDPASS_CTRL_PLAIN_FD";
pub const ENV_CTRL_TLS_FD: &str = "FDPASS_CTRL_TLS_FD";
pub const ENV_CTRL_SCANNER_FD: &str = "FDPASS_CTRL_SCANNER_FD";
pub const ENV_CTRL_DRAINER_FD: &str = "FDPASS_CTRL_DRAINER_FD";
pub const ENV_CTRL_SPAWNER_FD: &str = "FDPASS_CTRL_SPAWNER_FD";

// Worker listener FDs preserved across supervisor self-upgrade. Supervisor owns these; SCM_RIGHTS
// hands copies to workers on spawn
pub const ENV_LISTENER_PLAIN_FD: &str = "FDPASS_LISTENER_PLAIN_FD";
pub const ENV_LISTENER_TLS_FD: &str = "FDPASS_LISTENER_TLS_FD";
pub const ENV_LISTENER_PROCESSOR_FD: &str = "FDPASS_LISTENER_PROCESSOR_FD";
pub const ENV_LISTENER_SCANNER_FD: &str = "FDPASS_LISTENER_SCANNER_FD";
pub const ENV_PROCESSOR_PID: &str = "FDPASS_PROCESSOR_PID";
pub const ENV_PLAIN_PID: &str = "FDPASS_PLAIN_PID";
pub const ENV_TLS_PID: &str = "FDPASS_TLS_PID";
pub const ENV_SCANNER_PID: &str = "FDPASS_SCANNER_PID";
// Each adopted worker's last-reported generation, preserved across supervisor self-upgrade so the
// fresh supervisor can seed its `wait_for_successor` baseline correctly. Without these, an adopted
// gen-N worker looks like gen 0 to the new supervisor until its first status report, and a stale
// `Some(N)` left in the control link can trigger a false `Adopted` when that worker next upgrades.
pub const ENV_PROCESSOR_GEN: &str = "FDPASS_PROCESSOR_GEN";
pub const ENV_PLAIN_GEN: &str = "FDPASS_PLAIN_GEN";
pub const ENV_TLS_GEN: &str = "FDPASS_TLS_GEN";
pub const ENV_SCANNER_GEN: &str = "FDPASS_SCANNER_GEN";
pub const ENV_SUP_GENERATION: &str = "FDPASS_SUP_GENERATION";

// Set on every supervisor process spawned by the grandparent so the supervisor can detect it is
// running under grandparent mode and refuse SIGHUP self-upgrade (which would call `process::exit`
// and trigger the grandparent's `killpg`, killing the newly committed successor).
pub const ENV_UNDER_GRANDPARENT: &str = "FDPASS_UNDER_GRANDPARENT";

// Two-phase upgrade commit. Parent passes a pipe write-fd; the child writes `b"ok\n"` once it's
// past the point of no return, and parent commits the upgrade by exiting. If the child crashes or
// times out before signalling, parent rolls back: kill the child and resume serving. The timeout
// itself lives in `Config::ready_timeout_secs`.
pub const ENV_READY_FD: &str = "FDPASS_READY_FD";

// Cap-mode upgrade handoff. An in-place upgrade successor is `fexecve`'d from a worker already in
// FreeBSD capability mode, so `cap_enter()` is inherited and the new image's entire startup runs
// sandboxed; thus, every path-based open (sockets dir, cert/key dirs, self-exe) would return
// ECAPMODE. The upgrading worker pre-opened those before its own `cap_enter()`; on upgrade, it
// clears their CLOEXEC bit and advertises the fd numbers here, and the successor adopts them
// instead of opening by path (same idiom as `ENV_LISTENER_FD`). The config is the exception: it's
// pure data, not a capability, so its small JSON blob travels directly in `ENV_CONFIG_JSON`. Bulky
// data, such as processor session handoff state, uses an inherited FD instead. All are FreeBSD-only
// in effect (other OSes reopen by path fine) and scrubbed/re-set per spawn like the rest of
// `FDPASS_*`.
pub const ENV_CONFIG_JSON: &str = "FDPASS_CONFIG_JSON";

// These three are read only on FreeBSD (the dir-FD adopters are cfg'd out elsewhere); allow them to
// look unused on other targets
#[cfg_attr(
    not(target_os = "freebsd"),
    allow(
        dead_code,
        reason = "cap-mode directory FD handoff is only consumed on FreeBSD"
    )
)]
pub const ENV_SOCKETS_DIR_FD: &str = "FDPASS_SOCKETS_DIR_FD";
#[cfg_attr(
    not(target_os = "freebsd"),
    allow(
        dead_code,
        reason = "cap-mode TLS cert directory FD handoff is only consumed on FreeBSD"
    )
)]
pub const ENV_CERT_DIR_FD: &str = "FDPASS_CERT_DIR_FD";
#[cfg_attr(
    not(target_os = "freebsd"),
    allow(
        dead_code,
        reason = "cap-mode TLS key directory FD handoff is only consumed on FreeBSD"
    )
)]
pub const ENV_KEY_DIR_FD: &str = "FDPASS_KEY_DIR_FD";
pub const ENV_SELF_EXE_FD: &str = "FDPASS_SELF_EXE_FD";
pub const ENV_SELF_EXE_PATH: &str = "FDPASS_SELF_EXE_PATH";

// Wire-format version of cross-process JSON envelopes. The supervisor, workers, and admin client
// all stamp outgoing messages with `SCHEMA_VERSION` and refuse incoming messages whose version
// falls outside the [`MIN_COMPATIBLE_VERSION`, `SCHEMA_VERSION`] window. Bump on any
// backwards-incompatible change to ControlMsg / WorkerMsg / AdminResp / SessionHandoff; widen the
// floor only after a deprecation cycle.
pub const SCHEMA_VERSION: u32 = 1;
pub const MIN_COMPATIBLE_VERSION: u32 = 1;

pub fn is_schema_compatible(v: u32) -> bool {
    (MIN_COMPATIBLE_VERSION..=SCHEMA_VERSION).contains(&v)
}

/// `serde(default = ...)` fallback. Used when an older sender omits the `version` field entirely;
/// we treat that as v1 (the first version that existed). Anything sent post-v1 *must* include the
/// field.
pub fn default_schema_version() -> u32 {
    1
}

/// Sentinel exit code a worker uses when it cleanly handed off to an upgrade successor
/// (`process::exit(UPGRADE_COMMIT_EXIT_CODE)` after the ready-pipe ack). The supervisor's watchdog
/// treats this as "graceful, expected" and doesn't count it against the fast-exit total.
pub const UPGRADE_COMMIT_EXIT_CODE: i32 = 23;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// UDS-bridged session: the acceptor byte-forwards over UDS (both plain and TLS). The only
    /// variant produced now.
    #[default]
    Uds,
    /// Legacy TCP-direct session (plain-originated, FD passed via the removed `SCM_RIGHTS` handoff).
    /// Retained only so a new image can recognize and decline such a handoff from a pre-bridge
    /// generation during the upgrade that removes SCM — rather than misreading a TCP fd as a UDS one.
    Tcp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionHandoff {
    /// Underlying UDS session FD (the processor's end of the acceptor↔processor bridge),
    /// reconstructed as a `UnixStream`. Legacy `Tcp` handoffs are declined, not reconstructed.
    pub uds_fd: RawFd,
    #[serde(default)]
    pub transport: Transport,
    /// Bytes the `LinesCodec` had buffered but not yet split into a full line. Replayed into the new
    /// image's read buffer so a mid-flight line is not torn at the byte we exec'd.
    pub partial_line_bytes: Vec<u8>,
    /// Encoded echo bytes the `Framed` write buffer still held when the session was cancelled for
    /// upgrade (a `send` that was interrupted mid-flush). Replayed into the successor's write buffer
    /// and flushed before it resumes, so the in-flight echo completes instead of arriving torn — the
    /// write-side twin of `partial_line_bytes`.
    #[serde(default)]
    pub pending_write_bytes: Vec<u8>,
    pub lines_echoed: u64,
    pub connected_at_unix_ms: u64,
    /// TCP peer address from the acceptor's perspective, captured at session open via the processor
    /// preamble. Preserved across upgrade so the scanner-sidecar metadata can still bind to this
    /// session after exec.
    #[serde(default)]
    pub peer: String,
    /// RFC-1413 identd response captured by the scanner. Survives a processor upgrade so the
    /// adopted session keeps its identity annotation even though scanner only ever runs the lookup
    /// once (at accept time) per inbound TCP/TLS connection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ident: Option<String>,
    /// Acceptor-assigned trace ID; preserved across processor upgrades so logs for one session stay
    /// joinable.
    #[serde(default)]
    pub trace_id: String,
    /// Schema version stamped at serialize time. Adoption skips any handoff whose version we don't
    /// understand.
    #[serde(default = "default_schema_version")]
    pub version: u32,
}

pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, duration_millis_u64)
}

pub fn duration_millis_u64(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Generate a trace ID for a session. Format `<pid:hex>-<counter:hex>`; the pid prefix gives
/// cross-process uniqueness without a random source, and the counter component handles
/// intra-process collisions.
pub fn new_trace_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let pid = process::id();
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{pid:08x}-{n:016x}")
}

/// Strip every per-spawn `FDPASS_*` env var from a Command. The supervisor re-sets the keys it
/// actually wants the child to see; anything left over (stale FD numbers, last-run PIDs, last
/// generation) would mislead the child into adopting FDs that no longer belong to it.
///
/// A short allowlist is preserved across the scrub; config path and log format are process-global
/// toggles, not per-spawn state.
const PRESERVED_ENV: &[&str] = &[crate::config::ENV_CONFIG_PATH, "FDPASS_LOG_FORMAT"];

pub fn scrub_fdpass_env(cmd: &mut process::Command) {
    for k in fdpass_env_to_remove() {
        cmd.env_remove(&k);
    }
}

/// List of `FDPASS_*` env-var names that `scrub_fdpass_env` would clear. Mirrored separately so the
/// FreeBSD `fexecve` path can apply the same removals to the envp it builds (it bypasses
/// `std::process::Command`'s env machinery entirely).
pub fn fdpass_env_to_remove() -> Vec<String> {
    env::vars()
        .filter(|(k, _)| k.starts_with("FDPASS_") && !PRESERVED_ENV.contains(&k.as_str()))
        .map(|(k, _)| k)
        .collect()
}

/// Resolve the binary to exec when a worker upgrades itself. `binary_path` is the override the
/// admin can pass over the control plane. If absent, we fall back to `cached_self`, which workers
/// pre-resolve at startup before `apply_sandbox` (`cap_enter` blocks `current_exe()`'s namespace
/// loookup).
pub fn resolve_upgrade_exe(binary_path: Option<PathBuf>, cached_self: &Path) -> PathBuf {
    binary_path.unwrap_or_else(|| cached_self.to_path_buf())
}

/// Worker's pre-resolved `current_exe()` path + the same file as an FD. Computed once at startup
/// before `apply_sandbox` and reused across all in-place upgrades for that worker.
pub struct SelfExe {
    pub path: PathBuf,
    pub fd: OwnedFd,
}

/// Pre-open `current_exe()` and snapshot its path as an `OwnedFd`/`PathBuf`. Workers call this
/// before `apply_sandbox` because `cap_enter()` on FreeBSD blocks both `current_exe()`'s `readlink`
/// and the `open` of a global path.
///
/// In a cap-mode upgrade successor neither of those works, so if the upgrading parent handed us a
/// self-exe FD (`ENV_SELF_EXE_FD` + `ENV_SELF_EXE_PATH`) we adopt that instead of calling
/// `current_exe()`.
pub fn open_self_exe() -> Result<SelfExe> {
    use std::fs::File;
    if let Some(fd) = env_raw_fd(ENV_SELF_EXE_FD) {
        let path = env::var_os(ENV_SELF_EXE_PATH)
            .map(PathBuf::from)
            .unwrap_or_default();
        // SAFETY: parent cleared CLOEXEC on this fd and passed its number via env immediately
        // before fexecve; we own the inherited fd now
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        tracing::info!(?path, "adopted inherited self-exe FD (cap-mode upgrade)");
        return Ok(SelfExe { path, fd });
    }
    let path = env::current_exe().context("current_exe")?;
    let f = File::open(&path).with_context(|| format!("open self exe {}", path.display()))?;
    Ok(SelfExe { path, fd: f.into() })
}

/// Parse an `FDPASS_*` env var holding a raw fd number. Returns `None` if the var is unset or
/// unparseable.
pub fn env_raw_fd(name: &str) -> Option<RawFd> {
    env::var(name).ok().and_then(|s| s.parse::<RawFd>().ok())
}

/// Raw fds of a worker's pre-opened directory handles, gathered at the upgrade site for cap-mode
/// handoff: the `sockets` FD (all roles) and the cert/key dir FDs (TLS acceptor only). `None`
/// entries are simply not handed off. The config and self-exe FDs come from elsewhere (the `config`
/// global / `SelfExe`) so they aren't here. Cross-platform so upgrade signatures don't need `cfg`.
/// Fields are read only on FreeBSD (the handoff is cfg'd out elsewhere).
#[derive(Clone, Copy, Default)]
#[cfg_attr(
    not(target_os = "freebsd"),
    allow(
        dead_code,
        reason = "directory FD fields are only read by FreeBSD cap-mode upgrade handoff"
    )
)]
pub struct HandoffDirFds {
    pub sockets: Option<RawFd>,
    pub cert: Option<RawFd>,
    pub key: Option<RawFd>,
}

/// The pre-opened *capability* FDs an upgrading worker hands to its in-place successor, so the
/// successor can start under FreeBSD capability mode — things you can only obtain as a kernel FD (a
/// dir to the `openat()` / `connectat()` from, an executable to `fexecve`). Pure data (the parsed
/// config) travels separately as JSON. Built at the upgrade site from the structs the worker
/// already holds (`SelfExe`, `SocketsDialer`, `TlsCertSource`). `prepare` clears CLOEXEC on each
/// and returns the env pairs for the `fexecve` envp; hold the returned guards until the exec
/// commits (drop = restore CLOEXEC on rollback). FreeBSD only; other OSes reopen by path and never
/// set these.
#[cfg(target_os = "freebsd")]
pub struct CapModeHandoff<'a> {
    pub self_exe: &'a SelfExe,
    pub sockets_fd: Option<RawFd>,
    pub cert_fd: Option<RawFd>,
    pub key_fd: Option<RawFd>,
}

/// What `CapModeHandoff::prepare` returns: env pairs to add to the successor's environment, plus
/// the CLOEXEC guards to hold until the exec commits
#[cfg(target_os = "freebsd")]
type PreparedHandoff = (Vec<(String, String)>, Vec<CloexecGuard>);

#[cfg(target_os = "freebsd")]
impl CapModeHandoff<'_> {
    pub fn prepare(&self) -> Result<PreparedHandoff> {
        // self-exe FD is always handed off (the successor's open_self_exe can't call current_exe
        // under cap mode); the rest are optional
        let mut specs: Vec<(&str, RawFd)> = vec![(ENV_SELF_EXE_FD, self.self_exe.fd.as_raw_fd())];
        for (name, fd) in [
            (ENV_SOCKETS_DIR_FD, self.sockets_fd),
            (ENV_CERT_DIR_FD, self.cert_fd),
            (ENV_KEY_DIR_FD, self.key_fd),
        ] {
            if let Some(fd) = fd {
                specs.push((name, fd));
            }
        }

        let mut guards = Vec::with_capacity(specs.len());
        let mut env = Vec::with_capacity(specs.len() + 1);
        for (name, fd) in &specs {
            guards.push(CloexecGuard::clear(*fd)?);
            env.push(((*name).to_string(), fd.to_string()));
        }
        // The path is cosmetic (arg0 + logs); current_exe is unavailable in
        // the successor, so pass the parent's resolved path through too.
        env.push((
            ENV_SELF_EXE_PATH.to_string(),
            self.self_exe.path.to_string_lossy().into_owned(),
        ));
        Ok((env, guards))
    }
}

/// Extend `fexecve_env` with the cap-mode upgrade handoff (the parsed config as SON plus the
/// sockets/cert/key/self-exe capability FDs) and return the CLOEXEC guards to hold until exec.
/// No-op for `--target` (a different binary must not adopt our self-exe FD) or when unsandboxed
/// (the successor can open paths itself). FreeBSD-only; shared by all four worker upgrade paths.
#[cfg(target_os = "freebsd")]
pub fn cap_mode_handoff(
    fexecve_env: &mut Vec<(String, String)>,
    config: &crate::config::Config,
    self_exe: &SelfExe,
    dirs: HandoffDirFds,
    target_overridden: bool,
    role: &str,
) -> Result<Vec<CloexecGuard>> {
    // Effective (per-role) sandbox: a role that runs `off` (e.g. the scanner)
    // never enters cap mode, so its successor opens paths itself — no handoff.
    if target_overridden
        || config.security.effective_sandbox(role) == crate::config::SandboxMode::Off
    {
        return Ok(Vec::new());
    }
    // Config is small data, not a capability: serialize the already-parsed Config so
    // the successor skips path-based `Config::load` entirely.
    let config_json = serde_json::to_string(config).context("serialize config for handoff")?;
    fexecve_env.push((ENV_CONFIG_JSON.to_string(), config_json));

    let handoff = CapModeHandoff {
        self_exe,
        sockets_fd: dirs.sockets,
        cert_fd: dirs.cert,
        key_fd: dirs.key,
    };
    let (pairs, guards) = handoff.prepare()?;
    fexecve_env.extend(pairs);
    Ok(guards)
}

/// On FreeBSD, returns `Err` if the current process is in Capsicum capability mode AND the
/// self-exe binary is dynamically linked. A dynamic binary's ELF interpreter
/// (`/libexec/ld-elf.so.1`) is resolved by path during `fexecve`, which returns ECAPMODE
/// under `cap_enter`. The upgrade child dies instantly with no ready signal, producing a
/// cryptic 5-second timeout. Calling this early gives a clear error instead.
///
/// No-op on other platforms and when the process is not in capability mode.
#[cfg_attr(
    not(target_os = "freebsd"),
    allow(
        clippy::unnecessary_wraps,
        reason = "the fallible Capsicum check only exists on FreeBSD; the Result keeps one signature across platforms"
    )
)]
pub fn require_static_for_capmode_upgrade(self_exe: &SelfExe) -> Result<()> {
    #[cfg(target_os = "freebsd")]
    {
        use std::os::unix::io::AsRawFd;

        if in_capsicum_mode() && elf_has_interpreter(self_exe.fd.as_raw_fd()) {
            anyhow::bail!(
                "in-place upgrade under FreeBSD Capsicum capability mode requires a \
                 statically-linked binary — build with scripts/build-static.sh. \
                 A dynamically-linked successor cannot exec because fexecve triggers a \
                 path-based load of /libexec/ld-elf.so.1, which ECAPMODE rejects."
            );
        }
    }
    #[cfg(not(target_os = "freebsd"))]
    let _ = self_exe;
    Ok(())
}

/// Returns `true` if the current process is running in FreeBSD Capsicum capability mode.
#[cfg(target_os = "freebsd")]
fn in_capsicum_mode() -> bool {
    let mut mode: u32 = 0;
    // SAFETY: cap_getmode writes a single u32 through the pointer; no side effects.
    unsafe { nix::libc::cap_getmode(&mut mode) == 0 && mode != 0 }
}

/// Returns `true` if the ELF binary at `fd` has a `PT_INTERP` program header (i.e. is
/// dynamically linked and needs an ELF interpreter). Returns `false` on any read/parse
/// error — the safe default is to assume static and let `fexecve` fail naturally.
#[cfg(target_os = "freebsd")]
fn elf_has_interpreter(fd: std::os::unix::io::RawFd) -> bool {
    // ELF64 header layout (little-endian, which is all FreeBSD/amd64 uses):
    //   [0..4]   magic
    //   [4]      EI_CLASS   (2 = 64-bit)
    //   [5]      EI_DATA    (1 = LE)
    //   [32..40] e_phoff    (program-header table offset)
    //   [54..56] e_phentsize
    //   [56..58] e_phnum
    // Each 64-bit Phdr starts with a 4-byte p_type; PT_INTERP = 3.
    let mut ehdr = [0u8; 64];
    // SAFETY: pread on a valid fd with an in-scope buffer is always safe; n < 0 signals error.
    let n = unsafe { nix::libc::pread(fd, ehdr.as_mut_ptr().cast(), 64, 0) };
    if n < 64 || ehdr[0..4] != *b"\x7fELF" || ehdr[4] != 2 || ehdr[5] != 1 {
        return false;
    }
    let ph_off = i64::from_le_bytes(ehdr[32..40].try_into().unwrap());
    let ph_ent = u16::from_le_bytes(ehdr[54..56].try_into().unwrap()) as usize;
    let ph_num = u16::from_le_bytes(ehdr[56..58].try_into().unwrap()) as usize;
    if ph_ent == 0 {
        return false;
    }
    const PT_INTERP: u32 = 3;
    let mut p_type = [0u8; 4];
    for i in 0..ph_num {
        let off = ph_off + (i * ph_ent) as i64;
        // SAFETY: pread on the same valid fd with an in-scope 4-byte buffer.
        let n = unsafe { nix::libc::pread(fd, p_type.as_mut_ptr().cast(), 4, off) };
        if n >= 4 && u32::from_le_bytes(p_type) == PT_INTERP {
            return true;
        }
    }
    false
}

/// Install the FreeBSD `fexecve`-based `pre_exec` hook on `cmd`, or no-op on other OSes. Callers
/// always go through this helper so the upgrade sites can stay platform-agnostic.
pub fn install_fexecve_pre_exec(
    cmd: &mut process::Command,
    binary_fd: i32,
    exe_arg0: String,
    role_arg: String,
    extra_env: Vec<(String, String)>,
    env_remove: Vec<String>,
) {
    #[cfg(target_os = "freebsd")]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: the closure is async-signal-safe (no allocation outside pre-built CStrings, only
        // fexecve + _exit)
        unsafe {
            let hook = fexecve_pre_exec(binary_fd, exe_arg0, role_arg, extra_env, env_remove);
            cmd.pre_exec(hook);
        }
    }
    #[cfg(not(target_os = "freebsd"))]
    {
        let _ = (cmd, binary_fd, exe_arg0, role_arg, extra_env, env_remove);
    }
}

#[cfg(target_os = "freebsd")]
struct FexecvePreExecData {
    _arg0: std::ffi::CString,
    _arg1: std::ffi::CString,
    _envp_cstrings: Vec<std::ffi::CString>,
    argv_ptrs: [*const nix::libc::c_char; 3],
    envp_ptrs: Vec<*const nix::libc::c_char>,
}

#[cfg(target_os = "freebsd")]
// SAFETY: all raw pointers point into the owned CString buffers stored in the same struct. The
// pre_exec closure only reads these immutable pointers in the single post-fork child before
// fexecve/_exit, so transferring/sharing the closure object is safe for CommandExt's bounds.
unsafe impl Send for FexecvePreExecData {}

#[cfg(target_os = "freebsd")]
// SAFETY: see the Send impl; the pointed-to CString storage is immutable and owned by this struct.
unsafe impl Sync for FexecvePreExecData {}

#[cfg(target_os = "freebsd")]
impl FexecvePreExecData {
    fn fexecve_or_exit(&self, binary_fd: i32) -> ! {
        // SAFETY: binary_fd was opened before any potential cap_enter and inherited across fork.
        // argv/envp point to CString storage owned by self, which is captured by the pre_exec
        // closure and lives until fexecve replaces the image or _exit terminates the child.
        unsafe {
            nix::libc::fexecve(binary_fd, self.argv_ptrs.as_ptr(), self.envp_ptrs.as_ptr());
            // fexecve returns only on failure. Don't let the std-lib's execvp fall-through run,
            // because it would be ECAPMODE under cap mode.
            nix::libc::_exit(127);
        }
    }
}

/// FreeBSD-only `pre_exec` closure that swaps `execvp(path)` for `fexecve(binary_fd, argv, envp)`.
/// On Linux, the standard execve path already works under seccomp; on macOS, there's no `fexecve`
/// and no sandbox to satisfy. This helper exists for `cap_enter()`, which rejects path lookups
/// against the global filesystem namespace.
///
/// On success, control transfers to the new image. On failure, the closure `_exit(127)`s, never
/// returning `Ok`, so the stdlib's execvp path is never reached (it would be ECAPMODE under cap
/// mode).
///
/// `extra_env` and `env_remove` mirror what would have been on the Command (`cmd.env(k, v)` and
/// `cmd.env_remove(k)`); we have to apply them ourselves, because we're bypassing std's exec
/// machinery.
///
/// SAFETY: the returned closure runs in the forked child between fork() and the would-be execvp. It
/// only calls async-signal-safe operations (`fexecve`, `_exit`) on data captured by move before the
/// fork.
#[cfg(target_os = "freebsd")]
unsafe fn fexecve_pre_exec(
    binary_fd: i32,
    exe_arg0: String,
    role_arg: String,
    extra_env: Vec<(String, String)>,
    env_remove: Vec<String>,
) -> impl FnMut() -> std::io::Result<()> + 'static {
    use std::ffi::CString;
    let arg0 = CString::new(exe_arg0).expect("exe path has nul");
    let arg1 = CString::new(role_arg).expect("role has nul");

    // Build envp BEFORE the fork so allocations don't happen in the signal-unsafe context post-fork
    let mut env_map: std::collections::HashMap<String, String> = env::vars().collect();
    for k in &env_remove {
        env_map.remove(k);
    }
    for (k, v) in extra_env {
        env_map.insert(k, v);
    }
    let envp_cstrings: Vec<CString> = env_map
        .into_iter()
        .map(|(k, v)| CString::new(format!("{k}={v}")).expect("env value has nul"))
        .collect();
    let argv_ptrs: [*const nix::libc::c_char; 3] = [arg0.as_ptr(), arg1.as_ptr(), std::ptr::null()];
    let mut envp_ptrs: Vec<*const nix::libc::c_char> =
        envp_cstrings.iter().map(|c| c.as_ptr()).collect();
    envp_ptrs.push(std::ptr::null());
    let data = FexecvePreExecData {
        _arg0: arg0,
        _arg1: arg1,
        _envp_cstrings: envp_cstrings,
        argv_ptrs,
        envp_ptrs,
    };

    move || -> std::io::Result<()> {
        data.fexecve_or_exit(binary_fd);
    }
}

/// Create the upgrade ready-pipe. Parent keeps the read end (CLOEXEC set); the write end's CLOEXEC
/// bit is cleared so it survives the child's exec, and its raw FD number is what the parent puts in
/// `ENV_READY_FD`.
///
/// nix exposes `pipe2(O_CLOEXEC)` only on Linux/BSD, so for portability we use `pipe()` and set
/// `FD_CLOEXEC` on the read end ourselves.
pub fn make_ready_pipe() -> Result<(OwnedFd, RawFd)> {
    let (read_end, write_end) = pipe().context("pipe")?;
    set_cloexec(read_end.as_raw_fd())?;
    let write_fd = write_end.into_raw_fd();
    // pipe()'s output has CLOEXEC unset by default — leave write_fd as-is.
    Ok((read_end, write_fd))
}

pub fn set_cloexec(fd: RawFd) -> Result<()> {
    // SAFETY: caller owns `fd` and keeps it open for the duration of this call
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    let flags = fcntl(borrowed, FcntlArg::F_GETFD).context("F_GETFD")?;
    let new_flags = FdFlag::from_bits_truncate(flags) | FdFlag::FD_CLOEXEC;
    fcntl(borrowed, FcntlArg::F_SETFD(new_flags)).context("F_SETFD")?;
    Ok(())
}

/// Child-side: signal "ready" to the parent so it commits the upgrade. No-op if `ENV_READY_FD` is
/// unset (first-generation start, no parent waiting). Must be called once the worker has crossed
/// the point of no return: listener bound/adopted, any inherited sessions adopted, and
/// privilege-drop/sandbox setup completed. The control-plane task may start after this.
pub fn signal_ready_to_parent() -> Result<()> {
    let Ok(fd_str) = env::var(ENV_READY_FD) else {
        return Ok(());
    };
    let fd: RawFd = fd_str.parse().context(ENV_READY_FD)?;
    // SAFETY: parent set this FD on us via env immediately before spawn, with CLOEXEC cleared. We
    // own it; the BorrowedFd is dropped before the `close()`, so there's no aliasing.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    write(borrowed, b"ok\n").context("write ready ack")?;
    let _ = close(fd);
    Ok(())
}

/// Parent-side: block (with timeout) until the child signals ready. Returns Err if the child
/// crashed (EOF) or didn't signal in time.
pub async fn wait_for_child_ready(read_end: OwnedFd, timeout: Duration) -> Result<()> {
    let waited = tokio::time::timeout(
        timeout,
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut buf = [0u8; 8];
            let n = read(read_end.as_fd(), &mut buf).context("read ready pipe")?;
            if n == 0 {
                bail!("upgrade child closed ready pipe without signaling");
            }
            if !buf[..n].starts_with(b"ok") {
                bail!("upgrade child sent non-ok ready signal");
            }
            Ok(())
        }),
    )
    .await
    .context("upgrade ready signal timed out")?;
    waited.context("ready-wait join")?
}

/// Clear `FD_CLOEXEC`, then re-set it on drop unless `commit()` was called. Wraps `clear_cloexec` for
/// the upgrade path, so that a failure between "clear" and "successful exec" doesn't leak
/// CLOEXEC=false to whatever runs next. Pattern:
///
/// ```rust
/// let guard = CloexecGuard::clear(fd)?;
/// // ... build cmd, set env, etc (any ? can bail safely) ...
/// cmd.spawn()?;
/// guard.commit();   // child now has the FD; leave our copy alone
/// ```
pub struct CloexecGuard {
    fd: RawFd,
    armed: bool,
}

impl CloexecGuard {
    pub fn clear(fd: RawFd) -> Result<Self> {
        clear_cloexec(fd)?;
        Ok(Self { fd, armed: true })
    }

    /// The downstream exec/spawn happened; CLOEXEC=false is now intentional
    pub fn commit(mut self) {
        self.armed = false;
    }
}

impl Drop for CloexecGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Err(e) = set_cloexec(self.fd) {
            tracing::warn!(fd = self.fd, error = %e, "CloexecGuard restore failed");
        } else {
            tracing::info!(fd = self.fd, "CloexecGuard restored CLOEXEC (no commit)");
        }
    }
}

/// Clear `FD_CLOEXEC` so the FD survives execve
pub fn clear_cloexec(fd: RawFd) -> Result<()> {
    // SAFETY: caller owns `fd` and keeps it open for the duration of this call; nothing else takes
    // ownership of the BorrowedFd
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    let flags = fcntl(borrowed, FcntlArg::F_GETFD).context("F_GETFD")?;
    let new_flags = FdFlag::from_bits_truncate(flags) - FdFlag::FD_CLOEXEC;
    fcntl(borrowed, FcntlArg::F_SETFD(new_flags)).context("F_SETFD")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_handoff() -> SessionHandoff {
        SessionHandoff {
            uds_fd: 42,
            transport: Transport::Tcp,
            partial_line_bytes: b"hel".to_vec(),
            pending_write_bytes: b"lo\n".to_vec(),
            lines_echoed: 7,
            connected_at_unix_ms: 1_700_000_000_000,
            peer: "127.0.0.1:55555".into(),
            ident: Some("alice".into()),
            trace_id: "deadbeef-0000".into(),
            version: SCHEMA_VERSION,
        }
    }

    #[test]
    fn session_handoff_json_roundtrip() {
        let h = sample_handoff();
        let json = serde_json::to_string(&h).unwrap();
        let back: SessionHandoff = serde_json::from_str(&json).unwrap();
        assert_eq!(back.uds_fd, h.uds_fd);
        assert_eq!(back.transport, h.transport);
        assert_eq!(back.partial_line_bytes, h.partial_line_bytes);
        assert_eq!(back.pending_write_bytes, h.pending_write_bytes);
        assert_eq!(back.lines_echoed, h.lines_echoed);
        assert_eq!(back.peer, h.peer);
        assert_eq!(back.ident, h.ident);
        assert_eq!(back.trace_id, h.trace_id);
        assert_eq!(back.version, h.version);
    }

    #[test]
    fn session_handoff_legacy_json_no_version() {
        // Pre-versioning sender: omits both `version` and `trace_id`
        let legacy = r#"{
            "uds_fd": 5,
            "transport": "uds",
            "partial_line_bytes": [],
            "lines_echoed": 0,
            "connected_at_unix_ms": 0,
            "peer": "x:1"
        }"#;
        let h: SessionHandoff = serde_json::from_str(legacy).unwrap();
        assert_eq!(h.version, 1);
        assert_eq!(h.trace_id, "");
        assert_eq!(h.ident, None);
    }

    #[test]
    fn schema_compatibility_window() {
        assert!(is_schema_compatible(SCHEMA_VERSION));
        assert!(is_schema_compatible(MIN_COMPATIBLE_VERSION));
        assert!(!is_schema_compatible(0));
        assert!(!is_schema_compatible(SCHEMA_VERSION + 1));
    }

    #[test]
    fn new_trace_id_format() {
        let a = new_trace_id();
        let b = new_trace_id();
        // Format: <pid:8>-<counter:16>
        assert_eq!(a.len(), 8 + 1 + 16);
        assert!(a.contains('-'));
        assert_ne!(a, b, "counter must advance between calls");
    }

    #[test]
    fn env_raw_fd_parses_valid_numeric() {
        let env_lock = crate::test_env::lock();
        let _var = crate::test_env::EnvVarGuard::set(&env_lock, "FDPASS_TEST_ENVRAWFD_VALID", "42");

        assert_eq!(env_raw_fd("FDPASS_TEST_ENVRAWFD_VALID"), Some(42));
    }

    #[test]
    fn env_raw_fd_returns_none_when_unset() {
        let env_lock = crate::test_env::lock();
        let _var = crate::test_env::EnvVarGuard::unset(&env_lock, "FDPASS_TEST_ENVRAWFD_UNSET");

        assert_eq!(env_raw_fd("FDPASS_TEST_ENVRAWFD_UNSET"), None);
    }

    #[test]
    fn env_raw_fd_returns_none_for_non_numeric() {
        let env_lock = crate::test_env::lock();
        let _var = crate::test_env::EnvVarGuard::set(
            &env_lock,
            "FDPASS_TEST_ENVRAWFD_NONNUMERIC",
            "notanumber",
        );

        assert_eq!(env_raw_fd("FDPASS_TEST_ENVRAWFD_NONNUMERIC"), None);
    }

    #[test]
    fn resolve_upgrade_exe_uses_override_when_some() {
        let custom = PathBuf::from("/opt/new-echod");
        let cached = Path::new("/opt/old-echod");
        assert_eq!(resolve_upgrade_exe(Some(custom.clone()), cached), custom);
    }

    #[test]
    fn resolve_upgrade_exe_falls_back_to_cached_when_none() {
        let cached = Path::new("/opt/old-echod");
        assert_eq!(
            resolve_upgrade_exe(None, cached),
            PathBuf::from("/opt/old-echod")
        );
    }

    #[test]
    fn fdpass_env_to_remove_includes_fdpass_and_excludes_preserved() {
        let env_lock = crate::test_env::lock();
        let _sentinel =
            crate::test_env::EnvVarGuard::set(&env_lock, "FDPASS_TEST_TOREMOVE_SENTINEL", "yes");
        let _log_format = crate::test_env::EnvVarGuard::set(&env_lock, "FDPASS_LOG_FORMAT", "text");

        let list = fdpass_env_to_remove();
        assert!(
            list.contains(&"FDPASS_TEST_TOREMOVE_SENTINEL".to_string()),
            "FDPASS_TEST_TOREMOVE_SENTINEL must appear in the remove list"
        );
        assert!(
            !list.contains(&"FDPASS_LOG_FORMAT".to_string()),
            "FDPASS_LOG_FORMAT is preserved and must not appear in the remove list"
        );
    }

    #[test]
    fn scrub_fdpass_env_removes_fdpass_vars_from_command() {
        let env_lock = crate::test_env::lock();
        let _var =
            crate::test_env::EnvVarGuard::set(&env_lock, "FDPASS_TEST_SCRUB_VERIFY", "sentinel");

        let mut cmd = std::process::Command::new("true");
        scrub_fdpass_env(&mut cmd);
        let removed: Vec<_> = cmd
            .get_envs()
            .filter(|(_, v)| v.is_none())
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect();
        assert!(
            removed.contains(&"FDPASS_TEST_SCRUB_VERIFY".to_string()),
            "FDPASS_TEST_SCRUB_VERIFY should have been removed; removed={removed:?}"
        );
    }

    #[test]
    fn now_unix_ms_returns_reasonable_value() {
        let ms = now_unix_ms();
        // Must be after 2020-01-01 (1_577_836_800_000 ms) and before 2100.
        assert!(ms > 1_577_836_800_000, "now_unix_ms too small: {ms}");
        assert!(ms < 4_102_444_800_000, "now_unix_ms too large: {ms}");
    }

    fn get_fd_flags(fd: RawFd) -> nix::fcntl::FdFlag {
        // SAFETY: caller guarantees fd is open and we don't outlive it
        let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
        let flags = nix::fcntl::fcntl(borrowed, nix::fcntl::FcntlArg::F_GETFD).expect("F_GETFD");
        nix::fcntl::FdFlag::from_bits_truncate(flags)
    }

    #[test]
    fn make_ready_pipe_and_set_clear_cloexec() {
        let (read_end, write_fd) = make_ready_pipe().expect("make_ready_pipe");
        // Read end should have CLOEXEC set.
        assert!(
            get_fd_flags(read_end.as_raw_fd()).contains(nix::fcntl::FdFlag::FD_CLOEXEC),
            "read_end should have CLOEXEC"
        );
        // Clear and re-set CLOEXEC on the write end.
        clear_cloexec(write_fd).expect("clear_cloexec");
        assert!(
            !get_fd_flags(write_fd).contains(nix::fcntl::FdFlag::FD_CLOEXEC),
            "write_fd should have CLOEXEC cleared"
        );
        set_cloexec(write_fd).expect("set_cloexec");
        assert!(
            get_fd_flags(write_fd).contains(nix::fcntl::FdFlag::FD_CLOEXEC),
            "write_fd should have CLOEXEC after set"
        );
        // SAFETY: write_fd was returned from make_ready_pipe and we own it
        let _ = unsafe { std::os::fd::OwnedFd::from_raw_fd(write_fd) };
    }

    #[test]
    fn cloexec_guard_restores_on_drop() {
        let (read_end, _write_fd) = make_ready_pipe().expect("pipe");
        let raw = read_end.as_raw_fd();
        {
            let _guard = CloexecGuard::clear(raw).expect("CloexecGuard::clear");
            assert!(
                !get_fd_flags(raw).contains(nix::fcntl::FdFlag::FD_CLOEXEC),
                "CLOEXEC should be cleared inside guard"
            );
        } // guard dropped without commit → restores CLOEXEC
        assert!(
            get_fd_flags(raw).contains(nix::fcntl::FdFlag::FD_CLOEXEC),
            "guard drop should restore CLOEXEC"
        );
    }

    #[test]
    fn cloexec_guard_commit_leaves_cloexec_cleared() {
        let (read_end, _write_fd) = make_ready_pipe().expect("pipe");
        let raw = read_end.as_raw_fd();
        let guard = CloexecGuard::clear(raw).expect("CloexecGuard::clear");
        guard.commit();
        assert!(
            !get_fd_flags(raw).contains(nix::fcntl::FdFlag::FD_CLOEXEC),
            "after commit, CLOEXEC should stay cleared"
        );
    }

    #[test]
    fn signal_ready_to_parent_is_noop_when_env_unset() {
        // With no ENV_READY_FD in the environment the function should return Ok immediately.
        let result = signal_ready_to_parent();
        assert!(result.is_ok(), "should be Ok with no env var: {result:?}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wait_for_child_ready_succeeds_when_pipe_written() {
        let (read_end, write_fd) = make_ready_pipe().expect("pipe");
        // Write "ok\n" to the write end from a blocking task.
        tokio::task::spawn_blocking(move || {
            // SAFETY: we own write_fd
            let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(write_fd) };
            nix::unistd::write(borrowed, b"ok\n").unwrap();
            // SAFETY: write_fd was returned from make_ready_pipe and moved into this task
            unsafe { std::os::fd::OwnedFd::from_raw_fd(write_fd) }; // drop → close
        });
        let result = wait_for_child_ready(read_end, Duration::from_secs(5)).await;
        assert!(
            result.is_ok(),
            "should succeed when pipe is written: {result:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wait_for_child_ready_errors_on_eof() {
        let (read_end, write_fd) = make_ready_pipe().expect("pipe");
        // Close write end without writing → EOF → bail.
        // SAFETY: we own write_fd
        drop(unsafe { std::os::fd::OwnedFd::from_raw_fd(write_fd) });
        let result = wait_for_child_ready(read_end, Duration::from_secs(5)).await;
        assert!(result.is_err(), "EOF should return Err");
    }

    // NOTE: a "timeout" unit test for wait_for_child_ready is intentionally omitted. The function
    // uses spawn_blocking which calls a real blocking read(); tokio::time::timeout cancels the
    // outer Future but cannot abort the OS thread, which then blocks the test runner indefinitely.
    // The timeout path is exercised by the e2e upgrade tests.

    #[test]
    fn open_self_exe_returns_valid_path_and_fd() {
        let se = open_self_exe().expect("open_self_exe");
        assert!(
            se.path.exists(),
            "self-exe path should exist: {:?}",
            se.path
        );
        // FD should be valid (F_GETFD succeeds)
        let flags = nix::fcntl::fcntl(&se.fd, nix::fcntl::FcntlArg::F_GETFD).expect("F_GETFD");
        assert!(flags >= 0, "self-exe fd should be valid");
    }
}
