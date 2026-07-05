//! Worker privilege drop and syscall sandboxing. [`drop_privileges`] performs
//! the uid/gid drop; [`apply_sandbox`] installs the OS-specific syscall sandbox
//! (Linux seccomp allowlist, FreeBSD Capsicum capability mode).
//!
//! Workers call [`drop_privileges`] after acquiring their listener FDs and
//! loading any privileged files (TLS certs), but before signaling ready to
//! the supervisor — so a drop failure surfaces as a startup failure.
//!
//! The supervisor itself does NOT drop. `kill(2)` requires the sender's
//! real/effective uid to match the target's real/saved-set-uid (or to be
//! root). If the supervisor dropped to the same uid as the workers it would
//! work — but then nothing could SIGKILL the supervisor's runaway workers
//! either. Production model: supervisor runs as root via the unit file,
//! workers drop to a service account here.

use std::io;

use anyhow::{Context, Result, bail};
use nix::{
    libc,
    unistd::{Gid, Group, Uid, User, setgid, setuid},
};

use crate::config::{SandboxMode, SecurityConfig};

/// Apply the configured uid/gid drop, in the order required by POSIX:
/// supplementary groups → primary gid → uid. After the uid setuid we no
/// longer have `CAP_SETUID`, so the other two must happen first.
///
/// Name-form `drop_uid`/`drop_gid` (e.g. `"nobody"`) are resolved via NSS
/// and then **normalized to their numeric string form in `cfg`** before this
/// function returns. On FreeBSD the normalization matters: if a worker later
/// triggers an in-place upgrade it serializes the config to JSON for the
/// successor, and the successor runs in inherited Capsicum capability mode
/// where NSS lookups (`getpwnam_r` etc.) are blocked by ECAPMODE. Numeric
/// strings parse immediately without touching the path namespace.
///
/// No-op when both `drop_uid` and `drop_gid` are unset.
#[allow(clippy::similar_names, reason = "uid and gid are Unix conventions")]
pub fn drop_privileges(role: &str, cfg: &mut SecurityConfig) -> Result<()> {
    let target_uid = cfg.drop_uid.as_deref().map(resolve_uid).transpose()?;
    let target_gid = cfg.drop_gid.as_deref().map(resolve_gid).transpose()?;

    if target_uid.is_none() && target_gid.is_none() {
        return Ok(());
    }

    let starting_uid = Uid::effective().as_raw();
    let starting_root = starting_uid == 0;

    // setgroups requires CAP_SETGID. Only attempt it when we're root —
    // otherwise we'd error out on the dev-loop "drop to current uid" case.
    // nix doesn't expose setgroups on Apple targets, so we call libc
    // directly for portability.
    if starting_root {
        // SAFETY: clearing supplementary groups; passing 0/null is the
        // documented "drop all" form on every supported OS.
        let ret = unsafe { libc::setgroups(0, std::ptr::null()) };
        if ret != 0 {
            return Err(io::Error::last_os_error()).context("setgroups(0, NULL)");
        }
    }
    if let Some(gid) = target_gid {
        setgid(Gid::from_raw(gid)).with_context(|| format!("setgid({gid})"))?;
    }
    if let Some(uid) = target_uid {
        setuid(Uid::from_raw(uid)).with_context(|| format!("setuid({uid})"))?;
    }

    // Normalize name-form specs to their resolved numeric strings. The config
    // is serialized to JSON for cap-mode upgrade successors (ENV_CONFIG_JSON);
    // successors inherit Capsicum cap mode and cannot call getpwnam_r/getgrnam_r
    // — so the handoff must carry numeric IDs, not names.
    if let Some(uid) = target_uid {
        cfg.drop_uid = Some(uid.to_string());
    }
    if let Some(gid) = target_gid {
        cfg.drop_gid = Some(gid.to_string());
    }

    let new_uid = Uid::effective().as_raw();
    let new_gid = Gid::effective().as_raw();
    tracing::info!(
        role,
        from_uid = starting_uid,
        uid = new_uid,
        gid = new_gid,
        "dropped privileges"
    );

    // Defense in depth: if we started as root and successfully became
    // non-root, regaining root must fail. A kernel/setuid bug that left the
    // saved-set-uid as 0 would let a code-exec attacker climb back up.
    if starting_root && new_uid != 0 {
        // SAFETY: bare setuid is a thread-safe syscall; we only inspect the
        // return value and never trust the resulting state.
        let regain = unsafe { libc::setuid(0) };
        if regain == 0 {
            bail!("privilege drop appears reversible (setuid(0) succeeded); refusing to continue");
        }
    }

    Ok(())
}

/// Apply the configured syscall sandbox. Linux uses seccomp (allowlist),
/// FreeBSD uses Capsicum (capability mode). Called after [`drop_privileges`]
/// because the sandbox can block `setuid`/`setgid`, and before the worker
/// enters its accept loop so untrusted network input is the first thing the
/// sandboxed code sees.
///
/// The mode is resolved per role via [`SecurityConfig::effective_sandbox`], so
/// a role whose work is incompatible with the sandbox — notably the `scanner`,
/// whose outbound `connect()` is blocked under FreeBSD Capsicum — can be left
/// `off` while the rest run `strict`.
///
/// macOS is a dev-only target; `sandbox` warns-and-ignores there.
#[allow(
    clippy::unnecessary_wraps,
    reason = "macOS does not use Result but other platforms do."
)]
pub fn apply_sandbox(role: &str, cfg: &SecurityConfig) -> Result<()> {
    let mode = cfg.effective_sandbox(role);
    if mode == SandboxMode::Off {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        linux_seccomp::apply(role, mode)
    }
    #[cfg(target_os = "freebsd")]
    {
        freebsd_capsicum::apply(role, mode)
    }
    #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
    {
        let _ = role;
        tracing::warn!(
            ?mode,
            "sandbox configured but only supported on Linux/FreeBSD; ignoring"
        );
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod linux_seccomp {
    use super::{Context, Result, SandboxMode, libc};
    use seccompiler::{SeccompAction, SeccompFilter, SeccompRule, TargetArch, apply_filter};
    use std::collections::BTreeMap;

    /// Allowlist of syscalls workers actually need post-startup. Derived from
    /// strace + tokio/rustls/nix knowledge; tune with `sandbox = "log"`.
    /// Listed by `libc::SYS`_* constants so the same source compiles on any
    /// arch seccompiler supports.
    #[allow(
        clippy::too_many_lines,
        reason = "one flat, auditable syscall allowlist; splitting it would obscure the review"
    )]
    fn worker_syscalls() -> &'static [libc::c_long] {
        &[
            // -- core io
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_close,
            libc::SYS_lseek,
            // glibc reads files at an offset with pread64 (e.g. the dynamic
            // loader / cert read) where musl uses read+lseek; exists on both
            // arches, and is security-equivalent to the already-allowed read.
            libc::SYS_pread64,
            libc::SYS_readv,
            libc::SYS_writev,
            // -- memory
            libc::SYS_mmap,
            libc::SYS_munmap,
            libc::SYS_mprotect,
            libc::SYS_brk,
            libc::SYS_madvise,
            // -- process/thread info
            libc::SYS_getpid,
            libc::SYS_gettid,
            libc::SYS_getuid,
            libc::SYS_geteuid,
            libc::SYS_getgid,
            libc::SYS_getegid,
            libc::SYS_getppid,
            // -- time
            libc::SYS_clock_gettime,
            libc::SYS_clock_nanosleep,
            libc::SYS_nanosleep,
            libc::SYS_gettimeofday,
            // -- files (cert reload, log writes, socket cleanup, exec lookup)
            libc::SYS_openat,
            libc::SYS_fstat,
            libc::SYS_statx,
            libc::SYS_newfstatat,
            libc::SYS_fchmodat,
            libc::SYS_faccessat,
            libc::SYS_faccessat2,
            libc::SYS_fcntl,
            libc::SYS_dup,
            libc::SYS_dup3,
            libc::SYS_pipe2,
            libc::SYS_readlinkat,
            libc::SYS_unlinkat,
            libc::SYS_renameat2,
            libc::SYS_getdents64,
            libc::SYS_ftruncate,
            libc::SYS_fsync,
            // -- sockets (acceptor dials processor every accept; scanner dials out)
            libc::SYS_socket,
            libc::SYS_socketpair,
            libc::SYS_connect,
            libc::SYS_listen,
            libc::SYS_accept4,
            libc::SYS_bind,
            libc::SYS_sendto,
            libc::SYS_recvfrom,
            libc::SYS_sendmsg,
            libc::SYS_recvmsg,
            libc::SYS_shutdown,
            libc::SYS_getsockname,
            libc::SYS_getpeername,
            libc::SYS_getsockopt,
            libc::SYS_setsockopt,
            // -- polling / event loop
            libc::SYS_epoll_create1,
            libc::SYS_epoll_ctl,
            libc::SYS_epoll_pwait,
            libc::SYS_epoll_pwait2,
            libc::SYS_ppoll,
            libc::SYS_eventfd2,
            // -- signals
            libc::SYS_rt_sigaction,
            libc::SYS_rt_sigprocmask,
            libc::SYS_rt_sigreturn,
            libc::SYS_rt_sigtimedwait,
            libc::SYS_sigaltstack,
            libc::SYS_tkill,
            libc::SYS_tgkill,
            libc::SYS_kill,
            // -- threading
            libc::SYS_clone,
            libc::SYS_clone3,
            libc::SYS_futex,
            libc::SYS_set_robust_list,
            libc::SYS_get_robust_list,
            libc::SYS_set_tid_address,
            libc::SYS_prctl,
            libc::SYS_sched_yield,
            libc::SYS_sched_getaffinity,
            libc::SYS_rseq,
            libc::SYS_exit,
            libc::SYS_exit_group,
            // -- upgrade
            libc::SYS_execve,
            libc::SYS_prlimit64,
            libc::SYS_wait4,
            // pidfd_open: std::process::Command's child-reaping path on
            // modern Linux. pidfd_send_signal: for signaling via pidfd.
            libc::SYS_pidfd_open,
            libc::SYS_pidfd_send_signal,
            // seccomp: the upgrade child inherits this filter and must be
            // able to re-install its own after listener acquisition + drop.
            libc::SYS_seccomp,
            // setuid/setgid/setgroups: upgrade child re-runs drop_privileges
            // under the inherited filter. Safe to allow: once non-root, the
            // kernel's own permission check blocks setuid(0).
            libc::SYS_setuid,
            libc::SYS_setgid,
            libc::SYS_setgroups,
            // -- misc
            libc::SYS_ioctl,
            libc::SYS_getrandom,
            libc::SYS_membarrier,
            libc::SYS_restart_syscall,
            // -- x86_64-only syscalls. aarch64 dropped the legacy forms in
            //    favour of the *at / newer variants already listed above, but
            //    glibc and musl on x86_64 still emit them — notably in an upgrade
            //    successor's post-execve startup, which runs under the inherited
            //    filter. Without these a `sandbox = "strict"` upgrade SIGSYS'd on
            //    x86_64 while aarch64 passed. Each is the legacy equivalent of an
            //    already-allowed call, so the sandbox is no weaker:
            //      open       <- openat
            //      poll       <- ppoll
            //      pipe       <- pipe2
            //      access     <- faccessat       (glibc uses legacy access)
            //      unlink     <- unlinkat        (stale UDS socket cleanup)
            //      readlink   <- readlinkat      (current_exe -> /proc/self/exe)
            //      epoll_wait <- epoll_pwait     (glibc uses legacy epoll_wait)
            //      fork       <- clone/clone3    (TLS fork-and-drain child; musl
            //                                     fork() is SYS_fork on x86_64)
            //    arch_prctl(ARCH_SET_FS) sets up TLS and has no aarch64 syscall.
            //    The libc crate doesn't define these SYS_* on aarch64, so cfg
            //    them out there to keep the source compiling on both arches.
            //    (glibc and musl differ in which of these they emit, so the set
            //    is the union observed across both.)
            #[cfg(target_arch = "x86_64")]
            libc::SYS_open,
            #[cfg(target_arch = "x86_64")]
            libc::SYS_poll,
            #[cfg(target_arch = "x86_64")]
            libc::SYS_pipe,
            #[cfg(target_arch = "x86_64")]
            libc::SYS_access,
            #[cfg(target_arch = "x86_64")]
            libc::SYS_unlink,
            #[cfg(target_arch = "x86_64")]
            libc::SYS_readlink,
            #[cfg(target_arch = "x86_64")]
            libc::SYS_epoll_wait,
            #[cfg(target_arch = "x86_64")]
            libc::SYS_fork,
            #[cfg(target_arch = "x86_64")]
            libc::SYS_arch_prctl,
        ]
    }

    #[allow(clippy::unnecessary_wraps, reason = "Failable on non-x86_64/aarch64")]
    fn target_arch() -> Result<TargetArch> {
        #[cfg(target_arch = "aarch64")]
        {
            Ok(TargetArch::aarch64)
        }
        #[cfg(target_arch = "x86_64")]
        {
            Ok(TargetArch::x86_64)
        }
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        {
            bail!("seccomp filter not configured for this arch")
        }
    }

    pub fn apply(role: &str, mode: SandboxMode) -> Result<()> {
        let mismatch = match mode {
            SandboxMode::Strict => SeccompAction::KillProcess,
            SandboxMode::Log => SeccompAction::Log,
            SandboxMode::Off => return Ok(()),
        };

        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        for &n in worker_syscalls() {
            // `c_long` is i32 on 32-bit Linux arches, where this cast widens to
            // the map's i64 key; clippy only sees the 64-bit build (c_long ==
            // i64), where the cast looks redundant.
            #[allow(
                clippy::unnecessary_cast,
                reason = "c_long is narrower than i64 on supported 32-bit Linux targets"
            )]
            rules.insert(n as i64, vec![]);
        }
        let arch = target_arch()?;
        let filter = SeccompFilter::new(rules, mismatch, SeccompAction::Allow, arch)
            .context("build seccomp filter")?;
        let program: seccompiler::BpfProgram =
            filter.try_into().context("compile seccomp filter")?;
        apply_filter(&program).context("install seccomp filter")?;

        tracing::info!(
            role,
            ?mode,
            count = worker_syscalls().len(),
            "seccomp filter installed"
        );
        Ok(())
    }
}

#[cfg(target_os = "freebsd")]
mod freebsd_capsicum {
    //! Capsicum has only one mode of operation: after `cap_enter()` the
    //! process is in capability mode and may no longer use global namespaces
    //! (paths, sysctls, PIDs of other processes). Unlike seccomp's per-syscall
    //! allowlist, there's no equivalent of `Log` mode at the kernel level —
    //! both `Strict` and `Log` here just call `cap_enter()`.
    //!
    //! Known runtime consequences for this daemon:
    //!
    //!   * **Data plane works under cap mode** — `worker_common::SocketsDialer`
    //!     pre-opens `sockets_dir` and uses `connectat(2)` so the acceptor →
    //!     processor handoff doesn't touch the global path namespace.
    //!
    //!   * **TLS cert SIGHUP / admin reload works under cap mode** —
    //!     `acceptor::TlsCertSource` pre-opens the cert/key parent dirs as
    //!     `CAP_LOOKUP | CAP_READ` FDs before `cap_enter()` and reloads via
    //!     `openat(dir_fd, basename)`, so a long-lived worker can swap certs
    //!     without leaving capability mode.
    //!
    //!   * **In-place upgrade works under cap mode**, given two things. The
    //!     exec primitive is `fexecve(binary_fd, …)` via a pre-opened self-exe
    //!     FD (`handoff::open_self_exe`), so the exec syscall itself takes no
    //!     path. But the successor inherits cap mode, so (a) a *dynamically*
    //!     linked image dies in-kernel resolving `/libexec/ld-elf.so.1` by
    //!     path before `main` — fixed by a **static** binary
    //!     (`scripts/build-static.sh`); and (b) its startup (`Config::load`,
    //!     sockets dir, cert/key dirs, `current_exe`) is path-based — fixed by
    //!     the **FD handoff** in `handoff::cap_mode_handoff`, which pre-opens
    //!     each before `cap_enter` and passes the fd numbers to the successor
    //!     (it adopts them, like `ENV_LISTENER_FD`). Name-form
    //!     `drop_uid`/`drop_gid` (e.g. `"nobody"`) are **not** a problem:
    //!     `drop_privileges` normalizes them to numeric strings in the config
    //!     before `cap_enter`, so the JSON the successor loads already carries
    //!     numeric IDs and never calls `getpwnam_r`.
    //!
    //! Practical recommendation: on FreeBSD, run with `sandbox = "strict"`
    //! for steady-state security and ship the static binary so rolling
    //! upgrades keep working. The `--target` flag of `upgrade` is still
    //! blocked under cap mode (we can't open an arbitrary new path), so it
    //! requires `sandbox = "off"`; the supervisor itself is never sandboxed,
    //! so cold-restart upgrades always work.
    //!
    //!   * **The scanner can't run under cap mode.** Its identd probes are
    //!     outbound `connect()`s to arbitrary client IPs, which
    //!     Capsicum rejects with `ECAPMODE` (there's no pre-openable FD for an
    //!     address only known once a client connects). Override it to `off`
    //!     while the rest stay strict, via
    //!     `[security.sandbox_overrides] scanner = "off"`
    //!     ([`SecurityConfig::effective_sandbox`]).

    use super::*;
    use nix::libc;

    pub fn apply(role: &str, mode: SandboxMode) -> Result<()> {
        if mode == SandboxMode::Off {
            return Ok(());
        }
        // SAFETY: cap_enter has no preconditions; on success the process is
        // transitioned to capability mode. No further action is needed.
        let ret = unsafe { libc::cap_enter() };
        if ret != 0 {
            return Err(io::Error::last_os_error()).context("cap_enter");
        }
        tracing::info!(role, ?mode, "entered Capsicum capability mode");
        Ok(())
    }
}

/// Parse a uid spec: numeric (`"65534"`) or username (`"nobody"`). Names go
/// through NSS via `getpwnam_r`.
fn resolve_uid(spec: &str) -> Result<u32> {
    if let Ok(n) = spec.parse::<u32>() {
        return Ok(n);
    }
    let user = User::from_name(spec).with_context(|| format!("lookup user {spec}"))?;
    let user = user.ok_or_else(|| anyhow::anyhow!("no such user: {spec}"))?;
    Ok(user.uid.as_raw())
}

fn resolve_gid(spec: &str) -> Result<u32> {
    if let Ok(n) = spec.parse::<u32>() {
        return Ok(n);
    }
    let group = Group::from_name(spec).with_context(|| format!("lookup group {spec}"))?;
    let group = group.ok_or_else(|| anyhow::anyhow!("no such group: {spec}"))?;
    Ok(group.gid.as_raw())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_is_noop() {
        let mut cfg = SecurityConfig::default();
        drop_privileges("test", &mut cfg).expect("no-op drop should succeed");
    }

    #[test]
    fn resolve_uid_accepts_numeric() {
        assert_eq!(resolve_uid("0").unwrap(), 0);
        assert_eq!(resolve_uid("65534").unwrap(), 65534);
    }

    #[test]
    fn resolve_uid_rejects_unknown_name() {
        let err = resolve_uid("this-user-does-not-exist-fdpass").unwrap_err();
        assert!(format!("{err}").contains("no such user"));
    }

    #[test]
    fn resolve_uid_finds_root_by_name() {
        // "root" exists in every passwd database we'd ship to.
        let uid = resolve_uid("root").expect("root user lookup");
        assert_eq!(uid, 0);
    }

    #[test]
    fn resolve_gid_accepts_numeric() {
        assert_eq!(resolve_gid("0").unwrap(), 0);
    }

    #[test]
    fn resolve_gid_rejects_unknown_name() {
        let err = resolve_gid("this-group-does-not-exist-fdpass").unwrap_err();
        assert!(format!("{err}").contains("no such group"));
    }

    #[test]
    fn drop_to_current_uid_is_safe_noop() {
        // Setting drop_uid to the current uid is the dev-loop sanity check:
        // exercises the setuid path without requiring root.
        let cur = Uid::effective().as_raw();
        let mut cfg = SecurityConfig {
            drop_uid: Some(cur.to_string()),
            drop_gid: None,
            ..Default::default()
        };
        drop_privileges("test", &mut cfg).expect("drop to self should succeed");
        assert_eq!(Uid::effective().as_raw(), cur);
    }

    #[test]
    fn drop_privileges_normalizes_name_to_numeric() {
        // After a successful drop, cfg.drop_uid must be numeric so that
        // cap-mode upgrade successors (which inherit Capsicum and cannot call
        // getpwnam_r) can resolve it without touching the path namespace.
        let cur = Uid::effective().as_raw();
        let gid = Gid::effective().as_raw();
        let mut cfg = SecurityConfig {
            drop_uid: Some(cur.to_string()),
            drop_gid: Some(gid.to_string()),
            ..Default::default()
        };
        drop_privileges("test", &mut cfg).expect("drop to self should succeed");
        let uid_str = cfg
            .drop_uid
            .as_deref()
            .expect("drop_uid must be set after drop");
        let gid_str = cfg
            .drop_gid
            .as_deref()
            .expect("drop_gid must be set after drop");
        assert!(
            uid_str.parse::<u32>().is_ok(),
            "drop_uid must be numeric after drop: {uid_str:?}"
        );
        assert!(
            gid_str.parse::<u32>().is_ok(),
            "drop_gid must be numeric after drop: {gid_str:?}"
        );
        assert_eq!(uid_str, cur.to_string());
        assert_eq!(gid_str, gid.to_string());
    }
}
