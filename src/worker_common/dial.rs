use std::io;
use std::os::fd::RawFd;
use std::path::Path;
use std::time::Duration;

#[cfg(not(target_os = "freebsd"))]
use std::path::PathBuf;

#[cfg(target_os = "freebsd")]
use std::os::fd::OwnedFd;

#[cfg(target_os = "freebsd")]
use std::os::unix::io::{FromRawFd, IntoRawFd};

#[cfg(target_os = "freebsd")]
use anyhow::Context;
use anyhow::Result;

#[cfg(target_os = "freebsd")]
use std::os::unix::io::AsRawFd;

// ======================
// UDS DIAL BY DIR + NAME
// ======================
// Workers dial fixed-name UDS sockets under `sockets_dir` on every accepted client (acceptor ->
// processor) and from sidecars (scanner -> processor). On most OSes, this is a vanilla
// `connect(AF_UNIX, "/path/...")`. Under FreeBSD Capscium capability mode, that's blocked; path
// lookups against the global filesystem namespace return ECAPMODE. The fix is `connectat(dir_fd,
// ...)` with a pre-opened, capability-rights-limited dir FD.
//
// `SocketsDialer` hides that platform split behind one async `dial(name)`.

/// Per-OS strategy for dialing UDS sockets under `sockets_dir` by basename. On FreeBSD, this owns a
/// dir FD opened with `CAP_CONNECTAT` so the dial works after `cap_enter()`. Elsewhere it just
/// holds the directory path.
#[derive(Debug)]
pub struct SocketsDialer {
    #[cfg(not(target_os = "freebsd"))]
    dir: PathBuf,
    #[cfg(target_os = "freebsd")]
    dir_fd: OwnedFd,
}

impl SocketsDialer {
    /// Open the sockets directory and prepare the per-OS connect path. Call this *before*
    /// `apply_sandbox`; the FreeBSD branch needs to open the dir whilst paths are still reachable.
    #[allow(
        clippy::unnecessary_wraps,
        reason = "Failable on FreeBSD, nowhere else."
    )]
    pub fn open(sockets_dir: &Path) -> Result<Self> {
        #[cfg(target_os = "freebsd")]
        {
            use std::{fs::File, mem::MaybeUninit};

            use nix::libc::{
                __cap_rights_init, CAP_CONNECTAT, CAP_RIGHTS_VERSION, cap_rights_limit,
                cap_rights_t,
            };

            use crate::handoff::{ENV_SOCKETS_DIR_FD, env_raw_fd};

            // Cap-mode upgrade successor: adopt the inherited, already cap-limited dir FD rather
            // than reopening the path (ECAPMODE).
            if let Some(raw) = env_raw_fd(ENV_SOCKETS_DIR_FD) {
                // SAFETY: parent cleared CLOEXEC and passed the fd number via env right before
                // `fexecve()`; it's already CAP_CONNECTAT-limited
                let dir_fd = unsafe { OwnedFd::from_raw_fd(raw) };
                tracing::info!(
                    fd = raw,
                    "adopted inherited sockets_dir FD (cap-mode upgrade)"
                );
                return Ok(Self { dir_fd });
            }
            let f = File::open(sockets_dir)?;
            let dir_fd: OwnedFd = f.into();
            // Limit the FD's rights to just `connectat` so a future bug can't reuse it for
            // arbitrary operations.
            #[allow(
                unused_unsafe,
                reason = "FreeBSD libc cap_rights helpers are unsafe on supported toolchains"
            )]
            // SAFETY: __cap_rights_init/cap_rights_limit operate on a stack-local `cap_rights_t` we
            // initialise here (and read back only after `assume_init`) on the owned `dir_fd`; both
            // pointers are valid for the duration of the call.
            unsafe {
                let mut rights = MaybeUninit::<cap_rights_t>::uninit();
                __cap_rights_init(CAP_RIGHTS_VERSION, rights.as_mut_ptr(), CAP_CONNECTAT, 0u64);
                let rights = rights.assume_init();
                if cap_rights_limit(dir_fd.as_raw_fd(), &rights) != 0 {
                    return Err(io::Error::last_os_error())
                        .context("cap_rights_limit on sockets_dir");
                }
            }
            Ok(Self { dir_fd })
        }
        #[cfg(not(target_os = "freebsd"))]
        {
            Ok(Self {
                dir: sockets_dir.to_path_buf(),
            })
        }
    }

    /// Raw fd of the pre-opened sockets dir, for cap-mode upgrade handoff. `None` outside FreeBSD,
    /// where no dir FD is held (dials use the path).
    pub fn dir_raw_fd(&self) -> Option<RawFd> {
        #[cfg(target_os = "freebsd")]
        {
            Some(self.dir_fd.as_raw_fd())
        }
        #[cfg(not(target_os = "freebsd"))]
        {
            let _ = self;
            None
        }
    }

    /// Connect to `<sockets_dir>/<name>`. On FreeBSD uses `connectat` with the pre-opened dir FD;
    /// elsewhere, the regular `connect`. Returns a non-blocking tokio `UnixStream`.
    pub async fn dial(&self, name: &str) -> io::Result<tokio::net::UnixStream> {
        #[cfg(target_os = "freebsd")]
        {
            self.dial_via_connectat(name).await
        }
        #[cfg(not(target_os = "freebsd"))]
        {
            tokio::net::UnixStream::connect(self.dir.join(name)).await
        }
    }

    #[cfg(target_os = "freebsd")]
    async fn dial_via_connectat(&self, name: &str) -> io::Result<tokio::net::UnixStream> {
        // Non-blocking connectat so we can drive tokio-style readiness, then
        // convert the std stream to tokio's once writable.
        let sock = self.connectat_socket(name, true)?;
        // SAFETY: into_raw_fd transfers ownership out of `sock`; we re-wrap that
        // same fd in the std stream, which owns it from here.
        let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(sock.into_raw_fd()) };
        std_stream.set_nonblocking(true)?;
        let tokio_stream = tokio::net::UnixStream::from_std(std_stream)?;
        // Wait for writable to confirm the async connect completed (or
        // surface the connect-time error).
        tokio_stream.writable().await?;
        if let Some(err) = tokio_stream.take_error()? {
            return Err(err);
        }
        Ok(tokio_stream)
    }

    /// Mint an `AF_UNIX` socket and `connectat` it to `<dir_fd>/<name>`, where `name` is the
    /// RELATIVE basename written into `sun_path`. With `nonblocking`, sets `O_NONBLOCK` first and
    /// tolerates `EINPROGRESS` (the caller confirms completion via readiness); otherwise the
    /// connect blocks to completion. Returns the connected socket as an `OwnedFd`.
    #[cfg(target_os = "freebsd")]
    fn connectat_socket(&self, name: &str, nonblocking: bool) -> io::Result<OwnedFd> {
        use std::mem::{MaybeUninit, offset_of};

        use nix::libc::{
            AF_UNIX, EINPROGRESS, F_GETFL, F_SETFL, O_NONBLOCK, SOCK_STREAM, c_char, c_int, fcntl,
            sa_family_t, sockaddr, sockaddr_un, socket, socklen_t,
        };

        // SAFETY: socket() takes constant domain/type/protocol args and is always safe to call; the
        // return is checked for the error sentinel.
        let raw_fd = unsafe { socket(AF_UNIX, SOCK_STREAM, 0) };
        if raw_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: socket() just minted `raw_fd` and returned it (>= 0 checked above); we take sole
        // ownership of it here
        let sock: OwnedFd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        if nonblocking {
            // SAFETY: fcntl F_GETFL/F_SETFL act on `sock`, which we own and keep alive for the
            // duration of the block
            unsafe {
                let flags = fcntl(sock.as_raw_fd(), F_GETFL);
                if flags < 0 || fcntl(sock.as_raw_fd(), F_SETFL, flags | O_NONBLOCK) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        }

        // SAFETY: sockaddr_un is a repr(C) POD; an all-zero bit pattern is a valid (AF_UNSPEC,
        // empty path) value, which we immediately fill in
        let mut addr = unsafe { MaybeUninit::<sockaddr_un>::zeroed().assume_init() };
        addr.sun_family = AF_UNIX as sa_family_t;
        let name_bytes = name.as_bytes();
        if name_bytes.len() >= addr.sun_path.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "name too long"));
        }
        for (i, &b) in name_bytes.iter().enumerate() {
            addr.sun_path[i] = b as c_char;
        }
        let addr_len = (offset_of!(sockaddr_un, sun_path) + name_bytes.len() + 1) as socklen_t;

        // SAFETY: connectat gets our owned `dir_fd` and `sock` fds plus a pointer/len describing
        // `addr`, a fully-initialised `sockaddr_un` that outlives the call. FreeBSD's
        // `connectat(2)` isnt in the `nix::libc` crate by name, so it's declared locally.
        let ret = unsafe {
            unsafe extern "C" {
                fn connectat(
                    fd: c_int,
                    s: c_int,
                    name: *const sockaddr,
                    namelen: socklen_t,
                ) -> c_int;
            }
            connectat(
                self.dir_fd.as_raw_fd(),
                sock.as_raw_fd(),
                (&raw const addr).cast::<sockaddr>(),
                addr_len,
            )
        };
        if ret < 0 {
            let err = io::Error::last_os_error();
            // A non-blocking connect reports "in progress" via EINPROGRESS; the caller drives it to
            // completion through readiness. A blocking connect never returns that, so any error
            // there is terminal.
            if !(nonblocking && err.raw_os_error() == Some(EINPROGRESS)) {
                return Err(err);
            }
        }
        Ok(sock)
    }
}

/// Dial the supervisor's control socket with bounded retries. Returns `None` if we couldn't connect
/// within the budget; caller decides what to do. Goes via `SocketsDialer` so it works after
/// FreeBSD's `cap_enter()`.
pub async fn dial_control_plane(
    dialer: &SocketsDialer,
    basename: &str,
) -> Option<tokio::net::UnixStream> {
    for attempt in 0..50 {
        if let Ok(s) = dialer.dial(basename).await {
            return Some(s);
        }
        let delay = if attempt < 5 { 100 } else { 300 };
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_succeeds_on_existing_dir() {
        let dialer = SocketsDialer::open(&std::env::temp_dir());
        assert!(dialer.is_ok(), "open should succeed on a real directory");
    }

    #[cfg(not(target_os = "freebsd"))]
    #[test]
    fn dir_raw_fd_returns_none_on_non_freebsd() {
        let dialer = SocketsDialer::open(&std::env::temp_dir()).unwrap();
        assert_eq!(dialer.dir_raw_fd(), None);
    }

    #[cfg(target_os = "freebsd")]
    #[test]
    fn dir_raw_fd_returns_some_on_freebsd() {
        let dialer = SocketsDialer::open(&std::env::temp_dir()).unwrap();
        assert!(dialer.dir_raw_fd().is_some());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dial_connects_to_bound_unix_listener() {
        let dir = std::env::temp_dir();
        let name = format!("fdpass-dial-test-{}.sock", std::process::id());
        let sock_path = dir.join(&name);
        let _ = std::fs::remove_file(&sock_path);
        let _listener = tokio::net::UnixListener::bind(&sock_path).unwrap();
        let dialer = SocketsDialer::open(&dir).unwrap();
        let result = dialer.dial(&name).await;
        let _ = std::fs::remove_file(&sock_path);
        assert!(
            result.is_ok(),
            "dial should connect to the bound listener: {result:?}"
        );
    }
}
