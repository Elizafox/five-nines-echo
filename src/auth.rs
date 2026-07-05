//! Peer credential authentication for the UDS control plane.
//!
//! Every UDS accept site checks the connecting peer's uid against an allowlist before serving. We
//! use `SO_PEERCRED` on Linux and `LOCAL_PEERCRED` on macOS/FreeBSD, both via direct `getsockopt`,
//! because tokio's `peer_cred()` on macOS uses `getpeereid()`, which returns ENOTCONN once the peer
//! has called `shutdown()` (a common pattern for "write one line and disconnect"). The kernel
//! caches creds at connect time for both `SO_PEERCRED` and `LOCAL_PEERCRED`, so they survive the close.
//!
//! Default policy: only the effective uid of the running process. That matches the supervisor ->
//! workers -> admin-client model where every component runs as the same user. "Production"
//! deployments can override this via the TOML config.

use std::collections::HashSet;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::{Arc, RwLock};

use anyhow::{Result, bail};
use nix::unistd::Uid;

#[derive(Debug, Clone)]
pub struct PeerAllowlist {
    uids: HashSet<u32>,
}

impl PeerAllowlist {
    /// Default policy: only the effective uid of the running process
    pub fn current_user_only() -> Self {
        Self::from_uids([Uid::effective().as_raw()])
    }

    pub fn from_uids<I: IntoIterator<Item = u32>>(uids: I) -> Self {
        Self {
            uids: uids.into_iter().collect(),
        }
    }

    /// Resolve an allowlist from a slice of configured uids. Empty (the TOML default) is treated as
    /// `current_user_only()`, the conservative fallback when no auth section is present
    pub fn from_config(configured: &[u32]) -> Self {
        if configured.is_empty() {
            Self::current_user_only()
        } else {
            Self::from_uids(configured.iter().copied())
        }
    }

    pub fn contains(&self, uid: u32) -> bool {
        self.uids.contains(&uid)
    }
}

pub type SharedAllowlist = Arc<RwLock<PeerAllowlist>>;

/// Reject if the peer's uid isn't on the allowlist. Returns the peer's uid on success for
/// structured logging at the caller
pub fn check_peer(stream: &tokio::net::UnixStream, allow: &PeerAllowlist) -> Result<u32> {
    let uid = peer_uid(stream.as_raw_fd())?;
    if !allow.contains(uid) {
        bail!("rejected peer uid={uid}");
    }
    Ok(uid)
}

#[cfg(target_os = "linux")]
fn peer_uid(fd: RawFd) -> Result<u32> {
    use std::os::fd::BorrowedFd;

    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

    // SAFETY: caller owns `fd` and keeps it open for the duration of this call
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    let cred = getsockopt(&borrowed, PeerCredentials)
        .map_err(|e| anyhow::anyhow!("SO_PEERCRED failed: {e}"))?;
    Ok(cred.uid())
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn peer_uid(fd: RawFd) -> Result<u32> {
    use std::{io, mem::MaybeUninit};

    use nix::libc;

    // LOCAL_PEERCRED returns a `xucred` whose first cred is the peer's effective uid at connect
    // time. The kernel cached it; this works even after the peer has called `shutdown()` or
    // `close()`.
    //
    // `SOL_LOCAL` is `0` on both macOS and FreeBSD but the libc crate only exposes the named
    // constant on macOS, so we hardcode it for portability.
    const SOL_LOCAL: libc::c_int = 0;

    let mut cred = MaybeUninit::<libc::xucred>::uninit();
    let buf_size =
        libc::socklen_t::try_from(size_of::<libc::xucred>()).expect("xucred size fits socklen_t");
    let mut len = buf_size;
    // SAFETY: cred is a valid stack allocation of size buf_size; len reflects
    // the buffer's writable extent. getsockopt populates the buffer on success.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            SOL_LOCAL,
            libc::LOCAL_PEERCRED,
            cred.as_mut_ptr().cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    if ret < 0 {
        return Err(anyhow::anyhow!(
            "LOCAL_PEERCRED failed: {}",
            io::Error::last_os_error()
        ));
    }
    if len < buf_size {
        return Err(anyhow::anyhow!(
            "LOCAL_PEERCRED short read: got {len} of {buf_size} bytes"
        ));
    }
    // SAFETY: getsockopt returned success and wrote a full xucred (len check
    // above). xucred is repr(C) POD with no invalid bit patterns.
    Ok(unsafe { cred.assume_init() }.cr_uid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn current_uid() -> u32 {
        Uid::effective().as_raw()
    }

    #[test]
    fn current_user_only_contains_self_and_nothing_else() {
        let a = PeerAllowlist::current_user_only();
        assert!(a.contains(current_uid()));
        // Pick a uid we are not. uid::MAX is reserved, never an effective uid.
        assert!(!a.contains(u32::MAX));
    }

    #[test]
    fn from_uids_builds_exact_set() {
        let a = PeerAllowlist::from_uids([1, 2, 3]);
        for u in [1, 2, 3] {
            assert!(a.contains(u));
        }
        assert!(!a.contains(4));
    }

    #[test]
    fn from_config_empty_falls_back_to_current_user() {
        let a = PeerAllowlist::from_config(&[]);
        assert!(a.contains(current_uid()));
        assert!(!a.contains(current_uid().wrapping_add(1)));
    }

    #[test]
    fn from_config_non_empty_uses_exact_list() {
        // Specifically: an empty configured list defaults to "current user", but a non-empty list
        // does NOT auto-include the current user.
        let bogus = current_uid().wrapping_add(1234);
        let a = PeerAllowlist::from_config(&[bogus]);
        assert!(a.contains(bogus));
        // Edge case: if current uid happens to equal bogus (won't), skip.
        if current_uid() != bogus {
            assert!(!a.contains(current_uid()));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn check_peer_accepts_self_uid() {
        // Exercises the LOCAL_PEERCRED (macOS/FreeBSD) or SO_PEERCRED (Linux) path through a real
        // Unix socket pair. The peer uid on a connected pair is the current process's uid.
        let (a, _b) = tokio::net::UnixStream::pair().expect("socketpair");
        let allow = PeerAllowlist::current_user_only();
        let uid = check_peer(&a, &allow).expect("self uid should pass");
        assert_eq!(uid, current_uid());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn check_peer_rejects_unlisted_uid() {
        let (a, _b) = tokio::net::UnixStream::pair().expect("socketpair");
        // Allowlist a uid that isn't us
        let allow = PeerAllowlist::from_uids([current_uid().wrapping_add(1)]);
        assert!(check_peer(&a, &allow).is_err());
    }
}
