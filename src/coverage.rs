//! Explicit LLVM coverage-counter flush, for code paths that exit without running the profiling
//! runtime's `atexit` writer.
//!
//! Source-based coverage normally serializes counters via an `atexit` handler when a process exits
//! cleanly. Several paths in this daemon never reach that handler:
//!
//! - the TLS fork-and-drain child terminates via `libc::_exit`, and its parent via `exec`
//!   (`acceptor/tls_drain.rs`); and
//! - the plain/TLS acceptor has no production SIGTERM path (it shuts down via the control channel),
//!   so at teardown the supervisor's SIGTERM kills it before `atexit` runs — leaving worker-resident
//!   branches (e.g. the upgrade rollback) uncovered despite passing tests.
//!
//! Calling [`flush_coverage`] at those points makes coverage reflect what actually ran. It is a
//! no-op in ordinary builds and compiles away entirely.

/// Serialize LLVM coverage counters to the `LLVM_PROFILE_FILE` path now, instead of relying on the
/// profiling runtime's `atexit` writer. No-op unless built with coverage instrumentation.
#[cfg(coverage)]
pub(crate) fn flush_coverage() {
    unsafe extern "C" {
        fn __llvm_profile_write_file() -> core::ffi::c_int;
    }
    // SAFETY: `__llvm_profile_write_file` is linked by `-Cinstrument-coverage`, present exactly when
    // `cfg(coverage)` is set. It serializes profiling-owned counter buffers to the
    // `LLVM_PROFILE_FILE` path and takes no lock a parent tokio thread could hold, so it is safe to
    // call post-fork. `%p` in the path yields a per-pid file (child vs. parent don't collide); the
    // `%m` merge pool folds a pre-exec write into its same-pid post-exec successor.
    let _ = unsafe { __llvm_profile_write_file() };
}

/// Production no-op: without `-Cinstrument-coverage` the runtime symbol isn't linked, so it must not
/// be referenced.
#[cfg(not(coverage))]
#[inline(always)]
pub(crate) fn flush_coverage() {}
