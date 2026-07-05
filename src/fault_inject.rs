//! Deterministic fault injection for debug builds.
//!
//! Call sites sprinkled throughout the daemon use `fault_inject!("point.name")` to check whether
//! that point is active. In release builds, the macro expands to `None` and is optimised out
//! entirely; no runtime cost, no symbols in the release binary.
//!
//! Initialisation: call [`init`] once at startup (before spawning any worker threads) with the
//! parsed `[fault_inject]` config section.

#![cfg_attr(
    not(debug_assertions),
    allow(
        dead_code,
        reason = "fault injection internals are debug-only; release macro is a typed no-op"
    )
)]

use std::io;
use std::sync::{
    OnceLock,
    atomic::{AtomicU32, Ordering},
};

use crate::config::FaultPointConfig;

/// Payload returned to a call site when a fault fires
pub enum InjectedFault {
    IoError(io::ErrorKind, String),
    Skip,
    Panic(String),
}

impl InjectedFault {
    pub fn into_io_error(self) -> io::Error {
        match self {
            InjectedFault::IoError(kind, msg) => io::Error::new(kind, msg),
            InjectedFault::Skip => io::Error::other("fault: skip"),
            InjectedFault::Panic(msg) => panic!("{msg}"),
        }
    }

    pub fn into_anyhow(self) -> anyhow::Error {
        match self {
            InjectedFault::Panic(msg) => panic!("{msg}"),
            f => anyhow::Error::from(f.into_io_error()),
        }
    }
}

// Internal storage

enum StoredKind {
    IoError(io::ErrorKind, Box<str>),
    Skip,
    Panic(Box<str>),
}

struct ActivePoint {
    name: Box<str>,
    kind: StoredKind,
    /// `u32::MAX` = unlimited; `0` = exhausted; `N` = N shots left
    budget: AtomicU32,
}

impl ActivePoint {
    fn to_fault(&self) -> InjectedFault {
        match &self.kind {
            StoredKind::IoError(kind, msg) => InjectedFault::IoError(*kind, msg.to_string()),
            StoredKind::Skip => InjectedFault::Skip,
            StoredKind::Panic(msg) => InjectedFault::Panic(msg.to_string()),
        }
    }
}

static ACTIVE_POINTS: OnceLock<Vec<ActivePoint>> = OnceLock::new();

/// Build an `ActivePoint` from its config. Shared by `init` and the tests so the kind / budget
/// mapping lives in exactly one place
#[cfg(any(debug_assertions, test))]
fn build_active_point(p: &FaultPointConfig) -> ActivePoint {
    let kind = match p.kind.as_str() {
        "panic" => StoredKind::Panic(p.message.clone().into_boxed_str()),
        "skip" => StoredKind::Skip,
        // Default / "io_error"
        _ => StoredKind::IoError(io::ErrorKind::Other, p.message.clone().into_boxed_str()),
    };
    // trigger_budget 0 in config means unlimited.
    let budget = if p.trigger_budget == 0 {
        u32::MAX
    } else {
        p.trigger_budget
    };
    ActivePoint {
        name: p.name.clone().into_boxed_str(),
        kind,
        budget: AtomicU32::new(budget),
    }
}

/// Atomically consume one shot of `budget`, returning `true` if one was available. `u32::MAX` =
/// unlimited (stays put), `0` = exhausted.
fn try_fire(budget: &AtomicU32) -> bool {
    // fetch_update returns Ok(prev) when the closure returned Some (update committed), Err(0) when
    // budget was already 0 and the closure returned None
    budget
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |b| {
            if b == 0 {
                None // exhausted; don't update
            } else if b == u32::MAX {
                Some(u32::MAX) // unlimited; stay at MAX
            } else {
                Some(b - 1)
            }
        })
        .is_ok()
}

// Public API

/// Install the fault-injection table from the parsed config. Must be called before any worker
/// threads are spawned. Safe to call with an empty slice.
pub fn init(points: &[FaultPointConfig]) {
    #[cfg(debug_assertions)]
    {
        let active: Vec<ActivePoint> = points.iter().map(build_active_point).collect();
        // Silently no-op on second call. Shouldn't happen but harmless.
        let _ = ACTIVE_POINTS.set(active);
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = points;
    }
}

/// Check whether `point` should fire. Decrements the trigger budget; returns `None` if the point is
/// not configured, or its budget is exhausted.
///
/// In release builds this is unreachable; the `fault_inject!` macro expands to `None` before this
/// function would ever be called.
pub fn check(point: &str) -> Option<InjectedFault> {
    let points = ACTIVE_POINTS.get()?;
    for p in points {
        if p.name.as_ref() != point {
            continue;
        }
        return try_fire(&p.budget).then(|| p.to_fault());
    }
    None
}

// Macros

/// In debug builds: check the named injection point and return `Option<InjectedFault>`.
/// In release builds: unconditionally `None` (optimized out).
#[cfg(debug_assertions)]
#[macro_export]
macro_rules! fault_inject {
    ($point:literal) => {
        $crate::fault_inject::check($point)
    };
}

#[cfg(not(debug_assertions))]
#[macro_export]
macro_rules! fault_inject {
    ($point:literal) => {
        None::<$crate::fault_inject::InjectedFault>
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::FaultPointConfig;

    fn point(name: &str, kind: &str, msg: &str, budget: u32) -> FaultPointConfig {
        FaultPointConfig {
            name: name.into(),
            kind: kind.into(),
            message: msg.into(),
            trigger_budget: budget,
        }
    }

    fn fresh_points(pts: &[FaultPointConfig]) -> Vec<ActivePoint> {
        pts.iter().map(build_active_point).collect()
    }

    fn check_in(points: &[ActivePoint], name: &str) -> Option<()> {
        for p in points {
            if p.name.as_ref() != name {
                continue;
            }
            return try_fire(&p.budget).then_some(());
        }
        None
    }

    #[test]
    fn unknown_point_returns_none() {
        let pts = fresh_points(&[point("a.b", "io_error", "oops", 0)]);
        assert!(check_in(&pts, "c.d").is_none());
    }

    #[test]
    fn unlimited_budget_fires_repeatedly() {
        let pts = fresh_points(&[point("x", "io_error", "err", 0)]);
        for _ in 0..5 {
            assert!(check_in(&pts, "x").is_some());
        }
    }

    #[test]
    fn one_shot_budget_fires_once() {
        let pts = fresh_points(&[point("x", "io_error", "err", 1)]);
        assert!(check_in(&pts, "x").is_some());
        assert!(check_in(&pts, "x").is_none());
        assert!(check_in(&pts, "x").is_none());
    }

    #[test]
    fn budget_n_fires_n_times() {
        let pts = fresh_points(&[point("x", "skip", "", 3)]);
        for _ in 0..3 {
            assert!(check_in(&pts, "x").is_some(), "should fire");
        }
        assert!(check_in(&pts, "x").is_none(), "should be exhausted");
    }

    #[test]
    fn skip_kind_roundtrips() {
        let pts = fresh_points(&[point("p", "skip", "", 1)]);
        assert!(check_in(&pts, "p").is_some());
    }

    #[test]
    fn io_error_kind_roundtrips() {
        let pts = fresh_points(&[point("p", "io_error", "boom", 1)]);
        let ap = &pts[0];
        ap.budget.store(1, Ordering::Relaxed);
        match ap.to_fault() {
            InjectedFault::IoError(_, msg) => assert_eq!(msg, "boom"),
            _ => panic!("wrong variant"),
        }
    }

    #[cfg(debug_assertions)]
    #[test]
    fn release_noop_path_compiles() {
        // In release this would expand to None; in debug it hits check().
        // We can't fully test the release path here, but at least confirm the
        // debug path compiles and returns None for an unregistered point.
        let _ = crate::fault_inject::check("nonexistent.point");
    }

    #[test]
    fn into_io_error_from_io_error_variant() {
        let fault = InjectedFault::IoError(io::ErrorKind::ConnectionRefused, "refused".into());
        let err = fault.into_io_error();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
        assert!(err.to_string().contains("refused"));
    }

    #[test]
    fn into_io_error_from_skip_variant() {
        let err = InjectedFault::Skip.into_io_error();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert!(err.to_string().contains("skip"));
    }

    #[test]
    fn into_anyhow_from_io_error_variant() {
        let fault = InjectedFault::IoError(io::ErrorKind::TimedOut, "timed out".into());
        let err = fault.into_anyhow();
        assert!(err.to_string().contains("timed out"));
    }

    #[test]
    fn into_anyhow_from_skip_variant() {
        let err = InjectedFault::Skip.into_anyhow();
        assert!(err.to_string().contains("skip"));
    }

    #[test]
    fn to_fault_skip_variant_produces_skip() {
        let pts = fresh_points(&[point("p", "skip", "", 0)]);
        match pts[0].to_fault() {
            InjectedFault::Skip => {}
            _ => panic!("expected InjectedFault::Skip"),
        }
    }

    #[test]
    fn to_fault_panic_variant_produces_panic_message() {
        let pts = fresh_points(&[point("p", "panic", "kaboom", 0)]);
        match pts[0].to_fault() {
            InjectedFault::Panic(msg) => assert_eq!(msg, "kaboom"),
            _ => panic!("expected InjectedFault::Panic"),
        }
    }
}
