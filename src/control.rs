use std::path::PathBuf;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::{
    fault_inject,
    handoff::{
        MIN_COMPATIBLE_VERSION, SCHEMA_VERSION, default_schema_version, is_schema_compatible,
    },
};

/// Generic versioned wire envelope. Wraps a serde-tagged enum (or any struct that serialises as a
/// map) and adds a `version` sibling field, e.g. `{"version":1,"type":"shutdown",...}`. Used for
/// `ControlMsg`, `WorkerMsg`, and `AdminResp`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope<T> {
    #[serde(default = "default_schema_version")]
    pub version: u32,
    #[serde(flatten)]
    pub msg: T,
}

impl<T> Envelope<T> {
    /// Hand back the inner payload only if the version is supported
    pub fn into_msg(self) -> anyhow::Result<T> {
        if let Some(f) = fault_inject!("schema.version") {
            return Err(f
                .into_anyhow()
                .context("synthetic: forced schema version incompatibility"));
        }
        if !is_schema_compatible(self.version) {
            anyhow::bail!(
                "incompatible schema version {} (supported: {}..={})",
                self.version,
                MIN_COMPATIBLE_VERSION,
                SCHEMA_VERSION,
            );
        }
        Ok(self.msg)
    }
}

#[derive(Serialize)]
struct BorrowedEnvelope<'a, T: ?Sized> {
    version: u32,
    #[serde(flatten)]
    msg: &'a T,
}

/// Serialize a wire payload as one newline-terminated [`Envelope`] frame.
pub fn envelope_line<T: Serialize + ?Sized>(msg: &T) -> serde_json::Result<String> {
    let mut line = serde_json::to_string(&BorrowedEnvelope {
        version: SCHEMA_VERSION,
        msg,
    })?;
    line.push('\n');
    Ok(line)
}

/// Parse one line-delimited [`Envelope`] frame and validate its schema version.
pub fn parse_envelope<T: DeserializeOwned>(line: &str) -> anyhow::Result<T> {
    serde_json::from_str::<Envelope<T>>(line)
        .map_err(anyhow::Error::from)
        .and_then(Envelope::into_msg)
}

/// Supervisor → worker, and CLI → supervisor admin socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlMsg {
    Shutdown {
        grace_ms: u64,
    },
    Upgrade {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        binary_path: Option<PathBuf>,
        /// Admin-CLI -> supervisor: include the TLS acceptor in the rolling walk. Default false:
        /// TLS is treated as a long-lived terminator and skipped on routine upgrades. Workers
        /// ignore this field.
        #[serde(default)]
        include_tls: bool,
        /// Admin-CLI -> supervisor: after each per-role upgrade, observe the just-upgraded role for
        /// this many seconds; if its watchdog state regresses below `Healthy`, abort the rest of
        /// the walk. `None` (omitted) means no canary; walk all roles back-to-back
        #[serde(default, skip_serializing_if = "Option::is_none")]
        canary_secs: Option<u64>,
        /// Admin-CLI -> supervisor: restrict the upgrade to this single worker
        /// (`processor`/`plain`/`scanner`/`tls`) instead of walking all roles. `None` walks the full
        /// set. Motivating case: the processor holds the business logic and upgrades often — its
        /// in-flight sessions survive via UDS handoff — while the acceptor is thin, stable plumbing
        /// (accept + bridge) that rarely re-execs and resets in-flight sessions when it does. Workers
        /// ignore this field.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        only_role: Option<String>,
    },
    Status,
    /// Stop accepting new connections; keep existing sessions and the daemon running. Workers
    /// without listeners (processor, scanner) ignore
    Drain,
    /// Re-read config from disk and apply hot-reloadable fields. Currently `auth.allowed_uids` is
    /// the only reloadable knob. Other fields are logged-as-ignored. Acceptors with TLS also reload
    /// certs.
    Reload,
}

/// Worker → supervisor.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkerMsg {
    StatusReport(WorkerStatus),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerStatus {
    pub role: String,
    pub pid: u32,
    pub generation: u64,
    pub started_at_unix_ms: u64,
    pub in_flight: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listener_addr: Option<String>,
    /// Rate limiter stats: (`tracked_ips`, `idle_evictions`, `lru_evictions`, `cap_refused`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limiter_stats: Option<RateLimiterStats>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimiterStats {
    pub tracked_ips: usize,
    pub idle_evictions: u64,
    pub lru_evictions: u64,
    pub cap_refused: u64,
}

/// First line written by anyone dialing the processor's UDS. Two flavors:
///
/// - `Session`: rest of the connection is a UDS line-echo session. Used by both acceptors — the
///   plain acceptor forwards raw TCP bytes over this UDS; the TLS acceptor terminates TLS and
///   forwards the plaintext. The processor never touches the client socket directly.
/// - `Sidecar`: subsequent lines are `SessionMetadata` updates from the scanner. One persistent
///   connection per scanner; processor logs and annotates matching sessions
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProcessorPreamble {
    /// Line-echo session over this UDS. Used by both the plain acceptor (raw TCP bytes forwarded)
    /// and the TLS acceptor (plaintext after termination).
    Session {
        peer: String,
        role: String,
        /// Trace ID assigned by the acceptor; lets logs across the acceptor/processor/scanner trio
        /// be joined per session
        #[serde(default)]
        trace_id: String,
    },
    /// Persistent metadata channel from scanner.
    Sidecar,
}

/// One scan result published from scanner -> processor over the sidecar
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMetadata {
    pub peer: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ident: Option<String>,
    /// Acceptor's trace ID for this session: flows scanner -> processor here, so the sidecar
    /// receiver can log under the same id as the session
    #[serde(default)]
    pub trace_id: String,
}

/// Supervisor-side health view of a worker role: independent of whether the worker is currently
/// alive, derived from recent crash cadence
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    Healthy,
    Backoff,
    Flapping,
    /// Terminal: enough consecutive fast exits that the supervisor has stopped trying to respawn
    /// the role. Requires external intervention (a new binary, a config fix, then admin upgrade)
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleHealth {
    pub role: String,
    pub state: HealthState,
    pub consecutive_fast_exits: u32,
    pub next_backoff_ms: u64,
    pub total_restarts: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_restart_at_unix_ms: Option<u64>,
}

/// Events streamed by a post-fork TLS drainer child to the supervisor over
/// `/tmp/fdpass-drainer.sock`. The child has no tokio (its reactor is fork-undefined), so it writes
/// these frames synchronously with std sockets
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DrainerEvent {
    Hello {
        role: String,
        pid: u32,
        generation: u64,
        session_count: usize,
    },
    SessionDone {
        peer: String,
        outcome: SessionOutcome,
    },
    /// All sessions completed naturally; child is about to `_exit(0)` clean
    Complete,
    /// 5s drain deadline hit; `remaining` sessions were still mid-flight
    DeadlineExit { remaining: usize },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum SessionOutcome {
    CleanEof,
    Error { message: String },
}

/// Supervisor admin socket -> CLI
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AdminResp {
    Ok,
    Status {
        workers: Vec<WorkerStatus>,
        #[serde(default)]
        health: Vec<RoleHealth>,
    },
    Error {
        message: String,
    },
    /// Progress event for a single worker during a rolling upgrade
    UpgradeStep {
        worker: String,
        phase: UpgradePhase,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        generation_before: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        generation_after: Option<u64>,
        ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },
    /// Terminal frame for a rolling upgrade
    UpgradeComplete {
        all_ok: bool,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpgradePhase {
    Starting,
    Done,
    Timeout,
    Skipped,
    /// Canary observation window saw the just-upgraded role regress below `Healthy`; the rest of
    /// the walk was aborted
    CanaryAborted,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_stamps_current_version() {
        let line = envelope_line(&ControlMsg::Status).unwrap();
        let e: Envelope<ControlMsg> = serde_json::from_str(&line).unwrap();
        assert_eq!(e.version, SCHEMA_VERSION);
    }

    #[test]
    fn envelope_roundtrip_preserves_msg() {
        let json = envelope_line(&ControlMsg::Shutdown { grace_ms: 1234 }).unwrap();
        let back: Envelope<ControlMsg> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.version, SCHEMA_VERSION);
        match back.msg {
            ControlMsg::Shutdown { grace_ms } => assert_eq!(grace_ms, 1234),
            _ => panic!("variant changed under round-trip"),
        }
    }

    #[test]
    fn missing_version_field_defaults_to_v1() {
        // Legacy sender: no `version` key. We accept and treat as v1.
        let legacy = r#"{"type":"status"}"#;
        let env: Envelope<ControlMsg> = serde_json::from_str(legacy).unwrap();
        assert_eq!(env.version, 1);
        assert!(matches!(env.msg, ControlMsg::Status));
    }

    #[test]
    fn incompatible_high_version_rejected() {
        let evil = r#"{"version":99,"type":"status"}"#;
        let env: Envelope<ControlMsg> = serde_json::from_str(evil).unwrap();
        assert!(env.into_msg().is_err());
    }

    #[test]
    fn version_zero_rejected() {
        let bad = r#"{"version":0,"type":"status"}"#;
        let env: Envelope<ControlMsg> = serde_json::from_str(bad).unwrap();
        assert!(env.into_msg().is_err());
    }

    #[test]
    fn current_version_accepted() {
        let good = format!(r#"{{"version":{SCHEMA_VERSION},"type":"status"}}"#);
        let env: Envelope<ControlMsg> = serde_json::from_str(&good).unwrap();
        assert!(matches!(env.into_msg().unwrap(), ControlMsg::Status));
    }
}
