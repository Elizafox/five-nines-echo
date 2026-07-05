//! Runtime configuration. Loaded from a TOML file at startup; every section and field is optional
//! with a default matching the POC's hardcoded values, so an empty file is a valid config.
//!
//! Discovery order: `--config <path>` arg -> `FDPASS_CONFIG_PATH` env -> pure defaults (no file).
//! The supervisor propagates the resolved path via `FDPASS_CONFIG_PATH` so spawned workers and
//! upgrade-children load the same file without reparsing the CLI.

use std::collections::BTreeMap;
use std::env;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// A single named fault-injection point loaded from `[fault_inject]`
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct FaultPointConfig {
    pub name: String,
    /// `"io_error"` (default), `"skip"`, or `"panic"`
    pub kind: String,
    /// Human-readable message returned or logged when the fault fires
    pub message: String,
    /// How many times this point may fire. `0` = unlimited (default)
    pub trigger_budget: u32,
}

/// `[fault_inject]` table. Only effective in debug builds; in release the call-site macro expands
/// to `None` before `check()` is reached
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct FaultInjectConfig {
    pub points: Vec<FaultPointConfig>,
}

/// Env var pointing spawned children at the config file the supervisor used
pub const ENV_CONFIG_PATH: &str = "FDPASS_CONFIG_PATH";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    pub sockets_dir: PathBuf,
    pub plain_port: u16,
    pub tls_port: u16,
    pub ready_timeout_secs: u64,
    /// Override the identd port. Default 113 (the RFC-1413 well-known port). Set to a
    /// non-privileged port in test configs so the scanner doesn't need root.
    pub identd_port: u16,
    pub auth: AuthConfig,
    pub tls: TlsConfig,
    pub limits: LimitsConfig,
    pub metrics: MetricsConfig,
    pub health: HealthConfig,
    pub security: SecurityConfig,
    pub fault_inject: FaultInjectConfig,
}

/// Worker privilege drop. Numeric or name; both are looked up via NSS. Both fields default to
/// `None` (no drop) so dev/test environments (where the daemon already runs as a regular user) are
/// unaffected.
///
/// Production deployment: run the supervisor as root via the systemd unit so it can signal workers
/// post-drop, then set `drop_uid` / `drop_gid` here to the service account workers should run as.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct SecurityConfig {
    pub drop_uid: Option<String>,
    pub drop_gid: Option<String>,
    pub sandbox: SandboxMode,
    /// Per-role overrides of `sandbox`, keyed by role name (`processor` / `plain` / `tls` /
    /// `scanner`). A role absent here uses the global `sandbox`. The motivating case is the
    /// `scanner`: its whole job is outbound TCP probes (identd), which FreeBSD Capscium forbids
    /// (`connect()` to an arbitrary address returns `ECAPMODE`), so it must run `off` there even
    /// when acceptor/processor are `strict`.
    pub sandbox_overrides: BTreeMap<String, SandboxMode>,
}

impl SecurityConfig {
    /// Sandbox mode in effect for `role`: the per-role override from `sandbox_overrides` if one is
    /// set, otherwise the global `sandbox`.
    pub fn effective_sandbox(&self, role: &str) -> SandboxMode {
        self.sandbox_overrides
            .get(role)
            .copied()
            .unwrap_or(self.sandbox)
    }
}

/// Syscall sandbox. `Off` is the default; production should be `Strict`. The `Log` mode
/// (Linux-only) logs blocked syscalls via the audit subsystem instead of killing. This is useful
/// for tuning the allowlist before flipping to strict, but never appropriate for production
/// exposure.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SandboxMode {
    #[default]
    Off,
    Strict,
    Log,
}

/// HTTP `/healthz`-style endpoint. Empty `bind_addr` disables
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct HealthConfig {
    pub bind_addr: String,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            // Loopback-only by default; off-host probing requires deliberate config change (and
            // ideally a tighter firewall posture).
            bind_addr: "127.0.0.1:7079".into(),
        }
    }
}

/// Prometheus textfile-collector output. `path = ""` disables. The supervisor writes the file every
/// `interval_secs` seconds; `node_exporter` (or any textfile collector) picks it up on its own
/// scrape cadence.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct MetricsConfig {
    pub path: PathBuf,
    pub interval_secs: u64,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            // Empty = disabled. Production sets this to a path under the textfile-collector
            // directory
            path: PathBuf::new(),
            interval_secs: 15,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct AuthConfig {
    /// Uids allowed to connect to any UDS endpoint. Empty (the default) is interpreted as "only the
    /// effective UID of the running process"
    pub allowed_uids: Vec<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

/// DoS-bounding knobs. All three are per-acceptor (plain and tls each have their own
/// counters/buckets); set to 0 to disable particular check
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct LimitsConfig {
    /// Cap on live sessions per externally visible role, enforced in the acceptor for the full
    /// session lifetime — both plain and TLS now hold the accept guard until their byte-bridge to
    /// the processor ends. New accepts past the cap are accept-then-closed: TCP is established, then
    /// we immediately drop our half; the client sees a clean close.
    pub max_in_flight_per_role: u64,
    /// Idle timeout for TLS byte-bridge sessions. No bytes in either direction for this many
    /// seconds -> we close the session
    pub tls_idle_timeout_secs: u64,
    /// Per-IP token bucket: max sustained accept rate (tokens-per-second refill) and burst
    /// capacity. 0 disables this.
    pub accept_rate_per_ip: u32,
    pub accept_rate_burst: u32,
    /// Hard cap on tracked IPs in the per-IP rate limiter. When full, least-recently-used entries
    /// are evicted to admit new IPs. 0 = unbounded (no eviction)
    pub rate_limit_max_tracked_ips: usize,
    /// Evict buckets idle for longer than this (seconds). Opportunistically drops buckets not
    /// touched in this long to avoid unbouned growth during bursts of one-shot IPs.
    pub rate_limit_bucket_idle_ttl_secs: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_in_flight_per_role: 1024,
            tls_idle_timeout_secs: 300,
            accept_rate_per_ip: 50,
            accept_rate_burst: 100,
            rate_limit_max_tracked_ips: 65536,
            rate_limit_bucket_idle_ttl_secs: 300,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            sockets_dir: PathBuf::from("/tmp"),
            plain_port: 7070,
            tls_port: 7071,
            ready_timeout_secs: 3,
            identd_port: 113,
            limits: LimitsConfig::default(),
            metrics: MetricsConfig::default(),
            health: HealthConfig::default(),
            auth: AuthConfig::default(),
            tls: TlsConfig::default(),
            security: SecurityConfig::default(),
            fault_inject: FaultInjectConfig::default(),
        }
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            cert_path: PathBuf::from("certs/server.crt"),
            key_path: PathBuf::from("certs/server.key"),
        }
    }
}

impl Config {
    /// Load config from `path` if `Some`, else from `FDPASS_CONFIG_PATH` env var, else return pure
    /// defaults. If `RUNTIME_DIRECTORY` is set in the env (systemd's `RuntimeDirectory=fdpass`
    /// populates `/run/fdpass`), it overrides `sockets_dir`; the unit file is "the deployment
    /// system speaking" and we'd rather honour it than fight it.
    pub fn load(path: Option<PathBuf>) -> Result<Self> {
        // A cap-mode upgrade successor inherits the *already-parsed* config as JSON in
        // `ENV_CONFIG_JSON` (the upgrading worker serialised it), since `cap_enter()` blocks
        // reopening the file by path. The blob is fully resolved, including any RUNTIME_DIRECTORY
        // override, so return it verbatim; no path access, no reapplying overrides.
        if let Ok(json) = env::var(crate::handoff::ENV_CONFIG_JSON) {
            return serde_json::from_str(&json).context("parse inherited config JSON");
        }

        let resolved = path.or_else(|| env::var_os(ENV_CONFIG_PATH).map(PathBuf::from));
        let mut cfg = match resolved {
            None => Self::default(),
            Some(p) => {
                let text = std::fs::read_to_string(&p)
                    .with_context(|| format!("read config {}", p.display()))?;
                toml::from_str(&text).with_context(|| format!("parse config {}", p.display()))?
            }
        };
        if let Some(rd) = env::var_os("RUNTIME_DIRECTORY") {
            let rd_path = PathBuf::from(rd);
            if cfg.sockets_dir != rd_path {
                tracing::info!(
                    runtime_directory = %rd_path.display(),
                    previous = %cfg.sockets_dir.display(),
                    "sockets_dir overridden by RUNTIME_DIRECTORY",
                );
                cfg.sockets_dir = rd_path;
            }
        }
        Ok(cfg)
    }

    /// Path of an FD-passing socket by short name (e.g. `"proc"` -> `/tmp/fdpass-proc.sock`)
    pub fn socket_path(&self, name: &str) -> PathBuf {
        self.sockets_dir.join(format!("fdpass-{name}.sock"))
    }

    /// Basename (filename only) for a socket. The `SocketsDialer` uses this with `connectat()`
    /// under FreeBSD Capsicum, where the global path namespace isn't reachable
    pub fn socket_basename(name: &str) -> String {
        format!("fdpass-{name}.sock")
    }

    pub fn processor_sock(&self) -> PathBuf {
        self.socket_path("proc")
    }
    pub fn scanner_sock(&self) -> PathBuf {
        self.socket_path("scanner")
    }
    pub fn admin_sock(&self) -> PathBuf {
        self.socket_path("admin")
    }
    pub fn drainer_sock(&self) -> PathBuf {
        self.socket_path("drainer")
    }
    pub fn spawner_sock(&self) -> PathBuf {
        self.socket_path("spawner")
    }
    pub fn control_sock(&self, role: &str) -> PathBuf {
        self.socket_path(&format!("ctrl-{role}"))
    }

    pub fn ready_timeout(&self) -> Duration {
        Duration::from_secs(self.ready_timeout_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(toml_text: &str) -> Result<Config> {
        Ok(toml::from_str(toml_text)?)
    }

    #[test]
    fn config_json_roundtrips_for_upgrade_handoff() {
        // The cap-mode upgrade handoff serializes the parsed Config to JSON (ENV_CONFIG_JSON) and
        // the successor deserializes it insead of rereading the file by path. A lossy round-trip
        // would silently feed the successor a different config, so pin fidelity here.
        let c = Config {
            sockets_dir: PathBuf::from("/run/fdpass"),
            plain_port: 18070,
            tls_port: 18071,
            ready_timeout_secs: 9,
            identd_port: 1113,
            security: SecurityConfig {
                drop_uid: Some("1001".into()),
                drop_gid: Some("1001".into()),
                sandbox: SandboxMode::Strict,
                sandbox_overrides: BTreeMap::from([("scanner".into(), SandboxMode::Off)]),
            },
            auth: AuthConfig {
                allowed_uids: vec![1001, 42],
            },
            tls: TlsConfig {
                cert_path: PathBuf::from("/etc/ssl/a.crt"),
                key_path: PathBuf::from("/etc/ssl/a.key"),
            },
            ..Config::default()
        };
        let json = serde_json::to_string(&c).expect("serialize");
        let back: Config = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.sockets_dir, c.sockets_dir);
        assert_eq!(back.plain_port, c.plain_port);
        assert_eq!(back.tls_port, c.tls_port);
        assert_eq!(back.ready_timeout_secs, c.ready_timeout_secs);
        assert_eq!(back.identd_port, c.identd_port);
        assert_eq!(back.security.drop_uid, c.security.drop_uid);
        assert_eq!(back.security.drop_gid, c.security.drop_gid);
        assert_eq!(back.security.sandbox, c.security.sandbox);
        assert_eq!(
            back.security.sandbox_overrides,
            c.security.sandbox_overrides
        );
        assert_eq!(back.auth.allowed_uids, c.auth.allowed_uids);
        assert_eq!(back.tls.cert_path, c.tls.cert_path);
        assert_eq!(back.tls.key_path, c.tls.key_path);
        assert_eq!(
            back.limits.max_in_flight_per_role,
            c.limits.max_in_flight_per_role
        );
        assert_eq!(back.limits.accept_rate_per_ip, c.limits.accept_rate_per_ip);
    }

    #[test]
    fn empty_toml_yields_defaults() {
        let c = parse("").unwrap();
        let d = Config::default();
        assert_eq!(c.plain_port, d.plain_port);
        assert_eq!(c.tls_port, d.tls_port);
        assert_eq!(c.sockets_dir, d.sockets_dir);
        assert_eq!(c.ready_timeout_secs, d.ready_timeout_secs);
        assert_eq!(
            c.limits.max_in_flight_per_role,
            d.limits.max_in_flight_per_role
        );
        assert_eq!(c.health.bind_addr, d.health.bind_addr);
        assert!(c.metrics.path.as_os_str().is_empty());
    }

    #[test]
    fn effective_sandbox_uses_override_then_global() {
        let sec = SecurityConfig {
            sandbox: SandboxMode::Strict,
            sandbox_overrides: BTreeMap::from([("scanner".into(), SandboxMode::Off)]),
            ..Default::default()
        };
        // Overridden role gets its override; everyone else gets the global.
        assert_eq!(sec.effective_sandbox("scanner"), SandboxMode::Off);
        assert_eq!(sec.effective_sandbox("processor"), SandboxMode::Strict);
        assert_eq!(sec.effective_sandbox("tls"), SandboxMode::Strict);
    }

    #[test]
    fn sandbox_overrides_parse_from_toml() {
        let c = parse(
            "[security]\nsandbox = \"strict\"\n\
             [security.sandbox_overrides]\nscanner = \"off\"\n",
        )
        .unwrap();
        assert_eq!(c.security.sandbox, SandboxMode::Strict);
        assert_eq!(c.security.effective_sandbox("scanner"), SandboxMode::Off);
        assert_eq!(c.security.effective_sandbox("plain"), SandboxMode::Strict);
    }

    #[test]
    fn partial_section_keeps_other_defaults() {
        // Overriding one field in [limits] must not zero out the others
        let c = parse("[limits]\naccept_rate_per_ip = 7\n").unwrap();
        assert_eq!(c.limits.accept_rate_per_ip, 7);
        assert_eq!(c.limits.max_in_flight_per_role, 1024);
        assert_eq!(c.limits.tls_idle_timeout_secs, 300);
        // And other sections stay at defaults too
        assert_eq!(c.plain_port, 7070);
    }

    #[test]
    fn auth_empty_list_means_current_user() {
        // The config layer just parses an empty Vec; the policy ("empty == current user") lives in
        // PeerAllowlist::from_config
        let c = parse("[auth]\nallowed_uids = []\n").unwrap();
        assert!(c.auth.allowed_uids.is_empty());
        let allow = crate::auth::PeerAllowlist::from_config(&c.auth.allowed_uids);
        assert!(allow.contains(nix::unistd::Uid::effective().as_raw()));
    }

    #[test]
    fn auth_explicit_list_is_used_verbatim() {
        let c = parse("[auth]\nallowed_uids = [42, 7]\n").unwrap();
        assert_eq!(c.auth.allowed_uids, vec![42, 7]);
    }

    #[test]
    fn invalid_toml_errors() {
        // Wrong type for a known field
        let r: Result<Config, _> = toml::from_str("plain_port = \"abc\"\n");
        assert!(r.is_err());
    }

    #[test]
    fn socket_path_helpers_use_sockets_dir() {
        let c = Config {
            sockets_dir: PathBuf::from("/var/run/fdpass"),
            ..Config::default()
        };
        assert_eq!(
            c.processor_sock(),
            PathBuf::from("/var/run/fdpass/fdpass-proc.sock")
        );
        assert_eq!(
            c.admin_sock(),
            PathBuf::from("/var/run/fdpass/fdpass-admin.sock")
        );
        assert_eq!(
            c.control_sock("tls"),
            PathBuf::from("/var/run/fdpass/fdpass-ctrl-tls.sock"),
        );
    }

    #[test]
    fn ready_timeout_converts_secs_to_duration() {
        let c = Config {
            ready_timeout_secs: 9,
            ..Config::default()
        };
        assert_eq!(c.ready_timeout(), Duration::from_secs(9));
    }
}
