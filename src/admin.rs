use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::{
    config::Config,
    control::{
        AdminResp, ControlMsg, HealthState, RoleHealth, UpgradePhase, WorkerStatus, envelope_line,
        parse_envelope,
    },
    handoff::now_unix_ms,
};

pub async fn run_upgrade(args: &[String], config: &Config) -> Result<()> {
    let mut binary_path: Option<PathBuf> = None;
    let mut include_tls = false;
    let mut canary_secs: Option<u64> = None;
    let mut only_role: Option<String> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--target" | "-t" => {
                let v = it.next().context("--target requires a path argument")?;
                binary_path = Some(PathBuf::from(v));
            }
            "--include-tls" => {
                include_tls = true;
            }
            "--canary" => {
                let v = it.next().context("--canary requires a seconds value")?;
                canary_secs = Some(
                    v.parse()
                        .context("--canary must be a non-negative integer")?,
                );
            }
            "--role" | "-r" => {
                let v = it.next().context("--role requires a worker name")?;
                only_role = Some(v.clone());
            }
            "--help" | "-h" => {
                eprintln!(
                    "echod upgrade [--target <path>] [--role <worker>] [--include-tls] [--canary <secs>]"
                );
                eprintln!();
                eprintln!("Rolling upgrade: processor → plain → scanner (→ tls if --include-tls).");
                eprintln!("--role <processor|plain|scanner|tls> upgrades just that one worker.");
                eprintln!("  Upgrading 'processor' alone is the common zero-downtime path: its");
                eprintln!("  in-flight sessions survive via UDS handoff and the thin acceptor is");
                eprintln!("  left running, so no live connection is reset.");
                eprintln!("--canary N waits N seconds after each role's upgrade and aborts");
                eprintln!("the rest of the walk if that role's watchdog state regresses below");
                eprintln!("'healthy' (any of backoff / flapping / failed).");
                return Ok(());
            }
            other => bail!("unknown argument: {other}"),
        }
    }

    let label = match &only_role {
        Some(role) => format!("({role})"),
        None if include_tls => "(processor, plain, tls)".to_string(),
        None => "(processor, plain)".to_string(),
    };
    let canary_note = match canary_secs {
        Some(s) => format!(", canary {s}s"),
        None => String::new(),
    };
    if let Some(p) = &binary_path {
        eprintln!("rolling upgrade {label} → {}{canary_note}", p.display());
    } else {
        eprintln!("rolling upgrade {label} → current_exe per worker{canary_note}");
    }
    stream_upgrade(
        &ControlMsg::Upgrade {
            binary_path: binary_path.clone(),
            include_tls,
            canary_secs,
            only_role,
        },
        config,
    )
    .await
}

async fn stream_upgrade(msg: &ControlMsg, config: &Config) -> Result<()> {
    let sock = config.admin_sock();
    let stream = tokio::net::UnixStream::connect(&sock)
        .await
        .with_context(|| format!("connect {}", sock.display()))?;
    let (read_half, mut write_half) = stream.into_split();

    let line = envelope_line(msg)?;
    write_half
        .write_all(line.as_bytes())
        .await
        .context("admin write")?;
    write_half.shutdown().await.ok();

    let mut reader = BufReader::new(read_half);
    let mut buf = String::new();
    let mut overall_ok = true;
    loop {
        buf.clear();
        let n = reader
            .read_line(&mut buf)
            .await
            .context("admin read progress")?;
        if n == 0 {
            bail!("supervisor closed connection without UpgradeComplete");
        }
        let trimmed = buf.trim();
        if trimmed.is_empty() {
            continue;
        }
        let resp: AdminResp = parse_envelope(trimmed)
            .with_context(|| format!("incompatible admin response: {trimmed}"))?;
        match resp {
            AdminResp::UpgradeStep {
                worker,
                phase,
                generation_before,
                generation_after,
                ok,
                message,
            } => {
                let mark = if ok { "✓" } else { "✗" };
                let phase_str = match phase {
                    UpgradePhase::Starting => "starting",
                    UpgradePhase::Done => "done",
                    UpgradePhase::Timeout => "timeout",
                    UpgradePhase::Skipped => "skipped",
                    UpgradePhase::CanaryAborted => "canary aborted",
                };
                let gen_part = match (generation_before, generation_after) {
                    (Some(a), Some(b)) => format!(" (gen {a} → {b})"),
                    (Some(a), None) => format!(" (gen {a})"),
                    _ => String::new(),
                };
                let msg_part = message
                    .as_deref()
                    .map(|m| format!(" — {m}"))
                    .unwrap_or_default();
                println!("{mark} {worker:<10} {phase_str}{gen_part}{msg_part}");
                if !ok {
                    overall_ok = false;
                }
            }
            AdminResp::UpgradeComplete { all_ok } => {
                if all_ok && overall_ok {
                    eprintln!("upgrade complete");
                    return Ok(());
                }
                bail!("upgrade failed");
            }
            AdminResp::Error { message } => bail!("admin error: {message}"),
            AdminResp::Ok | AdminResp::Status { .. } => {
                bail!("unexpected response during rolling upgrade: {trimmed}")
            }
        }
    }
}

pub async fn run_status(args: &[String], config: &Config) -> Result<()> {
    if let Some(a) = args.iter().next() {
        match a.as_str() {
            "--help" | "-h" => {
                eprintln!("echod status");
                eprintln!();
                eprintln!("Asks the supervisor for a status report across all four workers.");
                return Ok(());
            }
            other => bail!("unknown argument: {other}"),
        }
    }

    let resp = dial_and_request(&ControlMsg::Status, config).await?;
    match resp {
        AdminResp::Status { workers, health } => {
            print_status_table(&workers, &health);
            Ok(())
        }
        AdminResp::Error { message } => bail!("admin error: {message}"),
        AdminResp::Ok | AdminResp::UpgradeStep { .. } | AdminResp::UpgradeComplete { .. } => {
            bail!("unexpected response to Status")
        }
    }
}

pub async fn run_drain(args: &[String], config: &Config) -> Result<()> {
    if let Some(a) = args.iter().next() {
        match a.as_str() {
            "--help" | "-h" => {
                eprintln!("echod drain");
                eprintln!();
                eprintln!("Tells the supervisor to stop accepting new connections on the plain");
                eprintln!("and TLS acceptors. Existing sessions continue. The daemon stays up;");
                eprintln!("processor/scanner are unaffected. Send `shutdown` (or kill the");
                eprintln!("supervisor) when in-flight sessions have drained.");
                return Ok(());
            }
            other => bail!("unknown argument: {other}"),
        }
    }
    let resp = dial_and_request(&ControlMsg::Drain, config).await?;
    match resp {
        AdminResp::Ok => {
            println!("drained: acceptors stopped accepting; existing sessions continue");
            Ok(())
        }
        AdminResp::Error { message } => bail!("admin error: {message}"),
        _ => bail!("unexpected response to Drain"),
    }
}

pub async fn run_reload(args: &[String], config: &Config) -> Result<()> {
    if let Some(a) = args.iter().next() {
        match a.as_str() {
            "--help" | "-h" => {
                eprintln!("echod reload");
                eprintln!();
                eprintln!("Tells each worker to re-read its config from disk. Hot-reloaded:");
                eprintln!("  - auth.allowed_uids");
                eprintln!("  - tls.cert_path / tls.key_path (TLS acceptor)");
                eprintln!("Other fields (ports, sockets_dir, security) need a restart.");
                return Ok(());
            }
            other => bail!("unknown argument: {other}"),
        }
    }
    let resp = dial_and_request(&ControlMsg::Reload, config).await?;
    match resp {
        AdminResp::Ok => {
            println!("reload broadcast to all workers");
            Ok(())
        }
        AdminResp::Error { message } => bail!("admin error: {message}"),
        _ => bail!("unexpected response to Reload"),
    }
}

async fn dial_and_request(msg: &ControlMsg, config: &Config) -> Result<AdminResp> {
    let sock = config.admin_sock();
    let stream = tokio::net::UnixStream::connect(&sock)
        .await
        .with_context(|| format!("connect {}", sock.display()))?;
    let (read_half, mut write_half) = stream.into_split();

    let line = envelope_line(msg)?;
    write_half
        .write_all(line.as_bytes())
        .await
        .context("admin write")?;
    write_half.shutdown().await.ok();

    let mut reader = BufReader::new(read_half);
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .await
        .context("admin read response")?;
    let response = response.trim();
    if response.is_empty() {
        bail!("supervisor closed connection without response");
    }
    let resp: AdminResp = parse_envelope(response)
        .with_context(|| format!("incompatible admin response: {response}"))?;
    Ok(resp)
}

fn print_status_table(workers: &[WorkerStatus], health: &[RoleHealth]) {
    println!(
        "{:<10} {:<10} {:<7} {:<4} {:<8} {:<9} {:<8} {:<10} LISTENER",
        "ROLE", "STATE", "PID", "GEN", "UPTIME", "RESTARTS", "BACKOFF", "IN_FLIGHT",
    );
    if workers.is_empty() && health.is_empty() {
        println!("(no workers connected)");
        return;
    }
    let now = now_unix_ms();
    let roles = ["processor", "plain", "tls", "scanner"];
    for role in roles {
        let w = workers.iter().find(|w| w.role == role);
        let h = health.iter().find(|h| h.role == role);
        let state = h.map_or_else(|| "-".into(), |h| format_state(h.state));
        let pid = w.map_or_else(|| "-".into(), |w| w.pid.to_string());
        let generation = w.map_or_else(|| "-".into(), |w| w.generation.to_string());
        let uptime = w.map_or_else(
            || "-".into(),
            |w| format_uptime(now.saturating_sub(w.started_at_unix_ms) / 1000),
        );
        let restarts = h.map_or_else(|| "-".into(), |h| h.total_restarts.to_string());
        let backoff = h.map_or_else(|| "-".into(), |h| format_backoff(h.next_backoff_ms));
        let in_flight = w.map_or_else(|| "-".into(), |w| w.in_flight.to_string());
        let listener = w.and_then(|w| w.listener_addr.as_deref()).unwrap_or("-");
        println!(
            "{role:<10} {state:<10} {pid:<7} {generation:<4} {uptime:<8} {restarts:<9} {backoff:<8} {in_flight:<10} {listener}",
        );
    }
}

fn format_state(s: HealthState) -> String {
    match s {
        HealthState::Healthy => "healthy".into(),
        HealthState::Backoff => "backoff".into(),
        HealthState::Flapping => "flapping".into(),
        HealthState::Failed => "FAILED".into(),
    }
}

fn format_backoff(ms: u64) -> String {
    if ms < 1000 {
        format!("{ms}ms")
    } else {
        format!("{}.{:01}s", ms / 1000, (ms % 1000) / 100)
    }
}

fn format_uptime(s: u64) -> String {
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m{:02}s", s / 60, s % 60)
    } else {
        format!("{}h{:02}m", s / 3600, (s % 3600) / 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    // Unit tests for the admin CLI client. The "response dispatch" tests stand up a one-shot mock
    // supervisor on a real UDS at `config.admin_sock()`, so run_* exercise their full request →
    // response → match arms without a live daemon.

    fn tmp_config(tag: &str) -> Config {
        static CTR: AtomicU32 = AtomicU32::new(0);
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        // Keep the dir short: macOS caps UDS paths at ~104 bytes, and admin_sock() appends
        // "fdpass-admin.sock". /tmp is where the daemon's sockets live by default anyway.
        let dir = PathBuf::from("/tmp")
            .join(format!("fdpass-admintest-{}-{tag}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Config {
            sockets_dir: dir,
            ..Default::default()
        }
    }

    fn cleanup(config: &Config) {
        let _ = std::fs::remove_dir_all(&config.sockets_dir);
    }

    /// Bind a one-shot mock admin socket, then in the background accept one connection, read the
    /// single request line, and write each response line back. `lines` are written verbatim (each
    /// gets a trailing newline) so callers can inject malformed frames too.
    fn mock_admin_lines(config: &Config, lines: Vec<String>) -> tokio::task::JoinHandle<()> {
        let sock = config.admin_sock();
        let _ = std::fs::remove_file(&sock);
        let listener = tokio::net::UnixListener::bind(&sock).unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read_half, mut write_half) = stream.into_split();
            let mut reader = BufReader::new(read_half);
            let mut req = String::new();
            let _ = reader.read_line(&mut req).await;
            for mut line in lines {
                line.push('\n');
                write_half.write_all(line.as_bytes()).await.unwrap();
            }
            let _ = write_half.shutdown().await;
        })
    }

    /// Same as `mock_admin_lines` but takes typed `AdminResp`s and serializes them as the daemon
    /// would (versioned envelope, one per line).
    fn mock_admin(config: &Config, responses: Vec<AdminResp>) -> tokio::task::JoinHandle<()> {
        let lines = responses
            .into_iter()
            .map(|r| {
                envelope_line(&r)
                    .unwrap()
                    .trim_end_matches('\n')
                    .to_string()
            })
            .collect();
        mock_admin_lines(config, lines)
    }

    // ----- argument parsing / usage (no server needed) -----

    #[tokio::test]
    async fn upgrade_help_returns_ok() {
        let config = tmp_config("up-help");
        run_upgrade(&["--help".into()], &config).await.unwrap();
        run_upgrade(&["-h".into()], &config).await.unwrap();
        cleanup(&config);
    }

    #[tokio::test]
    async fn upgrade_unknown_arg_errors() {
        let config = tmp_config("up-bad");
        let err = run_upgrade(&["--bogus".into()], &config).await.unwrap_err();
        assert!(err.to_string().contains("unknown argument"), "{err}");
        cleanup(&config);
    }

    #[tokio::test]
    async fn upgrade_missing_values_error_before_dial() {
        let config = tmp_config("up-missing");
        // Each flag consumes the next token; with none present these fail during parse, before any
        // connection attempt.
        for flag in ["--target", "--canary", "--role"] {
            let err = run_upgrade(&[flag.into()], &config).await.unwrap_err();
            assert!(err.to_string().contains("requires"), "{flag}: {err}");
        }
        // Non-numeric canary value fails the parse().
        let err = run_upgrade(&["--canary".into(), "soon".into()], &config)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("non-negative integer"), "{err}");
        cleanup(&config);
    }

    #[tokio::test]
    async fn status_drain_reload_help_and_unknown_arg() {
        let config = tmp_config("subcmd-args");
        run_status(&["--help".into()], &config).await.unwrap();
        run_drain(&["-h".into()], &config).await.unwrap();
        run_reload(&["--help".into()], &config).await.unwrap();
        for run in ["status", "drain", "reload"] {
            let err = match run {
                "status" => run_status(&["--nope".into()], &config).await,
                "drain" => run_drain(&["--nope".into()], &config).await,
                _ => run_reload(&["--nope".into()], &config).await,
            }
            .unwrap_err();
            assert!(err.to_string().contains("unknown argument"), "{run}: {err}");
        }
        cleanup(&config);
    }

    // ----- pure formatting helpers -----

    #[test]
    fn format_helpers_cover_all_branches() {
        assert_eq!(format_state(HealthState::Healthy), "healthy");
        assert_eq!(format_state(HealthState::Backoff), "backoff");
        assert_eq!(format_state(HealthState::Flapping), "flapping");
        assert_eq!(format_state(HealthState::Failed), "FAILED");

        assert_eq!(format_backoff(500), "500ms");
        assert_eq!(format_backoff(1500), "1.5s");

        assert_eq!(format_uptime(5), "5s");
        assert_eq!(format_uptime(65), "1m05s");
        assert_eq!(format_uptime(3700), "1h01m");
    }

    #[test]
    fn print_status_table_empty_and_populated() {
        // Empty: prints the "(no workers connected)" line and returns.
        print_status_table(&[], &[]);

        // Populated with an intentional role mismatch: "plain" has a worker but no health row
        // (h=None arms), "scanner" has health but no worker (w=None arms), and processor/tls have
        // neither.
        let workers = vec![WorkerStatus {
            role: "plain".into(),
            pid: 11,
            generation: 1,
            started_at_unix_ms: now_unix_ms().saturating_sub(65_000),
            in_flight: 3,
            listener_addr: Some("127.0.0.1:7070".into()),
            rate_limiter_stats: None,
        }];
        let health = vec![RoleHealth {
            role: "scanner".into(),
            state: HealthState::Flapping,
            consecutive_fast_exits: 1,
            next_backoff_ms: 1500,
            total_restarts: 9,
            last_restart_at_unix_ms: None,
        }];
        print_status_table(&workers, &health);
    }

    // ----- response dispatch (mock server) -----

    #[tokio::test]
    async fn run_status_prints_table_on_status_response() {
        let config = tmp_config("st-ok");
        let workers = vec![WorkerStatus {
            role: "plain".into(),
            pid: 42,
            generation: 1,
            started_at_unix_ms: now_unix_ms().saturating_sub(3_700_000),
            in_flight: 0,
            listener_addr: Some("127.0.0.1:7070".into()),
            rate_limiter_stats: None,
        }];
        let health = vec![RoleHealth {
            role: "plain".into(),
            state: HealthState::Healthy,
            consecutive_fast_exits: 0,
            next_backoff_ms: 0,
            total_restarts: 0,
            last_restart_at_unix_ms: None,
        }];
        let srv = mock_admin(&config, vec![AdminResp::Status { workers, health }]);
        run_status(&[], &config).await.unwrap();
        srv.await.unwrap();
        cleanup(&config);
    }

    #[tokio::test]
    async fn run_status_error_and_unexpected_responses() {
        let config = tmp_config("st-err");
        let srv = mock_admin(
            &config,
            vec![AdminResp::Error {
                message: "boom".into(),
            }],
        );
        let err = run_status(&[], &config).await.unwrap_err();
        assert!(err.to_string().contains("admin error"), "{err}");
        srv.await.unwrap();

        let srv = mock_admin(&config, vec![AdminResp::Ok]);
        let err = run_status(&[], &config).await.unwrap_err();
        assert!(err.to_string().contains("unexpected response"), "{err}");
        srv.await.unwrap();
        cleanup(&config);
    }

    #[tokio::test]
    async fn dial_and_request_closed_and_malformed() {
        let config = tmp_config("dial-err");
        // Closed with no response line.
        let srv = mock_admin_lines(&config, vec![]);
        let err = run_status(&[], &config).await.unwrap_err();
        assert!(err.to_string().contains("closed connection"), "{err}");
        srv.await.unwrap();

        // Non-JSON line -> parse failure.
        let srv = mock_admin_lines(&config, vec!["not json".into()]);
        let err = run_status(&[], &config).await.unwrap_err();
        assert!(err.to_string().contains("admin response"), "{err}");
        srv.await.unwrap();
        cleanup(&config);
    }

    #[tokio::test]
    async fn run_drain_all_arms() {
        let config = tmp_config("drain");
        let srv = mock_admin(&config, vec![AdminResp::Ok]);
        run_drain(&[], &config).await.unwrap();
        srv.await.unwrap();

        let srv = mock_admin(
            &config,
            vec![AdminResp::Error {
                message: "no".into(),
            }],
        );
        assert!(
            run_drain(&[], &config)
                .await
                .unwrap_err()
                .to_string()
                .contains("admin error")
        );
        srv.await.unwrap();

        let srv = mock_admin(
            &config,
            vec![AdminResp::Status {
                workers: vec![],
                health: vec![],
            }],
        );
        assert!(
            run_drain(&[], &config)
                .await
                .unwrap_err()
                .to_string()
                .contains("unexpected response")
        );
        srv.await.unwrap();
        cleanup(&config);
    }

    #[tokio::test]
    async fn run_reload_all_arms() {
        let config = tmp_config("reload");
        let srv = mock_admin(&config, vec![AdminResp::Ok]);
        run_reload(&[], &config).await.unwrap();
        srv.await.unwrap();

        let srv = mock_admin(
            &config,
            vec![AdminResp::Error {
                message: "no".into(),
            }],
        );
        assert!(
            run_reload(&[], &config)
                .await
                .unwrap_err()
                .to_string()
                .contains("admin error")
        );
        srv.await.unwrap();

        let srv = mock_admin(&config, vec![AdminResp::UpgradeComplete { all_ok: true }]);
        assert!(
            run_reload(&[], &config)
                .await
                .unwrap_err()
                .to_string()
                .contains("unexpected response")
        );
        srv.await.unwrap();
        cleanup(&config);
    }

    #[tokio::test]
    async fn run_upgrade_streams_all_phases_to_completion() {
        let config = tmp_config("up-ok");
        // One step per phase, each ok, with varied generation fields to hit every gen_part arm.
        let step = |phase, gb, ga| AdminResp::UpgradeStep {
            worker: "plain".into(),
            phase,
            generation_before: gb,
            generation_after: ga,
            ok: true,
            message: Some("moved".into()),
        };
        let srv = mock_admin(
            &config,
            vec![
                step(UpgradePhase::Starting, None, None),
                step(UpgradePhase::Done, Some(1), Some(2)),
                step(UpgradePhase::Timeout, Some(3), None),
                step(UpgradePhase::Skipped, None, None),
                step(UpgradePhase::CanaryAborted, None, None),
                AdminResp::UpgradeComplete { all_ok: true },
            ],
        );
        run_upgrade(&[], &config).await.unwrap();
        srv.await.unwrap();
        cleanup(&config);
    }

    #[tokio::test]
    async fn run_upgrade_failure_and_error_and_unexpected() {
        let config = tmp_config("up-fail");
        // A failed step then all_ok=false -> "upgrade failed".
        let srv = mock_admin(
            &config,
            vec![
                AdminResp::UpgradeStep {
                    worker: "tls".into(),
                    phase: UpgradePhase::Timeout,
                    generation_before: Some(1),
                    generation_after: None,
                    ok: false,
                    message: None,
                },
                AdminResp::UpgradeComplete { all_ok: false },
            ],
        );
        assert!(
            run_upgrade(&[], &config)
                .await
                .unwrap_err()
                .to_string()
                .contains("upgrade failed")
        );
        srv.await.unwrap();

        // Error frame mid-stream.
        let srv = mock_admin(
            &config,
            vec![AdminResp::Error {
                message: "nope".into(),
            }],
        );
        assert!(
            run_upgrade(&[], &config)
                .await
                .unwrap_err()
                .to_string()
                .contains("admin error")
        );
        srv.await.unwrap();

        // Unexpected frame type during the walk.
        let srv = mock_admin(&config, vec![AdminResp::Ok]);
        assert!(
            run_upgrade(&[], &config)
                .await
                .unwrap_err()
                .to_string()
                .contains("unexpected response during rolling upgrade")
        );
        srv.await.unwrap();

        // Stream ends before a terminal UpgradeComplete.
        let srv = mock_admin(
            &config,
            vec![AdminResp::UpgradeStep {
                worker: "plain".into(),
                phase: UpgradePhase::Starting,
                generation_before: None,
                generation_after: None,
                ok: true,
                message: None,
            }],
        );
        assert!(
            run_upgrade(&[], &config)
                .await
                .unwrap_err()
                .to_string()
                .contains("without UpgradeComplete")
        );
        srv.await.unwrap();
        cleanup(&config);
    }
}
