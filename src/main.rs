mod acceptor;
mod admin;
mod auth;
mod config;
mod control;
mod coverage;
#[macro_use]
mod fault_inject;
mod grandparent;
mod handoff;
mod health;
mod limits;
mod metrics;
mod processor;
mod scanner;
mod security;
mod supervisor;
mod systemd;
#[cfg(test)]
mod test_env;
mod worker_common;

// Exactly one TLS crypto backend must be selected via crate features (see Cargo.toml). `ring` is
// the default; `aws-lc-rs` is opt-in. These guards turn a misconfiguration into a clear message
// instead of a confusing "unresolved import `crypto_backend`" downstream.
#[cfg(all(feature = "ring", feature = "aws-lc-rs"))]
compile_error!(
    "features `ring` and `aws-lc-rs` are mutually exclusive; enable exactly one TLS crypto backend"
);
#[cfg(not(any(feature = "ring", feature = "aws-lc-rs")))]
compile_error!(
    "no TLS crypto backend selected; enable feature `ring` (default) or `aws-lc-rs` \
     (e.g. `--no-default-features --features aws-lc-rs`)"
);

use std::env;
use std::io;
use std::path::PathBuf;
use std::process;

use anyhow::{Result, bail};
use tracing_subscriber::EnvFilter;

use crate::config::Config;

fn init_tracing(role: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    // `FDPASS_LOG_FORMAT=json` switches the subscriber to JSON-per-line output (ready for shipping
    // to a log aggregator). Default stays human-readable text so the portability suite's grep
    // patterns work unchanged.
    let json = env::var("FDPASS_LOG_FORMAT").is_ok_and(|v| v == "json");
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_thread_ids(false)
        .with_writer(io::stderr)
        .with_ansi(false);
    let _ = if json {
        builder.json().try_init()
    } else {
        builder.try_init()
    };
    tracing::info!(role, pid = process::id(), "starting");
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let (role, config_path, rest) = parse_cli_args(&args[1..])?;
    if matches!(role.as_str(), "help" | "--help" | "-h") {
        print_help();
        return Ok(());
    }
    init_tracing(&role);

    // If the user passed --config explicitly, advertise it via env so every spawned child and
    // upgrade exec reloads the same file without having to rethread the CLI flag through
    if let Some(p) = &config_path {
        // SAFETY: we're in main(), single-threaded; no other reader of env.
        unsafe { env::set_var(config::ENV_CONFIG_PATH, p) };
    }
    let config = Config::load(config_path)?;
    fault_inject::init(&config.fault_inject.points);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    rt.block_on(async move {
        match role.as_str() {
            "grandparent" => grandparent::run().await,
            "supervisor" => supervisor::run(config).await,
            "processor" => processor::run(config).await,
            "plain" => acceptor::run(acceptor::Role::Plain, config).await,
            "tls" => acceptor::run(acceptor::Role::Tls, config).await,
            "scanner" => scanner::run(config).await,
            "upgrade" => admin::run_upgrade(&rest, &config).await,
            "status" => admin::run_status(&rest, &config).await,
            "drain" => admin::run_drain(&rest, &config).await,
            "reload" => admin::run_reload(&rest, &config).await,
            _ => unreachable!(),
        }
    })
}

fn parse_cli_args(args: &[String]) -> Result<(String, Option<PathBuf>, Vec<String>)> {
    let (config_path, args) = extract_config_flag(args);
    let sub = args.first().map_or("supervisor", String::as_str);

    let role = match sub {
        "grandparent" | "supervisor" | "processor" | "plain" | "tls" | "scanner" | "upgrade"
        | "status" | "drain" | "reload" | "help" | "--help" | "-h" => sub.to_string(),
        other => {
            print_help();
            bail!("unknown subcommand: {other}");
        }
    };
    let rest = args.get(1..).map_or_else(Vec::new, ToOwned::to_owned);
    Ok((role, config_path, rest))
}

/// Parse a leading `--config <path>` from a role's args. Returns the parsed path (if any) and the
/// rest of the args untouched
fn extract_config_flag(args: &[String]) -> (Option<PathBuf>, Vec<String>) {
    let mut path = None;
    let mut rest = Vec::with_capacity(args.len());
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--config" && i + 1 < args.len() {
            path = Some(PathBuf::from(&args[i + 1]));
            i += 2;
        } else {
            rest.push(args[i].clone());
            i += 1;
        }
    }
    (path, rest)
}

fn print_help() {
    eprintln!(
        "echod <grandparent|supervisor|processor|plain|tls|scanner|upgrade|status|drain|reload>"
    );
    eprintln!();
    eprintln!("  grandparent  respawn the supervisor on crash (thin systemd alternative)");
    eprintln!("  supervisor   spawn and supervise all workers (default)");
    eprintln!("  processor    UDS line-echo worker");
    eprintln!("  plain        plaintext TCP acceptor");
    eprintln!("  tls          TLS acceptor (rustls)");
    eprintln!("  scanner      outbound auxiliary lookups (identd)");
    eprintln!("  upgrade      admin client: ask supervisor to upgrade workers");
    eprintln!(
        "               flags: --target <path>, --role <worker>, --include-tls, --canary <secs>"
    );
    eprintln!("  status       admin client: print per-worker generation/pid/uptime/in-flight");
    eprintln!(
        "  drain        admin client: stop accepting new connections; keep existing sessions"
    );
    eprintln!("  reload       admin client: re-read config; refresh auth allowlist + TLS cert");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(args: &[&str]) -> Vec<String> {
        args.iter().map(|a| (*a).to_string()).collect()
    }

    #[test]
    fn no_flag_returns_none_and_original_args() {
        let (p, rest) = extract_config_flag(&s(&["--target", "/path", "--include-tls"]));
        assert!(p.is_none());
        assert_eq!(rest, s(&["--target", "/path", "--include-tls"]));
    }

    #[test]
    fn leading_config_flag_extracted() {
        let (p, rest) = extract_config_flag(&s(&["--config", "/etc/fdpass.toml", "--target", "x"]));
        assert_eq!(p, Some(PathBuf::from("/etc/fdpass.toml")));
        assert_eq!(rest, s(&["--target", "x"]));
    }

    #[test]
    fn mid_args_config_flag_extracted() {
        let (p, rest) = extract_config_flag(&s(&["--target", "x", "--config", "c.toml"]));
        assert_eq!(p, Some(PathBuf::from("c.toml")));
        assert_eq!(rest, s(&["--target", "x"]));
    }

    #[test]
    fn dangling_config_flag_is_left_alone() {
        let (p, rest) = extract_config_flag(&s(&["--target", "x", "--config"]));
        assert!(p.is_none());
        assert_eq!(rest, s(&["--target", "x", "--config"]));
    }

    #[test]
    fn empty_args_returns_empty() {
        let (p, rest) = extract_config_flag(&[]);
        assert!(p.is_none());
        assert!(rest.is_empty());
    }

    #[test]
    fn global_config_before_subcommand_is_accepted() {
        let (role, p, rest) =
            parse_cli_args(&s(&["--config", "/etc/fdpass.toml", "status"])).unwrap();
        assert_eq!(role, "status");
        assert_eq!(p, Some(PathBuf::from("/etc/fdpass.toml")));
        assert!(rest.is_empty());
    }

    #[test]
    fn config_only_defaults_to_supervisor() {
        let (role, p, rest) = parse_cli_args(&s(&["--config", "c.toml"])).unwrap();
        assert_eq!(role, "supervisor");
        assert_eq!(p, Some(PathBuf::from("c.toml")));
        assert!(rest.is_empty());
    }

    #[test]
    fn role_args_preserve_non_config_flags() {
        let (role, p, rest) =
            parse_cli_args(&s(&["upgrade", "--target", "bin", "--config", "c.toml"])).unwrap();
        assert_eq!(role, "upgrade");
        assert_eq!(p, Some(PathBuf::from("c.toml")));
        assert_eq!(rest, s(&["--target", "bin"]));
    }

    #[test]
    fn unknown_subcommand_errors() {
        let err = parse_cli_args(&s(&["bogus"])).unwrap_err();
        assert!(err.to_string().contains("unknown subcommand"));
    }
}
