//! `echobench` — connection-rate and throughput load generator for `echod`.
//!
//! Not part of the shipped `echod` binary; build/run on demand:
//! ```text
//! cargo run --release --example echobench -- --tls --mode throughput \
//!     --connections 200 --duration 10 --message-size 256
//! ```
//!
//! The server is a line-delimited echo (see `src/processor.rs`): a message is
//! payload bytes terminated by `\n`, echoed back verbatim. This tool opens many
//! concurrent connections and measures either how fast new connections / TLS
//! handshakes complete (`--mode conn`) or sustained message/byte throughput over
//! persistent connections (`--mode throughput`), plus round-trip latency.
//!
//! Loopback is NOT exempt from the server's per-IP accept rate limiter, so point
//! this at a server started with `accept_rate_per_ip = 0` (see `scripts/bench.sh`)
//! or you'll be measuring the throttle, not the server.

use std::array;
use std::io::BufReader;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use futures::{SinkExt, StreamExt};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_util::codec::{Framed, LinesCodec};

// TLS crypto backend, selected by the `ring` / `aws-lc-rs` crate features — mirrors
// src/acceptor/tls_cert.rs so the benchmark client uses the same provider as the server.
#[cfg(feature = "aws-lc-rs")]
use rustls::crypto::aws_lc_rs as crypto_backend;
#[cfg(feature = "ring")]
use rustls::crypto::ring as crypto_backend;

/// Matches the server's `LinesCodec::new_with_max_length(64 * 1024)` in `src/processor.rs`.
const MAX_LINE: usize = 64 * 1024;
/// Power-of-two nanosecond buckets: bucket `i` covers `[2^i, 2^(i+1))` ns, up to ~584 years.
const HIST_BUCKETS: usize = 64;

/// Any TCP or TLS stream, type-erased so the plain and TLS paths share one code path.
trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncReadWrite for T {}
type BoxedStream = Pin<Box<dyn AsyncReadWrite + Send>>;
type Conn = Framed<BoxedStream, LinesCodec>;

#[derive(Clone, Copy)]
enum Mode {
    Conn,
    Throughput,
}

struct Args {
    host: String,
    port: u16,
    tls: bool,
    mode: Mode,
    connections: usize,
    duration: u64,
    warmup: u64,
    message_size: usize,
    pipeline: usize,
    ca: Option<String>,
    server_name: String,
    json: bool,
}

fn usage() -> &'static str {
    "echobench — load generator for echod\n\
     \n\
     Transport:  --plain (default) | --tls   --host <ip> (127.0.0.1)   --port <n> (7070/7071)\n\
     Load:       --mode conn|throughput (throughput)   --connections <n> (50)\n\
                 --duration <secs> (10)   --warmup <secs> (0)\n\
                 --message-size <bytes> (128)   --pipeline <n> (1, throughput only)\n\
     TLS:        --server-name <name> (localhost)   --ca <path> (verify vs this root;\n\
                 default: skip verification, matching the generated self-signed cert)\n\
     Output:     --json"
}

fn take<'a>(argv: &'a [String], i: &mut usize, flag: &str) -> Result<&'a str> {
    *i += 1;
    argv.get(*i)
        .map(String::as_str)
        .ok_or_else(|| anyhow!("{flag} requires a value"))
}

fn parse_args() -> Result<Args> {
    let mut host = "127.0.0.1".to_string();
    let mut port: Option<u16> = None;
    let mut tls = false;
    let mut mode = Mode::Throughput;
    let mut connections = 50usize;
    let mut duration = 10u64;
    let mut warmup = 0u64;
    let mut message_size = 128usize;
    let mut pipeline = 1usize;
    let mut ca: Option<String> = None;
    let mut server_name = "localhost".to_string();
    let mut json = false;

    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < argv.len() {
        let flag = argv[i].clone();
        match flag.as_str() {
            "--tls" => tls = true,
            "--plain" => tls = false,
            "--json" => json = true,
            "--host" => host = take(&argv, &mut i, &flag)?.to_string(),
            "--port" => port = Some(take(&argv, &mut i, &flag)?.parse().context("--port")?),
            "--mode" => {
                mode = match take(&argv, &mut i, &flag)? {
                    "conn" => Mode::Conn,
                    "throughput" => Mode::Throughput,
                    other => bail!("--mode must be conn|throughput, got {other}"),
                };
            }
            "--connections" => {
                connections = take(&argv, &mut i, &flag)?
                    .parse()
                    .context("--connections")?;
            }
            "--duration" => duration = take(&argv, &mut i, &flag)?.parse().context("--duration")?,
            "--warmup" => warmup = take(&argv, &mut i, &flag)?.parse().context("--warmup")?,
            "--message-size" => {
                message_size = take(&argv, &mut i, &flag)?
                    .parse()
                    .context("--message-size")?;
            }
            "--pipeline" => pipeline = take(&argv, &mut i, &flag)?.parse().context("--pipeline")?,
            "--ca" => ca = Some(take(&argv, &mut i, &flag)?.to_string()),
            "--server-name" => server_name = take(&argv, &mut i, &flag)?.to_string(),
            "--help" | "-h" => {
                println!("{}", usage());
                std::process::exit(0);
            }
            other => bail!("unknown flag: {other}\n\n{}", usage()),
        }
        i += 1;
    }

    if connections == 0 {
        bail!("--connections must be > 0");
    }
    if duration == 0 {
        bail!("--duration must be > 0");
    }
    if message_size == 0 || message_size >= MAX_LINE {
        bail!("--message-size must be in 1..{MAX_LINE}");
    }
    if pipeline == 0 {
        bail!("--pipeline must be > 0");
    }
    let port = port.unwrap_or(if tls { 7071 } else { 7070 });
    Ok(Args {
        host,
        port,
        tls,
        mode,
        connections,
        duration,
        warmup,
        message_size,
        pipeline,
        ca,
        server_name,
        json,
    })
}

/// A `ServerCertVerifier` that trusts anything — used only under `--insecure`.
#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        crypto_backend::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

struct TlsCfg {
    connector: TlsConnector,
    domain: ServerName<'static>,
}

fn build_tls(args: &Args) -> Result<TlsCfg> {
    // Install the selected crypto provider, mirroring the server (src/acceptor/tls_cert.rs).
    let _ = crypto_backend::default_provider().install_default();

    // Verification is opt-in via --ca. By default we skip it: the generated server
    // cert (certs/gen.sh) is its own self-signed CA, which webpki rejects as an
    // end-entity (CaUsedAsEndEntity) — the same reason the e2e suite uses ssl.CERT_NONE.
    let config = if let Some(ca) = &args.ca {
        let mut roots = rustls::RootCertStore::empty();
        let file = std::fs::File::open(ca).with_context(|| format!("open CA {ca}"))?;
        let mut reader = BufReader::new(file);
        for cert in CertificateDer::pem_reader_iter(&mut reader) {
            roots
                .add(cert.context("parse CA cert")?)
                .context("add CA cert to root store")?;
        }
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    } else {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth()
    };

    let connector = TlsConnector::from(Arc::new(config));
    let domain = ServerName::try_from(args.server_name.clone())
        .with_context(|| format!("invalid --server-name {}", args.server_name))?;
    Ok(TlsCfg { connector, domain })
}

struct ConnCfg {
    host: String,
    port: u16,
    tls: Option<TlsCfg>,
}

async fn dial(cfg: &ConnCfg, rst_close: bool) -> Result<Conn> {
    let tcp = TcpStream::connect((cfg.host.as_str(), cfg.port))
        .await
        .context("tcp connect")?;
    tcp.set_nodelay(true).context("set_nodelay")?;
    if rst_close {
        // Close with RST (SO_LINGER=0) instead of FIN so neither side enters
        // TIME_WAIT — otherwise a high-rate connection benchmark exhausts the
        // loopback ephemeral-port range within seconds. Set via nix rather than
        // tokio's deprecated TcpStream::set_linger (deprecated because a
        // *non-zero* linger blocks on drop; a zero linger sends RST at once).
        let linger = nix::libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        nix::sys::socket::setsockopt(&tcp, nix::sys::socket::sockopt::Linger, &linger)
            .context("set SO_LINGER")?;
    }
    let stream: BoxedStream = if let Some(tls) = &cfg.tls {
        Box::pin(
            tls.connector
                .connect(tls.domain.clone(), tcp)
                .await
                .context("tls handshake")?,
        )
    } else {
        Box::pin(tcp)
    };
    Ok(Framed::new(
        stream,
        LinesCodec::new_with_max_length(MAX_LINE),
    ))
}

/// One line round-trip: send `payload`, expect it echoed back verbatim.
async fn ping(framed: &mut Conn, payload: &str) -> Result<()> {
    framed.send(payload).await.context("send")?;
    match framed.next().await {
        Some(Ok(line)) if line.len() == payload.len() => Ok(()),
        Some(Ok(_)) => bail!("echo length mismatch"),
        Some(Err(e)) => Err(anyhow!("decode: {e}")),
        None => bail!("connection closed before echo"),
    }
}

/// Lock-free approximate latency histogram over power-of-two nanosecond buckets.
struct Histogram {
    buckets: [AtomicU64; HIST_BUCKETS],
    max_ns: AtomicU64,
}

impl Histogram {
    fn new() -> Self {
        Self {
            buckets: array::from_fn(|_| AtomicU64::new(0)),
            max_ns: AtomicU64::new(0),
        }
    }

    fn record(&self, dur: Duration) {
        #[allow(
            clippy::cast_possible_truncation,
            reason = "durations in a benchmark run fit in u64 ns; saturating at u64::MAX is harmless"
        )]
        let ns = dur.as_nanos().min(u128::from(u64::MAX)) as u64;
        let idx = if ns == 0 { 0 } else { ns.ilog2() as usize };
        self.buckets[idx.min(HIST_BUCKETS - 1)].fetch_add(1, Ordering::Relaxed);
        self.max_ns.fetch_max(ns, Ordering::Relaxed);
    }

    fn total(&self) -> u64 {
        self.buckets.iter().map(|b| b.load(Ordering::Relaxed)).sum()
    }

    /// Upper bound (ns) of the bucket containing the `p` quantile. Resolution is ~2×.
    fn percentile(&self, p: f64) -> u64 {
        let total = self.total();
        if total == 0 {
            return 0;
        }
        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_sign_loss,
            clippy::cast_possible_truncation,
            reason = "sample counts stay well within f64 exact-integer range and p is in [0,1]"
        )]
        let target = (total as f64 * p).ceil() as u64;
        let mut cum = 0u64;
        for (idx, bucket) in self.buckets.iter().enumerate() {
            cum += bucket.load(Ordering::Relaxed);
            if cum >= target {
                return 1u64 << (idx + 1).min(63);
            }
        }
        self.max_ns.load(Ordering::Relaxed)
    }

    fn max(&self) -> u64 {
        self.max_ns.load(Ordering::Relaxed)
    }
}

struct Shared {
    recording: AtomicBool,
    connections: AtomicU64,
    messages: AtomicU64,
    bytes: AtomicU64,
    errors: AtomicU64,
    hist: Histogram,
}

impl Shared {
    fn new() -> Self {
        Self {
            recording: AtomicBool::new(false),
            connections: AtomicU64::new(0),
            messages: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            hist: Histogram::new(),
        }
    }

    fn recording(&self) -> bool {
        self.recording.load(Ordering::Relaxed)
    }

    fn note_error(&self) {
        if self.recording() {
            self.errors.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn as_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// Print connection/handshake errors to stderr when `ECHOBENCH_DEBUG` is set.
fn debug_err(what: &str, err: &anyhow::Error) {
    if std::env::var_os("ECHOBENCH_DEBUG").is_some() {
        eprintln!("{what}: {err:#}");
    }
}

/// `conn` mode: connect → one-line liveness ping → close, forever; time the setup.
async fn conn_worker(cfg: Arc<ConnCfg>, shared: Arc<Shared>, payload: Arc<str>, deadline: Instant) {
    while Instant::now() < deadline {
        let t0 = Instant::now();
        match dial(&cfg, true).await {
            Ok(mut framed) => {
                let setup = t0.elapsed();
                let alive = ping(&mut framed, &payload).await.is_ok();
                if shared.recording() {
                    if alive {
                        shared.connections.fetch_add(1, Ordering::Relaxed);
                        shared.hist.record(setup);
                    } else {
                        shared.errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
                // framed dropped here → connection closed.
            }
            Err(e) => {
                debug_err("dial", &e);
                shared.note_error();
            }
        }
    }
}

/// `throughput` mode: hold one connection, keep `pipeline` messages outstanding, time each RTT.
async fn throughput_worker(
    cfg: Arc<ConnCfg>,
    shared: Arc<Shared>,
    payload: Arc<str>,
    pipeline: usize,
    deadline: Instant,
) {
    let mut framed = match dial(&cfg, false).await {
        Ok(f) => f,
        Err(e) => {
            debug_err("dial", &e);
            shared.note_error();
            return;
        }
    };
    let mut sent: Vec<Instant> = Vec::with_capacity(pipeline);
    while Instant::now() < deadline {
        sent.clear();
        let mut ok = true;
        for _ in 0..pipeline {
            sent.push(Instant::now());
            if framed.feed(&*payload).await.is_err() {
                ok = false;
                break;
            }
        }
        if !ok || SinkExt::<&str>::flush(&mut framed).await.is_err() {
            shared.note_error();
            return;
        }
        for &t in &sent {
            if let Some(Ok(line)) = framed.next().await {
                if shared.recording() {
                    shared.messages.fetch_add(1, Ordering::Relaxed);
                    shared
                        .bytes
                        .fetch_add(as_u64(line.len()), Ordering::Relaxed);
                    shared.hist.record(t.elapsed());
                }
            } else {
                shared.note_error();
                return;
            }
        }
    }
}

#[allow(
    clippy::cast_precision_loss,
    reason = "benchmark counts are well within f64 exact-integer range for realistic runs"
)]
fn rate(count: u64, secs: f64) -> f64 {
    if secs <= 0.0 {
        0.0
    } else {
        count as f64 / secs
    }
}

fn fmt_ns(ns: u64) -> String {
    #[allow(
        clippy::cast_precision_loss,
        reason = "latency magnitudes are small; f64 is exact enough for display"
    )]
    let f = ns as f64;
    if ns >= 1_000_000_000 {
        format!("{:.2}s", f / 1e9)
    } else if ns >= 1_000_000 {
        format!("{:.2}ms", f / 1e6)
    } else if ns >= 1_000 {
        format!("{:.2}us", f / 1e3)
    } else {
        format!("{ns}ns")
    }
}

fn report(args: &Args, shared: &Shared, elapsed: Duration) {
    let secs = elapsed.as_secs_f64();
    let conns = shared.connections.load(Ordering::Relaxed);
    let msgs = shared.messages.load(Ordering::Relaxed);
    let bytes = shared.bytes.load(Ordering::Relaxed);
    let errors = shared.errors.load(Ordering::Relaxed);
    let (p50, p90, p99, pmax) = (
        shared.hist.percentile(0.50),
        shared.hist.percentile(0.90),
        shared.hist.percentile(0.99),
        shared.hist.max(),
    );
    let transport = if args.tls { "tls" } else { "plain" };
    let mode = match args.mode {
        Mode::Conn => "conn",
        Mode::Throughput => "throughput",
    };

    if args.json {
        let obj = serde_json::json!({
            "transport": transport,
            "mode": mode,
            "host": args.host,
            "port": args.port,
            "connections": args.connections,
            "measured_secs": secs,
            "message_size": args.message_size,
            "pipeline": args.pipeline,
            "connections_completed": conns,
            "messages": msgs,
            "bytes": bytes,
            "errors": errors,
            "connections_per_sec": rate(conns, secs),
            "messages_per_sec": rate(msgs, secs),
            "mib_per_sec": rate(bytes, secs) / (1024.0 * 1024.0),
            "latency_ns": { "p50": p50, "p90": p90, "p99": p99, "max": pmax },
        });
        println!("{}", serde_json::to_string_pretty(&obj).unwrap_or_default());
        return;
    }

    println!(
        "echobench: {transport} {mode} | {}:{} | {} conns x {}s",
        args.host, args.port, args.connections, args.duration
    );
    let lat = format!(
        "p50={} p90={} p99={} max={}  (~2x buckets)",
        fmt_ns(p50),
        fmt_ns(p90),
        fmt_ns(p99),
        fmt_ns(pmax)
    );
    match args.mode {
        Mode::Conn => {
            println!("  connections/sec : {:.1}", rate(conns, secs));
            println!("  setup latency   : {lat}");
        }
        Mode::Throughput => {
            println!(
                "  messages/sec    : {:.1}   ({} msg, {}B each, pipeline={})",
                rate(msgs, secs),
                msgs,
                args.message_size,
                args.pipeline
            );
            println!(
                "  throughput      : {:.2} MiB/s",
                rate(bytes, secs) / (1024.0 * 1024.0)
            );
            println!("  rtt latency     : {lat}");
        }
    }
    println!("  errors          : {errors}");
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args()?;
    let tls = if args.tls {
        Some(build_tls(&args)?)
    } else {
        None
    };
    let cfg = Arc::new(ConnCfg {
        host: args.host.clone(),
        port: args.port,
        tls,
    });
    let shared = Arc::new(Shared::new());
    let payload: Arc<str> = Arc::from("x".repeat(args.message_size).as_str());

    let deadline = Instant::now() + Duration::from_secs(args.warmup + args.duration);
    let mut handles = Vec::with_capacity(args.connections);
    for _ in 0..args.connections {
        let (cfg, shared, payload) = (cfg.clone(), shared.clone(), payload.clone());
        let handle = match args.mode {
            Mode::Conn => tokio::spawn(conn_worker(cfg, shared, payload, deadline)),
            Mode::Throughput => tokio::spawn(throughput_worker(
                cfg,
                shared,
                payload,
                args.pipeline,
                deadline,
            )),
        };
        handles.push(handle);
    }

    // Let the pool warm up before we start counting, then time the measurement window.
    if args.warmup > 0 {
        tokio::time::sleep(Duration::from_secs(args.warmup)).await;
    }
    let measure_start = Instant::now();
    shared.recording.store(true, Ordering::Relaxed);

    for h in handles {
        let _ = h.await;
    }
    report(&args, &shared, measure_start.elapsed());
    Ok(())
}
