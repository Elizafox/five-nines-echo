# five-nines-echo

A teaching-oriented Rust + Tokio proof of concept for a restartable Unix
daemon. The headline feature is **zero-downtime self-upgrade**: any worker (or
the supervisor itself) can `execve()` a new binary image while keeping its
listening socket, its in-flight client connections, and its kernel-side TCP
buffers intact. The vehicle is a deliberately trivial line-echo service on
TCP/7070 (plain) and TCP/7071 (TLS) — everything that isn't echoing is about how
you build, upgrade, harden, and operate a production daemon.

That complexity is intentional. Modern daemons are usually expected to restart
cleanly after crashes, roll out new binaries with minimal disruption, expose
health and metrics, reload config, drop privileges, cooperate with service
managers, and remain debuggable under pressure. This repo keeps the application
trivial so those operational requirements are visible directly, instead of
being hidden inside a framework or a larger service.

Single binary, multiple subcommands. 12.9k LOC across 44 Rust source files;
runs on Linux, macOS, and FreeBSD.

**New here?** Start with the [tutorial](docs/tutorial/00-overview.md) — a guided,
dependency-ordered walk through the codebase. This README is the map and the
quickstart; see [Documentation](#documentation) below for everything else.

## Quickstart

```bash
cargo build
./certs/gen.sh                # one-shot self-signed cert for CN=localhost
./target/debug/echod    # default subcommand: supervisor
```

Once the supervisor is up:

```bash
# Plain echo
printf 'hello\n' | nc -q1 localhost 7070

# TLS echo
printf 'hello\n' | openssl s_client -connect localhost:7071 -quiet -no_ign_eof

# Inspect state
./target/debug/echod status
```

`tracing` writes to stderr at INFO; `RUST_LOG=five_nines_echo=debug` for the noisy
version, `FDPASS_LOG_FORMAT=json` for JSON-per-line. See
[`07-operating.md`](docs/tutorial/07-operating.md) for upgrade / drain / reload
and the observability surfaces.

## Subcommands

The first argument selects a role (default: `supervisor`). Workers are normally
spawned by the supervisor, not run by hand.

| Subcommand | Role |
|---|---|
| `supervisor` | spawn and supervise all workers (default) |
| `grandparent` | respawn the supervisor on crash (thin systemd alternative) |
| `processor` | UDS line-echo worker |
| `plain` | plaintext TCP acceptor |
| `tls` | TLS acceptor (rustls) |
| `scanner` | outbound auxiliary lookup (identd connection-back) |
| `upgrade` | admin: rolling upgrade — flags `--target <path>`, `--role <worker>`, `--include-tls`, `--canary N` |
| `status` | admin: per-worker generation / pid / uptime / in-flight |
| `drain` | admin: stop accepting new connections; keep existing sessions |
| `reload` | admin: re-read config; refresh auth allowlist + TLS cert |

A global `--config <path>` flag (or `FDPASS_CONFIG_PATH`) selects the TOML config;
the supervisor propagates the resolved path to every child.

## Configuration

Every field is optional with a default; an empty file is valid. Each knob is
explained where it's used — follow the links.

| Section / key | Default | What it does |
|---|---|---|
| `sockets_dir` | `/tmp` | dir for all control-plane UDS endpoints |
| `plain_port` / `tls_port` | `7070` / `7071` | TCP listen ports |
| `ready_timeout_secs` | `3` | upgrade two-phase-commit deadline ([rung 2](docs/tutorial/03-upgrade-sessions.md)) |
| `identd_port` | `113` | scanner's identd probe port; override for unprivileged test setups |
| `[auth] allowed_uids` | `[]` (= current uid) | peer-uid allowlist for every UDS ([§operating](docs/tutorial/07-operating.md)) |
| `[tls] cert_path` / `key_path` | `certs/server.crt` / `.key` | TLS material; hot-reloadable on SIGHUP |
| `[limits] max_in_flight_per_role` | `1024` | concurrent-session cap (`0` disables) |
| `[limits] tls_idle_timeout_secs` | `300` | idle TLS session cutoff |
| `[limits] accept_rate_per_ip` / `accept_rate_burst` | `50` / `100` | per-IP token bucket |
| `[limits] rate_limit_max_tracked_ips` | `65536` | bound on the limiter's own memory |
| `[limits] rate_limit_bucket_idle_ttl_secs` | `300` | idle-bucket eviction TTL |
| `[health] bind_addr` | `127.0.0.1:7079` | HTTP health endpoint (empty disables) |
| `[metrics] path` / `interval_secs` | `""` (disabled) / `15` | Prometheus textfile output |
| `[security] drop_uid` / `drop_gid` | unset (no drop) | worker privilege drop ([§hardening](docs/tutorial/06-hardening.md)) |
| `[security] sandbox` | `off` | `off` \| `strict` \| `log` — seccomp (Linux) / Capsicum (FreeBSD) |
| `[security.sandbox_overrides]` | `{}` | per-role sandbox override (e.g. `scanner = "off"`) |

The DoS reasoning behind `[limits]` is in
[`07-operating.md`](docs/tutorial/07-operating.md) and
[`architecture.md#resource-bounds`](docs/architecture.md#resource-bounds); the
hardening order is in [`06-hardening.md`](docs/tutorial/06-hardening.md).
`[fault_inject]` (debug builds only) is documented in `src/fault_inject.rs`.

## Benchmarking

Connection-rate and throughput numbers come from `echobench`, a small async load
generator (`examples/echobench.rs`, not part of the shipped binary). It drives
many concurrent line-echo clients over plaintext or TLS and reports
connections/sec or messages/sec + MiB/s, plus approximate round-trip latency
percentiles.

Turnkey — builds a release `echod`, launches it with the rate limiter and
in-flight cap disabled on isolated ports, runs the plain/TLS × conn/throughput
matrix, then tears it down:

```bash
./scripts/bench.sh                                  # 50 conns x 10s, 256B messages
./scripts/bench.sh --connections 200 --duration 30 --message-size 1024
```

Or drive a server you started yourself:

```bash
cargo run --release --example echobench -- --tls --mode throughput \
    --connections 200 --duration 10 --message-size 256
cargo run --release --example echobench -- --plain --mode conn --connections 100
```

`--mode conn` measures new-connection / TLS-handshake rate (connections are
RST-closed via `SO_LINGER=0` so a high-rate run doesn't exhaust loopback
ephemeral ports); `--mode throughput` pumps newline-delimited messages over
persistent connections (`--pipeline N` for outstanding messages per connection).
TLS verification is off by default — the self-signed cert `certs/gen.sh`
produces is its own CA, which webpki won't accept as an end-entity, the same
reason the e2e suite uses
`CERT_NONE`; pass `--ca <path>` to verify against a real chain, or
`ECHOBENCH_DEBUG=1` to print handshake errors.

**Important:** loopback is *not* exempt from the per-IP accept rate limiter
([`[limits]`](#configuration)), so benchmark against a server with
`accept_rate_per_ip = 0` and `max_in_flight_per_role = 0` — exactly what
`scripts/bench.sh` configures.

## Documentation

This project is documented in four tiers:

- **Tutorial** — [`docs/tutorial/`](docs/tutorial/00-overview.md): the guided,
  dependency-ordered on-ramp. Read it in order:
  1. [`00-overview.md`](docs/tutorial/00-overview.md) — why an echo server is "hard"
  2. [`01-skeleton.md`](docs/tutorial/01-skeleton.md) — supervisor + worker, the plain data path
  3. [`02-upgrade-listener.md`](docs/tutorial/02-upgrade-listener.md) — upgrade rung 1
  4. [`03-upgrade-sessions.md`](docs/tutorial/03-upgrade-sessions.md) — upgrade rung 2
  5. [`04-upgrade-tls.md`](docs/tutorial/04-upgrade-tls.md) — upgrade rung 3
  6. [`05-staying-alive.md`](docs/tutorial/05-staying-alive.md) — watchdog + liveness beacon
  7. [`06-hardening.md`](docs/tutorial/06-hardening.md) — privilege drop + sandbox
  8. [`07-operating.md`](docs/tutorial/07-operating.md) — admin, drain, reload, health, metrics
  9. [`08-testability.md`](docs/tutorial/08-testability.md) — how the daemon stays provable in tests
  10. [`09-observability-and-debugging.md`](docs/tutorial/09-observability-and-debugging.md) — how to diagnose upgrades, flaps, and session issues
  11. [`10-control-plane-and-wire-compatibility.md`](docs/tutorial/10-control-plane-and-wire-compatibility.md) — versioned envelopes and mixed-generation safety
  12. [`11-portability-and-kernel-differences.md`](docs/tutorial/11-portability-and-kernel-differences.md) — Linux, FreeBSD, and macOS differences
- **Reference** — [`docs/architecture.md`](docs/architecture.md): the exhaustive,
  look-it-up companion (state machines, wire protocol, security trade-offs).
- **Tests** — [`e2e/README.md`](e2e/README.md): the cross-platform integration
  suite and what it covers, including portability and coverage.
- **Design notes** — `docs/notes/`: lab-notebook writeups of specific
  investigations (kept for provenance, not part of the guided path).

## TLS crypto backend

The rustls provider is a build-time choice, defaulting to **ring** — it needs no C
toolchain and is the cleanest fit for the static/musl and FreeBSD builds this repo
targets. To track the rustls upstream default instead, build against
**aws-lc-rs** (actively AWS-maintained, FIPS-capable, but pulls in cmake + a C
compiler):

```bash
cargo build                                          # ring (default)
cargo build --no-default-features --features aws-lc-rs
```

Exactly one backend must be enabled; a misconfiguration fails the build with a
clear message rather than a cryptic import error.

## Platform support

Windows isn't supported and isn't planned — SCM_RIGHTS is Unix-only and the
upgrade story is built around `execve`. The Linux seccomp sandbox is validated on
both **x86_64 and aarch64** (glibc and musl); the FreeBSD Capsicum path on aarch64.
Cross-target checking and the runtime suite (macOS, Linux, FreeBSD) are covered in
[`e2e/README.md`](e2e/README.md).
