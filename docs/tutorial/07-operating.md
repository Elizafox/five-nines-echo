# 07 · Operating it

> **After this page** you'll know how to drive the running daemon (status,
> upgrade, drain, reload), how it's bounded against abuse, and the three ways it
> tells you what it's doing (admin socket, health endpoint, metrics).

This is the operator's page. Where earlier pages explained *how* a mechanism
works, this one is *how you use it* — and where the reference detail lives.

## The control plane

Every worker holds a Unix socket to the supervisor; they exchange one versioned
JSON object per line. The directions:

- worker → supervisor: `WorkerMsg::StatusReport(WorkerStatus)`
- supervisor → worker: `ControlMsg::{Shutdown, Upgrade, Status, Drain, Reload}`

A separate **admin socket** (`fdpass-admin.sock`) is what the CLI dials. The
supervisor proxies your request to the per-worker control sockets and streams
progress back. The subcommands:

| Command | Effect |
|---|---|
| `status` | per-worker generation / pid / uptime / in-flight |
| `upgrade` | rolling upgrade: `processor → plain → scanner → tls?` |
| `drain` | stop accepting; keep existing sessions |
| `reload` | re-read config; swap auth allowlist + TLS cert |

`upgrade` flags: `--include-tls` (also walk the TLS acceptor), `--target <path>`
(upgrade to a different binary), `--canary N` (after each role, watch its
watchdog for N seconds and abort the rest of the walk if it regresses). The wire
protocol — `AdminResp`, the `UpgradeStep` progress stream, the envelope — is
[`../architecture.md#control-plane-wire-protocol`](../architecture.md#control-plane-wire-protocol).

### drain and reload, precisely

- **drain** is a *soft* drain: each acceptor flips an atomic flag and drops
  newly-accepted TCP immediately. Existing sessions own their FDs and keep
  echoing. The supervisor still holds the listener, so new clients see
  connect-then-EOF rather than `ECONNREFUSED` — load-balancer friendly.
- **reload** re-reads config and hot-swaps what's safe to change at runtime:
  `auth.allowed_uids` (behind an `RwLock`) and the TLS cert/key. Ports,
  sockets_dir, and security settings need a full restart.

All UDS endpoints are gated by `SO_PEERCRED`/`LOCAL_PEERCRED` against an
allowlist (default: same uid as the daemon) — see
[`../architecture.md#1-peer-auth`](../architecture.md#1-peer-auth).

## Bounded resources

Three knobs under `[limits]`, each `0` to disable. The implementation is
`limits.rs`; the DoS reasoning is
[`../architecture.md#resource-bounds`](../architecture.md#resource-bounds).

- `max_in_flight_per_role` — concurrent-session cap per acceptor; overflow is
  *accept-then-close* (a clean close, not a refused connect, so the kernel can
  still queue legitimate clients). Enforced by an atomic-counter `SessionGuard`
  that decrements on drop, so it's correct across cancellation and panic.
- `tls_idle_timeout_secs` — TLS sessions idle this long are closed by the bridge.
- `accept_rate_per_ip` + `accept_rate_burst` — per-source-IP token bucket. The
  interesting part is that the limiter itself is bounded against a
  many-distinct-IP flood: two-level eviction (idle-TTL sweep, then evict the
  least-throttled bucket) caps the IP→bucket map. Refuses new IPs only when every
  tracked bucket is genuinely throttled. Detail:
  [`../architecture.md#2-per-ip-rate-limiting-with-bounded-memory`](../architecture.md#2-per-ip-rate-limiting-with-bounded-memory).

## Three ways to observe it

Different consumers need different surfaces — that's why there are three.

- **Admin socket** (`echod status`) — for humans and CI. Authenticated
  (peer-uid). The rich view.
- **Health endpoint** — `GET` anything on `health.bind_addr` (default
  `127.0.0.1:7079`) returns JSON per-role state: **200** when every role is at
  worst `Backoff`, **503** the moment anything is `Failed`. For a load balancer
  or k8s liveness probe that can't authenticate to a UDS. (`health.rs`.)
- **Metrics** — if `metrics.path` is set, the supervisor writes a Prometheus
  textfile (atomic tmp+rename) every `metrics.interval_secs`, for the
  node_exporter textfile collector. Families cover supervisor/worker generation,
  in-flight, health, restart counters, and `fdpass_upgrade_total{role,outcome}`.
  (`metrics.rs`.)

Both the health endpoint and the metrics textfile exist *instead of* an
in-daemon HTTP `/metrics` surface, specifically to keep the scrape path off any
authenticated socket. The rationale is in
[`../architecture.md#whys`](../architecture.md#whys).

## Trace IDs: joining logs across processes

Every session gets a `trace_id = "<pid hex>-<counter hex>"`, minted by the
acceptor and threaded through the scanner request, the processor handoff, the
`SessionHandoff` across an upgrade, and the scanner's sidecar metadata. All four
workers' log lines for one client share it — so with `FDPASS_LOG_FORMAT=json` you
get joinable structured logs across process boundaries with no external tracing
infrastructure. (The scanner sidecar — identd probe result, published back to
the processor for log enrichment — is
[`../architecture.md#scanner-sidecar`](../architecture.md#scanner-sidecar).)

## systemd and TLS cert reload

- **systemd** is auto-detected via the standard env-var contract — no CLI flag.
  Socket activation (adopt FDs from `LISTEN_FDS`/`LISTEN_FDNAMES`), `Type=notify`
  (`READY=1`/`STOPPING=1`/`STATUS=`), and the `WatchdogSec=` liveness ping from
  [`05-staying-alive.md`](05-staying-alive.md). Sample units in `systemd/`, one
  `.socket` per FD. When not under systemd, all of this is a no-op.
- **TLS cert hot-reload**: `SIGHUP` the TLS acceptor's PID (`pid_of("tls")` from
  `status`) and it rebuilds the `TlsAcceptor` and swaps it behind an `RwLock`. New
  connections use the new cert; existing sessions keep the one they handshook
  with. A parse failure leaves the old cert in place. Target the TLS acceptor's
  PID specifically — the supervisor's own SIGHUP triggers a self-upgrade.

## Where to go next

You've walked the whole system. One last tutorial page covers **why the code is
structured to stay testable**, and how the project proves the cross-process and
cross-kernel claims it makes:
[`08-testability.md`](08-testability.md).

For exhaustive mechanism detail, the reference companion is
[`../architecture.md`](../architecture.md). For the full black-box suite, see
[`../../e2e/README.md`](../../e2e/README.md).

---

⇒ **Next:** [`08-testability.md`](08-testability.md)
