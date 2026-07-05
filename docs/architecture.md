# Architecture

> **New here? Start with [`tutorial/`](tutorial/00-overview.md)** — a guided,
> dependency-ordered walk through the system. This document is the *reference*
> companion: exhaustive and grouped by subsystem, not ordered for first reading.

This is the deeper companion to the README and the tutorial. The README is "what
you can do with it," the tutorial is "how to learn it in order," and this is "how
it actually works." Read it once before opening unfamiliar parts of the code, or
follow the `architecture.md#…` deep-links the tutorial drops at each step.

## Overview

five-nines-echo is more complex than a typical single-process service because
it keeps the data plane up while the control plane is changing underneath it.
That means several concerns have to line up at once:

- the **supervisor** owns the long-lived process tree and decides when workers
  are spawned, upgraded, or restarted
- **readiness** is a real protocol, not an assumption: a child must prove it
  adopted its state before the parent yields the role
- **rollback** is first-class so a bad binary, bad config, or startup failure
  does not drop live traffic
- **FD handoff** carries listeners and live session state across `exec` without
  reopening by path
- **sandboxing** changes what the successor can access, especially under FreeBSD
  capability mode, so upgrades must sometimes pre-open and inherit capability
  FDs
- **metrics** need to reflect the actual upgrade outcome, not just whether a
  child process existed
- **health** distinguishes healthy workers from flapping or failed ones so the
  supervisor can make restart decisions with backoff and thresholds
- **auth** gates the control and data-plane sockets so only allowed peers can
  talk to the service
- **graceful upgrades** preserve listeners, drain or re-adopt in-flight work,
  and avoid races when the successor takes over

The rest of this document explains how those pieces fit together in the process
tree, the socket layout, the upgrade path, and the health model.

## Process tree

```
  grandparent  (optional, watchdog only)
       │  spawn + waitpid + killpg-on-crash, exp backoff
       │  sets FDPASS_UNDER_GRANDPARENT=1 — supervisor refuses SIGHUP self-upgrade
       ▼
  supervisor  (long-lived, never sandboxed)
       │  setsid'd, owns all listeners + control sockets
       │
       │  ┌─── spawned via std::process::Command(current_exe()) ───┐
       │  │                                                        │
       ▼  ▼                                                        ▼
  processor   plain-acceptor   tls-acceptor   scanner    (transient: TLS
   (UDS)      (TCP)            (TCP+TLS)      (UDS)       drainer child)
```

The supervisor is the only process that calls `bind(2)`. Workers receive
their listener FDs either from the env (inherited across the worker's
own self-upgrade) or via SCM_RIGHTS from the supervisor's spawner socket.
This is why a worker crash doesn't drop the listening port: the
supervisor still holds the listener FD and clients queue in the kernel's
accept backlog during the watchdog backoff window.

Each role has its own pair of control sockets at fixed paths under
`sockets_dir` (default `/tmp/`):

| Socket | Direction | Purpose |
|---|---|---|
| `fdpass-admin.sock` | CLI → supervisor | `status`/`upgrade`/`drain`/`reload` |
| `fdpass-ctrl-{processor,plain,tls,scanner}.sock` | supervisor → worker | per-worker `ControlMsg` |
| `fdpass-spawner.sock` | worker → supervisor | request listener FD on cold start |
| `fdpass-drainer.sock` | TLS drainer child → supervisor | post-fork session events |
| `fdpass-proc.sock` | acceptor → processor | data plane (UDS `Session` byte-bridge) |
| `fdpass-scanner.sock` | acceptor → scanner | one-line scan-request JSON |

UDS endpoints are gated by `SO_PEERCRED` (Linux) / `LOCAL_PEERCRED`
(macOS, FreeBSD) against `auth.allowed_uids`. We use the raw `getsockopt`
forms rather than tokio's `peer_cred()` because the latter calls
`getpeereid()` on macOS, which returns `ENOTCONN` once the peer has
called `shutdown()` — a common pattern for "write one line, close."

## Upgrade flow

A rolling upgrade walks four roles in fixed order: `processor → plain →
scanner → tls?` (TLS only with `--include-tls`). `echod upgrade --role <worker>`
restricts the walk to a single worker; **`--role processor` is the routine
zero-downtime path** — the processor holds the business logic and changes often,
and its in-flight sessions survive its re-exec via UDS handoff (below), while the
thin accept+bridge acceptor is left running. A *full* walk re-execs the acceptor
too, which resets sessions in-flight during the swap window (the listener is
preserved, so no connection is refused); that's an accepted tradeoff, since the
acceptor is stable plumbing that rarely needs a new binary. For each role:

Concurrent upgrade requests — whether from simultaneous admin connections or a
SIGUSR2 while an admin walk is running — are serialized: a second walk is
rejected immediately if one is already in progress.

For the phase-by-phase state machine, including owned FDs and rollback
behavior, see [`upgrade-state-machine.md`](upgrade-state-machine.md).

```
admin CLI ─── ControlMsg::Upgrade ───▶ supervisor
                                          │
                                          │ send Upgrade over per-role
                                          │ control socket
                                          ▼
                                       worker (gen N)
                                          │ adopt-or-reuse listener FD
                                          │ fork+exec current_exe()
                                          │   with FDPASS_LISTENER_FD,
                                          │   FDPASS_READY_FD,
                                          │   FDPASS_UPGRADE_GENERATION=N+1,
                                          │   FDPASS_SESSIONS_FD=<pipe read fd>
                                          │ stream SessionHandoff JSON
                                          │   over the pipe
                                          ▼
                                       worker (gen N+1)
                                          │ adopt listener from env
                                          │ read sessions from inherited pipe
                                          │ re-load PeerAllowlist
                                          │ drop_privileges + apply_sandbox
                                          │ write "ok\n" to ready pipe ───▶ parent
                                          ▼
                                       parent reads ready pipe
                                          │   commit:   process::exit(23)
                                          │   timeout:  kill child, rollback
                                          │             — re-adopt sessions
                                       parent (gen N) — exit if commit
```

### Two-phase commit

The parent and child are bound by a single pipe (`FDPASS_READY_FD`). During
child startup the new worker writes `"ok\n"` only after adopting its inherited
state and completing worker initialization; the parent blocks on `read(2)` with
a `ready_timeout_secs` deadline.

- Child writes `ok\n` → parent reads it → parent `process::exit(23)`.
  Exit code 23 (`UPGRADE_COMMIT_EXIT_CODE`) is a sentinel: the
  supervisor's watchdog special-cases it and does *not* treat the exit
  as a fast-crash.
- Child fails to write within the deadline → parent kills the child and
  re-adopts the in-flight `SessionHandoff` records. The listener FD never
  leaves the parent's process so client TCP backlogs survive a rolled-back
  upgrade.

### Successor hand-off in `supervise_role`

When the gen-N parent exits with `UPGRADE_COMMIT_EXIT_CODE`, its
`supervise_role` loop must not immediately respawn — the gen-N+1 successor
(fork+exec'd by the parent, so a grandchild the supervisor never `wait`s
on) is taking over the role's control-plane slot. The loop runs a small
state machine instead: `wait_for_successor` snapshots a generation baseline before
`child.wait()` and then polls until the reported generation is strictly
greater than that snapshot (`Adopted`) or a 5s window elapses
(`Timeout` → respawn fresh). The baseline is the link's `last_generation`, falling
back — before the link has populated — to the worker's known current generation
rather than 0. That distinction matters for a worker adopted across a supervisor
self-upgrade: its real generation is carried in `AdoptedState` (the `FDPASS_*_GEN`
env vars) and seeds the baseline, so the strictly-greater comparison (not `≥ N+1`)
ensures a stale value left in the link before the gen-N worker's control
connection EOF is processed can't trigger a false adoption — for freshly-spawned
*and* adopted workers. On adoption it points `current_pid` at the
successor's reported PID (refreshed from later status reports while monitoring, in
case the PID captured at adoption was the dying worker's) and enters
`monitor_successor`, respawning only after the successor's control connection has
been gone for `SUCCESSOR_LOSS_GRACE` (3s). Since the supervisor isn't the successor's
parent, that dropped connection is the *only* death signal it gets — so
`accept_control` clears the link's writer on disconnect, fenced by a
per-connection `conn_epoch` so a stale reader can't clobber a worker that
already reconnected.

This closed a benign-on-Linux / broken-on-FreeBSD race where the old loop
slept then respawned a fresh gen-0 worker that raced the successor for the
last-write-wins control slot.

### Canary observation

If the admin CLI requested `--canary N`, after each per-role
`UpgradeStep { phase: Done }` the supervisor watches that role's watchdog
state for N seconds. If the state regresses to anything below `Healthy`
(typically `Backoff` from a fast exit), the supervisor emits
`UpgradePhase::CanaryAborted` and skips the remaining roles. A successful
canary is counted as `fdpass_upgrade_total{outcome="committed"}`; an
abort as `outcome="canary_aborted"`.

### Rollback

The processor's rollback path is the most interesting: the worker
serializes each live session as

```rust
SessionHandoff {
    version: SCHEMA_VERSION,
    peer, transport: Uds,  // Tcp is a legacy variant; declined on adoption (see below)
    uds_fd: RawFd,  // the processor's end of the acceptor↔processor bridge; CLOEXEC cleared here
    partial_line_bytes: Vec<u8>,  // post-newline tail in the framer
    ident, trace_id,
}
```

as a JSON list streamed over an inherited pipe advertised by the small
`FDPASS_SESSIONS_FD` env var. The new image's `adopt_inflight_sessions()`
reads that pipe, reconstructs each `Framed<…, LinesCodec>`, populates the
framer's read-buffer with `partial_line_bytes`, and spawns the session
task. A line whose first byte was sent before the upgrade and last byte
after is delivered intact.

If `FDPASS_SESSIONS_FD` is present, a pipe read failure or malformed JSON
payload is fatal before the child writes the ready ACK. That makes a broken
handoff a rollback instead of silently losing sessions while the parent commits.
Individual records with incompatible schema versions are still declined with a
warning so mixed-version rolling upgrades can continue.

If the upgrade is rolled back, the *parent* re-adopts those same
`SessionHandoff`s — the FDs were never closed because of the
`CloexecGuard`. Sessions resume on the same line boundary they would
have under a clean commit.

### TLS fork-and-drain

The TLS acceptor can't serialize live rustls session state, so its
upgrade is split:

1. Parent `fork()`s before exec.
2. Child stays alive, runs each remaining TLS session synchronously on
   blocking std sockets (it can't keep using tokio — the runtime shares
   kqueue/epoll FDs with the parent post-fork, which is UB).
3. Parent execs the new TLS acceptor with just the listener; the new
   image starts accepting on the same TCP port.
4. Child reports `DrainerEvent`s over the drainer socket and exits
   either when all sessions drain cleanly (`Complete`) or at the 5-second
   `DeadlineExit { remaining: usize }`.

## Watchdog

Per-role state machine, evaluated by the supervisor on every worker
exit:

```
                  ┌────────► Healthy ────────┐
                  │            │             │ counter ≥ 4
   uptime ≥ 5s    │            │ fast exit   ▼
                  └────────── Backoff ◄──── Flapping
                                │             │
                                │ counter ≥ 5 │
                                ▼             │
                              Failed ◄────────┘
                              (terminal — needs
                              admin upgrade to recover)
```

- A "fast exit" is one that happens within `WATCHDOG_HEALTHY_UPTIME` (5s)
  of the last spawn — i.e. the worker didn't make it to steady state.
- Backoff doubles per fast exit, capped at `WATCHDOG_MAX_BACKOFF` (30s).
  A single uptime ≥ 5s resets the consecutive-fast-exits counter back to
  zero.
- `WATCHDOG_FLAP_THRESHOLD = 4`, `WATCHDOG_FAIL_THRESHOLD = 5`. Thresholds
  are in `src/supervisor/watchdog.rs`.
- Exit code 23 (UPGRADE_COMMIT) is filtered out entirely — it doesn't
  count toward fast-exit accounting.
- `Failed` flips the `/healthz` endpoint to 503 and trips `Type=notify`'s
  `STATUS=` line, but the supervisor does NOT exit. Recovery is via
  `echod upgrade --target /path/to/fixed-binary` once a fix exists.

### systemd liveness watchdog

The state machine above catches a worker *exiting*; it can't catch the
supervisor's own tokio runtime *wedging* while the process stays alive.
When systemd sets `WatchdogSec=`, `systemd::spawn_watchdog` pings
`WATCHDOG=1` at half the interval — gated on a `WatchdogBeacon`
(`AtomicU64`) that the supervisor's core `select!` loop ticks on every
iteration. If the loop stops being polled (a blocked reactor, a mutex held
across an await), the beacon stalls, the ping stops, and systemd kills +
restarts per the unit's `Restart=`. It arms only when `WATCHDOG_USEC` is
set and `WATCHDOG_PID` (if present) matches our pid — so forked workers
don't ping, and an `execve` self-upgrade re-arms. A `SIGUSR2` rolling
upgrade runs inline in the select loop and briefly stops the beacon, so
`WatchdogSec` must exceed the worst-case upgrade (a few seconds). See
`systemd/fdpass.service`.

## Control plane wire protocol

All cross-process JSON is wrapped in a versioned envelope:

```rust
struct Envelope<T> {
    version: u32,  // SCHEMA_VERSION constant
    #[serde(flatten)] msg: T,
}
```

Messages without a `version` field default to 1, so old peers and new
peers in the supported compat window can talk. Receivers reject
incompatible versions with a `WARN` log and a structured error response.

`ControlMsg` (supervisor → worker, and CLI → supervisor admin):

| Variant | Fields | Purpose |
|---|---|---|
| `Shutdown` | `grace_ms: u64` | Terminal. Worker stops accepting, drains `grace_ms`, exits. |
| `Upgrade` | `binary_path?: PathBuf`, `include_tls: bool`, `canary_secs?: u64` | Per-role: re-exec. CLI: walk roles. |
| `Status` | — | Request `WorkerMsg::StatusReport` reply. |
| `Drain` | — | Soft-drain acceptors; processor/scanner ignore. |
| `Reload` | — | Re-read config; swap `PeerAllowlist` + TLS cert. |

`WorkerMsg::StatusReport(WorkerStatus { role, pid, generation,
started_at_unix_ms, in_flight, listener_addr? })` is the worker's reply
to `Status`.

`AdminResp` (supervisor → CLI):

| Variant | When |
|---|---|
| `Ok` | Drain, Reload, Shutdown ACK |
| `Status { workers, health }` | Status reply |
| `UpgradeStep { worker, phase, generation_before, generation_after, ok, message? }` | Stream of progress lines during a rolling upgrade |
| `UpgradeComplete { all_ok: bool }` | Final frame |
| `Error { message: String }` | Anything went wrong |

## Data plane

### Plain TCP path

```
client ──TCP──▶ plain-acceptor
                     │ socket(AF_UNIX) + connect("/tmp/fdpass-proc.sock")
                     │ send ProcessorPreamble::Session { peer, role: "plain", trace_id }
                     │
                     ▼
                  processor reads framed lines over UDS, echoes back over the same UDS
                  plain-acceptor byte-bridges TCP↔UDS for the life of the session
```

The plain acceptor terminates the client TCP, opens a UDS to the processor, writes a one-line
`Session` preamble, and then byte-forwards between the client TCP and the processor UDS (two
independently-spawned copy tasks). The processor only ever sees a UDS line-echo session; it never
touches the client socket. Rate limits and the per-role session cap stay on the acceptor, which
holds the accept guard for the whole session.

### TLS path

```
client ──TCP+TLS──▶ tls-acceptor
                       │ tls_acceptor.accept(tcp).await → TlsStream<TcpStream> (rustls owns state)
                       │ socket(AF_UNIX) + connect(processor)
                       │ send ProcessorPreamble::Session { peer, role: "tls", trace_id }
                       ▼
                    processor reads framed lines over UDS, echoes plaintext back over the same UDS
                    tls-acceptor byte-bridges TLS↔UDS
```

Plain and TLS are the **same shape**: the acceptor terminates the transport and byte-bridges the
plaintext to a processor UDS `Session`. The only difference is TLS runs a handshake first and, being
non-serializable, needs fork-and-drain for an *acceptor* upgrade (see [TLS fork-and-drain](#tls-fork-and-drain));
a plain bridge is just two fds and has no such constraint.

### Why a UDS bridge and not an SCM_RIGHTS FD handoff?

An earlier version of this tree did plain differently: the acceptor passed the raw client **TCP fd**
to the processor via `SCM_RIGHTS` (`sendmsg` ancillary data) and then dropped out of the data path,
and the processor talked to the client directly. That had a genuine merit — because the processor
owned the client socket, a *processor* upgrade preserved the session by handing off the TCP fd, and
the acceptor was never in the plain data path at all. But it carried real cost:

- **An asymmetric data plane.** Plain (fd handoff, processor-owns-socket) and TLS (byte bridge) were
  two different mechanisms with two different session types (`Transport::Tcp` vs `Uds`), duplicated
  session-spawn / fd-reconstruct paths, and a delicate custom `recvmsg` preamble reader — it had to
  grab the fd and the preamble line in a single kernel message, which left tokio's readiness state
  in a state prone to a hard-to-reproduce first-read lost-wakeup.
- **The SCM_RIGHTS ack race.** `sendmsg` returns once the cmsg is *queued*, so the acceptor had to
  block on an explicit `ok\n` ack from the processor before `close()`-ing its own fd — otherwise the
  last reference on the TCP socket could drop before the receive-side fd existed and the kernel
  would RST the client (observed on macOS, Linux, and FreeBSD). An entire documented sub-protocol
  existed only to make the handoff unambiguous.

We measured the two shapes head-to-head (release, loopback): **throughput is a wash** — the workload
is bound by the processor's per-line work, not the transport — and the bridge adds only **~15 µs of
per-round-trip latency** from the extra hop, which vanishes under concurrency. Given that, the bridge
won on **symmetry**: one data-plane mechanism, one session type (`Uds`), the fragile `recvmsg` reader
and the ack race both deleted, and plain/TLS as equal citizens. The processor's `Session` read is now
a plain `Framed<UnixStream, LinesCodec>` whose first decoded frame is the preamble — so a preamble
and first data line that arrive coalesced decode as two frames natively, with no raw pre-read to hand
off.

The one thing the bridge gives up: the plain acceptor is now **in** the data path, so an *acceptor*
upgrade resets in-flight plain sessions (as it always has for TLS). We accept that, because the
acceptor is thin, stable "accept + bridge" plumbing that rarely changes — while the meaty,
frequently-changing **processor** upgrades independently and *does* preserve sessions via UDS handoff.
See [Upgrade flow](#upgrade-flow) and `echod upgrade --role processor`.

### Scanner sidecar

For each accepted client the acceptor writes a one-line
`ScanRequest::SessionObserved { client_ip, client_port, server_port,
role, trace_id }` to `fdpass-scanner.sock`. The notification goes
through `worker_common::SocketsDialer` (not a raw `UnixStream::connect`)
so it works under FreeBSD `cap_enter()` — a path-based connect returns
`ECAPMODE`. Scanner spawns an identd (RFC 1413) probe, then publishes a
`SessionMetadata { peer, ident?, trace_id }` over the long-lived sidecar
connection to the processor. The
processor stashes it by peer address and annotates subsequent log lines
for that session.

## Resource bounds

Each acceptor enforces two per-connection DoS limits:

### 1. Session cap

`max_in_flight_per_role` limits concurrent accepted connections per
acceptor. Connections past the cap trigger an accept-then-close: TCP is
successfully established, then our half is immediately closed — the client
sees a clean close rather than connection refused. This avoids the SYN
queue on the listening socket, allowing the kernel to queue legitimate
clients while we're overloaded.

Implementation: `SessionCap` in `src/limits.rs` uses a shared atomic
counter with optimistic CAS loops. Returned `SessionGuard` decrements on
drop, so the limit self-enforces across async cancellation and panic paths.

### 2. Per-IP rate limiting with bounded memory

`accept_rate_per_ip` and `accept_rate_burst` define a token-bucket limiter
per source IP. An attacker spraying connections from many distinct addresses
could inflate the IP→bucket map without bound, turning the limiter itself into
a memory-exhaustion DoS against the acceptor.

The limiter implements two-level eviction to bound memory:

- **Hard cap** (`rate_limit_max_tracked_ips`, default 65536): never track more
  than N distinct IPs. When full, inserting a new IP triggers eviction.

- **Idle TTL** (`rate_limit_bucket_idle_ttl_secs`, default 300): buckets not
  touched in this interval are opportunistically dropped during eviction scans,
  so a burst of one-shot IPs doesn't pin memory at the cap indefinitely.

When evicting at cap:

1. First, drop any idle buckets (last_touch older than TTL). Often sufficient.
2. If still full, evict the bucket with the most tokens (least throttled),
   using LRU (oldest last_touch) as tiebreaker. Full buckets (tokens ≈ capacity)
   are safe to evict since the IP isn't currently rate-limited.
3. If all buckets are throttled (tokens < 1.0, can't take a token), refuse the
   new IP (cap_refused metric). Correct backpressure under a genuine distributed
   flood: new sources get dropped rather than evicting state of IPs still being
   limited.

Implementation: `RateLimiter` in `src/limits.rs`. Eviction on insert-at-cap is
O(max_tracked) but only runs on contended insertions; for a 65536-IP cap this
is a sub-millisecond scan. Eviction stats (idle/LRU/refused counts) are exposed
as Prometheus metrics.

Both limits reset per acceptor role (plain and TLS each have independent
counters). Set either to 0 to disable.

## Security layers

Applied in this order during worker startup:

```
adopt_or_bind_listener      // needs bind/socket — must be pre-sandbox
open TLS cert source        // TLS only: pre-open cert/key dir FDs + initial
                            //   load, before cap_enter (enables reload later)
drop_privileges             // needs setgroups/setgid/setuid
apply_sandbox               // seccomp (Linux) | cap_enter (FreeBSD)
signal_ready_to_parent      // first thing that fails the upgrade if any
accept loop                 // untrusted network input from here on
```

### 1. Peer auth

`SO_PEERCRED`/`LOCAL_PEERCRED` gates every UDS accept against
`auth.allowed_uids`. Empty list defaults to "current uid only." Hot-
reloadable via `echod reload`.

LOCAL_PEERCRED returns a `xucred` whose `cr_uid` is the peer's effective
uid at connect time — cached by the kernel, so it survives the peer
calling `shutdown()` or `close()`. We allocate the xucred with
`MaybeUninit` to avoid the spurious zero-init.

### 2. Privilege drop

`drop_privileges()` does setgroups → setgid → setuid in the
POSIX-required order, then verifies that `setuid(0)` fails when we
expect it to (defense-in-depth against kernel bugs leaving the
saved-set-uid as 0).

The supervisor does NOT drop. `kill(2)` requires the sender's real or
effective uid to match the target's real/saved-set-uid (or be root); if
the supervisor dropped to the workers' uid, signaling them would work,
but a runaway worker that has setuid'd elsewhere couldn't be SIGKILL'd
back. Production model: supervisor as root via `systemd User=root +
CapabilityBoundingSet=…`, workers drop to a service account.

### 3. Sandbox

Linux uses seccomp-bpf with an explicit allowlist of ~90 syscalls. The
allowlist was derived by `strace -f` + iteration under `sandbox = "log"`
mode. Notable inclusions:

- `pidfd_open`, `pidfd_send_signal` — Rust's `std::process::Command`
  uses pidfd-based child reaping on modern Linux.
- `seccomp` itself — the upgrade child inherits the parent's filter and
  needs to re-install its own after listener-adopt + drop.
- `setuid`/`setgid`/`setgroups` — same reason; the upgrade child
  re-runs `drop_privileges`. Safe to allow: once non-root, the kernel's
  own permission check blocks `setuid(0)`.

FreeBSD uses Capsicum via `cap_enter()`. There is no per-syscall
allowlist; the kernel revokes access to global namespaces (paths, PIDs of
non-descendant processes, sysctls). For the data plane, both the
acceptor → processor handoff and the acceptor → scanner notification go
through `worker_common::SocketsDialer`, which holds a pre-opened,
capability-rights-limited dir FD for `sockets_dir` and uses `connectat(2)`
so the AF_UNIX connects don't touch the global path namespace. Plain + TLS
data flow works under cap mode and the e2e suite asserts the full echo
round-trip.

**Upgrade under cap mode** works, but only after clearing two sequential
blockers that `ktrace` (FreeBSD 15.0) pinned down. `cap_enter()` is inherited
across fork+exec, so the re-exec'd successor's *entire* startup runs in
capability mode, where every path-based open returns `ECAPMODE`:

1. The kernel resolves the ELF interpreter `/libexec/ld-elf.so.1` by path
   during image activation, before any userspace runs — so a
   *dynamically-linked* successor dies in the kernel and never reaches
   `main`. Fixed by shipping a **static** binary (no `PT_INTERP`); build with
   `scripts/build-static.sh`.
2. The static successor reaches `main`, then hits `Config::load`, the sockets
   dir, the TLS cert/key dirs, and `current_exe()` — all path-based. Fixed by
   **pre-opening every one of these as an FD before `cap_enter` and handing
   the fd numbers to the successor**, exactly as `ENV_LISTENER_FD` already
   does for the listener. The upgrading worker clears CLOEXEC on the
   pre-opened config / sockets-dir / cert-dir / key-dir / self-exe FDs and
   passes their numbers via env (`handoff::cap_mode_handoff`); the successor
   adopts them in `Config::load`, `SocketsDialer::open`, `TlsCertSource::open`,
   and `open_self_exe` instead of opening paths. Handoff happens only for a
   sandboxed *self*-upgrade — `--target` (a different binary) and unsandboxed
   runs keep the path-based startup.

On FreeBSD, the final image switch uses `fexecve` against the pre-opened
self-exe FD. The `pre_exec` hook precomputes the argv/envp C strings and pointer
vectors before `fork`; after `fork` it only calls `fexecve` or `_exit`, avoiding
allocator use in the async-signal-unsafe window.

`drop_uid`/`drop_gid` may be names or numeric strings: `drop_privileges`
resolves any name → numeric ID and writes the result back into the config
struct before `cap_enter`. The config JSON handed to upgrade successors
therefore always carries numeric IDs; the successor's `drop_privileges` parses
them directly without touching the path namespace. `--target` upgrades still
require `sandbox = "off"` (an arbitrary new path can't be pre-opened).

**TLS cert SIGHUP / admin reload** works under cap mode.
`acceptor::tls_cert::TlsCertSource` (modeled on `SocketsDialer`) pre-opens the
cert and key parent directories as `CAP_LOOKUP | CAP_READ` dir FDs before
`cap_enter()`, then reloads via `openat(dir_fd, basename, O_RDONLY)`. A
long-lived worker can swap certs without leaving capability mode; verified
on FreeBSD 15.0 by `test_tls_cert_reload_under_strict_sandbox`.

See the rustdoc on `freebsd_capsicum` for the full design notes.

macOS is a dev target; sandbox warns-and-ignores.

## Schema versioning

`SCHEMA_VERSION` (currently 1) and `MIN_COMPATIBLE_VERSION` (1) live in
`handoff.rs`. The `Envelope::into_msg()` check fires on every cross-
process JSON read. This matters in three places:

1. **Admin CLI ↔ supervisor.** An old client against a new daemon, or
   vice versa.
2. **Supervisor ↔ workers.** During a rolling upgrade the supervisor is
   the *old* image briefly talking to *new* workers.
3. **Upgrade-time session adoption.** `SessionHandoff::version` is
   checked in `adopt_inflight_sessions`; incompatible sessions are
   dropped with a `WARN` (`declined to adopt session with incompatible
   schema`).

Bumping the version is a deliberate act: increment `SCHEMA_VERSION`,
adjust `MIN_COMPATIBLE_VERSION` only if you genuinely want to break old
peers, and write a migration note in the commit message.

## Trace IDs

Format: `<pid as 4-byte hex>-<per-process counter as 8-byte hex>`,
e.g. `0000db17-0000000000000001`. Minted by the acceptor at accept time
and threaded through:

- `ScanRequest::SessionObserved` (acceptor → scanner)
- `ProcessorPreamble::Session` (acceptor → processor)
- `SessionHandoff` (preserved across upgrade)
- `SessionMetadata` (scanner sidecar → processor)

Log lines from all four workers for the same session share the same
`trace_id`. Combined with `FDPASS_LOG_FORMAT=json`, you get
structured, joinable logs across process boundaries with no external
tracing infrastructure.

## Why's

A few design choices that aren't obvious from the code.

- **Why isn't the supervisor sandboxed?** Same reason it doesn't drop
  privileges: it needs to `kill(2)` arbitrary children, and many sandbox
  configurations block that. Keeping the supervisor unrestricted also
  means a sandbox bug in worker setup doesn't take the whole daemon
  down.
- **Why fork-and-drain for TLS but not plain?** This is specifically about an
  *acceptor* upgrade (a processor upgrade preserves both via UDS handoff).
  Rustls session state is not serializable (the spec deliberately makes it
  non-portable across implementations), so the only way to keep a mid-flight
  TLS session alive across an acceptor binary swap is to keep the *original
  process* alive for it — fork-and-drain. A plain bridge, by contrast, is just
  two fds and a byte pump with no unserializable state, so it *could* be handed
  off to the successor across exec the way the processor hands off its sessions.
  We deliberately don't: the plain acceptor just resets in-flight sessions on its
  own (rare) upgrade, because adding a handoff path there isn't worth it for
  stable plumbing. So the asymmetry is a choice — TLS *must* fork-and-drain,
  plain *chooses* not to preserve across an acceptor swap.
- **Why fork() not unshare/pdfork()?** Portability. `pdfork` is
  FreeBSD-only and `clone3(CLONE_PIDFD)` is Linux-only. `fork()`
  works everywhere.
- **Why not a single Tokio runtime for the drainer?** Tokio's reactor
  registers its kqueue/epoll FDs into the inherited address space;
  after fork those FDs reference the *parent's* kernel objects. Driving
  the reactor in the child would race the parent on the same kqueue.
  The drainer uses blocking std sockets + `nix::poll` instead.
- **Why an HTTP /healthz endpoint when we have an admin socket?**
  Different consumers. The admin socket is for human operators and CI
  (`status`, `upgrade`); /healthz is for the load balancer or
  Kubernetes liveness probe, which can't authenticate to a UDS.
- **Why a Prometheus textfile rather than a real HTTP `/metrics`
  endpoint?** Same reason: shielding the scrape path from auth. The
  textfile-collector pattern lets node_exporter (already exposed) read
  a file the supervisor owns; we don't have to maintain a second HTTP
  surface inside the daemon.

## Miscellaneous design notes

### Lint policy for exceptions

The crate enables `clippy::allow_attributes_without_reason`. Prefer deleting
dead code or refactoring the shape that triggered a lint; a remaining
`#[allow(...)]` must carry `reason = "..."`. The current exceptions are limited
to platform-specific cfg seams, FFI/toolchain differences, or tests that
intentionally serialize process-global state.

### Data-plane history: SCM_RIGHTS → UDS bridge

The plain path used to hand the client TCP fd to the processor via `SCM_RIGHTS`
(with an `ok\n` ack protocol to avoid a close/RST race) instead of byte-bridging
over UDS. It was replaced by the unified UDS bridge for symmetry with TLS at a
negligible cost (throughput wash, ~15 µs added latency). The full rationale,
including the ack race it eliminated, is under
[Why a UDS bridge and not an SCM_RIGHTS FD handoff?](#why-a-uds-bridge-and-not-an-scm_rights-fd-handoff).
