# 00 · Why an echo server is "hard"

> **After this page** you'll know what problem each part of the codebase
> solves, and the order to read the rest of the tutorial in.

## The joke and the point

five-nines-echo is a line-echo server: send it `hello\n`, it sends back `hello\n`.
That's the entire feature. Everything else - ~12.9k lines across 43 Rust
source files - is about the *operational* problem: how do you run a long-lived
network daemon you can **upgrade without dropping a single connection**, **keep
alive across crashes and hangs**, **lock down with a sandbox**, and **operate**
(drain, reload, observe) while it's serving traffic?

The echo payload is deliberately trivial so that none of those concerns are
obscured by application logic. Every line of code that *isn't* echoing is
unambiguously about the daemon problem this project teaches.

The single hardest thing here is **zero-downtime self-upgrade**: a worker (or
the supervisor itself) `execve()`s a new binary image while keeping its
listening socket, its in-flight client connections, and the kernel's TCP
buffers intact. That problem is the spine of the whole design, so it's the
spine of this tutorial too.

## Why this much machinery exists

This is not complexity added just to make a toy echo server look impressive.
Modern daemons are usually expected to do many of these things as a baseline:
restart cleanly after crashes, roll out new binaries without obvious downtime,
expose health and metrics, reload configuration, drop privileges, survive under
service managers, and give operators enough visibility to debug production
problems.

None of those expectations are unusual anymore. What is unusual is that they
are often hidden inside frameworks, sidecars, init systems, or years of
accumulated service code. This repo keeps the *application* trivial so the
*operational* complexity is impossible to miss. The point is not "look how hard
echo is"; the point is that even a boring daemon becomes intricate once you
take modern runtime expectations seriously.

That is why the codebase spends so much effort on file-descriptor ownership,
upgrade handoff, watchdog state, sandbox constraints, and observability. Those
are not side quests around the real system. For a production daemon, they *are*
part of the real system.

## The shape of the running system

One binary, many subcommands; the supervisor spawns the rest as child processes.

```
                grandparent     (optional; restarts supervisor on crash)
                     │
                     ▼
                 supervisor     owns every listener + control socket
            ┌────────┬──────────┬────────┐
            ▼        ▼          ▼        ▼
        processor  plain       tls     scanner
          (line    (TCP)      (TLS     (identd
          echo)      │       bridge)    probe)
            ▲        │          │        │
            │        └──────────┘        │
            │         byte-bridge        │
            │          over UDS          │
            │                            │
            └────── sidecar metadata ────┘
```

The one rule that makes everything else possible: **only the supervisor calls
`bind(2)`.** Workers receive their listener FD from the supervisor (via
SCM_RIGHTS) or inherit it across their own re-exec. So when a worker dies, the
listening port doesn't go with it; the supervisor still holds the listener and
clients queue in the kernel's accept backlog.

## Map of the territory

```
src/
├── main.rs           subcommand dispatch, --config parsing
├── config.rs         TOML Config struct, defaults, paths
├── auth.rs           SO_PEERCRED / LOCAL_PEERCRED uid allowlist
├── control.rs        JSON message envelopes + schema version
├── handoff.rs        FD/session passing, ready-pipe, CloexecGuard
├── limits.rs         session cap + per-IP token bucket
├── metrics.rs        Prometheus textfile collector + upgrade counters
├── health.rs         HTTP /healthz endpoint
├── security.rs       drop_privileges + per-OS sandbox dispatcher
├── systemd.rs        socket activation + sd_notify
├── worker_common.rs  worker plumbing façade
├── worker_common/
│   ├── dial.rs       sockets_dir dialer + control-plane dial
│   ├── listeners.rs  adopt-or-bind + spawner listener requests
│   └── scm.rs        SCM_RIGHTS send/receive primitives
├── grandparent.rs    optional supervisor-respawn watchdog
├── supervisor.rs     listener ownership + control orchestration
├── supervisor/
│   ├── control.rs    control-link state + status/upgrade helpers
│   ├── listeners.rs  listener adoption/bind helpers
│   ├── self_upgrade.rs supervisor exec/FD handoff
│   ├── spawner.rs    worker listener SCM_RIGHTS server
│   ├── drainer.rs    drain event logging + fallback SIGTERM
│   ├── metrics.rs    periodic metrics writer
│   ├── admin.rs      admin socket + rolling upgrade workflow
│   ├── worker.rs     worker spawn/adoption lifecycle
│   └── watchdog.rs   worker crash-cadence state machine
├── processor.rs      line echo runtime + sidecar metadata
├── processor/
│   ├── control.rs    control-plane client + status snapshot
│   ├── sidecar.rs    scanner sidecar receiver
│   └── upgrade.rs    processor session adoption + rollback upgrade
├── acceptor.rs       plain + TLS accept loops/upgrades (both UDS-bridged to the processor)
├── acceptor/
│   ├── control.rs    status client + upgrade sidecar
│   ├── data.rs       client registry + plain UDS bridge to the processor
│   ├── upgrade.rs    listener-preserving upgrade path
│   ├── tls_cert.rs   TLS cert/key loading + reload strategy
│   ├── tls_drain.rs  TLS fork-and-drain upgrade path
│   └── tls_client.rs TLS bridge/session lifecycle
├── scanner.rs        identd back-connection probe
├── scanner/
│   ├── control.rs    control-plane client + status snapshot
│   ├── sidecar.rs    processor sidecar publisher
│   └── upgrade.rs    listener-preserving scanner upgrade path
├── fault_inject.rs   debug-only fault injection macro + trigger store
└── admin.rs          status/upgrade/drain/reload admin clients
```

## The reading path

The tutorial is ordered by **dependency depth** — each step builds on the one
before, and the three "upgrade rungs" (chosen by *what state must survive* a
binary swap) are the centerpiece. Stop after any step and you'll still have a
coherent mental model.

1. [`01-skeleton.md`](01-skeleton.md) — supervisor + one worker, how a listener
   gets to a worker, and the plain TCP data path (UDS bridge).
2. [`02-upgrade-listener.md`](02-upgrade-listener.md) — **upgrade rung 1**:
   re-exec keeping only the listener.
3. [`03-upgrade-sessions.md`](03-upgrade-sessions.md) — **upgrade rung 2**:
   keep in-flight sessions too (the processor), with two-phase commit + rollback.
4. [`04-upgrade-tls.md`](04-upgrade-tls.md) — **upgrade rung 3**: live TLS, which
   can't be serialized — fork-and-drain.
5. [`05-staying-alive.md`](05-staying-alive.md) — the watchdog state machine and
   the systemd liveness beacon (catching *exits* vs. *hangs*).
6. [`06-hardening.md`](06-hardening.md) — privilege drop + sandbox (seccomp on
   Linux, Capsicum on FreeBSD).
7. [`07-operating.md`](07-operating.md) — running it: admin socket, drain,
   reload, health endpoint, metrics, trace IDs.
8. [`08-testability.md`](08-testability.md) — why the code is shaped the way it
   is so upgrades, crashes, sandboxes, and failure paths can be proved in tests.
9. [`09-observability-and-debugging.md`](09-observability-and-debugging.md) —
   how to diagnose upgrade stalls, watchdog regressions, and session-level
   issues from status, health, metrics, and logs together.
10. [`10-control-plane-and-wire-compatibility.md`](10-control-plane-and-wire-compatibility.md) —
    how versioned envelopes, mixed generations, and session handoff compatibility
    constrain safe upgrades.
11. [`11-portability-and-kernel-differences.md`](11-portability-and-kernel-differences.md) —
    what really changes across Linux, FreeBSD, and macOS, and how the design
    absorbs those kernel differences.

For exhaustive, look-it-up detail on any mechanism, the reference companion is
[`../architecture.md`](../architecture.md). This tutorial points into it
liberally; read it when you want the full state machine, not the story.

---

⇒ **Next:** [`01-skeleton.md`](01-skeleton.md) — the minimal supervisor + worker.
