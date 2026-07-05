# 05 · Staying alive: crashes *and* hangs

> **After this page** you'll understand the two distinct failure modes a daemon
> must survive — a process that *exits* and a process that *wedges while still
> running* — and the two completely different mechanisms that catch them.

The single most useful idea on this page: **"is it alive?" has two answers.** A
process can be dead-and-gone (it `exit`ed or crashed) or alive-but-useless (it's
running but its event loop is wedged). These are different failures and no single
watchdog catches both. five-nines-echo has one mechanism for each.

## Failure mode 1: a worker exits → the watchdog state machine

When a worker process exits, the supervisor sees it (it spawned the worker and
`wait()`s on it). It runs a per-role state machine, evaluated on every exit:

```
                  ┌────────► Healthy ────────┐
                  │            │             │ counter ≥ 4
   uptime ≥ 5s    │            │ fast exit   ▼
                  └────────── Backoff ◄──── Flapping
                                │             │
                                │ counter ≥ 5 │
                                ▼             │
                              Failed ◄────────┘
                              (terminal — needs admin upgrade to recover)
```

- A **fast exit** is one within 5s of spawn (`WATCHDOG_HEALTHY_UPTIME`) — the
  worker didn't reach steady state. Backoff doubles per fast exit, capped at 30s.
  A single ≥5s run resets the counter.
- After 4 consecutive fast exits the role is **Flapping**; after 5, **Failed**.
- **Failed is terminal**: it flips `/healthz` to 503 and sets the systemd
  `STATUS=` line, but the supervisor does *not* exit. You recover with
  `echod upgrade --target /path/to/fixed-binary`.
- Exit code 23 (the upgrade-commit sentinel from
  [`03-upgrade-sessions.md`](03-upgrade-sessions.md)) is filtered out entirely —
  a successful upgrade is not a crash.

Thresholds live in `src/supervisor/watchdog.rs`; full transition table:
[`../architecture.md#watchdog`](../architecture.md#watchdog).

The **grandparent** (optional, `echod grandparent`) is the same idea one
level up: it spawns the supervisor, `waitpid`s, and respawns it with exponential
backoff if it *exits*. It's a thin stand-in for systemd's `Restart=on-failure`.

## Failure mode 2: the supervisor hangs → the systemd liveness beacon

Now the failure the state machine *can't* catch: the supervisor's own tokio
runtime wedges — a blocked reactor, a mutex held across an `await` — but the
process stays alive. It never exits, so nothing above ever fires. From the
outside it looks up; from the inside it's doing nothing.

This needs a liveness signal that depends on the event loop *actually making
progress*. That's the **watchdog beacon**:

- the supervisor's core `select!` loop ticks a `WatchdogBeacon` (an `AtomicU64`)
  on every iteration;
- `systemd::spawn_watchdog` pings systemd's `WATCHDOG=1` at half the configured
  `WatchdogSec` interval — **but only while the beacon keeps advancing.**

If the loop stalls, the beacon stops, the ping stops, and systemd kills and
restarts the daemon per the unit's `Restart=`. A wedge becomes a restart. The
beacon arms only when systemd set `WATCHDOG_USEC` (and `WATCHDOG_PID` matches),
so forked workers don't ping and a re-exec re-arms. Detail:
[`../architecture.md#systemd-liveness-watchdog`](../architecture.md#systemd-liveness-watchdog).

> One caveat worth remembering: a rolling upgrade runs inline in the select loop
> and briefly stops ticking the beacon, so `WatchdogSec` must exceed your
> worst-case upgrade time (a few seconds).

## The two-by-two you should walk away with

| | detects an **exit** | detects a **hang** |
|---|---|---|
| **worker** | supervisor watchdog state machine | (n/a — workers don't run the beacon) |
| **supervisor** | grandparent respawn | systemd liveness beacon |

Most systems only build the left column and are surprised when a hung process
sits there "healthy." Building the right column is the lesson of this page.

---

⇒ **Next:** [`06-hardening.md`](06-hardening.md) — dropping privileges and
sandboxing the workers.
