# 03 · Upgrade rung 2: carry the sessions across

> **After this page** you'll understand how the processor upgrades *without
> dropping in-flight connections* — serializing each live session, the
> two-phase commit that makes a failed upgrade safe, and the rollback path.

This is the most intricate rung. It's rung 1 (keep the listener) plus a way to
preserve the state rung 1 discards: the in-flight client connections.

## A connection is an FD plus a few bytes

Recall from [`01-skeleton.md`](01-skeleton.md) that the processor's client
connection is "just an FD." To carry one across an `exec`, you need two things:

1. **the FD itself** — kept alive by clearing CLOEXEC, exactly like the
   listener in rung 1; and
2. **the tiny bit of userspace state wrapped around it** — specifically, any
   bytes the line-framer has read but not yet delivered (a half-received line).

That second part is what stops a mid-flight line from being torn. The processor
serializes each live session as a `SessionHandoff` record (in `handoff.rs`):

```rust
SessionHandoff {
    version: SCHEMA_VERSION,
    peer, transport: Uds | Tcp,
    fd: RawFd,                    // CLOEXEC cleared before exec
    partial_line_bytes: Vec<u8>,  // the framer's unflushed read buffer
    ident, trace_id,
}
```

All the live sessions are serialized as a JSON list, but the bulky payload does
not go into the environment. The parent creates a pipe, passes the read end's FD
number in the small `FDPASS_SESSIONS_FD` env var, and streams the JSON to the
child after spawn. The new image's
`processor::upgrade::adopt_inflight_sessions` reads that inherited pipe, rebuilds
each `Framed<…, LinesCodec>`, **pre-loads the framer's read buffer with
`partial_line_bytes`**, and respawns the session task. A line whose first byte
arrived before the upgrade and last byte after is delivered intact. Full detail:
[`../architecture.md#rollback`](../architecture.md#rollback).

Because `FDPASS_SESSIONS_FD` means "the parent drained sessions for this
successor," a read failure or malformed JSON payload is fatal: the child exits
before signaling ready, and the parent rolls back by re-adopting its sessions.
Only individual records with incompatible schema versions are skipped.

## Two-phase commit: making a bad upgrade safe

Here's the danger: what if the new binary is broken and crashes on startup? If
the old process has already exited, those handed-off connections die with it.

The fix is a **two-phase commit** over a single pipe (`FDPASS_READY_FD`). The
old process (the parent) `fork+exec`s the new image but does **not** exit yet —
it blocks reading that pipe:

```
parent (gen N)                      child (gen N+1)
   │ fork + exec child                 │ adopt listener from env
   │ stream sessions over pipe      ───▶ read sessions from FDPASS_SESSIONS_FD
   │                                   │ re-load config, drop privileges, sandbox
   │ block on read(FDPASS_READY_FD) ◀──┤ write "ok\n" only after successful adoption
   │                                   ▼
   ├─ got "ok\n":  process::exit(23)   (commit — child owns the role now)
   └─ timeout:     kill child,         (rollback — parent re-adopts its sessions)
                   re-adopt sessions
```

- **Commit:** child signals ready → parent exits with code **23**
  (`UPGRADE_COMMIT_EXIT_CODE`), a sentinel the supervisor's watchdog recognizes
  and does *not* count as a crash (see [`05-staying-alive.md`](05-staying-alive.md)).
- **Rollback:** child never signals within `ready_timeout_secs` → parent kills
  it and **re-adopts the very same `SessionHandoff` records**. The FDs were never
  closed (a `CloexecGuard` in `handoff.rs` holds them open across the whole
  attempt), so sessions resume on the exact line boundary they'd have hit under a
  clean commit. The listener FD never left the parent, so client backlogs survive
  too.

This is the payoff of keeping the old process alive until the new one proves it
can start: a broken deploy is a no-op, not an outage.
[`../architecture.md#two-phase-commit`](../architecture.md#two-phase-commit) has
the exit-code reasoning in full.

## The successor handoff (the part that bites cross-platform)

There's a wrinkle the supervisor has to handle. The new processor (gen N+1) was
`fork+exec`'d *by the old worker*, so from the supervisor's point of view it's a
**grandchild it never spawned and can't `wait()` on**. When the gen-N parent
exits with code 23, the supervisor's per-role loop must *not* immediately respawn
a fresh worker — that would race the successor for the role's (last-write-wins)
control-plane slot.

So `supervisor::supervise_role` runs a small state machine instead of respawning:

- `wait_for_successor` polls the control link until it sees generation N+1
  (**Adopted**) or a 5s window elapses (**Timeout** → respawn fresh).
- on adoption it points `current_pid` at the successor and calls
  `monitor_successor`, which only respawns after the successor's control
  connection has been gone continuously for `SUCCESSOR_LOSS_GRACE` (3s) —
  debounced so a brief reconnect doesn't trigger a spurious respawn.

This closed a race that was benign on Linux but broke on FreeBSD under the
sandbox. The full state-machine writeup, including the `conn_epoch` writer
fencing, is
[`../architecture.md#successor-hand-off-in-supervise_role`](../architecture.md#successor-hand-off-in-supervise_role).

## Schema versioning: old and new images talking

During a rolling upgrade the *old* supervisor briefly talks to *new* workers,
and a new image adopts sessions serialized by an old one. Every cross-process
JSON message — including `SessionHandoff` — carries a `version` field, and the
receiver declines anything outside its supported range (with a `WARN`, not a
crash). `processor::upgrade::adopt_inflight_sessions` drops incompatible
sessions rather than misparsing them; malformed inherited payloads are different
and fail startup so the parent can roll back. See
[`../architecture.md#schema-versioning`](../architecture.md#schema-versioning).

---

⇒ **Next:** [`04-upgrade-tls.md`](04-upgrade-tls.md) — upgrade rung 3, for state
that *can't* be serialized at all.
