# Upgrade State Machine

This document treats upgrade and handoff as one state machine:

- a worker upgrades itself by preserving the state it owns across `exec`
- the supervisor adopts the successor and then monitors it
- rollback means the old process keeps serving and the new one is discarded

The key rule is simple: **the process that owns a piece of state must keep the
FD for that state open until the successor has proved it can serve**. Anything
else is a best-effort optimization, not the contract.

## Core phases

```
Serving
  │
  ├── Prepare handoff
  │     - freeze the owned state
  │     - clear CLOEXEC on the FDs that must survive exec
  │     - create the ready pipe
  │     - create any bulk-data pipe, if needed
  │
  ├── Spawn successor
  │     - exec the next image
  │     - pass inherited FD numbers in env
  │
  ├── Child bootstrap
  │     - adopt inherited FDs
  │     - rebuild in-memory state
  │     - re-load config / allowlists / sandbox
  │     - write `ok\n` to the ready pipe only after the process is safe to serve
  │
  ├── Commit
  │     - parent reads `ok\n`
  │     - parent exits with `UPGRADE_COMMIT_EXIT_CODE`
  │     - supervisor later adopts the successor
  │
  └── Rollback
        - child never becomes ready, closes early, or times out
        - parent kills the child
        - parent restores or re-adopts the state it still owns
        - service continues under the old generation
```

The upgrade is not committed when the child is merely spawned. It is committed
only after the child has adopted the inherited FDs and written the ready ack.

## State ownership

The following table is the ownership boundary the code relies on.

| State | Owner before upgrade | How it survives | Owner after commit |
|---|---|---|---|
| Worker listener | worker or supervisor, depending on role | clear CLOEXEC and pass FD number | successor |
| Processor in-flight sessions | processor | clear CLOEXEC on each session FD and stream `SessionHandoff` records | successor |
| TLS live sessions | TLS acceptor | not serialized; handled by fork-and-drain | drainer child until drain completes |
| Ready pipe write end | parent | inherited as `FDPASS_READY_FD` | child only long enough to signal readiness |
| Ready pipe read end | parent | kept private in the parent | parent only |
| Session handoff pipe read end | child | inherited as `FDPASS_SESSIONS_FD` | child only long enough to read the payload |
| Session handoff pipe write end | parent | spawned after child creation, written once | parent only long enough to stream JSON |
| Supervisor control/listener FDs | supervisor | clear CLOEXEC before self-upgrade | successor supervisor |
| FreeBSD cap-mode FDs | upgrading worker | pre-opened before `cap_enter()`, then passed by env | successor worker |

On FreeBSD self-upgrades, the successor also receives pre-opened capability
FDs for the config dir, sockets dir, cert dir, key dir, and self-executable
FD. Those are the only way the successor can bootstrap inside capability mode.

## Worker upgrade flow

### 1. Processor

The processor owns the hardest state: live sessions.

1. Drain the live session registry into `SessionHandoff` records.
2. Clear CLOEXEC on each session FD and on the listener FD.
3. Create a session-payload pipe and a ready pipe.
4. Spawn the successor with:
   - `FDPASS_LISTENER_FD`
   - `FDPASS_SESSIONS_FD`
   - `FDPASS_READY_FD`
   - `FDPASS_UPGRADE_GENERATION`
5. The child reads the session payload, reconstructs each session, reloads
   config and allowlists, then signals ready.
6. The parent waits for the ack.
7. On ack, the parent exits with `UPGRADE_COMMIT_EXIT_CODE`.
8. On failure, the parent kills the child and re-adopts the drained sessions.

Important detail: a malformed or unreadable session payload from
`FDPASS_SESSIONS_FD` is treated as a startup failure, not as a partial upgrade.
That is what makes broken session handoff roll back cleanly.

### 2. Plain acceptor and scanner

These roles do not own long-lived session state.

1. Clear CLOEXEC on the listener FD.
2. Spawn the successor with the listener FD and the ready pipe.
3. Child adopts the listener and starts serving.
4. If the child never becomes ready, the parent kills it and keeps the listener.

The scanner has one extra wrinkle: it waits briefly for its own in-flight scan
work to finish before execing, but the state machine is the same.

### 3. TLS acceptor

TLS cannot serialize live rustls state. It therefore uses a different branch:

1. Parent forks.
2. Child stays alive as a drainer and finishes the existing TLS sessions.
3. Parent execs the new TLS acceptor with the listener.
4. New clients go to the new binary immediately.

This is still an upgrade/handoff state machine, but the “owned state” is kept in
the old process rather than moved to the new one.

## Supervisor handoff after commit

When a worker exits with `UPGRADE_COMMIT_EXIT_CODE`, the supervisor must not
respawn immediately.

1. It waits for the successor to report a generation strictly greater than the baseline it snapshots before `child.wait()`. The baseline is the generation the role last reported, or — before the link has populated — the worker's known current generation (which for a worker adopted across a supervisor self-upgrade is carried in `AdoptedState`, not defaulted to 0). Combined with the strictly-greater test, that means a stale value left in the link before its EOF clears can't trigger a false adoption, for both freshly-spawned and adopted workers.
2. If the successor appears, the supervisor adopts its PID and watches the
   control link. The successor is a grandchild it never spawned, so it has no
   child handle for it — it watches the control link instead of `child.wait()`.
   If that adopted successor later upgrades *itself*, its own successor bumps
   the generation on the control link; the supervisor recognizes the
   strictly-higher generation and re-adopts it, giving a second (or Nth)
   generation upgrade the same generation-strict protection as the first
   instead of racing a fresh respawn against a successor slow to dial in.
3. If the successor disappears — the control link is gone for the loss grace
   with no newer generation — the supervisor respawns fresh.
4. If no successor appears within the adoption window, the supervisor treats
   the upgrade as failed and respawns fresh.

This prevents the old generation from racing the new one for the control-plane
slot.

## Rollback behavior

Rollback is not one generic path. It depends on what state the role owns.

- Listener-only roles: kill the child, restore CLOEXEC if needed, keep serving
  on the original listener.
- Processor: kill the child, re-adopt the same session FDs, reconstruct the
  registry, keep serving the existing connections.
- Supervisor self-upgrade: kill the child, keep the old supervisor alive, and
  let the `CloexecGuard`s restore any FD flags that were cleared for the attempt.
- TLS: no rollback of live TLS state is possible across exec, so the old
  drainer continues until the remaining sessions finish or the drain deadline
  expires.

**Control client after rollback.** The worker's control client sets
`terminal=true` when it forwards the `Upgrade` message and then exits, relying
on the process either committing (and exiting) or never returning from
`do_upgrade`. On rollback `do_upgrade` does return, so the worker respawns its
control client immediately — otherwise the supervisor loses its control channel
to the still-running worker.

The important invariant is that rollback never leaves the service dependent on
the child. If the child failed to become ready, it is removed from the picture.

## Failure handling

The state machine distinguishes failure classes because the response differs.

| Failure | Handling |
|---|---|
| Spawn or exec fails | the upgrade attempt aborts immediately; the parent keeps serving |
| Child closes the ready pipe early | treated as failed startup; parent rolls back |
| Child times out before acking ready | parent kills child and rolls back |
| Session payload cannot be parsed from `FDPASS_SESSIONS_FD` | startup failure; roll back |
| Individual session FD cannot be reconstructed | warn, close that FD, continue with the rest |
| Incompatible session schema version | warn and skip that record |
| Successor never reconnects after commit | supervisor waits briefly, then respawns fresh |
| Successor reconnects but later disappears | supervisor waits for the loss grace, then respawns fresh |
| Canary window regresses below `Healthy` | abort the remaining roles, leave already-committed roles in place |

The upgrade protocol prefers a clean rollback over partial success. The only
accepted partial success is the documented one: skip a single incompatible
session record, keep the rest.

## Practical reading order

If you are debugging a failure, read the machine in this order:

1. Which role owns the state?
2. Which FDs were cleared of CLOEXEC?
3. Did the child write `ok\n`?
4. If not, did the parent kill the child and resume serving?
5. If yes, did the supervisor adopt the successor or wrongly respawn?

That sequence mirrors the implementation and is usually enough to locate the
broken edge quickly.
