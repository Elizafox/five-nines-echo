# 02 · Upgrade rung 1: keep the listener

> **After this page** you'll understand the simplest zero-downtime upgrade —
> swapping the binary while preserving only the listening socket — and the
> CLOEXEC + env-var mechanism that makes it work.

## The three rungs, and why there are three

A "zero-downtime upgrade" means different things depending on **what state has
to survive the binary swap**. five-nines-echo has three answers, and which one a
role uses is determined entirely by that question:

| Rung | What survives | Roles | Mechanism |
|---|---|---|---|
| **1** | just the listener | scanner, plain acceptor, supervisor itself | `execve` with the FD in an env var |
| **2** | listener **+** in-flight sessions | processor | serialize each session, re-adopt post-exec |
| **3** | listener **+** live TLS | tls acceptor | `fork()`, drain old sessions in the child |

This page is rung 1. Rungs 2 and 3 are the next two pages. Getting rung 1 in
your head first makes the others read as "rung 1, plus a trick for the state
that rung 1 throws away."

## The mechanism

A process that `execve()`s replaces its own image but keeps its open file
descriptors — *unless* a descriptor has the `FD_CLOEXEC` flag, which tells the
kernel to close it across `exec`. Listening sockets normally have it set.

So rung 1 is three steps:

1. **Clear CLOEXEC** on the listener FD, so it survives the `exec`.
2. **`execve` the new binary**, passing the listener's FD number in
   `FDPASS_LISTENER_FD` (and the generation counter in
   `FDPASS_UPGRADE_GENERATION`).
3. The new image's **adopt-or-bind** (from [`01-skeleton.md`](01-skeleton.md))
   finds `FDPASS_LISTENER_FD` set and adopts that FD instead of binding a fresh
   one.

The FD number is the same integer on both sides of the `exec` — that's the whole
trick. The CLOEXEC manipulation and the env-var contract live in `handoff.rs`
(look for `clear_cloexec` and the `ENV_LISTENER_FD` constant).

```
worker (gen N)
   │ clear_cloexec(listener_fd)
   │ execve(self, env: FDPASS_LISTENER_FD=<fd>, FDPASS_UPGRADE_GENERATION=N+1)
   ▼
worker (gen N+1)   ── adopt listener from env, start accepting ──▶ same port, no gap
```

Because the listener never closed, the kernel's accept backlog is untouched: any
client that connected during the swap is still queued, not reset.

## Who drives it

For a worker, the supervisor sends a `ControlMsg::Upgrade` over that role's
control socket and the worker re-execs itself. The supervisor *itself* upgrades
the same way (on `SIGHUP`) — it's just another process holding listeners. The
end-to-end flow, including how the supervisor notices the new generation took
over, is in [`../architecture.md#upgrade-flow`](../architecture.md#upgrade-flow);
the supervisor-side bookkeeping is in `supervisor/control.rs`.

## What rung 1 throws away

Rung 1 keeps the *door* open but forgets everyone already inside: in-flight
client connections are dropped. For the scanner and the plain acceptor that's
fine — they hold no long-lived client state worth saving (the acceptor handed
its connections off to the processor microseconds after accepting them).

But the **processor** is exactly the process holding those handed-off
connections. Dropping them on every upgrade would mean every deploy severs every
active echo session. That's the problem rung 2 solves.

---

⇒ **Next:** [`03-upgrade-sessions.md`](03-upgrade-sessions.md) — upgrade rung 2,
carrying in-flight sessions across the swap.
