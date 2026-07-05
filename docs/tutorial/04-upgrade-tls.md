# 04 · Upgrade rung 3: fork-and-drain for TLS

> **After this page** you'll understand why TLS sessions can't use rung 2, and
> the fork-and-drain technique that keeps them alive across an upgrade by
> keeping the *old process* alive instead of the *state*.

## Why rung 2 doesn't work here

Rung 2 worked because a plain session is reducible to "an FD plus a few
buffered bytes" — both serializable. A TLS session is not. After the handshake,
rustls holds negotiated keys, sequence numbers, and cipher state that the TLS
spec deliberately makes **non-portable** across implementations. There's no
`SessionHandoff` you can write into an env var.

If you can't move the *state* to a new process, the only option is to keep the
*process* that already holds it. That's fork-and-drain.

## The TLS data path, for context

Unlike the plain path, the TLS acceptor can't hand the client FD to the
processor — it terminates TLS in-process (rustls owns the socket) and
**byte-bridges** plaintext to the processor over a fresh Unix socket:

```
client ──TCP+TLS──▶ tls-acceptor ──plaintext over UDS──▶ processor
                    (rustls owns the session;            (echoes plaintext back
                     bridges bytes both ways)             over the same UDS)
```

So the live state that must survive an upgrade lives *inside the tls-acceptor
process*. Detail: [`../architecture.md#tls-path`](../architecture.md#tls-path).

## Fork, then split the work

```
tls-acceptor (gen N)
   │ fork()
   ├──────────────┐
   ▼              ▼
parent          child ("drainer")
 │ exec new       │ stops accepting new connections
 │ image with     │ runs each *existing* TLS session to completion
 │ just the       │ on blocking std sockets + nix::poll
 │ listener       │ reports DrainerEvents over the drainer socket
 ▼                │ exits at "Complete" or a 5s DeadlineExit
new acceptor      ▼
 accepts on     (gone once old sessions finish)
 same port
```

1. The parent `fork()`s, then `exec`s the new image with just the listener
   (plain rung 1). The new acceptor starts accepting on the same TCP port
   immediately — new clients are served by the new binary.
2. The child stays alive as a **drainer**: it finishes the TLS sessions it
   already holds, then exits — either when all drain cleanly (`Complete`) or at a
   5-second deadline (`DeadlineExit { remaining }`).

The implementation is the drainer path in `src/acceptor/tls_drain.rs`; the event protocol is
[`../architecture.md#tls-fork-and-drain`](../architecture.md#tls-fork-and-drain).

## The one rule the drainer must obey: no tokio

This is the subtle, instructive part. The drainer **cannot use tokio**. Tokio's
reactor registers its `kqueue`/`epoll` FDs into the process's address space; after
`fork()`, those FDs still reference the *parent's* kernel objects. Driving the
runtime in the child would race the parent on the same kqueue — undefined
behavior. So the drainer drops to **blocking std sockets + `nix::poll`** for its
remaining sessions. It's a deliberate step *down* in abstraction, forced by the
fork.

(Why `fork()` and not something cleaner like `pdfork`/`CLONE_PIDFD`? Portability —
those are FreeBSD-only and Linux-only respectively; `fork()` works everywhere.
The reasoning for these choices is collected in
[`../architecture.md#whys`](../architecture.md#whys).)

## The three rungs, recapped

You've now seen all three, and the pattern is: **the harder the state is to
move, the more of the old world you keep.**

- **Rung 1** keeps the door (listener), drops everyone inside.
- **Rung 2** keeps the door *and* the people, by serializing each connection.
- **Rung 3** keeps the door, lets new people in the new binary, and keeps the
  *old building standing* until the last old occupant leaves.

---

⇒ **Next:** [`05-staying-alive.md`](05-staying-alive.md) — keeping the daemon
running across crashes *and* hangs.
