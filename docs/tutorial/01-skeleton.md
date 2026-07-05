# 01 · The skeleton: supervisor + one worker

> **After this page** you'll understand how a listening socket gets from the
> supervisor into a worker, and how a plain TCP connection reaches the echo
> processor — the foundation every upgrade rung builds on.

## The cast

Forget the four workers for a moment. The minimal system is three processes:

- a **supervisor** that binds the listeners and spawns children,
- a **plain acceptor** that owns TCP/7070, and
- a **processor** that does the actual line echo.

The supervisor binds *everything* — both TCP ports and all the control-plane
Unix sockets — and hands each worker the FD it needs. A worker never calls
`bind(2)` itself. This is the design decision the rest of the project leans on:
because the supervisor holds every listener, a worker can die (or be replaced)
without the port ever closing.

## Getting a listener into a worker: adopt-or-bind

Each worker, on startup, asks one question: *do I already have my listener, or
do I need one?* That's the **adopt-or-bind** logic in `worker_common.rs`. A
listener can arrive three ways, checked in priority order:

1. **From systemd** (socket activation) — covered in
   [`07-operating.md`](07-operating.md).
2. **From the environment** — an FD number in `FDPASS_LISTENER_FD`, inherited
   across the worker's own re-exec. This is the hook the upgrade story uses
   (next page).
3. **From the supervisor** over a "spawner" Unix socket, via SCM_RIGHTS — the
   cold-start path.

SCM_RIGHTS is the kernel mechanism for passing an open file descriptor across a
Unix-domain socket. The receiving process gets a *new* FD in its own table that
refers to the *same* kernel file object. That single primitive — "send an open
socket to another process" — is how the supervisor hands a bound **listener** to
a worker on cold start (the path above), and it's why a listener survives a
worker crash. (The plain data path below deliberately does *not* use it — see
that section for why.) The low-level send/recv lives in `src/worker_common/scm.rs`
(built on `nix`); see [`../architecture.md#process-tree`](../architecture.md#process-tree).

## The plain data path

Now a client connects to TCP/7070. The acceptor terminates the TCP, opens a Unix
socket to the processor, and byte-bridges between them for the life of the
session:

```
client ──TCP──▶ plain-acceptor
                     │  socket(AF_UNIX) + connect to processor
                     │  send ProcessorPreamble::Session { peer, role: "plain", trace_id }
                     ▼
                  processor  reads framed lines over UDS, echoes back over the same UDS
                  plain-acceptor byte-forwards TCP↔UDS (two spawned copy tasks)
```

The acceptor stays in the data path for the whole session, forwarding raw bytes
between the client's TCP socket and the processor's Unix socket. The processor
only ever sees a UDS line-echo session — it never touches the client socket. This
is the *same* shape the TLS path uses (terminate the transport, bridge the
plaintext to a processor `Session` over UDS), so plain and TLS are handled
identically. The implementation is `acceptor::data::bridge_plain_via_uds`: dial
the processor, write the one-line preamble, then run two `tokio::spawn`ed pumps
(client→processor and processor→client) until either side closes.

### Why not just pass the fd?

An earlier version did exactly that: the acceptor `SCM_RIGHTS`-passed the raw TCP
fd to the processor and dropped out of the data path, so the processor talked to
the client directly. It worked, and it had one nice property — the acceptor
wasn't in the plain data path, so a *processor* upgrade preserved the session for
free. But it made plain and TLS two different mechanisms with two session types,
and it needed a fiddly `sendmsg`/`recvmsg` + `ok\n`-ack protocol to dodge a
close/RST race (`sendmsg` returns once the cmsg is *queued*, so closing the fd too
early could drop the socket's last reference before the receiver's fd existed).
The UDS bridge trades a hair of latency (~15 µs/round-trip, throughput unchanged)
for one uniform data path. Full rationale:
[`../architecture.md#why-a-uds-bridge-and-not-an-scm_rights-fd-handoff`](../architecture.md#why-a-uds-bridge-and-not-an-scm_rights-fd-handoff).

## The fourth worker: the scanner

The overview diagram shows a fourth worker — the **scanner** — that has no
listener of its own. It exists to answer one question: *how do you add outbound
TCP from a daemon while keeping it off the hot path?*

The hook is **identd** (RFC 1413), chosen because it's the simplest possible
back-connection protocol. When a client connects, the acceptor fires a one-line
`ScanRequest::SessionObserved` JSON event at the scanner's Unix socket and
immediately moves on. The scanner, on its own time, dials the *client's* port
113, sends `client_port,server_port\r\n`, and reads one line back: the RFC 1413
response containing a username or an error token.

The protocol is trivial by design: the real exercise is the structural question
of *where to put the outbound work* and what constraints that imposes.

```
           acceptor ──UDS one-shot──▶ scanner
                                           │ connect to client:113
                                           │ "client_port,server_port\r\n"
                                           ◀── "...:USERID:UNIX:alice\r\n"
                                           │
                                           └──sidecar UDS──▶ processor
                                                             (enriches session logs)
```

The scanner sits in its own process for two reasons that come out of the
architecture, not from principle:

1. **Egress isolation.** The outbound identd probe has 2-second timeouts and
   runs in the critical path of nothing. If the scanner hangs, stalls, or
   crashes, the acceptor's hot path — accept, then bridge to the processor — is
   unaffected.

2. **Sandbox compatibility.** The acceptor and processor are locked down with
   `seccomp` (Linux) or `cap_enter` (FreeBSD) after startup; those sandboxes
   forbid `connect(2)` to arbitrary addresses. The scanner needs that syscall and
   gets a relaxed policy. Giving it its own process means each worker's sandbox
   can be tightened to exactly what *that role* needs.
   (See [`06-hardening.md`](06-hardening.md).)

The **sidecar connection** completes the loop: after the probe finishes, the
scanner pushes a `SessionMetadata` frame — peer, ident result, trace ID — over
a persistent UDS connection to the processor. The processor
stashes it by peer address and annotates subsequent log lines for that session.
Because the sidecar arrives asynchronously (the echo session may already be
under way), this is purely additive: if it never arrives, the session logs are
just less rich.

The result path doesn't go through the acceptor at all. The acceptor fires and
forgets; the scanner publishes directly to the processor. That's the pattern:
**fan out the slow side-effect, fan in the results where they're useful**.

## Why this matters for everything else

You've now seen the two moves the whole daemon is built from:

- **the supervisor owns listeners, workers borrow them** — so workers are
  disposable, and
- **an open connection is just an FD you can hand to another process** — so a
  connection can outlive the process that accepted it.

Rung 1 of the upgrade story uses the first. Rung 2 uses the second.

---

⇒ **Next:** [`02-upgrade-listener.md`](02-upgrade-listener.md) — upgrade rung 1,
re-exec keeping only the listener.
