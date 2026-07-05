# 06 · Hardening: drop privileges, then sandbox

> **After this page** you'll understand the order workers lock themselves down
> in, why the supervisor stays unrestricted, and how the same upgrade story from
> the earlier rungs survives a syscall sandbox.

Both hardening knobs live under `[security]` and are **opt-in** — no-ops when
unset. They're applied in a specific order during worker startup, and the order
is the whole lesson.

## The startup sequence

```
adopt_or_bind_listener      // needs bind/socket — must happen pre-sandbox
open TLS cert source        // TLS only: pre-open cert/key dir FDs + load
drop_privileges             // needs setgroups/setgid/setuid
apply_sandbox               // seccomp (Linux) | cap_enter (FreeBSD)
signal_ready_to_parent      // first thing whose failure fails the upgrade
accept loop                 // untrusted network input from here on
```

Read it top to bottom: **acquire every privileged resource first, then drop the
ability to acquire more, then sandbox, and only then touch the network.** Each
step removes power the later steps no longer need. By the time a byte of client
data is read, the process can't open new files, change uid, or call most
syscalls. The dispatcher is in `security.rs`.

## Privilege drop

`drop_privileges` does `setgroups(0,NULL)` → `setgid` → `setuid`, in exactly that
POSIX-required order (get it wrong and you drop the group while you can no longer
change it). Then a defense-in-depth check: it verifies `setuid(0)` *fails*, so a
kernel bug that left the saved-set-uid at 0 aborts startup instead of leaving a
re-rootable worker.

**The supervisor deliberately does not drop.** `kill(2)` requires the sender's
real/saved-set-uid to match the target's or be root; if the supervisor dropped
to the workers' uid, a runaway worker that `setuid`'d elsewhere couldn't be
`SIGKILL`'d. The production model is: supervisor as root (via the systemd unit),
workers drop to a service account. Same reasoning keeps the supervisor
*unsandboxed* — it needs to signal arbitrary children, and a sandbox bug in
worker setup shouldn't take the whole daemon down.

## Sandbox: two kernels, two philosophies

`sandbox = "off" | "strict" | "log"`. macOS warns-and-ignores (it's a dev
target). The two real implementations are instructively different:

- **Linux — seccomp-bpf**: an explicit *allowlist* of ~90 syscalls; anything off
  the list traps to `SIGSYS` and kills the process. The list was derived
  empirically (`strace -f` + iterating under `"log"` mode, which substitutes
  `SECCOMP_RET_LOG` so you can find what to add before flipping back to
  `"strict"`). It's a per-syscall whitelist you maintain.
- **FreeBSD — Capsicum (`cap_enter`)**: no per-syscall list at all. The process
  enters *capability mode*, where the kernel revokes access to every **global
  namespace** — paths, PIDs of non-descendants, sysctls. You can only act through
  file descriptors you already hold. It's coarser but categorical.

Full allowlist rationale and the per-OS picture:
[`../architecture.md#security-layers`](../architecture.md#security-layers) and
[`../architecture.md#3-sandbox`](../architecture.md#3-sandbox).

## How the upgrade story survives the sandbox

This is where the earlier rungs and this page collide, and it's the sharpest
systems lesson in the project. Capsicum is inherited across `fork+exec`, so a
re-exec'd successor (rungs 1–3) does its *entire* startup in capability mode —
where every path-based `open` returns `ECAPMODE`. Two consequences:

1. **A dynamically-linked binary can't even start.** The kernel resolves the ELF
   interpreter `/libexec/ld-elf.so.1` *by path* during image activation, before
   any userspace runs — so it dies in the kernel. The fix is a **static binary**
   (no `PT_INTERP`); build with `scripts/build-static.sh`.
2. **Path-based startup fails.** Even static, the successor hits `Config::load`,
   the sockets dir, the cert/key dirs, `current_exe()` — all paths. The fix
   generalizes the rung-1 `FDPASS_LISTENER_FD` idiom: **pre-open each of those as
   an FD before `cap_enter` and hand the FD numbers to the successor**, which
   adopts them instead of opening paths.

The same FD-not-path discipline runs through the data plane: the
acceptor → processor and acceptor→scanner connects use `connectat(2)` against a
pre-opened directory FD (a path-based `connect` would be `ECAPMODE`), and TLS
cert reload uses `openat` on a pre-opened cert-dir FD. The reasoning, and the
constraints (e.g. `drop_uid`/`drop_gid` must resolve to numeric IDs before
`cap_enter`, because NSS name lookup is path-based; `--target` upgrades require
`sandbox = "off"`), are documented in full at
[`../architecture.md#security-layers`](../architecture.md#security-layers) and in
the rustdoc on `security::freebsd_capsicum`.

One implementation detail matters for safety: FreeBSD self-upgrade execs the
pre-opened binary FD with `fexecve`. The `pre_exec` hook prepares argv/envp C
strings and pointer vectors before `fork`; after `fork` it only calls `fexecve`
or `_exit`, so it does not allocate inside the async-signal-unsafe child window.

---

⇒ **Next:** [`07-operating.md`](07-operating.md) — driving and observing the
running daemon.
