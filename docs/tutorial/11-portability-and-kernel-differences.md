# 11 · Portability and kernel differences

> **After this page** you'll know which parts of this daemon are portable in the
> pleasant sense, which are merely conditionalized, and which are fundamentally
> shaped by kernel behavior.

This project is portable, but not by pretending every OS is the same. The code
works because it names the differences and designs around them.

## The same architecture, different kernel contracts

The top-level model is stable across platforms:

- supervisor owns listeners;
- workers talk over Unix sockets;
- upgrades preserve listeners and sometimes sessions;
- peer auth gates local control paths;
- workers drop privileges, then sandbox.

What changes is the kernel contract underneath each step.

## Peer credentials are not one API

The project uses:

- `SO_PEERCRED` on Linux,
- `LOCAL_PEERCRED` on BSD/macOS.

They solve the same problem but not with identical types or semantics. The docs
call this out because UDS auth is part of the control-plane trust boundary, not
an incidental implementation detail.

The summary lives in
[`../architecture.md#1-peer-auth`](../architecture.md#1-peer-auth).

## Linux seccomp and FreeBSD Capsicum are different kinds of sandbox

Linux seccomp is an explicit syscall allowlist. FreeBSD Capsicum is capability
mode: global namespaces disappear and only already-opened descriptors remain
usable.

Those are not cosmetic differences.

- Under **seccomp**, the work is curating the allowlist and discovering missing
  syscalls.
- Under **Capsicum**, the work is redesigning startup and I/O around pre-opened
  descriptors.

That is why the same `[security]` knob leads to different code shapes in
[`../../src/security.rs`](../../src/security.rs).

## FreeBSD strict mode forces FD-oriented startup

The sharpest portability lesson in the repo is FreeBSD upgrade under strict
sandboxing.

Because `cap_enter()` is inherited across `fork+exec`, a re-exec'd successor
starts life with path lookups already blocked. That creates two separate
problems:

1. **dynamic binaries fail before `main`**
   The kernel resolves `/libexec/ld-elf.so.1` by path during image activation,
   so a dynamically-linked successor dies in the kernel under capability mode.
2. **static binaries still fail during userspace startup**
   Config loading, sockets dir access, cert reload sources, and self-exe lookup
   are all path-based unless the code is written otherwise.

The fixes are correspondingly concrete:

- build a static binary with `scripts/build-static.sh`;
- pre-open config, socket-dir, cert-dir, key-dir, and self-exe FDs before
  entering capability mode;
- re-exec with `fexecve`;
- use `connectat` / `openat` against those inherited FDs instead of reopening
  paths.

That is why so much of the FreeBSD path in this codebase is about "adopt an FD"
instead of "open a path again".

## Some features are intentionally asymmetric

Portability does not mean every feature behaves identically everywhere.

- **macOS** is a development target; sandboxing warns and does not enforce.
- **FreeBSD scanner egress** cannot work under Capsicum because outbound
  `connect()` to arbitrary addresses returns `ECAPMODE`. The recommended posture
  is global strict sandboxing with `scanner = "off"` as an override.
- **`--target` upgrades** under FreeBSD strict mode are intentionally not
  supported, because an arbitrary new path cannot be pre-opened by the already
  sandboxed worker.

These are good examples of a healthy portability stance: state the limit and
design the operational contract around it.

## systemd is Linux-specific, but the daemon stays coherent without it

Socket activation and `sd_notify` are real integration points on Linux, but the
rest of the design does not depend on them.

When systemd env vars are absent, those features are no-ops. When they are
present, the code adopts listeners and emits readiness/watchdog signals.

That is a good portability boundary: OS integration as an optional outer layer,
not something smeared through the data plane.

## Portability work belongs in tests too

The repo's test strategy reflects the kernel split:

- macOS, Linux, and FreeBSD e2e runs are all named in
  [`../../e2e/README.md`](../../e2e/README.md);
- FreeBSD strict-mode upgrade explicitly requires the static build;
- platform-specific assertions exist where behavior genuinely differs.

That is the standard to copy. If the code has `#[cfg]`, the test plan should
usually say why.

## The deeper lesson

Most "portable" systems code is not portable because it found a universal API.
It is portable because it found a stable architecture that can survive several
different kernel APIs underneath.

In this project, that stable architecture is:

- listener ownership in the supervisor,
- explicit control and handoff channels,
- FD-oriented upgrade boundaries,
- and a security model applied after privileged setup.

Everything else is negotiation with the host OS.

---

*End of the tutorial series. ⇐ Back to [`00-overview.md`](00-overview.md).*
