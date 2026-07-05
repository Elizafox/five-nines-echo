# 08 · Testability: designing a daemon you can prove

> **After this page** you'll know how this codebase keeps a multi-process,
> upgradeable daemon testable: what gets unit-tested, what only makes sense as
> an end-to-end scenario, and which code shapes make the difference.

This project is a useful tutorial only if its claims can be checked. "Zero
downtime", "survives crashes", and "still works under a sandbox" are not
properties you establish with a few happy-path unit tests; they are behaviors
that have to survive process boundaries, signals, inherited FDs, and kernel
differences.

That constraint feeds back into the implementation. A lot of the code is shaped
the way it is not just to *work*, but to be *provable in tests*.

## The three testing layers

The repo uses three layers, each for a different kind of risk.

1. **Inline unit tests** (`#[test]`, `#[tokio::test]`) for logic that can be
   isolated inside one process: config parsing, peer-auth checks, watchdog state
   transitions, schema compatibility, SCM helpers, health response shaping.
2. **Single-process async tests with real sockets or in-memory transports** for
   protocol edges that need Tokio and actual I/O semantics, but not a full
   supervisor tree.
3. **Black-box end-to-end tests** in [`../../e2e/README.md`](../../e2e/README.md)
   for behavior that only emerges across processes: rolling upgrade, session
   adoption, fork-and-drain TLS, signal handling, watchdog respawn, strict
   sandbox behavior, systemd contracts.

The key discipline is: **test the smallest surface that can actually falsify the
claim.** If a property depends on `fork+exec`, inherited FDs, or multiple roles
coordinating over UDS, forcing it into a unit test usually produces a fake test,
not a cheaper one.

## Shape the code so the hard part is small

The recurring pattern is to peel deterministic logic away from runtime shell
code.

- In [`../../src/supervisor/watchdog.rs`](../../src/supervisor/watchdog.rs),
  `record_exit` is the real entry point, but the state machine lives in
  `apply_exit(status, uptime)`. Tests can drive exact uptimes and exit codes
  without sleeping for real time.
- In [`../../src/scanner.rs`](../../src/scanner.rs), `ident_lookup` does the
  network dial, but the protocol exchange is split into `ident_exchange(stream,
  ...)` over generic `AsyncRead + AsyncWrite`. That lets tests use an in-memory
  duplex instead of binding privileged port 113.
- In [`../../src/health.rs`](../../src/health.rs), the test helper binds an
  ephemeral port and runs the accept loop directly, bypassing the production
  top-level binder so tests exercise HTTP behavior without depending on a fixed
  address.

This is the practical rule: **keep syscalls, environment access, and process
control at the edge; move branching logic inward behind ordinary function
arguments.**

## Prefer already-opened resources over path lookups

The upgrade and sandbox machinery already pushes the codebase toward FD-oriented
design, and that also helps testability.

When a function accepts an open listener, stream, or directory FD, a test can
manufacture one cheaply. When it insists on opening a hard-coded path itself,
the test has to recreate more of the world around it.

You can see that pattern in the handoff path:

- the supervisor hands workers listeners instead of having every worker call
  `bind(2)`;
- upgrade code passes session payloads and directory handles explicitly;
- FreeBSD strict mode depends on pre-opened FDs anyway, so tests can adopt the
  same seam the runtime uses.

That is one of the better architectural lessons in this repo: **an interface
that is good for capability-style security is often also good for tests.**

## Treat time, env vars, and signals as hostile dependencies

Most flaky daemon tests come from process-global state, not from business logic.
This codebase handles that directly.

- Env-var readers such as [`../../src/systemd.rs`](../../src/systemd.rs) keep
  mutation localized, and tests that touch the environment serialize through a
  crate-wide lock in [`../../src/test_env.rs`](../../src/test_env.rs) because
  `cargo test` runs in parallel by default. Rust 2024 makes `set_var`/`remove_var`
  unsafe — the environment is process-global and other threads or foreign code
  may read it — so that module hands out RAII guards (`EnvScope`, `EnvVarGuard`)
  whose lifetimes are tied to the held lock and which restore the prior value on
  drop. The lock therefore cannot be released while a test-set value is still
  visible, which is the property that makes the mutation safe.
- Time-based behavior uses Tokio test runtimes deliberately. Some tests run on
  `current_thread`; some watchdog/monitor tests also use `start_paused = true`
  so backoff and timeout behavior can be advanced deterministically.
- Signal-driven behavior is mostly proven in e2e, where a real child process can
  be signaled and observed, instead of trying to mock away the kernel contract.

If a test touches global process state, the burden is higher: isolate it, make
the serialization explicit, and keep the scope small.

## Failure-path coverage needs more than mocks

A lot of the interesting bugs here are in branches the kernel rarely gives you
on demand: successor never signals ready, session handoff decode fails, metrics
write breaks, TLS cert reload fails, control-plane decode fails.

That is why the repo has debug-only fault injection in
[`../../src/fault_inject.rs`](../../src/fault_inject.rs) and dedicated scenarios
in [`../../e2e/README.md`](../../e2e/README.md). Fault injection lets the tests
trip those branches *inside the real process topology* instead of rewriting the
code to make every internal call mockable.

That tradeoff is intentional. For this class of system, **deterministic failure
in the real wiring is usually more valuable than elaborate mocking in a fake
wiring**.

## Portability claims need platform-specific tests

This daemon makes kernel-specific promises: seccomp on Linux, Capsicum on
FreeBSD, warn-and-ignore sandboxing on macOS, `SO_PEERCRED` vs.
`LOCAL_PEERCRED`, `fexecve` under capability mode, systemd contracts where they
exist.

So the test strategy does not pretend one platform is enough. The e2e suite is
explicit about what runs where, what FreeBSD needs from the build
(`scripts/build-static.sh` for strict-mode in-place upgrade), and which
scenarios are asserting platform-specific behavior.

That is the standard to copy: if a design depends on kernel behavior, the test
plan has to name the kernel.

## What to copy into your own daemon

If you are building something like this yourself, the highest-value habits are:

- split protocol/state-machine logic away from spawning, signals, and path I/O;
- accept open resources or trait-based I/O where practical;
- use `current_thread` / paused time for timing-sensitive async tests;
- serialize tests that mutate env vars or other process-global state;
- reserve e2e for claims about multi-process behavior, upgrades, and sandboxing;
- add fault injection for rare but critical failure paths.

None of that is specific to an echo server. It is the reusable part.

---

⇒ **Next:** [`09-observability-and-debugging.md`](09-observability-and-debugging.md)
