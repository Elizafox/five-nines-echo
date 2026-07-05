# e2e tests

System-level Python suite that drives `echod` as a black-box
subprocess. Each test cleans up sockets, spawns its own supervisor in a
fresh process group, exercises one rung, and tears it back down.

These are NOT unit tests (those live next to the Rust source as `#[test]`
/ `#[tokio::test]` blocks). They're integration tests for behavior that
only emerges across processes — fork-and-drain, SCM_RIGHTS handoff,
supervisor↔worker control protocol, signal handling, schema versioning
across binary generations, drain/reload admin commands, etc.

## Running

From repo root, with a fresh build:

```bash
cargo build
python3 e2e/portability.py
```

Override the binary path with `--bin` or `FDPASS_BIN=`. The script
defaults to `../target/debug/echod` relative to itself, so it
finds the standard `cargo build` output when run from the repo root.

For quicker portability runs, the harness can list or filter tests by name:

```bash
python3 e2e/portability.py --list
python3 e2e/portability.py --match strict --match systemd
python3 e2e/portability.py --no-fault-inject
python3 e2e/portability.py --fault-inject-only
```

It expects to be run with the repo root as the working directory —
the TLS acceptor loads `certs/server.crt` and `certs/server.key` by
relative path. Generate the cert once with `./certs/gen.sh`.

**On FreeBSD, build a static binary and point `--bin` at it:**

```sh
./scripts/build-static.sh
python3 e2e/portability.py --bin target/$(rustc -vV | awk '/^host:/{print $2}')/debug/echod
```

In-place upgrade under `sandbox = "strict"` (Capsicum) needs the static
binary — a dynamically-linked successor can't re-exec under `cap_enter`
(the kernel resolves `/libexec/ld-elf.so.1` by path). With a dynamic
binary the upgrade-under-strict tests will fail at the re-exec. Linux and
macOS are unaffected; any `cargo build` works there.

## What it covers

54 scenarios. **44 behavioral:** plain echo, TLS echo, scanner, peer auth,
TOML config, `RUNTIME_DIRECTORY` override, systemd `Type=notify` + socket
activation + watchdog ping, processor-only upgrade preserving sessions, TLS cert reload on
SIGHUP, schema-version rejection, health endpoint (200 + 503), metrics
textfile, upgrade-counter increments, canary upgrade commit + abort, upgrade
rollback, session cap, TLS idle timeout,
per-IP rate limit, structured-log trace propagation, crash survival, TLS
fork-and-drain, watchdog backoff + fail, grandparent respawn, admin drain +
reload, worker privilege drop, sandbox strict, strict-mode in-place upgrade
commit, adopted-successor crash + respawn, scanner egress under strict +
per-role sandbox override.

**10 fault-injection** (via `[fault_inject]`, debug builds only — see
`src/fault_inject.rs`): TLS cert load + parse failure, upgrade ready-signal +
session-handoff failure, processor dispatch, control decode, SCM recvmsg, health
bind, metrics write, and schema-version rejection. These exercise the error
paths that are otherwise hard to trigger without kernel cooperation.

Passes on macOS, Linux (x86_64 and aarch64, glibc and musl), and
FreeBSD (aarch64). On FreeBSD the sandbox-strict test asserts the Capsicum
log line only; on macOS the sandbox knob warns-and-ignores, so the
test exercises plain + upgrade with sandbox config wired but inactive. The
seccomp allowlist is arch-aware: x86_64 libc still emits legacy syscalls
(`open`, `poll`, `access`, `epoll_wait`, …) that aarch64 replaced with the
`*at`/newer forms, so those are added under `cfg(target_arch = "x86_64")`.

The scanner-egress test pins the recommended FreeBSD posture: global
`sandbox = "strict"` plus `[security.sandbox_overrides] scanner = "off"`.
Under Capsicum the scanner's outbound identd `connect()` is ECAPMODE, so
it must stay out of cap mode; the test ensures an identd answers on :113
(its own fake one when run as root, else a host-provided identd) and
asserts the scan captured a non-empty `ident=` (proof egress fired),
guarding against a regression that silently re-sandboxes the scanner or
breaks the cap-mode-safe acceptor→scanner notification.

## Portability

Beyond this runtime suite, a static cross-check compiles the daemon for targets
we don't run here:

```bash
cargo check --target {aarch64,x86_64}-{linux-gnu,linux-musl,freebsd,netbsd}
```

The runtime suite's 54 scenarios all pass on macOS, Linux (x86_64 and aarch64,
glibc and musl), and FreeBSD (aarch64). On FreeBSD the sandbox-strict test asserts
the Capsicum log line only; on macOS the sandbox knob warns-and-ignores. In addition,
160+ inline `#[test]` / `#[tokio::test]` units next to the Rust source cover the
smaller pieces (config parsing, peer-uid resolution, SCM_RIGHTS roundtrip,
watchdog state machine, successor-wait + monitor state machine, systemd watchdog
beacon, schema-version compatibility, …).

## Coverage

`cargo-llvm-cov` measures unit + e2e together (the unit suite alone tops out
around 54% — most of the daemon is e2e-only):

```bash
cargo install cargo-llvm-cov
rustup component add llvm-tools-preview

# Build the instrumented daemon first: the e2e suite runs this real binary, and
# `cargo test` alone does not produce target/llvm-cov-target/debug/echod.
# `--cfg coverage` enables the pre-exec/pre-_exit coverage flush in the drain
# path (src/coverage.rs); without it acceptor/tls_drain.rs reads 0% and the
# combined total drops to ~78%.
RUSTFLAGS="-C instrument-coverage --cfg coverage" \
CARGO_TARGET_DIR=target/llvm-cov-target \
  cargo build

RUSTFLAGS="-C instrument-coverage --cfg coverage" \
LLVM_PROFILE_FILE='target/llvm-cov-target/cov/cov-%p-%8m.profraw' \
CARGO_TARGET_DIR=target/llvm-cov-target \
  cargo test
LLVM_PROFILE_FILE='target/llvm-cov-target/cov/e2e-%p-%8m.profraw' \
  python3 e2e/portability.py \
    --bin target/llvm-cov-target/debug/echod

# unit + e2e in one report (~93% lines on macOS)
cp target/llvm-cov-target/cov/*.profraw target/llvm-cov-target/
cargo llvm-cov report --summary-only
cargo llvm-cov report --html --output-dir target/coverage-report
```

The uncovered lines that remain are dominated by error paths (TLS cert load
failure, accept/decode errors, schema-version rejection) — which is exactly what
the 10 fault-injection scenarios above target. The rest are minor OS-specific
branches and intentional error-logging paths hard to trigger without kernel
cooperation.

## Why Python and not Rust?

The orchestration work (spawn + wait + observe + kill) is roughly the
same in either language. Python wins on conciseness (`subprocess.Popen`,
`socket.create_connection`, `ssl.create_default_context()` with one-line
self-signed-cert tolerance, `os.killpg`) and on the lack of a compile
step between "edit a test" and "see it run." Rust integration tests
might be worth writing for paths that benefit from sharing the daemon's
own types (e.g. wire-protocol structural assertions); these orchestration
tests don't.
