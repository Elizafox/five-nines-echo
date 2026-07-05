#!/bin/sh
# Build a statically-linked echod for the host target.
#
# REQUIRED on FreeBSD for in-place upgrade under Capsicum capability mode
# (`sandbox = "strict"`): a dynamically-linked binary cannot re-exec under
# `cap_enter`, because the kernel resolves the ELF interpreter
# (`/libexec/ld-elf.so.1`) by path during execve, which returns ECAPMODE in
# the inherited capability mode. A static binary has no PT_INTERP, so the
# re-exec'd successor reaches `main` and adopts its config/socket/cert FDs from
# the parent. See docs/notes/static-link-investigation.md.
#
# `crt-static` is applied via the target-scoped `CARGO_TARGET_<triple>_RUSTFLAGS`
# (not a global `RUSTFLAGS`) and with an explicit `--target`, so the host
# proc-macro/build-script pipeline stays dynamic — a global flag would fail with
# "cannot produce proc-macro ... target does not support these crate types".
#
# The binary lands at target/<triple>/debug/echod (or release/ with
# `--release`). Point the e2e suite at it: python3 e2e/portability.py --bin <path>.
set -eu

triple=$(rustc -vV | awk '/^host:/ {print $2}')
var="CARGO_TARGET_$(printf '%s' "$triple" | tr 'a-z-' 'A-Z_')_RUSTFLAGS"
export "$var=-C target-feature=+crt-static"
exec cargo build --target "$triple" "$@"
