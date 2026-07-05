#!/usr/bin/env python3
"""
Runtime portability suite. Exercises the architectural rungs that are most
likely to differ between Unix variants (SCM_RIGHTS, kqueue-vs-epoll readiness,
fork-and-drain, watchdog backoff). Self-contained so it can be dropped into a
Linux/BSD VM with just the binary and run.

Usage (from repo root):
    cargo build
    python3 e2e/portability.py [--bin /path/to/echod]

The default `--bin` resolves relative to the script: `../target/debug/
echod`. Override with `--bin` or `FDPASS_BIN=...`.

Exits 0 iff every test passes.

Each test:
  - cleans up sockets,
  - spawns its own supervisor in a fresh process group,
  - exercises the rung,
  - tears the supervisor back down.

Identd assertions come in two flavors. Tests that don't control an identd
(`test_scanner_fires`) only check that a scan *fired* (sidecar metadata
received), since identd is unusual on Linux servers (the macOS host happens to
have one). Tests that stand up a mock identd (`_MockIdentd`) and point
`identd_port` at it demand ident=Some(...) as a deterministic egress proof.
"""
import os, sys, socket, ssl, subprocess, time, signal, re, tempfile, argparse, traceback, threading
from pathlib import Path

# ----- binary inspection -------------------------------------------------

def _is_static_elf(path):
    """Return True if `path` is a statically-linked ELF binary (no PT_INTERP segment).
    Used on FreeBSD to gate tests that require a static binary for cap-mode upgrades."""
    try:
        with open(path, "rb") as f:
            ehdr = f.read(64)
        if len(ehdr) < 64 or ehdr[:4] != b"\x7fELF" or ehdr[4] != 2 or ehdr[5] != 1:
            return False  # not 64-bit LE ELF; assume dynamic (conservative)
        import struct
        ph_off, = struct.unpack_from("<Q", ehdr, 32)
        ph_ent, = struct.unpack_from("<H", ehdr, 54)
        ph_num, = struct.unpack_from("<H", ehdr, 56)
        if ph_ent == 0:
            return True
        PT_INTERP = 3
        with open(path, "rb") as f:
            for i in range(ph_num):
                f.seek(ph_off + i * ph_ent)
                entry = f.read(4)
                if len(entry) == 4:
                    p_type, = struct.unpack_from("<I", entry)
                    if p_type == PT_INTERP:
                        return False
        return True
    except OSError:
        return False

# ----- sockets / cleanup -------------------------------------------------

SOCKS = [
    "/tmp/fdpass-proc.sock",
    "/tmp/fdpass-scanner.sock",
    "/tmp/fdpass-admin.sock",
    "/tmp/fdpass-drainer.sock",
    "/tmp/fdpass-spawner.sock",
    "/tmp/fdpass-ctrl-processor.sock",
    "/tmp/fdpass-ctrl-plain.sock",
    "/tmp/fdpass-ctrl-tls.sock",
    "/tmp/fdpass-ctrl-scanner.sock",
]

def cleanup_sockets():
    for s in SOCKS:
        try: os.remove(s)
        except FileNotFoundError: pass

def kill_lingering(bin_path):
    subprocess.run(["pkill", "-f", f"{bin_path} supervisor"], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.3)

# ----- supervisor lifecycle ----------------------------------------------

class Supervisor:
    def __init__(self, bin_path, log_path, config_path=None, plain_port=7070,
                 extra_env=None, preexec=None, pass_fds=()):
        self.bin_path = bin_path
        self.log_path = log_path
        self.config_path = config_path
        self.plain_port = plain_port
        self.extra_env = extra_env or {}
        self.preexec = preexec
        self.pass_fds = pass_fds
        self.proc = None
        self.logf = None

    def __enter__(self):
        kill_lingering(self.bin_path)
        cleanup_sockets()
        try: os.remove(self.log_path)
        except FileNotFoundError: pass
        self.logf = open(self.log_path, "wb")
        cmd = [self.bin_path, "supervisor"]
        if self.config_path:
            cmd += ["--config", self.config_path]
        # When extra_env is empty we pass env=None so Popen uses os.environ
        # at exec-time — that lets the user's preexec_fn set env vars
        # (e.g. LISTEN_PID=os.getpid()) that the child actually sees.
        env = None
        if self.extra_env:
            env = os.environ.copy()
            env.update(self.extra_env)
        def preexec():
            if self.preexec:
                self.preexec()
            os.setsid()
        self.proc = subprocess.Popen(
            cmd,
            stdout=self.logf, stderr=self.logf,
            preexec_fn=preexec,
            env=env,
            pass_fds=self.pass_fds,
        )
        # Wait for plain port to be listening.
        for _ in range(60):
            try:
                with socket.create_connection(("127.0.0.1", self.plain_port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError(f"supervisor never opened plain port {self.plain_port}")
        time.sleep(0.3)
        return self

    def __exit__(self, *_):
        try:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
        self.logf.close()

    def status(self):
        return subprocess.run(
            [self.bin_path, "status"], capture_output=True, text=True, timeout=10,
        ).stdout

    def upgrade(self, *args):
        return subprocess.run(
            [self.bin_path, "upgrade", *args], capture_output=True, text=True, timeout=20,
        )

    def pid_of(self, role, retries=15):
        for _ in range(retries):
            for line in self.status().splitlines():
                if line.startswith(role + " "):
                    cols = re.split(r"\s+", line.strip())
                    if cols[2] != "-":
                        return int(cols[2])
            time.sleep(0.15)
        return None

    def grep(self, pattern):
        """One-shot grep over the log file as it stands now."""
        with open(self.log_path) as f:
            return [l for l in f if re.search(pattern, l)]

    def grep_eventually(self, pattern, timeout=2.0):
        """Like `grep`, but polls until the pattern appears or `timeout`
        expires. Use this when the log line is written asynchronously after
        whatever the test just did — Linux's redirected-stderr buffering can
        delay writes that macOS happens to flush immediately."""
        deadline = time.time() + timeout
        while True:
            hits = self.grep(pattern)
            if hits or time.time() > deadline:
                return hits
            time.sleep(0.05)

# ----- helpers -----------------------------------------------------------

def read_line(s, timeout=3.0):
    s.settimeout(timeout)
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = s.recv(64)
        if not chunk:
            return buf.decode(errors="replace")
        buf += chunk
    return buf.decode().rstrip("\n")

class _MockIdentd:
    """Minimal RFC-1413 server for testing. Binds on an OS-assigned port and returns
    `lport, rport : USERID : UNIX : <username>` for every query. Use as a context manager."""
    def __init__(self, username="test-user"):
        self.username = username
        self.port = None
        self._lsn = None
        self._thread = None
        self._running = False

    def __enter__(self):
        self._lsn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._lsn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._lsn.bind(("127.0.0.1", 0))
        self.port = self._lsn.getsockname()[1]
        self._lsn.listen(8)
        self._lsn.settimeout(0.2)
        self._running = True
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def _serve(self):
        while self._running:
            try:
                conn, _ = self._lsn.accept()
            except OSError:
                continue
            try:
                conn.settimeout(1.0)
                data = b""
                while not data.endswith(b"\n"):
                    chunk = conn.recv(64)
                    if not chunk:
                        break
                    data += chunk
                query = data.decode(errors="replace").strip()
                parts = query.split(",", 1)
                if len(parts) == 2:
                    lport, rport = parts[0].strip(), parts[1].strip()
                    resp = f"{lport}, {rport} : USERID : UNIX : {self.username}\r\n"
                else:
                    resp = f"{query} : ERROR : INVALID-PORT\r\n"
                conn.sendall(resp.encode())
            except OSError:
                pass
            finally:
                conn.close()

    def __exit__(self, *_):
        self._running = False
        self._lsn.close()
        self._thread.join(timeout=1.0)

def open_tls():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    raw = socket.create_connection(("127.0.0.1", 7071), timeout=2)
    return ctx.wrap_socket(raw, server_hostname="localhost")

# ----- test cases --------------------------------------------------------

def test_plain_echo(bin_path, log_path):
    """Basic plain echo: accept → UDS bridge to processor → echo back."""
    with Supervisor(bin_path, log_path) as sup:
        s = socket.create_connection(("127.0.0.1", 7070), timeout=2)
        s.sendall(b"portability-check\n")
        reply = read_line(s)
        assert reply == "portability-check", f"got {reply!r}"
        s.close()
        # Confirm the processor served this as a UDS bridge session — the plain acceptor forwards
        # over UDS, same shape as TLS, with no SCM fd handoff.
        sessions = sup.grep(r"new uds session .*role=plain")
        assert sessions, "no plain UDS session log entry — wrong code path taken?"

def test_tls_echo(bin_path, log_path):
    """TLS path is byte-bridge over UDS (Session preamble); still works."""
    with Supervisor(bin_path, log_path) as sup:
        s = open_tls()
        s.sendall(b"tls-check\n")
        reply = read_line(s)
        assert reply == "tls-check", f"got {reply!r}"
        s.close()
        sess = sup.grep(r"new uds session.*role=tls")
        assert sess, "no TLS session log"

def test_scanner_fires(bin_path, log_path):
    """Scanner publishes metadata for every connect, regardless of identd presence."""
    with Supervisor(bin_path, log_path) as sup:
        s = socket.create_connection(("127.0.0.1", 7070), timeout=2)
        peer_port = s.getsockname()[1]
        s.sendall(b"ping\n")
        read_line(s)
        s.close()
        time.sleep(3.0)  # scanner's 2s identd timeout + slack
        meta = sup.grep(r"sidecar metadata received.*peer=.*:" + str(peer_port))
        assert meta, f"no sidecar metadata for peer port {peer_port}"
        # NOTE: we deliberately don't assert ident=Some. Plenty of Linux/BSD
        # boxes don't run identd; the test is just "did the scan fire and
        # publish via sidecar". ident_lookup returning None is normal.

def test_scanner_ident_captured(bin_path, log_path):
    """Mock identd on a configurable port: scanner must capture ident=Some(...)."""
    cfg_dir = tempfile.mkdtemp(prefix="fdpass-ident-present-")
    cfg_path = os.path.join(cfg_dir, "fdpass.toml")
    with _MockIdentd("test-user") as mock:
        with open(cfg_path, "w") as f:
            f.write(f"identd_port = {mock.port}\n")
        with Supervisor(bin_path, log_path, config_path=cfg_path) as sup:
            s = socket.create_connection(("127.0.0.1", 7070), timeout=2)
            s.sendall(b"ping\n")
            read_line(s)
            s.close()
            hits = sup.grep_eventually(r'scan complete.*ident=Some\(', timeout=5)
            assert hits, (
                "scanner did not log ident=Some(...) — mock identd on port "
                f"{mock.port} not reached, or identd_port config not wired?"
            )
            assert "test-user" in "\n".join(hits), (
                "ident=Some(...) present but username 'test-user' missing — "
                "wrong response parsed?"
            )

def test_scanner_no_ident_when_no_identd(bin_path, log_path):
    """With nothing listening on identd_port, scanner logs ident=None and still publishes metadata."""
    cfg_dir = tempfile.mkdtemp(prefix="fdpass-ident-absent-")
    cfg_path = os.path.join(cfg_dir, "fdpass.toml")
    # Bind to claim an OS-assigned port, then close it so the port is free but
    # nothing is listening — the scanner's connect() will get ECONNREFUSED fast.
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    dead_port = probe.getsockname()[1]
    probe.close()
    with open(cfg_path, "w") as f:
        f.write(f"identd_port = {dead_port}\n")
    with Supervisor(bin_path, log_path, config_path=cfg_path) as sup:
        s = socket.create_connection(("127.0.0.1", 7070), timeout=2)
        peer_port = s.getsockname()[1]
        s.sendall(b"ping\n")
        read_line(s)
        s.close()
        # ECONNREFUSED is near-instant; 3s is ample even with scheduler jitter
        hits = sup.grep_eventually(r"scan complete.*ident=None", timeout=3)
        assert hits, (
            "scanner did not log ident=None after connect-refused identd — "
            "dial may have hung or unexpectedly succeeded"
        )
        meta = sup.grep(r"sidecar metadata received.*peer=.*:" + str(peer_port))
        assert meta, "sidecar metadata not published even though scan fired"

def test_processor_upgrade_preserves_tcp(bin_path, log_path):
    """In-flight plain session survives a processor-only upgrade: the processor re-execs and adopts
    its UDS bridge session, while the thin acceptor keeps running so the client never notices."""
    with Supervisor(bin_path, log_path) as sup:
        s = socket.create_connection(("127.0.0.1", 7070), timeout=2)
        s.sendall(b"before-upgrade\n")
        assert read_line(s) == "before-upgrade"
        r = sup.upgrade("--role", "processor")
        assert r.returncode == 0, r.stderr
        s.sendall(b"after-upgrade\n")
        assert read_line(s) == "after-upgrade", "in-flight session lost across processor upgrade"
        s.close()
        adopted = sup.grep(r"adopting in-flight sessions count=")
        assert adopted, "no adopt-sessions log"

def test_second_generation_upgrade_readopts_not_respawns(bin_path, log_path):
    """A worker's *second* upgrade must be adopted by generation just like the first, not raced by
    a fresh gen-0 respawn (follow-up review #6).

    After the first processor upgrade the supervisor sits in monitor_successor: the gen-1 successor
    is a grandchild it never spawned, so it's no longer in child.wait() for it. A further upgrade
    advances the generation on the control link, and monitor_successor must recognize that and
    re-adopt rather than fall back to the weaker writer-absence heuristic. This drives the
    generation-advance (Readopted) path end to end and asserts the in-flight session survives both
    hops."""
    with Supervisor(bin_path, log_path) as sup:
        s = socket.create_connection(("127.0.0.1", 7070), timeout=2)
        s.sendall(b"gen0\n")
        assert read_line(s) == "gen0"

        # First upgrade: the gen-0 worker commits and the supervisor adopts the gen-1 successor.
        r = sup.upgrade("--role", "processor")
        assert r.returncode == 0, r.stderr
        assert sup.grep_eventually(r"successor adopted; standing down respawn", timeout=5), \
            "first upgrade never adopted a successor"
        s.sendall(b"gen1\n")
        assert read_line(s) == "gen1", "in-flight session lost across first upgrade"
        time.sleep(0.3)  # let the supervisor settle into monitor_successor

        # Second upgrade: the *adopted* successor upgrades itself. The supervisor observes only the
        # generation advance on the control link (not a child exit), so this exercises the
        # re-adoption path rather than wait_for_successor.
        r = sup.upgrade("--role", "processor")
        assert r.returncode == 0, r.stderr
        # This line is emitted ONLY by the re-adoption arm — the #6 fix.
        assert sup.grep_eventually(r"adopted successor upgraded itself; re-adopting", timeout=5), \
            "second upgrade did not re-adopt (monitor_successor missed the generation advance)"

        # Continuity: the same in-flight session survived both upgrades end to end.
        s.sendall(b"gen2\n")
        assert read_line(s) == "gen2", "in-flight session lost across second upgrade"
        s.close()

        # Re-adoption stands down the respawn, so the worker was never declared lost and respawned
        # fresh between the two upgrades.
        assert not sup.grep(r"adopted successor disappeared"), \
            "processor was respawned fresh instead of re-adopted across the second upgrade"

def _pgrep_f(needle):
    """Return list of PIDs whose full argv contains `needle`."""
    out = subprocess.run(
        ["pgrep", "-f", needle], capture_output=True, text=True,
    )
    if out.returncode not in (0, 1):
        raise RuntimeError(f"pgrep failed: {out.stderr}")
    return [int(x) for x in out.stdout.split() if x.strip()]

def test_grandparent_respawns_supervisor(bin_path, log_path):
    """Grandparent respawns the supervisor after a hard kill; workers come back."""
    kill_lingering(bin_path)
    cleanup_sockets()
    try: os.remove(log_path)
    except FileNotFoundError: pass
    logf = open(log_path, "wb")
    proc = subprocess.Popen(
        [bin_path, "grandparent"],
        stdout=logf, stderr=logf,
        preexec_fn=os.setsid,
    )
    try:
        # Wait for plain port (first supervisor generation).
        for _ in range(60):
            try:
                with socket.create_connection(("127.0.0.1", 7070), timeout=0.2): break
            except OSError: time.sleep(0.1)
        else:
            raise RuntimeError("grandparent never opened plain port")
        time.sleep(0.3)

        with socket.create_connection(("127.0.0.1", 7070), timeout=2) as s:
            s.sendall(b"before-kill\n")
            assert read_line(s) == "before-kill"

        # Locate the supervisor child of grandparent. grandparent's own argv is
        # "echod grandparent", so "echod supervisor" only matches
        # the child process.
        sup_pids = _pgrep_f(f"{bin_path} supervisor")
        assert len(sup_pids) == 1, f"expected one supervisor, found {sup_pids}"
        old_sup = sup_pids[0]
        os.kill(old_sup, signal.SIGKILL)

        # Wait for the new supervisor to come up and bind plain.
        deadline = time.time() + 15
        new_sup = None
        while time.time() < deadline:
            pids = _pgrep_f(f"{bin_path} supervisor")
            if pids and pids[0] != old_sup:
                new_sup = pids[0]
                break
            time.sleep(0.2)
        assert new_sup is not None, "grandparent never respawned supervisor"

        # Plain listener must recover too.
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", 7070), timeout=0.2): break
            except OSError: time.sleep(0.2)
        else:
            raise RuntimeError("plain port never came back after respawn")
        time.sleep(0.3)

        with socket.create_connection(("127.0.0.1", 7070), timeout=2) as s:
            s.sendall(b"after-respawn\n")
            assert read_line(s) == "after-respawn"
    finally:
        try: os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except ProcessLookupError: pass
        try: proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try: os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except ProcessLookupError: pass
            proc.wait()
        logf.close()

def test_grandparent_supervisor_refuses_self_upgrade_on_sighup(bin_path, log_path):
    """Under grandparent mode the supervisor must REFUSE a SIGHUP self-upgrade.
    On commit do_self_upgrade calls process::exit(UPGRADE_COMMIT_EXIT_CODE); the
    grandparent reacts to that exit with a killpg that would take out the very
    successor the supervisor just handed off to. So the SIGHUP arm checks
    FDPASS_UNDER_GRANDPARENT (set by the grandparent on the supervisor child) and
    logs a refusal instead of calling do_self_upgrade.

    Complements test_supervisor_self_upgrade_on_sighup, which drives the *commit*
    branch when NOT under a grandparent. This covers the guard branch — the
    grandparent-refusal path that previously had no e2e coverage."""
    kill_lingering(bin_path)
    cleanup_sockets()
    try: os.remove(log_path)
    except FileNotFoundError: pass
    logf = open(log_path, "wb")
    proc = subprocess.Popen(
        [bin_path, "grandparent"],
        stdout=logf, stderr=logf,
        preexec_fn=os.setsid,
    )
    def grep_log(pattern):
        with open(log_path) as f:
            return [l for l in f if re.search(pattern, l)]
    def grep_log_eventually(pattern, timeout):
        deadline = time.time() + timeout
        while True:
            hits = grep_log(pattern)
            if hits or time.time() > deadline:
                return hits
            time.sleep(0.05)
    try:
        # Wait for the plain port: the supervisor booted under the grandparent.
        for _ in range(60):
            try:
                with socket.create_connection(("127.0.0.1", 7070), timeout=0.2): break
            except OSError: time.sleep(0.1)
        else:
            raise RuntimeError("grandparent never opened plain port")
        time.sleep(0.3)

        with socket.create_connection(("127.0.0.1", 7070), timeout=2) as s:
            s.sendall(b"before-sighup\n")
            assert read_line(s) == "before-sighup"

        # Exactly one supervisor child (argv "echod supervisor"; the grandparent's
        # own "echod grandparent" argv doesn't match), running under grandparent
        # mode with FDPASS_UNDER_GRANDPARENT=1.
        sup_pids = _pgrep_f(f"{bin_path} supervisor")
        assert len(sup_pids) == 1, f"expected one supervisor, found {sup_pids}"
        sup = sup_pids[0]

        os.kill(sup, signal.SIGHUP)

        # The guard branch logs a refusal warning; do_self_upgrade is never called.
        assert grep_log_eventually(
            r"SIGHUP ignored: supervisor self-upgrade is not supported under", timeout=5
        ), "supervisor never logged the grandparent-mode SIGHUP refusal"

        # Give any (erroneous) self-upgrade time to unfold, then prove it didn't:
        # neither self-upgrade log line appears, and the supervisor is the SAME
        # process. Had it self-upgraded, process::exit would have tripped the
        # grandparent's killpg and a fresh supervisor with a new pid would now own
        # the port.
        time.sleep(1.0)
        assert not grep_log(r"self-upgrading supervisor"), \
            "supervisor entered the self-upgrade branch under grandparent mode despite the guard"
        assert not grep_log(r"self-upgrade committed"), \
            "supervisor committed a self-upgrade under grandparent mode"
        still = _pgrep_f(f"{bin_path} supervisor")
        assert still == [sup], \
            f"supervisor pid changed after a refused SIGHUP ({sup} -> {still}); expected the same process"

        # Service keeps flowing on the original, un-upgraded supervisor.
        with socket.create_connection(("127.0.0.1", 7070), timeout=2) as s:
            s.sendall(b"after-sighup\n")
            assert read_line(s) == "after-sighup"
    finally:
        try: os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except ProcessLookupError: pass
        try: proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try: os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except ProcessLookupError: pass
            proc.wait()
        logf.close()

def test_supervisor_self_upgrade_on_sighup(bin_path, log_path):
    """SIGHUP to the *supervisor* triggers a two-phase self-upgrade: it spawns a
    successor that inherits every control/listener FD, adopts the running workers,
    signals ready, and the old supervisor process::exit()s. Workers keep their
    pids (adopted, not restarted), the in-flight plain session survives, and the
    successor serves fresh connections — no window where the port is down.

    Exercises supervisor/self_upgrade.rs::do_self_upgrade all the way to its
    commit branch (previously 0% covered: no other scenario SIGHUPs the
    supervisor; the TLS-cert-reload test SIGHUPs the acceptor worker instead)."""
    with Supervisor(bin_path, log_path) as sup:
        old_sup = sup.proc.pid
        try:
            plain_pid_before = sup.pid_of("plain")
            proc_pid_before = sup.pid_of("processor")
            assert plain_pid_before and proc_pid_before, "couldn't read worker pids pre-upgrade"

            # In-flight plain session that must survive the supervisor swap.
            s = socket.create_connection(("127.0.0.1", 7070), timeout=2)
            s.sendall(b"before-self-upgrade\n")
            assert read_line(s) == "before-self-upgrade"

            # SIGHUP the supervisor process itself (not a worker) → self-upgrade.
            os.kill(old_sup, signal.SIGHUP)

            assert sup.grep_eventually(
                r"SIGHUP received; self-upgrading supervisor", timeout=5
            ), "supervisor never logged the SIGHUP self-upgrade"
            # This line is emitted from do_self_upgrade's Ok/commit arm — the coverage target.
            assert sup.grep_eventually(
                r"self-upgrade committed", timeout=10
            ), "self-upgrade never committed (do_self_upgrade commit branch not reached)"

            # A successor supervisor with a fresh pid takes over.
            deadline = time.time() + 15
            new_sup = None
            while time.time() < deadline:
                live = [p for p in _pgrep_f(f"{bin_path} supervisor") if p != old_sup]
                if live:
                    new_sup = live[0]
                    break
                time.sleep(0.2)
            assert new_sup is not None, "no successor supervisor after SIGHUP self-upgrade"

            # A second "supervisor generation" line == the successor booted (generation 1).
            gens = sup.grep_eventually(r"supervisor generation", timeout=5)
            assert len(gens) >= 2, f"expected successor generation log line, saw {len(gens)}"

            # Continuity: the in-flight session still echoes through the swap.
            s.sendall(b"after-self-upgrade\n")
            assert read_line(s) == "after-self-upgrade", \
                "in-flight plain session lost across supervisor self-upgrade"
            s.close()

            # Workers were adopted, not respawned: pids unchanged.
            plain_pid_after = sup.pid_of("plain")
            proc_pid_after = sup.pid_of("processor")
            assert plain_pid_after == plain_pid_before, \
                f"plain worker restarted across self-upgrade ({plain_pid_before} -> {plain_pid_after}); expected adoption"
            assert proc_pid_after == proc_pid_before, \
                f"processor worker restarted across self-upgrade ({proc_pid_before} -> {proc_pid_after}); expected adoption"

            # Successor serves new connections.
            with socket.create_connection(("127.0.0.1", 7070), timeout=2) as s2:
                s2.sendall(b"post-self-upgrade\n")
                assert read_line(s2) == "post-self-upgrade", \
                    "successor supervisor not serving new plain connections"
        finally:
            # The old supervisor process::exit()s on commit, but its successor and
            # the *adopted* workers keep running in the old supervisor's process
            # group (pgid == old_sup, established via setsid at spawn). Supervisor
            # .__exit__ keys cleanup off the now-exited old_sup pid, and
            # kill_lingering only matches "…supervisor" argv — so without this the
            # orphaned TLS/plain workers survive, hold their ports, and break the
            # next test. killpg takes the pgid directly, so no getpgid on the
            # exited group leader is needed.
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(old_sup, sig)
                except (ProcessLookupError, PermissionError):
                    break
                time.sleep(0.4)

def test_crash_survival(bin_path, log_path):
    """A: supervisor owns the listener; queued connections survive worker crash."""
    with Supervisor(bin_path, log_path) as sup:
        plain_pid = sup.pid_of("plain")
        assert plain_pid, "couldn't read plain pid"
        os.kill(plain_pid, signal.SIGKILL)
        # Race to connect during the watchdog backoff window
        deadline = time.time() + 2
        s = None
        while time.time() < deadline:
            try:
                s = socket.create_connection(("127.0.0.1", 7070), timeout=0.2)
                break
            except OSError:
                time.sleep(0.05)
        assert s is not None, "couldn't connect during plain backoff"
        s.sendall(b"queued-thru-crash\n")
        reply = read_line(s, timeout=4.0)
        assert reply == "queued-thru-crash", f"got {reply!r}"
        s.close()

def test_fork_and_drain(bin_path, log_path):
    """TLS fork-and-drain: kept TLS session works after the parent execs, and a
    graceful client close lets the drain child finish cleanly.

    Closing session A mid-drain drives the child's SessionDone + Complete emit
    paths and the supervisor drainer's matching log arms — all of which stay
    uncovered if the session is merely held open until teardown."""
    with Supervisor(bin_path, log_path) as sup:
        a = open_tls()
        a.sendall(b"baseline\n")
        assert read_line(a) == "baseline"
        # Background --include-tls so we can talk on session A meanwhile
        upg = subprocess.Popen(
            [bin_path, "upgrade", "--include-tls"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        time.sleep(0.7)
        a.sendall(b"post-fork\n")
        try:
            reply = read_line(a, timeout=3.0)
            assert reply == "post-fork", f"got {reply!r} — child drainer didn't echo"
            # Drainer logged the child's Hello on connect.
            assert sup.grep_eventually(r"drainer: child connected", timeout=3), \
                "expected drainer Hello log"
            # Graceful close → the child finishes the (only) session and exits
            # clean, so the supervisor-side drainer logs SessionDone then Complete.
            a.close()
            assert sup.grep_eventually(r"drainer: session done", timeout=5), \
                "expected drainer SessionDone after client close"
            assert sup.grep_eventually(r"drainer: all sessions drained", timeout=5), \
                "expected drainer Complete after the last session drained"
        finally:
            upg.communicate(timeout=15)

def test_fork_and_drain_deadline(bin_path, log_path):
    """A TLS session kept active past the drain child's 5s hard deadline forces
    DeadlineExit + hard-_exit (drainer logs 'deadline hit; force-exit').

    The child's per-session idle timeout is 1.5s, so an idle session would just
    drain clean; we send keepalive traffic (<1.5s apart) to hold it open until
    the deadline thread fires."""
    with Supervisor(bin_path, log_path) as sup:
        a = open_tls()
        a.sendall(b"baseline\n")
        assert read_line(a) == "baseline"
        upg = subprocess.Popen(
            [bin_path, "upgrade", "--include-tls"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        upg.communicate(timeout=15)
        fired = False
        end = time.time() + 9
        while time.time() < end:
            try:
                a.sendall(b"keepalive\n")
                read_line(a, timeout=0.7)
            except OSError:
                pass  # child _exited at the deadline; the socket is gone
            if sup.grep(r"drainer: deadline hit; force-exit"):
                fired = True
                break
            time.sleep(0.4)
        try:
            a.close()
        except OSError:
            pass
        assert fired, \
            "expected DeadlineExit after keeping the session past the 5s deadline"

def test_toml_config(bin_path, log_path):
    """Supervisor honors a TOML --config: custom plain_port + allowlist."""
    cfg_dir = tempfile.mkdtemp(prefix="fdpass-cfg-")
    cfg_path = os.path.join(cfg_dir, "fdpass.toml")
    my_uid = os.getuid()
    with open(cfg_path, "w") as f:
        f.write(
            "plain_port = 18070\n"
            "tls_port = 18071\n"
            "ready_timeout_secs = 3\n"
            "\n"
            "[auth]\n"
            f"allowed_uids = [{my_uid}]\n"
        )
    with Supervisor(bin_path, log_path, config_path=cfg_path, plain_port=18070):
        s = socket.create_connection(("127.0.0.1", 18070), timeout=2)
        s.sendall(b"toml-config\n")
        assert read_line(s) == "toml-config"
        s.close()

def test_workers_sandbox_strict(bin_path, log_path):
    """sandbox=strict applies the per-OS syscall sandbox.

    Linux: seccomp allowlist; full data-plane and upgrade still work.
    FreeBSD: Capsicum cap_enter — workers enter capability mode but the
             current data-plane path-based UDS connect and execve-based
             upgrade are blocked by design, so we only assert each worker
             logged entry into cap mode.
    macOS: warn-and-ignore (no sandbox impl); same data-plane assertions
           as Linux work because nothing was actually restricted."""
    cfg_dir = tempfile.mkdtemp(prefix="fdpass-sandbox-")
    cfg_path = os.path.join(cfg_dir, "fdpass.toml")
    my_uid = os.getuid()
    with open(cfg_path, "w") as f:
        f.write(
            f"[auth]\nallowed_uids = [{my_uid}]\n"
            f"\n[security]\ndrop_uid = \"{my_uid}\"\nsandbox = \"strict\"\n"
        )
    with Supervisor(bin_path, log_path, config_path=cfg_path) as sup:
        if sys.platform.startswith("freebsd"):
            # Under cap_enter the data plane works (connectat), cert reload
            # works (openat — test_tls_cert_reload_under_strict_sandbox), and
            # in-place upgrade works given a static binary + the FD handoff
            # (test_freebsd_strict_upgrade_commits). This test just asserts
            # cap-mode entry + plain/TLS echo; the dedicated tests cover the rest.
            for role in ("processor", "plain", "tls", "scanner"):
                hits = sup.grep_eventually(
                    rf'entered Capsicum capability mode.*role="?{role}"?',
                    timeout=3,
                )
                assert hits, f"no Capsicum entry log for {role}"
            # Plain echo under cap mode.
            s = socket.create_connection(("127.0.0.1", 7070), timeout=2)
            s.sendall(b"sandboxed-plain\n")
            assert read_line(s) == "sandboxed-plain"
            s.close()
            # TLS echo under cap mode.
            tls = open_tls()
            tls.sendall(b"sandboxed-tls\n")
            assert read_line(tls) == "sandboxed-tls"
            tls.close()
            return
        # Linux + macOS: full data-plane + upgrade.
        s = socket.create_connection(("127.0.0.1", 7070), timeout=2)
        s.sendall(b"sandboxed\n")
        assert read_line(s) == "sandboxed"
        s.close()
        r = sup.upgrade()
        assert r.returncode == 0, r.stderr
        s = socket.create_connection(("127.0.0.1", 7070), timeout=2)
        s.sendall(b"post-sandbox-upgrade\n")
        assert read_line(s) == "post-sandbox-upgrade"
        s.close()
        if sys.platform.startswith("linux"):
            for role in ("processor", "plain", "tls", "scanner"):
                hits = sup.grep_eventually(
                    rf'seccomp filter installed.*role="?{role}"?', timeout=3,
                )
                assert hits, f"no 'seccomp filter installed' log line for {role}"

def test_freebsd_strict_upgrade_commits(bin_path, log_path):
    """Under sandbox=strict, an in-place upgrade commits cleanly: the
    successor adopts the open TCP session, status reflects the new
    generation, and the supervisor logs "successor adopted" (proving the
    fix went through `supervise_role`'s new wait/monitor path rather than
    being saved by a benign-coincidence timing window).

    Asserted on every platform — the same code path runs everywhere, and
    a regression that breaks adoption on Linux/macOS would silently
    re-introduce the FreeBSD race.

    NOTE: on FreeBSD this requires a *static* binary (scripts/build-static.sh)
    — under cap_enter a dynamically-linked successor can't re-exec (the kernel
    resolves /libexec/ld-elf.so.1 by path). Run the suite with
    --bin target/<triple>/debug/echod there. On Linux/macOS any build
    works."""
    if sys.platform.startswith("freebsd") and not _is_static_elf(bin_path):
        print(
            f"SKIP: {bin_path} is dynamically linked; FreeBSD cap-mode upgrade requires a "
            "static binary. Build with scripts/build-static.sh and re-run with --bin <path>."
        )
        return
    cfg_dir = tempfile.mkdtemp(prefix="fdpass-strict-upgrade-")
    cfg_path = os.path.join(cfg_dir, "fdpass.toml")
    my_uid = os.getuid()
    with open(cfg_path, "w") as f:
        f.write(
            f"[auth]\nallowed_uids = [{my_uid}]\n"
            f"\n[security]\ndrop_uid = \"{my_uid}\"\nsandbox = \"strict\"\n"
        )
    with Supervisor(bin_path, log_path, config_path=cfg_path) as sup:
        s = socket.create_connection(("127.0.0.1", 7070), timeout=2)
        s.sendall(b"before-strict-upgrade\n")
        assert read_line(s) == "before-strict-upgrade"
        # Processor-only upgrade: the meaty tier re-execs and adopts its UDS session under the strict
        # sandbox; the thin acceptor is untouched, so the in-flight session survives.
        r = sup.upgrade("--role", "processor")
        assert r.returncode == 0, r.stderr
        s.sendall(b"after-strict-upgrade\n")
        assert read_line(s) == "after-strict-upgrade", \
            "in-flight session lost across strict-mode processor upgrade"
        s.close()
        # The supervisor's supervise_role logs this whenever the new
        # state machine's wait_for_successor returns Adopted. Its
        # presence is the *direct* proof that the fix engaged — a
        # pre-fix supervisor would either time out (FreeBSD) or never
        # enter the path on a benign-race Linux run.
        hits = sup.grep_eventually(
            r"successor adopted; standing down respawn",
            timeout=5,
        )
        assert hits, "supervisor never logged 'successor adopted'"
        # And `status` should report the bumped generation. Columns are
        # ROLE STATE PID GEN UPTIME RESTARTS BACKOFF IN_FLIGHT LISTENER.
        out = sup.status()
        proc_row = next(
            (l for l in out.splitlines() if l.startswith("processor ")),
            "",
        )
        cols = re.split(r"\s+", proc_row.strip())
        assert len(cols) >= 4 and cols[3] == "1", \
            f"processor row didn't show post-upgrade generation=1: {proc_row!r}"

def test_upgrade_then_successor_crash_respawns(bin_path, log_path):
    """After an in-place upgrade, supervise_role adopts the successor and
    monitors it via the control link. If that adopted worker (a grandchild the
    supervisor never spawned, so there's no waitpid on it) then dies, the
    supervisor must notice the dropped control connection and respawn a fresh
    worker. This exercises monitor_successor's loss path — which only works
    because the control reader now clears `writer` on disconnect."""
    with Supervisor(bin_path, log_path) as sup:
        s = socket.create_connection(("127.0.0.1", 7070), timeout=2)
        s.sendall(b"pre-upgrade\n")
        assert read_line(s) == "pre-upgrade"
        s.close()

        # Upgrade so every role is now an adopted gen-1 successor.
        r = sup.upgrade()
        assert r.returncode == 0, r.stderr
        assert sup.grep_eventually(
            r"successor adopted; standing down respawn", timeout=5), \
            "upgrade didn't adopt a successor"

        # Kill the adopted processor successor outright.
        proc_pid = sup.pid_of("processor")
        assert proc_pid, "no processor pid after upgrade"
        os.kill(proc_pid, signal.SIGKILL)

        # The supervisor must detect the lost control link (after the
        # SUCCESSOR_LOSS_GRACE window) and respawn. Pre-fix, `writer` was never
        # cleared, so monitor_successor blocked forever and this never logged.
        assert sup.grep_eventually(
            r"adopted successor disappeared; respawning fresh", timeout=8), \
            "supervisor never detected the adopted successor's death"

        # A fresh processor (different PID) handles new traffic.
        new_pid = sup.pid_of("processor", retries=40)
        assert new_pid and new_pid != proc_pid, \
            f"processor not respawned (old={proc_pid}, new={new_pid})"
        s2 = socket.create_connection(("127.0.0.1", 7070), timeout=2)
        s2.sendall(b"post-respawn\n")
        assert read_line(s2) == "post-respawn", "fresh processor not echoing"
        s2.close()

def test_admin_drain_stops_new_accepts_but_keeps_sessions(bin_path, log_path):
    """`drain` releases the listener; existing sessions continue, new SYNs refused."""
    with Supervisor(bin_path, log_path) as sup:
        # Open a session BEFORE drain — it must survive the drain.
        keeper = socket.create_connection(("127.0.0.1", 7070), timeout=2)
        keeper.sendall(b"pre-drain\n")
        assert read_line(keeper) == "pre-drain"

        # Drain.
        r = subprocess.run(
            [bin_path, "drain"], capture_output=True, text=True, timeout=10,
        )
        assert r.returncode == 0, f"drain failed: {r.stderr}"

        # Both acceptor roles must have logged the drain.
        for role in ("plain", "tls"):
            hits = sup.grep_eventually(
                rf'drained: new accepts will be dropped.*role="?{role}"?',
                timeout=3,
            )
            assert hits, f"no drain log for {role}"

        # New connections see a soft-drain: server accepts then immediately
        # drop(tcp) → FIN; client recv returns 0 bytes.  Do NOT send before
        # recv: the server's close() sends FIN, and any data we send after
        # that triggers a RST, which surfaces as ConnectionReset (OSError)
        # rather than the clean EOF we're checking for.
        deadline = time.time() + 3
        saw_drained = False
        while time.time() < deadline:
            try:
                ns = socket.create_connection(("127.0.0.1", 7070), timeout=0.3)
                ns.settimeout(1.0)
                data = ns.recv(64)
                ns.close()
                if data == b"":
                    saw_drained = True
                    break
            except OSError:
                pass
            time.sleep(0.1)
        assert saw_drained, "expected new connections to see immediate EOF after drain"

        # The pre-drain session still echoes.
        keeper.sendall(b"post-drain\n")
        assert read_line(keeper) == "post-drain"
        keeper.close()

def test_admin_reload_swaps_auth_allowlist(bin_path, log_path):
    """`reload` re-reads config; auth.allowed_uids change takes effect live.

    The acceptor → processor handoff runs as our uid, so the reloaded list
    must still include us or the data plane breaks. Test reloads from
    `[my_uid]` to `[my_uid, 42]` — different list, still allowed — and asserts
    the workers logged the new contents."""
    cfg_dir = tempfile.mkdtemp(prefix="fdpass-reload-")
    cfg_path = os.path.join(cfg_dir, "fdpass.toml")
    my_uid = os.getuid()
    with open(cfg_path, "w") as f:
        f.write(f"[auth]\nallowed_uids = [{my_uid}]\n")
    with Supervisor(bin_path, log_path, config_path=cfg_path) as sup:
        # Sanity: traffic flows under the initial allowlist.
        s = socket.create_connection(("127.0.0.1", 7070), timeout=2)
        s.sendall(b"pre-reload\n")
        assert read_line(s) == "pre-reload"
        s.close()

        # Rewrite config: same uid (still allowed) plus an extra entry. The
        # change is observable in the workers' log lines but the data plane
        # keeps working.
        with open(cfg_path, "w") as f:
            f.write(f"[auth]\nallowed_uids = [{my_uid}, 42]\n")
        r = subprocess.run(
            [bin_path, "reload", "--config", cfg_path],
            capture_output=True, text=True, timeout=10,
        )
        assert r.returncode == 0, f"reload failed: {r.stderr}"

        # Workers that authenticate UDS peers log the refreshed list.
        # Order in HashSet-backed Debug isn't stable, so match both elements
        # separately.
        for role in ("processor", "scanner"):
            hits = sup.grep_eventually(
                r'auth allowlist refreshed', timeout=3,
            )
            assert hits, f"no reload log for {role}"
            joined = "\n".join(hits)
            assert str(my_uid) in joined, f"missing my_uid in {role} reload log"
            assert "42" in joined, f"missing 42 in {role} reload log"

        # Post-reload traffic still works.
        s = socket.create_connection(("127.0.0.1", 7070), timeout=2)
        s.sendall(b"post-reload\n")
        assert read_line(s) == "post-reload"
        s.close()

def test_workers_drop_privileges(bin_path, log_path):
    """Workers log 'dropped privileges' for each role when drop_uid is set.

    We can't actually setuid to nobody as a non-root test, so we set drop_uid
    to the current user's numeric uid — that's a valid (no-op) setuid that
    still exercises the full drop_privileges code path."""
    cfg_dir = tempfile.mkdtemp(prefix="fdpass-sec-")
    cfg_path = os.path.join(cfg_dir, "fdpass.toml")
    my_uid = os.getuid()
    with open(cfg_path, "w") as f:
        f.write(
            f"[auth]\nallowed_uids = [{my_uid}]\n"
            f"\n[security]\ndrop_uid = \"{my_uid}\"\n"
        )
    with Supervisor(bin_path, log_path, config_path=cfg_path) as sup:
        # Smoke: still serves traffic.
        s = socket.create_connection(("127.0.0.1", 7070), timeout=2)
        s.sendall(b"after-drop\n")
        assert read_line(s) == "after-drop"
        s.close()
        # Every worker role should have logged a drop.
        for role in ("processor", "plain", "tls", "scanner"):
            hits = sup.grep_eventually(
                rf'dropped privileges.*role="?{role}"?', timeout=3,
            )
            assert hits, f"no 'dropped privileges' log line for {role}"

def test_runtime_directory_override(bin_path, log_path):
    """`RUNTIME_DIRECTORY` env (set by systemd's `RuntimeDirectory=`) overrides sockets_dir."""
    rd = tempfile.mkdtemp(prefix="fdpass-rd-")
    sup = Supervisor(bin_path, log_path, extra_env={"RUNTIME_DIRECTORY": rd})
    with sup:
        # If RUNTIME_DIRECTORY honored, the admin sock lives under rd, and
        # plain echo still works on the default port.
        admin_sock = os.path.join(rd, "fdpass-admin.sock")
        for _ in range(20):
            if os.path.exists(admin_sock):
                break
            time.sleep(0.1)
        assert os.path.exists(admin_sock), f"admin sock not found at {admin_sock}"
        s = socket.create_connection(("127.0.0.1", 7070), timeout=2)
        s.sendall(b"rd-test\n")
        assert read_line(s) == "rd-test"
        s.close()
        assert sup.grep(r"sockets_dir overridden by RUNTIME_DIRECTORY"), \
            "no override log line"

def test_systemd_notify_ready(bin_path, log_path):
    """Supervisor writes READY=1 to NOTIFY_SOCKET on startup, STOPPING=1 on shutdown."""
    notify_path = "/tmp/echod-notify.sock"
    try: os.remove(notify_path)
    except FileNotFoundError: pass
    notify_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    notify_sock.bind(notify_path)
    try:
        sup = Supervisor(bin_path, log_path, extra_env={"NOTIFY_SOCKET": notify_path})

        def drain(timeout):
            notify_sock.settimeout(timeout)
            msgs = []
            try:
                while True:
                    data, _ = notify_sock.recvfrom(4096)
                    msgs.append(data)
            except socket.timeout:
                pass
            return b"\n".join(msgs)

        with sup:
            startup = drain(2.0)
            assert b"READY=1" in startup, f"no READY=1 in {startup!r}"
            assert b"STATUS=ready" in startup, f"no STATUS in {startup!r}"
        # After context exit, supervisor was SIGTERM'd.
        shutdown = drain(1.0)
        assert b"STOPPING=1" in shutdown, f"no STOPPING=1 in {shutdown!r}"
    finally:
        notify_sock.close()
        try: os.remove(notify_path)
        except FileNotFoundError: pass

def test_systemd_watchdog_pings(bin_path, log_path):
    """With WATCHDOG_USEC set, the supervisor periodically sends WATCHDOG=1 to
    NOTIFY_SOCKET. The ping is driven by a liveness beacon ticked from the core
    select loop, not a free-running timer. No WATCHDOG_PID is set: the daemon
    arms on WATCHDOG_USEC alone when PID is absent, sidestepping the
    PID-known-only-after-fork problem in the harness."""
    notify_path = "/tmp/echod-watchdog.sock"
    try: os.remove(notify_path)
    except FileNotFoundError: pass
    notify_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    notify_sock.bind(notify_path)
    try:
        sup = Supervisor(bin_path, log_path, extra_env={
            "NOTIFY_SOCKET": notify_path,
            "WATCHDOG_USEC": "400000",   # 400ms → ~200ms ping interval
        })
        with sup:
            notify_sock.settimeout(0.5)
            saw_watchdog = False
            deadline = time.time() + 3.0
            while time.time() < deadline:
                try:
                    data, _ = notify_sock.recvfrom(4096)
                except socket.timeout:
                    continue
                if b"WATCHDOG=1" in data:
                    saw_watchdog = True
                    break
            assert saw_watchdog, "no WATCHDOG=1 datagram arrived within 3s"
    finally:
        notify_sock.close()
        try: os.remove(notify_path)
        except FileNotFoundError: pass

def test_systemd_socket_activation(bin_path, log_path):
    """Supervisor adopts a TCP listener passed via LISTEN_FDS/LISTEN_FDNAMES=plain."""
    cleanup_sockets()
    # Pre-bind the plain TCP listener.
    plain = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    plain.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    plain.bind(("127.0.0.1", 18090))
    plain.listen(64)
    listener_fd = plain.fileno()

    cfg_dir = tempfile.mkdtemp(prefix="fdpass-sd-")
    cfg_path = os.path.join(cfg_dir, "fdpass.toml")
    with open(cfg_path, "w") as f:
        # plain_port must match the FD we pre-bound to.
        f.write("plain_port = 18090\ntls_port = 18091\n")

    def preexec_activation():
        # Move the pre-bound listener to FD 3 (where systemd places it).
        if listener_fd != 3:
            os.dup2(listener_fd, 3)
        # LISTEN_PID must match the child's pid; we're in the child now.
        os.environ["LISTEN_PID"] = str(os.getpid())
        os.environ["LISTEN_FDS"] = "1"
        os.environ["LISTEN_FDNAMES"] = "plain"

    sup = Supervisor(
        bin_path, log_path,
        config_path=cfg_path,
        plain_port=18090,
        preexec=preexec_activation,
        # FD 3 is created in preexec via dup2; pass_fds must include it so
        # subprocess's "close everything else" step skips it.
        pass_fds=tuple({listener_fd, 3}),
    )
    try:
        with sup:
            s = socket.create_connection(("127.0.0.1", 18090), timeout=2)
            s.sendall(b"sd-activated\n")
            assert read_line(s) == "sd-activated"
            s.close()
            lines = sup.grep(r"adopted .* listener .* from systemd")
            assert lines, "no systemd-adoption log line"
    finally:
        plain.close()

def test_peer_auth_self_uid_allowed(bin_path, log_path):
    """Connections from same uid pass peer-cred auth (smoke test)."""
    with Supervisor(bin_path, log_path) as sup:
        # Admin status uses the admin UDS, which is auth-gated. If our uid
        # weren't allowlisted, this would silently close.
        out = sup.status()
        assert "processor" in out, f"status didn't return rows: {out!r}"
        # Belt-and-suspenders: a rejection would have logged.
        rejections = sup.grep(r"peer rejected")
        assert not rejections, f"unexpected peer rejection(s): {rejections}"

def _gen_self_signed(cert_path, key_path, cn):
    """openssl-generate a fresh self-signed cert with the given CN."""
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", key_path, "-out", cert_path, "-days", "1",
        "-subj", f"/CN={cn}",
    ], check=True, capture_output=True)

def _peer_cert_bytes(port):
    """Open a TLS connection and return the peer's DER cert."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    raw = socket.create_connection(("127.0.0.1", port), timeout=2)
    with ctx.wrap_socket(raw, server_hostname="x") as s:
        return s.getpeercert(binary_form=True)

def test_tls_cert_reload_on_sighup(bin_path, log_path):
    """SIGHUP to the TLS acceptor re-reads cert/key and serves the new cert."""
    cert_dir = tempfile.mkdtemp(prefix="fdpass-cert-")
    cert_path = os.path.join(cert_dir, "server.crt")
    key_path = os.path.join(cert_dir, "server.key")
    _gen_self_signed(cert_path, key_path, "alpha")

    cfg_path = os.path.join(cert_dir, "fdpass.toml")
    with open(cfg_path, "w") as f:
        f.write(
            "[tls]\n"
            f'cert_path = "{cert_path}"\n'
            f'key_path = "{key_path}"\n'
        )

    with Supervisor(bin_path, log_path, config_path=cfg_path) as sup:
        before = _peer_cert_bytes(7071)

        # Generate a new cert with a different CN and overwrite the files.
        _gen_self_signed(cert_path, key_path, "beta")

        # SIGHUP the TLS acceptor.
        tls_pid = sup.pid_of("tls")
        assert tls_pid, "tls pid unavailable"
        os.kill(tls_pid, signal.SIGHUP)
        time.sleep(0.5)

        after = _peer_cert_bytes(7071)
        assert before != after, "cert did not change after SIGHUP"
        assert sup.grep(r"TLS cert/key reloaded on SIGHUP"), "no reload log line"

def test_tls_cert_reload_under_strict_sandbox(bin_path, log_path):
    """SIGHUP cert reload works while the TLS acceptor is sandboxed.

    The cap-mode case: on FreeBSD the worker is in Capsicum capability mode,
    so the reload can't open the cert by path — it must `openat()` a dir FD
    pre-opened before `cap_enter()`. On Linux the seccomp allowlist already
    permits `openat`; on macOS the sandbox is a no-op. Asserted on every
    platform so a regression in the pre-open/openat plumbing surfaces
    everywhere, not just on FreeBSD."""
    cert_dir = tempfile.mkdtemp(prefix="fdpass-cert-strict-")
    cert_path = os.path.join(cert_dir, "server.crt")
    key_path = os.path.join(cert_dir, "server.key")
    _gen_self_signed(cert_path, key_path, "alpha-strict")

    cfg_path = os.path.join(cert_dir, "fdpass.toml")
    with open(cfg_path, "w") as f:
        f.write(
            "[tls]\n"
            f'cert_path = "{cert_path}"\n'
            f'key_path = "{key_path}"\n'
            "\n[security]\n"
            'sandbox = "strict"\n'
        )

    with Supervisor(bin_path, log_path, config_path=cfg_path) as sup:
        # Confirm the TLS worker really entered its sandbox first — otherwise
        # we'd just be re-testing the non-sandboxed reload path.
        if sys.platform.startswith("freebsd"):
            assert sup.grep_eventually(
                r'entered Capsicum capability mode.*role="?tls"?', timeout=3,
            ), "tls worker never entered capability mode"
        elif sys.platform.startswith("linux"):
            assert sup.grep_eventually(
                r'seccomp filter installed.*role="?tls"?', timeout=3,
            ), "tls worker never installed seccomp filter"

        before = _peer_cert_bytes(7071)

        # Overwrite cert/key with a fresh identity and SIGHUP the acceptor.
        _gen_self_signed(cert_path, key_path, "beta-strict")
        tls_pid = sup.pid_of("tls")
        assert tls_pid, "tls pid unavailable"
        os.kill(tls_pid, signal.SIGHUP)
        time.sleep(0.5)

        after = _peer_cert_bytes(7071)
        assert before != after, \
            "cert did not change after SIGHUP under strict sandbox"
        assert sup.grep(r"TLS cert/key reloaded on SIGHUP"), "no reload log line"

def test_scanner_egress_under_strict_with_override(bin_path, log_path):
    """Regression guard for the silent-ECAPMODE scanner trap.

    Under the recommended FreeBSD config — global `sandbox = "strict"` but
    `[security.sandbox_overrides] scanner = "off"` — the scanner stays OUT of
    Capsicum capability mode, so its one outbound connection-back (the RFC-1413
    identd lookup) still works. We prove that end-to-end: point `identd_port` at
    a mock identd, drive a loopback client, and assert the scanner captured
    `ident=Some(...)` in `scan complete`.

    The scanner reaching the mock and reading a reply is the proof egress works
    under this config. If a regression dropped the per-role override and put the
    scanner back under `cap_enter`, its outbound `connect()` would fail ECAPMODE,
    `ident` would be None, and this fails. The configurable `identd_port` lets us
    use a mock on an unprivileged loopback port, so the test needs no root and
    the egress assertion runs deterministically everywhere.

    Cap-mode entry is only observable (and only actually blocks egress) on
    FreeBSD, so the "strict roles capped, scanner not capped" assertions are
    gated there."""
    cfg_dir = tempfile.mkdtemp(prefix="fdpass-scanner-egress-")
    cfg_path = os.path.join(cfg_dir, "fdpass.toml")
    my_uid = os.getuid()
    with _MockIdentd("egress-user") as mock:
        with open(cfg_path, "w") as f:
            f.write(
                f"identd_port = {mock.port}\n"
                f"[auth]\nallowed_uids = [{my_uid}]\n"
                "\n[security]\n"
                f'drop_uid = "{my_uid}"\n'
                'sandbox = "strict"\n'
                "\n[security.sandbox_overrides]\n"
                'scanner = "off"\n'
            )
        with Supervisor(bin_path, log_path, config_path=cfg_path) as sup:
            # The per-role override took effect: the strict roles entered cap
            # mode, the scanner did NOT. FreeBSD-only — the one OS where cap
            # entry is observable and where it would actually break egress.
            if sys.platform.startswith("freebsd"):
                for role in ("processor", "plain", "tls"):
                    assert sup.grep_eventually(
                        rf'entered Capsicum capability mode.*role="?{role}"?',
                        timeout=3,
                    ), f"{role} never entered cap mode — global strict not applied?"
                scanner_capped = sup.grep(
                    r'entered Capsicum capability mode.*role="?scanner"?')
                assert not scanner_capped, \
                    "scanner entered cap mode despite override=off; egress would ECAPMODE"

            # Loopback client → scanner runs its identd lookup against
            # 127.0.0.1:<identd_port>, where our mock is listening.
            s = socket.create_connection(("127.0.0.1", 7070), timeout=2)
            s.sendall(b"egress-probe\n")
            assert read_line(s) == "egress-probe"
            s.close()

            # The scanner's identd connect() must have reached the mock and read
            # a reply. ident=None here == the ECAPMODE regression (outbound
            # connect blocked) or the scan never fired.
            hits = sup.grep_eventually(r"scan complete.*ident=Some\(", timeout=5)
            assert hits, (
                "scanner reported ident=None despite the mock identd on port "
                f"{mock.port} — outbound connect() blocked (ECAPMODE regression?) "
                "or the scan didn't fire"
            )

def _http_get(addr, port, path="/healthz", timeout=2.0):
    """Bare-bones HTTP/1.1 GET. Returns (status_code, body_str)."""
    s = socket.create_connection((addr, port), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
    chunks = []
    while True:
        try:
            c = s.recv(4096)
        except socket.timeout:
            break
        if not c:
            break
        chunks.append(c)
    s.close()
    text = b"".join(chunks).decode(errors="replace")
    status = 0
    if text.startswith("HTTP/"):
        parts = text.split(" ", 2)
        if len(parts) >= 2:
            try: status = int(parts[1])
            except ValueError: pass
    body = ""
    if "\r\n\r\n" in text:
        body = text.split("\r\n\r\n", 1)[1]
    return status, body

def test_health_endpoint_200_when_healthy(bin_path, log_path):
    with Supervisor(bin_path, log_path) as sup:
        time.sleep(0.3)  # let health server bind
        code, body = _http_get("127.0.0.1", 7079)
        assert code == 200, f"expected 200, got {code}\n--- body ---\n{body}"
        assert '"status":"ok"' in body, body
        # Every role appears.
        for role in ("processor", "plain", "tls", "scanner"):
            assert f'"role":"{role}"' in body, f"missing role {role}: {body}"

def test_health_endpoint_503_when_failed(bin_path, log_path):
    """Pummel scanner into FAILED state, then /healthz returns 503."""
    with Supervisor(bin_path, log_path) as sup:
        time.sleep(0.3)
        # Hit scanner with enough fast SIGKILLs to cross FAIL threshold.
        backoff_ms = 200
        for _ in range(5):
            pid = sup.pid_of("scanner")
            if pid:
                try: os.kill(pid, signal.SIGKILL)
                except ProcessLookupError: pass
            time.sleep(backoff_ms / 1000.0 + 0.3)
            backoff_ms = min(backoff_ms * 2, 30_000)
        time.sleep(0.5)
        code, body = _http_get("127.0.0.1", 7079)
        assert code == 503, f"expected 503, got {code}\n--- body ---\n{body}"
        assert '"status":"degraded"' in body, body
        assert '"state":"failed"' in body, body

def test_upgrade_counters_increment(bin_path, log_path):
    """Successful upgrade bumps fdpass_upgrade_total{outcome=committed}."""
    cfg_dir = tempfile.mkdtemp(prefix="fdpass-upcnt-")
    metrics_path = os.path.join(cfg_dir, "fdpass.prom")
    cfg_path = os.path.join(cfg_dir, "fdpass.toml")
    with open(cfg_path, "w") as f:
        f.write(f'[metrics]\npath = "{metrics_path}"\ninterval_secs = 1\n')
    with Supervisor(bin_path, log_path, config_path=cfg_path) as sup:
        # Open a TCP session so the processor upgrade has something to drain.
        s = socket.create_connection(("127.0.0.1", 7070), timeout=2)
        s.sendall(b"pre\n")
        assert read_line(s) == "pre"
        r = sup.upgrade()
        assert r.returncode == 0, r.stderr
        # Wait for the metrics writer to flush at least one snapshot post-upgrade.
        deadline = time.time() + 3
        committed = 0
        while time.time() < deadline:
            try:
                with open(metrics_path) as f: text = f.read()
            except FileNotFoundError:
                text = ""
            m = re.search(
                r'fdpass_upgrade_total\{role="processor",outcome="committed"\} (\d+)',
                text,
            )
            if m and int(m.group(1)) > 0:
                committed = int(m.group(1))
                break
            time.sleep(0.2)
        s.close()
        assert committed >= 1, f"expected committed counter >= 1, file:\n{text}"

def test_metrics_textfile_emitted(bin_path, log_path):
    """Supervisor writes a Prometheus textfile at the configured interval."""
    cfg_dir = tempfile.mkdtemp(prefix="fdpass-metrics-")
    metrics_path = os.path.join(cfg_dir, "fdpass.prom")
    cfg_path = os.path.join(cfg_dir, "fdpass.toml")
    with open(cfg_path, "w") as f:
        f.write(f'[metrics]\npath = "{metrics_path}"\ninterval_secs = 1\n')
    with Supervisor(bin_path, log_path, config_path=cfg_path) as sup:
        # Drive a TCP connection so in_flight nonzero appears.
        s = socket.create_connection(("127.0.0.1", 7070), timeout=2)
        s.sendall(b"metric-me\n")
        assert read_line(s) == "metric-me"
        # Wait past one interval; the writer logs on startup, then polls.
        deadline = time.time() + 3
        text = ""
        while time.time() < deadline:
            if os.path.exists(metrics_path):
                with open(metrics_path) as f:
                    text = f.read()
                if "fdpass_supervisor_generation" in text:
                    break
            time.sleep(0.2)
        s.close()
        # Required metric families.
        for needle in [
            "# HELP fdpass_supervisor_generation",
            "# TYPE fdpass_supervisor_generation gauge",
            "fdpass_supervisor_generation 0",
            'fdpass_worker_generation{role="processor"}',
            'fdpass_worker_in_flight{role="processor"}',
            'fdpass_worker_pid{role="processor"}',
            'fdpass_worker_health{role="processor"} 0',
            'fdpass_worker_restarts_total{role="processor"}',
            'fdpass_upgrade_total{role="processor",outcome="committed"} 0',
            'fdpass_upgrade_total{role="plain",outcome="canary_aborted"} 0',
        ]:
            assert needle in text, f"missing {needle!r}\n--- file ---\n{text}"
        # No stale `.tmp` left behind.
        assert not os.path.exists(metrics_path + ".tmp"), "tmp file should be renamed away"

def test_session_cap_accept_then_close(bin_path, log_path):
    """When max_in_flight is hit, new TLS clients are accept-then-closed."""
    cfg_dir = tempfile.mkdtemp(prefix="fdpass-cap-")
    cfg_path = os.path.join(cfg_dir, "fdpass.toml")
    with open(cfg_path, "w") as f:
        f.write(
            "[limits]\n"
            "max_in_flight_per_role = 2\n"
            "tls_idle_timeout_secs = 0\n"
            "accept_rate_per_ip = 0\n"
        )
    with Supervisor(bin_path, log_path, config_path=cfg_path) as sup:
        # Hold 2 TLS sessions open so the cap is reached.
        held = [open_tls(), open_tls()]
        for s in held:
            s.sendall(b"hi\n")
            assert read_line(s) == "hi"
        time.sleep(0.3)  # let in-flight register
        # 3rd TLS client: TCP is accepted then immediately dropped — the
        # client's TLS handshake either fails outright or completes against
        # a half-dead socket. Either way `open_tls()` raises.
        refused = False
        try:
            tls = open_tls()
            tls.settimeout(1.0)
            try:
                tls.sendall(b"should-not-see-this\n")
                data = tls.recv(64)
                refused = (data == b"")
            except (BrokenPipeError, ssl.SSLError, OSError):
                refused = True
            tls.close()
        except (ConnectionResetError, ssl.SSLError, OSError):
            refused = True
        assert refused, "3rd over-cap TLS client was served instead of being closed"
        assert sup.grep(r"session cap reached"), "no cap log line"
        for s in held: s.close()

def test_tls_idle_timeout_closes_session(bin_path, log_path):
    """TLS sessions idle beyond `tls_idle_timeout_secs` get closed by the acceptor."""
    cfg_dir = tempfile.mkdtemp(prefix="fdpass-idle-")
    cfg_path = os.path.join(cfg_dir, "fdpass.toml")
    with open(cfg_path, "w") as f:
        f.write("[limits]\ntls_idle_timeout_secs = 1\n")
    with Supervisor(bin_path, log_path, config_path=cfg_path) as sup:
        s = open_tls()
        s.sendall(b"keep-me\n")
        assert read_line(s) == "keep-me"
        # Idle for > 1s. Acceptor's watchdog (polls at idle/4 ≈ 250ms) should
        # close the session ~1-1.5s in.
        time.sleep(2.0)
        s.settimeout(2.0)
        data = b""
        try:
            data = s.recv(64)
        except (socket.timeout, ssl.SSLError, OSError):
            pass
        assert data == b"", f"expected closed idle conn, got {data!r}"
        s.close()
        assert sup.grep(r"TLS session idle timeout"), "no idle-timeout log line"

def test_per_ip_rate_limit(bin_path, log_path):
    """Bursting past the per-IP token bucket starts getting accept-rejected."""
    cfg_dir = tempfile.mkdtemp(prefix="fdpass-rate-")
    cfg_path = os.path.join(cfg_dir, "fdpass.toml")
    with open(cfg_path, "w") as f:
        # 1 token/sec refill, burst of 2 → after 2 quick connects, the 3rd
        # within ~1s should be dropped.
        f.write("[limits]\naccept_rate_per_ip = 1\naccept_rate_burst = 2\n")
    with Supervisor(bin_path, log_path, config_path=cfg_path) as sup:
        # Burst 5 fast connects from 127.0.0.1. A drop manifests EITHER as
        # an OS-level error during connect/send/recv (Linux) OR as a clean
        # close after the 3-way handshake — we accept-then-close, so the
        # client's recv just returns b'' (FreeBSD). Count actual echoes.
        results = []
        for i in range(5):
            expected = f"r{i}"
            try:
                s = socket.create_connection(("127.0.0.1", 7070), timeout=1)
                s.settimeout(0.5)
                s.sendall(f"{expected}\n".encode())
                line = read_line(s, timeout=0.5)
                if line == expected:
                    results.append(("ok", line))
                else:
                    results.append(("drop", f"empty/short: {line!r}"))
                s.close()
            except (socket.timeout, OSError) as e:
                results.append(("drop", str(e)))
        oks = sum(1 for r, _ in results if r == "ok")
        assert oks <= 3, f"expected some drops; got {results}"
        assert sup.grep(r"rate-limited"), "no rate-limit log line"

def test_schema_versioning_rejects_incompatible(bin_path, log_path):
    """Admin message with an unsupported schema version is rejected."""
    import json as _json
    with Supervisor(bin_path, log_path) as sup:
        # Hand-craft a status request with version=99 — outside our supported range.
        bad = _json.dumps({"version": 99, "type": "status"}) + "\n"
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect("/tmp/fdpass-admin.sock")
        s.sendall(bad.encode())
        s.shutdown(socket.SHUT_WR)
        # Supervisor logs the incompat and drops the connection without replying.
        data = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        s.close()
        assert data == b"", f"expected no response for incompat msg; got {data!r}"
        # WARN line is emitted from a spawned task; on Linux redirected
        # stderr is fully buffered so wait for it to flush.
        assert sup.grep_eventually(r"incompatible (admin message|schema version)"), \
            "no 'incompatible' log line"
        # And confirm a *good* admin call still works after that.
        out = sup.status()
        assert "processor" in out, f"status broken after incompat probe: {out!r}"

def test_structured_logs_and_trace_id(bin_path, log_path):
    """FDPASS_LOG_FORMAT=json → one JSON object per line, trace_id propagates
    acceptor → processor for both plain and TLS sessions."""
    sup = Supervisor(bin_path, log_path, extra_env={"FDPASS_LOG_FORMAT": "json"})
    with sup:
        # Plain echo to drive a trace through acceptor → processor SCM handoff.
        s = socket.create_connection(("127.0.0.1", 7070), timeout=2)
        s.sendall(b"trace-me\n")
        assert read_line(s) == "trace-me"
        s.close()
        # TLS path uses byte-bridge over UDS.
        tls = open_tls()
        tls.sendall(b"trace-me-tls\n")
        assert read_line(tls) == "trace-me-tls"
        tls.close()
        time.sleep(0.5)

    # Every log line is a valid JSON object.
    import json as _json
    json_lines = 0
    accept_traces, session_traces, scan_traces, sidecar_traces = set(), set(), set(), set()
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = _json.loads(line)  # raises if any line isn't JSON
            json_lines += 1
            fields = obj.get("fields", {})
            msg = fields.get("message", "")
            tid = fields.get("trace_id")
            if not tid:
                continue
            if msg == "accepted client":
                accept_traces.add(tid)
            elif msg == "new uds session":
                session_traces.add(tid)
            elif msg == "scan complete":
                scan_traces.add(tid)
            elif msg == "sidecar metadata received":
                sidecar_traces.add(tid)
    assert json_lines > 20, f"expected many JSON lines, got {json_lines}"
    # Trace IDs assigned at accept must show up in all three downstream paths.
    assert (accept_traces & session_traces), \
        f"acceptor→processor trace join broken; accept={accept_traces} session={session_traces}"
    assert (accept_traces & scan_traces), \
        f"acceptor→scanner trace join broken; accept={accept_traces} scan={scan_traces}"
    assert (accept_traces & sidecar_traces), \
        f"scanner→processor sidecar trace join broken; accept={accept_traces} sidecar={sidecar_traces}"

def test_canary_upgrade(bin_path, log_path):
    """`--canary 1` runs an observation window per role; all roles healthy → walk completes."""
    with Supervisor(bin_path, log_path) as sup:
        # Sanity: existing TCP session still works after a canary upgrade.
        s = socket.create_connection(("127.0.0.1", 7070), timeout=2)
        s.sendall(b"pre-canary\n")
        assert read_line(s) == "pre-canary"
        r = sup.upgrade("--canary", "1")
        assert r.returncode == 0, r.stderr
        # 3 roles × 1s canary windows → log lines visible.
        clean = sup.grep(r"canary: window clean")
        assert len(clean) >= 2, f"expected at least 2 'canary: window clean' lines, got {clean}"
        # A full walk re-execs the plain acceptor, which resets sessions in-flight during the swap
        # (the listener is preserved, so new connections are unaffected). The pre-canary socket is
        # therefore expected to drop; verify the service is live on a fresh connection.
        s.close()
        s2 = socket.create_connection(("127.0.0.1", 7070), timeout=2)
        s2.sendall(b"post-canary\n")
        assert read_line(s2, timeout=3.0) == "post-canary"
        s2.close()

def test_upgrade_unknown_role(bin_path, log_path):
    """`upgrade --role <bogus>` names no known worker: the supervisor warns and
    the walk completes with all_ok=false, so the CLI exits non-zero."""
    with Supervisor(bin_path, log_path) as sup:
        r = sup.upgrade("--role", "nonesuch")
        assert r.returncode != 0, \
            f"expected non-zero exit for unknown role, got {r.returncode}: {r.stdout}"
        assert sup.grep_eventually(
            r"upgrade --role names no known worker", timeout=3), \
            "expected unknown-role warning in supervisor log"

def test_upgrade_single_role(bin_path, log_path):
    """`upgrade --role processor` upgrades just that worker (routine zero-downtime
    path): in-flight plain session survives, generation advances for processor only."""
    with Supervisor(bin_path, log_path) as sup:
        s = socket.create_connection(("127.0.0.1", 7070), timeout=2)
        s.sendall(b"pre-single\n")
        assert read_line(s) == "pre-single"
        r = sup.upgrade("--role", "processor")
        assert r.returncode == 0, r.stderr
        # Processor upgrade keeps the plain acceptor and its sessions up.
        s.sendall(b"post-single\n")
        assert read_line(s, timeout=3.0) == "post-single"
        s.close()

def test_upgrade_plain_rollback(bin_path, log_path):
    """`upgrade --role plain --target <broken>` rolls back the PLAIN acceptor
    specifically (test_upgrade_rollback's default walk breaks at the processor,
    so it never reaches plain). The acceptor re-adopts its listener on rollback,
    so the in-flight session keeps working."""
    with Supervisor(bin_path, log_path) as sup:
        s = socket.create_connection(("127.0.0.1", 7070), timeout=2)
        s.sendall(b"before-plain-rollback\n")
        assert read_line(s) == "before-plain-rollback"
        broken_dir = tempfile.mkdtemp(prefix="fdpass-broken-")
        broken = os.path.join(broken_dir, "broken")
        with open(broken, "w") as f:
            f.write("#!/bin/sh\nexit 1\n")
        os.chmod(broken, 0o755)
        r = sup.upgrade("--role", "plain", "--target", broken)
        assert r.returncode != 0, f"expected rollback failure exit: {r.stdout}"
        assert sup.grep_eventually(r"upgrade rollback", timeout=5), \
            "expected plain-acceptor rollback log"
        s.sendall(b"after-plain-rollback\n")
        assert read_line(s, timeout=5.0) == "after-plain-rollback", \
            "in-flight session lost on plain-acceptor rollback"
        s.close()

def test_upgrade_rollback(bin_path, log_path):
    """Upgrade to a broken binary rolls back; in-flight TCP session survives."""
    with Supervisor(bin_path, log_path) as sup:
        s = socket.create_connection(("127.0.0.1", 7070), timeout=2)
        s.sendall(b"before-rollback\n")
        assert read_line(s) == "before-rollback"

        # Point upgrade at a binary that exits immediately. New image will
        # never signal ready; parent rolls back and re-adopts our session.
        broken_dir = tempfile.mkdtemp(prefix="fdpass-broken-")
        broken = os.path.join(broken_dir, "broken")
        with open(broken, "w") as f:
            f.write("#!/bin/sh\nexit 1\n")
        os.chmod(broken, 0o755)

        sup.upgrade("--target", broken)
        time.sleep(0.5)  # let rollback settle

        s.sendall(b"after-rollback\n")
        reply = read_line(s, timeout=5.0)
        assert reply == "after-rollback", f"session lost on rollback: got {reply!r}"
        s.close()

        rollback_logs = sup.grep(r"upgrade rollback")
        assert rollback_logs, "expected 'upgrade rollback' in supervisor logs"
        # CloexecGuard fires on rollback (commit() never called) → CLOEXEC restored.
        restored = sup.grep(r"CloexecGuard restored CLOEXEC")
        assert restored, "expected CloexecGuard to restore CLOEXEC on rollback"

def test_watchdog_fail_state(bin_path, log_path):
    """Five fast scanner exits in a row → state transitions to FAILED."""
    with Supervisor(bin_path, log_path) as sup:
        time.sleep(0.4)
        # Kill the scanner repeatedly. After each kill we wait long enough
        # for the supervisor's backoff sleep to elapse and the next child to
        # come up so we can kill that one too. Backoff doubles (200ms,
        # 400ms, 800ms, 1.6s, 3.2s) — sleep windows track that.
        backoff_ms = 200
        for _ in range(5):
            pid = sup.pid_of("scanner")
            if pid:
                try: os.kill(pid, signal.SIGKILL)
                except ProcessLookupError: pass
            # Sleep at least (current backoff) + small slack for respawn.
            time.sleep(backoff_ms / 1000.0 + 0.3)
            backoff_ms = min(backoff_ms * 2, 30_000)
        time.sleep(0.5)
        out = sup.status()
        scanner_row = next(
            (line for line in out.splitlines() if line.startswith("scanner ")),
            "",
        )
        assert "FAILED" in scanner_row, scanner_row
        log_hits = sup.grep(r"role marked FAILED")
        assert log_hits, "expected 'role marked FAILED' log line"

def test_watchdog_backoff(bin_path, log_path):
    """Three fast scanner exits → state observable as `backoff` then `flapping`."""
    with Supervisor(bin_path, log_path) as sup:
        time.sleep(0.4)
        for i in range(4):
            pid = sup.pid_of("scanner")
            if pid:
                try: os.kill(pid, signal.SIGKILL)
                except ProcessLookupError: pass
            time.sleep(0.7)
        out = sup.status()
        # Look for "flapping" or "backoff" in the scanner row
        scanner_row = next(
            (line for line in out.splitlines() if line.startswith("scanner ")),
            "",
        )
        assert "backoff" in scanner_row or "flapping" in scanner_row, scanner_row

# ----- fault injection tests ---------------------------------------------

def _write_fault_config(fault_points, extra=""):
    """Write a temp TOML config with the given [fault_inject] points.

    Each entry in fault_points is a dict with keys: name, kind (default
    "io_error"), message (default "synthetic fault"), trigger_budget (default 0
    = unlimited).  `extra` is appended verbatim for other config sections.
    """
    cfg_dir = tempfile.mkdtemp(prefix="fdpass-fault-")
    cfg_path = os.path.join(cfg_dir, "fdpass.toml")
    lines = []
    for p in fault_points:
        lines.append("[[fault_inject.points]]")
        lines.append(f'name = "{p["name"]}"')
        lines.append(f'kind = "{p.get("kind", "io_error")}"')
        lines.append(f'message = "{p.get("message", "synthetic fault")}"')
        lines.append(f'trigger_budget = {p.get("trigger_budget", 0)}')
        lines.append("")
    if extra:
        lines.append(extra)
    with open(cfg_path, "w") as f:
        f.write("\n".join(lines))
    return cfg_path


def test_fault_inject_tls_cert_load(bin_path, log_path):
    """tls.cert_load fault: TLS acceptor logs an error on startup, but plain survives.

    trigger_budget=1 means each spawned TLS worker process fires the fault once
    on startup (budgets are per-process).  TLS stays in backoff/respawn loop;
    we verify only that the error appears in the log and plain is unaffected.
    """
    cfg_path = _write_fault_config([{
        "name": "tls.cert_load",
        "kind": "io_error",
        "message": "synthetic cert load failure",
        "trigger_budget": 1,
    }])
    with Supervisor(bin_path, log_path, config_path=cfg_path) as sup:
        # Plain must work immediately — its startup is unaffected by TLS fault.
        s = socket.create_connection(("127.0.0.1", 7070), timeout=2)
        s.sendall(b"plain-survives-tls-fault\n")
        assert read_line(s) == "plain-survives-tls-fault"
        s.close()
        # The synthetic error must appear in the log.
        assert sup.grep_eventually(r"synthetic cert load failure", timeout=5), \
            "expected synthetic cert load error in log"


def test_fault_inject_tls_cert_parse(bin_path, log_path):
    """tls.cert_parse fault: PEM-parse step fails on startup; plain is unaffected.

    trigger_budget=1 means each spawned TLS worker process fires the fault once
    (budgets are per-process).  TLS stays in backoff/respawn loop; we verify
    the error appears in the log and plain traffic is unaffected.
    """
    cfg_path = _write_fault_config([{
        "name": "tls.cert_parse",
        "kind": "io_error",
        "message": "synthetic cert parse failure",
        "trigger_budget": 1,
    }])
    with Supervisor(bin_path, log_path, config_path=cfg_path) as sup:
        s = socket.create_connection(("127.0.0.1", 7070), timeout=2)
        s.sendall(b"plain-ok-during-parse-fault\n")
        assert read_line(s) == "plain-ok-during-parse-fault"
        s.close()
        assert sup.grep_eventually(r"synthetic cert parse failure", timeout=5), \
            "expected synthetic cert parse error in log"


def test_fault_inject_upgrade_ready_signal(bin_path, log_path):
    """upgrade.ready_signal fault: upgrade child appears hung → rollback.

    The fault (budget=1) fires immediately, bypassing wait_for_child_ready and
    triggering rollback.  The pre-existing TCP session must survive because
    do_upgrade re-adopts the drained sessions on rollback.
    """
    cfg_path = _write_fault_config([{
        "name": "upgrade.ready_signal",
        "kind": "skip",
        "message": "synthetic: upgrade child never signaled ready",
        "trigger_budget": 1,
    }])
    with Supervisor(bin_path, log_path, config_path=cfg_path) as sup:
        s = socket.create_connection(("127.0.0.1", 7070), timeout=2)
        s.sendall(b"before-rollback\n")
        assert read_line(s) == "before-rollback"

        # Upgrade: rolls back due to the fault (ignore the return code —
        # the rollback path may or may not propagate an error to the client).
        sup.upgrade()
        time.sleep(0.5)

        rollback = sup.grep_eventually(r"upgrade rollback", timeout=5)
        assert rollback, "expected 'upgrade rollback' log after ready-signal fault"

        # Pre-existing session must still echo (rollback re-adopted it).
        s.sendall(b"after-rollback\n")
        reply = read_line(s, timeout=5.0)
        assert reply == "after-rollback", f"session lost on rollback: {reply!r}"
        s.close()


def test_fault_inject_upgrade_session_handoff(bin_path, log_path):
    """upgrade.session_handoff fault: one session's handoff is skipped.

    The upgrade should still commit (the other sessions hand off normally),
    and plain echo continues to work after the upgrade.
    """
    cfg_path = _write_fault_config([{
        "name": "upgrade.session_handoff",
        "kind": "skip",
        "message": "",
        "trigger_budget": 1,
    }])
    with Supervisor(bin_path, log_path, config_path=cfg_path) as sup:
        # Open two sessions: the first handoff fires the fault (dropped),
        # the second handoff proceeds normally.
        s1 = socket.create_connection(("127.0.0.1", 7070), timeout=2)
        s1.sendall(b"s1-pre\n")
        assert read_line(s1) == "s1-pre"
        s2 = socket.create_connection(("127.0.0.1", 7070), timeout=2)
        s2.sendall(b"s2-pre\n")
        assert read_line(s2) == "s2-pre"

        r = sup.upgrade()
        assert r.returncode == 0, f"upgrade with session-handoff fault failed: {r.stderr}"

        assert sup.grep_eventually(r"session handoff skipped by fault injection", timeout=5), \
            "expected 'session handoff skipped' log"

        # New connections still work post-upgrade.
        s3 = socket.create_connection(("127.0.0.1", 7070), timeout=2)
        s3.sendall(b"post-upgrade\n")
        assert read_line(s3) == "post-upgrade"
        s3.close()
        s1.close()
        s2.close()


def test_fault_inject_control_decode(bin_path, log_path):
    """control.decode fault: supervisor logs error on worker status-report decode.

    Workers only send WorkerMsg::StatusReport in response to a ControlMsg::Status
    from the supervisor, which is triggered by the admin `status` command.  We
    call status() to force the exchange, verify the error is logged, then confirm
    the daemon still serves plain traffic.
    """
    cfg_path = _write_fault_config([{
        "name": "control.decode",
        "kind": "io_error",
        "message": "synthetic control decode error",
        "trigger_budget": 0,  # fire on every status-report decode
    }])
    with Supervisor(bin_path, log_path, config_path=cfg_path) as sup:
        s = socket.create_connection(("127.0.0.1", 7070), timeout=2)
        s.sendall(b"plain-during-ctrl-fault\n")
        assert read_line(s) == "plain-during-ctrl-fault"
        s.close()
        # Trigger the supervisor→worker status exchange so the fault fires.
        sup.status()
        assert sup.grep_eventually(r"synthetic control decode error", timeout=5), \
            "expected synthetic control decode error in log"
        # Daemon still alive: another echo works.
        s = socket.create_connection(("127.0.0.1", 7070), timeout=2)
        s.sendall(b"still-alive\n")
        assert read_line(s) == "still-alive"
        s.close()


def test_fault_inject_scm_recvmsg(bin_path, log_path):
    """scm.recvmsg fault: SCM_RIGHTS recv fails; worker logs fallback-to-bind.

    trigger_budget=1 fires once per spawned worker process.  Workers whose
    fallback bind can succeed (processor's UDS) start normally; workers
    whose port is held by the supervisor (plain TCP 7070, TLS TCP 7071) fail
    to bind and are respawned.  We verify the error path is exercised and
    the supervisor stays alive (does not crash).
    """
    cfg_path = _write_fault_config([{
        "name": "scm.recvmsg",
        "kind": "io_error",
        "message": "synthetic SCM_RIGHTS recv failure",
        "trigger_budget": 1,
    }])
    with Supervisor(bin_path, log_path, config_path=cfg_path) as sup:
        # Fault fires during startup on at least one worker.
        assert sup.grep_eventually(r"spawner unavailable; falling back to bind", timeout=5), \
            "expected SCM fallback log after scm.recvmsg fault"
        # Supervisor must still be running: it should log watchdog events.
        assert sup.grep_eventually(r"watchdog|worker child active", timeout=3), \
            "supervisor exited or stopped logging after scm.recvmsg fault"


def test_fault_inject_processor_dispatch(bin_path, log_path):
    """processor.dispatch fault: dispatch_incoming drops the connection when fired.

    budget=1 fires on the first dispatch_incoming call, which in practice is
    the scanner's sidecar connection during startup.  After the one-shot clears,
    all subsequent connections (including user traffic) are dispatched normally.
    """
    cfg_path = _write_fault_config([{
        "name": "processor.dispatch",
        "kind": "skip",
        "message": "",
        "trigger_budget": 1,
    }])
    with Supervisor(bin_path, log_path, config_path=cfg_path) as sup:
        # The fault fires on the first dispatch during startup.
        assert sup.grep_eventually(
            r"processor\.dispatch fault injected", timeout=5
        ), "expected dispatch fault log"
        # Budget exhausted — plain echo works normally.
        s = socket.create_connection(("127.0.0.1", 7070), timeout=2)
        s.sendall(b"dispatch-after-fault\n")
        assert read_line(s) == "dispatch-after-fault"
        s.close()


def test_fault_inject_health_bind(bin_path, log_path):
    """health.bind fault: health endpoint fails to bind; plain still serves traffic."""
    cfg_path = _write_fault_config([{
        "name": "health.bind",
        "kind": "io_error",
        "message": "synthetic health bind failure",
        "trigger_budget": 1,
    }])
    with Supervisor(bin_path, log_path, config_path=cfg_path) as sup:
        s = socket.create_connection(("127.0.0.1", 7070), timeout=2)
        s.sendall(b"plain-no-health\n")
        assert read_line(s) == "plain-no-health"
        s.close()
        assert sup.grep_eventually(r"synthetic health bind failure", timeout=5), \
            "expected synthetic health bind error in log"


def test_fault_inject_metrics_write(bin_path, log_path):
    """metrics.write fault: textfile write fails; supervisor logs error and keeps running."""
    cfg_dir = tempfile.mkdtemp(prefix="fdpass-fi-metrics-")
    metrics_path = os.path.join(cfg_dir, "fdpass.prom")
    cfg_path = _write_fault_config(
        [{
            "name": "metrics.write",
            "kind": "io_error",
            "message": "synthetic metrics write failure",
            "trigger_budget": 1,
        }],
        extra=f'[metrics]\npath = "{metrics_path}"\ninterval_secs = 1\n',
    )
    with Supervisor(bin_path, log_path, config_path=cfg_path) as sup:
        s = socket.create_connection(("127.0.0.1", 7070), timeout=2)
        s.sendall(b"metrics-fault\n")
        assert read_line(s) == "metrics-fault"
        s.close()
        assert sup.grep_eventually(r"synthetic metrics write failure", timeout=5), \
            "expected synthetic metrics write error in log"
        # After the one-shot clears, supervisor eventually writes the file.
        deadline = time.time() + 5
        while time.time() < deadline:
            if os.path.exists(metrics_path):
                break
            time.sleep(0.2)
        assert os.path.exists(metrics_path), \
            "metrics file never appeared after one-shot write fault cleared"


def test_fault_inject_schema_version(bin_path, log_path):
    """schema.version fault: forces 'incompatible version' error on next into_msg call.

    `into_msg` is called both when the supervisor decodes admin requests and when
    it decodes WorkerMsg status reports.  The first call (triggered by status())
    fires the fault; the second call succeeds.  We verify the log and that admin
    keeps working after the budget is spent.
    """
    cfg_path = _write_fault_config([{
        "name": "schema.version",
        "kind": "io_error",
        "message": "synthetic: forced schema version incompatibility",
        "trigger_budget": 1,
    }])
    with Supervisor(bin_path, log_path, config_path=cfg_path) as sup:
        s = socket.create_connection(("127.0.0.1", 7070), timeout=2)
        s.sendall(b"plain-during-schema-fault\n")
        assert read_line(s) == "plain-during-schema-fault"
        s.close()
        # Trigger the first into_msg call so the fault fires (may return empty/error).
        sup.status()
        # The fault wraps into anyhow::Error whose outer context (logged via %e)
        # is "incompatible admin message: {json}"; the inner "synthetic: ..."
        # message is in the chain but not shown by Display in tracing.
        assert sup.grep_eventually(
            r"incompatible admin message", timeout=5
        ), "expected admin-message rejection in log (schema.version fault)"
        # Budget exhausted: admin works normally on the next request.
        out = sup.status()
        assert "processor" in out, f"status broken after schema-version fault: {out!r}"


# ----- runner ------------------------------------------------------------

BEHAVIORAL_TESTS = [
    test_plain_echo,
    test_tls_echo,
    test_scanner_fires,
    test_scanner_ident_captured,
    test_scanner_no_ident_when_no_identd,
    test_peer_auth_self_uid_allowed,
    test_toml_config,
    test_admin_drain_stops_new_accepts_but_keeps_sessions,
    test_admin_reload_swaps_auth_allowlist,
    test_workers_drop_privileges,
    test_workers_sandbox_strict,
    test_freebsd_strict_upgrade_commits,
    test_upgrade_then_successor_crash_respawns,
    test_runtime_directory_override,
    test_systemd_notify_ready,
    test_systemd_watchdog_pings,
    test_systemd_socket_activation,
    test_processor_upgrade_preserves_tcp,
    test_second_generation_upgrade_readopts_not_respawns,
    test_tls_cert_reload_on_sighup,
    test_tls_cert_reload_under_strict_sandbox,
    test_scanner_egress_under_strict_with_override,
    test_schema_versioning_rejects_incompatible,
    test_health_endpoint_200_when_healthy,
    test_health_endpoint_503_when_failed,
    test_metrics_textfile_emitted,
    test_upgrade_counters_increment,
    test_session_cap_accept_then_close,
    test_tls_idle_timeout_closes_session,
    test_per_ip_rate_limit,
    test_structured_logs_and_trace_id,
    test_canary_upgrade,
    test_upgrade_unknown_role,
    test_upgrade_single_role,
    test_upgrade_plain_rollback,
    test_upgrade_rollback,
    test_crash_survival,
    test_supervisor_self_upgrade_on_sighup,
    test_fork_and_drain,
    test_fork_and_drain_deadline,
    test_watchdog_backoff,
    test_watchdog_fail_state,
    test_grandparent_respawns_supervisor,
    test_grandparent_supervisor_refuses_self_upgrade_on_sighup,
]

FAULT_INJECTION_TESTS = [
    test_fault_inject_tls_cert_load,
    test_fault_inject_tls_cert_parse,
    test_fault_inject_upgrade_ready_signal,
    test_fault_inject_upgrade_session_handoff,
    test_fault_inject_control_decode,
    test_fault_inject_scm_recvmsg,
    test_fault_inject_processor_dispatch,
    test_fault_inject_health_bind,
    test_fault_inject_metrics_write,
    test_fault_inject_schema_version,
]

TESTS = BEHAVIORAL_TESTS + FAULT_INJECTION_TESTS

def _compile_patterns(patterns):
    return [re.compile(pattern) for pattern in patterns]

def _selected_tests(args):
    tests = TESTS
    if args.fault_inject_only:
        tests = FAULT_INJECTION_TESTS
    elif args.no_fault_inject:
        tests = BEHAVIORAL_TESTS

    include = _compile_patterns(args.match)
    exclude = _compile_patterns(args.exclude)
    selected = []
    for test in tests:
        name = test.__name__
        if include and not any(pattern.search(name) for pattern in include):
            continue
        if any(pattern.search(name) for pattern in exclude):
            continue
        selected.append(test)
    return selected

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--bin",
        default=os.environ.get(
            "FDPASS_BIN",
            # Script lives at <repo>/e2e/portability.py; the default binary
            # is the repo's own `cargo build` output.
            str(Path(__file__).resolve().parent.parent
                / "target" / "debug" / "echod"),
        ),
    )
    parser.add_argument(
        "--match",
        action="append",
        default=[],
        help="run only tests whose name matches this regex (repeatable)",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="skip tests whose name matches this regex (repeatable)",
    )
    fault_group = parser.add_mutually_exclusive_group()
    fault_group.add_argument(
        "--fault-inject-only",
        action="store_true",
        help="run only the fault-injection scenarios",
    )
    fault_group.add_argument(
        "--no-fault-inject",
        action="store_true",
        help="skip the fault-injection scenarios",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="list the selected tests and exit",
    )
    args = parser.parse_args()
    bin_path = os.path.abspath(args.bin)
    if not os.path.isfile(bin_path) or not os.access(bin_path, os.X_OK):
        print(f"ERROR: binary not found or not executable: {bin_path}")
        print("Build it with `cargo build` and pass --bin /path/to/target/debug/echod")
        return 2
    try:
        selected = _selected_tests(args)
    except re.error as e:
        print(f"ERROR: invalid regex: {e}")
        return 2

    if args.list:
        for test in selected:
            print(test.__name__)
        return 0

    if not selected:
        print("ERROR: no tests selected")
        return 2

    print(f"==> binary: {bin_path}")
    print(f"==> platform: {os.uname().sysname} {os.uname().machine}")
    print(
        "==> selected: "
        f"{len(selected)} tests "
        f"({len(BEHAVIORAL_TESTS)} behavioral, {len(FAULT_INJECTION_TESTS)} fault-injection total)"
    )
    print()

    logdir = tempfile.mkdtemp(prefix="fdpass-portability-")
    print(f"==> per-test logs: {logdir}")
    print()

    width = max(len(t.__name__) for t in selected)
    failures = []
    for t in selected:
        log_path = os.path.join(logdir, f"{t.__name__}.log")
        name = t.__name__.ljust(width)
        sys.stdout.write(f"{name}  ")
        sys.stdout.flush()
        t0 = time.time()
        try:
            t(bin_path, log_path)
            dt = time.time() - t0
            print(f"PASS  ({dt:.1f}s)")
        except Exception as e:
            dt = time.time() - t0
            print(f"FAIL  ({dt:.1f}s)")
            tb = traceback.format_exc()
            failures.append((t.__name__, str(e), log_path, tb))

    print()
    if not failures:
        print(f"All {len(selected)} selected tests passed.")
        return 0
    print(f"{len(failures)} of {len(selected)} selected tests failed:")
    for name, msg, log, tb in failures:
        print(f"\n--- {name} ---")
        print(f"   {msg}")
        print(f"   log: {log}")
        for line in tb.splitlines()[-3:]:
            print(f"   {line}")
    return 1

if __name__ == "__main__":
    sys.exit(main())
