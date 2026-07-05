# 09 · Observability and debugging

> **After this page** you'll know how to diagnose the daemon when an upgrade
> stalls, a worker flaps, TLS reload fails, or sandboxing breaks a path you
> thought was safe.

[`07-operating.md`](07-operating.md) covered the surfaces: admin socket, health
endpoint, metrics, logs. This page is about using them together.

The practical rule is simple: **do not trust a single surface on its own**.
Each one answers a different question.

- `echod status` tells you what the supervisor thinks each worker is doing
  *right now*.
- `/healthz` collapses that state into a load-balancer answer: serve traffic or
  not.
- metrics tell you what happened over time.
- logs explain *why* it happened.

## Start with the admin view

The first question in any incident is whether the supervisor still has a live
control path to each role. `echod status` is the quickest answer because it
shows both per-worker status and the watchdog-derived health snapshot.

Read it in this order:

1. **generation** — did the worker actually roll to a new image?
2. **pid / uptime** — is it the same process, a fresh respawn, or a rapid loop?
3. **in_flight** — is work stuck draining, or did sessions disappear?
4. **health state** — `healthy`, `backoff`, `flapping`, or `failed`.

`HealthState` is defined in [`../../src/control.rs`](../../src/control.rs), and
the transition logic lives in
[`../../src/supervisor/watchdog.rs`](../../src/supervisor/watchdog.rs).

## Reading an upgrade failure

Rolling upgrade progress is streamed as `AdminResp::UpgradeStep` frames:
`Starting`, then either `Done`, `Timeout`, `CanaryAborted`, or `Skipped`. The
supervisor emits them in [`../../src/supervisor/admin.rs`](../../src/supervisor/admin.rs).

When an upgrade looks bad, sort it into one of these buckets:

- **Generation never changed**: the worker never reconnected after `Upgrade`.
  Expect a `Timeout`. Look for startup failures in the worker logs: config load,
  privilege drop, sandbox entry, ready-pipe signaling, inherited-FD adoption.
- **Generation changed, then health regressed**: the upgrade technically
  committed, but the new worker started fast-exiting. That becomes
  `CanaryAborted` when `--canary` is in use.
- **Only one role is broken**: upgrade that role alone first. This is why
  `processor` can be upgraded independently from the thinner acceptors.

The important distinction is **commit failure vs. post-commit regression**.
Those are different bugs with different evidence.

## What watchdog states mean operationally

The watchdog is not just "up or down". It encodes crash cadence:

- `healthy` — either no recent fast exits, or the current worker has stayed up
  long enough to clear the penalty window.
- `backoff` — recent fast exits, but below the flap threshold.
- `flapping` — repeated fast exits; still respawning, but unstable.
- `failed` — enough consecutive fast exits that the role is considered broken.

The exact thresholds are documented in
[`../architecture.md#worker-watchdog`](../architecture.md#worker-watchdog) and
implemented in [`../../src/supervisor/watchdog.rs`](../../src/supervisor/watchdog.rs).

Two consequences matter during debugging:

- `/healthz` returns **503** the moment any role reaches `failed`.
- the supervisor itself stays alive, so the recovery path is usually
  `echod upgrade --target /path/to/fixed-binary`, not a blind full restart.

## Use logs to explain, not to detect

Logs are best after the admin or health surfaces have already told you which
role is suspect.

Typical signatures:

- **schema mismatch**: incompatible-version warning while decoding a control or
  handoff envelope; the generation may never advance or a session adoption may
  be declined.
- **successor never ready**: upgrade request is logged, then the old worker
  times out waiting for the child ready signal.
- **TLS reload failure**: the acceptor logs that reload failed and explicitly
  kept the previous cert/key.
- **sandbox denial on FreeBSD**: expect `ECAPMODE` around any path-based open or
  outbound connect that escaped the FD-oriented design.
- **Linux seccomp miss**: expect the worker to die under strict mode after a
  syscall outside the allowlist.

Those are not hypothetical categories; they map directly to the e2e suite in
[`../../e2e/README.md`](../../e2e/README.md).

## Trace IDs are the join key

Every accepted session gets a `trace_id` minted in the acceptor and then
threaded through:

- acceptor logs,
- scanner `SessionObserved`,
- processor `Session` preamble,
- `SessionHandoff` during upgrade,
- scanner sidecar metadata back into the processor.

The exact path is summarized in
[`../architecture.md#trace-ids`](../architecture.md#trace-ids). In practice,
this means one client session can be followed across multiple worker processes
even through an upgrade boundary.

If you need to answer "what happened to this specific connection?", `trace_id`
is the first thing to grep for.

## Match the surface to the failure

Use the right tool for the question:

- **Is traffic safe to keep routing?** `/healthz`
- **Which role is failing and how recently?** `echod status`
- **Is the system getting worse or recovering over time?** metrics
- **Why did the role behave that way?** logs

Metrics are especially useful for the slow questions. The textfile includes
generation, in-flight, health, restart counters, and
`fdpass_upgrade_total{role,outcome}`. If upgrades are "mostly fine" but one
role keeps timing out or aborting canaries, that counter family will show it
even after the immediate logs have rolled away.

## A practical debugging loop

For this daemon, a good incident loop is:

1. check `echod status`;
2. confirm whether `/healthz` is degraded or still serving;
3. inspect the role's recent logs, filtered by `role` and then `trace_id` if it
   is session-specific;
4. look at metrics for repeated upgrade, restart, or in-flight patterns;
5. if the bug is role-local, upgrade just that role to a fixed binary first.

That ordering avoids a common mistake: tailing logs before you know whether the
problem is a single worker, the supervisor, or merely an old transient event.

---

⇒ **Next:** [`10-control-plane-and-wire-compatibility.md`](10-control-plane-and-wire-compatibility.md)
