# 10 · Control plane and wire compatibility

> **After this page** you'll know why versioned JSON envelopes are a first-class
> part of the design, and which compatibility boundaries matter during an
> upgradeable daemon's life.

The data plane in this project is simple bytes and lines. The control plane is
where compatibility gets dangerous.

During a rolling upgrade, the system briefly contains old and new images at the
same time. That means message compatibility is not optional; it is part of the
upgrade mechanism.

## One envelope for every cross-process JSON message

Cross-process JSON is wrapped in [`Envelope<T>`](../../src/control.rs), which
adds a sibling `version` field to the payload.

That envelope is used for:

- `ControlMsg` on supervisor↔worker and CLI→supervisor links,
- `WorkerMsg` replies,
- `AdminResp` progress streamed back to the CLI.

Parsing goes through `parse_envelope`, which deserializes and then calls
`Envelope::into_msg()`. Compatibility is checked there, against
`SCHEMA_VERSION` and `MIN_COMPATIBLE_VERSION`.

The reference overview is
[`../architecture.md#control-plane-wire-protocol`](../architecture.md#control-plane-wire-protocol).

## The three compatibility boundaries

This repo has three distinct versioning problems.

1. **CLI ↔ supervisor**
   An old `echod status` or `echod upgrade` client may talk to a newer daemon,
   or the reverse.
2. **Supervisor ↔ workers**
   During a rolling upgrade, the old supervisor talks to a new worker and then a
   new supervisor may later talk to an older still-running worker.
3. **Upgrade-time session adoption**
   `SessionHandoff` records preserve in-flight processor sessions across a
   re-exec. Those records also carry a schema version.

The third boundary is easy to miss and the most expensive to get wrong, because
a mismatch there can silently turn "zero-downtime processor upgrade" into
"session loss on upgrade".

## Compatibility policy is explicit

Messages without a `version` field default to 1, which is the initial
compatibility escape hatch for older peers. Beyond that, the policy is
deliberate:

- bump `SCHEMA_VERSION` when you change the wire format;
- keep `MIN_COMPATIBLE_VERSION` where it is if you still support older peers;
- raise `MIN_COMPATIBLE_VERSION` only when you intentionally break them.

That is not just bookkeeping. It is a statement about which mixed-generation
pairs are allowed to coexist during deployment.

## What happens on mismatch

On an incompatible envelope, `into_msg()` returns an error. That propagates
differently depending on the channel:

- admin/control paths return structured error responses or log warnings;
- session adoption declines incompatible sessions and keeps going for the rest.

That "decline one record, keep the process alive" behavior is important. The
processor's adoption path does not assume every inherited session is salvageable;
it filters on compatibility and logs what it dropped.

The architectural summary is in
[`../architecture.md#schema-versioning`](../architecture.md#schema-versioning).

## Evolving the control plane safely

For this design, the safest wire changes follow a boring pattern:

1. add new fields as optional with serde defaults;
2. make old receivers ignore what they do not need;
3. keep semantic meaning stable for existing variants;
4. only remove or repurpose fields when you are also willing to bump the
   minimum compatible version.

The repo already leans on that pattern. For example, control-plane structs use
defaults and `skip_serializing_if` on fields that are not always present, which
gives older peers room to coexist.

## Why this matters more here than in a normal CLI tool

In a one-shot program, wire incompatibility is just an error path. In a
zero-downtime daemon, it can break the upgrade story itself.

Examples:

- if the admin CLI cannot understand `UpgradeStep`, operators lose visibility
  into whether the walk committed or stalled;
- if a worker cannot parse `Upgrade` or `Reload`, the supervisor can no longer
  drive the role safely;
- if `SessionHandoff` becomes incompatible, the processor may reconnect but fail
  to preserve in-flight sessions.

So compatibility is not a polish feature. It is part of correctness.

## Test the boundaries that matter

This repo checks compatibility in both inline tests and e2e:

- unit tests cover envelope parsing and schema-compatibility helpers;
- e2e covers schema-version rejection in the real process topology.

That split is right for this problem. Unit tests prove the parser and policy.
End-to-end tests prove that the failure is observable and non-catastrophic in
the running system.

## A maintainer's checklist

Before changing any control-plane or handoff type, answer these questions:

- Which peers can see this message?
- Can mixed generations coexist during an upgrade after this change?
- Does the old peer need to understand the new field, or can it ignore it?
- What happens to already-live sessions crossing the upgrade boundary?
- Which test should fail if this compatibility contract breaks?

If those answers are vague, the change is not ready yet.

---

⇒ **Next:** [`11-portability-and-kernel-differences.md`](11-portability-and-kernel-differences.md)
