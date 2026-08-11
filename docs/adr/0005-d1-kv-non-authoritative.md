# ADR-0005: D1 and KV Are Non-Authoritative

- Status: Accepted
- Date: 2026-08-11
- Scope: D1 projector, KV usage, edge API, RP lifecycle checks

## Context

D1 provides useful queryable projections and KV can cache immutable public data, but either may
return stale information. A stale `active` value must never authorize a subject after its
authoritative Durable Object is terminally revoked.

## Decision

D1 stores only a rebuildable operational projection and event index. KV, if used, stores only
immutable/cached public configuration or other values that cannot make authorization unsafe when
stale. Neither D1 nor KV participates in current lifecycle authorization.

If D1 disagrees with the subject Durable Object, the Durable Object wins. Projector consumers
deduplicate by deterministic `eventId`, ignore duplicates, and apply state only when the incoming
sequence is not older than the stored sequence. Admin access to D1 is protected and does not expose
a public subject directory.

Worker memory, R2, Queue state, metrics, and transparency artifacts are likewise non-authoritative.

## Consequences

- D1 can be lost, restored with Time Travel, or rebuilt without mutating subject authority.
- Queue lag affects operational views and transparency latency, not registration/status/revocation
  correctness.
- Caches can improve immutable discovery/key delivery but cannot cache an unsafe lifecycle decision
  beyond an explicitly verified signed-status policy.
- Operational tooling must label projection state as non-authoritative.

## Compliance

Tests cover stale D1 after revocation, duplicate/out-of-order events, projector rebuild, Queue
retry, and architectural/lint checks that prevent lifecycle authorization through D1 or KV.
