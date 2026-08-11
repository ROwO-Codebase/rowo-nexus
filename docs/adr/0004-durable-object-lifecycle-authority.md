# ADR-0004: Durable Object Lifecycle Authority

- Status: Accepted
- Date: 2026-08-11
- Scope: registry, edge API, projector, relying-party lifecycle checks

## Context

Revocation must be irreversible and immediately serializable for one subject. Worker memory is
ephemeral, KV is eventually consistent, D1 replicas may be stale, R2 is not a coordination
primitive, and Queue delivery can retry or lag.

## Decision

One deterministic SQLite-backed `IdentityState` Durable Object per self-certifying subject is the
only authoritative mutable lifecycle source. It owns genesis, `active|revoked` state, sequence,
server timestamps, action idempotency, and a durable outbox.

Registration creates sequence `0`. State-changing requests carry `expectedSequence`. Revocation
verification, terminal state update, sequence increment, action record, and outbox insert commit
atomically. No code path may transition `revoked` back to `active`.

Queue publication occurs after commit and retries from the outbox. Strict status checks address the
subject Durable Object.

## Consequences

- Concurrent registration/revocation is serialized at the subject boundary.
- Queue or projector outages may cause lag without weakening lifecycle correctness or signed
  receipts.
- Repeated identical registration/revocation is idempotent; subject/genesis conflict is a critical
  security signal.
- The authoritative state machine stays deliberately small: `NONE -> ACTIVE -> REVOKED`.

## Compliance

Tests cover 50 concurrent identical registrations, racing signature/secret revocation, sequence
conflicts, attempted unrevocation, outbox retry, and current-control denial after terminal
revocation.
