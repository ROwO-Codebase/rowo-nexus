# Identity Lifecycle

The authoritative lifecycle is intentionally terminal:

```text
NONE --register--> ACTIVE --revoke/dispose--> REVOKED
```

There is no `REVOKED -> ACTIVE` transition, ownership transfer, recovery into a new key, or
server-side identity claim in v1.

## Authority and sequence

One SQLite-backed `IdentityState` Durable Object is addressed deterministically from each
self-certifying subject. It is the only mutable lifecycle authority and owns genesis, current state,
sequence, timestamps, idempotency history, and its durable event outbox.

Registration creates `ACTIVE` at sequence `0`. A state-changing request carries `expectedSequence`;
the Durable Object checks and increments it atomically. Re-registering identical genesis is
idempotent. Genesis conflict for the same subject is a critical error.

D1 is a rebuildable operational projection. KV, R2, Queue consumers, transparency logs, and Worker
memory are not lifecycle authority.

## Revocation

An active identity can revoke through either:

- a typed revocation payload signed by the identity's Ed25519 key; or
- disclosure of the 32-byte revocation secret whose domain-separated SHA-256 commitment is in
  genesis.

Within one Durable Object transaction the registry checks active state and sequence, verifies the
chosen authorization, records `REVOKED`, increments sequence, assigns server time, records the
action, and inserts an outbox event. Repeated revocation is idempotent and returns the same terminal
state.

The mutation and outbox insert commit together. Queue publication happens afterward; failed sends
remain durable and retry through alarms or later requests. Consumers deduplicate deterministic event
IDs.

## Disposal

The wallet disposal order is mandatory:

1. ask for clear confirmation of the selected identity;
2. submit a terminal revocation;
3. verify the service-signed revocation receipt and subject/state;
4. only then erase local key material, revocation secret, scope mappings, and active references
   where possible;
5. retain only minimal receipt/history data if the user chooses.

If revocation fails, the wallet must not present disposal as complete. Browser/OS deletion is
best-effort; registry revocation is what prevents surviving or restored key material from regaining
future control.

## Rotation and continuity

Privacy rotation generates a new independent identity and may separately revoke the old one. No
combined rotation endpoint, old/new database column, event, or automatic proof link is permitted.

Continuity linking is an explicit, separately versioned certificate signed by both identities after
clear linkability warnings. It is never produced as a side effect of rotation.
