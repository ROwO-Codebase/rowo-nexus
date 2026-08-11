# ADR-0010: Hash-Only Transparency

- Status: Accepted
- Date: 2026-08-11
- Scope: registry events, transparency Worker/DOs, public artifacts

## Context

Transparency should make silent registry-history rewriting difficult without turning Nexus into a
public chronological directory of pseudonyms. Publishing ordered subjects would create new
correlation metadata even though lifecycle state is cryptographically public.

## Decision

Transparency appends deterministic registry event hashes, deduplicated by event ID, to shardable
append-only structures. The production interface supports 256 shards selected from the first hash
byte; development may use one shard without changing receipt schemas.

Signed checkpoints expose shard ID, size, Merkle root (or reviewed equivalent), checkpoint time,
signer `kid`, and inclusion proofs requested by an event hash the holder already knows. R2 stores
signed checkpoint manifests and optional compact hash segments.

No public API lists subjects or registry events chronologically. A global checkpoint manifest may
commit to all shard roots but must not expose a subject inventory.

## Consequences

- Holders can audit inclusion using receipt-derived event hashes without browsing a pseudonym
  directory.
- Queue retries cannot create duplicate leaves.
- Transparency lag or outage does not control lifecycle authorization; the subject Durable Object
  remains authoritative.
- Public checkpoint keys are purpose-separated from registry receipt/status keys and retained for
  the promised verification lifetime.

## Compliance

Tests cover deterministic event hashing, duplicate delivery, inclusion-proof verification,
checkpoint signatures, shard-compatible interfaces, and absence of chronological subject enumeration
from public schemas/endpoints.
