# Nexus transparency Worker

This Worker is a hash-only, downstream audit service. It is never a lifecycle authority.

- The projector calls the idempotent `append(RegistryEventV1)` service-binding RPC.
- Registry events are strictly parsed and their deterministic event ID is recomputed before append.
- The first event-hash byte selects one of 256 `TransparencyShard` Durable Objects.
- Shards store an append-only RFC 6962-style SHA-256 tree in SQLite.
- Public APIs return signed shard checkpoints and inclusion proofs by event hash only.
- `publishCheckpoint(shardId)` writes an immutable R2 checkpoint and a non-evidentiary latest
  pointer.
- The `0 0 * * *` UTC cron publishes all shard checkpoints in batches of 16, then publishes the
  complete global manifest. Its promise is registered with `waitUntil` and awaited, so a failed R2,
  Durable Object, validation, or signing operation makes the scheduled invocation fail visibly.

There is intentionally no subject search, event listing, public append route, or registry event body
in public artifacts. Signed checkpoints help observers detect rewrites when they retain and compare
them; they do not by themselves prevent every split-view attack.

The optional generic notary described in the protocol specification is not enabled here. It remains
a separate opt-in extension with its own signing key and abuse policy.

## Transparency verification keys

`GET /.well-known/nexus-transparency-keys.json` returns the strict shared `ServiceKeySet` configured
in `TRANSPARENCY_PUBLIC_KEYSET_JSON`. It is public, CORS-readable, ETag-enabled, and cached for five
minutes. The endpoint is the purpose boundary: every key must be Ed25519/EdDSA, have an exact `kid`,
and have either no `use` or `use: "sig"`. Custom JWK purpose fields are rejected.

Configure `TRANSPARENCY_SIGNING_KEY_PKCS8_B64URL` as a Worker secret and set
`TRANSPARENCY_SIGNING_KID` to the matching public key's `kid`. For rotation, add the new public key
to the keyset while retaining all historical transparency keys, update the secret and current `kid`,
and deploy the three values together. Historical keys must remain published for as long as their
signed checkpoints are expected to verify.

The registry service keyset and this transparency keyset are separate trust contexts. They are not
interchangeable even if a `kid` happens to have the same text. Transparency keys must not sign
registry receipts or status statements, and registry keys must not verify transparency artifacts.

## Publication operations

The daily 00:00 UTC schedule is deliberately the only automatic production publication path; there
is no public administration endpoint. It writes one immutable and one `latest.json` object for each
shard, then the corresponding immutable and latest global objects. Checkpoints are durable per tree
size and Ed25519 signatures are deterministic, so a retry with no new events rewrites the same bytes
and creates no new immutable key. Alert on failed scheduled invocations and retry the invocation
after correcting the dependency or configuration failure.
