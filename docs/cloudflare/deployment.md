# Cloudflare Deployment

This is the Phase 0 deployment contract. Binding syntax and product behavior must be re-checked
against current primary Cloudflare documentation before each implementation phase or production
rollout; examples in `NEXUS_SPEC.md` are illustrative rather than copy-ready.

## Service topology

```text
wallet.rowo.link (static wallet; client keys only)
        |
nexus.rowo.link (edge validation, CORS, receipts/status signing)
        |
        +-- REGISTRY_SERVICE --> registry Worker
        |                           +-- IdentityState SQLite DOs (authority)
        |                           +-- v1 outbox --> nexus-registry-events Queue --+
        |                           +-- v2 device outbox                           |
        |                                 --> nexus-registry-device-events Queue --+--> D1 projector
        |                                                                              +-- TRANSPARENCY_SERVICE RPC
        |                                                                                    +-- shard DOs
        |                                                                                    +-- R2 checkpoints

status.rowo.link (optional controlled transparency/checkpoint publication)

notes.rowo.link (reference RP assets + API)
        +-- ReferenceRpState SQLite DO (durable challenges, notes, sessions, receipts)
```

Service Bindings keep registry and transparency internal APIs off the public Internet. The edge
Worker performs strict method, content-type, size, schema, CORS, and abuse validation but never owns
lifecycle state in memory.

## Environments

Use four isolated environment classes:

| Environment   | Purpose                                      | Data policy                                                                   |
| ------------- | -------------------------------------------- | ----------------------------------------------------------------------------- |
| `local`       | Developer machine and deterministic fixtures | Local emulation; non-production fixture keys only.                            |
| `preview/dev` | Pull requests and integration branches       | Ephemeral/synthetic identities; never bound to production resources.          |
| `staging`     | Release candidate and migration rehearsal    | Dedicated resources and keys; no production identity data.                    |
| `production`  | Public service                               | Production-only namespaces, buckets, databases, queues, domains, and secrets. |

Every environment has distinct:

- registry receipt/status signing key and `kid`;
- Durable Object namespace/migration history;
- D1 database;
- Queue producers/consumers;
- R2 transparency bucket;
- rate-limit namespace and metrics dataset;
- wallet/API/status origins.

Preview or staging Workers must never reference production Durable Objects, D1, R2, Queues, service
bindings, or signing secrets. CI for untrusted pull requests receives no production Cloudflare
credentials and performs local builds/dry runs only.

## Public endpoints and headers

- `wallet.<domain>`: dedicated wallet UI, strict CSP, no third-party scripts/analytics/fonts, no
  framing, no referrer, and no credentials shared with the API.
- `nexus.<domain>`: fixed protocol endpoints using `application/nexus+json`; mutation/status
  responses use `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, and
  `Referrer-Policy: no-referrer`.
- `status.<domain>`: optional signed checkpoint artifacts under an explicit cache policy; never a
  chronological subject directory.
- `notes.<domain>`: reference RP static assets and proof-gated API backed by its own SQLite Durable
  Object; it is not a Nexus lifecycle authority.

Public read/status CORS may use a wildcard only because responses are public and requests have no
credentials. Mutation endpoints admit only the wallet origin and explicitly approved native/CLI
clients. Wildcard CORS is never combined with credentials.

Discovery is versioned for strict-client compatibility. `/.well-known/nexus.json` retains the exact
v1 response. V2-aware clients use `/.well-known/nexus-v2.json`, which advertises v1 and v2 proof
protocols, the `/v2/device` registry base, `nexus.popup.v2` and `nexus.popup.v1`, and a link back to
the v1 discovery document. Adding v2 MUST NOT widen the legacy response.

## Bindings and authority

- Registry Worker: `IDENTITY_STATE` SQLite Durable Objects, `REGISTRY_EVENTS` producing to
  `nexus-registry-events`, and `REGISTRY_DEVICE_EVENTS` producing to the separate
  `nexus-registry-device-events` queue.
- Projector Worker: separate consumers for both queues, non-authoritative `INDEX_DB` D1, and an
  internal transparency binding. Each queue has its own dead-letter queue.
- Edge Worker: internal `REGISTRY_SERVICE`, coarse rate limiter, and aggregate-only metrics.
- Transparency Worker: shard Durable Objects and R2 checkpoint storage.
- Reference RP Worker: static assets, a coarse API rate limiter, and one SQLite Durable Object for
  its application data.
- KV, when present, stores only immutable/cached public configuration. It never stores lifecycle
  authorization.

Lifecycle mutations and outbox events commit atomically inside the subject Durable Object. Queue
failure may delay projection/transparency, but cannot roll back or weaken revocation. D1 is rebuilt
from events and never queried to authorize current control.

The identity and device queues are independently at-least-once and unordered. Projector deployment
must tolerate a v2 device event arriving before its v1 registration anchor, deduplicate each event
by its deterministic ID, and reconcile materialized device state after the anchor appears. Device
events are never parsed as v1 lifecycle events and never change the v1 identity sequence.

The transparency Worker publishes all 256 shard checkpoints and the ordered global manifest through
its daily UTC cron. There is no public checkpoint-administration endpoint. Alert on failed scheduled
invocations and retain historical public verification keys for every published checkpoint lifetime.

## Secrets and keys

Store private service keys in per-Worker secrets or an explicitly approved Secrets Store deployment.
Separate registry receipt/status, transparency checkpoint, and optional notary keys. Publish public
key history by `kid` for at least the promised receipt-verification lifetime.

User signing keys, agreement keys, revocation secrets, and plaintext wallet manifests never enter
Cloudflare secrets, logs, environment variables, or storage.

## Migration and release procedure

1. Run formatting, lint, strict type checks, all unit/Worker/vector/browser tests, build, and every
   Worker dry run.
2. Verify no production credentials are present in PR/preview context and resource IDs resolve only
   to the target environment.
3. Apply version-controlled D1 migrations to a restored realistic fixture; confirm projector replay,
   duplicate, and out-of-order behavior. Before enabling the device queue consumer, apply
   `migrations/d1/0002_device_projection_v2.sql`; confirm early device-event reconciliation and that
   existing v1 tables and projections remain unchanged.
4. Apply Durable Object class/storage migrations using versioned Wrangler migration tags and
   application-level schema migration code.
5. Provision both source queues and their distinct dead-letter queues. Deploy the projector with
   both consumers, then the registry with both producer bindings. Deploy remaining internal services
   before the public edge, then the wallet/reference surfaces.
6. Run smoke checks for exact v1 discovery, versioned v2 discovery, JWKS,
   register/status/revoke/device operations, service receipt verification, both outboxes and queues,
   early-event reconciliation, and D1 non-authority.
7. Confirm wallet CSP, exact-origin popup behavior, and absence of key/proof material in network and
   logs.
8. Monitor privacy-safe error/latency buckets and outbox/projector lag; do not add identifiers to
   diagnose failures.

Production migration runbooks require a tested recovery path. D1 Time Travel can recover the
projection but does not replace idempotency/event replay. Durable Object authority must never be
mutated to match stale or corrupt D1 data.

## Rollback boundaries

Application and edge code may roll back to a compatible version. Lifecycle events and terminal
revocations do not roll back. Schema or suite changes require new protocol versions and ADR/security
review; they cannot silently reinterpret existing genesis or signed objects.
