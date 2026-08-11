# Incident Response

Preserve lifecycle correctness and minimize new sensitive collection during every incident. Do not
enable verbose payload logging, copy production secrets into tickets, or use real identities in
reproduction steps.

## Common first response

1. Assign an incident lead, severity, UTC timeline, and private communications channel.
2. Identify affected environment, service, protocol/suite, `kid`, and time window using privacy-safe
   aggregates.
3. Contain only the affected boundary; do not mutate terminal identity state or trust D1/KV to
   repair authority.
4. Preserve necessary evidence under restricted access and the normal retention ceiling; document
   any approved extension.
5. Use synthetic identities to reproduce and validate the fix.
6. Rotate exposed service credentials, deploy through the isolated environment pipeline, and run
   protocol/Worker/browser regression tests.
7. Publish an incident statement when public trust artifacts or promised verification are affected.
8. Complete a blameless review covering root cause, privacy impact, protocol invariants, detection
   gaps, and follow-up owners.

## User signing-key compromise

If the user retains the independent revocation secret:

1. submit secret-mode revocation to the authoritative subject Durable Object;
2. verify the signed terminal revocation receipt;
3. relying parties using strict freshness immediately deny new control proofs;
4. create a new independent identity if desired, without publishing an old/new link;
5. assess RP acceptance receipts for activity during the exposure window.

Before revocation, Nexus cannot distinguish the legitimate holder from a thief who has the signing
key. After revocation, surviving or copied keys can still make mathematically valid signatures, but
current-control authorization must fail.

## Nexus registry receipt/status key compromise

1. Stop issuing with the compromised `kid` and isolate the affected secret/binding.
2. Generate and deploy a replacement key in each affected environment; never reuse a key from
   another environment or purpose.
3. Publish the replacement public key and retain the old public key for historical verification.
4. Publish a signed incident/trust statement marking the compromise interval and affected key
   purpose.
5. Assess receipts and status statements issued during exposure; shorten/deny status-statement trust
   as required by RP policy.
6. Confirm no user private identity keys were present. Service-key compromise cannot forge user
   Ed25519 identity signatures.

Transparency checkpoint and optional notary keys follow the same containment pattern but remain
purpose-separated from registry signing.

## Wallet-origin or supply-chain compromise

Wallet XSS or malicious deployed JavaScript may request signatures even from non-extractable keys.

1. Disable the wallet deployment or affected proof operation while preserving public registry status
   access.
2. Revoke compromised deployment/service credentials and identify the exact build
   artifact/dependency interval.
3. Compare immutable build provenance, CSP, lockfile, and deployed assets; remove unauthorized
   third-party code.
4. Warn users that identities used during the interval may require terminal revocation and
   independent replacement.
5. Validate that no raw key, revocation secret, scope map, or proof payload was exfiltrated through
   network/log/analytics paths.
6. Redeploy a reviewed artifact and rerun two-origin popup, CSP, network-leak, and consent tests.

## D1 loss, corruption, or stale projection

D1 is not authoritative; registration, status, and revocation continue through subject Durable
Objects.

1. Remove the projector/admin view from operational use if it is misleading.
2. Recover with D1 Time Travel where appropriate or rebuild from registry events/transparency/export
   fixtures.
3. Reconcile sampled or inventoried subjects against authoritative Durable Objects.
4. Test duplicate and out-of-order projector handling before resuming.
5. Never change a subject Durable Object to match D1.

## Queue/projector/transparency outage

Authoritative lifecycle mutations may continue because the Durable Object transaction writes a
durable outbox before Queue publication.

1. Monitor pending outbox age/count using aggregate buckets.
2. Restore the Queue/consumer without deleting pending outbox entries.
3. Trigger alarms or safe replay; consumers deduplicate by deterministic `eventId`.
4. Verify D1 sequences and transparency leaves/checkpoints converge without duplicates.
5. Registry receipts remain valid; communicate projection/transparency lag if public promises are
   affected.

## Durable Object lifecycle anomaly

Treat any apparent subject/genesis conflict, divergent sequence, double terminal event, or
`REVOKED -> ACTIVE` observation as critical.

1. Stop affected mutation paths without deleting evidence.
2. Verify the self-certifying subject, canonical genesis bytes, action history, sequence, and signed
   receipts.
3. Do not use D1, KV, or admin edits to override the subject Durable Object.
4. Escalate for protocol/security review before any data repair. Terminal revocation must not be
   rolled back.

## Network-correlation or privacy incident

Nexus does not guarantee network anonymity, but unexpected collection or retention is an incident.

1. disable the unnecessary log/trace/analytics dimension;
2. identify datasets, processors, access, and retention interval;
3. delete excess telemetry where legally and operationally permitted without deleting
   protocol-required revocation state;
4. update the data inventory, tests, provider configuration, and public limitation statement;
5. assess whether users or RPs require notification.

## Exit criteria

Close an incident only after containment, tested remediation, environment-wide key/resource
verification, retention cleanup, required user/operator communication, and tracked follow-up
actions. Production remains blocked if any cryptographic, lifecycle, origin, logging, or privacy
invariant is uncertain.
