# Nexus Anonymous Identity Protocol & Cloudflare Reference Architecture

**Status:** Implementation Specification / Codex Build Plan  
**Version:** `0.1.0-draft`  
**Last validated:** 2026-08-11  
**Primary runtime:** Cloudflare Workers  
**Primary language:** TypeScript  
**Repository:** `nexus` (standalone from any consuming anonymous platform)

---

## 0. Purpose

Nexus is a reusable cryptographic identity layer for anonymous and pseudonymous applications.

Nexus MUST let a person create one or more disposable cryptographic identities, use those identities to prove control of posts/chats/resources, rotate to unrelated identities, and irreversibly dispose of an identity without requiring the service to know the person's real-world identity.

Nexus is **not** an account system. It MUST NOT create a globally visible account identifier that every relying application receives. A single local Nexus wallet MAY manage many identities, but those identities MUST be independent and unlinkable by default.

The central semantic is:

> A resource belongs to a Nexus subject if control can be proven with the cryptographic key material bound to that subject, subject to the subject's current lifecycle state.

The central privacy invariant is:

> Nexus MAY know that a cryptographic subject exists, but MUST NOT require or persist a mapping from that subject to a real person, email address, phone number, social account, permanent user ID, or other civil identity.

This document specifies the protocol, cryptographic objects, Cloudflare deployment, data models, repository architecture, browser wallet, relying-party integration, lifecycle semantics, threat model, implementation phases, and acceptance criteria.

---

## 1. Normative language

The words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative requirements.

When implementation convenience conflicts with a privacy or cryptographic invariant in this document, the invariant wins.

---

## 2. Goals

Nexus MUST provide:

1. **Self-certifying pseudonyms**
   - A subject identifier is derived cryptographically from an immutable public identity document.
   - A different public key cannot be substituted while preserving the same subject.

2. **Proof of control**
   - A user can prove that they currently control a subject without a username/password account.
   - Proofs are audience-bound, action-bound, resource-bound, time-bounded, and replay-resistant.

3. **Disposable identities**
   - Identities are independently generated.
   - Disposing one identity MUST NOT affect any other identity.
   - Disposal is an irreversible server-recognized revocation followed by best-effort client crypto-shredding.

4. **Privacy-preserving rotation**
   - Default rotation creates a completely independent identity with no protocol-visible link to the previous one.
   - Continuity-preserving linking is a separate, explicit operation.

5. **No real-identity database link**
   - No Nexus table or application integration contract requires `user_id -> subject`.

6. **Reusable relying-party integration**
   - Forums, chat systems, document systems, games, or other applications can consume the same protocol and verifier SDK.

7. **Unified local wallet, pairwise public pseudonyms**
   - One wallet can organize many identities locally.
   - The wallet MUST NOT expose a permanent root/controller identifier to relying applications.

8. **Independent verification**
   - Signatures and subject derivation MUST be verifiable locally using the public protocol package.
   - Fresh lifecycle status may require a registry lookup or a sufficiently fresh signed status statement.

9. **Cloudflare-native deployment**
   - Workers provide public protocol endpoints.
   - Durable Objects provide authoritative per-subject lifecycle coordination.
   - D1 is a non-authoritative projection/index.
   - Queues handle asynchronous projection/logging work.
   - R2 stores opaque encrypted backup blobs and transparency artifacts.

10. **Algorithm and protocol versioning**
    - Every signed object and identity suite is versioned from day one.

---

## 3. Non-goals

Version 1 does NOT attempt to provide:

- Proof that one human controls only one identity.
- Sybil resistance solely from cryptography.
- Guaranteed network anonymity from Cloudflare, ISPs, Tor exit nodes, or timing correlation.
- Recovery of a disposed private key.
- A way for a user to destroy a private key and later still prove live possession of that destroyed key.
- A universal cross-application user ID.
- A social graph shared by Nexus.
- Server-side custody of user identity private keys.
- A custom cryptographic primitive.
- End-to-end chat encryption itself. Chat protocols such as MLS belong to consuming applications; Nexus supplies identity/control primitives.
- Perfect physical secure deletion from browser/OS storage. Nexus enforces disposal through irreversible revocation even if old key material survives elsewhere.

---

# Part I — Security and Privacy Model

## 4. Terminology

### 4.1 Nexus Wallet

A client application served from the dedicated Nexus wallet origin. It stores and uses private identity material locally and presents consent UI for relying-party proof requests.

### 4.2 Controller

A **local-only concept** used by the wallet to organize identities. It MUST NOT be represented by a global public user identifier.

### 4.3 Identity / Subject

A disposable pseudonymous cryptographic identity represented externally by a self-certifying subject string.

Example:

```text
nx1_KXvYGtIr9V5ISvMZgkMQy7sUe6V8KaPmTVc66N9cH1Q
```

### 4.4 Relying Party (RP)

An application that accepts Nexus identities, for example an anonymous forum or chat platform.

### 4.5 Genesis Document

The immutable public material from which a Nexus subject is derived.

### 4.6 Ownership Proof

A signed statement proving control of a subject for a particular audience, action, resource, challenge nonce, and validity interval.

### 4.7 Registry

The public Nexus service that records genesis documents and authoritative lifecycle state (`active` or `revoked`).

### 4.8 Disposal

The terminal process:

1. publish irreversible revocation;
2. receive a valid revocation receipt;
3. erase local identity key material and local references where possible.

### 4.9 Privacy Rotation

Creating a new independent identity and optionally revoking the old identity, without publishing a cryptographic link between them.

### 4.10 Continuity Link

An explicit certificate signed by two identities stating that they are intentionally linked. It is never created automatically.

---

## 5. Privacy invariants

The implementation MUST enforce all of the following.

### P1 — No permanent public controller identifier

The wallet MUST NOT send a stable controller ID, vault ID, installation ID, device ID, account ID, or master public key to relying parties.

### P2 — Independent identities

Each disposable identity MUST use independently generated random private key material. Disposable identities MUST NOT be deterministically derived from a surviving master seed.

Reason: if identity `A` can be regenerated from a master seed, deleting `A` is not meaningful cryptographic disposal.

### P3 — Scope relationships are local

The mapping:

```text
RP origin -> locally selected Nexus identities
```

MUST remain in the local wallet manifest or opaque encrypted backup. It MUST NOT be stored in plaintext in the Nexus registry.

### P4 — No RP audience in identity genesis

The Genesis Document MUST NOT contain an application domain or relying-party identifier. This prevents the Nexus registry from learning the intended application for an identity merely from registration.

### P5 — Cross-scope reuse requires explicit user action

The wallet SDK MUST default to one or more identities selected for the requesting RP origin. Using the same identity with a different RP origin MUST require explicit confirmation.

### P6 — No cookies on protocol API

`api.nexus.example` SHOULD be stateless with respect to browser cookies. The core identity API MUST NOT require a session cookie.

### P7 — Sensitive data never enters logs

Application logs MUST NOT contain:

- private keys;
- revocation secrets;
- backup capability secrets;
- raw signed proof bodies;
- identity Genesis Documents unless explicitly running a local debug build;
- subject identifiers in routine access logs;
- IP addresses or user agents written by application code.

### P8 — Identity identifiers stay out of URLs where practical

Identity-specific public APIs SHOULD use fixed POST endpoints with the subject in the request body rather than URL path/query parameters. This reduces accidental identity exposure in HTTP access logs, browser history, proxies, and analytics.

### P9 — Nexus registry is not an identity directory

There MUST NOT be a public endpoint to enumerate subjects by registration time, IP, device, platform, or other metadata.

### P10 — D1 is never an authorization source

D1 read replicas/projections MUST NOT determine whether a subject is currently active. Current lifecycle authority belongs to the subject's Durable Object.

---

## 6. Threat model

Nexus MUST be designed against the following attackers.

### T1 — Database attacker

An attacker obtains a D1 export, R2 objects, or operational data.

Expected protection:

- no real-person mapping exists;
- no user private identity keys exist server-side;
- backup objects are encrypted client-side;
- D1 contains only public cryptographic state/projections and operational metadata permitted by this spec.

### T2 — Identity forger

An attacker generates a new key and claims an existing subject.

Expected protection:

- subject is derived from immutable genesis material;
- public-key substitution changes the subject;
- signatures verify only under the genesis signing key.

### T3 — Replay attacker

An attacker replays a previously valid proof.

Expected protection:

- RP challenge nonce is single-use;
- proof includes `aud`, `act`, `resource`, `iat`, `exp`, and nonce;
- RP atomically consumes the challenge.

### T4 — Cross-application proof replay

A proof issued for App A is submitted to App B.

Expected protection:

- `aud` is mandatory and exact-match validated.

### T5 — Post-disposal key holder

An attacker later obtains an old exported key or backup copy.

Expected protection:

- current-control operations fail because registry state is irrevocably `revoked`;
- current proofs MUST be checked against sufficiently fresh lifecycle state;
- historical authorship claims require a trusted receipt/timestamp from before revocation, because a stolen old private key can forge a backdated self-asserted timestamp.

### T6 — Malicious relying party

An RP tries to make the wallet sign a statement for another audience/action/resource.

Expected protection:

- wallet derives audience from the actual `postMessage` sender origin;
- user sees the action/resource in consent UI;
- the wallet does not accept arbitrary `aud` from RP-controlled JSON.

### T7 — XSS against wallet origin

An attacker executes arbitrary JavaScript in the wallet origin.

Impact:

- XSS is treated as potentially equivalent to key compromise.

Mitigation:

- no third-party scripts;
- strict CSP;
- no dynamic `eval`/`Function`;
- dependencies pinned and audited;
- all key operations require wallet-origin code;
- build and deployment pipeline is security-critical.

### T8 — Nexus service operator

The operator attempts to correlate users.

Protection boundary:

- protocol/data design denies direct real-person mappings;
- registry does not receive RP audience during identity registration;
- wallet/RP proofs do not need to transit Nexus;
- optional backup is opaque ciphertext.

Limitation:

- network-level metadata may still allow correlation by Cloudflare or an operator with sufficiently broad telemetry. Nexus MUST document that pseudonym unlinkability is not equivalent to network anonymity.

### T9 — Sybil attacker

An attacker creates many valid identities.

Expected behavior:

- cryptography does not solve this;
- optional Turnstile, issuance quotas, invitation systems, proof-of-work, or future privacy-preserving quota tokens may be layered on without changing identity ownership semantics.

### T10 — Compromised Nexus receipt-signing key

Expected protection:

- user identity signatures remain self-certifying and are not forgeable by the Nexus server;
- server key rotation uses `kid` and published key history;
- historical receipts remain verifiable under retained public keys;
- compromise procedures revoke the server key and publish a replacement trust statement.

---

# Part II — Protocol and Cryptography

## 7. Cryptographic suite v1

The v1 suite is:

```text
Suite ID: NX-25519-SHA256-JCS-v1
Signing: Ed25519
Subject hash: SHA-256
Optional key agreement: X25519
KDF where needed: HKDF-SHA-256
Local/backup AEAD: AES-256-GCM
Canonicalization: RFC 8785 JSON Canonicalization Scheme (JCS)
Binary encoding in JSON: base64url without padding
Randomness: Web Crypto CSPRNG only
```

### 7.1 Mandatory rules

- MUST use `crypto.getRandomValues()` / Web Crypto secure randomness.
- MUST NOT use `Math.random()` for cryptographic or identifier material.
- MUST NOT implement Ed25519, SHA-256, X25519, HKDF, or AES manually.
- Server-side Workers SHOULD use Web Crypto APIs supplied by the Workers runtime.
- Client code SHOULD use Web Crypto where supported; any fallback library MUST be audited, pinned, isolated behind the crypto-provider interface, and pass the same test vectors.
- Cryptographic algorithm names MUST never be inferred from untrusted strings and passed directly to arbitrary crypto APIs. Schemas enumerate supported suites.

### 7.2 Algorithm agility

Every identity and signed object includes explicit `protocol`/`suite` identifiers.

Unknown suites MUST fail closed.

Existing subjects MUST NOT silently migrate to a new suite because their subject hash commits to the genesis document. Future suites coexist with v1; continuity is represented explicitly if desired.

---

## 8. Canonical JSON rules

All signed protocol objects MUST:

1. validate against a strict schema;
2. reject unknown fields unless the versioned schema explicitly allows them;
3. represent binary values as unpadded base64url strings;
4. represent times as integer Unix epoch seconds;
5. use ASCII-only protocol identifiers, action strings, audience origins, resource identifiers, and subject strings;
6. canonicalize using RFC 8785 JCS before signing/hashing.

Human-authored text MUST NOT be inserted directly into core protocol identifiers. Applications SHOULD hash arbitrary content bytes and sign the hash.

### 8.1 Domain-separated signature preimage

For every signed Nexus object:

```text
signature_preimage =
    UTF8("NEXUS-SIGNATURE\0") ||
    UTF8(protocol_identifier) ||
    0x00 ||
    UTF8(JCS(object_without_signature))
```

The public SDK MUST expose high-level methods such as `prove()`, `revoke()`, and `link()` rather than a generic `sign(bytes)` method to normal application callers.

---

## 9. Identity Genesis Document

### 9.1 Schema

```ts
interface IdentityGenesisV1 {
  protocol: "nexus.identity.v1";
  suite: "NX-25519-SHA256-JCS-v1";
  signingKey: {
    alg: "Ed25519";
    publicKey: string; // base64url(raw 32 bytes)
  };
  agreementKey?: {
    alg: "X25519";
    publicKey: string; // base64url(raw 32 bytes)
  };
  revocationCommitment: string; // base64url(32-byte SHA-256)
}
```

No timestamp, user metadata, RP origin, display name, device ID, or controller ID belongs in genesis.

### 9.2 Revocation secret

For every identity, generate:

```text
R = SecureRandom(32 bytes)
```

Compute:

```text
revocationCommitment =
  SHA256(
    UTF8("NEXUS-REVOCATION-COMMITMENT\0v1\0") || R
  )
```

`R` is private until terminal revocation through the recovery/revocation-secret path.

### 9.3 Subject derivation

Compute:

```text
genesis_bytes = UTF8(JCS(IdentityGenesisV1))

genesis_hash = SHA256(
  UTF8("NEXUS-IDENTITY-GENESIS\0v1\0") || genesis_bytes
)

subject = "nx1_" + base64url(genesis_hash)
```

The verifier MUST recompute the subject. The wire-supplied `subject` MUST never be trusted without recomputation.

### 9.4 Identity bundle (private local object)

The wallet stores approximately:

```ts
interface LocalIdentityRecordV1 {
  localId: string; // random local-only UUID, never shared
  subject: string;
  genesis: IdentityGenesisV1;
  signingPrivateKeyRef: string;
  agreementPrivateKeyRef?: string;
  revocationSecretRef: string;
  localScopes: string[]; // RP origins, local-only
  label?: string;       // local-only
  localState: "active" | "revoked";
  registrationReceipt?: RegistryReceiptV1;
  revocationReceipt?: RegistryReceiptV1;
}
```

`localId`, `localScopes`, and `label` MUST NOT appear in registry requests.

---

## 10. Lifecycle state machine

Authoritative state is intentionally tiny:

```text
        register
  NONE ----------> ACTIVE
                       |
                       | terminal revoke/dispose
                       v
                    REVOKED
```

There is no transition from `REVOKED` back to `ACTIVE`.

There is no server-side `claimed`, `recovered`, `transferred`, or `new-owner` state in v1.

A disposed subject can never be reactivated or re-claimed by anyone, even with a surviving copy of the old signing key.

---

## 11. Registry action sequence

Each subject has an authoritative integer sequence.

```text
registration: sequence = 0
first state-changing action: expectedSequence = 0 -> new sequence = 1
```

For v1, revocation is the only terminal state-changing action.

A state-changing request MUST include `expectedSequence`. The Durable Object atomically verifies it.

This prevents races and gives deterministic idempotency semantics.

---

## 12. Ownership Proof

### 12.1 Schema

```ts
interface OwnershipProofPayloadV1 {
  protocol: "nexus.ownership-proof.v1";
  subject: string;
  genesis: IdentityGenesisV1;
  aud: string;       // exact RP HTTPS origin, e.g. https://forum.example
  act: string;       // ASCII action, e.g. post.edit
  resource: string;  // ASCII RP-defined identifier, e.g. post:01J...
  nonce: string;     // base64url >= 128 bits random
  iat: number;       // epoch seconds
  exp: number;       // epoch seconds
  contextHash?: string; // optional SHA-256 of RP-defined request/body context
}

interface OwnershipProofV1 {
  payload: OwnershipProofPayloadV1;
  signature: string; // Ed25519 raw signature base64url
}
```

### 12.2 Required semantics

- `aud` MUST exactly equal the relying party's configured origin.
- Wildcards are forbidden.
- `act` MUST be checked against the server-side operation being authorized.
- `resource` MUST be checked against the actual target resource.
- `nonce` MUST come from the RP's backend and MUST be single-use.
- RP SHOULD set proof lifetime to <= 120 seconds; default target is 60 seconds.
- RP MUST enforce a bounded clock skew.
- RP MUST atomically consume the nonce after successful verification.
- A proof for one action/resource MUST NOT authorize another action/resource.

### 12.3 Proof verification algorithm

The verifier MUST execute in this order:

1. strict schema validation;
2. protocol/suite support check;
3. recompute subject from genesis;
4. compare recomputed subject to `payload.subject`;
5. check `aud` exact match;
6. check `act` exact match;
7. check `resource` exact match;
8. check nonce exists, is unexpired, and is not consumed;
9. check `iat`/`exp` window;
10. canonicalize payload and verify Ed25519 signature;
11. evaluate lifecycle status according to RP policy;
12. atomically consume nonce;
13. authorize the application operation.

Nonce consumption and the protected application mutation SHOULD be within one application-side transaction when possible.

---

## 13. Lifecycle freshness policies for relying parties

Cryptographic signature verification can be fully local. **Fresh revocation status cannot be guaranteed offline indefinitely.** RPs MUST choose an explicit policy.

### 13.1 `strict` policy

Before every security-sensitive state-changing action, query the authoritative registry status.

Use for:

- account/identity ownership changes;
- deletion of valuable data;
- moderation/admin capability;
- signing high-value records.

### 13.2 `session` policy

Check lifecycle status during authentication, then issue an RP-local short-lived session.

Recommended maximum session without revalidation: 5 minutes for anonymous ownership-sensitive applications.

This introduces a bounded revocation propagation window.

### 13.3 `stapled-status` policy

The RP accepts a Nexus-signed status statement whose `exp` is within a configured freshness window.

This can reduce direct registry calls but also creates a bounded revocation window.

### 13.4 Historical proof policy

A self-asserted `iat` is NOT sufficient to prove that a signature existed before revocation. If historical authorship matters after disposal, require a trusted timestamp/receipt generated before `revokedAt`.

---

## 14. Revocation / disposal

Nexus supports two terminal revocation mechanisms.

### 14.1 Signing-key revocation

```ts
interface RevokeBySignaturePayloadV1 {
  protocol: "nexus.revoke.v1";
  subject: string;
  expectedSequence: number;
  nonce: string;
  iat: number;
  reasonCode?: "dispose" | "key-compromise" | "lost-device";
}
```

The payload is signed with the subject signing key.

### 14.2 Revocation-secret revocation

A user who retained `R` may revoke without the signing key.

Request contains:

```ts
interface RevokeBySecretV1 {
  protocol: "nexus.revoke-secret.v1";
  subject: string;
  expectedSequence: number;
  revocationSecret: string; // base64url(32 bytes)
}
```

The server computes the versioned commitment and compares it in constant-time where practical.

The secret is terminal-only. Once the identity is revoked, disclosure/replay of `R` has no further capability.

### 14.3 Disposal algorithm

The wallet MUST:

1. fetch authoritative status;
2. if already revoked, verify/store the existing receipt/status and continue;
3. submit revocation;
4. require a cryptographically valid registry receipt confirming `REVOKED`;
5. delete the signing private key, agreement private key, and revocation secret from active local storage;
6. mark local identity `revoked` or remove it according to user preference;
7. if encrypted backup is enabled, publish a new backup version that excludes active private material for the disposed identity;
8. retain only public genesis/receipts if the user wants historical reference.

The UI MUST NOT claim secure physical erasure. It SHOULD say the identity is *cryptographically disabled for future control*.

---

## 15. Privacy rotation

Default rotation is not a registry operation.

Algorithm:

1. create a new independent identity using fresh random key material;
2. register it in a separate request;
3. locally associate the new identity with the RP scope;
4. optionally revoke the old identity in a separate request;
5. do not send `{oldSubject,newSubject}` to Nexus;
6. do not create a continuity certificate.

The SDK MUST NOT expose `rotate(oldSubject)` as a server endpoint because that creates an unnecessary server-side link.

A high-level wallet UI MAY call the user action “Rotate”, but internally it performs independent create + optional old revoke.

---

## 16. Explicit continuity link

If a user intentionally wants to prove that two identities are related, use a dual-signed certificate.

```ts
interface ContinuityLinkPayloadV1 {
  protocol: "nexus.continuity-link.v1";
  subjectA: string;
  genesisA: IdentityGenesisV1;
  subjectB: string;
  genesisB: IdentityGenesisV1;
  scope?: string; // optional ASCII RP-defined scope
  iat: number;
  exp?: number;
  nonce: string;
}

interface ContinuityLinkV1 {
  payload: ContinuityLinkPayloadV1;
  signatureA: string;
  signatureB: string;
}
```

Both signatures MUST cover the identical payload.

Nexus registry SHOULD NOT store these links by default. Relying parties or users can store them where needed.

---

## 17. Historical authorship and trusted receipts

A critical subtlety:

If an old private key survives in a backup and is obtained after revocation, the holder can create a new signature with a fake old `iat` value. Therefore:

> A private-key signature alone proves key possession, not trustworthy wall-clock creation time.

For durable historical authorship, the consuming platform SHOULD issue an acceptance receipt when the artifact is created.

Example:

```ts
interface ArtifactReceiptPayloadV1 {
  protocol: "example-platform.artifact-receipt.v1";
  resource: string;
  subject: string;
  contentHash: string;
  userSignatureHash: string;
  acceptedAt: number; // platform trusted time
}
```

The platform signs the receipt with its own service key.

Nexus MAY also provide the optional hash-only Notary Service described later. The notary timestamps a digest without learning the artifact content.

---

# Part III — Cloudflare Architecture

## 18. Service topology

The Nexus repository is a monorepo that deploys multiple narrowly scoped Workers/services.

```text
                              Internet
                                 |
                +----------------+----------------+
                |                                 |
        wallet.nexus.example              api.nexus.example
        Workers Static Assets               Edge Worker
                |                                 |
                |                         Service Bindings
                |                                 |
                |                  +--------------+--------------+
                |                  |                             |
                |          Registry Service              Backup Service
                |                  |                             |
                |          Durable Objects                      R2
                |          IdentityState                        |
                |                  |                             |
                |             DO Outbox                         |
                |                  |
                |                Queue
                |                  |
                |        +---------+----------+
                |        |                    |
                |    D1 Projector       Transparency Worker
                |                             |
                |                   TransparencyShard DOs
                |                             |
                |                        R2 snapshots
                |
                +---- client-side keys only
```

### 18.1 Public domains

Recommended:

```text
wallet.nexus.example   # wallet UI; no third-party scripts
api.nexus.example      # fixed protocol endpoints
status.nexus.example   # optional public transparency/checkpoint assets
```

The API and wallet MAY be on separate origins to make trust boundaries explicit.

---

## 19. Cloudflare service responsibilities

### 19.1 Cloudflare Workers — public edge/API

Use a Module Worker as the public API gateway.

Responsibilities:

- strict method/content-type/body-size validation;
- protocol schema validation;
- CORS;
- abuse checks;
- service binding calls;
- server receipt/status signing;
- response headers;
- no authoritative lifecycle state in Worker memory.

The Worker MUST treat in-memory state as a cache only.

### 19.2 Service Bindings — internal service boundaries

Use Service Bindings rather than public HTTP endpoints between Nexus Workers.

Recommended internal services:

```text
REGISTRY_SERVICE
BACKUP_SERVICE
TRANSPARENCY_SERVICE
```

Benefits for this design:

- internal APIs are not publicly addressable;
- no internal API tokens are required;
- service boundaries remain explicit inside one Cloudflare account.

### 19.3 Durable Objects — authoritative lifecycle

Create one `IdentityState` Durable Object per subject:

```ts
const id = env.IDENTITY_STATE.idFromName(subject);
const stub = env.IDENTITY_STATE.get(id);
```

The subject DO is the **only authoritative mutable lifecycle source**.

It owns:

- genesis document;
- current state;
- sequence number;
- registration timestamp;
- revocation timestamp;
- action history required for idempotency;
- durable outbox entries waiting for Queue publication.

SQLite-backed Durable Object storage is required.

Reason: per-object storage is transactional/strongly consistent and the object provides a natural serialization boundary for concurrent lifecycle operations.

### 19.4 D1 — queryable non-authoritative projection

D1 stores a rebuildable projection for:

- operational queries;
- aggregate counts;
- admin inspection by subject if necessary;
- transparency event lookup indexes;
- migration/reporting convenience.

D1 MUST NOT authorize current subject actions.

If D1 disagrees with the subject Durable Object, the Durable Object wins.

### 19.5 Cloudflare Queues — asynchronous event distribution

Use a queue such as:

```text
nexus-registry-events
```

for:

- D1 projection updates;
- transparency log append jobs;
- aggregate analytics events;
- optional webhook-like future integrations.

Consumers MUST be idempotent because delivery can be retried.

Every event has a deterministic `eventId`.

### 19.6 R2 — opaque blobs and audit artifacts

Use separate buckets:

```text
nexus-vault-backups
nexus-transparency
```

R2 stores:

- encrypted client vault backups only;
- transparency log segment snapshots;
- signed checkpoint manifests;
- long-term D1 export archives if operationally desired.

The backup bucket MUST NOT be public.

The transparency bucket MAY be exposed only through a Worker/custom domain with explicit cache/security policy.

### 19.7 Workers KV — allowed only for non-authoritative cache/config

Workers KV MUST NOT store authoritative revocation state because KV is eventually consistent.

Allowed uses include:

- immutable protocol documentation metadata;
- immutable/cached public server keysets;
- non-security-critical feature flags;
- cache of already immutable artifacts.

If a value can make an authorization decision unsafe when stale, it does not belong in KV.

### 19.8 Turnstile — optional anti-automation

Turnstile MAY protect expensive/abusable endpoints such as identity registration or anonymous quota-token minting.

Rules:

- Turnstile is anti-abuse, not identity authentication.
- Server-side Siteverify validation is mandatory.
- Do not store the Turnstile token with the subject.
- Do not add a permanent “human ID” as a result of Turnstile.
- Use Turnstile only when product abuse requirements justify the additional network metadata exposure.

### 19.9 Workers Rate Limiting binding — coarse edge defense

Use for endpoint-level limits such as:

- registration attempts;
- status batch requests;
- backup writes;
- notary submissions.

It MUST NOT be treated as a global cryptographic quota or uniqueness guarantee.

### 19.10 Workers Analytics Engine — aggregate-only metrics

Optional.

Allowed metrics:

```text
operation=register success=1
operation=revoke success=1
operation=status_batch size_bucket=10
error_code=INVALID_SIGNATURE
latency_bucket=...
```

Forbidden dimensions:

- subject;
- IP;
- user agent;
- backup ID;
- RP origin;
- raw nonce;
- proof ID.

### 19.11 Workers Secrets / Secrets Store

Nexus service signing keys and external service secrets MUST use Workers secrets or Secrets Store bindings.

User identity private keys MUST NEVER use Cloudflare Secrets Store because they must never reach the server.

As of this spec date, Secrets Store is an open-beta Cloudflare service. Production deployments MAY prefer normal per-Worker secrets until the operator is comfortable with beta dependencies.

### 19.12 Workflows — optional maintenance only

Workflows MAY automate:

- periodic D1 export to R2;
- long-running audit jobs;
- cleanup of expired encrypted backups;
- transparency checkpoint publication.

Workflows MUST NOT sit in the live signature verification or revocation correctness path.

---

## 20. Why Durable Objects, not D1/KV, own lifecycle

Required decision:

```text
Current subject lifecycle authority = IdentityState Durable Object
```

Not:

```text
KV        # eventual consistency unacceptable
D1 read replica # potentially stale
Worker memory   # non-durable
R2        # object store, wrong coordination primitive
```

The Durable Object key is deterministic from the self-certifying subject. No global `users` table is required to locate lifecycle state.

---

## 21. IdentityState Durable Object schema

Use SQLite-backed storage.

Suggested schema inside each subject DO:

```sql
CREATE TABLE IF NOT EXISTS identity_state (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  subject TEXT NOT NULL UNIQUE,
  protocol TEXT NOT NULL,
  suite TEXT NOT NULL,
  genesis_jcs TEXT NOT NULL,
  genesis_hash BLOB NOT NULL,
  signing_public_key BLOB NOT NULL,
  agreement_public_key BLOB,
  revocation_commitment BLOB NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('active', 'revoked')),
  sequence INTEGER NOT NULL,
  registered_at INTEGER NOT NULL,
  revoked_at INTEGER,
  revocation_event_id TEXT
);

CREATE TABLE IF NOT EXISTS actions (
  sequence INTEGER PRIMARY KEY,
  event_id TEXT NOT NULL UNIQUE,
  action_type TEXT NOT NULL,
  event_hash BLOB NOT NULL,
  accepted_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS outbox (
  event_id TEXT PRIMARY KEY,
  payload_jcs TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  published_at INTEGER,
  attempt_count INTEGER NOT NULL DEFAULT 0
);
```

### 21.1 Registration transaction

Within one DO transaction:

1. if state does not exist, insert ACTIVE state with sequence `0`;
2. insert action `register`;
3. insert outbox event;
4. commit;
5. return state/action to registry service.

If the identity already exists with identical genesis, registration is idempotent and returns the original/current status.

If the same subject somehow resolves to different genesis bytes, return `409 SUBJECT_GENESIS_CONFLICT` and emit a critical security metric.

### 21.2 Revocation transaction

Within one DO transaction:

1. load state;
2. require `active` or return idempotent existing revocation state;
3. verify `expectedSequence`;
4. verify signing proof OR revocation commitment;
5. set `state='revoked'`;
6. increment sequence;
7. set `revoked_at` from server clock;
8. insert action;
9. insert outbox event;
10. commit.

No later method may transition back to active.

---

## 22. Transactional Outbox pattern

A successful lifecycle mutation MUST NOT rely on a best-effort `queue.send()` after the database commit with no recovery path.

Use a per-DO durable outbox.

Algorithm:

1. state mutation and outbox record commit atomically;
2. after commit, attempt to publish outbox messages to Queue;
3. mark `published_at` only after `send()` succeeds;
4. if send fails, retain record;
5. schedule a Durable Object alarm or retry on the next request;
6. consumer deduplicates by `eventId`.

This makes D1/transparency propagation eventually reliable without making the queue part of the authoritative state transaction.

---

## 23. Registry event format

```ts
interface RegistryEventV1 {
  protocol: "nexus.registry-event.v1";
  eventId: string;
  eventType: "registered" | "revoked";
  subject: string;
  genesisHash: string;
  sequence: number;
  state: "active" | "revoked";
  acceptedAt: number;
  actionHash: string;
}
```

Compute:

```text
eventHash = SHA256(
  UTF8("NEXUS-REGISTRY-EVENT\0v1\0") || UTF8(JCS(event_without_eventId))
)

eventId = "nxe1_" + base64url(eventHash)
```

Queue consumers MUST treat `eventId` as the idempotency key.

---

## 24. D1 projection schema

Example:

```sql
CREATE TABLE identities (
  subject TEXT PRIMARY KEY,
  genesis_hash TEXT NOT NULL,
  protocol TEXT NOT NULL,
  suite TEXT NOT NULL,
  state TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  registered_at INTEGER NOT NULL,
  revoked_at INTEGER,
  updated_at INTEGER NOT NULL
);

CREATE TABLE registry_events (
  event_id TEXT PRIMARY KEY,
  subject TEXT NOT NULL,
  event_type TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  accepted_at INTEGER NOT NULL,
  action_hash TEXT NOT NULL,
  FOREIGN KEY(subject) REFERENCES identities(subject)
);

CREATE INDEX idx_identities_state ON identities(state);
CREATE INDEX idx_identities_registered_at ON identities(registered_at);
CREATE INDEX idx_registry_events_subject_sequence
  ON registry_events(subject, sequence);
```

The projector MUST upsert only if incoming `sequence >= stored sequence` and MUST ignore duplicate `event_id`.

D1 data is operational data, not a user directory. Admin APIs to search it SHOULD be protected by Cloudflare Access or equivalent operator controls and are outside the public protocol.

---

# Part IV — Public API

## 25. API conventions

Base:

```text
https://api.nexus.example/v1
```

Content type:

```text
application/nexus+json
```

Rules:

- HTTPS only.
- No identity in query strings.
- Fixed endpoint paths for identity operations.
- Maximum body sizes enforced before parsing.
- Unknown JSON fields rejected for signed protocol objects.
- Successful mutation responses include signed receipt.
- Error bodies never echo secrets or full proofs.

---

## 26. Discovery endpoints

### `GET /.well-known/nexus.json`

Returns:

```json
{
  "protocols": ["nexus.identity.v1", "nexus.ownership-proof.v1"],
  "suites": ["NX-25519-SHA256-JCS-v1"],
  "registry": "https://api.nexus.example/v1",
  "jwks": "https://api.nexus.example/.well-known/jwks.json",
  "wallet": "https://wallet.nexus.example"
}
```

### `GET /.well-known/jwks.json`

Publishes Nexus service receipt/status public signing keys using standard Ed25519 JWK representation.

Public keys MUST remain available for at least the lifetime of receipts the service promises to verify.

---

## 27. Register identity

### `POST /v1/identity/register`

Request:

```json
{
  "subject": "nx1_...",
  "genesis": {
    "protocol": "nexus.identity.v1",
    "suite": "NX-25519-SHA256-JCS-v1",
    "signingKey": {"alg":"Ed25519","publicKey":"..."},
    "agreementKey": {"alg":"X25519","publicKey":"..."},
    "revocationCommitment": "..."
  },
  "turnstileToken": "optional"
}
```

Server:

1. strict-validate request;
2. recompute subject;
3. optional abuse validation;
4. call `REGISTRY_SERVICE.register()`;
5. receive authoritative state;
6. sign Registry Receipt;
7. return receipt.

The server MUST NOT persist the Turnstile token or associate it with D1 projection rows.

---

## 28. Get authoritative status

### `POST /v1/identity/status`

Request:

```json
{"subject":"nx1_..."}
```

Response:

```json
{
  "subject": "nx1_...",
  "state": "active",
  "sequence": 0,
  "registeredAt": 1786400000,
  "revokedAt": null,
  "genesis": {"...":"..."},
  "statusStatement": {"...":"signed object"}
}
```

This endpoint MUST read the subject Durable Object, not D1/KV.

### `POST /v1/identity/status-batch`

Request:

```json
{"subjects":["nx1_...","nx1_..."]}
```

- Hard maximum: 100 subjects/request in v1.
- Each status comes from the corresponding subject DO.
- Results preserve request order.
- Partial per-subject errors are allowed; the outer request does not fail because one subject is unknown.

---

## 29. Revoke identity

### `POST /v1/identity/revoke`

Accept exactly one of:

```json
{
  "mode": "signature",
  "payload": {"...":"RevokeBySignaturePayloadV1"},
  "signature": "..."
}
```

or:

```json
{
  "mode": "secret",
  "payload": {"...":"RevokeBySecretV1"}
}
```

Response contains signed Registry Receipt with state `revoked` and server `acceptedAt`.

Repeated identical revocation requests MUST be idempotent.

A revoked identity can never be changed back to active.

---

## 30. Signed Registry Receipt

```ts
interface RegistryReceiptPayloadV1 {
  protocol: "nexus.registry-receipt.v1";
  eventId: string;
  subject: string;
  genesisHash: string;
  eventType: "registered" | "revoked";
  sequence: number;
  state: "active" | "revoked";
  acceptedAt: number;
  signerKid: string;
}

interface RegistryReceiptV1 {
  payload: RegistryReceiptPayloadV1;
  signature: string;
}
```

Receipt signing uses a Nexus service key, NOT any user key.

Receipts provide trusted service time for the registry event.

---

## 31. Signed Status Statement

```ts
interface StatusStatementPayloadV1 {
  protocol: "nexus.status-statement.v1";
  subject: string;
  state: "active" | "revoked";
  sequence: number;
  registeredAt: number;
  revokedAt?: number;
  iat: number;
  exp: number;
  signerKid: string;
}
```

Default validity target: 60 seconds.

A relying party that accepts status statements MUST enforce `exp` itself.

---

## 32. Error model

```ts
interface NexusError {
  error: {
    code: string;
    message: string;
    requestId?: string; // random operational ID, not stable user ID
  }
}
```

Required codes include:

```text
BAD_REQUEST
UNSUPPORTED_PROTOCOL
UNSUPPORTED_SUITE
INVALID_SUBJECT
INVALID_SIGNATURE
INVALID_REVOCATION_SECRET
IDENTITY_NOT_FOUND
IDENTITY_REVOKED
SEQUENCE_CONFLICT
SUBJECT_GENESIS_CONFLICT
RATE_LIMITED
TURNSTILE_REQUIRED
TURNSTILE_INVALID
BODY_TOO_LARGE
INTERNAL_ERROR
```

Error messages MUST NOT reveal whether a guessed revocation secret was close/correct in any partial sense.

---

# Part V — Unified Browser Wallet

## 33. Wallet origin model

A unified web wallet MUST run on a dedicated origin:

```text
https://wallet.nexus.example
```

Private keys are used only within this origin.

Relying-party pages never receive raw private keys or revocation secrets.

The wallet is analogous to a cryptographic approval surface, not an OAuth account provider.

---

## 34. Why a separate wallet origin is required

If every RP embeds the Nexus SDK and stores keys in the RP origin's IndexedDB, there is no unified Nexus vault because browser storage is origin-scoped.

The dedicated wallet origin enables:

```text
one local wallet
    -> identity A for forum.example
    -> identity B for forum.example
    -> identity C for chat.example
```

without exposing a common public controller ID.

---

## 35. RP <-> Wallet popup protocol

### 35.1 Security rule

The wallet MUST derive the audience from `MessageEvent.origin` and MUST NOT trust an `aud` string supplied inside RP JSON.

### 35.2 Flow

1. RP frontend requests a challenge from its own backend.
2. RP SDK opens the Nexus wallet popup.
3. Wallet sends a non-sensitive `NEXUS_READY` message to opener.
4. RP sends `NEXUS_PROOF_REQUEST` using `postMessage`.
5. Wallet receives the request and records `event.origin` as authoritative audience.
6. Wallet validates request schema and challenge expiry.
7. Wallet shows consent UI:
   - requesting origin;
   - selected identity/local label;
   - action;
   - resource label/ID;
   - warning if identity is not already locally scoped to this origin.
8. User approves.
9. Wallet signs Ownership Proof with `aud = event.origin`.
10. Wallet replies only to the exact `event.origin` using `event.source.postMessage(result, event.origin)`.
11. RP sends proof to its backend.
12. RP backend verifies proof and registry freshness.

### 35.3 Prohibited popup behavior

- MUST NOT use `postMessage(..., "*")` for secret/proof responses.
- MUST NOT trust URL query parameter `aud` as authoritative.
- MUST NOT automatically approve requests without user-visible origin/action context in v1.
- MUST NOT expose the full local identity list to the RP.

---

## 36. Browser SDK API

Recommended public API:

```ts
const result = await nexus.requestProof({
  action: "post.edit",
  resource: "post:01JABC...",
  nonce: challenge.nonce,
  expiresAt: challenge.expiresAt,
  contextHash
});
```

The caller does NOT provide `aud`; the wallet derives it from the browser origin boundary.

Response:

```ts
interface NexusProofResult {
  proof: OwnershipProofV1;
}
```

Additional APIs:

```ts
nexus.createIdentity()
nexus.chooseIdentity()
nexus.disposeIdentity()
nexus.getLocalIdentitySummaries()
nexus.exportIdentity()   // optional/phase 2; user gesture required
nexus.importIdentity()   // optional/phase 2
```

RP pages MUST NOT receive `getLocalIdentitySummaries()` results; that method is wallet UI/internal only.

---

## 37. Wallet local storage

### 37.1 Required

Use IndexedDB for structured local state.

Do not store private key material in:

- `localStorage`;
- URL fragments/query strings;
- cookies;
- service worker cache;
- plaintext JSON files automatically.

### 37.2 Key storage abstraction

Implement:

```ts
interface KeyVault {
  createSigningKey(): Promise<KeyRef>;
  sign(ref: KeyRef, data: Uint8Array): Promise<Uint8Array>;
  createAgreementKey(): Promise<KeyRef>;
  deleteKey(ref: KeyRef): Promise<void>;
  storeRevocationSecret(secret: Uint8Array): Promise<SecretRef>;
  readRevocationSecret(ref: SecretRef): Promise<Uint8Array>;
  deleteSecret(ref: SecretRef): Promise<void>;
}
```

No consumer outside wallet internals gets a raw key by default.

### 37.3 WebCrypto implementation

Prefer non-extractable `CryptoKey` objects for normal local operation where browser support/IndexedDB persistence is verified by test.

Portable export/backup is a separate mode and may require an explicitly exportable encrypted key representation.

### 37.4 XSS statement

Non-extractable keys do not make XSS harmless: malicious wallet-origin JavaScript may still ask the browser to sign using a key. Therefore CSP/build integrity and user consent remain mandatory.

---

## 38. Wallet CSP and browser hardening

Wallet responses SHOULD include a CSP equivalent to:

```text
default-src 'self';
script-src 'self';
style-src 'self';
img-src 'self' data:;
connect-src https://api.nexus.example;
object-src 'none';
base-uri 'none';
frame-ancestors 'none';
form-action 'self';
```

Additional rules:

- no third-party analytics;
- no remote fonts if avoidable;
- no tag managers;
- no runtime CDN JavaScript dependencies;
- no `unsafe-eval`;
- avoid `unsafe-inline` scripts;
- set `Referrer-Policy: no-referrer`;
- set `X-Content-Type-Options: nosniff`;
- use strict permissions policy;
- verify that any COOP/COEP headers do not break the required cross-origin popup/opener messaging flow.

---

# Part VI — Relying-Party Integration Contract

## 39. Nexus does not issue an RP login account

The RP owns its own session after proof verification.

Recommended flow:

```text
RP backend -> random challenge
browser -> wallet proof
browser -> RP backend proof
RP backend -> verify + lifecycle check
RP backend -> short-lived RP-local session
```

Nexus does not need to observe subsequent RP requests.

---

## 40. RP challenge schema

Example application-side challenge:

```ts
interface RpChallenge {
  challengeId: string;
  nonce: string; // >=128 random bits
  action: string;
  resource: string;
  expiresAt: number;
}
```

The RP stores only what it needs to consume the challenge once.

Suggested database:

```sql
CREATE TABLE nexus_challenges (
  challenge_id TEXT PRIMARY KEY,
  nonce_hash TEXT NOT NULL UNIQUE,
  action TEXT NOT NULL,
  resource TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER
);
```

Challenge expiry target: <= 120 seconds.

---

## 41. RP verifier package

Package:

```text
@nexus/verifier
```

Public API:

```ts
verifySubject(genesis, claimedSubject)
verifyOwnershipProof(proof, expected)
verifyRegistryReceipt(receipt, keyset)
verifyStatusStatement(statement, keyset, now)
```

Optional helper:

```ts
checkLifecycle(subject, {
  registryUrl,
  policy: "strict" | "session" | "stapled-status"
})
```

The verifier package MUST have zero dependencies on Cloudflare bindings so Node, Deno, Bun, Workers, and other runtimes can consume it.

---

## 42. Platform database rule

A consuming anonymous platform stores:

```text
resource.author_subject = nx1_...
```

It MUST NOT require:

```text
resource.nexus_user_id
resource.controller_id
resource.vault_id
resource.real_user_id
```

The platform MAY store genesis/public key material alongside the resource or in a subject-public-key table for offline signature verification.

---

## 43. Recommended resource ownership pattern

At resource creation:

1. RP issues challenge for `resource.create` with a provisional resource ID.
2. wallet signs proof.
3. RP verifies subject/proof/lifecycle.
4. RP creates resource with immutable `author_subject`.
5. RP stores user proof hash.
6. RP issues a signed Artifact Receipt if durable historical authorship is a product feature.

At edit/delete:

1. RP reads immutable `author_subject` from database.
2. RP issues resource-specific challenge.
3. user proves the same subject.
4. RP verifies current lifecycle.
5. perform mutation.

An RP MUST NOT provide a generic “claim this old resource” endpoint that replaces `author_subject` based only on a new key assertion.

---

# Part VII — Optional Opaque Encrypted Backup

## 44. Backup privacy model

Backup is optional and MUST be designed so Cloudflare stores only ciphertext plus minimal opaque version metadata.

The backup service MUST NOT parse the wallet manifest or learn which subjects it contains.

The server MUST NOT have the vault decryption key.

---

## 45. Backup object

Versioned envelope example:

```ts
interface EncryptedVaultBackupV1 {
  protocol: "nexus.vault-backup.v1";
  kdf: {
    name: "argon2id";
    version: 1;
    salt: string;
    memoryKiB: number;
    iterations: number;
    parallelism: number;
  };
  aead: {
    name: "AES-256-GCM";
    iv: string;
  };
  ciphertext: string;
}
```

KDF parameters MUST be versioned and MUST be selected by a dedicated security review before Phase 2 implementation. Codex MUST NOT invent parameters silently.

Alternative recovery methods may be added behind a new envelope version.

---

## 46. Backup capability

Backup authentication is independent of any Nexus identity.

Generate:

```text
backupId = SecureRandom(16 bytes)
backupSecret = SecureRandom(32 bytes)
```

Server stores only a hash of `backupSecret` and an opaque R2 object key.

No subject list is stored next to the backup metadata.

Updating a backup does not require presenting any Nexus identity proof.

---

## 47. Backup disposal caveat

An old backup may contain a private key for an identity that is later disposed.

This does not reactivate the identity because the registry is terminally revoked.

However, old key material could create fake **backdated self-signed** claims. Therefore historical authorship systems MUST rely on trusted pre-revocation acceptance timestamps/receipts, not merely a claimed `iat` inside a user signature.

---

# Part VIII — Transparency and Notary

## 48. Transparency goals

The transparency system SHOULD make it difficult for the Nexus operator to silently rewrite registry history.

It MUST minimize new public metadata.

Therefore v1 transparency is **hash-first**, not a public chronological directory of subjects.

---

## 49. Scalable sharded transparency log

Production design:

```text
subject/event hash first byte
        |
        +--> shard 00
        +--> shard 01
        ...
        +--> shard ff
```

Use one `TransparencyShard` Durable Object per shard.

Each shard:

- receives deterministic event hashes;
- deduplicates by `eventId`;
- assigns append sequence;
- maintains an append-only Merkle tree or equivalent auditable hash structure;
- periodically emits checkpoint root.

A daily/global checkpoint manifest contains the 256 shard roots and is signed by a Nexus checkpoint key.

Store checkpoint manifests and optional compact log segments in R2.

A single-shard implementation MAY be used in development/MVP, but code interfaces MUST permit sharding without changing receipt schemas.

---

## 50. Hash-only public exposure

Public transparency artifacts SHOULD expose:

- shard ID;
- checkpoint size;
- Merkle root;
- checkpoint timestamp;
- server signature;
- inclusion proof APIs by `eventHash`.

They SHOULD NOT expose a public API that lists subject identifiers chronologically.

The user already knows their event hash from the Registry Receipt and can request its inclusion proof.

---

## 51. Optional generic Notary Service

Nexus MAY expose:

### `POST /v1/notary/stamp`

Input:

```json
{"digest":"base64url-32-byte-sha256"}
```

Output:

```ts
interface NotaryReceiptPayloadV1 {
  protocol: "nexus.notary-receipt.v1";
  digest: string;
  acceptedAt: number;
  signerKid: string;
}
```

The service timestamps only the digest. It does not need the post/chat/document content or subject.

A platform can combine:

```text
user signed artifact claim
+ platform acceptance receipt
+ optional Nexus hash timestamp
```

to provide stronger historical evidence without publishing content to Nexus.

---

# Part IX — Anti-Abuse Without Identity Accounts

## 52. Layered abuse model

Nexus identity creation is intentionally cheap. Anti-abuse must be separate from identity ownership.

Layer options:

1. Cloudflare Rate Limiting binding — coarse request defense.
2. Turnstile — proof-of-human friction for registration/expensive operations.
3. RP-side reputation — scoped only to a pseudonym within that RP.
4. Invitations — application-specific.
5. Proof-of-work — application-specific/optional.
6. Future privacy-preserving anonymous quota tokens — separate protocol package/phase.

Never make “passed Turnstile” a durable person identifier.

---

## 53. Future anonymous quota tokens

Do not improvise a blind-signature scheme in v1.

If anonymous reusable quota tokens are added, implement a standardized Privacy Pass/VOPRF-style protocol in a separate versioned package after security review.

The identity verifier MUST remain independent from the quota-token verifier.

---

# Part X — Repository Architecture

## 54. Repository layout

Use a pnpm workspace/monorepo inside the standalone Nexus repository.

```text
nexus/
├── README.md
├── SECURITY.md
├── LICENSE
├── package.json
├── pnpm-workspace.yaml
├── tsconfig.base.json
├── eslint.config.*
├── prettier.config.*
│
├── docs/
│   ├── protocol/
│   │   ├── identity.md
│   │   ├── proofs.md
│   │   ├── lifecycle.md
│   │   ├── relying-party.md
│   │   └── threat-model.md
│   ├── cloudflare/
│   │   ├── deployment.md
│   │   ├── data-retention.md
│   │   └── incident-response.md
│   └── adr/
│       ├── 0001-self-certifying-subjects.md
│       ├── 0002-do-authoritative-lifecycle.md
│       ├── 0003-no-global-controller-id.md
│       ├── 0004-jcs-wire-format.md
│       └── 0005-hash-only-transparency.md
│
├── packages/
│   ├── protocol/
│   │   ├── src/schemas/
│   │   ├── src/canonical/
│   │   ├── src/identifiers/
│   │   └── src/index.ts
│   ├── crypto/
│   │   ├── src/provider.ts
│   │   ├── src/webcrypto.ts
│   │   └── src/index.ts
│   ├── verifier/
│   │   ├── src/subject.ts
│   │   ├── src/proof.ts
│   │   ├── src/receipt.ts
│   │   └── src/index.ts
│   ├── sdk-browser/
│   │   ├── src/popup.ts
│   │   ├── src/messages.ts
│   │   └── src/index.ts
│   ├── wallet-core/
│   │   ├── src/identity-manager.ts
│   │   ├── src/key-vault.ts
│   │   ├── src/scope-manager.ts
│   │   └── src/disposal.ts
│   ├── test-vectors/
│   │   ├── vectors/*.json
│   │   └── src/index.ts
│   └── cloudflare-common/
│       ├── src/errors.ts
│       ├── src/receipt-signing.ts
│       └── src/headers.ts
│
├── apps/
│   ├── wallet/
│   │   ├── src/
│   │   └── public/
│   └── reference-rp/
│       ├── src/
│       └── migrations/
│
├── workers/
│   ├── edge-api/
│   │   ├── src/index.ts
│   │   └── wrangler.jsonc
│   ├── registry/
│   │   ├── src/index.ts
│   │   ├── src/identity-state-do.ts
│   │   └── wrangler.jsonc
│   ├── projector/
│   │   ├── src/index.ts
│   │   └── wrangler.jsonc
│   ├── transparency/
│   │   ├── src/index.ts
│   │   ├── src/transparency-shard-do.ts
│   │   └── wrangler.jsonc
│   └── backup/
│       ├── src/index.ts
│       └── wrangler.jsonc
│
├── migrations/
│   └── d1/
│       ├── 0001_initial.sql
│       └── ...
│
├── scripts/
│   ├── generate-test-vectors.ts
│   ├── verify-test-vectors.ts
│   ├── rotate-service-key.ts
│   └── publish-checkpoint.ts
│
└── tests/
    ├── protocol/
    ├── worker-integration/
    ├── browser-e2e/
    ├── concurrency/
    └── security/
```

---

## 55. Package boundaries

### `@nexus/protocol`

Owns:

- types;
- strict schemas;
- JCS canonicalization wrapper;
- base64url rules;
- protocol constants;
- subject/event identifier computation.

No network or Cloudflare code.

### `@nexus/crypto`

Owns:

- `CryptoProvider` interface;
- WebCrypto implementation;
- domain-separated signing helpers;
- hashing/HKDF/AEAD helpers.

No app business logic.

### `@nexus/verifier`

Owns pure verification.

It MUST run without Cloudflare bindings.

### `@nexus/sdk-browser`

Owns RP-to-wallet popup transport only.

It MUST NOT contain private key storage.

### `@nexus/wallet-core`

Owns private identity operations and local scope selection.

It MUST NOT be imported by relying-party apps.

### `@nexus/test-vectors`

Language/runtime-neutral expected values.

---

## 56. No circular authority

Dependency direction MUST remain:

```text
protocol <- crypto <- verifier
protocol <- crypto <- wallet-core <- wallet app
protocol <- verifier <- workers
protocol <- sdk-browser <- relying party frontend
```

Workers MUST NOT become the only place where protocol behavior is defined.

---

# Part XI — Cloudflare Configuration

## 57. Example edge Worker bindings

Illustrative `wrangler.jsonc`:

```jsonc
{
  "$schema": "node_modules/wrangler/config-schema.json",
  "name": "nexus-edge-api",
  "main": "src/index.ts",
  "compatibility_date": "2026-08-11",
  "services": [
    { "binding": "REGISTRY_SERVICE", "service": "nexus-registry" },
    { "binding": "BACKUP_SERVICE", "service": "nexus-backup" }
  ],
  "ratelimits": [
    {
      "name": "PUBLIC_API_RATE_LIMITER",
      "namespace_id": "1001",
      "simple": { "limit": 120, "period": 60 }
    }
  ],
  "analytics_engine_datasets": [
    { "binding": "METRICS", "dataset": "nexus_metrics" }
  ],
  "observability": {
    "enabled": true,
    "logs": { "enabled": true, "head_sampling_rate": 0.01 },
    "traces": { "enabled": true, "head_sampling_rate": 0.001 }
  }
}
```

Values are examples. Codex MUST verify the exact current Wrangler schema during implementation rather than copying configuration blindly.

### 57.1 Logging rule

Even with sampling enabled, application code must emit only privacy-safe structured values. Do not assume sampling makes sensitive logging acceptable.

---

## 58. Registry Worker bindings

Conceptually:

```jsonc
{
  "name": "nexus-registry",
  "main": "src/index.ts",
  "compatibility_date": "2026-08-11",
  "durable_objects": {
    "bindings": [
      { "name": "IDENTITY_STATE", "class_name": "IdentityState" }
    ]
  },
  "queues": {
    "producers": [
      { "binding": "REGISTRY_EVENTS", "queue": "nexus-registry-events" }
    ]
  },
  "migrations": [
    { "tag": "v1", "new_sqlite_classes": ["IdentityState"] }
  ]
}
```

---

## 59. Projector Worker bindings

Conceptually:

```jsonc
{
  "name": "nexus-projector",
  "main": "src/index.ts",
  "compatibility_date": "2026-08-11",
  "d1_databases": [
    {
      "binding": "INDEX_DB",
      "database_name": "nexus-index",
      "database_id": "<configured-at-deploy>"
    }
  ],
  "queues": {
    "consumers": [
      { "queue": "nexus-registry-events", "max_batch_size": 100 }
    ]
  },
  "services": [
    { "binding": "TRANSPARENCY_SERVICE", "service": "nexus-transparency" }
  ]
}
```

---

# Part XII — Service Signing Keys

## 60. Key purposes

Separate server keys by purpose where practical:

```text
registry receipt/status signing key
transparency checkpoint signing key
notary signing key (optional)
```

Never reuse user identity primitives as server keys.

### 60.1 Storage

Private service keys are stored in Workers secrets or Secrets Store.

Recommended secret representation: base64url/PEM PKCS#8 imported into WebCrypto at runtime.

### 60.2 Runtime caching

A Worker isolate MAY cache an imported non-exportable `CryptoKey` in module scope for performance. This cache is not authoritative state and must be reconstructable from the secret binding after isolate restart.

### 60.3 Public key distribution

Publish public key history using `kid`.

Do not remove a historical public key while receipts under that key are expected to remain verifiable.

---

# Part XIII — Observability, Retention, and Privacy

## 61. Structured metrics only

Code may emit:

```json
{"event":"api_result","operation":"register","result":"ok","latencyBucket":"lt50ms"}
```

Code must not emit:

```json
{"subject":"nx1_...","ip":"...","proof":{...}}
```

### 61.1 Request IDs

A random request ID MAY be generated per request for debugging.

It MUST:

- be random;
- not persist across requests;
- not be derived from subject/IP/device;
- not be returned or stored as a user identifier.

### 61.2 Retention policy

Define explicit retention for:

- Worker logs;
- D1 registry projection;
- R2 transparency artifacts;
- encrypted backups;
- abuse events.

Public cryptographic registry state may be permanent by protocol design; network telemetry should be minimized and short-lived.

---

# Part XIV — Security Headers and Edge Rules

## 62. API headers

API responses SHOULD include:

```text
Cache-Control: no-store                  # mutation/status responses
Content-Type: application/nexus+json
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
```

Well-known public key/discovery endpoints MAY be cached with short controlled TTLs and ETags because their content is public.

### 62.1 CORS

- Public read/status APIs MAY use `Access-Control-Allow-Origin: *` only because they use no cookies/credentials and return public cryptographic state.
- Mutation APIs used by wallet SHOULD allow the wallet origin and approved native/CLI clients as appropriate.
- Never combine wildcard origin with credentialed browser requests.

---

# Part XV — Testing Strategy

## 63. Test layers

Use Cloudflare's Workers Vitest integration for Worker-runtime unit/integration tests and browser E2E tests for wallet popup behavior.

Required categories:

1. protocol unit tests;
2. cryptographic test vectors;
3. verifier tests;
4. Durable Object concurrency tests;
5. Queue duplicate/retry tests;
6. D1 projection tests;
7. wallet IndexedDB tests;
8. popup origin-confusion tests;
9. full reference RP flow;
10. revocation/disposal tests;
11. log-leak tests;
12. fuzz/property tests for schemas/canonicalization.

---

## 64. Mandatory cryptographic test vectors

Commit deterministic vectors for:

- Genesis JCS bytes;
- genesis hash;
- subject;
- ownership proof canonical bytes;
- Ed25519 signature and verification;
- revocation commitment;
- Registry Event hash/event ID;
- Registry Receipt signature;
- Status Statement signature;
- Continuity Link dual signatures.

Every supported runtime implementation MUST pass the same vectors.

Private test keys in vectors MUST be explicitly documented as non-production fixtures.

---

## 65. Mandatory negative tests

Codex MUST implement tests proving rejection of:

- altered genesis with original subject;
- altered public key;
- altered action;
- altered resource;
- wrong audience;
- expired proof;
- proof not yet valid beyond clock skew;
- nonce replay;
- reused nonce for a different action;
- malformed base64url;
- padded base64url if protocol forbids padding;
- unknown protocol version;
- unknown crypto suite;
- invalid Ed25519 signature;
- wrong revocation secret;
- stale sequence;
- concurrent double revocation;
- attempted unrevocation;
- proof using revoked identity;
- RP trying to choose a fake `aud` different from `MessageEvent.origin`;
- proof returned to wildcard/incorrect origin;
- Queue duplicate event;
- out-of-order D1 projector events;
- use of KV as lifecycle authority (architectural test/lint where feasible).

---

## 66. Disposal acceptance tests

Scenario:

1. create identity;
2. create valid ownership proof;
3. register subject;
4. verify proof succeeds while active;
5. revoke subject;
6. verify registry receipt;
7. attempt new proof with still-available test private key;
8. signature verification itself succeeds;
9. **authorization MUST fail because lifecycle is revoked**;
10. repeated revocation returns same terminal state;
11. creating unrelated identity B works;
12. registry contains no link A -> B.

This test demonstrates the central post-disposal property.

---

## 67. Concurrency tests

At minimum:

- 50 concurrent first-time registrations of identical genesis -> exactly one state, idempotent responses;
- concurrent revoke requests with same sequence -> exactly one transition;
- revoke via signing key racing revoke via revocation secret -> one terminal event;
- outbox survives simulated Queue failure;
- outbox retry does not duplicate D1 event or transparency leaf.

---

## 68. Browser security E2E tests

Use two test origins:

```text
rp-a.test
rp-b.test
```

Verify:

- proof requested from A contains `aud=A`;
- B cannot replay A proof;
- wallet does not reveal A's scoped identity list to B;
- fake `aud=B` in A's request is ignored/rejected;
- response goes only to A origin;
- popup closure/cancellation returns safe error;
- wallet requires user gesture/approval in v1;
- no private key appears in network inspector payloads.

---

# Part XVI — Codex Implementation Rules

## 69. Hard guardrails

Codex MUST NOT:

1. invent cryptographic primitives;
2. use `Math.random()` for security values;
3. create a `users` table as a shortcut;
4. create a global public controller/vault ID;
5. derive all disposable identities from a recoverable master seed;
6. store private identity keys on Cloudflare;
7. put subject IDs in URL query strings unnecessarily;
8. log proofs/private keys/revocation secrets;
9. use Workers KV as lifecycle source of truth;
10. make D1 projection authoritative for revocation;
11. use a generic raw-sign API in the RP-facing SDK;
12. trust caller-supplied audience in the wallet;
13. use wildcard `postMessage` target for proof responses;
14. allow `REVOKED -> ACTIVE`;
15. implement “claim old identity with new key”;
16. silently change canonicalization or crypto algorithms;
17. add third-party JavaScript to wallet origin without explicit architectural approval;
18. implement backup KDF parameters without a reviewed versioned decision;
19. treat Turnstile as authentication;
20. conflate cryptographic pseudonymity with network anonymity.

---

## 70. Coding conventions

- TypeScript strict mode.
- No `any` in protocol/crypto/verifier packages except tightly isolated interoperability boundaries.
- All external inputs validated with strict schemas.
- Domain errors use typed error codes.
- All time obtained through injectable clock interfaces in core logic for deterministic tests.
- All randomness obtained through injectable CSPRNG interfaces in tests, Web Crypto in production.
- No environment-specific globals in `protocol` or `verifier` unless web-standard.
- Protocol packages have 100% branch coverage target for verification paths.
- Security-sensitive comparison helpers centralized.
- Every protocol change requires a new/updated test vector.

---

# Part XVII — Implementation Phases

## 71. Phase 0 — Scaffold and ADRs

Codex deliverables:

- pnpm workspace;
- TypeScript strict config;
- lint/format/test tooling;
- Cloudflare Worker projects;
- ADR files matching this spec;
- CI skeleton;
- reference environment naming.

Exit criteria:

- all packages build;
- Workers dry-run/build successfully;
- no production functionality yet.

---

## 72. Phase 1 — Protocol + Crypto + Test Vectors

Implement:

- JCS wrapper;
- base64url canonical helpers;
- domain-separated hash/sign helpers;
- Identity Genesis schema;
- subject derivation;
- revocation commitment;
- Ownership Proof schema/sign/verify;
- Registry Receipt and Status Statement schema/verify;
- test vectors.

Exit criteria:

- vectors pass in Node and Workers runtime;
- modified payloads fail verification;
- unknown suites fail closed.

Do not begin UI before this phase is stable.

---

## 73. Phase 2 — Authoritative Registry

Implement:

- `IdentityState` SQLite Durable Object;
- registration;
- status;
- signature/secret revocation;
- atomic sequence handling;
- durable outbox;
- registry service binding;
- public edge endpoints;
- service receipt signing.

Exit criteria:

- concurrency tests pass;
- disposal acceptance test passes;
- DO, not D1/KV, is demonstrably authoritative.

---

## 74. Phase 3 — Queue + D1 Projection

Implement:

- registry event queue producer;
- outbox retry/alarm;
- projector consumer;
- D1 migrations;
- idempotent/out-of-order logic;
- operational aggregate metrics.

Exit criteria:

- queue retries produce no duplicate logical events;
- D1 can be rebuilt from event stream/test fixture;
- simulated stale D1 cannot authorize a revoked identity.

---

## 75. Phase 4 — Wallet

Implement:

- wallet static application;
- IndexedDB storage;
- KeyVault abstraction;
- identity creation;
- local RP scope mapping;
- registration;
- disposal flow;
- safe consent UI;
- security headers/CSP.

Exit criteria:

- no user private key reaches Worker in integration tests;
- wallet can create/register/revoke identity;
- disposal waits for receipt before erasing active key material.

---

## 76. Phase 5 — RP SDK + Reference RP

Implement:

- popup transport SDK;
- origin-derived audience;
- reference RP challenge endpoint;
- verifier package integration;
- short-lived RP session example;
- sample resource create/edit/delete ownership.

Exit criteria:

- full browser E2E flow passes;
- cross-origin replay fails;
- revoked identity cannot edit/delete/create protected resources.

---

## 77. Phase 6 — Privacy Rotation and Explicit Linking

Implement:

- wallet “new identity / rotate” UX as create-independent + optional revoke;
- continuity-link schema and verification;
- explicit warnings about linkability.

Exit criteria:

- default rotation produces no old/new relation in Registry Event/D1 schemas;
- continuity link works only with both signatures.

---

## 78. Phase 7 — Transparency / Notary

Implement:

- shard abstraction;
- TransparencyShard DO;
- hash-only append;
- checkpoint signing;
- R2 checkpoint publication;
- inclusion proof API;
- optional digest notary.

Exit criteria:

- inclusion proof verifies locally;
- duplicate queue event cannot create duplicate leaf;
- public artifacts do not expose a chronological subject directory.

---

## 79. Phase 8 — Encrypted Backup

Only after a separate KDF/backup security ADR is approved.

Implement:

- portable encrypted vault serialization;
- reviewed password/recovery KDF;
- AES-GCM envelope;
- opaque backup capability;
- R2 storage;
- restore;
- deletion;
- post-disposal backup update.

Exit criteria:

- server cannot decrypt fixture backup;
- tampered ciphertext fails authentication;
- backup metadata contains no subject list;
- restoring disposed key does not restore registry control.

---

## 80. Phase 9 — Security hardening

Required before production:

- independent cryptographic/code review;
- dependency audit;
- CSP review;
- origin-confusion review;
- replay/race review;
- Cloudflare configuration review;
- incident response drill for service-signing-key compromise;
- privacy/retention review;
- fuzzing/canonicalization differential tests.

---

# Part XVIII — CI/CD

## 81. Pull request checks

Required:

```text
pnpm lint
pnpm typecheck
pnpm test
pnpm test:workers
pnpm test:e2e
pnpm test:vectors
pnpm build
wrangler deploy --dry-run (for each Worker)
```

Additionally:

- secret scanning;
- dependency vulnerability scan;
- lockfile integrity;
- no production Cloudflare credentials available to untrusted PR builds.

---

## 82. Deployment environments

Use separate Cloudflare resources for:

```text
local
preview/dev
staging
production
```

Never point preview Workers at production DO namespaces, D1 databases, R2 backup buckets, or service-signing secrets.

Each environment has a distinct service receipt signing key.

---

## 83. Database migrations

- D1 migrations are version-controlled.
- DO SQLite class schema migrations are versioned with Durable Object migrations and application-level schema migration code as required.
- migration tests use realistic existing-state fixtures.
- production migration runbooks include rollback/recovery procedures.
- D1 Time Travel is operational recovery only; it does not replace event/idempotency design.

---

# Part XIX — Incident Response

## 84. User key compromise

If signing key is compromised but user has revocation secret:

1. user uses secret revocation;
2. registry marks subject revoked;
3. RP strict checks immediately deny future control;
4. user creates unrelated identity if desired.

Nexus cannot distinguish legitimate holder from thief before revocation solely from the signing key; that is inherent in possession-based identity.

---

## 85. Nexus service signing key compromise

Procedure:

1. stop issuing with compromised `kid`;
2. publish replacement key;
3. preserve compromised public key for historical verification but mark compromise interval in a signed incident statement;
4. assess receipts/status statements issued during exposure;
5. note that user Ed25519 identity signatures remain independently verifiable and were not exposed by the server key compromise.

---

## 86. D1 loss/corruption

D1 is a projection.

Authorization remains available through subject Durable Objects.

Recover D1 using:

- Time Travel where appropriate;
- replay/rebuild from registry events/transparency/export fixtures;
- reconciliation against authoritative DO status for sampled/all subjects if an administrative rebuild process has subject inventory.

Do not mutate subject DOs to match D1.

---

## 87. Queue outage

Identity state changes may still commit because Queue is not authoritative.

Outbox records remain pending and retry later.

Registry receipts remain valid.

D1/transparency may lag; operational status endpoints remain authoritative through DOs.

---

# Part XX — Reference Integration with the Anonymous Platform Repo

## 88. Repo boundary

Two separate repositories:

```text
nexus/                 # protocol, wallet, SDKs, Cloudflare identity services
anonymous-platform/    # posts, chats, feeds, moderation, media, application DB
```

The anonymous platform consumes released Nexus packages, not Nexus source via relative path/submodule.

Recommended published packages:

```text
@nexus/protocol
@nexus/verifier
@nexus/sdk-browser
```

The platform MUST NOT import `wallet-core`.

---

## 89. Anonymous Platform responsibilities

The platform owns:

- post/comment/chat resource models;
- feed/search;
- moderation;
- chat E2EE/session protocol;
- application challenges;
- application sessions;
- artifact acceptance receipts;
- application abuse policy;
- application DB.

Nexus owns only cryptographic identity/control primitives and lifecycle.

---

## 90. Platform example

Database:

```sql
CREATE TABLE posts (
  post_id TEXT PRIMARY KEY,
  author_subject TEXT NOT NULL,
  body TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  accepted_proof_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
```

No foreign key to a `users` table is necessary.

Create flow:

```text
platform backend creates provisional post ID + challenge
       -> browser asks Nexus wallet for post.create proof
       -> wallet signs with selected subject
       -> platform verifies proof + live lifecycle
       -> platform inserts post(author_subject=subject)
       -> platform returns signed artifact receipt
```

Edit/delete follow the same pattern against immutable `author_subject`.

---

# Part XXI — Design Decisions to Preserve

## 91. ADR summary

The following are foundational decisions and MUST require an explicit ADR + protocol/security review to change.

### ADR-0001: Self-certifying subject

Subject is the domain-separated hash of canonical immutable genesis.

### ADR-0002: No global controller ID

Unified wallet state is local/opaque; applications receive disposable subjects only.

### ADR-0003: Independent random identity keys

No recoverable master seed deterministically regenerates disposable identities.

### ADR-0004: Durable Object lifecycle authority

Per-subject DO owns state transitions and sequence.

### ADR-0005: D1 and KV are non-authoritative

D1 is a projection; KV cannot authorize lifecycle state.

### ADR-0006: Audience derived from browser origin

Wallet never trusts RP-supplied `aud`.

### ADR-0007: Revocation before deletion

Disposal is server-recognized terminal revocation followed by local crypto-shredding.

### ADR-0008: Default rotation is unlinkable

Create new + optional revoke old; no combined server rotation endpoint.

### ADR-0009: Historical timestamps require trusted receipts

Self-signed `iat` cannot establish historical time after key leakage.

### ADR-0010: Hash-only transparency

Avoid creating a public chronological pseudonym directory.

---

# Part XXII — Definition of Done

## 92. MVP definition of done

Nexus v1 MVP is complete only when all are true:

- [ ] identity generation uses independent secure randomness;
- [ ] subject derivation is deterministic and covered by vectors;
- [ ] proofs are audience/action/resource/nonce/time bound;
- [ ] proof replay is rejected by reference RP;
- [ ] registry uses per-subject SQLite Durable Objects;
- [ ] registration is idempotent;
- [ ] revocation is terminal and concurrency-safe;
- [ ] revocation by signing key works;
- [ ] revocation by revocation secret works;
- [ ] old key cannot regain future control after revocation;
- [ ] D1 is not used for lifecycle authorization;
- [ ] Queue/outbox projection is idempotent;
- [ ] wallet keys never reach Cloudflare server endpoints;
- [ ] wallet popup derives audience from `MessageEvent.origin`;
- [ ] default rotation produces no registry old/new linkage;
- [ ] reference RP stores `author_subject`, not Nexus user/controller IDs;
- [ ] no sensitive values are emitted in application logs;
- [ ] cross-origin E2E security tests pass;
- [ ] cryptographic test vectors pass in Workers and non-Workers verifier runtime;
- [ ] public documentation states network anonymity limitations;
- [ ] SECURITY.md documents reporting and key-compromise procedure.

---

# Part XXIII — Codex Execution Instructions

## 93. How Codex should work from this specification

Codex should implement in phases and treat this document as the architectural contract.

For each phase:

1. read the relevant ADRs/spec sections;
2. produce a short implementation plan;
3. implement only that phase's scope;
4. add/modify tests before declaring completion;
5. run lint/typecheck/unit/integration tests;
6. verify no privacy invariant was weakened;
7. update ADR/spec only when a real implementation constraint is discovered;
8. never “simplify” a security invariant without marking it as an explicit blocker;
9. commit generated Cloudflare migrations/config alongside code;
10. leave the repository in a deployable/testable state.

When uncertain about a cryptographic or Cloudflare behavior, Codex MUST consult the current primary documentation rather than guessing.

---

# Appendix A — Recommended public TypeScript interfaces

```ts
export type NexusSubject = `nx1_${string}`;

export interface CreateIdentityResult {
  subject: NexusSubject;
  genesis: IdentityGenesisV1;
  registrationReceipt?: RegistryReceiptV1;
}

export interface ProofRequest {
  action: string;
  resource: string;
  nonce: string;
  expiresAt: number;
  contextHash?: string;
}

export interface VerificationExpectation {
  audience: string;
  action: string;
  resource: string;
  nonce: string;
  now: number;
  maxClockSkewSeconds: number;
}

export interface VerifiedSubject {
  subject: NexusSubject;
  signingPublicKey: Uint8Array;
  agreementPublicKey?: Uint8Array;
}
```

---

# Appendix B — Example verification pseudocode

```ts
async function verifyRpOperation(
  proof: OwnershipProofV1,
  expected: VerificationExpectation,
  challengeStore: ChallengeStore,
  registry: LifecycleProvider,
): Promise<VerifiedSubject> {
  const parsed = ownershipProofSchema.parse(proof);

  const computed = await deriveSubject(parsed.payload.genesis);
  if (computed !== parsed.payload.subject) throw err("INVALID_SUBJECT");

  if (parsed.payload.aud !== expected.audience) throw err("WRONG_AUDIENCE");
  if (parsed.payload.act !== expected.action) throw err("WRONG_ACTION");
  if (parsed.payload.resource !== expected.resource) throw err("WRONG_RESOURCE");
  if (parsed.payload.nonce !== expected.nonce) throw err("WRONG_NONCE");

  validateTimeWindow(parsed.payload.iat, parsed.payload.exp, expected);

  const ok = await verifyOwnershipSignature(parsed);
  if (!ok) throw err("INVALID_SIGNATURE");

  const challenge = await challengeStore.get(expected.nonce);
  if (!challenge || challenge.consumed || challenge.expired) {
    throw err("NONCE_REPLAY_OR_EXPIRED");
  }

  const state = await registry.getAuthoritativeStatus(computed);
  if (state.state !== "active") throw err("IDENTITY_REVOKED");

  await challengeStore.consumeAtomically(expected.nonce);

  return {
    subject: computed,
    signingPublicKey: decodeKey(parsed.payload.genesis.signingKey.publicKey),
    agreementPublicKey: parsed.payload.genesis.agreementKey
      ? decodeKey(parsed.payload.genesis.agreementKey.publicKey)
      : undefined,
  };
}
```

Application code must ensure the challenge consumption and protected mutation have suitable transactional semantics.

---

# Appendix C — Cloudflare product usage matrix

| Product | Nexus role | Authoritative? | Privacy note |
|---|---|---:|---|
| Workers | API edge, wallet assets, service code | No lifecycle state in memory | Avoid sensitive logging |
| Service Bindings | Internal Worker-to-Worker APIs | N/A | Avoid public internal endpoints |
| Durable Objects + SQLite | Per-subject lifecycle + outbox | **Yes** | Store cryptographic state only |
| D1 | Queryable projection/index | **No** | No real-person/RP mapping |
| Queues | Async projection/transparency | No | Idempotent consumers |
| R2 | Encrypted backups + transparency artifacts | No | Backup is client ciphertext |
| KV | Immutable/cache/config only | **Never for revocation** | Eventual consistency |
| Turnstile | Optional anti-abuse | No | Never becomes user identity |
| Rate Limiting binding | Coarse edge throttling | No | Not a global quota guarantee |
| Analytics Engine | Aggregate health metrics | No | No subject/IP/RP dimensions |
| Workers Secrets | Nexus service keys | Service trust only | Never user keys |
| Secrets Store | Optional centralized service secrets | Service trust only | Open beta as of spec date |
| Workflows | Maintenance/export/checkpoints | No | Keep off auth path |

---

# Appendix D — Primary standards and Cloudflare references

These references were checked while preparing this implementation spec. Codex should re-check current documentation at implementation time.

## Cryptographic / wire standards

- RFC 8032 — EdDSA / Ed25519: https://datatracker.ietf.org/doc/rfc8032/
- RFC 7748 — X25519: https://datatracker.ietf.org/doc/rfc7748/
- RFC 5869 — HKDF: https://datatracker.ietf.org/doc/html/rfc5869
- RFC 8785 — JSON Canonicalization Scheme: https://datatracker.ietf.org/doc/html/rfc8785

## Cloudflare

- Workers Web Crypto: https://developers.cloudflare.com/workers/runtime-apis/web-crypto/
- Workers bindings: https://developers.cloudflare.com/workers/runtime-apis/bindings/
- Service Bindings: https://developers.cloudflare.com/workers/runtime-apis/bindings/service-bindings/
- Durable Objects overview: https://developers.cloudflare.com/durable-objects/
- SQLite-backed Durable Object storage: https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/
- Durable Objects rules: https://developers.cloudflare.com/durable-objects/best-practices/rules-of-durable-objects/
- D1 overview: https://developers.cloudflare.com/d1/
- D1 Time Travel: https://developers.cloudflare.com/d1/reference/time-travel/
- D1 read replication: https://developers.cloudflare.com/d1/best-practices/read-replication/
- Queues: https://developers.cloudflare.com/queues/
- R2: https://developers.cloudflare.com/r2/how-r2-works/
- Workers KV consistency: https://developers.cloudflare.com/kv/concepts/how-kv-works/
- Turnstile server validation: https://developers.cloudflare.com/turnstile/get-started/server-side-validation/
- Workers Rate Limiting API: https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/
- Workers Analytics Engine: https://developers.cloudflare.com/analytics/analytics-engine/
- Workers Secrets: https://developers.cloudflare.com/workers/configuration/secrets/
- Secrets Store: https://developers.cloudflare.com/secrets-store/
- Workers observability/logs: https://developers.cloudflare.com/workers/observability/logs/workers-logs/
- Workers Vitest integration: https://developers.cloudflare.com/workers/testing/vitest-integration/
- Workflows: https://developers.cloudflare.com/workflows/

---

# Appendix E — Security review questions before production

The reviewer must answer at least:

1. Can any server-side record link a subject to a real person or stable controller?
2. Can the wallet accidentally reuse one identity across unrelated origins without explicit consent?
3. Can a malicious RP cause a proof to be signed for a different audience than its real origin?
4. Can a proof be replayed after its challenge is consumed?
5. Can a stale D1/KV value authorize a revoked subject?
6. Can concurrent revocation requests create divergent state?
7. Can a disposed identity ever transition back to active?
8. Can the server reconstruct a disposed identity from a master secret?
9. Can Cloudflare or application logs contain subject/private proof material unnecessarily?
10. Can an old key restored from backup produce a falsely “historical” claim that the product accepts without a trusted pre-revocation receipt?
11. Can a compromise of the Nexus server receipt key forge user identity signatures? The answer must be no.
12. Does the wallet load any third-party JavaScript capable of requesting signatures?
13. Are all protocol encodings canonical and cross-runtime deterministic?
14. Are all algorithm/version failures fail-closed?
15. Is every use of KV demonstrably non-authoritative?
16. Can a Queue retry duplicate a transparency leaf or D1 logical event?
17. Does backup storage reveal a subject list or RP scope mapping?
18. Does the product clearly distinguish pseudonymity from network anonymity?

If any answer is uncertain, production release is blocked pending review.
