# Root and Device Delegation Protocol v2

**Status:** Additive protocol profile  
**Wire version:** `v2`  
**Identity anchor:** unchanged `nexus.identity.v1` genesis and `nx1_` subject

This document is normative for the Nexus v2 root/device delegation profile. The v1 identity, proof,
registry, and popup contracts in [`NEXUS_SPEC.md`](../../NEXUS_SPEC.md) remain normative and
unchanged. Implementations use the v1 signing-key pair as an identity root and add independently
generated, individually revocable device signing keys beneath it.

The profile lets several devices prove control of the same `nx1_` subject without copying the root
private key. It does not create a wallet-wide root, global account, global installation identifier,
or new subject format.

## Normative invariants

1. Every identity has its own independently generated root key. The root is the Ed25519 signing key
   already committed to by that identity's `nexus.identity.v1` genesis.
2. A root private key MUST be created and retained as non-extractable. It MUST NOT enter a device
   transfer bundle, network request, log, server store, or relying-party proof.
3. Device private keys MUST be independently CSPRNG-generated Ed25519 keys. They MUST NOT be derived
   from the root or from another device key.
4. A device key proves the same identity only through a valid root-signed authorization whose
   subject and genesis hash recompute to that identity.
5. A device MAY activate and revoke only its own authorization. It MUST NOT authorize another key,
   revoke another device, replace the root, or terminally revoke the subject.
6. The root MAY authorize or revoke any device for its own subject. Root revocation targets the
   device key identifier and is irreversible, including when the device has not yet activated.
7. Terminal v1 identity revocation dominates all device state. No device operation may reactivate a
   terminally revoked subject.
8. Root and device signing are typed operations. Neither the wallet nor RP-facing SDK exposes a
   generic raw-sign API.
9. Public device IDs are subject-and-key-bound authorization identifiers, not physical-device,
   wallet, controller, account, or cross-subject identifiers. A fresh device key MUST be generated
   for every identity and intended installation.
10. All objects use strict versioned schemas, reject unknown fields, use canonical unpadded
    base64url binary values and integer Unix seconds, and use the v1 RFC 8785 JCS signature
    construction.

## Compatibility model

V2 preserves the v1 identity anchor:

```text
IdentityGenesisV1.signingKey -> v2 root public key
IdentityGenesisV1             -> unchanged
subject                       -> unchanged nx1_ value
v1 identity lifecycle         -> unchanged
```

An existing active v1 identity can opt into v2 on the device that already holds its non-extractable
v1 signing key. The wallet treats that key as the root, generates a new device key, root-authorizes
it, and follows the normal activation flow. The existing key is not exported, converted, or
replaced, and RP records containing `author_subject` do not migrate.

An upgraded wallet SHOULD stop using the root for routine v2 RP proofs. It MAY continue to make a
`nexus.ownership-proof.v1` with the root for an explicitly negotiated legacy flow. This is a
compatibility path, not a v2 device proof.

Compatibility has an intentional limit: a v1-only verifier does not understand a device
authorization chain and MUST reject `nexus.ownership-proof.v2` as unsupported. An updated RP may
accept v1, v2, or both only when its backend challenge explicitly states the accepted proof
protocols. It MUST NOT silently downgrade a challenge from v2 to v1 based on browser-supplied data.

| Flow                              | Required behavior                                                                                                    |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Existing v1 proof or endpoint     | Remains byte-for-byte and semantically unchanged.                                                                    |
| Existing v1 identity enables v2   | Keeps the same genesis, subject, and terminal lifecycle; current signing key becomes the root.                       |
| V2 device proves to updated RP    | RP verifies the root authorization, device signature, exact challenge, identity state, and exact device state.       |
| V2 device contacts v1-only RP     | Fails as unsupported unless that installation also holds the root and the user explicitly chooses a v1 legacy proof. |
| V1 identity is terminally revoked | Every v2 device is unusable regardless of its own recorded state.                                                    |

### Popup negotiation

The `nexus.popup.v1` channel remains unchanged and can return only a v1 proof. Updated clients use
the additive `nexus.popup.v2` channel. The wallet advertises its ordered `supportedProofProtocols`,
and the RP sends a non-empty, duplicate-free ordered `acceptedProofProtocols` list containing
`nexus.ownership-proof.v2`, `nexus.ownership-proof.v1`, or both. The result names the selected
`proofProtocol` and contains the matching strict proof type.

Popup negotiation is not authorization policy. The RP backend MUST bind the same accepted protocol
list to its stored challenge and independently reject a result whose protocol was not offered. The
wallet MUST return `UNSUPPORTED_PROOF_PROTOCOL` when there is no intersection and MUST NOT silently
fall back to v1.

## Cryptographic encodings and identifiers

Every signature in this profile uses the existing Nexus preimage:

```text
UTF8("NEXUS-SIGNATURE\0") ||
UTF8(payload.protocol) ||
0x00 ||
UTF8(JCS(payload))
```

Identifiers are recomputed by consumers; a wire value is never trusted by itself:

```text
device_id_payload = JCS({
  subject,
  signingKey: { alg: "Ed25519", publicKey: device_public_key }
})

deviceId = "nxd2_" || base64url(SHA256(
  UTF8("NEXUS-DEVICE-ID\0v2\0") || UTF8(device_id_payload)
))

authorizationId = "nxa2_" || base64url(SHA256(
  UTF8("NEXUS-DEVICE-AUTHORIZATION\0v2\0") ||
  UTF8(JCS(device_authorization_payload))
))

operationId = "nxo2_" || base64url(SHA256(
  UTF8("NEXUS-DEVICE-OPERATION\0v2\0") || UTF8(JCS(signed_operation_payload))
))
```

`deviceId` identifies one public key under one subject. Reusing the same private key under another
subject produces a different ID but is forbidden because it creates a correlation and compromise
link. `authorizationId` identifies the complete root grant, including its nonce and time window.
`operationId` provides deterministic idempotency for the exact signed activation or revocation
payload.

## Device authorization

The root signs the complete authorization payload:

```ts
interface DeviceAuthorizationPayloadV2 {
  protocol: 'nexus.device-authorization.v2';
  subject: NexusSubject;
  genesisHash: Base64Url32;
  deviceId: NexusDeviceIdV2; // nxd2_...
  signingKey: {
    alg: 'Ed25519';
    publicKey: Base64Url32;
  };
  authorizationNonce: Base64Url32;
  validFrom: number;
  activationDeadline: number;
  expiresAt: number;
}

interface DeviceAuthorizationV2 {
  payload: DeviceAuthorizationPayloadV2;
  rootSignature: Base64Url64;
}
```

The root MUST verify or construct the subject from its own stored genesis. It MUST NOT sign a
caller-selected subject, genesis hash, device ID, or authorization time outside wallet policy.
Validators require:

```text
validFrom <= activationDeadline <= expiresAt
activationDeadline - validFrom <= 30 days
expiresAt - validFrom <= 366 days
```

The authorization grants only proof signing, activation of that exact authorization, and
self-revocation of that exact device. V2 deliberately has no extensible capability array: unknown
future authority requires a new protocol version.

Renewal uses a new device key, `deviceId`, authorization nonce, and authorization. An expired or
revoked device key is never reauthorized.

## Device activation

An authorization is not active until the target proves possession of the device private key:

```ts
interface DeviceActivationPayloadV2 {
  protocol: 'nexus.device-activation.v2';
  subject: NexusSubject;
  deviceId: NexusDeviceIdV2;
  authorizationId: NexusDeviceAuthorizationIdV2; // nxa2_...
  requestId: Base64Url32;
  iat: number;
  exp: number;
}

interface DeviceActivationRequestV2 {
  authorization: DeviceAuthorizationV2;
  payload: DeviceActivationPayloadV2;
  deviceSignature: Base64Url64;
}
```

The registry MUST atomically:

1. strict-validate both payloads and reject unknown fields;
2. require the v1 identity to exist and be active;
3. derive its genesis hash and compare it with the authorization;
4. recompute `deviceId` and `authorizationId`;
5. verify the root signature against `genesis.signingKey`;
6. enforce the activation and authorization windows using registry time;
7. require a short-lived activation payload and verify the device signature;
8. reject a device tombstone, previous revocation, or conflicting authorization; and
9. commit active device state, the `nxo2_` operation ID, and an outbox event together.

Exact replay is idempotent. A different authorization for an existing device ID fails closed.

## Ownership proof v2

```ts
interface OwnershipProofPayloadV2 {
  protocol: 'nexus.ownership-proof.v2';
  subject: NexusSubject;
  genesis: IdentityGenesisV1;
  deviceId: NexusDeviceIdV2;
  authorizationId: NexusDeviceAuthorizationIdV2;
  authorization: DeviceAuthorizationV2;
  aud: string;
  act: string;
  resource: string;
  nonce: Base64UrlAtLeast16;
  iat: number;
  exp: number;
  contextHash?: Base64Url32;
}

interface OwnershipProofV2 {
  payload: OwnershipProofPayloadV2;
  deviceSignature: Base64Url64;
}

interface VerificationExpectationV2 extends VerificationExpectation {
  // null requires the proof to omit contextHash; otherwise it must match exactly.
  contextHash: Base64Url32 | null;
}
```

The authorization is embedded so verification is self-contained apart from fresh state. The device
signature covers the complete nested authorization and RP challenge binding. Verification MUST:

1. dispatch strictly on `nexus.ownership-proof.v2` and strict-validate nested objects;
2. recompute the `nx1_` subject and genesis hash from the unchanged v1 genesis;
3. recompute and exact-match `nxd2_` and `nxa2_` identifiers;
4. verify the root signature using the public key in genesis;
5. enforce the authorization validity period;
6. exact-match `aud`, `act`, `resource`, nonce, and `VerificationExpectationV2.contextHash`; a null
   expectation requires omission rather than accepting any value;
7. validate the proof time window and verify the device signature;
8. obtain sufficiently fresh status for the exact `{ subject, deviceId, authorizationId }`;
9. require both the identity and exact device authorization to be active; and
10. atomically consume the RP challenge before or transactionally with the protected mutation.

A v1 subject-only status result is insufficient for a v2 current-control decision. RP sessions
created with v2 MUST retain the device and authorization IDs and recheck that exact authority under
their documented freshness policy.

The authorization interval is half-open: it is usable at `validFrom` and expired when registry or
verifier time is `>= expiresAt`. Device authorization expiry receives no clock-skew extension.
Activation at `activationDeadline` follows the registry's bounded clock-skew policy; proof `exp` and
RP challenge expiry retain the existing v1 verification policy. An active status statement cannot
extend an authorization beyond its signed `expiresAt`.

## Per-device revocation

### Self-revocation

```ts
interface DeviceSelfRevokePayloadV2 {
  protocol: 'nexus.device-self-revoke.v2';
  subject: NexusSubject;
  genesisHash: Base64Url32;
  deviceId: NexusDeviceIdV2;
  authorizationId: NexusDeviceAuthorizationIdV2;
  requestId: Base64Url32;
  issuedAt: number;
  reasonCode?: 'dispose' | 'key-compromise' | 'lost-device' | 'replaced';
}

interface DeviceSelfRevokeRequestV2 {
  authorization: DeviceAuthorizationV2;
  payload: DeviceSelfRevokePayloadV2;
  deviceSignature: Base64Url64;
}
```

Self-revocation affects only the signing key that verifies the request. The registry MUST accept a
valid self-revocation even before activation or after authorization expiry because the operation
only removes authority. It creates a permanent device tombstone.

The installed wallet submits and verifies the signed registry result before best-effort deletion of
the local device key. Deletion without registry-confirmed revocation MUST NOT be presented as
completed disposal.

### Root revocation

```ts
interface DeviceRootRevokePayloadV2 {
  protocol: 'nexus.device-root-revoke.v2';
  subject: NexusSubject;
  genesisHash: Base64Url32;
  deviceId: NexusDeviceIdV2;
  requestId: Base64Url32;
  issuedAt: number;
  reasonCode?: 'dispose' | 'key-compromise' | 'lost-device' | 'replaced';
}

interface DeviceRootRevokeRequestV2 {
  payload: DeviceRootRevokePayloadV2;
  rootSignature: Base64Url64;
}
```

Root revocation permanently tombstones the `deviceId`, whether active, expired, absent, or pending
activation. This lets a root invalidate a lost transfer package before it is installed. The root
does not need the target device's private key or current authorization ID.

Device operations MUST NOT use the v1 identity `expectedSequence`. An offline root cannot know about
unrelated device changes. Device events instead use operation idempotency and monotonic rules:

- revocation dominates activation;
- a revoked device never becomes active again;
- racing root and self-revocations converge on revoked;
- exact replay returns the original result; and
- terminal identity revocation dominates every race.

## Authoritative registry state

The existing deterministic per-subject Durable Object remains the sole authority. V2 adds a
per-device ledger under that subject; it does not change v1 identity state or sequence.

```text
v1 identity sequence:
  active = 0
  terminally revoked = 1

v2 device-ledger sequence:
  increments for every effective device activation or revocation
```

Device events MUST use separately versioned v2 event, receipt, status, and outbox schemas. They MUST
NOT be emitted as v1 identity events because strict v1 consumers require active identity sequence
`0` and revoked identity sequence `1`.

The reference deployment publishes the v1 outbox through `REGISTRY_EVENTS` to
`nexus-registry-events` and the device outbox through `REGISTRY_DEVICE_EVENTS` to
`nexus-registry-device-events`. The projector consumes them independently and applies
`migrations/d1/0002_device_projection_v2.sql` for its non-authoritative device projection. Because
the queues are unordered relative to each other, it persists an early device event and defers
materialized device state until the matching v1 anchor arrives. Each stream has its own dead-letter
queue and deterministic event-ID deduplication.

Per-device state is monotonic:

```text
ABSENT  --activate--> ACTIVE --self/root revoke--> REVOKED
   |                                             (terminal)
   +-------------root/self revoke--------------> REVOKED TOMBSTONE

ACTIVE --authorization time passes--> EXPIRED (derived authorization result)
```

The registry MUST NOT expose a public endpoint that lists devices for a subject. Status requests
name the exact device and authorization IDs already present in a proof. A v2 signed status statement
reports at least the subject, genesis hash, identity state and sequence, device-ledger sequence,
device and authorization IDs, effective device state, authorization expiry, statement validity, and
service signing `kid`.

The wallet permits the holder to poll this exact status tuple manually for an installed device or
for a device in the root wallet's local authorization catalog. It MUST validate the response schema,
service signature, freshness, and exact subject, genesis, device, and authorization binding before
recording the observation. An observed revoked, expired, or unknown state disables device proofs
locally. Polling alone MUST NOT delete a device key or mark receipt-gated local revocation complete;
key deletion still requires a verified terminal registry receipt. The reference wallet records the
last checked time and does not require a background service or push channel.

Recommended additive endpoints are:

```text
POST /v2/device/activate
POST /v2/device/status
POST /v2/device/status-batch
POST /v2/device/revoke-self
POST /v2/device/revoke-root
```

All `/v1` routes and wire responses remain unchanged. Terminal identity disposal continues through
`POST /v1/identity/revoke`.

The same compatibility rule applies to discovery: `/.well-known/nexus.json` retains its exact v1
shape. V2-aware clients fetch `/.well-known/nexus-v2.json`, which advertises the device registry and
popup channels and links to the v1 discovery document.

V2 device endpoints use an additive `NexusDeviceError` wire schema. It accepts the closed v1
protocol-domain error set plus these transport and device codes:

```text
METHOD_NOT_ALLOWED
UNSUPPORTED_MEDIA_TYPE
ORIGIN_NOT_ALLOWED
HTTPS_REQUIRED
SERVICE_UNAVAILABLE
DEVICE_NOT_FOUND
DEVICE_REVOKED
DEVICE_AUTHORIZATION_CONFLICT
```

None of them are added to the strict v1 `NexusError` schema. The five HTTP/Edge transport faults
pre-exist v2 outside the strict v1 protocol-domain schema; including them in the additive v2 schema
does not change the v1 wire object. Verifier-only outcomes such as `DEVICE_EXPIRED`, `WRONG_DEVICE`,
`WRONG_AUTHORIZATION`, and `WRONG_CONTEXT` are not registry wire error codes.

## Offline device transfer

The root may create an exportable device key solely so it can install that device authority on
another device. This is not identity/root-key export.

The root-created flow is:

1. Generate a fresh device Ed25519 key as temporarily extractable.
2. Construct and sign its `nexus.device-authorization.v2` authorization.
3. Export the device private key directly into an authenticated encrypted transfer envelope.
4. Release the temporary key handle and overwrite transient byte arrays where practical.
5. On the target, decrypt and strict-validate the bundle locally.
6. Recompute the subject, root signature, key pair, and identifiers before import.
7. Import the device private key as non-extractable.
8. Activate by proving device-key possession to the registry.
9. Delete the transfer file/code and transient plaintext on a best-effort basis.

The encrypted plaintext contains only the subject, public genesis, authorization, algorithm and
format metadata, and the device private key. It MUST NOT contain the root private key, revocation
secret, other identities, RP scope mappings, device labels, or authorization history.

The outer envelope MUST use versioned authenticated encryption such as AES-256-GCM with fresh random
nonces and authenticated metadata. Key establishment SHOULD use either a destination-generated
ephemeral X25519 transport public key or a uniformly random transfer code with at least 128 bits of
entropy expanded with HKDF-SHA-256. An ordinary user password MUST NOT be used as the only
protection unless a separately versioned, reviewed Argon2id suite defines its parameters and
recovery UX.

The reference wallet implements the high-entropy transfer-key option with this envelope:

```ts
interface DeviceTransferEnvelopeV2 {
  protocol: 'nexus.device-transfer.v2';
  suite: 'NX-HKDF-SHA256-AES256GCM-v2';
  bundleId: string; // canonical base64url, 32 bytes
  salt: string; // canonical base64url, 32 bytes
  iv: string; // canonical base64url, 12 bytes
  ciphertext: string; // canonical base64url, includes 128-bit GCM tag
}
```

It generates a separate uniformly random 32-byte transfer key, expands the content key with
HKDF-SHA-256 using `NEXUS-DEVICE-TRANSFER\0v2\0` as `info`, and authenticates the canonical envelope
header as AES-GCM additional data.

The reference wallet offers two offline transports:

- **JSON bundle:** the transfer key MUST be delivered over a channel separate from the downloaded
  bundle and MUST NOT be embedded in or stored beside that file.
- **Direct-display QR:** the root wallet MAY render one QR that contains both the encrypted envelope
  and transfer key for a nearby target wallet to scan. The QR is therefore a complete bearer
  credential: encryption does not protect it from a camera, screenshot, shoulder surfer, or copied
  display. The wallet MUST generate and decode it locally without a QR web service, URL shortener,
  analytics request, or network fetch; MUST NOT automatically copy, download, or persist it; and
  MUST warn that any capture can install an indistinguishable clone. Closing the transfer flow MUST
  discard the in-memory representation on a best-effort basis.

The compact reference QR payload is ASCII and versioned independently from the encrypted envelope:

```text
nexus-device-transfer:v2:<bundleId>.<salt>.<iv>.<ciphertext>.<transferKey>
```

Every component is canonical unpadded base64url; `bundleId`, `salt`, `iv`, and `transferKey` decode
to 32, 32, 12, and 32 bytes respectively. The reference profile caps the complete payload at 2,200
bytes so it fits one QR symbol at error-correction level M. A larger transfer MUST fall back to the
JSON method instead of splitting secrets across unversioned animated or multi-part QR codes.

The destination-generated alternative is safer: the destination creates a non-extractable device key
and sends only its public enrollment request to the offline root. The root signs an authorization,
so no private key is transferred. Implementations SHOULD offer this mode when a one-way offline
channel is available.

### Transfer is copying, not a guaranteed move

An exported device bundle can be copied before deletion. All copies contain the same private key,
produce the same `nxd2_` identifier, and are indistinguishable to Nexus. The product MUST NOT claim
that it can enumerate or individually revoke physical clones. Revoking that device ID invalidates
every clone. A separate intended installation therefore requires a separately generated key and
authorization.

## Root storage, upgrade, and loss

A newly created v2 identity SHOULD keep its root in an offline or rarely connected device and use a
device key even on the root installation for ordinary proofs. Hardware-backed, user-mediated root
signing is preferred where available.

For an upgraded v1 identity, `extractable:false` prevents a standards-compliant raw key export but
does not retroactively make the browser installation an isolated offline signer. Wallet-origin
malicious code may still invoke a browser-held key and some browser threat models may permit a
usable `CryptoKey` capability to be copied without exposing raw bytes. The UI MUST describe this as
"existing key used as root," not as a hardware or air-gapped guarantee.

Root loss is not recoverable by a device key. Existing active devices continue only until their
authorizations expire or the identity is terminally revoked. They may self-revoke, but cannot renew,
authorize replacements, revoke siblings, or recover the root. The v1 revocation secret, if retained
separately, can terminally destroy the identity but cannot restore root authority.

## Threats and residual risk

| Threat                      | Consequence and control                                                                                                                                                                            |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Root compromise             | Attacker can authorize or revoke any device for that subject. Keep root non-extractable, offline/rarely used, typed, and user-mediated. Terminal v1 revocation is the final containment mechanism. |
| Device compromise           | Attacker can make proofs as that subject until exact device status reflects revocation. Use short proofs, fresh status, and root/self revocation.                                                  |
| Transfer-bundle theft       | Attacker can install or clone that device. Encrypt locally with high-entropy key establishment and let the root preemptively tombstone the device ID.                                              |
| Bundle cloning              | Physical copies are indistinguishable. Generate one key per installation and revoke the shared device ID to invalidate every clone.                                                                |
| Root loss                   | No renewal or new device authorization. Existing devices cannot elevate themselves; retained revocation secret only permits terminal destruction.                                                  |
| Registry rollback/staleness | A revoked device could appear active. The per-subject Durable Object is authoritative; D1/KV/Queue state never authorizes current control.                                                         |
| Correlation                 | A device ID is stable within one subject and can link uses of that subject. Never reuse a device key across subjects; keep labels/platform metadata local and expose no device-list endpoint.      |
| Wallet XSS                  | Non-extractable keys may still be invoked. Preserve strict CSP, dependency/build controls, origin-derived audience, typed consent, and root isolation.                                             |

## Required negative and concurrency tests

Before production, implementations MUST cover at least:

- root signature, device signature, subject, genesis hash, `nxd2_`, and `nxa2_` mismatch;
- unknown fields/protocols, malformed canonical base64url, invalid time ordering, expired
  activation, expired authorization, and excessive proof lifetime;
- activation without possession, conflicting authorization, activation after tombstone, and
  attempted reauthorization of a revoked key;
- self-revocation signed by a sibling device and root revocation signed by a device;
- v2 proof checked with only v1 subject status;
- RP challenge replay, cross-origin/action/resource substitution, and downgrade attempts;
- activation racing root revocation, self-revocation racing root revocation, and either operation
  racing terminal identity revocation;
- idempotent exact replay of activation and each revocation mode;
- transfer tampering, wrong transfer code, key/public mismatch, root material accidentally included,
  and target import as extractable; and
- existing v1 identities, proofs, receipts, status statements, and terminal revocation remaining
  unchanged after v2 support is enabled.
