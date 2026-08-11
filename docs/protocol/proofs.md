# Ownership Proofs and Receipts

This document summarizes the v1 signed-object rules. `NEXUS_SPEC.md` remains normative.

## Signing format

Every signed object is strictly validated, encoded with unpadded base64url, uses integer Unix
seconds, and is canonicalized with RFC 8785 JCS. The signature preimage is domain separated:

```text
UTF8("NEXUS-SIGNATURE\0") ||
UTF8(protocol_identifier) ||
0x00 ||
UTF8(JCS(object_without_signature))
```

Normal application APIs expose typed operations such as `prove`, `revoke`, and `link`; the RP-facing
SDK must not expose arbitrary raw signing.

## Ownership proof

`nexus.ownership-proof.v1` binds all of the following:

- the self-certifying `subject` and full public genesis;
- `aud`: the exact RP HTTPS origin;
- `act`: the exact server-side operation;
- `resource`: the exact RP resource identifier;
- a backend-generated, single-use nonce with at least 128 bits of randomness;
- `iat` and `exp` integer timestamps;
- optional `contextHash`, normally SHA-256 over the RP-defined request/body context.

Proof lifetime should be at most 120 seconds; 60 seconds is the default target. Wildcard audiences
are forbidden.

## Verification order

The verifier must:

1. strict-validate the schema and supported protocol/suite;
2. derive the subject from genesis and compare it to the claimed subject;
3. exact-match audience, action, resource, and nonce;
4. confirm the challenge exists, is unexpired, and is unconsumed;
5. validate the time window and bounded clock skew;
6. verify the Ed25519 signature over the canonical domain-separated preimage;
7. obtain lifecycle state under the RP's declared freshness policy;
8. reject any non-active subject for current-control operations;
9. atomically consume the challenge before or transactionally with the protected mutation.

Reordering these steps must not cause secrets or detailed validation state to leak through errors or
logs.

## Lifecycle freshness

- `strict`: query the authoritative registry status for every sensitive operation.
- `session`: perform a strict check at session start and use a short RP-local session within an
  explicitly documented risk window.
- `stapled-status`: accept a valid, unexpired service-signed status statement with an enforced
  expiry.

D1, KV, Queue state, Worker memory, or an expired status statement cannot authorize a subject.

## Registry receipts and status statements

Registration and revocation return a `nexus.registry-receipt.v1` signed by a Nexus service key,
containing the deterministic event ID, subject/genesis hash, event type, sequence, terminal state,
accepted time, and signer `kid`. A `nexus.status-statement.v1` reports active/revoked state with a
short validity period; relying parties enforce its `exp`.

Service keys are distinct from user identity keys. The public key history remains available while
receipts under a `kid` are expected to verify.

## Historical claims

A user-controlled `iat` is not trusted historical time after old key material is stolen or copied.
Durable historical authorship needs a trusted pre-revocation acceptance receipt or timestamp from
the RP, registry, or reviewed notary flow. A valid old user signature can establish possession of an
old key, but cannot by itself prove when it was made.
