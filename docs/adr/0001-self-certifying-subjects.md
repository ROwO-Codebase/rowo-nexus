# ADR-0001: Self-Certifying Subjects

- Status: Accepted
- Date: 2026-08-11
- Scope: protocol, verifier, wallet, registry

## Context

Nexus needs a pseudonymous identifier whose controlling public key cannot be substituted by a
registry operator, relying party, or attacker. It must not rely on a username, account row,
directory lookup, or civil identity.

## Decision

An immutable `nexus.identity.v1` genesis document contains the versioned suite, Ed25519 public
signing key, optional X25519 public agreement key, and domain-separated revocation commitment. It
contains no timestamp, relying-party origin, user metadata, device ID, or controller ID.

The subject is:

```text
genesis_bytes = UTF8(JCS(genesis))
genesis_hash  = SHA256(UTF8("NEXUS-IDENTITY-GENESIS\0v1\0") || genesis_bytes)
subject       = "nx1_" + base64url(genesis_hash)
```

Every verifier recomputes the subject from strict-schema-validated canonical genesis. The supplied
subject alone is never authoritative. Existing subjects never silently migrate to another suite
because the suite and genesis are part of the hash commitment.

Canonical bytes are therefore part of this decision. Genesis and every other hashed or signed Nexus
object use a strict versioned schema, unpadded base64url binary fields, integer Unix seconds, and
RFC 8785 JCS. Signed objects use the domain-separated preimage:

```text
UTF8("NEXUS-SIGNATURE\0") ||
UTF8(protocol_identifier) ||
0x00 ||
UTF8(JCS(object_without_signature))
```

Subjects, registry events, and revocation commitments use their own specified domain-separated hash
preimages. Unsupported protocols, suites, algorithms, fields, or encodings fail closed.

## Consequences

- Public-key substitution produces a different subject.
- Verification can be runtime-local and independent of the Nexus service; fresh lifecycle state
  remains a separate registry concern.
- Any genesis change creates a new identity rather than mutating the old one.
- Canonicalization, encoding, and suite behavior are consensus/security-critical and require
  deterministic cross-runtime vectors.
- Subject strings are public pseudonyms, not secret identifiers, user accounts, or network-anonymity
  guarantees.
- Canonicalization and domain separation cannot change through a serializer/library swap without a
  new protocol version and updated vectors.

## Compliance

Tests must cover canonical genesis bytes, hash/subject vectors, altered genesis/key rejection,
malformed/padded base64url, unknown fields/protocol/suite rejection, signed-object canonical bytes,
domain separation, fuzz/differential cases, and Node/Workers parity.
