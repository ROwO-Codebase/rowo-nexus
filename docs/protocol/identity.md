# Identity Protocol

This document summarizes the v1 identity contract. `NEXUS_SPEC.md` remains normative.

## Suite

`NX-25519-SHA256-JCS-v1` uses Ed25519 signing, SHA-256 subject hashing, optional X25519 agreement,
HKDF-SHA-256 where needed, AES-256-GCM for local envelopes, RFC 8785 JSON Canonicalization Scheme
(JCS), and unpadded base64url binary fields.

All signed inputs are strictly schema-validated before canonicalization. Unknown fields, protocols,
or suites fail closed. Cryptographic algorithm names are enumerated by the schema and never passed
from untrusted strings to arbitrary APIs.

## Genesis

An identity genesis document contains only:

```ts
interface IdentityGenesisV1 {
  protocol: 'nexus.identity.v1';
  suite: 'NX-25519-SHA256-JCS-v1';
  signingKey: { alg: 'Ed25519'; publicKey: string };
  agreementKey?: { alg: 'X25519'; publicKey: string };
  revocationCommitment: string;
}
```

It contains no timestamp, label, relying-party origin, controller, device, account, or
civil-identity field.

Each identity gets independently generated signing material and a 32-byte revocation secret `R`.
Identity keys must come from Web Crypto CSPRNG facilities and must not be deterministically derived
from a surviving master seed. The commitment is:

```text
SHA256(UTF8("NEXUS-REVOCATION-COMMITMENT\0v1\0") || R)
```

## Subject derivation

The self-certifying subject commits to the exact canonical genesis bytes:

```text
genesis_bytes = UTF8(JCS(genesis))
genesis_hash  = SHA256(UTF8("NEXUS-IDENTITY-GENESIS\0v1\0") || genesis_bytes)
subject       = "nx1_" + base64url(genesis_hash)
```

Verifiers always recompute this value. A wire-supplied subject is never trusted by itself, and
changing a key or commitment necessarily changes the subject.

## Local identity state

The dedicated wallet origin stores private key references, the revocation secret reference, local
labels, and the local map from RP origins to identities in IndexedDB. Normal operation should use
non-extractable `CryptoKey` objects where browser persistence is verified. Private key material,
revocation secrets, local labels/scopes, stable installation IDs, or controller IDs must never reach
an RP or Cloudflare service.

Nexus v1 provides no private-key export, import, backup, recovery, or server-side wallet storage
path. Identity keys remain local and non-extractable in the wallet.

The additive [v2 root/device profile](./device-delegation-v2.md) does not change that rule for the
identity key. It treats the unchanged v1 signing key as a non-extractable per-identity root and lets
it authorize independently generated device signing keys. An existing active v1 identity can adopt
that workflow without changing its genesis or `nx1_` subject.

## Privacy properties and limits

- A wallet may manage many identities, but exposes no stable public controller.
- Reusing one identity across origins requires explicit user confirmation.
- Registration does not reveal the identity's intended RP.
- Rotation creates an unrelated identity by default; continuity linking is separate and explicit.
- Nexus does not prove that one person owns only one identity.
- Cryptographic unlinkability is not network anonymity. Cloudflare, ISPs, RPs, or timing observers
  may correlate traffic.
