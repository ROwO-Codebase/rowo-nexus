# ADR-0003: Independent Random Identity Keys

- Status: Accepted
- Date: 2026-08-11
- Scope: wallet key vault, identity creation, rotation

## Context

Disposable identities need meaningful cryptographic disposal and default unlinkability. If every
identity can be regenerated from a surviving master seed or deterministic hierarchy, deleting one
private key does not actually dispose of it and compromise of the root links or recovers all
descendants.

## Decision

Each identity uses independently generated random private key material and an independent 32-byte
revocation secret. Production randomness comes only from Web Crypto CSPRNG facilities.
`Math.random()` and deterministic child derivation from a recoverable master seed are forbidden for
identity, secret, nonce, capability, or identifier material.

The normal wallet key vault uses isolated key references and prefers non-extractable `CryptoKey`
objects where persistence is verified. No consumer outside wallet internals receives a raw private
key by default.

The v1 wallet exposes no portable private-key export/import or recovery path and cannot introduce a
master seed that silently regenerates identities.

## Consequences

- Losing an identity's independent key material may be unrecoverable; this is consistent with
  meaningful disposal.
- Compromise or disposal of one identity does not cryptographically compromise another.
- Default rotation generates a truly independent subject.
- Tests inject deterministic CSPRNG providers only as fixtures; production code always uses Web
  Crypto randomness.
- Best-effort local erasure remains limited by browser/OS storage, so terminal server revocation is
  still required.

## Compliance

Tests verify independent key/secret generation, deterministic fixture injection boundaries, lack of
master-seed derivation APIs, absence of user keys in network/server payloads, and independent
identity creation after another identity is revoked.
