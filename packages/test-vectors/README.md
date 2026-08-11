# Nexus deterministic test vectors

These JSON files are language-neutral fixtures for Nexus v1 canonicalization, hashing, identifiers,
and Ed25519 signatures.

> **NON-PRODUCTION TEST FIXTURES:** `keys.json` contains public RFC 8032 test seeds wrapped in
> PKCS#8. The corresponding private keys are public knowledge. Never use these keys, seeds,
> signatures, revocation secrets, or nonces outside tests.

Regenerate with `pnpm --filter @nexus/test-vectors generate`, then independently verify with
`pnpm --filter @nexus/test-vectors verify`. Generation imports fixed PKCS#8 fixtures; it never
replaces or controls Web Crypto randomness.
