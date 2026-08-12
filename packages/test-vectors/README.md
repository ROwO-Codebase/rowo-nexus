# Nexus deterministic test vectors

These JSON files are language-neutral fixtures for Nexus v1 canonicalization, hashing, identifiers,
and Ed25519 signatures, plus the additive v2 device-delegation chain. The v2 vectors deliberately
anchor every device authorization to an unchanged `IdentityGenesisV1`; there is no
`IdentityGenesisV2`.

> **NON-PRODUCTION TEST FIXTURES:** `keys.json` contains public RFC 8032 test seeds wrapped in
> PKCS#8. The corresponding private keys are public knowledge. Never use these keys, seeds,
> signatures, revocation secrets, or nonces outside tests.

Regenerate with `pnpm --filter @nexus/test-vectors generate`, then independently verify with
`pnpm --filter @nexus/test-vectors verify`. Generation imports fixed PKCS#8 fixtures; it never
replaces or controls Web Crypto randomness.

The committed v1 files remain byte-for-byte stable. The `*-v2.json` files cover:

- device ID and authorization ID derivation, including the root authorization signature;
- activation operation ID derivation and the device proof-of-possession signature;
- device-signed ownership proofs embedding the root authorization;
- device registry event IDs and service-signed receipts; and
- service-signed combined identity/device status statements.

The root key uses RFC 8032 TEST 1 (`identity-a`), the device key uses TEST 2 (`identity-b`), and
registry statements use TEST 3 (`service-registry`). Verification recomputes every preimage, hash,
identifier, and signature, and includes payload/signature tamper checks.
