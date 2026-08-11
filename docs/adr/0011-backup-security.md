# ADR-0011: Opaque Encrypted Backup Security

- Status: **PROPOSED — BLOCKED**
- Date: 2026-08-11
- Scope: wallet export/restore, backup capability, backup Worker/R2

## Context

Portable backup can reduce accidental loss, but it creates an offline password/recovery-guessing
surface and may preserve private keys after local disposal. A weak, improvised, or unversioned
key-derivation decision would undermine the wallet's security. The service must learn neither the
vault plaintext nor the subjects/RP scopes inside it.

## Proposed invariant set

- Encryption and authentication occur client-side before upload.
- The server stores only a versioned opaque ciphertext envelope and minimal capability metadata.
- Backup authentication is independent of every Nexus identity and uses random backup ID/secret
  capability material; the server stores only a verifier/hash of the capability secret.
- The server never receives the vault decryption key, plaintext manifest, subject list, RP scope
  map, private key, or revocation secret.
- Tampering must fail authenticated decryption; envelope fields are strict and versioned.
- Restore cannot reactivate a terminally revoked subject.
- Historical claims from restored old keys require trusted pre-revocation receipts, not
  self-asserted `iat` values.
- Deletion/expiry must cover current objects, prior versions, caches, exports, and disaster-recovery
  copies under a documented retention policy.

## Blocked decision

This ADR deliberately does **not** select a password/recovery KDF, parameter values, device-class
calibration, recovery-secret composition, downgrade policy, or envelope migration rules. Those
choices require dedicated security review, representative performance measurements, test vectors,
threat-cost analysis, and an approved amendment to this ADR.

No placeholder or “temporary” KDF parameters may ship. No production backup upload, exportable-key
workflow, restore path, R2 bucket binding, or user-facing availability promise may be enabled while
this ADR is blocked. `NEXUS_BACKUP_ENABLED` remains false.

## Required evidence before approval

1. documented attacker model for stolen R2/database contents and offline guessing;
2. reviewed KDF/recovery design with explicit versioned parameters and device performance
   measurements;
3. entropy and UX analysis for every supported recovery method;
4. versioned envelope/AAD format and downgrade/migration behavior;
5. deterministic fixtures plus tamper, wrong-secret, downgrade, and cross-runtime tests;
6. capability rotation, rate-limit, deletion, expiry, and disaster-recovery retention design;
7. post-disposal backup update behavior that reveals no subject list;
8. independent cryptographic and privacy review approval.

## Consequences while blocked

- The wallet may use normal local non-extractable keys and IndexedDB state.
- Backup Worker code may exist only as disabled scaffolding that cannot accept production data.
- Documentation and UI must clearly mark backup/export/restore unavailable.
- Identity disposal remains registry revocation followed by best-effort local deletion; users cannot
  rely on Nexus to recover disposed or lost keys.
