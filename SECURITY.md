# Security Policy

ROwO Nexus is security- and privacy-critical software. It is currently under active development and
has not completed the independent cryptographic, code, deployment, and privacy reviews required for
production.

## Supported versions

Only the latest commit on the default branch is eligible for security fixes during the pre-release
period. No released version should currently be treated as production-supported.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use the repository's private GitHub
Security Advisory reporting flow. Include:

- the affected package, Worker, endpoint, or commit;
- the security or privacy invariant at risk;
- reproduction steps or a minimal proof of concept;
- realistic impact, including whether key material, proof replay, lifecycle state, or correlation is
  involved;
- any suggested mitigation.

Do not include real user private keys, revocation secrets, full ownership proofs, IP addresses, or
other sensitive personal data. Use freshly generated test identities.

Maintainers should acknowledge a complete report promptly, keep investigation details private,
coordinate a fix and disclosure window with the reporter, and preserve evidence without expanding
sensitive telemetry. Public disclosure should occur only after affected deployments and key material
have been addressed.

## Security invariants

Changes must preserve the normative requirements in `NEXUS_SPEC.md`, especially:

- no global controller/user identifier and no civil-identity mapping;
- independent CSPRNG-generated identity keys, not deterministic children of a recoverable master
  seed;
- non-extractable per-identity roots and independently generated v2 device keys, with no root-key
  export or device-key derivation from the root;
- root-signed device authorization, possession-proven activation, exact per-device status checks,
  irreversible device tombstones, and terminal identity revocation dominating all device state;
- no user private keys, revocation secrets, or plaintext vault contents on Cloudflare;
- exact audience, action, resource, nonce, and time binding for proofs;
- audience derived from `MessageEvent.origin`, with exact-origin proof responses;
- per-subject SQLite Durable Objects as the only lifecycle authority;
- terminal `ACTIVE -> REVOKED` lifecycle with no reactivation or key replacement;
- strict schema validation, RFC 8785 canonicalization, domain separation, and fail-closed
  version/suite handling;
- no sensitive values or stable identity/network dimensions in application logs;
- no third-party runtime JavaScript on the wallet origin.

The additive v2 profile permits encrypted offline transfer of a newly generated device private key,
not the identity/root key. Reports involving transfer-envelope plaintext, weak key establishment, QR
capture or unintended persistence, clone handling, device-status staleness, sibling-device
authority, root loss, or v1 downgrade are security-sensitive. See
[`docs/protocol/device-delegation-v2.md`](./docs/protocol/device-delegation-v2.md).

Nexus provides pseudonymous cryptographic identity, not network anonymity. A report showing
correlation through network or timing metadata may still be valuable, but the protocol alone cannot
guarantee protection from Cloudflare, ISPs, relying parties, or a broadly observing operator.

## Incident classes

Operational procedures for user-key compromise, service-signing-key compromise, D1 loss, Queue
failure, and suspected wallet-origin compromise are documented in
[docs/cloudflare/incident-response.md](./docs/cloudflare/incident-response.md).

Service signing keys are distinct from user identity keys. Compromise of a Nexus service key must
not enable an attacker to forge an Ed25519 signature made by a user's identity key.
