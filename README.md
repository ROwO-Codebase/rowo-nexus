# ROwO Nexus

ROwO Nexus is a reusable cryptographic identity layer for anonymous and pseudonymous applications.
It lets a browser wallet create independent, disposable, self-certifying identities; prove control
of application resources; rotate without creating a public link; and irreversibly revoke an identity
without a username, password, or civil-identity record.

This repository is a standalone pnpm/TypeScript monorepo. The normative architecture and security
contract is [NEXUS_SPEC.md](./NEXUS_SPEC.md). When implementation convenience conflicts with that
specification, the privacy or cryptographic invariant wins.

> **Project status:** pre-production reference implementation. The protocol, wallet, relying-party
> example, Cloudflare services, and security test suites are implemented, but the repository has not
> completed the independent cryptographic, privacy, and operational reviews required for production.
> Do not use it to protect real users or valuable resources yet.

## What Nexus is—and is not

Nexus provides self-certifying pseudonyms, audience/action/resource-bound proofs, authoritative
lifecycle checks, signed registry receipts, and a local wallet that can manage multiple unrelated
identities.

Nexus is not an account provider, a global user directory, a one-person-one-identity system, or a
network-anonymity service. Cloudflare, network providers, relying parties, and timing observers may
still correlate traffic. Users who need network anonymity require a separate, carefully reviewed
anonymity layer.

## Architecture

- `packages/protocol`: strict schemas, canonical JSON, encodings, identifiers, and protocol
  constants.
- `packages/crypto`: Web Crypto providers and domain-separated cryptographic helpers.
- `packages/verifier`: runtime-portable subject, proof, receipt, and status verification.
- `packages/sdk-browser`: relying-party-to-wallet popup transport; it never stores private keys.
- `packages/wallet-core`: local private-key operations, scopes, rotation, and disposal.
- `apps/wallet`: dedicated-origin wallet UI with no third-party runtime JavaScript.
- `apps/reference-rp`: deployable anonymous-notes RP with durable challenges, sessions, and
  immutable resource ownership.
- `workers/registry`: per-subject SQLite Durable Object lifecycle authority.
- `workers/edge-api`: fixed public protocol endpoints and service receipt/status signing.
- `workers/projector`: idempotent Queue-to-D1 projection.
- `workers/transparency`: hash-only transparency checkpoints.

The lifecycle authority is always the per-subject Durable Object. D1, KV, R2, Queue consumers,
Worker memory, and transparency data cannot authorize current control.

### Foundational decisions

1. [ADR-0001: Self-certifying subjects](./docs/adr/0001-self-certifying-subjects.md)
2. [ADR-0002: No global controller identifier](./docs/adr/0002-no-global-controller-id.md)
3. [ADR-0003: Independent random identity keys](./docs/adr/0003-independent-random-identity-keys.md)
4. [ADR-0004: Durable Object lifecycle authority](./docs/adr/0004-durable-object-lifecycle-authority.md)
5. [ADR-0005: D1 and KV are non-authoritative](./docs/adr/0005-d1-kv-non-authoritative.md)
6. [ADR-0006: Audience derived from browser origin](./docs/adr/0006-audience-derived-from-browser-origin.md)
7. [ADR-0007: Revocation before deletion](./docs/adr/0007-revocation-before-deletion.md)
8. [ADR-0008: Default rotation is unlinkable](./docs/adr/0008-default-rotation-unlinkable.md)
9. [ADR-0009: Historical timestamps require trusted receipts](./docs/adr/0009-trusted-historical-timestamps.md)
10. [ADR-0010: Hash-only transparency](./docs/adr/0010-hash-only-transparency.md)
11. [ADR-0011: Root-authorized device keys](./docs/adr/0011-root-authorized-device-keys.md)

Nexus v1 intentionally provides no identity-key backup, portable private-key export/import, or cloud
recovery service. The additive [v2 root/device profile](./docs/protocol/device-delegation-v2.md)
preserves the same `nx1_` identity and non-extractable root while allowing that root to authorize
independently revocable device signing keys. Only a device key may be copied through an encrypted
offline transfer bundle or a locally rendered direct-scan QR credential; the identity/root key is
never exported. Existing v1 proofs and endpoints remain unchanged.

## Prerequisites

- Node.js 22 or newer
- pnpm 11.16.0 (use Corepack)

## Local development

```bash
corepack enable
pnpm install
pnpm check
```

Run the application surfaces when their packages are available:

```bash
pnpm dev:wallet
pnpm dev:rp
```

The RP development server uses an untrusted local HTTPS certificate because Nexus proof audiences
must be exact HTTPS origins. Accept the browser's local certificate warning before testing the UI.
The complete production-boundary local flow—including its signed registry fixture and distinct TLS
origins—is exercised with `pnpm test:e2e`.

Copy `.env.example` to a local, ignored environment file only when a local package requires it.
Production service keys belong in Cloudflare Workers secrets or Secrets Store, never in repository
files or CI variables available to untrusted pull requests.

## Verification

The pull-request gates mirror these commands:

```bash
pnpm format:check
pnpm lint
pnpm typecheck
pnpm test
pnpm test:workers
pnpm test:vectors
pnpm test:e2e
pnpm build
pnpm cf:dry-run
```

Security-sensitive protocol changes require updated deterministic test vectors. The wallet and
two-origin reference flow also require browser tests for origin confusion, replay, key leakage, and
disposal.

The release-facing `@nexus/protocol`, `@nexus/crypto`, `@nexus/verifier`, and `@nexus/sdk-browser`
packages are packable public packages. Publishing remains an explicit release operation;
repository-relative imports are not the supported integration boundary.

## Environments

Cloudflare resources and service-signing keys are isolated across `local`, `preview/dev`, `staging`,
and `production`. Preview Workers must never bind to production Durable Objects, D1 databases,
Queues, R2 buckets, or signing secrets.

See [deployment](./docs/cloudflare/deployment.md),
[data retention](./docs/cloudflare/data-retention.md),
[incident response](./docs/cloudflare/incident-response.md), and
[security reporting](./SECURITY.md).

Wrangler files intentionally contain example domains, resource names, and public key identifiers.
Deployment requires environment-specific Cloudflare resources plus separately provisioned Worker
secrets; a successful dry run does not provision those resources.

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](./CONTRIBUTING.md) before opening a pull request,
especially for protocol, cryptographic, lifecycle, wallet-origin, or Cloudflare authority changes.

The [ROwO Nexus Developer Portal](https://developers.rowo.link/nexus) is the recommended place to
learn the product, follow the quick start, and use safe playgrounds before working on an
integration. Keep Nexus contributions and documentation distinct from ROwO OAuth concepts.

## License

MIT. See [LICENSE](./LICENSE).
