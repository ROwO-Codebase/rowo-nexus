# Contributing to ROwO Nexus

Thank you for helping improve ROwO Nexus. Contributions are welcome across the protocol,
cryptographic utilities, verifier, browser SDK, wallet, reference relying party, Cloudflare
services, tests, and documentation.

Nexus is security- and privacy-critical and remains a pre-production reference implementation. A
change is successful only when it preserves the system's privacy boundaries and fails closed under
malformed input, replay, stale lifecycle data, and partial infrastructure failure.

Nexus provides pseudonymous cryptographic control, not network anonymity. Do not describe a Nexus
subject as anonymous to Cloudflare, network providers, relying parties, or timing observers.

## Start with the ROwO Developer Portal

Before changing an integration surface, learn the product through the
[ROwO Nexus Developer Portal](https://developers.rowo.link/nexus). It is the recommended entry point
for contributors and application developers:

- [Nexus introduction](https://developers.rowo.link/nexus) explains what Nexus proves and how it
  differs from ROwO OAuth.
- [Nexus documentation](https://developers.rowo.link/nexus/docs/introduction) covers wallet
  transport, ownership proofs, identity lifecycle, public APIs, and the security checklist.
- [Quick start](https://developers.rowo.link/nexus/docs/quick-start) walks through the relying-party
  integration flow.
- [Nexus playground](https://developers.rowo.link/nexus/playground) safely explores proof-request
  shapes and public lifecycle status without OAuth credentials or private keys.
- [Reference Notes app](https://notes.rowo.link) demonstrates the complete wallet, challenge,
  verification, replay-prevention, and lifecycle flow.

Keep Nexus and OAuth concepts separate. Nexus proves that a pseudonymous cryptographic subject
approved one exact action on one exact resource. It does not sign in a ROwO account, issue access or
refresh tokens, expose profile claims, or establish personhood.

The portal is the friendliest learning surface; [NEXUS_SPEC.md](./NEXUS_SPEC.md), the accepted ADRs,
and the implementation in this repository remain authoritative. If the portal and repository
disagree, open an issue so both can be corrected.

Use only synthetic identities and public test fixtures while learning or contributing. Never paste
real private keys, revocation secrets, full live proofs, personal data, or production credentials
into the portal, an issue, a pull request, or a test fixture.

## Before you begin

Read the material relevant to your change:

1. [NEXUS_SPEC.md](./NEXUS_SPEC.md) for the normative architecture and protocol contract.
2. [SECURITY.md](./SECURITY.md) and the [threat model](./docs/protocol/threat-model.md) for
   reporting rules and security invariants.
3. The protocol guides under [`docs/protocol`](./docs/protocol) for identity, proof, lifecycle, and
   relying-party behavior.
4. The accepted architecture decisions under [`docs/adr`](./docs/adr).
5. The README for the package, app, or Worker you are changing, when one exists.

For a new protocol version, cryptographic primitive, identity-linking feature, lifecycle transition,
storage authority, logging dimension, or deployment trust boundary, open a
[GitHub issue](https://github.com/ROwO-Codebase/rowo-nexus/issues) before implementation. Small bug
fixes, focused tests, accessibility improvements, and documentation corrections can go directly to a
pull request.

Suspected vulnerabilities must not be discussed in a public issue. Follow the private reporting
process in [SECURITY.md](./SECURITY.md).

## Development setup

Requirements:

- Node.js 22 or newer
- Corepack
- pnpm 11.16.0

Clone and verify the repository:

```bash
git clone https://github.com/ROwO-Codebase/rowo-nexus.git
cd rowo-nexus
corepack enable
pnpm install --frozen-lockfile
pnpm exec playwright install chrome
pnpm check
```

Use pnpm throughout the workspace; do not generate npm or Yarn lockfiles. If a dependency changes,
run `pnpm install`, review the complete `pnpm-lock.yaml` diff, and commit the lockfile with the
manifest change.

Copy `.env.example` only to an ignored local environment file when a workspace needs it. Never use
production Cloudflare credentials, signing keys, resource identifiers, or data for contributor
development.

Run the application surfaces with:

```bash
pnpm dev:wallet
pnpm dev:rp
```

The reference RP uses local HTTPS because a Nexus proof audience is an exact HTTPS origin. Its local
certificate is untrusted and is only for loopback development. See the
[wallet](./apps/wallet/README.md) and [reference RP](./apps/reference-rp/README.md) instructions
before testing browser flows.

## Repository boundaries

Keep each responsibility in its owning workspace:

| Area                         | Responsibility                                                                         |
| ---------------------------- | -------------------------------------------------------------------------------------- |
| `packages/protocol`          | Strict schemas, wire types, canonical JSON, encodings, constants, and identifiers      |
| `packages/crypto`            | Web Crypto providers and domain-separated cryptographic operations                     |
| `packages/verifier`          | Runtime-portable proof, receipt, lifecycle, and transparency verification              |
| `packages/sdk-browser`       | Exact-origin RP-to-wallet popup transport; never private-key storage                   |
| `packages/wallet-core`       | Local identity keys, proof creation, rotation, continuity, and disposal                |
| `packages/test-vectors`      | Deterministic, language-neutral protocol fixtures using public test-only keys          |
| `packages/cloudflare-common` | Shared Worker request, response, logging, and service-signing boundaries               |
| `apps/wallet`                | Dedicated-origin wallet and consent UI with no third-party runtime JavaScript          |
| `apps/reference-rp`          | Example challenge storage, atomic proof consumption, sessions, and immutable ownership |
| `workers/registry`           | The only authoritative identity lifecycle state                                        |
| `workers/edge-api`           | Public protocol endpoints, validation, CORS, and signed service responses              |
| `workers/projector`          | Idempotent D1 projection; never an authorization source                                |
| `workers/transparency`       | Hash-only registry event transparency and signed checkpoints                           |

Prefer importing the owning package over duplicating schemas, canonicalization, identifier
derivation, signature conventions, or protocol constants in another workspace.

Dependency authority flows from `protocol` to `crypto` to `verifier`: crypto imports protocol
contracts, and the verifier consumes those shared contracts and cryptographic operations. Keep
wallet-core out of relying parties, and keep application-specific code out of the portable protocol,
crypto, and verifier packages.

## Security and privacy rules

Changes that violate these boundaries will not be accepted:

- Do not create a global controller, user, or civil-identity mapping.
- Do not derive identities from a recoverable master seed; identity keys are independently generated
  with a CSPRNG.
- Do not implement custom cryptographic primitives or use `Math.random()` for security-sensitive
  values.
- Do not send user private keys or plaintext wallet vault contents to a server.
- A revocation secret may transit only in the strict secret-mode `revoke` request to the
  authoritative registry. Never persist, log, echo, cache, or include it in any other request or
  response.
- Do not accept an audience supplied in proof-request JSON. The wallet derives it from the exact
  `MessageEvent.origin`.
- Require proofs to exact-bind the server-expected audience, action, resource, nonce, and time
  window, then atomically consume the single-use challenge with the protected mutation.
- Parse every external protocol object with strict schemas. Use RFC 8785 canonical JSON, canonical
  unpadded base64url, and the specified domain separation; reject unknown fields, versions, and
  suites.
- Do not use wildcard `postMessage` targets for proofs, errors containing sensitive context, or
  results.
- Do not authorize from D1, KV, R2, Queue state, Worker memory, or transparency data. Lifecycle
  authority belongs to the per-subject Durable Object.
- Do not add a `REVOKED -> ACTIVE` transition, key replacement, or identity transfer.
- Do not delete local key material before authoritative revocation is verified.
- Do not put subjects, proofs, secrets, IP addresses, resource identifiers, or other stable identity
  dimensions in routine logs or metrics.
- Do not add third-party runtime JavaScript, analytics, remote fonts, or unrelated network access to
  the wallet origin.
- Do not add identity-key backup, portable private-key export/import, cloud recovery, or key restore
  surfaces. Lost wallet key material is intentionally unrecoverable in Nexus v1.

When requirements conflict, choose the more private and fail-closed behavior and explain the
trade-off in the pull request.

Contributors should validate Cloudflare changes with `pnpm cf:dry-run`. Production deployments,
remote migrations, secret rotation, checkpoint publication, and package publishing are maintainer
release operations and must not be performed from a contribution branch.

## Making a change

1. Create a focused branch from the current default branch.
2. Keep the change small enough to review and avoid unrelated formatting or generated-file churn.
3. Add or update tests before changing security-sensitive behavior.
4. Update protocol documentation, ADRs, deployment guidance, or the Developer Portal when the public
   contract or contributor workflow changes.
5. Run focused package tests during development, then run the repository gates before requesting
   review.

Conventional commit-style summaries are encouraged, for example:

```text
feat(wallet): add registration recovery state
fix(verifier): reject a mismatched resource
docs: clarify authoritative status checks
test(registry): cover concurrent revocation
```

Do not include secrets, subject identifiers, proof material, or user data in branch names, commit
messages, screenshots, fixtures, or CI logs.

## Tests and required evidence

Run the full local gate when possible:

```bash
pnpm check
```

It covers formatting, linting, strict type checks, unit tests, Worker tests, deterministic vectors,
browser security tests, builds, and Cloudflare deployment dry runs. Local E2E runs use the Google
Chrome channel; install Chrome normally or let Playwright install that channel with:

```bash
pnpm exec playwright install chrome
```

CI sets `CI=true` and installs Playwright's bundled Chromium with system dependencies instead.

At minimum, run the gates relevant to your change:

| Change                                    | Required checks                                                      |
| ----------------------------------------- | -------------------------------------------------------------------- |
| Documentation only                        | `pnpm format:check` and link/content review                          |
| Package or schema                         | `pnpm lint`, `pnpm typecheck`, `pnpm test`                           |
| Protocol or cryptography                  | Package tests, `pnpm test`, and `pnpm test:vectors`                  |
| Registry, API, projector, or transparency | `pnpm test:workers` and `pnpm cf:dry-run`                            |
| Wallet, browser SDK, or reference RP      | Relevant unit tests, `pnpm test:e2e`, and `pnpm build`               |
| Dependency update                         | Relevant gates, lockfile review, and `pnpm audit --audit-level high` |

Protocol and cryptographic changes require deterministic positive and negative vectors. Regenerate
and independently verify them with:

```bash
pnpm build:packages
pnpm --filter @nexus/test-vectors generate
pnpm --filter @nexus/test-vectors verify
pnpm test:vectors
```

Never replace the public non-production vector keys with operational key material.

## Pull request checklist

A pull request should:

- explain the problem and the chosen behavior;
- identify the affected trust boundary or security invariant;
- describe user-visible, protocol, storage, logging, and deployment effects;
- list the exact commands run and their results;
- include tests for success, malformed input, replay, stale state, and failure paths as applicable;
- update deterministic vectors and public documentation when contracts change;
- avoid unrelated files, secrets, production identifiers, and generated artifacts;
- call out any intentionally deferred work or review that is still required.

Screenshots are useful for wallet and reference-RP interface changes, but use synthetic identities
and redact all subjects, resources, proofs, and request identifiers.

Maintainers may ask for additional cryptographic, privacy, browser-origin, concurrency, or
deployment review before merging. Passing CI is necessary but does not replace security review.

## Documentation and Developer Portal updates

Public integration changes should update both this repository and the
[ROwO Nexus Developer Portal](https://developers.rowo.link/nexus). Keep Nexus material under the
portal's dedicated `/nexus` routes rather than placing it in OAuth documentation.

The portal source lives in the separate
[`ROwO-Codebase/rowo-auth`](https://github.com/ROwO-Codebase/rowo-auth) repository under
`apps/developers`. Coordinate a companion issue or pull request there when a Nexus change affects
public instructions, examples, or playground behavior.

Examples must:

- use `https://nexus.rowo.link` as the public API and `https://wallet.rowo.link` as the wallet;
- omit an `aud` field from proof requests;
- issue challenges on the RP backend, not solely in browser code;
- use exact action, resource, nonce, expiry, and optional context-hash expectations;
- perform an authoritative lifecycle check and atomically consume the challenge;
- describe a Nexus subject as a pseudonym, not a user, account, or person;
- label the implementation and package APIs as pre-production until a reviewed release says
  otherwise.

## License

Unless stated otherwise, contributions to this repository are made available under the repository's
[MIT License](./LICENSE).
