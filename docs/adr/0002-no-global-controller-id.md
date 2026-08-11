# ADR-0002: No Global Controller Identifier

- Status: Accepted
- Date: 2026-08-11
- Scope: wallet, protocol, registry, RP SDK, backup

## Context

A unified wallet needs to organize many disposable identities locally without creating a global
account or stable cross-application correlation handle. A public master key, wallet ID, installation
ID, controller row, or account identifier would undermine unlinkability.

## Decision

The controller is a local-only wallet concept. The wallet exposes only self-certifying subjects
selected for the requesting RP. It never sends a stable controller, vault, account, device,
installation, or master-public-key identifier to an RP or Nexus service.

The local RP-origin-to-identity map and human labels remain in IndexedDB or inside opaque encrypted
backup ciphertext. Cross-origin reuse of the same identity requires explicit confirmation. The
registry does not receive intended RP scope during registration.

Relying parties store immutable `author_subject` values rather than Nexus user/controller foreign
keys. Nexus schemas and persistence do not create a `users` table or a lookup from a
person/account/controller to subjects.

## Consequences

- There is no global account lookup, universal profile, or one-person-one-identity property.
- Wallet convenience cannot add a protocol-visible common root.
- RP sessions remain RP-local and do not require Nexus to observe later requests.
- Anti-abuse remains separate and cannot create a durable human identifier.
- Optional backup must reveal neither the local manifest nor its subject/scope list.

## Compliance

Schema and architectural tests reject controller/user/vault identifiers in public contracts. Browser
E2E proves origin-scoped selection and no cross-origin identity-list disclosure. Data-model review
confirms no civil-identity or stable-controller mapping.
