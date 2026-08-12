# ADR-0011: Root-Authorized Device Keys

- Status: Accepted
- Date: 2026-08-12
- Scope: identity compatibility, wallet key vault, proofs, registry lifecycle, offline transfer

## Context

Nexus v1 binds one non-extractable Ed25519 key to a self-certifying `nx1_` subject. Copying that
identity key to several devices would make every copy full identity authority, prevent individual
device revocation, and turn a migration artifact into an indefinite identity clone. Changing the
genesis key would change the subject and break existing RP ownership records.

Users nevertheless need to use one subject on several devices, invalidate one device without
destroying the identity, and provision another device through an offline root-controlled flow.
Existing active v1 identities must be able to adopt the same workflow without replacing their key or
subject.

## Decision

The existing `nexus.identity.v1` signing key becomes the per-identity root for the additive v2
profile. The genesis and `nx1_` subject remain unchanged. The root key remains non-extractable and
authorizes independently generated Ed25519 device keys with `nexus.device-authorization.v2`. Device
keys use subject-bound `nxd2_` identifiers; authorizations use `nxa2_` identifiers; signed device
operations use `nxo2_` idempotency identifiers.

The root does not make ordinary `nexus.ownership-proof.v2` proofs. Each device activates its exact
authorization with `nexus.device-activation.v2` and then signs v2 RP proofs. A device may revoke
only itself with `nexus.device-self-revoke.v2`; the root may irrevocably tombstone any device with
`nexus.device-root-revoke.v2`. Terminal v1 subject revocation dominates all device state.

The existing per-subject Durable Object remains authoritative and gains a separate monotonic device
ledger. Device events do not change the v1 identity sequence or masquerade as v1 lifecycle events.
Relying parties store the same subject for resource ownership but must check both subject and exact
device authorization state when accepting v2 proofs.

An existing v1 wallet can enable v2 by using its current signing key as root and generating a new
device key. It may still make v1 root-key proofs only for explicitly negotiated legacy flows. A
v1-only verifier cannot validate a v2 proof; backward compatibility preserves existing contracts
rather than making new proof types understandable to old software.

The root may provision another device by exporting only a newly generated device private key in a
versioned authenticated encrypted bundle. The root private key, revocation secret, RP scopes,
labels, and other identities never enter the bundle. The destination imports the device key as
non-extractable and proves possession during activation. A destination-generated non-extractable key
with an offline public enrollment request is preferred when available.

## Consequences

- Several device keys can prove the same stable `nx1_` subject without sharing the root private key.
- Compromise or loss of one device can be contained by revoking its `nxd2_` identifier; sibling
  devices remain active unless the subject itself is revoked.
- A root can tombstone a lost authorization before activation, and a device can dispose itself
  without being able to affect siblings.
- The registry and updated RPs learn a subject-bound device identifier and device-change timing.
  They still receive no global physical-device, wallet, account, or controller identifier.
- Device authorization chains and exact device status add verification and registry complexity.
- An exported device bundle is copyable. Nexus cannot distinguish physical clones; revoking the
  shared device ID invalidates all of them.
- Root compromise is catastrophic for device authorization under that subject. Root loss is not
  recoverable: devices cannot elevate themselves, renew, or authorize replacements.
- An upgraded browser-held v1 key is compatible but is not retroactively an air-gapped or
  hardware-backed root.
- Existing v1 wire objects, endpoints, proofs, verifier behavior, and subject lifecycle remain
  unchanged. Unsupported v2 objects fail closed in v1-only implementations.

## Compliance

The normative profile is
[`docs/protocol/device-delegation-v2.md`](../protocol/device-delegation-v2.md). Protocol vectors and
tests verify root/device signature separation, subject and identifier recomputation, activation
possession, monotonic per-device revocation, terminal identity dominance, downgrade rejection,
transfer-envelope integrity, non-extractable target import, and unchanged v1 vectors and behavior.
