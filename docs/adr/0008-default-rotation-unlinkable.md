# ADR-0008: Default Rotation Is Unlinkable

- Status: Accepted
- Date: 2026-08-11
- Scope: wallet rotation, registry API/events, D1 projection, continuity links

## Context

A convenient combined rotation endpoint or automatic old/new certificate would create a durable
correlation graph. Privacy rotation and public continuity are different user intents and must not be
conflated.

## Decision

Default rotation means generate a new independently random identity and optionally revoke the old
identity as a separate operation. There is no combined server rotation endpoint, old/new field in
registry events or projections, automatic wallet proof, or implicit continuity relationship.

Continuity linking is a separate versioned certificate signed by both identities after explicit
warnings that it makes them intentionally linkable. It is never generated automatically.

## Consequences

- The registry cannot infer a rotation edge from protocol data alone.
- Applications cannot assume a new subject inherits resources, reputation, or authorization from an
  old subject.
- Users who deliberately choose continuity receive a verifiable but privacy-reducing artifact.
- Timing/network observation may still correlate operations; unlinkable protocol data is not a
  network-anonymity guarantee.

## Compliance

Rotation tests confirm unrelated keys/genesis/subjects, no old/new relation in API/event/D1 schemas,
optional independent old-subject revocation, and continuity verification only when both required
signatures are valid.
