# ADR-0006: Audience Derived from Browser Origin

- Status: Accepted
- Date: 2026-08-11
- Scope: browser wallet, popup transport, RP SDK

## Context

A malicious RP can place any string inside its request JSON or wallet URL. If the wallet trusts a
caller-supplied audience, it may sign a proof usable by another application or return a proof to the
wrong origin.

## Decision

The wallet derives proof `aud` exclusively from the actual `MessageEvent.origin`. The RP-facing
request API does not accept an authoritative audience field, and URL/query parameters never define
it.

After strict request validation and visible approval, the wallet signs with `aud = event.origin` and
responds only through `event.source.postMessage(result, event.origin)`. Wildcard proof/secret
responses are forbidden. The consent UI displays the requesting origin, selected local identity
label, action, resource, and any cross-scope reuse warning.

## Consequences

- Proofs cannot be replayed at another exact origin when RPs verify `aud` correctly.
- The wallet must run at a dedicated origin and keep popup/opener behavior compatible with its
  security headers.
- Cross-origin identity reuse is visible and explicit.
- The RP never receives the wallet's full local identity list.

## Compliance

Two-origin browser E2E covers fake audiences, cross-origin replay, exact-target responses, popup
cancellation/closure, required user approval, scoped identity isolation, and absence of key material
in network payloads.
