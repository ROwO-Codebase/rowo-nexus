# ADR-0007: Revocation Before Deletion

- Status: Accepted
- Date: 2026-08-11
- Scope: wallet disposal, registry, relying-party authorization

## Context

Browser and operating-system storage cannot guarantee physical secure deletion, and exported or old
backup copies may survive. Local deletion alone therefore cannot establish that a subject has lost
future control.

## Decision

Disposal is a terminal server-recognized revocation followed by best-effort local crypto-shredding.
The wallet must:

1. clearly confirm the selected identity;
2. submit signing-key or revocation-secret revocation with the expected sequence;
3. verify the signed registry receipt is for that subject and terminal `revoked` state;
4. only then delete local key handles, revocation secret, scopes, and active references where
   possible.

If revocation or receipt verification fails, the wallet must not present disposal as complete.
Current-control authorization always checks sufficiently fresh lifecycle state and rejects revoked
subjects even if an old private key can still make a valid signature.

## Consequences

- Restored/exported keys cannot reactivate a disposed subject.
- Offline signature verification may still succeed after revocation; signature validity and current
  authorization are distinct.
- The user cannot recover or transfer a disposed identity through a new key.
- Minimal signed revocation receipt/history may remain locally if the user chooses.

## Compliance

The disposal acceptance test retains the test private key after revocation, confirms its signatures
remain mathematically valid, and proves authorization still fails. Tests also cover
revocation/receipt failure, idempotent repeated revocation, and attempted `REVOKED -> ACTIVE`.
