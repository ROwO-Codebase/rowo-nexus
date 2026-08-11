# ADR-0009: Historical Timestamps Require Trusted Receipts

- Status: Accepted
- Date: 2026-08-11
- Scope: ownership proofs, RP resource receipts, registry/notary receipts, backup restore

## Context

After a private key is stolen or restored from an old backup, its holder can create a valid
signature containing an arbitrary backdated `iat`. Cryptography proves key possession, not that the
self-asserted timestamp is truthful.

## Decision

Historical authorship or acceptance time requires a trusted receipt/timestamp issued before
revocation by a relying party, the Nexus registry, or a reviewed digest-only notary. A self-signed
ownership proof establishes only its cryptographic statements, subject to current lifecycle and
challenge checks; its `iat` alone is not trusted historical evidence.

RPs needing durable authorship issue a signed artifact acceptance receipt at resource creation and
retain the accepted proof hash/content hash. Registry receipts provide trusted service time for
registration/revocation events. The optional notary accepts only a digest and reveals no content or
subject.

## Consequences

- Restored old keys cannot manufacture accepted pre-revocation history merely by backdating a proof.
- Current-control and historical-authorship policies remain explicit and separate.
- Key compromise does not erase valid trusted receipts issued before the compromise/revocation
  interval, but service-key incidents may affect their trust assessment.
- Backup design must document this limitation prominently.

## Compliance

Tests reject historical-policy reliance on user `iat` alone, verify receipt signatures/`kid` history
and content/proof hashes, and demonstrate that post-revocation signatures cannot create new accepted
historical artifacts.
