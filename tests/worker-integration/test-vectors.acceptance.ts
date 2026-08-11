import { describe, expect, it } from 'vitest';

import {
  computeRevocationCommitment,
  deriveGenesisHash,
  deriveRegistryEventId,
  deriveSubject,
} from '@nexus/crypto';
import {
  canonicalize,
  continuityLinkV1Schema,
  decodeBase64Url,
  encodeBase64Url,
  identityGenesisV1Schema,
  ownershipProofV1Schema,
  registryEventV1Schema,
  registryEventWithoutEventIdV1Schema,
  registryReceiptV1Schema,
  revokeBySignatureRequestV1Schema,
  serviceKeySetSchema,
  signedGlobalTransparencyCheckpointV1Schema,
  signedTransparencyCheckpointV1Schema,
  statusStatementV1Schema,
  transparencyInclusionProofV1Schema,
} from '@nexus/protocol';
import { ED25519_FIXTURES, FIXTURE_WARNING, bytesFromHex, bytesToHex } from '@nexus/test-vectors';
import {
  verifyAuthenticatedInclusionProof,
  verifyContinuityLink,
  verifyGlobalTransparencyCheckpoint,
  verifyOwnershipProof,
  verifyRegistryReceipt,
  verifyRevokeBySignature,
  verifyStatusStatement,
  verifyTransparencyCheckpoint,
} from '@nexus/verifier';

import base64url from '../../packages/test-vectors/vectors/base64url.json';
import canonicalization from '../../packages/test-vectors/vectors/canonicalization.json';
import continuityLink from '../../packages/test-vectors/vectors/continuity-link.json';
import identity from '../../packages/test-vectors/vectors/identity.json';
import keys from '../../packages/test-vectors/vectors/keys.json';
import ownershipProof from '../../packages/test-vectors/vectors/ownership-proof.json';
import registryEvent from '../../packages/test-vectors/vectors/registry-event.json';
import registryReceipt from '../../packages/test-vectors/vectors/registry-receipt.json';
import revocationCommitment from '../../packages/test-vectors/vectors/revocation-commitment.json';
import signingKeyRevoke from '../../packages/test-vectors/vectors/signing-key-revoke.json';
import statusStatement from '../../packages/test-vectors/vectors/status-statement.json';
import transparency from '../../packages/test-vectors/vectors/transparency.json';

const committed = new Map<string, unknown>([
  ['base64url.json', base64url],
  ['canonicalization.json', canonicalization],
  ['continuity-link.json', continuityLink],
  ['identity.json', identity],
  ['keys.json', keys],
  ['ownership-proof.json', ownershipProof],
  ['registry-event.json', registryEvent],
  ['registry-receipt.json', registryReceipt],
  ['revocation-commitment.json', revocationCommitment],
  ['signing-key-revoke.json', signingKeyRevoke],
  ['status-statement.json', statusStatement],
  ['transparency.json', transparency],
]);

describe('committed cryptographic vectors in the Workers runtime', () => {
  it('reproduces every committed vector byte-value and verifies representative signed objects', async () => {
    expect(keys.warning).toBe(FIXTURE_WARNING);
    expect(committed.size).toBe(12);
    for (const [name, vector] of committed) {
      expect(vector, name).toMatchObject({ schema: 'nexus.test-vectors.v1' });
    }

    for (const testCase of base64url.valid) {
      expect(encodeBase64Url(bytesFromHex(testCase.hex))).toBe(testCase.base64url);
      expect(bytesToHex(decodeBase64Url(testCase.base64url))).toBe(testCase.hex);
    }
    for (const testCase of canonicalization.cases) {
      expect(canonicalize(testCase.value)).toBe(testCase.canonicalJcs);
    }
    expect(keys.fixtures.map((fixture) => fixture.publicKeyHex)).toEqual(
      Object.values(ED25519_FIXTURES).map((fixture) => fixture.publicKeyHex),
    );

    const commitment = await computeRevocationCommitment(
      bytesFromHex(revocationCommitment.secretHex),
    );
    expect(bytesToHex(commitment)).toBe(revocationCommitment.commitmentHex);
    expect(encodeBase64Url(commitment)).toBe(revocationCommitment.commitmentBase64Url);

    const genesis = identityGenesisV1Schema.parse(identity.genesis);
    expect(await deriveSubject(genesis)).toBe(identity.subject);
    expect(encodeBase64Url(await deriveGenesisHash(genesis))).toBe(identity.genesisHashBase64Url);

    const proof = ownershipProofV1Schema.parse(ownershipProof.proof);
    await expect(
      verifyOwnershipProof(proof, {
        audience: proof.payload.aud,
        action: proof.payload.act,
        resource: proof.payload.resource,
        nonce: proof.payload.nonce,
        now: proof.payload.iat,
        maxClockSkewSeconds: 0,
      }),
    ).resolves.toMatchObject({ subject: proof.payload.subject });

    const eventWithoutId = registryEventWithoutEventIdV1Schema.parse(
      registryEvent.eventWithoutEventId,
    );
    const event = registryEventV1Schema.parse(registryEvent.event);
    await expect(deriveRegistryEventId(eventWithoutId)).resolves.toMatchObject({
      eventId: event.eventId,
    });

    const receipt = registryReceiptV1Schema.parse(registryReceipt.receipt);
    await expect(
      verifyRegistryReceipt(receipt, serviceKeySetSchema.parse(registryReceipt.keyset), {
        subject: receipt.payload.subject,
        genesisHash: receipt.payload.genesisHash,
        eventType: receipt.payload.eventType,
        sequence: receipt.payload.sequence,
        state: receipt.payload.state,
      }),
    ).resolves.toEqual(receipt);

    const statement = statusStatementV1Schema.parse(statusStatement.statement);
    await expect(
      verifyStatusStatement(
        statement,
        serviceKeySetSchema.parse(statusStatement.keyset),
        statusStatement.verificationTime,
        { subject: statement.payload.subject, maxClockSkewSeconds: 0 },
      ),
    ).resolves.toEqual(statement);

    const revokeRequest = revokeBySignatureRequestV1Schema.parse(signingKeyRevoke.request);
    const revokeVerification = signingKeyRevoke.verification;
    await expect(
      verifyRevokeBySignature(
        revokeRequest,
        identityGenesisV1Schema.parse(signingKeyRevoke.genesis),
        {
          subject: revokeRequest.payload.subject,
          expectedSequence: revokeVerification.expectedSequence,
          nonce: revokeRequest.payload.nonce,
          now: revokeVerification.now,
          maxClockSkewSeconds: revokeVerification.maxClockSkewSeconds,
        },
      ),
    ).resolves.toMatchObject({ subject: revokeRequest.payload.subject });

    const link = continuityLinkV1Schema.parse(continuityLink.link);
    await expect(
      verifyContinuityLink(link, {
        subjectA: link.payload.subjectA,
        subjectB: link.payload.subjectB,
        ...(link.payload.scope === undefined ? {} : { scope: link.payload.scope }),
        nonce: link.payload.nonce,
        now: link.payload.iat,
        maxClockSkewSeconds: 0,
      }),
    ).resolves.toEqual(link);

    const transparencyKeyset = serviceKeySetSchema.parse(transparency.keyset);
    const checkpoint = signedTransparencyCheckpointV1Schema.parse(transparency.checkpoint.signed);
    await expect(
      verifyTransparencyCheckpoint(
        checkpoint,
        transparencyKeyset,
        transparency.verification.checkpoint,
      ),
    ).resolves.toEqual(checkpoint);

    const globalCheckpoint = signedGlobalTransparencyCheckpointV1Schema.parse(
      transparency.globalCheckpoint.signed,
    );
    await expect(
      verifyGlobalTransparencyCheckpoint(
        globalCheckpoint,
        transparencyKeyset,
        transparency.verification.globalCheckpoint,
      ),
    ).resolves.toEqual(globalCheckpoint);

    const inclusionProof = transparencyInclusionProofV1Schema.parse(transparency.inclusionProof);
    await expect(
      verifyAuthenticatedInclusionProof(
        inclusionProof,
        transparencyKeyset,
        transparency.verification.inclusion,
      ),
    ).resolves.toEqual(inclusionProof);
  });
});
