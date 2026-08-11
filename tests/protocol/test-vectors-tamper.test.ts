import { readFile } from 'node:fs/promises';

import { deriveRegistryEventId } from '../../packages/crypto/dist/index.js';
import {
  canonicalize,
  continuityLinkV1Schema,
  decodeBase64Url,
  encodeBase64Url,
  identityGenesisV1Schema,
  ownershipProofV1Schema,
  registryEventWithoutEventIdV1Schema,
  registryReceiptV1Schema,
  revokeBySignatureRequestV1Schema,
  serviceKeySetSchema,
  signedGlobalTransparencyCheckpointV1Schema,
  signedTransparencyCheckpointV1Schema,
  statusStatementV1Schema,
  transparencyInclusionProofV1Schema,
} from '../../packages/protocol/dist/index.js';
import type {
  Base64Url32,
  Base64UrlAtLeast16,
  NexusSubject,
  OwnershipProofV1,
  VerificationExpectation,
} from '../../packages/protocol/dist/index.js';
import {
  verifyAuthenticatedInclusionProof,
  verifyContinuityLink,
  verifyGlobalTransparencyCheckpoint,
  verifyOwnershipProof,
  verifyRegistryReceipt,
  verifyRevocationSecret,
  verifyRevokeBySignature,
  verifyStatusStatement,
  verifyTransparencyCheckpoint,
} from '../../packages/verifier/dist/index.js';
import { describe, expect, it } from 'vitest';

interface JsonObject {
  readonly [key: string]: unknown;
}

const vectorDirectory = new URL('../../packages/test-vectors/vectors/', import.meta.url);

function object(value: unknown): JsonObject {
  if (value === null || Array.isArray(value) || typeof value !== 'object') {
    throw new TypeError('Expected a JSON object.');
  }
  return value as JsonObject;
}

async function vector(name: string): Promise<JsonObject> {
  return object(JSON.parse(await readFile(new URL(name, vectorDirectory), 'utf8')));
}

function alterBase64Url<T extends string>(value: T): T {
  return `${value[0] === 'A' ? 'B' : 'A'}${value.slice(1)}` as T;
}

function ownershipExpectation(proof: OwnershipProofV1): VerificationExpectation {
  return {
    audience: proof.payload.aud,
    action: proof.payload.act,
    resource: proof.payload.resource,
    nonce: proof.payload.nonce,
    now: proof.payload.iat,
    maxClockSkewSeconds: 0,
  };
}

describe('ownership proof vector tamper resistance', () => {
  it('accepts the committed proof', async () => {
    const proofVector = await vector('ownership-proof.json');
    const proof = ownershipProofV1Schema.parse(proofVector.proof);
    await expect(verifyOwnershipProof(proof, ownershipExpectation(proof))).resolves.toMatchObject({
      subject: proof.payload.subject,
    });
  });

  it('rejects altered action and resource despite matching caller expectations', async () => {
    const proofVector = await vector('ownership-proof.json');
    const proof = ownershipProofV1Schema.parse(proofVector.proof);

    const actionTamper = structuredClone(proof);
    actionTamper.payload.act = 'resource.delete';
    await expect(
      verifyOwnershipProof(actionTamper, ownershipExpectation(actionTamper)),
    ).rejects.toThrow();

    const resourceTamper = structuredClone(proof);
    resourceTamper.payload.resource = 'urn:example:resource:beta';
    await expect(
      verifyOwnershipProof(resourceTamper, ownershipExpectation(resourceTamper)),
    ).rejects.toThrow();
  });

  it('rejects altered genesis or public key under the original subject', async () => {
    const [proofVector, keysVector] = await Promise.all([
      vector('ownership-proof.json'),
      vector('keys.json'),
    ]);
    const proof = ownershipProofV1Schema.parse(proofVector.proof);
    const fixtures = keysVector.fixtures;
    if (!Array.isArray(fixtures)) throw new TypeError('Expected key fixtures.');
    const identityB = object(fixtures[1]);
    const replacementPublicKey = identityB.publicKeyBase64Url;
    if (typeof replacementPublicKey !== 'string') throw new TypeError('Expected public key.');

    const tampered = structuredClone(proof) as unknown as JsonObject;
    const payload = object(tampered.payload);
    const genesis = object(payload.genesis);
    const signingKey = object(genesis.signingKey);
    (signingKey as { publicKey: string }).publicKey = replacementPublicKey;

    await expect(verifyOwnershipProof(tampered, ownershipExpectation(proof))).rejects.toThrow();
  });

  it('rejects audience mismatch, expiry, and a future proof beyond skew', async () => {
    const proofVector = await vector('ownership-proof.json');
    const proof = ownershipProofV1Schema.parse(proofVector.proof);
    const expected = ownershipExpectation(proof);

    await expect(
      verifyOwnershipProof(proof, { ...expected, audience: 'https://other.example' }),
    ).rejects.toThrow();
    await expect(
      verifyOwnershipProof(proof, { ...expected, now: proof.payload.exp + 1 }),
    ).rejects.toThrow();
    await expect(
      verifyOwnershipProof(proof, { ...expected, now: proof.payload.iat - 1 }),
    ).rejects.toThrow();
  });

  it('rejects invalid signatures, malformed base64url, and padding', async () => {
    const proofVector = await vector('ownership-proof.json');
    const proof = ownershipProofV1Schema.parse(proofVector.proof);

    const invalidSignature = structuredClone(proof);
    invalidSignature.signature = alterBase64Url(invalidSignature.signature);
    await expect(
      verifyOwnershipProof(invalidSignature, ownershipExpectation(proof)),
    ).rejects.toThrow();

    await expect(
      verifyOwnershipProof(
        { ...proof, signature: `${proof.signature}=` },
        ownershipExpectation(proof),
      ),
    ).rejects.toThrow();

    await expect(
      verifyOwnershipProof(
        {
          ...proof,
          payload: { ...proof.payload, nonce: 'not+base64url' },
        },
        ownershipExpectation(proof),
      ),
    ).rejects.toThrow();
  });

  it('fails closed for unknown protocol versions and crypto suites', async () => {
    const proofVector = await vector('ownership-proof.json');
    const proof = ownershipProofV1Schema.parse(proofVector.proof);

    await expect(
      verifyOwnershipProof(
        { ...proof, payload: { ...proof.payload, protocol: 'nexus.ownership-proof.v2' } },
        ownershipExpectation(proof),
      ),
    ).rejects.toThrow();
    await expect(
      verifyOwnershipProof(
        {
          ...proof,
          payload: {
            ...proof.payload,
            genesis: { ...proof.payload.genesis, suite: 'NX-UNKNOWN-v9' },
          },
        },
        ownershipExpectation(proof),
      ),
    ).rejects.toThrow();
  });
});

describe('service statement vectors', () => {
  it('rejects tampered Registry Receipt payloads and signatures', async () => {
    const receiptVector = await vector('registry-receipt.json');
    const receipt = registryReceiptV1Schema.parse(receiptVector.receipt);
    const keyset = serviceKeySetSchema.parse(receiptVector.keyset);

    await expect(verifyRegistryReceipt(receipt, keyset)).resolves.toEqual(receipt);

    const payloadTamper = structuredClone(receipt);
    payloadTamper.payload.acceptedAt += 1;
    await expect(verifyRegistryReceipt(payloadTamper, keyset)).rejects.toThrow();

    const signatureTamper = structuredClone(receipt);
    signatureTamper.signature = alterBase64Url(signatureTamper.signature);
    await expect(verifyRegistryReceipt(signatureTamper, keyset)).rejects.toThrow();
  });

  it('rejects tampered or expired Status Statements', async () => {
    const statusVector = await vector('status-statement.json');
    const statement = statusStatementV1Schema.parse(statusVector.statement);
    const keyset = serviceKeySetSchema.parse(statusVector.keyset);

    await expect(verifyStatusStatement(statement, keyset, statement.payload.iat)).resolves.toEqual(
      statement,
    );
    await expect(
      verifyStatusStatement(statement, keyset, statement.payload.exp + 1),
    ).rejects.toThrow();

    const tampered = structuredClone(statement);
    tampered.payload.exp += 1;
    await expect(verifyStatusStatement(tampered, keyset, tampered.payload.iat)).rejects.toThrow();
  });
});

describe('revocation vectors', () => {
  it('rejects tampered signing-key revocations', async () => {
    const revokeVector = await vector('signing-key-revoke.json');
    const request = revokeBySignatureRequestV1Schema.parse(revokeVector.request);
    const genesis = identityGenesisV1Schema.parse(revokeVector.genesis);
    const expected = object(revokeVector.verification);
    const verification = {
      subject: expected.subject as NexusSubject,
      expectedSequence: expected.expectedSequence as number,
      nonce: expected.nonce as Base64UrlAtLeast16,
      now: expected.now as number,
      maxClockSkewSeconds: expected.maxClockSkewSeconds as number,
    };

    await expect(verifyRevokeBySignature(request, genesis, verification)).resolves.toMatchObject({
      subject: verification.subject,
    });

    const tampered = structuredClone(request);
    tampered.payload.expectedSequence = 1;
    await expect(
      verifyRevokeBySignature(tampered, genesis, {
        ...verification,
        expectedSequence: 1,
      }),
    ).rejects.toThrow();
  });

  it('rejects a wrong revocation secret and stale sequence', async () => {
    const [identityVector, revocationVector] = await Promise.all([
      vector('identity.json'),
      vector('revocation-commitment.json'),
    ]);
    const genesis = identityGenesisV1Schema.parse(identityVector.genesis);
    const subject = identityVector.subject as NexusSubject;
    const secretHex = revocationVector.secretHex;
    if (typeof secretHex !== 'string') throw new TypeError('Expected revocation secret.');
    const secretBytes = Uint8Array.from(secretHex.match(/.{2}/gu) ?? [], (byte) =>
      Number.parseInt(byte, 16),
    );
    const validSecret = encodeBase64Url(secretBytes) as Base64Url32;
    const validRequest = {
      mode: 'secret',
      payload: {
        protocol: 'nexus.revoke-secret.v1',
        subject,
        expectedSequence: 0,
        revocationSecret: validSecret,
      },
    };

    await expect(
      verifyRevocationSecret(validRequest, genesis, { subject, expectedSequence: 0 }),
    ).resolves.toMatchObject({ subject });

    await expect(
      verifyRevocationSecret(
        {
          ...validRequest,
          payload: {
            ...validRequest.payload,
            revocationSecret: alterBase64Url(validSecret),
          },
        },
        genesis,
        { subject, expectedSequence: 0 },
      ),
    ).rejects.toThrow();

    await expect(
      verifyRevocationSecret(validRequest, genesis, { subject, expectedSequence: 1 }),
    ).rejects.toThrow();
  });
});

describe('continuity and registry event vectors', () => {
  it('requires both continuity-link signatures over one identical payload', async () => {
    const linkVector = await vector('continuity-link.json');
    const link = continuityLinkV1Schema.parse(linkVector.link);
    const rawExpected = object(linkVector.verification);
    const expected = {
      subjectA: rawExpected.subjectA as NexusSubject,
      subjectB: rawExpected.subjectB as NexusSubject,
      scope: rawExpected.scope as string,
      nonce: rawExpected.nonce as Base64UrlAtLeast16,
      now: rawExpected.now as number,
      maxClockSkewSeconds: rawExpected.maxClockSkewSeconds as number,
    };

    await expect(verifyContinuityLink(link, expected)).resolves.toEqual(link);

    const badA = structuredClone(link);
    badA.signatureA = alterBase64Url(badA.signatureA);
    await expect(verifyContinuityLink(badA, expected)).rejects.toThrow();

    const badB = structuredClone(link);
    badB.signatureB = alterBase64Url(badB.signatureB);
    await expect(verifyContinuityLink(badB, expected)).rejects.toThrow();

    const payloadTamper = structuredClone(link);
    payloadTamper.payload.scope = 'rp.example:other-scope';
    await expect(
      verifyContinuityLink(payloadTamper, {
        ...expected,
        scope: payloadTamper.payload.scope,
      }),
    ).rejects.toThrow();
  });

  it('changes the Registry Event hash and ID when the event is altered', async () => {
    const eventVector = await vector('registry-event.json');
    const event = registryEventWithoutEventIdV1Schema.parse(eventVector.eventWithoutEventId);
    const original = await deriveRegistryEventId(event);
    const tampered = structuredClone(event);
    tampered.acceptedAt += 1;
    const altered = await deriveRegistryEventId(tampered);
    expect(altered.eventId).not.toBe(original.eventId);
    expect(Array.from(altered.eventHash)).not.toEqual(Array.from(original.eventHash));
  });
});

describe('authenticated transparency vectors', () => {
  it('verifies the shard checkpoint, global manifest, and composed inclusion proof', async () => {
    const transparencyVector = await vector('transparency.json');
    const checkpointVector = object(transparencyVector.checkpoint);
    const globalVector = object(transparencyVector.globalCheckpoint);
    const checkpoint = signedTransparencyCheckpointV1Schema.parse(checkpointVector.signed);
    const globalCheckpoint = signedGlobalTransparencyCheckpointV1Schema.parse(globalVector.signed);
    const proof = transparencyInclusionProofV1Schema.parse(transparencyVector.inclusionProof);
    const keyset = serviceKeySetSchema.parse(transparencyVector.keyset);
    const checkpointExpected = {
      now: checkpoint.payload.checkpointedAt,
      maxAgeSeconds: 60,
      maxClockSkewSeconds: 0,
      signerKid: checkpoint.payload.signerKid,
      shardId: checkpoint.payload.shardId,
      treeSize: checkpoint.payload.treeSize,
      rootHash: checkpoint.payload.rootHash,
    };
    const inclusionExpected = {
      ...checkpointExpected,
      eventHash: proof.eventHash,
    };

    await expect(
      verifyTransparencyCheckpoint(checkpoint, keyset, checkpointExpected),
    ).resolves.toEqual(checkpoint);
    await expect(
      verifyGlobalTransparencyCheckpoint(globalCheckpoint, keyset, {
        now: globalCheckpoint.payload.checkpointedAt,
        maxAgeSeconds: 60,
        maxClockSkewSeconds: 0,
        signerKid: globalCheckpoint.payload.signerKid,
        shards: globalCheckpoint.payload.shards,
      }),
    ).resolves.toEqual(globalCheckpoint);
    await expect(
      verifyAuthenticatedInclusionProof(proof, keyset, inclusionExpected),
    ).resolves.toEqual(proof);
  });

  it('rejects wrong kids and altered checkpoint/global signatures', async () => {
    const transparencyVector = await vector('transparency.json');
    const checkpoint = signedTransparencyCheckpointV1Schema.parse(
      object(transparencyVector.checkpoint).signed,
    );
    const globalCheckpoint = signedGlobalTransparencyCheckpointV1Schema.parse(
      object(transparencyVector.globalCheckpoint).signed,
    );
    const keyset = serviceKeySetSchema.parse(transparencyVector.keyset);
    const expected = {
      now: checkpoint.payload.checkpointedAt,
      maxAgeSeconds: 60,
      maxClockSkewSeconds: 0,
      signerKid: checkpoint.payload.signerKid,
    };

    await expect(
      verifyTransparencyCheckpoint(checkpoint, keyset, {
        ...expected,
        signerKid: 'wrong-transparency-kid',
      }),
    ).rejects.toThrow();

    const badCheckpointSignature = structuredClone(checkpoint);
    badCheckpointSignature.signature = alterBase64Url(badCheckpointSignature.signature);
    await expect(
      verifyTransparencyCheckpoint(badCheckpointSignature, keyset, expected),
    ).rejects.toThrow();

    const badGlobalSignature = structuredClone(globalCheckpoint);
    badGlobalSignature.signature = alterBase64Url(badGlobalSignature.signature);
    await expect(
      verifyGlobalTransparencyCheckpoint(badGlobalSignature, keyset, {
        ...expected,
        now: globalCheckpoint.payload.checkpointedAt,
      }),
    ).rejects.toThrow();
  });

  it('rejects wrong roots, shards, and inclusion audit paths', async () => {
    const transparencyVector = await vector('transparency.json');
    const checkpoint = signedTransparencyCheckpointV1Schema.parse(
      object(transparencyVector.checkpoint).signed,
    );
    const globalCheckpoint = signedGlobalTransparencyCheckpointV1Schema.parse(
      object(transparencyVector.globalCheckpoint).signed,
    );
    const proof = transparencyInclusionProofV1Schema.parse(transparencyVector.inclusionProof);
    const keyset = serviceKeySetSchema.parse(transparencyVector.keyset);
    const expected = {
      now: checkpoint.payload.checkpointedAt,
      maxAgeSeconds: 60,
      maxClockSkewSeconds: 0,
      signerKid: checkpoint.payload.signerKid,
      eventHash: proof.eventHash,
      shardId: proof.shardId,
      treeSize: proof.treeSize,
      rootHash: checkpoint.payload.rootHash,
    };

    await expect(
      verifyAuthenticatedInclusionProof(proof, keyset, {
        ...expected,
        rootHash: alterBase64Url(expected.rootHash),
      }),
    ).rejects.toThrow();
    await expect(
      verifyAuthenticatedInclusionProof(proof, keyset, {
        ...expected,
        shardId: proof.shardId === 'ff' ? 'fe' : 'ff',
      }),
    ).rejects.toThrow();

    const pathTamper = structuredClone(proof);
    const firstPathNode = pathTamper.auditPath[0];
    if (firstPathNode === undefined) throw new TypeError('Expected an audit path node.');
    pathTamper.auditPath[0] = alterBase64Url(firstPathNode);
    await expect(verifyAuthenticatedInclusionProof(pathTamper, keyset, expected)).rejects.toThrow();

    const expectedShards = structuredClone(globalCheckpoint.payload.shards);
    const targetShard = expectedShards.find((shard) => shard.shardId === proof.shardId);
    if (targetShard === undefined) throw new TypeError('Expected the target shard.');
    targetShard.rootHash = alterBase64Url(targetShard.rootHash);
    await expect(
      verifyGlobalTransparencyCheckpoint(globalCheckpoint, keyset, {
        now: globalCheckpoint.payload.checkpointedAt,
        maxAgeSeconds: 60,
        maxClockSkewSeconds: 0,
        signerKid: globalCheckpoint.payload.signerKid,
        shards: expectedShards,
      }),
    ).rejects.toThrow();
  });
});

describe('base64url and JCS edge vectors', () => {
  it('rejects every committed non-canonical base64url encoding', async () => {
    const encodingVector = await vector('base64url.json');
    if (!Array.isArray(encodingVector.invalid)) throw new TypeError('Expected invalid cases.');
    for (const rawCase of encodingVector.invalid) {
      const testCase = object(rawCase);
      expect(() => decodeBase64Url(testCase.value as string)).toThrow();
    }
  });

  it('rejects lone Unicode surrogates from the committed JCS edge set', async () => {
    const jcsVector = await vector('canonicalization.json');
    if (!Array.isArray(jcsVector.rejectedJsonLiterals)) {
      throw new TypeError('Expected rejected JCS cases.');
    }
    for (const rawCase of jcsVector.rejectedJsonLiterals) {
      const testCase = object(rawCase);
      expect(() => canonicalize(JSON.parse(testCase.json as string))).toThrow();
    }
  });
});
