import {
  IDENTITY_PROTOCOL_V1,
  NEXUS_SUITE_V1,
  OWNERSHIP_PROOF_PROTOCOL_V1,
  ownershipProofV1Schema,
  verificationExpectationSchema,
} from '@nexus/protocol';
import type { OwnershipProofV1, VerificationExpectation, VerifiedSubject } from '@nexus/protocol';

import { verificationError } from './errors.js';
import {
  importIdentitySigningKey,
  parseExternal,
  validateExpiringWindow,
  verifyParsedSubject,
  verifyPayloadSignature,
} from './internal.js';
import { MAX_SIGNED_OBJECT_LIFETIME_SECONDS } from './types.js';

function parseOwnershipProof(value: unknown): OwnershipProofV1 {
  return parseExternal(ownershipProofV1Schema, value, {
    protocols: [
      {
        path: ['payload', 'protocol'],
        expected: OWNERSHIP_PROOF_PROTOCOL_V1,
      },
      {
        path: ['payload', 'genesis', 'protocol'],
        expected: IDENTITY_PROTOCOL_V1,
      },
    ],
    suites: [
      {
        path: ['payload', 'genesis', 'suite'],
        expected: NEXUS_SUITE_V1,
      },
    ],
  });
}

function parseExpectation(value: unknown): VerificationExpectation {
  return parseExternal(verificationExpectationSchema, value);
}

export async function verifyOwnershipProof(
  proof: unknown,
  expected: unknown,
): Promise<VerifiedSubject> {
  const parsed = parseOwnershipProof(proof);
  const expectation = parseExpectation(expected);
  const verifiedSubject = await verifyParsedSubject(parsed.payload.genesis, parsed.payload.subject);

  if (parsed.payload.aud !== expectation.audience) {
    throw verificationError('WRONG_AUDIENCE');
  }
  if (parsed.payload.act !== expectation.action) {
    throw verificationError('WRONG_ACTION');
  }
  if (parsed.payload.resource !== expectation.resource) {
    throw verificationError('WRONG_RESOURCE');
  }
  if (parsed.payload.nonce !== expectation.nonce) {
    throw verificationError('WRONG_NONCE');
  }

  validateExpiringWindow(
    parsed.payload.iat,
    parsed.payload.exp,
    expectation.now,
    expectation.maxClockSkewSeconds,
    MAX_SIGNED_OBJECT_LIFETIME_SECONDS,
  );

  const publicKey = await importIdentitySigningKey(parsed.payload.genesis);
  await verifyPayloadSignature(parsed.payload, parsed.signature, publicKey);
  return verifiedSubject;
}
