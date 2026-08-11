import {
  IDENTITY_PROTOCOL_V1,
  NEXUS_SUITE_V1,
  REVOKE_PROTOCOL_V1,
  REVOKE_SECRET_PROTOCOL_V1,
  decodeBase64UrlExact,
  revokeBySecretRequestV1Schema,
  revokeBySignatureRequestV1Schema,
} from '@nexus/protocol';
import type {
  IdentityGenesisV1,
  RevokeBySecretRequestV1,
  RevokeBySignatureRequestV1,
  VerifiedSubject,
} from '@nexus/protocol';
import { computeRevocationCommitment, constantTimeEqual } from '@nexus/crypto';

import { verificationError } from './errors.js';
import {
  assertClockInput,
  assertNonNegativeInteger,
  importIdentitySigningKey,
  parseExternal,
  parseGenesis,
  validateIssuedAt,
  verifyParsedSubject,
  verifyPayloadSignature,
} from './internal.js';
import type { RevokeBySecretExpectation, RevokeBySignatureExpectation } from './types.js';
import { MAX_SIGNED_OBJECT_LIFETIME_SECONDS } from './types.js';

function parseSignatureRequest(value: unknown): RevokeBySignatureRequestV1 {
  return parseExternal(revokeBySignatureRequestV1Schema, value, {
    protocols: [{ path: ['payload', 'protocol'], expected: REVOKE_PROTOCOL_V1 }],
  });
}

function parseSecretRequest(value: unknown): RevokeBySecretRequestV1 {
  return parseExternal(revokeBySecretRequestV1Schema, value, {
    protocols: [
      {
        path: ['payload', 'protocol'],
        expected: REVOKE_SECRET_PROTOCOL_V1,
      },
    ],
  });
}

function parseIdentityGenesis(value: unknown): IdentityGenesisV1 {
  return parseGenesis(value, IDENTITY_PROTOCOL_V1, NEXUS_SUITE_V1);
}

export async function verifyRevokeBySignature(
  request: unknown,
  genesis: unknown,
  expected: RevokeBySignatureExpectation,
): Promise<VerifiedSubject> {
  const parsed = parseSignatureRequest(request);
  const parsedGenesis = parseIdentityGenesis(genesis);
  assertClockInput(expected.now, expected.maxClockSkewSeconds);
  assertNonNegativeInteger(expected.expectedSequence);

  const verifiedSubject = await verifyParsedSubject(parsedGenesis, parsed.payload.subject);

  if (parsed.payload.subject !== expected.subject) {
    throw verificationError('INVALID_SUBJECT');
  }
  if (parsed.payload.expectedSequence !== expected.expectedSequence) {
    throw verificationError('SEQUENCE_CONFLICT');
  }
  if (parsed.payload.nonce !== expected.nonce) {
    throw verificationError('WRONG_NONCE');
  }

  validateIssuedAt(
    parsed.payload.iat,
    expected.now,
    expected.maxClockSkewSeconds,
    expected.maxAgeSeconds ?? MAX_SIGNED_OBJECT_LIFETIME_SECONDS,
  );

  const publicKey = await importIdentitySigningKey(parsedGenesis);
  await verifyPayloadSignature(parsed.payload, parsed.signature, publicKey);
  return verifiedSubject;
}

export async function verifyRevocationSecret(
  request: unknown,
  genesis: unknown,
  expected: RevokeBySecretExpectation,
): Promise<VerifiedSubject> {
  const parsed = parseSecretRequest(request);
  const parsedGenesis = parseIdentityGenesis(genesis);
  assertNonNegativeInteger(expected.expectedSequence);

  const verifiedSubject = await verifyParsedSubject(parsedGenesis, parsed.payload.subject);

  if (parsed.payload.subject !== expected.subject) {
    throw verificationError('INVALID_SUBJECT');
  }
  if (parsed.payload.expectedSequence !== expected.expectedSequence) {
    throw verificationError('SEQUENCE_CONFLICT');
  }

  const suppliedSecret = decodeBase64UrlExact(parsed.payload.revocationSecret, 32);
  const suppliedCommitment = await computeRevocationCommitment(suppliedSecret);
  const expectedCommitment = decodeBase64UrlExact(parsedGenesis.revocationCommitment, 32);

  if (!constantTimeEqual(suppliedCommitment, expectedCommitment)) {
    throw verificationError('INVALID_REVOCATION_SECRET');
  }

  return verifiedSubject;
}
