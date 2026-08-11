import {
  CONTINUITY_LINK_PROTOCOL_V1,
  IDENTITY_PROTOCOL_V1,
  NEXUS_SUITE_V1,
  continuityLinkV1Schema,
} from '@nexus/protocol';
import type { ContinuityLinkV1 } from '@nexus/protocol';

import { verificationError } from './errors.js';
import {
  assertClockInput,
  assertNonNegativeInteger,
  importIdentitySigningKey,
  parseExternal,
  validateExpiringWindow,
  verifyParsedSubject,
  verifyPayloadSignature,
} from './internal.js';
import type { ContinuityLinkExpectation } from './types.js';
import { MAX_SIGNED_OBJECT_LIFETIME_SECONDS } from './types.js';

export async function verifyContinuityLink(
  link: unknown,
  expected: ContinuityLinkExpectation,
): Promise<ContinuityLinkV1> {
  const parsed = parseExternal(continuityLinkV1Schema, link, {
    protocols: [
      {
        path: ['payload', 'protocol'],
        expected: CONTINUITY_LINK_PROTOCOL_V1,
      },
      {
        path: ['payload', 'genesisA', 'protocol'],
        expected: IDENTITY_PROTOCOL_V1,
      },
      {
        path: ['payload', 'genesisB', 'protocol'],
        expected: IDENTITY_PROTOCOL_V1,
      },
    ],
    suites: [
      {
        path: ['payload', 'genesisA', 'suite'],
        expected: NEXUS_SUITE_V1,
      },
      {
        path: ['payload', 'genesisB', 'suite'],
        expected: NEXUS_SUITE_V1,
      },
    ],
  });
  assertClockInput(expected.now, expected.maxClockSkewSeconds);

  await verifyParsedSubject(parsed.payload.genesisA, parsed.payload.subjectA);
  await verifyParsedSubject(parsed.payload.genesisB, parsed.payload.subjectB);

  if (expected.subjectA !== undefined && parsed.payload.subjectA !== expected.subjectA) {
    throw verificationError('INVALID_SUBJECT');
  }
  if (expected.subjectB !== undefined && parsed.payload.subjectB !== expected.subjectB) {
    throw verificationError('INVALID_SUBJECT');
  }
  if (parsed.payload.nonce !== expected.nonce) {
    throw verificationError('WRONG_NONCE');
  }
  if (
    Object.prototype.hasOwnProperty.call(expected, 'scope') &&
    parsed.payload.scope !== expected.scope
  ) {
    throw verificationError('WRONG_SCOPE');
  }

  if (parsed.payload.iat > expected.now + expected.maxClockSkewSeconds) {
    throw verificationError('PROOF_NOT_YET_VALID');
  }
  if (parsed.payload.exp !== undefined) {
    const maxLifetime = expected.maxLifetimeSeconds ?? MAX_SIGNED_OBJECT_LIFETIME_SECONDS;
    assertNonNegativeInteger(maxLifetime);
    validateExpiringWindow(
      parsed.payload.iat,
      parsed.payload.exp,
      expected.now,
      expected.maxClockSkewSeconds,
      maxLifetime,
    );
  }

  const [publicKeyA, publicKeyB] = await Promise.all([
    importIdentitySigningKey(parsed.payload.genesisA),
    importIdentitySigningKey(parsed.payload.genesisB),
  ]);

  // Both keys verify signatures over the exact same parsed payload object.
  await verifyPayloadSignature(parsed.payload, parsed.signatureA, publicKeyA);
  await verifyPayloadSignature(parsed.payload, parsed.signatureB, publicKeyB);
  return parsed;
}
