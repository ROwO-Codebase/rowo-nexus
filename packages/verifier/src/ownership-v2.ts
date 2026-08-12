import { deriveDeviceAuthorizationIdV2, deriveDeviceIdV2, deriveGenesisHash } from '@nexus/crypto';
import {
  IDENTITY_PROTOCOL_V1,
  NEXUS_SUITE_V1,
  OWNERSHIP_PROOF_PROTOCOL_V1,
  OWNERSHIP_PROOF_PROTOCOL_V2,
  decodeBase64UrlExact,
  encodeBase64Url,
  ownershipProofV1Schema,
  ownershipProofV2Schema,
  verificationExpectationV2Schema,
} from '@nexus/protocol';
import type {
  OwnershipProofV2,
  VerificationExpectation,
  VerificationExpectationV2,
  VerifiedSubject,
} from '@nexus/protocol';

import { rethrowVerificationErrorV2, verificationError, verificationErrorV2 } from './errors.js';
import {
  importEd25519PublicKey,
  importIdentitySigningKey,
  parseExternal,
  validateExpiringWindow,
  verifyParsedSubject,
  verifyPayloadSignature,
} from './internal.js';
import { verifyOwnershipProof } from './ownership.js';
import {
  MAX_SIGNED_OBJECT_LIFETIME_SECONDS,
  type OwnershipProofAnyOptions,
  type VerifiedDeviceSubject,
} from './types.js';

function parseOwnershipProofV2(value: unknown): OwnershipProofV2 {
  return parseExternal(ownershipProofV2Schema, value, {
    protocols: [
      { path: ['payload', 'protocol'], expected: OWNERSHIP_PROOF_PROTOCOL_V2 },
      { path: ['payload', 'genesis', 'protocol'], expected: IDENTITY_PROTOCOL_V1 },
      {
        path: ['payload', 'authorization', 'payload', 'protocol'],
        expected: 'nexus.device-authorization.v2',
      },
    ],
    suites: [{ path: ['payload', 'genesis', 'suite'], expected: NEXUS_SUITE_V1 }],
  });
}

function parseExpectation(value: unknown): VerificationExpectationV2 {
  return parseExternal(verificationExpectationV2Schema, value);
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function readProofProtocol(value: unknown): unknown {
  if (!isRecord(value)) return undefined;
  const payload = value['payload'];
  if (!isRecord(payload)) return undefined;
  return payload['protocol'];
}

function validateDispatcherOptions(value: OwnershipProofAnyOptions): void {
  const acceptedProtocols =
    typeof value === 'object' && value !== null ? value.acceptedProtocols : undefined;
  if (
    typeof value !== 'object' ||
    value === null ||
    Object.keys(value).length !== 1 ||
    !Array.isArray(acceptedProtocols) ||
    acceptedProtocols.length === 0 ||
    acceptedProtocols.length > 2 ||
    new Set<unknown>(acceptedProtocols).size !== acceptedProtocols.length ||
    acceptedProtocols.some(
      (protocol) =>
        protocol !== OWNERSHIP_PROOF_PROTOCOL_V1 && protocol !== OWNERSHIP_PROOF_PROTOCOL_V2,
    )
  ) {
    throw verificationError('BAD_REQUEST');
  }
}

function toV1Expectation(expected: VerificationExpectationV2): VerificationExpectation {
  return {
    audience: expected.audience,
    action: expected.action,
    resource: expected.resource,
    nonce: expected.nonce,
    now: expected.now,
    maxClockSkewSeconds: expected.maxClockSkewSeconds,
  };
}

function verifyContextBinding(
  actual: string | undefined,
  expected: VerificationExpectationV2['contextHash'],
): void {
  if (expected === null ? actual !== undefined : actual !== expected) {
    throw verificationErrorV2('WRONG_CONTEXT');
  }
}

async function verifyOwnershipProofV1WithContext(
  proof: unknown,
  expected: VerificationExpectationV2,
): Promise<VerifiedSubject> {
  const parsed = parseExternal(ownershipProofV1Schema, proof, {
    protocols: [
      { path: ['payload', 'protocol'], expected: OWNERSHIP_PROOF_PROTOCOL_V1 },
      { path: ['payload', 'genesis', 'protocol'], expected: IDENTITY_PROTOCOL_V1 },
    ],
    suites: [{ path: ['payload', 'genesis', 'suite'], expected: NEXUS_SUITE_V1 }],
  });
  verifyContextBinding(parsed.payload.contextHash, expected.contextHash);
  return verifyOwnershipProof(parsed, toV1Expectation(expected));
}

async function verifyOwnershipProofV2Internal(
  proof: unknown,
  expected: VerificationExpectationV2,
): Promise<VerifiedDeviceSubject> {
  const parsed = parseOwnershipProofV2(proof);
  const expectation = parseExpectation(expected);
  const payload = parsed.payload;
  const authorization = payload.authorization.payload;

  const verifiedRoot = await verifyParsedSubject(payload.genesis, payload.subject);
  if (authorization.subject !== payload.subject) throw verificationError('INVALID_SUBJECT');

  const genesisHash = encodeBase64Url(await deriveGenesisHash(payload.genesis));
  if (authorization.genesisHash !== genesisHash) throw verificationError('WRONG_GENESIS_HASH');

  const derivedDeviceId = await deriveDeviceIdV2({
    subject: authorization.subject,
    signingKey: authorization.signingKey,
  });
  if (authorization.deviceId !== derivedDeviceId || payload.deviceId !== derivedDeviceId) {
    throw verificationErrorV2('WRONG_DEVICE');
  }
  if (authorization.signingKey.publicKey === payload.genesis.signingKey.publicKey) {
    throw verificationError('INVALID_KEY');
  }

  const derivedAuthorizationId = await deriveDeviceAuthorizationIdV2(authorization);
  if (payload.authorizationId !== derivedAuthorizationId) {
    throw verificationErrorV2('WRONG_AUTHORIZATION');
  }

  const rootPublicKey = await importIdentitySigningKey(payload.genesis);
  await verifyPayloadSignature(authorization, payload.authorization.rootSignature, rootPublicKey);

  if (payload.iat < authorization.validFrom) throw verificationError('PROOF_NOT_YET_VALID');
  if (payload.exp > authorization.expiresAt) throw verificationErrorV2('DEVICE_EXPIRED');
  if (expectation.now < authorization.validFrom - expectation.maxClockSkewSeconds) {
    throw verificationError('PROOF_NOT_YET_VALID');
  }
  if (expectation.now >= authorization.expiresAt) {
    throw verificationErrorV2('DEVICE_EXPIRED');
  }

  if (payload.aud !== expectation.audience) throw verificationError('WRONG_AUDIENCE');
  if (payload.act !== expectation.action) throw verificationError('WRONG_ACTION');
  if (payload.resource !== expectation.resource) throw verificationError('WRONG_RESOURCE');
  if (payload.nonce !== expectation.nonce) throw verificationError('WRONG_NONCE');
  verifyContextBinding(payload.contextHash, expectation.contextHash);

  validateExpiringWindow(
    payload.iat,
    payload.exp,
    expectation.now,
    expectation.maxClockSkewSeconds,
    MAX_SIGNED_OBJECT_LIFETIME_SECONDS,
  );

  const devicePublicKey = await importEd25519PublicKey(authorization.signingKey.publicKey);
  await verifyPayloadSignature(payload, parsed.deviceSignature, devicePublicKey);

  return {
    protocol: OWNERSHIP_PROOF_PROTOCOL_V2,
    subject: verifiedRoot.subject,
    rootSigningPublicKey: verifiedRoot.signingPublicKey,
    deviceId: derivedDeviceId,
    deviceSigningPublicKey: decodeBase64UrlExact(authorization.signingKey.publicKey, 32),
    authorizationId: derivedAuthorizationId,
  };
}

/** Verifies the complete v1-root -> v2-device -> v2-proof signature chain. */
export async function verifyOwnershipProofV2(
  proof: unknown,
  expected: VerificationExpectationV2,
): Promise<VerifiedDeviceSubject> {
  try {
    return await verifyOwnershipProofV2Internal(proof, expected);
  } catch (error) {
    rethrowVerificationErrorV2(error);
  }
}

/** Explicit version dispatcher. Callers must name every protocol they accept. */
export async function verifyOwnershipProofAny(
  proof: unknown,
  expected: VerificationExpectationV2,
  options: OwnershipProofAnyOptions,
): Promise<VerifiedSubject | VerifiedDeviceSubject> {
  try {
    validateDispatcherOptions(options);
    const protocol = readProofProtocol(proof);
    if (typeof protocol !== 'string') throw verificationError('BAD_REQUEST');
    if (!options.acceptedProtocols.some((accepted) => accepted === protocol)) {
      throw verificationError('UNSUPPORTED_PROTOCOL');
    }

    switch (protocol) {
      case OWNERSHIP_PROOF_PROTOCOL_V1:
        return await verifyOwnershipProofV1WithContext(proof, parseExpectation(expected));
      case OWNERSHIP_PROOF_PROTOCOL_V2:
        return await verifyOwnershipProofV2Internal(proof, expected);
      default:
        throw verificationError('UNSUPPORTED_PROTOCOL');
    }
  } catch (error) {
    rethrowVerificationErrorV2(error);
  }
}
