import { getDefaultCryptoProvider } from '@nexus/crypto';
import {
  REGISTRY_RECEIPT_PROTOCOL_V1,
  STATUS_STATEMENT_PROTOCOL_V1,
  decodeBase64UrlExact,
  registryReceiptV1Schema,
  serviceKeySetSchema,
  statusStatementV1Schema,
} from '@nexus/protocol';
import type {
  Ed25519PublicJwk,
  RegistryReceiptV1,
  ServiceKeySet,
  StatusStatementV1,
} from '@nexus/protocol';

import { verificationError } from './errors.js';
import { assertNonNegativeInteger, parseExternal, verifyPayloadSignature } from './internal.js';
import type { RegistryReceiptExpectation, StatusStatementExpectation } from './types.js';

export function parseServiceKeyset(value: unknown): ServiceKeySet {
  const result = serviceKeySetSchema.safeParse(value);
  if (result.success) return result.data;

  // The strict schema runs first; this only classifies a standard JWK `use`
  // mismatch into the stable verifier error expected by callers.
  if (typeof value === 'object' && value !== null && 'keys' in value) {
    const keys = Reflect.get(value, 'keys');
    if (
      Array.isArray(keys) &&
      keys.some(
        (key) =>
          typeof key === 'object' &&
          key !== null &&
          'use' in key &&
          Reflect.get(key, 'use') !== 'sig',
      )
    ) {
      throw verificationError('KEY_PURPOSE_MISMATCH');
    }
  }

  return parseExternal(serviceKeySetSchema, value);
}

function findSigningKey(keyset: ServiceKeySet, signerKid: string): Ed25519PublicJwk {
  const matching = keyset.keys.filter((candidate) => candidate.kid === signerKid);
  if (matching.length === 0) throw verificationError('KEY_NOT_FOUND');
  if (matching.length !== 1) throw verificationError('INVALID_KEY');

  const key = matching[0];
  if (key === undefined) throw verificationError('KEY_NOT_FOUND');
  if (key.use !== undefined && key.use !== 'sig') {
    throw verificationError('KEY_PURPOSE_MISMATCH');
  }
  return key;
}

export async function verifyServiceSignature<T extends { protocol: string }>(
  payload: T,
  signature: string,
  signerKid: string,
  keyset: ServiceKeySet,
): Promise<void> {
  const jwk = findSigningKey(keyset, signerKid);
  const raw = decodeBase64UrlExact(jwk.x, 32);

  let publicKey: CryptoKey;
  try {
    publicKey = await getDefaultCryptoProvider().importEd25519PublicKey(raw);
  } catch {
    throw verificationError('INVALID_KEY');
  }

  await verifyPayloadSignature(payload, signature, publicKey);
}

export async function verifyRegistryReceipt(
  receipt: unknown,
  keyset: unknown,
  expected: RegistryReceiptExpectation = {},
): Promise<RegistryReceiptV1> {
  const parsed = parseExternal(registryReceiptV1Schema, receipt, {
    protocols: [
      {
        path: ['payload', 'protocol'],
        expected: REGISTRY_RECEIPT_PROTOCOL_V1,
      },
    ],
  });
  const parsedKeyset = parseServiceKeyset(keyset);

  await verifyServiceSignature(
    parsed.payload,
    parsed.signature,
    parsed.payload.signerKid,
    parsedKeyset,
  );

  if (expected.subject !== undefined && parsed.payload.subject !== expected.subject) {
    throw verificationError('INVALID_SUBJECT');
  }
  if (expected.genesisHash !== undefined && parsed.payload.genesisHash !== expected.genesisHash) {
    throw verificationError('WRONG_GENESIS_HASH');
  }
  if (expected.eventType !== undefined && parsed.payload.eventType !== expected.eventType) {
    throw verificationError('WRONG_EVENT_TYPE');
  }
  if (expected.sequence !== undefined && parsed.payload.sequence !== expected.sequence) {
    throw verificationError('SEQUENCE_CONFLICT');
  }
  if (expected.state !== undefined && parsed.payload.state !== expected.state) {
    throw verificationError('WRONG_STATE');
  }

  return parsed;
}

export async function verifyStatusStatement(
  statement: unknown,
  keyset: unknown,
  now: number,
  expected: StatusStatementExpectation = {},
): Promise<StatusStatementV1> {
  const parsed = parseExternal(statusStatementV1Schema, statement, {
    protocols: [
      {
        path: ['payload', 'protocol'],
        expected: STATUS_STATEMENT_PROTOCOL_V1,
      },
    ],
  });
  const parsedKeyset = parseServiceKeyset(keyset);
  const maxClockSkewSeconds = expected.maxClockSkewSeconds ?? 0;
  assertNonNegativeInteger(now);
  assertNonNegativeInteger(maxClockSkewSeconds);

  await verifyServiceSignature(
    parsed.payload,
    parsed.signature,
    parsed.payload.signerKid,
    parsedKeyset,
  );

  if (parsed.payload.iat > now + maxClockSkewSeconds) {
    throw verificationError('PROOF_NOT_YET_VALID');
  }

  // Status freshness is not extended by proof clock skew: callers MUST enforce exp.
  if (now > parsed.payload.exp) throw verificationError('PROOF_EXPIRED');

  if (expected.subject !== undefined && parsed.payload.subject !== expected.subject) {
    throw verificationError('INVALID_SUBJECT');
  }

  return parsed;
}
