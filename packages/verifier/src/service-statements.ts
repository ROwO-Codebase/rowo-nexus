import { getDefaultCryptoProvider } from '@nexus/crypto';
import {
  REGISTRY_RECEIPT_PROTOCOL_V1,
  DEVICE_REGISTRY_RECEIPT_PROTOCOL_V2,
  DEVICE_STATUS_STATEMENT_PROTOCOL_V2,
  STATUS_STATEMENT_PROTOCOL_V1,
  decodeBase64UrlExact,
  registryReceiptV1Schema,
  deviceRegistryReceiptV2Schema,
  deviceStatusStatementV2Schema,
  serviceKeySetSchema,
  statusStatementV1Schema,
} from '@nexus/protocol';
import type {
  Ed25519PublicJwk,
  DeviceRegistryReceiptV2,
  DeviceStatusStatementV2,
  RegistryReceiptV1,
  ServiceKeySet,
  StatusStatementV1,
} from '@nexus/protocol';

import { rethrowVerificationErrorV2, verificationError, verificationErrorV2 } from './errors.js';
import { assertNonNegativeInteger, parseExternal, verifyPayloadSignature } from './internal.js';
import type {
  DeviceStatusStatementExpectation,
  DeviceRegistryReceiptExpectation,
  RegistryReceiptExpectation,
  StatusStatementExpectation,
} from './types.js';

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

/** Verifies a service-signed v2 device activation or revocation receipt. */
async function verifyDeviceRegistryReceiptInternal(
  receipt: unknown,
  keyset: unknown,
  expected: DeviceRegistryReceiptExpectation = {},
): Promise<DeviceRegistryReceiptV2> {
  const parsed = parseExternal(deviceRegistryReceiptV2Schema, receipt, {
    protocols: [
      {
        path: ['payload', 'protocol'],
        expected: DEVICE_REGISTRY_RECEIPT_PROTOCOL_V2,
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

  if (expected.eventId !== undefined && parsed.payload.eventId !== expected.eventId) {
    throw verificationErrorV2('WRONG_EVENT_ID');
  }
  if (expected.operationId !== undefined && parsed.payload.operationId !== expected.operationId) {
    throw verificationErrorV2('WRONG_OPERATION');
  }
  if (expected.subject !== undefined && parsed.payload.subject !== expected.subject) {
    throw verificationError('INVALID_SUBJECT');
  }
  if (expected.genesisHash !== undefined && parsed.payload.genesisHash !== expected.genesisHash) {
    throw verificationError('WRONG_GENESIS_HASH');
  }
  if (expected.eventType !== undefined && parsed.payload.eventType !== expected.eventType) {
    throw verificationError('WRONG_EVENT_TYPE');
  }
  if (
    expected.identityState !== undefined &&
    parsed.payload.identityState !== expected.identityState
  ) {
    throw verificationError('WRONG_STATE');
  }
  if (
    expected.identitySequence !== undefined &&
    parsed.payload.identitySequence !== expected.identitySequence
  ) {
    throw verificationError('SEQUENCE_CONFLICT');
  }
  if (
    expected.deviceLedgerSequence !== undefined &&
    parsed.payload.deviceLedgerSequence !== expected.deviceLedgerSequence
  ) {
    throw verificationError('SEQUENCE_CONFLICT');
  }
  if (expected.deviceId !== undefined && parsed.payload.deviceId !== expected.deviceId) {
    throw verificationErrorV2('WRONG_DEVICE');
  }
  if (
    expected.authorizationId !== undefined &&
    parsed.payload.authorizationId !== expected.authorizationId
  ) {
    throw verificationErrorV2('WRONG_AUTHORIZATION');
  }
  if (expected.deviceState !== undefined && parsed.payload.deviceState !== expected.deviceState) {
    throw verificationError('WRONG_STATE');
  }
  if (
    expected.authorizationExpiresAt !== undefined &&
    parsed.payload.authorizationExpiresAt !== expected.authorizationExpiresAt
  ) {
    throw verificationErrorV2('WRONG_AUTHORIZATION');
  }
  if (expected.acceptedAt !== undefined && parsed.payload.acceptedAt !== expected.acceptedAt) {
    throw verificationError('WRONG_STATE');
  }
  if (expected.revokedBy !== undefined && parsed.payload.revokedBy !== expected.revokedBy) {
    throw verificationError('WRONG_STATE');
  }

  return parsed;
}

export async function verifyDeviceRegistryReceipt(
  receipt: unknown,
  keyset: unknown,
  expected: DeviceRegistryReceiptExpectation = {},
): Promise<DeviceRegistryReceiptV2> {
  try {
    return await verifyDeviceRegistryReceiptInternal(receipt, keyset, expected);
  } catch (error) {
    rethrowVerificationErrorV2(error);
  }
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

/** Verifies a service-signed combined identity/device lifecycle statement. */
async function verifyDeviceStatusStatementInternal(
  statement: unknown,
  keyset: unknown,
  now: number,
  expected: DeviceStatusStatementExpectation = {},
): Promise<DeviceStatusStatementV2> {
  const parsed = parseExternal(deviceStatusStatementV2Schema, statement, {
    protocols: [
      {
        path: ['payload', 'protocol'],
        expected: DEVICE_STATUS_STATEMENT_PROTOCOL_V2,
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
  if (now > parsed.payload.exp) throw verificationError('PROOF_EXPIRED');
  if (
    parsed.payload.deviceState === 'active' &&
    parsed.payload.authorizationExpiresAt !== undefined &&
    now >= parsed.payload.authorizationExpiresAt
  ) {
    throw verificationErrorV2('DEVICE_EXPIRED');
  }

  if (expected.subject !== undefined && parsed.payload.subject !== expected.subject) {
    throw verificationError('INVALID_SUBJECT');
  }
  if (expected.genesisHash !== undefined && parsed.payload.genesisHash !== expected.genesisHash) {
    throw verificationError('WRONG_GENESIS_HASH');
  }
  if (expected.deviceId !== undefined && parsed.payload.deviceId !== expected.deviceId) {
    throw verificationErrorV2('WRONG_DEVICE');
  }
  if (
    expected.authorizationId !== undefined &&
    parsed.payload.authorizationId !== expected.authorizationId
  ) {
    throw verificationErrorV2('WRONG_AUTHORIZATION');
  }
  if (
    expected.identityState !== undefined &&
    parsed.payload.identityState !== expected.identityState
  ) {
    throw verificationError('WRONG_STATE');
  }
  if (
    expected.identitySequence !== undefined &&
    parsed.payload.identitySequence !== expected.identitySequence
  ) {
    throw verificationError('SEQUENCE_CONFLICT');
  }
  if (
    expected.deviceLedgerSequence !== undefined &&
    parsed.payload.deviceLedgerSequence !== expected.deviceLedgerSequence
  ) {
    throw verificationError('SEQUENCE_CONFLICT');
  }
  if (expected.deviceState !== undefined && parsed.payload.deviceState !== expected.deviceState) {
    throw verificationError('WRONG_STATE');
  }
  if (
    expected.authorizationExpiresAt !== undefined &&
    parsed.payload.authorizationExpiresAt !== expected.authorizationExpiresAt
  ) {
    throw verificationErrorV2('WRONG_AUTHORIZATION');
  }

  return parsed;
}

export async function verifyDeviceStatusStatement(
  statement: unknown,
  keyset: unknown,
  now: number,
  expected: DeviceStatusStatementExpectation = {},
): Promise<DeviceStatusStatementV2> {
  try {
    return await verifyDeviceStatusStatementInternal(statement, keyset, now, expected);
  } catch (error) {
    rethrowVerificationErrorV2(error);
  }
}
