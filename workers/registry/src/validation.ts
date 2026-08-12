import {
  IDENTITY_PROTOCOL_V1,
  NEXUS_SUITE_V1,
  base64Url64Schema,
  canonicalize,
  decodeBase64UrlExact,
  deviceActivationRequestV2Schema,
  deviceRootRevokeRequestV2Schema,
  deviceSelfRevokeRequestV2Schema,
  encodeBase64Url,
  identityGenesisV1Schema,
  nexusSubjectSchema,
  nexusDeviceAuthorizationIdV2Schema,
  nexusDeviceIdV2Schema,
  revokeBySecretV1Schema,
  revokeBySignaturePayloadV1Schema,
} from '@nexus/protocol';
import type {
  DeviceActivationRequestV2,
  DeviceRootRevokeRequestV2,
  DeviceSelfRevokeRequestV2,
  RevokeBySecretV1,
  RevokeBySignaturePayloadV1,
} from '@nexus/protocol';
import { deriveGenesisHash, deriveSubject } from '@nexus/crypto';

import { fail, succeed } from './errors';
import type {
  PreparedRegistration,
  DeviceStatusCommand,
  RegisterCommand,
  RegistryResult,
  RevokeBySignatureCommand,
} from './types';

function isExactRecord(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

export async function prepareRegistration(
  value: unknown,
): Promise<RegistryResult<PreparedRegistration>> {
  if (!isExactRecord(value, ['genesis', 'subject'])) {
    return fail('BAD_REQUEST');
  }

  const rawGenesis = value.genesis;
  if (typeof rawGenesis === 'object' && rawGenesis !== null) {
    const genesisRecord = rawGenesis as Record<string, unknown>;
    const protocol = genesisRecord.protocol;
    if (typeof protocol === 'string' && protocol !== IDENTITY_PROTOCOL_V1) {
      return fail('UNSUPPORTED_PROTOCOL');
    }
    const suite = genesisRecord.suite;
    if (typeof suite === 'string' && suite !== NEXUS_SUITE_V1) {
      return fail('UNSUPPORTED_SUITE');
    }
  }

  const subjectResult = nexusSubjectSchema.safeParse(value.subject);
  const genesisResult = identityGenesisV1Schema.safeParse(rawGenesis);
  if (!subjectResult.success || !genesisResult.success) {
    return fail('BAD_REQUEST');
  }

  const genesis = genesisResult.data;
  const computedSubject = await deriveSubject(genesis);
  if (computedSubject !== subjectResult.data) {
    return fail('INVALID_SUBJECT');
  }

  const genesisHashBytes = await deriveGenesisHash(genesis);
  return succeed({
    subject: computedSubject,
    genesis,
    genesisJcs: canonicalize(genesis),
    genesisHash: encodeBase64Url(genesisHashBytes) as PreparedRegistration['genesisHash'],
    genesisHashBytes,
    signingPublicKey: decodeBase64UrlExact(genesis.signingKey.publicKey, 32),
    agreementPublicKey:
      genesis.agreementKey === undefined
        ? null
        : decodeBase64UrlExact(genesis.agreementKey.publicKey, 32),
    revocationCommitment: decodeBase64UrlExact(genesis.revocationCommitment, 32),
  });
}

export function parseSignatureCommand(value: unknown): RegistryResult<RevokeBySignatureCommand> {
  if (!isExactRecord(value, ['payload', 'signature'])) {
    return fail('BAD_REQUEST');
  }
  const payload = revokeBySignaturePayloadV1Schema.safeParse(value.payload);
  const signature = base64Url64Schema.safeParse(value.signature);
  if (!payload.success || !signature.success) {
    return fail('BAD_REQUEST');
  }
  return succeed({ payload: payload.data, signature: signature.data });
}

export function parseSecretCommand(value: unknown): RegistryResult<RevokeBySecretV1> {
  const result = revokeBySecretV1Schema.safeParse(value);
  return result.success ? succeed(result.data) : fail('BAD_REQUEST');
}

export function parseStatusSubject(value: unknown): RegistryResult<string> {
  const result = nexusSubjectSchema.safeParse(value);
  return result.success ? succeed(result.data) : fail('INVALID_SUBJECT');
}

export function parseDeviceActivationCommand(
  value: unknown,
): RegistryResult<DeviceActivationRequestV2> {
  const result = deviceActivationRequestV2Schema.safeParse(value);
  return result.success ? succeed(result.data) : fail('BAD_REQUEST');
}

export function parseDeviceSelfRevokeCommand(
  value: unknown,
): RegistryResult<DeviceSelfRevokeRequestV2> {
  const result = deviceSelfRevokeRequestV2Schema.safeParse(value);
  return result.success ? succeed(result.data) : fail('BAD_REQUEST');
}

export function parseDeviceRootRevokeCommand(
  value: unknown,
): RegistryResult<DeviceRootRevokeRequestV2> {
  const result = deviceRootRevokeRequestV2Schema.safeParse(value);
  return result.success ? succeed(result.data) : fail('BAD_REQUEST');
}

export function parseDeviceStatusCommand(value: unknown): RegistryResult<DeviceStatusCommand> {
  if (!isExactRecord(value, ['authorizationId', 'deviceId', 'subject'])) {
    return fail('BAD_REQUEST');
  }
  const subject = nexusSubjectSchema.safeParse(value.subject);
  const deviceId = nexusDeviceIdV2Schema.safeParse(value.deviceId);
  const authorizationId = nexusDeviceAuthorizationIdV2Schema.safeParse(value.authorizationId);
  if (!subject.success || !deviceId.success || !authorizationId.success) {
    return fail('BAD_REQUEST');
  }
  return succeed({
    subject: subject.data,
    deviceId: deviceId.data,
    authorizationId: authorizationId.data,
  });
}

export function assertPreparedRegistration(
  input: PreparedRegistration,
): Promise<RegistryResult<PreparedRegistration>> {
  const command: RegisterCommand = { subject: input.subject, genesis: input.genesis };
  return prepareRegistration(command);
}

export type ParsedSignaturePayload = RevokeBySignaturePayloadV1;
