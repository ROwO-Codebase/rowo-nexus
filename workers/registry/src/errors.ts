import type { RegistryErrorCode, RegistryResult } from './types';

const MESSAGES: Readonly<Record<RegistryErrorCode, string>> = {
  BAD_REQUEST: 'The registry request is malformed.',
  UNSUPPORTED_PROTOCOL: 'The protocol version is not supported.',
  UNSUPPORTED_SUITE: 'The cryptographic suite is not supported.',
  INVALID_SUBJECT: 'The subject does not match its genesis document.',
  INVALID_SIGNATURE: 'The revocation signature is invalid.',
  INVALID_REVOCATION_SECRET: 'The revocation secret is invalid.',
  IDENTITY_NOT_FOUND: 'The identity was not found.',
  IDENTITY_REVOKED: 'The identity is revoked.',
  DEVICE_NOT_FOUND: 'The device authorization was not found.',
  DEVICE_REVOKED: 'The device is revoked.',
  DEVICE_AUTHORIZATION_CONFLICT: 'The device is bound to a different authorization.',
  SEQUENCE_CONFLICT: 'The lifecycle sequence does not match.',
  SUBJECT_GENESIS_CONFLICT: 'The subject is bound to different genesis bytes.',
  INTERNAL_ERROR: 'The registry operation failed.',
};

export function fail<T = never>(code: RegistryErrorCode): RegistryResult<T> {
  return { ok: false, error: { code, message: MESSAGES[code] } };
}

export function succeed<T>(value: T): RegistryResult<T> {
  return { ok: true, value };
}
