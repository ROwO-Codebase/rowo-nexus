/** Stable v1 verifier error surface. Keep this list closed for compatibility. */
export const NEXUS_VERIFICATION_ERROR_CODES = [
  'BAD_REQUEST',
  'UNSUPPORTED_PROTOCOL',
  'UNSUPPORTED_SUITE',
  'INVALID_SUBJECT',
  'INVALID_SIGNATURE',
  'INVALID_REVOCATION_SECRET',
  'WRONG_AUDIENCE',
  'WRONG_ACTION',
  'WRONG_RESOURCE',
  'WRONG_NONCE',
  'SEQUENCE_CONFLICT',
  'PROOF_NOT_YET_VALID',
  'PROOF_EXPIRED',
  'PROOF_LIFETIME_EXCEEDED',
  'NONCE_REPLAY_OR_EXPIRED',
  'IDENTITY_NOT_FOUND',
  'IDENTITY_REVOKED',
  'KEY_NOT_FOUND',
  'INVALID_KEY',
  'KEY_PURPOSE_MISMATCH',
  'WRONG_EVENT_TYPE',
  'WRONG_STATE',
  'WRONG_GENESIS_HASH',
  'WRONG_SCOPE',
  'WRONG_SHARD',
  'WRONG_ROOT',
  'WRONG_TREE_SIZE',
  'WRONG_MANIFEST',
  'WRONG_EVENT_HASH',
  'INVALID_INCLUSION_PROOF',
] as const;

export type NexusVerificationErrorCode = (typeof NEXUS_VERIFICATION_ERROR_CODES)[number];

const V2_ONLY_VERIFICATION_ERROR_CODES = [
  'WRONG_CONTEXT',
  'DEVICE_NOT_FOUND',
  'DEVICE_REVOKED',
  'DEVICE_EXPIRED',
  'WRONG_DEVICE',
  'WRONG_AUTHORIZATION',
  'WRONG_EVENT_ID',
  'WRONG_OPERATION',
] as const;

/** Additive v2 verifier error surface; the legacy list above remains unchanged. */
export const NEXUS_VERIFICATION_ERROR_CODES_V2 = [
  ...NEXUS_VERIFICATION_ERROR_CODES,
  ...V2_ONLY_VERIFICATION_ERROR_CODES,
] as const;

export type NexusVerificationErrorCodeV2 = (typeof NEXUS_VERIFICATION_ERROR_CODES_V2)[number];

const ERROR_MESSAGES: Readonly<Record<NexusVerificationErrorCode, string>> = {
  BAD_REQUEST: 'The verification input is malformed.',
  UNSUPPORTED_PROTOCOL: 'The protocol version is not supported.',
  UNSUPPORTED_SUITE: 'The cryptographic suite is not supported.',
  INVALID_SUBJECT: 'The subject does not match its genesis document.',
  INVALID_SIGNATURE: 'The signature is invalid.',
  INVALID_REVOCATION_SECRET: 'The revocation credential is invalid.',
  WRONG_AUDIENCE: 'The proof audience does not match.',
  WRONG_ACTION: 'The proof action does not match.',
  WRONG_RESOURCE: 'The proof resource does not match.',
  WRONG_NONCE: 'The nonce does not match.',
  SEQUENCE_CONFLICT: 'The lifecycle sequence does not match.',
  PROOF_NOT_YET_VALID: 'The signed object is not yet valid.',
  PROOF_EXPIRED: 'The signed object has expired.',
  PROOF_LIFETIME_EXCEEDED: 'The signed object lifetime is too long.',
  NONCE_REPLAY_OR_EXPIRED: 'The challenge is missing, expired, or already consumed.',
  IDENTITY_NOT_FOUND: 'The identity was not found in authoritative lifecycle state.',
  IDENTITY_REVOKED: 'The identity is revoked.',
  KEY_NOT_FOUND: 'The referenced verification key was not found.',
  INVALID_KEY: 'The referenced verification key is invalid.',
  KEY_PURPOSE_MISMATCH: 'The verification key has the wrong purpose.',
  WRONG_EVENT_TYPE: 'The registry event type does not match.',
  WRONG_STATE: 'The lifecycle state does not match.',
  WRONG_GENESIS_HASH: 'The genesis hash does not match.',
  WRONG_SCOPE: 'The continuity scope does not match.',
  WRONG_SHARD: 'The transparency shard does not match.',
  WRONG_ROOT: 'The transparency root does not match.',
  WRONG_TREE_SIZE: 'The transparency tree size does not match.',
  WRONG_MANIFEST: 'The transparency manifest does not match.',
  WRONG_EVENT_HASH: 'The transparency event hash does not match.',
  INVALID_INCLUSION_PROOF: 'The transparency inclusion proof is invalid.',
};

const V2_ERROR_MESSAGES: Readonly<Record<NexusVerificationErrorCodeV2, string>> = {
  ...ERROR_MESSAGES,
  WRONG_CONTEXT: 'The proof context binding does not match.',
  DEVICE_NOT_FOUND: 'The device authorization was not found in authoritative lifecycle state.',
  DEVICE_REVOKED: 'The device authorization is revoked.',
  DEVICE_EXPIRED: 'The device authorization has expired.',
  WRONG_DEVICE: 'The device identifier does not match.',
  WRONG_AUTHORIZATION: 'The device authorization does not match.',
  WRONG_EVENT_ID: 'The registry event identifier does not match.',
  WRONG_OPERATION: 'The registry operation identifier does not match.',
};

const V2_LEGACY_CODE: Readonly<Record<NexusVerificationErrorCodeV2, NexusVerificationErrorCode>> = {
  BAD_REQUEST: 'BAD_REQUEST',
  UNSUPPORTED_PROTOCOL: 'UNSUPPORTED_PROTOCOL',
  UNSUPPORTED_SUITE: 'UNSUPPORTED_SUITE',
  INVALID_SUBJECT: 'INVALID_SUBJECT',
  INVALID_SIGNATURE: 'INVALID_SIGNATURE',
  INVALID_REVOCATION_SECRET: 'INVALID_REVOCATION_SECRET',
  WRONG_AUDIENCE: 'WRONG_AUDIENCE',
  WRONG_ACTION: 'WRONG_ACTION',
  WRONG_RESOURCE: 'WRONG_RESOURCE',
  WRONG_NONCE: 'WRONG_NONCE',
  SEQUENCE_CONFLICT: 'SEQUENCE_CONFLICT',
  PROOF_NOT_YET_VALID: 'PROOF_NOT_YET_VALID',
  PROOF_EXPIRED: 'PROOF_EXPIRED',
  PROOF_LIFETIME_EXCEEDED: 'PROOF_LIFETIME_EXCEEDED',
  NONCE_REPLAY_OR_EXPIRED: 'NONCE_REPLAY_OR_EXPIRED',
  IDENTITY_NOT_FOUND: 'IDENTITY_NOT_FOUND',
  IDENTITY_REVOKED: 'IDENTITY_REVOKED',
  KEY_NOT_FOUND: 'KEY_NOT_FOUND',
  INVALID_KEY: 'INVALID_KEY',
  KEY_PURPOSE_MISMATCH: 'KEY_PURPOSE_MISMATCH',
  WRONG_EVENT_TYPE: 'WRONG_EVENT_TYPE',
  WRONG_STATE: 'WRONG_STATE',
  WRONG_GENESIS_HASH: 'WRONG_GENESIS_HASH',
  WRONG_SCOPE: 'WRONG_SCOPE',
  WRONG_SHARD: 'WRONG_SHARD',
  WRONG_ROOT: 'WRONG_ROOT',
  WRONG_TREE_SIZE: 'WRONG_TREE_SIZE',
  WRONG_MANIFEST: 'WRONG_MANIFEST',
  WRONG_EVENT_HASH: 'WRONG_EVENT_HASH',
  INVALID_INCLUSION_PROOF: 'INVALID_INCLUSION_PROOF',
  WRONG_CONTEXT: 'WRONG_NONCE',
  DEVICE_NOT_FOUND: 'IDENTITY_NOT_FOUND',
  DEVICE_REVOKED: 'IDENTITY_REVOKED',
  DEVICE_EXPIRED: 'PROOF_EXPIRED',
  WRONG_DEVICE: 'INVALID_SUBJECT',
  WRONG_AUTHORIZATION: 'BAD_REQUEST',
  WRONG_EVENT_ID: 'WRONG_EVENT_HASH',
  WRONG_OPERATION: 'WRONG_EVENT_HASH',
};

export class NexusVerificationError extends Error {
  readonly code: NexusVerificationErrorCode;

  constructor(code: NexusVerificationErrorCode, message = ERROR_MESSAGES[code]) {
    super(message);
    this.name = 'NexusVerificationError';
    this.code = code;
  }
}

/**
 * Additive v2 error. `codeV2` is exact; inherited `code` is a stable legacy
 * category so existing `instanceof NexusVerificationError` handlers remain useful.
 */
export class NexusVerificationErrorV2 extends NexusVerificationError {
  readonly codeV2: NexusVerificationErrorCodeV2;

  constructor(codeV2: NexusVerificationErrorCodeV2, message = V2_ERROR_MESSAGES[codeV2]) {
    super(V2_LEGACY_CODE[codeV2], message);
    this.name = 'NexusVerificationErrorV2';
    this.codeV2 = codeV2;
  }
}

export function verificationError(code: NexusVerificationErrorCode): NexusVerificationError {
  return new NexusVerificationError(code);
}

export function verificationErrorV2(code: NexusVerificationErrorCodeV2): NexusVerificationErrorV2 {
  return new NexusVerificationErrorV2(code);
}

export function rethrowVerificationErrorV2(error: unknown): never {
  if (error instanceof NexusVerificationErrorV2) throw error;
  if (error instanceof NexusVerificationError) {
    throw new NexusVerificationErrorV2(error.code, error.message);
  }
  throw error;
}
