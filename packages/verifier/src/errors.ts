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

export class NexusVerificationError extends Error {
  readonly code: NexusVerificationErrorCode;

  constructor(code: NexusVerificationErrorCode, message = ERROR_MESSAGES[code]) {
    super(message);
    this.name = 'NexusVerificationError';
    this.code = code;
  }
}

export function verificationError(code: NexusVerificationErrorCode): NexusVerificationError {
  return new NexusVerificationError(code);
}
