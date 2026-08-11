import { NexusVerificationError } from '@nexus/verifier';

export type RpWorkerErrorCode =
  | 'BAD_REQUEST'
  | 'NOT_FOUND'
  | 'CHALLENGE_EXPIRED'
  | 'CHALLENGE_MISMATCH'
  | 'AUTHOR_MISMATCH'
  | 'OPERATION_NOT_ALLOWED'
  | 'VERSION_CONFLICT'
  | 'SESSION_INVALID'
  | 'IDENTITY_NOT_FOUND'
  | 'IDENTITY_REVOKED'
  | 'RATE_LIMITED'
  | 'SERVICE_UNAVAILABLE'
  | 'INTERNAL_ERROR';

export class RpWorkerError extends Error {
  public constructor(
    public readonly code: RpWorkerErrorCode,
    message: string,
    public readonly status: number,
  ) {
    super(message);
    this.name = 'RpWorkerError';
  }
}

export interface SafeWorkerError {
  readonly code: string;
  readonly message: string;
  readonly status: number;
}

const VERIFICATION_MESSAGES: Readonly<Record<string, string>> = Object.freeze({
  WRONG_AUDIENCE: 'The proof was issued for a different relying-party origin.',
  WRONG_ACTION: 'The proof does not authorize this action.',
  WRONG_RESOURCE: 'The proof does not authorize this note.',
  WRONG_NONCE: 'The proof does not match this one-time challenge.',
  IDENTITY_REVOKED: 'This Nexus identity is revoked and cannot change notes.',
  IDENTITY_NOT_FOUND: 'This Nexus identity is not active in the authoritative registry.',
  INVALID_SIGNATURE: 'The wallet proof signature is invalid.',
  INVALID_SUBJECT: 'The proof subject does not match its public identity document.',
  PROOF_NOT_YET_VALID: 'The proof is not valid yet.',
  PROOF_EXPIRED: 'The proof has expired.',
  PROOF_LIFETIME_EXCEEDED: 'The proof lifetime is too long.',
});

export function toSafeWorkerError(error: unknown): SafeWorkerError {
  if (error instanceof RpWorkerError) {
    return { code: error.code, message: error.message, status: error.status };
  }
  if (error instanceof NexusVerificationError) {
    return {
      code: error.code,
      message: VERIFICATION_MESSAGES[error.code] ?? 'The Nexus proof was rejected.',
      status: 403,
    };
  }
  return {
    code: 'INTERNAL_ERROR',
    message: 'The demo service could not complete the request.',
    status: 500,
  };
}
