import { NexusVerificationError } from '@nexus/verifier';

export type RpErrorCode =
  | 'BAD_REQUEST'
  | 'NOT_FOUND'
  | 'CHALLENGE_EXPIRED'
  | 'CHALLENGE_MISMATCH'
  | 'AUTHOR_MISMATCH'
  | 'OPERATION_NOT_ALLOWED'
  | 'NAME_TAKEN'
  | 'VERSION_CONFLICT'
  | 'SESSION_INVALID'
  | 'INTERNAL_ERROR';

export class RpError extends Error {
  public constructor(
    public readonly code: RpErrorCode,
    message: string,
    public readonly status: number,
  ) {
    super(message);
    this.name = 'RpError';
  }
}

export interface SafeApiError {
  status: number;
  code: string;
  message: string;
}

const VERIFICATION_MESSAGES: Readonly<Record<string, string>> = {
  NONCE_REPLAY_OR_EXPIRED: 'This proof challenge has expired or was already used.',
  WRONG_AUDIENCE: 'The proof was issued for a different relying-party origin.',
  WRONG_ACTION: 'The proof does not authorize this action.',
  WRONG_RESOURCE: 'The proof does not authorize this note.',
  WRONG_NONCE: 'The proof does not match this one-time challenge.',
  IDENTITY_REVOKED: 'This Nexus identity is revoked and cannot change notes.',
  IDENTITY_NOT_FOUND: 'This Nexus identity is not active in the authoritative registry.',
  INVALID_SIGNATURE: 'The wallet proof signature is invalid.',
  INVALID_SUBJECT: 'The proof subject does not match its public identity document.',
};

export function toSafeApiError(error: unknown): SafeApiError {
  if (error instanceof RpError) {
    return { status: error.status, code: error.code, message: error.message };
  }
  if (error instanceof NexusVerificationError) {
    return {
      status: 403,
      code: error.code,
      message: VERIFICATION_MESSAGES[error.code] ?? 'The Nexus proof was rejected.',
    };
  }
  return {
    status: 500,
    code: 'INTERNAL_ERROR',
    message: 'The demo service could not complete the request.',
  };
}
