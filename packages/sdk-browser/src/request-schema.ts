import { proofRequestSchema, type ProofRequest } from '@nexus/protocol';

const MAX_CHALLENGE_LIFETIME_SECONDS = 120;

export class ProofRequestValidationError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = 'ProofRequestValidationError';
  }
}

export function parseProofRequest(value: unknown, nowSeconds: number): ProofRequest {
  const parsed = proofRequestSchema.safeParse(value);
  if (!parsed.success) throw invalid('request does not match the strict ProofRequest schema');

  if (parsed.data.expiresAt <= nowSeconds) throw invalid('challenge has expired');
  if (parsed.data.expiresAt > nowSeconds + MAX_CHALLENGE_LIFETIME_SECONDS) {
    throw invalid('challenge lifetime exceeds 120 seconds');
  }

  return parsed.data;
}

function invalid(message: string): ProofRequestValidationError {
  return new ProofRequestValidationError(message);
}
