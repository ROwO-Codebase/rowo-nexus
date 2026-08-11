import type { OwnershipProofV1, VerificationExpectation, VerifiedSubject } from '@nexus/protocol';

import { verificationError } from './errors.js';
import { verifyOwnershipProof } from './ownership.js';
import type { ChallengeStore, LifecycleProvider } from './types.js';

/**
 * Complete online RP authorization verification. Unlike verifyOwnershipProof,
 * this helper explicitly checks authoritative lifecycle state and atomically
 * consumes the backend-issued challenge.
 */
export async function verifyRpOperation(
  proof: OwnershipProofV1,
  expected: VerificationExpectation,
  challengeStore: ChallengeStore,
  lifecycle: LifecycleProvider,
): Promise<VerifiedSubject> {
  const verified = await verifyOwnershipProof(proof, expected);

  const challenge = await challengeStore.get(expected.nonce);
  if (
    challenge === null ||
    challenge.consumed ||
    challenge.nonce !== expected.nonce ||
    challenge.action !== expected.action ||
    challenge.resource !== expected.resource ||
    expected.now > challenge.expiresAt
  ) {
    throw verificationError('NONCE_REPLAY_OR_EXPIRED');
  }

  const status = await lifecycle.getAuthoritativeStatus(verified.subject);
  if (status.state === 'not-found') {
    throw verificationError('IDENTITY_NOT_FOUND');
  }
  if (status.state !== 'active') {
    throw verificationError('IDENTITY_REVOKED');
  }

  const consumed = await challengeStore.consumeAtomically(expected.nonce);
  if (!consumed) throw verificationError('NONCE_REPLAY_OR_EXPIRED');
  return verified;
}
