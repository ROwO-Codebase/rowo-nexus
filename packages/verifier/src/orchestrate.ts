import type {
  OwnershipProofV1,
  OwnershipProofV2,
  VerificationExpectation,
  VerificationExpectationV2,
  VerifiedSubject,
} from '@nexus/protocol';

import { rethrowVerificationErrorV2, verificationError, verificationErrorV2 } from './errors.js';
import { verifyOwnershipProof } from './ownership.js';
import { verifyOwnershipProofV2 } from './ownership-v2.js';
import type {
  ChallengeStore,
  DeviceLifecycleProvider,
  LifecycleProvider,
  VerifiedDeviceSubject,
} from './types.js';

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

/**
 * Complete online authorization for a root-authorized v2 device. Both the
 * identity and the exact device authorization must remain authoritative.
 */
async function verifyRpOperationV2Internal(
  proof: OwnershipProofV2,
  expected: VerificationExpectationV2,
  challengeStore: ChallengeStore,
  lifecycle: LifecycleProvider,
  deviceLifecycle: DeviceLifecycleProvider,
): Promise<VerifiedDeviceSubject> {
  const verified = await verifyOwnershipProofV2(proof, expected);

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

  const identityStatus = await lifecycle.getAuthoritativeStatus(verified.subject);
  if (identityStatus.state === 'not-found') throw verificationError('IDENTITY_NOT_FOUND');
  if (identityStatus.state !== 'active') throw verificationError('IDENTITY_REVOKED');

  const deviceStatus = await deviceLifecycle.getAuthoritativeDeviceStatus(
    verified.subject,
    verified.deviceId,
    verified.authorizationId,
  );
  if (deviceStatus.state === 'not-found') throw verificationErrorV2('DEVICE_NOT_FOUND');
  // The device status response is a combined snapshot. Requiring its identity
  // component prevents an independently fetched stale v1-active result from
  // overriding a current terminal identity revocation.
  if (deviceStatus.identityState !== 'active') throw verificationError('IDENTITY_REVOKED');
  if (deviceStatus.deviceId !== verified.deviceId) throw verificationErrorV2('WRONG_DEVICE');
  if (deviceStatus.authorizationId !== verified.authorizationId) {
    throw verificationErrorV2('WRONG_AUTHORIZATION');
  }
  if (deviceStatus.state === 'revoked') throw verificationErrorV2('DEVICE_REVOKED');
  if (
    deviceStatus.state === 'expired' ||
    (deviceStatus.authorizationExpiresAt !== undefined &&
      expected.now >= deviceStatus.authorizationExpiresAt)
  ) {
    throw verificationErrorV2('DEVICE_EXPIRED');
  }

  const consumed = await challengeStore.consumeAtomically(expected.nonce);
  if (!consumed) throw verificationError('NONCE_REPLAY_OR_EXPIRED');
  return verified;
}

export async function verifyRpOperationV2(
  proof: OwnershipProofV2,
  expected: VerificationExpectationV2,
  challengeStore: ChallengeStore,
  lifecycle: LifecycleProvider,
  deviceLifecycle: DeviceLifecycleProvider,
): Promise<VerifiedDeviceSubject> {
  try {
    return await verifyRpOperationV2Internal(
      proof,
      expected,
      challengeStore,
      lifecycle,
      deviceLifecycle,
    );
  } catch (error) {
    rethrowVerificationErrorV2(error);
  }
}
