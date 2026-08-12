import type { LocalIdentitySummary } from '@nexus/wallet-core';

export function canCreateProof(identity: LocalIdentitySummary): boolean {
  return identity.localState === 'active' && identity.proofReady;
}

export function needsRegistrationRecovery(identity: LocalIdentitySummary): boolean {
  return identity.device === undefined && identity.localState === 'active' && !identity.registered;
}

export function canUseRegisteredIdentityActions(identity: LocalIdentitySummary): boolean {
  // Rotation, continuity, and terminal identity disposal require the root/v1 key. Delegated
  // devices get their own self-revocation flow and must never be offered root operations.
  return identity.device === undefined && identity.localState === 'active' && identity.registered;
}

export function canRemoveLocalIdentity(
  identity: LocalIdentitySummary,
  now = Math.floor(Date.now() / 1_000),
): boolean {
  if (identity.localState === 'revoked') return true;
  const device = identity.device;
  return (
    device !== undefined &&
    (device.localState === 'revoked' ||
      device.registryState === 'revoked' ||
      device.registryState === 'expired' ||
      now >= device.expiresAt)
  );
}
