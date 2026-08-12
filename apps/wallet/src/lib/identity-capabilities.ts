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
