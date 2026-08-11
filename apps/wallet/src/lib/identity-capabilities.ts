import type { LocalIdentitySummary } from '@nexus/wallet-core';

export function needsRegistrationRecovery(identity: LocalIdentitySummary): boolean {
  return identity.localState === 'active' && !identity.registered;
}

export function canUseRegisteredIdentityActions(identity: LocalIdentitySummary): boolean {
  return identity.localState === 'active' && identity.registered;
}
