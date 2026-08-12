import type { LocalIdentitySummary } from '@nexus/wallet-core';
import { describe, expect, it } from 'vitest';

import {
  canCreateProof,
  canUseRegisteredIdentityActions,
  needsRegistrationRecovery,
} from './identity-capabilities';

function identity(
  localState: LocalIdentitySummary['localState'],
  registered: boolean,
): LocalIdentitySummary {
  return {
    localId: 'local-id',
    subject: 'nx1_test',
    localScopes: [],
    authorizationHistory: [],
    localState,
    registered,
    proofReady: localState === 'active' && registered,
    hasAgreementKey: false,
    issuedDevices: [],
  };
}

describe('identity action capabilities', () => {
  it('offers only registration recovery for an active unregistered identity', () => {
    const retained = identity('active', false);
    expect(needsRegistrationRecovery(retained)).toBe(true);
    expect(canUseRegisteredIdentityActions(retained)).toBe(false);
  });

  it('enables proof-dependent lifecycle actions only after registration', () => {
    expect(canUseRegisteredIdentityActions(identity('active', true))).toBe(true);
    expect(canUseRegisteredIdentityActions(identity('revoked', true))).toBe(false);
  });

  it('never offers v1 registration recovery or root lifecycle actions to a delegated device', () => {
    const device: LocalIdentitySummary = {
      ...identity('active', true),
      device: {
        deviceId: 'nxd2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        authorizationId: 'nxa2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        localState: 'active',
        activationDeadline: 1_800_000_000,
        expiresAt: 1_900_000_000,
      },
      proofReady: true,
    };
    expect(needsRegistrationRecovery(device)).toBe(false);
    expect(canUseRegisteredIdentityActions(device)).toBe(false);
    expect(canCreateProof(device)).toBe(true);
    expect(
      canCreateProof({
        ...device,
        device: { ...device.device!, localState: 'pending-activation' },
        proofReady: false,
      }),
    ).toBe(false);
  });

  it('does not offer a proof when core marks an otherwise active device unready', () => {
    const expiredDevice: LocalIdentitySummary = {
      ...identity('active', true),
      proofReady: false,
      device: {
        deviceId: 'nxd2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        authorizationId: 'nxa2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        localState: 'active',
        activationDeadline: 1_700_000_000,
        expiresAt: 1_800_000_000,
      },
    };

    expect(canCreateProof(expiredDevice)).toBe(false);
  });
});
