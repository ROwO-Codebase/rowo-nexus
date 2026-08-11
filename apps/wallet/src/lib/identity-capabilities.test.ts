import type { LocalIdentitySummary } from '@nexus/wallet-core';
import { describe, expect, it } from 'vitest';

import {
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
    hasAgreementKey: false,
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
});
