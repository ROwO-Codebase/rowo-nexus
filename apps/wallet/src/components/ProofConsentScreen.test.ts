import type { LocalIdentitySummary } from '@nexus/wallet-core';
import { describe, expect, it } from 'vitest';

import {
  identityProofProtocols,
  requiresLegacyRootConfirmation,
  resolveConsentIdentityId,
} from './ProofConsentScreen';

function identity(
  localId: string,
  overrides: Partial<LocalIdentitySummary> = {},
): LocalIdentitySummary {
  return {
    localId,
    subject: `nx1_${localId}`,
    localScopes: [],
    authorizationHistory: [],
    localState: 'active',
    registered: true,
    proofReady: true,
    hasAgreementKey: false,
    issuedDevices: [],
    ...overrides,
  };
}

describe('proof consent identity selection', () => {
  it('selects the first eligible identity when identities arrive after popup mount', () => {
    expect(resolveConsentIdentityId([], '')).toBe('');

    const lateIdentities = [
      identity('revoked', { localState: 'revoked' }),
      identity('unregistered', { registered: false, proofReady: false }),
      identity('first-active'),
      identity('second-active'),
    ];

    expect(resolveConsentIdentityId(lateIdentities, '')).toBe('first-active');
  });

  it('does not override a valid identity selected by the user', () => {
    const identities = [identity('first-active'), identity('user-choice')];

    expect(resolveConsentIdentityId(identities, 'user-choice')).toBe('user-choice');
  });

  it('prefers an active v2 device over a root credential by default', () => {
    const root = identity('root');
    const device = identity('device', {
      registered: false,
      device: {
        deviceId: 'nxd2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        authorizationId: 'nxa2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        localState: 'active',
        activationDeadline: 1_800_000_000,
        expiresAt: 1_900_000_000,
      },
    });

    expect(resolveConsentIdentityId([root, device], '')).toBe('device');
    expect(requiresLegacyRootConfirmation(root, 'nexus.ownership-proof.v1')).toBe(true);
    expect(requiresLegacyRootConfirmation(device, 'nexus.ownership-proof.v2')).toBe(false);
  });

  it('replaces a selection that is no longer eligible', () => {
    const identities = [
      identity('first-active'),
      identity('stale-choice', { localState: 'revoked' }),
    ];

    expect(resolveConsentIdentityId(identities, 'stale-choice')).toBe('first-active');
  });

  it('makes root/v1 identities eligible only for v1 proofs', () => {
    expect(identityProofProtocols(identity('root'))).toEqual(['nexus.ownership-proof.v1']);
  });

  it('makes active device installations eligible only for v2 proofs', () => {
    const device = identity('device', {
      device: {
        deviceId: 'nxd2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        authorizationId: 'nxa2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        localState: 'active',
        activationDeadline: 1_800_000_000,
        expiresAt: 1_900_000_000,
      },
      proofReady: true,
    });
    expect(identityProofProtocols(device)).toEqual(['nexus.ownership-proof.v2']);
  });

  it('does not allow a pending or revoked device installation to prove', () => {
    for (const localState of ['pending-activation', 'revoked'] as const) {
      const device = identity(`device-${localState}`, {
        device: {
          deviceId: 'nxd2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          authorizationId: 'nxa2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          localState,
          activationDeadline: 1_800_000_000,
          expiresAt: 1_900_000_000,
        },
        proofReady: false,
      });
      expect(identityProofProtocols(device)).toEqual([]);
    }
  });
});
