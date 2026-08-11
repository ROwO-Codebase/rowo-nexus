import type { LocalIdentitySummary } from '@nexus/wallet-core';
import { describe, expect, it } from 'vitest';

import { resolveConsentIdentityId } from './ProofConsentScreen';

function identity(
  localId: string,
  overrides: Partial<LocalIdentitySummary> = {},
): LocalIdentitySummary {
  return {
    localId,
    subject: `nx1_${localId}`,
    localScopes: [],
    localState: 'active',
    registered: true,
    hasAgreementKey: false,
    ...overrides,
  };
}

describe('proof consent identity selection', () => {
  it('selects the first eligible identity when identities arrive after popup mount', () => {
    expect(resolveConsentIdentityId([], '')).toBe('');

    const lateIdentities = [
      identity('revoked', { localState: 'revoked' }),
      identity('unregistered', { registered: false }),
      identity('first-active'),
      identity('second-active'),
    ];

    expect(resolveConsentIdentityId(lateIdentities, '')).toBe('first-active');
  });

  it('does not override a valid identity selected by the user', () => {
    const identities = [identity('first-active'), identity('user-choice')];

    expect(resolveConsentIdentityId(identities, 'user-choice')).toBe('user-choice');
  });

  it('replaces a selection that is no longer eligible', () => {
    const identities = [
      identity('first-active'),
      identity('stale-choice', { localState: 'revoked' }),
    ];

    expect(resolveConsentIdentityId(identities, 'stale-choice')).toBe('first-active');
  });
});
