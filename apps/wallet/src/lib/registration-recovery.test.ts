import type { RegistryReceiptV1 } from '@nexus/protocol';
import { describe, expect, it, vi } from 'vitest';

import { retryIdentityRegistration } from './registration-recovery';

describe('registration recovery adapter', () => {
  it('retries the retained identity through WalletCore registration without deleting it', async () => {
    const receipt = { payload: {}, signature: 'test' } as unknown as RegistryReceiptV1;
    const registerIdentity = vi.fn().mockResolvedValue(receipt);
    const walletCore = { registerIdentity };

    await expect(retryIdentityRegistration(walletCore, 'local-retained-id')).resolves.toBe(receipt);
    expect(registerIdentity).toHaveBeenCalledOnce();
    expect(registerIdentity).toHaveBeenCalledWith('local-retained-id');
    expect(Object.keys(walletCore)).toEqual(['registerIdentity']);
  });
});
