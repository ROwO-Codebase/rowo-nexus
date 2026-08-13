import type { CreatedLocalIdentity, ImportedDeviceV2 } from '@nexus/wallet-core';
import {
  deviceAuthorizationV2Schema,
  identityGenesisV1Schema,
  nexusDeviceAuthorizationIdV2Schema,
  nexusDeviceIdV2Schema,
  nexusSubjectSchema,
} from '@nexus/protocol';
import { describe, expect, it, vi } from 'vitest';

import {
  createIdentityWithOptionalLocalDevice,
  type CreateIdentityOperations,
} from './create-identity';

const root: CreatedLocalIdentity = {
  localId: 'root-local',
  subject: nexusSubjectSchema.parse('nx1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'),
  genesis: identityGenesisV1Schema.parse({
    protocol: 'nexus.identity.v1',
    suite: 'NX-25519-SHA256-JCS-v1',
    signingKey: {
      alg: 'Ed25519',
      publicKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    },
    revocationCommitment: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  }),
};

const imported: ImportedDeviceV2 = {
  localId: 'device-local',
  subject: root.subject,
  deviceId: nexusDeviceIdV2Schema.parse('nxd2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'),
  authorizationId: nexusDeviceAuthorizationIdV2Schema.parse(
    'nxa2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  ),
  authorization: deviceAuthorizationV2Schema.parse({
    payload: {
      protocol: 'nexus.device-authorization.v2',
      subject: root.subject,
      genesisHash: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      deviceId: 'nxd2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      signingKey: {
        alg: 'Ed25519',
        publicKey: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA',
      },
      authorizationNonce: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      validFrom: 1,
      activationDeadline: 2,
      expiresAt: 3,
    },
    rootSignature:
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  }),
};

function operations(overrides: Partial<CreateIdentityOperations> = {}): CreateIdentityOperations {
  return {
    createIdentity: vi.fn(() => Promise.resolve(root)),
    provisionDeviceOnThisWallet: vi.fn(() => Promise.resolve(imported)),
    activateDevice: vi.fn(() => Promise.resolve()),
    ...overrides,
  };
}

describe('new identity local-device provisioning', () => {
  it('creates, installs, activates, and labels a device by default', async () => {
    const api = operations();
    const result = await createIdentityWithOptionalLocalDevice(api, { label: 'Campus forum' });

    expect(api.provisionDeviceOnThisWallet).toHaveBeenCalledWith(root.localId, {
      label: 'Campus forum · this device',
    });
    expect(api.activateDevice).toHaveBeenCalledWith(imported.localId);
    expect(result).toMatchObject({ root, device: imported, deviceState: 'active' });
  });

  it('preserves the exact root-only flow when the option is disabled', async () => {
    const api = operations();
    const result = await createIdentityWithOptionalLocalDevice(api, { withDeviceKey: false });

    expect(result).toEqual({ root });
    expect(api.provisionDeviceOnThisWallet).not.toHaveBeenCalled();
    expect(api.activateDevice).not.toHaveBeenCalled();
  });

  it('retains and selects a pending device when activation is unavailable', async () => {
    const api = operations({
      activateDevice: vi.fn(() => Promise.reject(new Error('registry unavailable'))),
    });
    const result = await createIdentityWithOptionalLocalDevice(api, {});

    expect(result).toMatchObject({
      root,
      device: imported,
      deviceState: 'pending-activation',
      deviceError: 'registry unavailable',
    });
    expect(api.provisionDeviceOnThisWallet).toHaveBeenCalledWith(root.localId, {
      label: 'This device',
    });
  });

  it('reports partial success when same-wallet provisioning fails', async () => {
    const api = operations({
      provisionDeviceOnThisWallet: vi.fn(() => Promise.reject(new Error('storage unavailable'))),
    });
    const result = await createIdentityWithOptionalLocalDevice(api, {});

    expect(result).toEqual({ root, deviceError: 'storage unavailable' });
  });
});
