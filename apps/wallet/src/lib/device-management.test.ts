import { describe, expect, it, vi } from 'vitest';
import type {
  DeviceTransferEnvelopeV2,
  ImportedDeviceV2,
  LocalIdentitySummary,
} from '@nexus/wallet-core';

import { canCreateProof } from './identity-capabilities';
import {
  decodeDeviceTransferKey,
  deviceManagementCapabilities,
  encodeDeviceTransferKey,
  installAndActivateDevice,
  parseDeviceTransferQr,
  serializeDeviceTransferBundle,
  serializeDeviceTransferQr,
} from './device-management';

function identity(overrides: Partial<LocalIdentitySummary> = {}): LocalIdentitySummary {
  return {
    localId: 'local-1',
    subject: 'nx1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
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

const bundle: DeviceTransferEnvelopeV2 = {
  protocol: 'nexus.device-transfer.v2',
  suite: 'NX-HKDF-SHA256-AES256GCM-v2',
  bundleId: 'bundle',
  salt: 'salt',
  iv: 'iv',
  ciphertext: 'ciphertext',
};

const qrBundle: DeviceTransferEnvelopeV2 = {
  protocol: 'nexus.device-transfer.v2',
  suite: 'NX-HKDF-SHA256-AES256GCM-v2',
  bundleId: encodeDeviceTransferKey(new Uint8Array(32).fill(1)),
  salt: encodeDeviceTransferKey(new Uint8Array(32).fill(2)),
  iv: 'AwMDAwMDAwMDAwMD',
  ciphertext: 'BAQEBAQEBAQEBAQEBAQEBA',
};

const imported = {
  localId: 'device-local',
  subject: 'nx1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  deviceId: 'nxd2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  authorizationId: 'nxa2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  authorization: {},
} as unknown as ImportedDeviceV2;

describe('v2 wallet device management', () => {
  it('strictly role-gates root and delegated-device actions', () => {
    expect(deviceManagementCapabilities(identity())).toEqual({
      issueDevice: true,
      activateDevice: false,
      selfRevokeDevice: false,
      rootRevokeDevice: true,
    });

    const pending = identity({
      registered: false,
      proofReady: false,
      device: {
        deviceId: imported.deviceId,
        authorizationId: imported.authorizationId,
        localState: 'pending-activation',
        activationDeadline: 2_000_000_000,
        expiresAt: 2_100_000_000,
      },
    });
    expect(deviceManagementCapabilities(pending)).toEqual({
      issueDevice: false,
      activateDevice: true,
      selfRevokeDevice: true,
      rootRevokeDevice: false,
    });
    expect(canCreateProof(pending)).toBe(false);

    const activeDevice = identity({
      registered: false,
      device: { ...pending.device!, localState: 'active' },
    });
    expect(deviceManagementCapabilities(activeDevice)).toEqual({
      issueDevice: false,
      activateDevice: false,
      selfRevokeDevice: true,
      rootRevokeDevice: false,
    });
  });

  it('keeps the transfer key separate from the downloaded bundle', () => {
    const key = Uint8Array.from({ length: 32 }, (_, index) => index);
    const encoded = encodeDeviceTransferKey(key);
    expect(decodeDeviceTransferKey(encoded)).toEqual(key);
    const serialized = serializeDeviceTransferBundle(bundle);
    expect(serialized).not.toContain(encoded);
    expect(serialized).not.toContain('transferKey');
    expect(Object.keys(JSON.parse(serialized) as object).sort()).toEqual([
      'bundleId',
      'ciphertext',
      'iv',
      'protocol',
      'salt',
      'suite',
    ]);
  });

  it('round-trips a complete offline QR bearer credential', () => {
    const key = encodeDeviceTransferKey(new Uint8Array(32).fill(5));
    const payload = serializeDeviceTransferQr(qrBundle, key);

    expect(payload).toContain(key);
    expect(payload).not.toContain('https://');
    expect(parseDeviceTransferQr(payload)).toEqual({ bundle: qrBundle, transferKey: key });
  });

  it('strictly rejects non-Nexus, malformed, and oversized QR payloads', () => {
    expect(() => parseDeviceTransferQr('https://example.com/device-transfer')).toThrow(
      'not a Nexus device transfer',
    );
    const key = encodeDeviceTransferKey(new Uint8Array(32).fill(5));
    const payload = serializeDeviceTransferQr(qrBundle, key);
    expect(() => parseDeviceTransferQr(`${payload}.extra`)).toThrow('malformed');
    expect(() => parseDeviceTransferQr(`${payload.slice(0, -1)}!`)).toThrow('43-character');
    expect(() =>
      serializeDeviceTransferQr({ ...qrBundle, ciphertext: 'A'.repeat(2_100) }, key),
    ).toThrow('too large for one QR code');
  });

  it('retains the installed device for retry when activation fails and wipes key bytes', async () => {
    const transferKey = new Uint8Array(32).fill(7);
    const importDeviceTransfer = vi.fn(() => Promise.resolve(imported));
    const activateDevice = vi.fn(() => Promise.reject(new Error('registry unavailable')));
    const result = await installAndActivateDevice(
      { importDeviceTransfer, activateDevice },
      bundle,
      transferKey,
    );

    expect(result).toEqual({
      imported,
      state: 'pending-activation',
      activationError: 'registry unavailable',
    });
    expect(transferKey).toEqual(new Uint8Array(32));
    expect(importDeviceTransfer).toHaveBeenCalledOnce();
    expect(activateDevice).toHaveBeenCalledWith(imported.localId);
  });

  it('does not attempt activation when import fails and still wipes key bytes', async () => {
    const transferKey = new Uint8Array(32).fill(9);
    const activateDevice = vi.fn();
    await expect(
      installAndActivateDevice(
        {
          importDeviceTransfer: vi.fn(() => Promise.reject(new Error('bad bundle'))),
          activateDevice,
        },
        bundle,
        transferKey,
      ),
    ).rejects.toThrow('bad bundle');
    expect(transferKey).toEqual(new Uint8Array(32));
    expect(activateDevice).not.toHaveBeenCalled();
  });

  it('closes activation exactly at the deadline or authorization expiry but keeps cancellation', () => {
    const pending = identity({
      registered: false,
      proofReady: false,
      device: {
        deviceId: imported.deviceId,
        authorizationId: imported.authorizationId,
        localState: 'pending-activation',
        activationDeadline: 2_000,
        expiresAt: 3_000,
      },
    });

    expect(deviceManagementCapabilities(pending, 1_999)).toMatchObject({
      activateDevice: true,
      selfRevokeDevice: true,
    });
    expect(deviceManagementCapabilities(pending, 2_000)).toMatchObject({
      activateDevice: false,
      selfRevokeDevice: true,
    });

    const expiryFirst = identity({
      registered: false,
      proofReady: false,
      device: { ...pending.device!, activationDeadline: 3_000, expiresAt: 2_000 },
    });
    expect(deviceManagementCapabilities(expiryFirst, 1_999).activateDevice).toBe(true);
    expect(deviceManagementCapabilities(expiryFirst, 2_000)).toMatchObject({
      activateDevice: false,
      selfRevokeDevice: true,
    });
  });
});
