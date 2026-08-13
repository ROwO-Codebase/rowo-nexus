import type {
  CreatedLocalIdentity,
  ImportedDeviceV2,
  IssueDeviceTransferOptions,
} from '@nexus/wallet-core';

import type { DeviceInstallResult } from './device-management';
import type { CreateIdentityInput } from './wallet-adapter';

export interface CreatedIdentityWithLocalDevice {
  root: CreatedLocalIdentity;
  device?: ImportedDeviceV2;
  deviceState?: DeviceInstallResult['state'];
  deviceError?: string;
}

export interface CreateIdentityOperations {
  createIdentity: (input: CreateIdentityInput) => Promise<CreatedLocalIdentity>;
  provisionDeviceOnThisWallet: (
    rootLocalId: string,
    options?: IssueDeviceTransferOptions,
  ) => Promise<ImportedDeviceV2>;
  activateDevice: (localId: string) => Promise<unknown>;
}

function deviceNickname(rootNickname: string | undefined): string {
  return rootNickname === undefined ? 'This device' : `${rootNickname} · this device`;
}

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : 'The device key could not be installed.';
}

/**
 * Creates the root first, then optionally provisions a separate device key through the existing
 * authenticated transfer pipeline. Once the root exists, device failures are returned as partial
 * success so the UI never invites the user to create a duplicate root identity.
 */
export async function createIdentityWithOptionalLocalDevice(
  operations: CreateIdentityOperations,
  input: CreateIdentityInput,
): Promise<CreatedIdentityWithLocalDevice> {
  const root = await operations.createIdentity(input);
  if (input.withDeviceKey === false) return { root };

  try {
    const label = deviceNickname(input.label);
    const device = await operations.provisionDeviceOnThisWallet(root.localId, { label });
    try {
      await operations.activateDevice(device.localId);
    } catch (error) {
      return {
        root,
        device,
        deviceState: 'pending-activation',
        deviceError: describeError(error),
      };
    }
    return { root, device, deviceState: 'active' };
  } catch (error) {
    return { root, deviceError: describeError(error) };
  }
}
