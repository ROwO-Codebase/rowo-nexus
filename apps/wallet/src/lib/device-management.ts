import type {
  DeviceTransferEnvelopeV2,
  ImportedDeviceV2,
  LocalIdentitySummary,
} from '@nexus/wallet-core';

export const MAX_DEVICE_TRANSFER_FILE_BYTES = 96 * 1024;

export interface DeviceManagementCapabilities {
  issueDevice: boolean;
  activateDevice: boolean;
  selfRevokeDevice: boolean;
  rootRevokeDevice: boolean;
}

export function deviceManagementCapabilities(
  identity: LocalIdentitySummary,
  now = Math.floor(Date.now() / 1_000),
): DeviceManagementCapabilities {
  const locallyActive = identity.localState === 'active';
  if (identity.device === undefined) {
    const rootReady = locallyActive && identity.registered;
    return {
      issueDevice: rootReady,
      activateDevice: false,
      selfRevokeDevice: false,
      rootRevokeDevice: rootReady,
    };
  }
  return {
    issueDevice: false,
    activateDevice:
      locallyActive &&
      identity.device.localState === 'pending-activation' &&
      now < identity.device.activationDeadline &&
      now < identity.device.expiresAt,
    selfRevokeDevice: locallyActive && identity.device.localState !== 'revoked',
    rootRevokeDevice: false,
  };
}

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

/** Encodes the 32-byte transfer secret without including it in the bundle. */
export function encodeDeviceTransferKey(bytes: Uint8Array): string {
  if (bytes.byteLength !== 32) {
    throw new Error('The device transfer key must contain exactly 32 bytes.');
  }
  return encodeBase64Url(bytes);
}

/** Strictly accepts the canonical, unpadded base64url encoding of exactly 32 bytes. */
export function decodeDeviceTransferKey(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]{43}$/u.test(value)) {
    throw new Error('Enter the 43-character transfer key exactly as it was shown.');
  }
  let binary: string;
  try {
    binary = atob(`${value.replaceAll('-', '+').replaceAll('_', '/')}=`);
  } catch (error) {
    throw new Error('The transfer key is not valid base64url.', { cause: error });
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (bytes.byteLength !== 32 || encodeBase64Url(bytes) !== value) {
    bytes.fill(0);
    throw new Error('The transfer key is not the canonical encoding of 32 bytes.');
  }
  return bytes;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function parseDeviceTransferBundleJson(
  text: string,
  byteLength = new TextEncoder().encode(text).byteLength,
): DeviceTransferEnvelopeV2 {
  if (byteLength > MAX_DEVICE_TRANSFER_FILE_BYTES) {
    throw new Error('The device transfer file is larger than 96 KiB.');
  }
  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch (error) {
    throw new Error('The selected file is not valid JSON.', { cause: error });
  }
  if (!isRecord(value)) throw new Error('The selected file is not a device transfer bundle.');
  const expectedKeys = ['bundleId', 'ciphertext', 'iv', 'protocol', 'salt', 'suite'];
  const keys = Object.keys(value).sort();
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key, index) => key !== expectedKeys[index])
  ) {
    throw new Error('The device transfer bundle has unexpected or missing fields.');
  }
  if (
    value.protocol !== 'nexus.device-transfer.v2' ||
    value.suite !== 'NX-HKDF-SHA256-AES256GCM-v2' ||
    typeof value.bundleId !== 'string' ||
    typeof value.salt !== 'string' ||
    typeof value.iv !== 'string' ||
    typeof value.ciphertext !== 'string'
  ) {
    throw new Error('The selected file uses an unsupported device transfer format.');
  }
  return value as unknown as DeviceTransferEnvelopeV2;
}

export function serializeDeviceTransferBundle(bundle: DeviceTransferEnvelopeV2): string {
  const serialized = `${JSON.stringify(bundle, null, 2)}\n`;
  const parsed = JSON.parse(serialized) as Record<string, unknown>;
  if ('transferKey' in parsed || 'transfer_key' in parsed || 'key' in parsed) {
    throw new Error('Refusing to serialize a bundle that contains its transfer key.');
  }
  return serialized;
}

export interface DeviceInstallOperations {
  importDeviceTransfer(
    bundle: DeviceTransferEnvelopeV2,
    transferKey: Uint8Array,
  ): Promise<ImportedDeviceV2>;
  activateDevice(localId: string): Promise<unknown>;
}

export type DeviceInstallResult =
  | { imported: ImportedDeviceV2; state: 'active' }
  | { imported: ImportedDeviceV2; state: 'pending-activation'; activationError: string };

/**
 * Installs first, then attempts activation. The imported signing key remains available for an
 * explicit retry if registry activation fails. The caller-owned transfer bytes are always wiped.
 */
export async function installAndActivateDevice(
  operations: DeviceInstallOperations,
  bundle: DeviceTransferEnvelopeV2,
  transferKey: Uint8Array,
): Promise<DeviceInstallResult> {
  let imported: ImportedDeviceV2;
  try {
    imported = await operations.importDeviceTransfer(bundle, transferKey);
  } finally {
    transferKey.fill(0);
  }
  try {
    await operations.activateDevice(imported.localId);
    return { imported, state: 'active' };
  } catch (error) {
    return {
      imported,
      state: 'pending-activation',
      activationError:
        error instanceof Error ? error.message : 'The registry could not activate this device.',
    };
  }
}
